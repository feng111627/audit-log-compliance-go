package pipeline

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/feng111627/audit-log-compliance-go/pkg/audit"
	"github.com/feng111627/audit-log-compliance-go/pkg/rule"
	"github.com/feng111627/audit-log-compliance-go/pkg/segment"
)

const rulesJSON = `{
  "rules": [
    {"id":"login-failed-burst","description":"5分钟内登录失败5次",
     "kind":"threshold","event_type":"login_failed","window":"5m","threshold":5},
    {"id":"admin-grant","description":"窗口内管理员授权",
     "kind":"threshold","event_type":"privilege_granted","window":"1h","threshold":1,
     "payload":{"role":"admin"}},
    {"id":"silence-gap","description":"任意审计事件10分钟空档",
     "kind":"gap","window":"10m","gap":"10m"}
  ]
}`

func openPipeline(t *testing.T, dir string) *Pipeline {
	t.Helper()
	rules, err := rule.ParseRules([]byte(rulesJSON))
	if err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time {
		return time.Date(2026, 10, 6, 10, 0, 0, 0, time.UTC)
	}
	p, err := New(Config{
		Dir:    dir,
		Policy: segment.RotationPolicy{MaxSegmentBytes: 1200, MaxSegments: 4},
		Rules:  rules,
		Now:    clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestPipelineConcurrentWriteRotateReplay 业务：端到端——并发写入触发轮转保留，
// 留存数据校验通过；重启后重放相同数据告警结论一致。
func TestPipelineConcurrentWriteRotateReplay(t *testing.T) {
	t.Log("【业务:端到端流水线】4 来源并发写入 -> 按大小轮转+保留4段 -> 全量/增量校验 -> 重启重放告警一致")
	dir := t.TempDir()
	p := openPipeline(t, dir)

	base := time.Date(2026, 10, 6, 10, 0, 0, 0, time.UTC)
	const nSource = 4
	const perSource = 120
	var wg sync.WaitGroup
	var failMu sync.Mutex
	var failures []error
	for s := 0; s < nSource; s++ {
		wg.Add(1)
		go func(s int) {
			defer wg.Done()
			src := fmt.Sprintf("src-%d", s)
			for i := int64(1); i <= perSource; i++ {
				typ := "login_ok"
				actor := fmt.Sprintf("user-%d", i%7)
				payload := map[string]any(nil)
				// src-0 制造登录失败聚集；周期性制造管理员授权。
				if s == 0 && i%6 == 0 {
					typ = "login_failed"
				}
				if i%40 == 0 {
					typ = "privilege_granted"
					actor = "admin"
					payload = map[string]any{"role": "admin"}
				}
				ev := audit.Event{
					ID:      fmt.Sprintf("%s-%d", src, i),
					Source:  src,
					Seq:     i,
					Type:    typ,
					Actor:   actor,
					Time:    base.Add(time.Duration(i) * time.Second),
					Payload: payload,
				}
				if err := p.Submit(ev); err != nil {
					failMu.Lock()
					failures = append(failures, err)
					failMu.Unlock()
				}
			}
		}(s)
	}
	wg.Wait()
	if len(failures) != 0 {
		t.Fatalf("并发写入出现 %d 个失败, 首个: %v", len(failures), failures[0])
	}

	// 并发阶段结束后顺序追加一段“尾部”数据：与并发期相距很久（制造空档），
	// 随后 40 秒内聚集 5 次登录失败。这些事件最后写入，必然落在最新留存段落。
	tail := base.Add(2000 * time.Second)
	tailEvents := []audit.Event{
		{ID: "tail-1", Source: "tail", Seq: 1, Type: "login_ok", Time: tail},
	}
	for i := int64(2); i <= 6; i++ {
		tailEvents = append(tailEvents, audit.Event{
			ID: fmt.Sprintf("tail-%d", i), Source: "tail", Seq: i,
			Type: "login_failed", Actor: "attacker",
			Time: tail.Add(time.Duration(i) * 10 * time.Second),
		})
	}
	for _, ev := range tailEvents {
		if err := p.Submit(ev); err != nil {
			t.Fatalf("尾部事件提交失败: %v", err)
		}
	}
	p.CloseSource("src-0")
	if err := p.Submit(audit.Event{ID: "late", Source: "src-0", Seq: perSource + 1,
		Type: "x", Time: base}); !errors.Is(err, audit.ErrSourceClosed) {
		t.Fatalf("关闭来源后应 ErrSourceClosed, 得到 %v", err)
	}
	if err := p.Seal(); err != nil {
		t.Fatal(err)
	}

	// 轮转与保留确实发生。
	full, err := p.VerifyFull()
	if err != nil {
		t.Fatal(err)
	}
	if !full.OK {
		for _, sr := range full.Segments {
			t.Errorf("留存段落 %s: %s %s", sr.Name, sr.Reason, sr.Detail)
		}
	}
	if len(full.Segments) != 4 {
		t.Fatalf("保留策略应剩 4 段, 实际 %d", len(full.Segments))
	}
	t.Logf("【业务:端到端流水线】并发写入 %d 事件, 轮转保留后 %d 段全部校验通过",
		nSource*perSource, len(full.Segments))

	// 增量校验：锚点取第 3 段。
	anchor := p.Anchor()
	inc, err := p.VerifyIncremental(anchor)
	if err != nil {
		t.Fatal(err)
	}
	if !inc.OK || inc.Mode != "incremental" {
		t.Fatalf("增量校验异常: %+v", inc)
	}

	alerts1, err := p.ReplayAlerts()
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}

	// 重启：重开目录再重放，告警必须完全一致。
	p2 := openPipeline(t, dir)
	defer p2.Close()
	alerts2, err := p2.ReplayAlerts()
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts1) == 0 {
		t.Fatal("应至少重放出登录失败聚集/权限提升告警")
	}
	// 登录失败聚集与长空档必须命中（尾部数据保证存活于保留窗口）。
	mustHit := map[string]bool{"login-failed-burst": false, "silence-gap": false}
	for _, a := range alerts1 {
		mustHit[a.RuleID] = true
	}
	for id, hit := range mustHit {
		if !hit {
			t.Fatalf("期望重放命中规则 %s，实际告警: %v", id, counts(alerts1))
		}
	}
	if len(alerts1) != len(alerts2) {
		t.Fatalf("重启重放告警数量不一致: %d != %d", len(alerts1), len(alerts2))
	}
	fp1 := fingerprintSet(alerts1)
	fp2 := fingerprintSet(alerts2)
	if len(fp1) != len(alerts1) {
		t.Fatal("首次重放内部出现重复指纹，判定不具备可区分性")
	}
	for fp := range fp1 {
		if !fp2[fp] {
			t.Fatalf("重启重放缺少告警指纹 %s", fp)
		}
	}
	counts := map[string]int{}
	for _, a := range alerts1 {
		counts[a.RuleID]++
	}
	t.Logf("【业务:端到端流水线】重放告警 %d 条(指纹重启后完全一致): %v", len(alerts1), counts)
}

// TestPipelineReplayRejectsTamperedData 业务：留存数据被篡改时不得产出告警，
// 必须先暴露完整性原因。
func TestPipelineReplayRejectsTamperedData(t *testing.T) {
	t.Log("【业务:端到端-篡改拦截】篡改留存段落后 ReplayAlerts 必须报错而非静默给出告警")
	dir := t.TempDir()
	p := openPipeline(t, dir)
	base := time.Date(2026, 10, 6, 10, 0, 0, 0, time.UTC)
	for i := int64(1); i <= 40; i++ {
		if err := p.Submit(audit.Event{ID: fmt.Sprintf("e%d", i), Source: "s", Seq: i,
			Type: "login_failed", Time: base.Add(time.Duration(i) * time.Second)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}

	// 直接破坏磁盘上的一个封存段落（等长篡改，哈希链必然失配）。
	matches, _ := filepath.Glob(filepath.Join(dir, "segment-*.log"))
	if len(matches) < 2 {
		t.Fatalf("应至少轮转 2 段, 实际 %d", len(matches))
	}
	target := matches[0]
	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	nb := []byte{}
	nb = append(nb, b...)
	nb[len(nb)/2] = swapByte(nb[len(nb)/2])
	if err := os.WriteFile(target, nb, 0o644); err != nil {
		t.Fatal(err)
	}

	p2 := openPipeline(t, dir)
	defer p2.Close()
	r, err := p2.VerifyFull()
	if err != nil {
		t.Fatal(err)
	}
	if r.OK {
		t.Fatal("篡改后全量校验必须失败")
	}
	if _, err := p2.ReplayAlerts(); err == nil {
		t.Fatal("篡改数据下重放必须返回完整性错误，禁止对不可信数据产出告警")
	} else {
		t.Logf("【业务:端到端-篡改拦截】通过: 重放被完整性校验拦截 -> %v", err)
	}
}

func fingerprintSet(alerts []rule.Alert) map[string]bool {
	m := make(map[string]bool, len(alerts))
	for _, a := range alerts {
		m[a.Fingerprint] = true
	}
	return m
}

func counts(alerts []rule.Alert) map[string]int {
	c := map[string]int{}
	for _, a := range alerts {
		c[a.RuleID]++
	}
	return c
}

func swapByte(b byte) byte {
	switch b {
	case 'a':
		return 'b'
	default:
		if b == ' ' || b == '\n' || b == '"' {
			return 'X'
		}
		return 'a'
	}
}
