package rule

import (
	"strings"
	"testing"
	"time"

	"github.com/feng111627/audit-log-compliance-go/pkg/audit"
)

func at(sec int) time.Time {
	return time.Unix(int64(sec), 0).UTC()
}

var evSeq int64

func newEv(id, src, typ, actor string, t time.Time, payload map[string]any) audit.Event {
	evSeq++
	return audit.Event{ID: id, Source: src, Seq: evSeq, Type: typ, Actor: actor, Time: t, Payload: payload}
}

func mustParse(t *testing.T, raw string) []Rule {
	t.Helper()
	rs, err := ParseRules([]byte(raw))
	if err != nil {
		t.Fatalf("规则解析失败: %v", err)
	}
	return rs
}

// TestThresholdBurst 业务：登录失败在窗口内聚集触发一次告警，窗口外不触发。
func TestThresholdBurst(t *testing.T) {
	rs := mustParse(t, `{"id":"login-burst","kind":"threshold",
		"event_type":"login_failed","window":"5m","threshold":3}`)
	eng := NewEngine(rs)
	t.Log("【业务:告警-登录失败聚集】5 分钟内 3 次失败触发 1 条告警；窗口过期后不累计")
	alerts := []Alert{}
	alerts = append(alerts, eng.Process(newEv("a1", "h", "login_failed", "bob", at(0), nil))...)
	alerts = append(alerts, eng.Process(newEv("a2", "h", "login_failed", "bob", at(60), nil))...)
	alerts = append(alerts, eng.Process(newEv("a3", "h", "login_failed", "bob", at(120), nil))...)
	if len(alerts) != 1 {
		t.Fatalf("期望 1 条聚集告警, 得到 %d", len(alerts))
	}
	a := alerts[0]
	if a.RuleID != "login-burst" || a.Group != "bob" || len(a.EventIDs) != 3 {
		t.Fatalf("告警内容不符: %+v", a)
	}
	if a.Fingerprint == "" {
		t.Fatal("告警必须带指纹")
	}
	// 窗口已消费：紧接着再来 2 条不应告警。
	alerts = append(alerts, eng.Process(newEv("a4", "h", "login_failed", "bob", at(130), nil))...)
	alerts = append(alerts, eng.Process(newEv("a5", "h", "login_failed", "bob", at(140), nil))...)
	if n := countRule(alerts, "login-burst"); n != 1 {
		t.Fatalf("消费窗口后不应重复告警, 共 %d 条", n)
	}
	// 窗口过期：间距超过 5m 的失败不累计。
	eng2 := NewEngine(rs)
	var got []Alert
	for _, s := range []int{0, 400, 800} {
		got = append(got, eng2.Process(newEv("x", "h", "login_failed", "bob", at(s), nil))...)
	}
	if len(got) != 0 {
		t.Fatalf("窗口外事件不应聚集告警, 得到 %d 条", len(got))
	}
	t.Logf("【业务:告警-登录失败聚集】通过: 告警窗口 %s..%s 指纹 %.12s...",
		a.WindowStart.Format(time.RFC3339), a.WindowEnd.Format(time.RFC3339), a.Fingerprint)
}

// TestPrivilegeEscalation 业务：权限提升规则借助 payload 匹配并按主体判定。
func TestPrivilegeEscalation(t *testing.T) {
	t.Log("【业务:告警-权限提升】窗口内出现 type=privilege_granted 且 payload.role=admin 达阈值即告警")
	rs := mustParse(t, `{"id":"priv-esc","kind":"threshold","event_type":"privilege_granted",
		"window":"1h","threshold":2,"payload":{"role":"admin"}}`)
	eng := NewEngine(rs)
	var alerts []Alert
	alerts = append(alerts, eng.Process(newEv("p1", "h", "privilege_granted", "u", at(0),
		map[string]any{"role": "admin"}))...)
	// role 不匹配，必须忽略。
	alerts = append(alerts, eng.Process(newEv("p2", "h", "privilege_granted", "u", at(10),
		map[string]any{"role": "viewer"}))...)
	alerts = append(alerts, eng.Process(newEv("p3", "h", "privilege_granted", "u", at(20),
		map[string]any{"role": "admin"}))...)
	if len(alerts) != 1 || len(alerts[0].EventIDs) != 2 ||
		alerts[0].EventIDs[0] != "p1" || alerts[0].EventIDs[1] != "p3" {
		t.Fatalf("payload 过滤结果不符: %+v", alerts)
	}
	t.Log("【业务:告警-权限提升】通过: 非匹配 payload 被忽略，仅 2 条 admin 授权触发")
}

// TestGapDetection 业务：日志空档检测，相邻事件时差达到 gap 即告警。
func TestGapDetection(t *testing.T) {
	t.Log("【业务:告警-日志空档】相邻匹配事件间隔 >= gap 告警；间隔不足不告警")
	rs := mustParse(t, `{"id":"log-gap","kind":"gap","gap":"10m"}`)
	eng := NewEngine(rs)
	var alerts []Alert
	alerts = append(alerts, eng.Process(newEv("g1", "h", "login_ok", "", at(0), nil))...)
	alerts = append(alerts, eng.Process(newEv("g2", "h", "login_ok", "", at(600), nil))...) // 恰好 10m
	if len(alerts) != 1 {
		t.Fatalf("边界相等(10m)应触发, 得到 %d", len(alerts))
	}
	// 后续事件恢复正常节奏，不再告警。
	alerts = append(alerts, eng.Process(newEv("g3", "h", "login_ok", "", at(601), nil))...)
	if n := countRule(alerts, "log-gap"); n != 1 {
		t.Fatalf("恢复后不应再告警, 共 %d", n)
	}

	eng2 := NewEngine(rs)
	var got []Alert
	for _, s := range []int{0, 60, 120} {
		got = append(got, eng2.Process(newEv("g", "h", "login_ok", "", at(s), nil))...)
	}
	if len(got) != 0 {
		t.Fatalf("间隔不足 gap 不应告警, 得到 %d", len(got))
	}
	t.Log("【业务:告警-日志空档】通过: 边界相等触发，恢复后不误报")
}

// TestGapTailFlush 业务：停机时距最后事件超过 gap，Flush 报告持续空档。
func TestGapTailFlush(t *testing.T) {
	t.Log("【业务:告警-日志空档-尾段】最后事件之后持续无日志，Flush 显式报告")
	rs := mustParse(t, `{"id":"log-gap","kind":"gap","gap":"10m"}`)
	eng := NewEngine(rs)
	eng.Process(newEv("g1", "h", "login_ok", "", at(0), nil))
	alerts := eng.Flush(at(900))
	if len(alerts) != 1 || alerts[0].WindowEnd != at(900) {
		t.Fatalf("Flush 应产出 1 条尾段空档告警, 得到 %+v", alerts)
	}
	// 同一时钟重复 Flush 不应重复告警。
	if again := eng.Flush(at(900)); len(again) != 0 {
		t.Fatalf("重复 Flush 不应重复告警, 得到 %d", len(again))
	}
	t.Log("【业务:告警-日志空档-尾段】通过")
}

// TestReplayDeterministic 业务：重启/乱序到达重放相同数据，告警结论与指纹完全一致。
func TestReplayDeterministic(t *testing.T) {
	t.Log("【业务:规则重放】不同 goroutine 到达顺序下重放，告警集合、窗口与指纹必须一致")
	rs := mustParse(t, `{
		"rules":[
			{"id":"login-burst","kind":"threshold","event_type":"login_failed","window":"5m","threshold":3},
			{"id":"log-gap","kind":"gap","gap":"10m"}
		]}`)

	mk := func() []audit.Event {
		evSeq = 0
		return []audit.Event{
			newEv("e1", "h1", "login_ok", "", at(0), nil),
			newEv("f1", "h2", "login_failed", "bob", at(10), nil),
			newEv("f2", "h2", "login_failed", "bob", at(20), nil),
			newEv("f3", "h2", "login_failed", "bob", at(30), nil),
			newEv("e2", "h1", "login_ok", "", at(900), nil),
		}
	}
	first := NewEngine(rs).Replay(mk())
	// 打乱到达顺序（模拟并发乱序到达）。
	shuffled := mk()
	shuffled[0], shuffled[4] = shuffled[4], shuffled[0]
	shuffled[1], shuffled[3] = shuffled[3], shuffled[1]
	second := NewEngine(rs).Replay(shuffled)

	if len(first) == 0 {
		t.Fatal("应至少触发登录聚集与空档各一条")
	}
	if len(first) != len(second) {
		t.Fatalf("告警数量不一致: %d != %d", len(first), len(second))
	}
	for i := range first {
		if first[i].Fingerprint != second[i].Fingerprint {
			t.Fatalf("第 %d 条告警指纹不一致:\n%+v\n%+v", i, first[i], second[i])
		}
	}
	// 再重放一次（模拟重启）仍完全一致。
	third := NewEngine(rs).Replay(mk())
	for i := range first {
		if first[i].Fingerprint != third[i].Fingerprint {
			t.Fatalf("重启重放第 %d 条告警指纹不一致", i)
		}
	}
	for _, a := range first {
		t.Logf("【业务:规则重放】稳定告警 rule=%s 窗口=%s..%s 指纹=%.12s...",
			a.RuleID, a.WindowStart, a.WindowEnd, a.Fingerprint)
	}
}

// TestInvalidRulesRejected 业务：非法/不可解析规则必须带原因拒绝，绝不静默跳过。
func TestInvalidRulesRejected(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"用例:空输入", ``, "empty"},
		{"用例:缺 id", `{"kind":"threshold","window":"1m","threshold":1}`, `"id"`},
		{"用例:未知 kind", `{"id":"x","kind":"weird","window":"1m","threshold":1}`, "unknown kind"},
		{"用例:threshold 缺 threshold", `{"id":"x","kind":"threshold","window":"1m"}`, "threshold"},
		{"用例:threshold 缺 window", `{"id":"x","kind":"threshold","threshold":1}`, "window"},
		{"用例:threshold 为 0", `{"id":"x","kind":"threshold","window":"1m","threshold":0}`, ">="},
		{"用例:duration 非法", `{"id":"x","kind":"threshold","window":"abc","threshold":1}`, "invalid duration"},
		{"用例:gap 缺字段", `{"id":"x","kind":"gap"}`, "gap"},
		{"用例:window 小于 gap", `{"id":"x","kind":"gap","gap":"10m","window":"1m"}`, "must be >="},
		{"用例:JSON 语法错误", `{"id":"x", broken}`, "parse rejected"},
		{"用例:未知字段", `{"id":"x","kind":"gap","gap":"1m","bogus":1}`, "unknown field"},
		{"用例:规则集中第二条非法", `{
			"rules":[
				{"id":"ok","kind":"gap","gap":"1m"},
				{"id":"bad","kind":"threshold","threshold":2}
			]}`, "rule #2"},
		{"用例:规则 id 重复", `{
			"rules":[
				{"id":"dup","kind":"gap","gap":"1m"},
				{"id":"dup","kind":"gap","gap":"2m"}
			]}`, "duplicate rule id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseRules([]byte(tc.raw))
			if err == nil {
				t.Fatalf("非法规则必须被拒绝")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("错误原因不含 %q: %v", tc.want, err)
			}
			if !strings.Contains(err.Error(), "reject") {
				t.Fatalf("错误必须显式表明拒绝: %v", err)
			}
		})
	}
}

func countRule(alerts []Alert, id string) int {
	n := 0
	for _, a := range alerts {
		if a.RuleID == id {
			n++
		}
	}
	return n
}
