package segment

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/feng111627/audit-log-compliance-go/pkg/audit"
)

var testClock atomic.Int64 // 虚拟时钟（Unix 秒），可复现

func fakeNow() time.Time {
	return time.Unix(testClock.Load(), 0).UTC()
}

func evAt(id, src string, seq int64, typ string, t time.Time) audit.Event {
	return audit.Event{ID: id, Source: src, Seq: seq, Type: typ, Time: t,
		Payload: map[string]any{"k": "v"}}
}

func newTestStore(t *testing.T, p RotationPolicy) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	testClock.Store(1_000_000)
	s, err := Open(dir, p, fakeNow)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, dir
}

func appendN(t *testing.T, s *Store, src string, n int, start time.Time) {
	t.Helper()
	for i := 1; i <= n; i++ {
		ev := evAt(fmt.Sprintf("%s-%d", src, i), src, int64(i), "login_failed",
			start.Add(time.Duration(i)*time.Second))
		if err := s.Append(ev); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
}

// TestRotationBySize 业务：按大小轮转，多段落全量校验通过且链连续。
func TestRotationBySize(t *testing.T) {
	t.Log("【业务:轮转-按大小】段落达到阈值后在下次写入时轮转，封存有 footer，全量校验通过")
	s, _ := newTestStore(t, RotationPolicy{MaxSegmentBytes: 300})
	appendN(t, s, "h", 20, fakeNow())
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}
	if len(s.man.Segments) < 2 {
		t.Fatalf("期望发生轮转产生 >=2 个段落, 实际 %d", len(s.man.Segments))
	}
	r, err := s.VerifyFull()
	if err != nil {
		t.Fatal(err)
	}
	if !r.OK {
		for _, sr := range r.Segments {
			t.Errorf("段落 %s: %s %s", sr.Name, sr.Reason, sr.Detail)
		}
	}
	t.Logf("【业务:轮转-按大小】通过: 共 %d 个封存段落", len(s.man.Segments))
}

// TestRotationByTime 业务：按事件时间跨度轮转，固定时钟下结论可复现。
func TestRotationByTime(t *testing.T) {
	t.Log("【业务:轮转-按时间】相邻事件跨度超过 MaxSegmentAge 即轮转")
	s, _ := newTestStore(t, RotationPolicy{MaxSegmentAge: 10 * time.Second})
	base := fakeNow()
	for i := 1; i <= 6; i++ {
		if err := s.Append(evAt(fmt.Sprintf("e%d", i), "h", int64(i), "x",
			base.Add(time.Duration(i)*5*time.Second))); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}
	if len(s.man.Segments) < 2 {
		t.Fatalf("期望按时间轮转, 实际段落数 %d", len(s.man.Segments))
	}
	if r, _ := s.VerifyFull(); !r.OK {
		t.Fatal("时间轮转后完整性校验失败")
	}
	t.Logf("【业务:轮转-按时间】通过: %d 个段落", len(s.man.Segments))
}

// TestRetentionKeepsVerifiable 业务：保留清理删除旧段落后，留存数据仍可验证、可扫描。
func TestRetentionKeepsVerifiable(t *testing.T) {
	t.Log("【业务:保留策略】MaxSegments=2 清理旧段落；被删文件消失，剩余段落全量校验通过")
	s, dir := newTestStore(t, RotationPolicy{MaxSegmentBytes: 200, MaxSegments: 2})
	appendN(t, s, "h", 30, fakeNow())
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	logFiles := 0
	for _, en := range entries {
		if strings.HasSuffix(en.Name(), ".log") {
			logFiles++
		}
	}
	if logFiles != 2 || len(s.man.Segments) != 2 {
		t.Fatalf("保留后应剩 2 段: 目录 %d 个文件, 清单 %d 条", logFiles, len(s.man.Segments))
	}
	// 清单中的每个段落文件都必须真实存在，且不存在清单外的孤儿段落。
	listed := map[string]bool{}
	for _, e := range s.man.Segments {
		if _, err := os.Stat(filepath.Join(dir, e.Name)); err != nil {
			t.Fatalf("留存段落 %s 应存在: %v", e.Name, err)
		}
		listed[e.Name] = true
	}
	for _, en := range entries {
		if strings.HasSuffix(en.Name(), ".log") && !listed[en.Name()] {
			t.Fatalf("发现清单外孤儿段落 %s", en.Name())
		}
	}
	r, err := s.VerifyFull()
	if err != nil {
		t.Fatal(err)
	}
	if !r.OK {
		for _, sr := range r.Segments {
			t.Errorf("留存段落 %s 校验失败: %s %s", sr.Name, sr.Reason, sr.Detail)
		}
	}
	count := 0
	if err := s.ScanEvents(func(ev audit.Event) error { count++; return nil }); err != nil {
		t.Fatalf("留存数据扫描失败: %v", err)
	}
	t.Logf("【业务:保留策略】通过: 清理后剩 %d 段、%d 条事件均可验证", len(s.man.Segments), count)
}

// TestReopenPersistence 业务：重启后恢复链与锚点，校验结论不变。
func TestReopenPersistence(t *testing.T) {
	t.Log("【业务:重启恢复】封存+重开存储，锚点不变、全量校验通过、事件可扫描")
	dir := t.TempDir()
	testClock.Store(1_000_000)
	s, err := Open(dir, RotationPolicy{MaxSegmentBytes: 300}, fakeNow)
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, s, "h", 15, fakeNow())
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}
	anchor := s.Anchor()
	if anchor == "" {
		t.Fatal("封存后应有锚点")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(dir, RotationPolicy{MaxSegmentBytes: 300}, fakeNow)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if s2.Anchor() != anchor {
		t.Fatalf("重开后锚点变化: %s != %s", s2.Anchor(), anchor)
	}
	if r, _ := s2.VerifyFull(); !r.OK {
		t.Fatal("重开后全量校验失败")
	}
	count := 0
	if err := s2.ScanEvents(func(audit.Event) error { count++; return nil }); err != nil {
		t.Fatal(err)
	}
	t.Logf("【业务:重启恢复】通过: 锚点 %s, 恢复 %d 条事件", anchor, count)
}

// TestVerifyDetectsTamperTruncateMissing 业务：篡改/截断/缺失在全量与增量下均被识别且原因可区分。
func TestVerifyDetectsTamperTruncateMissing(t *testing.T) {
	cases := []struct {
		name   string
		reason Reason
		damage func(t *testing.T, dir string, segs []Entry)
	}{
		{
			"用例:篡改事件内容(等长替换字符)", ReasonTampered,
			func(t *testing.T, dir string, segs []Entry) {
				p := filepath.Join(dir, segs[len(segs)-1].Name)
				b, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				nb := strings.Replace(string(b), "login_failed", "Login_failed", 1)
				if nb == string(b) {
					t.Fatal("篡改替换未生效")
				}
				if err := os.WriteFile(p, []byte(nb), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			"用例:截断(删除封存 footer)", ReasonTruncated,
			func(t *testing.T, dir string, segs []Entry) {
				p := filepath.Join(dir, segs[len(segs)-1].Name)
				b, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
				if len(lines) < 2 {
					t.Fatal("段落行数不足以删除 footer")
				}
				out := strings.Join(lines[:len(lines)-1], "\n") + "\n"
				if err := os.WriteFile(p, []byte(out), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			"用例:缺失(删除段落文件)", ReasonMissing,
			func(t *testing.T, dir string, segs []Entry) {
				if err := os.Remove(filepath.Join(dir, segs[1].Name)); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("【业务:完整性校验】%s：全量校验必须给出 %s", tc.name, tc.reason)
			s, dir := newTestStore(t, RotationPolicy{MaxSegmentBytes: 220})
			appendN(t, s, "h", 24, fakeNow())
			if err := s.Seal(); err != nil {
				t.Fatal(err)
			}
			if r, _ := s.VerifyFull(); !r.OK {
				t.Fatal("前置: 健康数据应校验通过")
			}
			segs := append([]Entry(nil), s.man.Segments...)
			if len(segs) < 3 {
				t.Fatalf("需要 >=3 个段落做增量验证, 实际 %d", len(segs))
			}
			anchor := fmt.Sprintf("%d:%s", segs[0].Index, segs[0].Digest)
			tc.damage(t, dir, segs)

			rf, err := s.VerifyFull()
			if err != nil {
				t.Fatal(err)
			}
			if rf.OK || !reportHasReason(rf, tc.reason) {
				t.Fatalf("全量校验期望发现 %s, 得到 OK=%v 原因集=%v", tc.reason, rf.OK, reasons(rf))
			}
			ri, err := s.VerifyIncremental(anchor)
			if err != nil {
				t.Fatal(err)
			}
			if ri.OK || !reportHasReason(ri, tc.reason) {
				t.Fatalf("增量校验(锚点 %s)期望发现 %s, 得到 OK=%v 原因集=%v",
					anchor, tc.reason, ri.OK, reasons(ri))
			}
			t.Logf("【业务:完整性校验】通过: 全量与增量均判定为 %s", tc.reason)
		})
	}
}

// TestIncrementalAnchorMismatch 业务：锚点摘要与清单不符时给出 tampered 判定。
func TestIncrementalAnchorMismatch(t *testing.T) {
	t.Log("【业务:完整性校验-增量】伪造/过期锚点摘要必须被判 tampered 而非静默通过")
	s, _ := newTestStore(t, RotationPolicy{MaxSegmentBytes: 300})
	appendN(t, s, "h", 20, fakeNow())
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}
	e := s.man.Segments[0]
	badAnchor := fmt.Sprintf("%d:%s", e.Index, "deadbeef")
	r, err := s.VerifyIncremental(badAnchor)
	if err != nil {
		t.Fatal(err)
	}
	if r.OK || !reportHasReason(r, ReasonTampered) {
		t.Fatalf("过期锚点应判 tampered, 得到 OK=%v %v", r.OK, reasons(r))
	}
	t.Log("【业务:完整性校验-增量】通过: 锚点不一致被识别")
}

// TestCapacityExceeded 业务：总容量触顶且保留无可清理时，写入失败可分类为容量受限。
func TestCapacityExceeded(t *testing.T) {
	t.Log("【业务:容量受限】MaxTotalBytes 触顶后 Append 返回 ErrCapacityExceeded")
	s, _ := newTestStore(t, RotationPolicy{MaxTotalBytes: 500})
	ev := evAt("e1", "h", 1, "x", fakeNow())
	var got error
	for i := int64(1); ; i++ {
		ev.ID = fmt.Sprintf("e%d", i)
		ev.Seq = i
		ev.Time = fakeNow().Add(time.Duration(i) * time.Second)
		if err := s.Append(ev); err != nil {
			got = err
			break
		}
		if i > 100 {
			t.Fatal("容量限制未生效")
		}
	}
	if !errors.Is(got, audit.ErrCapacityExceeded) {
		t.Fatalf("期望 ErrCapacityExceeded, 得到 %v", got)
	}
	t.Logf("【业务:容量受限】通过: %v", got)
}

func reportHasReason(r *Report, want Reason) bool {
	for _, sr := range r.Segments {
		if sr.Reason == want {
			return true
		}
	}
	return false
}

func reasons(r *Report) []Reason {
	var out []Reason
	for _, sr := range r.Segments {
		out = append(out, sr.Reason)
	}
	return out
}

// TestReopenUnsealedSegment 业务：崩溃场景模拟——活动段落未封存即重开，
// 链与计数应被恢复，补封存后全量校验通过。
func TestReopenUnsealedSegment(t *testing.T) {
	t.Log("【业务:重启恢复-未封存】活动段落无 footer 时重开，恢复链头/计数后可继续追加并封存")
	dir := t.TempDir()
	testClock.Store(1_000_000)
	s, err := Open(dir, RotationPolicy{}, fakeNow)
	if err != nil {
		t.Fatal(err)
	}
	for i := int64(1); i <= 5; i++ {
		if err := s.Append(evAt(fmt.Sprintf("u%d", i), "h", i, "x", fakeNow().Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatal(err)
		}
	}
	// 不 Seal 直接关闭底层文件句柄（模拟进程被杀，未走 Close）。
	s.mu.Lock()
	if err := s.cur.Close(); err != nil {
		t.Fatal(err)
	}
	s.cur = nil
	s.mu.Unlock()

	s2, err := Open(dir, RotationPolicy{}, fakeNow)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if s2.count != 5 {
		t.Fatalf("未封存段落恢复计数 = %d, 期望 5", s2.count)
	}
	if err := s2.Append(evAt("u6", "h", 6, "x", fakeNow().Add(6*time.Second))); err != nil {
		t.Fatalf("恢复后追加失败: %v", err)
	}
	if err := s2.Seal(); err != nil {
		t.Fatal(err)
	}
	if r, _ := s2.VerifyFull(); !r.OK {
		t.Fatal("未封存段恢复并封存后应校验通过")
	}
	t.Log("【业务:重启恢复-未封存】通过")
}

// TestRetentionByAge 业务：按事件时间年龄保留，仅清理超龄封存段落。
func TestRetentionByAge(t *testing.T) {
	t.Log("【业务:保留-按年龄】MaxAge=1h 且时钟前进后，旧段落被清理、新段落保留且可验证")
	dir := t.TempDir()
	testClock.Store(1_000_000)
	s, err := Open(dir, RotationPolicy{MaxSegmentBytes: 250}, fakeNow)
	if err != nil {
		t.Fatal(err)
	}
	base := fakeNow()
	appendN(t, s, "h", 10, base) // 第一批：t0 附近
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}
	oldCount := len(s.man.Segments)
	// 时钟前进 2 小时，再写新段落。
	testClock.Store(1_000_000 + 7200)
	appendN(t, s, "h", 10, fakeNow())
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}
	// 显式按年龄清理一次。
	if err := s.EnforceRetention(RotationPolicy{MaxSegmentBytes: 250, MaxAge: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if len(s.man.Segments) >= oldCount+2 {
		t.Fatalf("超龄旧段落应被清理, 仍有 %d 段", len(s.man.Segments))
	}
	for _, e := range s.man.Segments {
		if !e.MaxTime.IsZero() && e.MaxTime.Before(fakeNow().Add(-time.Hour)) {
			t.Fatalf("超龄段落 %s 未清理", e.Name)
		}
	}
	if r, _ := s.VerifyFull(); !r.OK {
		t.Fatal("年龄清理后留存数据应可验证")
	}
	t.Logf("【业务:保留-按年龄】通过: 清理后 %d 段可验证", len(s.man.Segments))
}

// TestConcurrentAppend 业务：底层存储并发 Append 不产生损坏，校验通过。
func TestConcurrentAppend(t *testing.T) {
	t.Log("【业务:并发落地】多 goroutine 直接并发 Append 后全量哈希链校验通过")
	s, _ := newTestStore(t, RotationPolicy{MaxSegmentBytes: 400})
	base := fakeNow()
	var wg sync.WaitGroup
	for g := 0; g < 6; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			src := fmt.Sprintf("g%d", g)
			for i := int64(1); i <= 30; i++ {
				if err := s.Append(evAt(fmt.Sprintf("%s-%d", src, i), src, i, "x",
					base.Add(time.Duration(g)*time.Minute+time.Duration(i)*time.Second))); err != nil {
					t.Errorf("append: %v", err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.VerifyFull(); !r.OK {
		for _, sr := range r.Segments {
			t.Errorf("%s: %s %s", sr.Name, sr.Reason, sr.Detail)
		}
		t.Fatal("并发落地后完整性校验失败")
	}
	t.Log("【业务:并发落地】通过")
}

// TestVerifyCorruptRecord 业务：段落中写入不可解析行时判定为 corrupt。
func TestVerifyCorruptRecord(t *testing.T) {
	t.Log("【业务:完整性校验-损坏】在封存段落尾追加非法 JSON 行必须判定 corrupt")
	s, dir := newTestStore(t, RotationPolicy{})
	appendN(t, s, "h", 3, fakeNow())
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}
	name := s.man.Segments[0].Name
	p := filepath.Join(dir, name)
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("{not-json\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	r, err := s.VerifyFull()
	if err != nil {
		t.Fatal(err)
	}
	if r.OK || !reportHasReason(r, ReasonCorrupt) {
		t.Fatalf("期望 corrupt 判定, 得到 OK=%v %v", r.OK, reasons(r))
	}
	var sawScanCorrupt bool
	if err := s.ScanEvents(func(audit.Event) error { return nil }); err != nil {
		var se *ScanError
		if errors.As(err, &se) && se.Reason == ReasonCorrupt {
			sawScanCorrupt = true
		}
	}
	if !sawScanCorrupt {
		t.Fatal("扫描损坏段落应返回 *ScanError(corrupt)")
	}
	t.Log("【业务:完整性校验-损坏】通过: 全量与扫描均判定 corrupt")
}
