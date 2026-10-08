package audit

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeEvents 向指定 Writer 写入 n 条单来源事件。
func writeEvents(t *testing.T, w *Writer, src string, n int, start time.Time) {
	t.Helper()
	for i := 1; i <= n; i++ {
		e := Event{
			Source:    src,
			Seq:       uint64(i),
			Timestamp: start.Add(time.Duration(i) * time.Second),
			Type:      EventTypeLoginFailed,
			Actor:     "u",
		}
		if err := w.Write(e); err != nil {
			t.Fatalf("write seq %d: %v", i, err)
		}
	}
}

// appendRaw 向段落文件尾部直接写字节（模拟进程被杀时的半成品写）。
func appendRaw(t *testing.T, path string, data []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
}

// TestCrashRecoveryTornTail 覆盖业务：异常中断后重启续写。
// 写入若干事件后，模拟进程在批次写一半时被杀（截断 JSON + 坏行），
// 重开目录必须：重放已确认事件一条不少、丢弃半成品、续写成功、全量校验通过。
func TestCrashRecoveryTornTail(t *testing.T) {
	t.Log("业务: 崩溃恢复 | 用例: 活跃段尾部写一半被杀，重开后重放旧数据、丢弃半成品、续写新数据并通过校验")
	dir := t.TempDir()

	// 第一轮：正常写入 5 条（未封存，模拟崩溃发生在活跃段）。
	st1, err := NewStore(dir, RotationPolicy{}, RetentionPolicy{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	w1 := NewWriter(st1)
	writeEvents(t, w1, "app", 5, baseTime())

	activePath := filepath.Join(dir, segmentFileName(st1.ActiveSegmentID()))
	// 模拟强杀：半条截断 JSON（无结尾）+ 一行结构已坏的记录。
	appendRaw(t, activePath, []byte(`{"source":"app","seq":6,"timestamp":"2026-10-06T00:00:06Z"`))
	appendRaw(t, activePath, []byte("\n{\"source\":\"app\",\"seq\":7, broken}\n"))

	// 第二轮：重开同一目录，触发自动恢复。
	st2, err := NewStore(dir, RotationPolicy{}, RetentionPolicy{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	rec := st2.LastRecovery()
	if !rec.Recovered {
		t.Fatalf("expect Recovered=true, report=%+v", rec)
	}
	if rec.ReplayedEvents != 5 {
		t.Fatalf("replayed events %d, want 5 (confirmed data must not be lost)", rec.ReplayedEvents)
	}
	if rec.DiscardedLines == 0 {
		t.Fatalf("discarded lines %d, want > 0", rec.DiscardedLines)
	}
	if rec.ActiveSegmentID != st1.ActiveSegmentID() {
		t.Fatalf("recovered segment %d, want %d", rec.ActiveSegmentID, st1.ActiveSegmentID())
	}
	if len(rec.Issues) == 0 || rec.Issues[0].Reason != ReasonRecordCorrupt {
		t.Fatalf("recovery issues should classify as record_corrupt: %+v", rec.Issues)
	}
	t.Logf("结果: 重放 %d 条、丢弃 %d 条半成品（%s 行 %d）、剔除 %d 字节",
		rec.ReplayedEvents, rec.DiscardedLines,
		rec.Issues[0].Reason, rec.Issues[0].Line, rec.TruncatedBytes)

	// 恢复后旧数据一条不少。
	old, err := st2.AllEvents()
	if err != nil {
		t.Fatal(err)
	}
	if len(old) != 5 {
		t.Fatalf("old events after recovery %d, want 5", len(old))
	}

	// 用现存数据重建 Writer 序号，续写 seq 6..10。
	w2, err := NewWriterFromStore(st2)
	if err != nil {
		t.Fatal(err)
	}
	for i := 6; i <= 10; i++ {
		e := Event{
			Source: "app", Seq: uint64(i),
			Timestamp: baseTime().Add(time.Duration(i) * time.Second),
			Type:      EventTypeLoginFailed, Actor: "u",
		}
		if err := w2.Write(e); err != nil {
			t.Fatalf("continue write seq %d: %v", i, err)
		}
	}

	// 封存后做全量与“含活跃段”校验，旧数据+新数据一起通过，
	// 不能因为上次没正常结束就被误判为被外部改动。
	if err := st2.Seal(); err != nil {
		t.Fatal(err)
	}
	full := VerifyAll(st2)
	if !full.OK {
		t.Fatalf("verify after recovery+continue failed: %+v", full.Segments)
	}
	all, err := st2.AllEvents()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 10 {
		t.Fatalf("total events %d, want 10 (5 replayed + 5 new)", len(all))
	}
	for i, e := range all {
		if e.Seq != uint64(i+1) {
			t.Fatalf("event[%d].Seq=%d, want %d (ordering broken after recovery)", i, e.Seq, i+1)
		}
	}
	t.Logf("结果: 续写后共 %d 条事件序号连续 1..10，全量校验 ok=true", len(all))
}

// TestCrashRecoveryCleanShutdown 覆盖业务：正常关闭不应报告恢复。
func TestCrashRecoveryCleanShutdown(t *testing.T) {
	t.Log("业务: 崩溃恢复 | 用例: 正常写入后重开，Recovered=false 且数据不丢")
	dir := t.TempDir()
	st1, err := NewStore(dir, RotationPolicy{}, RetentionPolicy{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	w1 := NewWriter(st1)
	writeEvents(t, w1, "app", 3, baseTime())
	if err := st1.Seal(); err != nil {
		t.Fatal(err)
	}

	st2, err := NewStore(dir, RotationPolicy{}, RetentionPolicy{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	rec := st2.LastRecovery()
	if rec.Recovered {
		t.Fatalf("clean shutdown should not recover: %+v", rec)
	}
	if rec.SealedSegments != 1 {
		t.Fatalf("sealed segments %d, want 1", rec.SealedSegments)
	}
	evs, _ := st2.AllEvents()
	if len(evs) != 3 {
		t.Fatalf("events %d, want 3", len(evs))
	}
	t.Log("结果: 正常封存后重开无需恢复，3 条事件完整")
}

// TestRecoveryDoesNotTouchSealedSegments 覆盖业务：恢复只动未封存活跃段，
// 已封存段落即便存在也不被恢复逻辑改写。
func TestRecoveryDoesNotTouchSealedSegments(t *testing.T) {
	t.Log("业务: 崩溃恢复 | 用例: 已有多个封存段 + 活跃段半成品，恢复仅修复活跃段")
	dir := t.TempDir()
	st1, err := NewStore(dir, RotationPolicy{MaxBytes: 400}, RetentionPolicy{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	w1 := NewWriter(st1)
	writeEvents(t, w1, "app", 25, baseTime())
	// 不 Seal：轮转已产生若干封存段，最后仍有活跃段。
	sealedBefore := len(st1.Segments())
	if sealedBefore < 2 {
		t.Fatalf("setup: want >=2 sealed segments, got %d", sealedBefore)
	}
	activeID := st1.ActiveSegmentID()
	appendRaw(t, filepath.Join(dir, segmentFileName(activeID)),
		[]byte("{broken-active-tail"))

	st2, err := NewStore(dir, RotationPolicy{MaxBytes: 400}, RetentionPolicy{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	rec := st2.LastRecovery()
	if !rec.Recovered || rec.ActiveSegmentID != activeID {
		t.Fatalf("unexpected recovery report: %+v", rec)
	}
	if len(st2.Segments()) != sealedBefore {
		t.Fatalf("sealed segments changed %d -> %d", sealedBefore, len(st2.Segments()))
	}
	// 封存段必须仍然完整可校验。
	if rep := VerifyAll(st2); !rep.OK {
		t.Fatalf("sealed segments should still verify: %+v", rep.Segments)
	}
	t.Logf("结果: %d 个封存段不受影响且校验通过，仅活跃段被修复", sealedBefore)
}

// TestNewWriterFromStoreSeqResume 覆盖业务：重启后序号从现存数据正确续接，
// 不能把合法的下一条误判为乱序。
func TestNewWriterFromStoreSeqResume(t *testing.T) {
	t.Log("业务: 崩溃恢复 | 用例: 多来源重开后各来源序号正确续接")
	dir := t.TempDir()
	st1, _ := NewStore(dir, RotationPolicy{}, RetentionPolicy{}, 0)
	w1 := NewWriter(st1)
	writeEvents(t, w1, "a", 4, baseTime())
	writeEvents(t, w1, "b", 2, baseTime())

	st2, _ := NewStore(dir, RotationPolicy{}, RetentionPolicy{}, 0)
	w2, err := NewWriterFromStore(st2)
	if err != nil {
		t.Fatal(err)
	}
	if w2.LastSeq("a") != 4 || w2.LastSeq("b") != 2 {
		t.Fatalf("last seq a=%d b=%d, want 4,2", w2.LastSeq("a"), w2.LastSeq("b"))
	}
	next := Event{Source: "a", Seq: 5, Timestamp: baseTime().Add(5 * time.Second),
		Type: EventTypeLoginFailed, Actor: "u"}
	if err := w2.Write(next); err != nil {
		t.Fatalf("resume write seq 5: %v", err)
	}
	dup := Event{Source: "a", Seq: 5, Timestamp: baseTime().Add(5 * time.Second),
		Type: EventTypeLoginFailed, Actor: "u"}
	if err := w2.Write(dup); !errors.Is(err, ErrValidation) {
		t.Fatalf("duplicate seq after resume: got %v, want ErrValidation", err)
	}
	t.Log("结果: 重开后来源 a 序号续到 4、b 续到 2；seq5 可写、重复 seq5 仍被拒")
}

// TestCrashRecoveryThenRotateAndIncremental 覆盖业务：恢复后继续写入并轮转，
// 新旧数据混合封存，全量与增量校验都通过，链不因崩溃恢复而断。
func TestCrashRecoveryThenRotateAndIncremental(t *testing.T) {
	t.Log("业务: 崩溃恢复 | 用例: 恢复后续写触发轮转，跨恢复点全量/增量校验通过")
	dir := t.TempDir()
	st1, _ := NewStore(dir, RotationPolicy{MaxBytes: 400}, RetentionPolicy{}, 0)
	w1 := NewWriter(st1)
	writeEvents(t, w1, "app", 20, baseTime())
	// 在活跃段制造半成品。
	active := st1.ActiveSegmentID()
	appendRaw(t, filepath.Join(dir, segmentFileName(active)), []byte("{torn"))

	st2, _ := NewStore(dir, RotationPolicy{MaxBytes: 400}, RetentionPolicy{}, 0)
	rec := st2.LastRecovery()
	if !rec.Recovered {
		t.Fatal("expect recovery")
	}
	w2, err := NewWriterFromStore(st2)
	if err != nil {
		t.Fatal(err)
	}
	// 续写更多事件，迫使在恢复后的干净活跃段上继续轮转。
	for i := int(w2.LastSeq("app")) + 1; i <= 40; i++ {
		e := Event{Source: "app", Seq: uint64(i),
			Timestamp: baseTime().Add(time.Duration(i) * time.Second),
			Type:      EventTypeLoginFailed, Actor: "u"}
		if err := w2.Write(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := st2.Seal(); err != nil {
		t.Fatal(err)
	}

	full := VerifyAll(st2)
	if !full.OK {
		t.Fatalf("full verify after recovery+rotate: %+v", full.Segments)
	}
	segs := st2.Segments()
	mid := segs[len(segs)/2].ID
	inc := VerifyIncremental(st2, mid)
	if !inc.OK {
		t.Fatalf("incremental across recovery point: %+v", inc.Segments)
	}
	// 事件总数 = 恢复前的 + 续写的（半成品除外）。
	all, _ := st2.AllEvents()
	if len(all) != 40 {
		t.Fatalf("total events %d, want 40", len(all))
	}
	// 抢救报告：全部封存段 verified，且增量可继续。
	srep, err := Salvage(st2, SalvageOptions{IncludeActive: true})
	if err != nil {
		t.Fatal(err)
	}
	if !srep.OK || !srep.IncrementalOK {
		t.Fatalf("salvage after recovery: OK=%v IncrementalOK=%v", srep.OK, srep.IncrementalOK)
	}
	t.Logf("结果: 恢复后续写轮转产生 %d 封存段，共 %d 事件，全量/增量/Salvage 全部通过",
		len(segs), len(all))
}
