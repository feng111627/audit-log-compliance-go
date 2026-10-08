package audit

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

// openRecoveryDir 准备一个含若干已确认事件的存储，返回目录与存储。
func openRecoveryDir(t *testing.T, n int) (string, *Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := NewStore(dir, RotationPolicy{}, RetentionPolicy{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	w := NewWriter(st)
	for i := 1; i <= n; i++ {
		e := Event{Source: "auth", Seq: uint64(i), Timestamp: baseTime().Add(time.Duration(i) * time.Second),
			Type: "login_failed", Actor: "alice"}
		if err := w.Write(e); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	return dir, st
}

// appendRawToActive 以低层方式向活跃段追加原始字节（模拟写到一半被杀）。
func appendRawToActive(t *testing.T, st *Store, s string) {
	t.Helper()
	p := st.segmentPath(st.ActiveSegmentID())
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

func rawEventLine(t *testing.T, e Event) string {
	t.Helper()
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

// TestRecoverCommittedDataIntact 覆盖业务：崩溃恢复 | 已确认数据一条不少。
func TestRecoverCommittedDataIntact(t *testing.T) {
	t.Log("业务: 异常中断后重启续写 | 用例: 中断前已确认的事件重开后一条不少")
	dir, _ := openRecoveryDir(t, 5)
	st, err := NewStore(dir, RotationPolicy{}, RetentionPolicy{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	rep := st.RecoveryReport()
	if rep.RecoveredEvents != 5 {
		t.Fatalf("recovered=%d, want 5", rep.RecoveredEvents)
	}
	if rep.DiscardedEvents != 0 || rep.TruncatedBytes != 0 {
		t.Fatalf("clean shutdown should discard nothing: %+v", rep)
	}
	evs, err := st.AllEvents()
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 5 {
		t.Fatalf("events after reopen %d, want 5", len(evs))
	}
	for i := uint64(1); i <= 5; i++ {
		if evs[i-1].Seq != i {
			t.Fatalf("seq order broken at %d: %+v", i, evs[i-1])
		}
	}
	t.Logf("结果: 5 条已确认事件全部重放，丢弃=%d 截断=%d 字节", rep.DiscardedEvents, rep.TruncatedBytes)
}

// TestRecoverTornBatchDiscarded 覆盖业务：崩溃恢复 | 半成品批次整组丢弃不拖坏数据。
func TestRecoverTornBatchDiscarded(t *testing.T) {
	t.Log("业务: 异常中断后重启续写 | 用例: 写到一半的批次整组丢弃，已确认批次不受影响")
	dir, st := openRecoveryDir(t, 3)
	// 第 4、5 条事件行已落盘，但提交标记未写（进程被杀）。
	appendRawToActive(t, st, rawEventLine(t, Event{Source: "auth", Seq: 4, Timestamp: baseTime(), Type: "login_failed"}))
	appendRawToActive(t, st, rawEventLine(t, Event{Source: "auth", Seq: 5, Timestamp: baseTime(), Type: "login_failed"}))

	st2, err := NewStore(dir, RotationPolicy{}, RetentionPolicy{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	rep := st2.RecoveryReport()
	if rep.RecoveredEvents != 3 {
		t.Fatalf("recovered=%d want 3", rep.RecoveredEvents)
	}
	if rep.DiscardedEvents != 2 {
		t.Fatalf("discarded=%d want 2 (torn whole batch)", rep.DiscardedEvents)
	}
	if rep.TruncatedBytes <= 0 {
		t.Fatal("expected positive truncated bytes")
	}
	// 截断后读取，半成品事件一条都不能混进来。
	evs, err := st2.ReadEvents(st2.ActiveSegmentID())
	if err != nil {
		t.Fatalf("recovered active segment must be readable: %v", err)
	}
	if len(evs) != 3 {
		t.Fatalf("after truncate events=%d want 3", len(evs))
	}
	t.Logf("结果: 重放 %d 条，半成品批次 %d 条整组丢弃，截断 %d 字节",
		rep.RecoveredEvents, rep.DiscardedEvents, rep.TruncatedBytes)
}

// TestRecoverTornHalfLine 覆盖业务：崩溃恢复 | 半行写入（无换行收尾）被截掉。
func TestRecoverTornHalfLine(t *testing.T) {
	t.Log("业务: 异常中断后重启续写 | 用例: 最后一行写了一半（无换行）被截掉")
	dir, st := openRecoveryDir(t, 3)
	appendRawToActive(t, st, `{"source":"auth","seq":4,"timestamp":"2026-10-06T00:00:00Z","type":"x"`)

	st2, err := NewStore(dir, RotationPolicy{}, RetentionPolicy{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	rep := st2.RecoveryReport()
	if rep.RecoveredEvents != 3 {
		t.Fatalf("recovered=%d want 3", rep.RecoveredEvents)
	}
	if rep.TruncatedBytes <= 0 {
		t.Fatal("half-written line must be truncated away")
	}
	evs, _ := st2.ReadEvents(st2.ActiveSegmentID())
	if len(evs) != 3 {
		t.Fatalf("events=%d want 3", len(evs))
	}
	t.Logf("结果: 半行写入被截掉 %d 字节，3 条已确认事件完好", rep.TruncatedBytes)
}

// TestRecoverContinueWriteAndVerify 覆盖业务：恢复后续写的新数据与旧数据一起通过校验。
func TestRecoverContinueWriteAndVerify(t *testing.T) {
	t.Log("业务: 异常中断后重启续写 | 用例: 恢复后续写新数据，新旧合并读取且不被当作篡改")
	dir, st := openRecoveryDir(t, 3)
	appendRawToActive(t, st, rawEventLine(t, Event{Source: "auth", Seq: 4, Timestamp: baseTime(), Type: "x"}))

	st2, err := NewStore(dir, RotationPolicy{MaxBytes: 600}, RetentionPolicy{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	w := NewWriter(st2)
	if got := w.LastSeq("auth"); got != 3 {
		t.Fatalf("writer seed seq=%d want 3", got)
	}
	// 用正确序号续写 seq 4、5、6。
	for i := uint64(4); i <= 6; i++ {
		e := Event{Source: "auth", Seq: i, Timestamp: baseTime().Add(time.Duration(i) * time.Second),
			Type: "login_failed", Actor: "alice"}
		if err := w.Write(e); err != nil {
			t.Fatalf("continue write seq %d: %v", i, err)
		}
	}
	evs, err := st2.AllEvents()
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 6 {
		t.Fatalf("merged events=%d want 6", len(evs))
	}
	// 封存后全量校验必须通过——续写数据不能因"上次没正常结束"被判篡改。
	if err := st2.Seal(); err != nil {
		t.Fatal(err)
	}
	if rep := VerifyAll(st2); !rep.OK {
		t.Fatalf("verify after continue-write failed: %+v", rep.Segments)
	}
	t.Log("结果: 恢复后续写 seq 4-6，新旧合并共 6 条，封存后全量校验通过")
}

// TestRecoverIdempotentReopen 覆盖业务：崩溃恢复 | 恢复动作幂等，再次打开不再丢数据。
func TestRecoverIdempotentReopen(t *testing.T) {
	t.Log("业务: 异常中断后重启续写 | 用例: 恢复一次后再次打开，结果稳定不重复截断")
	dir, st := openRecoveryDir(t, 3)
	appendRawToActive(t, st, rawEventLine(t, Event{Source: "auth", Seq: 4, Timestamp: baseTime(), Type: "x"}))

	st1, err := NewStore(dir, RotationPolicy{}, RetentionPolicy{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	r1 := st1.RecoveryReport()
	if r1.DiscardedEvents != 1 {
		t.Fatalf("first recovery discarded=%d want 1", r1.DiscardedEvents)
	}
	st2, err := NewStore(dir, RotationPolicy{}, RetentionPolicy{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	r2 := st2.RecoveryReport()
	if r2.RecoveredEvents != 3 || r2.DiscardedEvents != 0 || r2.TruncatedBytes != 0 {
		t.Fatalf("second reopen must be clean: %+v", r2)
	}
	t.Log("结果: 首次恢复丢弃 1 条半成品，再次打开无新增丢弃/截断，恢复幂等")
}

// TestRecoverReportCounts 覆盖业务：崩溃恢复对账 | 报告明确重放/丢弃条数。
func TestRecoverReportCounts(t *testing.T) {
	t.Log("业务: 异常中断后重启续写 | 用例: 恢复报告可对账（重放数、丢弃数、说明明细）")
	dir, st := openRecoveryDir(t, 4)
	appendRawToActive(t, st, rawEventLine(t, Event{Source: "auth", Seq: 5, Timestamp: baseTime(), Type: "x"}))
	appendRawToActive(t, st, rawEventLine(t, Event{Source: "auth", Seq: 6, Timestamp: baseTime(), Type: "x"}))

	st2, err := NewStore(dir, RotationPolicy{}, RetentionPolicy{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	rep := st2.RecoveryReport()
	if rep.ActiveSegmentID != st.ActiveSegmentID() {
		t.Fatalf("report active id=%d want %d", rep.ActiveSegmentID, st.ActiveSegmentID())
	}
	if rep.RecoveredEvents != 4 || rep.DiscardedEvents != 2 {
		t.Fatalf("counts wrong: recovered=%d discarded=%d", rep.RecoveredEvents, rep.DiscardedEvents)
	}
	if len(rep.Details) == 0 {
		t.Fatal("report should contain human-readable details")
	}
	for _, d := range rep.Details {
		t.Logf("对账明细: %s", d)
	}
}

// TestWriteBatchAtomicity 覆盖业务：成组提交 | 整批要么全可见要么全不可见。
func TestWriteBatchAtomicity(t *testing.T) {
	t.Log("业务: 异常中断后重启续写 | 用例: WriteBatch 原子提交，整批一起出现")
	dir := t.TempDir()
	st, err := NewStore(dir, RotationPolicy{}, RetentionPolicy{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	w := NewWriter(st)
	batch := []Event{
		{Source: "b", Seq: 1, Timestamp: baseTime(), Type: "login_failed"},
		{Source: "b", Seq: 2, Timestamp: baseTime(), Type: "login_failed"},
		{Source: "b", Seq: 3, Timestamp: baseTime(), Type: "login_failed"},
	}
	if err := w.WriteBatch(batch); err != nil {
		t.Fatal(err)
	}
	evs, _ := st.AllEvents()
	if len(evs) != 3 {
		t.Fatalf("committed batch events=%d want 3", len(evs))
	}
	// 批内序号不连续 => 整批拒绝，存储中不留任何记录。
	bad := []Event{
		{Source: "b", Seq: 4, Timestamp: baseTime(), Type: "login_failed"},
		{Source: "b", Seq: 6, Timestamp: baseTime(), Type: "login_failed"}, // 跳号
	}
	if err := w.WriteBatch(bad); !errors.Is(err, ErrValidation) {
		t.Fatalf("gap batch should be rejected with ErrValidation, got %v", err)
	}
	evs2, _ := st.AllEvents()
	if len(evs2) != 3 {
		t.Fatalf("rejected batch must not touch storage, events=%d want 3", len(evs2))
	}
	if got := w.LastSeq("b"); got != 3 {
		t.Fatalf("seq must not advance after rejected batch, got %d", got)
	}
	t.Log("结果: 整批 3 条原子提交；跳号批次整体拒绝，存储与序号均不受污染")
}

// TestRecoverMultiSourceSeqRebuild 覆盖业务：崩溃恢复 | 多来源序号快照重建。
func TestRecoverMultiSourceSeqRebuild(t *testing.T) {
	t.Log("业务: 异常中断后重启续写 | 用例: 重开后各来源从已提交最大序号接着写")
	dir := t.TempDir()
	st, _ := NewStore(dir, RotationPolicy{}, RetentionPolicy{}, 0)
	w := NewWriter(st)
	for i := uint64(1); i <= 4; i++ {
		if err := w.Write(Event{Source: "a", Seq: i, Timestamp: baseTime(), Type: "login_failed"}); err != nil {
			t.Fatal(err)
		}
	}
	for i := uint64(1); i <= 2; i++ {
		if err := w.Write(Event{Source: "b", Seq: i, Timestamp: baseTime(), Type: "login_failed"}); err != nil {
			t.Fatal(err)
		}
	}
	st2, _ := NewStore(dir, RotationPolicy{}, RetentionPolicy{}, 0)
	w2 := NewWriter(st2)
	if w2.LastSeq("a") != 4 || w2.LastSeq("b") != 2 {
		t.Fatalf("rebuilt seqs a=%d b=%d, want 4/2", w2.LastSeq("a"), w2.LastSeq("b"))
	}
	// 各来源正确续写。
	if err := w2.Write(Event{Source: "a", Seq: 5, Timestamp: baseTime(), Type: "login_failed"}); err != nil {
		t.Fatalf("continue a5: %v", err)
	}
	if err := w2.Write(Event{Source: "b", Seq: 3, Timestamp: baseTime(), Type: "login_failed"}); err != nil {
		t.Fatalf("continue b3: %v", err)
	}
	// 重复序号仍被拒绝（重建状态真正生效）。
	if err := w2.Write(Event{Source: "a", Seq: 5, Timestamp: baseTime(), Type: "login_failed"}); !errors.Is(err, ErrValidation) {
		t.Fatalf("duplicate after reopen should reject, got %v", err)
	}
	t.Log("结果: 多来源序号快照重建为 a=4,b=2，续写成功，重复序号仍被拒绝")
}
