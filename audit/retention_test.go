package audit

import (
	"errors"
	"os"
	"testing"
	"time"
)

// sealedSizes 返回各封存段文件大小（按 ID 顺序）。
func sealedSizes(t *testing.T, s *Store) map[int]int64 {
	t.Helper()
	out := map[int]int64{}
	for _, seg := range s.Segments() {
		path := s.segmentPath(seg.ID)
		if fi, err := os.Stat(path); err == nil {
			out[seg.ID] = fi.Size()
		}
	}
	return out
}

// setupRetentionStore 构造含若干封存段的存储，并手动回填可区分的 SealedAt，
// 使按时间清理在测试中确定可控。
func setupRetentionStore(t *testing.T, rotMaxBytes int64, events int) (string, *Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := NewStore(dir, RotationPolicy{MaxBytes: rotMaxBytes}, RetentionPolicy{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	w := NewWriter(st)
	writeNEvents(t, w, "app", events, baseTime())
	if err := st.Seal(); err != nil {
		t.Fatal(err)
	}
	return dir, st
}

// ageSealedSegments 重写清单，把封存段 SealedAt 依次设为 now-i*step，
// 段越旧时间越早。
func ageSealedSegments(t *testing.T, s *Store, now time.Time, step time.Duration) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.sealed)
	for i := range s.sealed {
		s.sealed[i].SealedAt = now.Add(-time.Duration(n-1-i) * step)
	}
	if err := s.saveManifestLocked(); err != nil {
		t.Fatal(err)
	}
}

// TestRetentionByBytesActuallyDeletes 覆盖业务：按空间清理必须真的删掉段。
func TestRetentionByBytesActuallyDeletes(t *testing.T) {
	t.Log("业务: 组合保留清理 | 用例: 配置 MaxBytes 后超限的最旧段被真实删除")
	_, st := setupRetentionStore(t, 300, 30)
	segs := st.Segments()
	if len(segs) < 3 {
		t.Fatalf("setup want >=3 segments, got %d", len(segs))
	}

	// 只保留最后 1 个段的大小作为上限，逼迫删除其余全部旧段。
	sizes := sealedSizes(t, st)
	var newestSize int64
	newestID := segs[len(segs)-1].ID
	newestSize = sizes[newestID]

	st.ret.MaxBytes = newestSize + 1
	now := baseTime().Add(24 * time.Hour)
	res, err := st.ApplyRetentionDetailed(now)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Removed) == 0 {
		t.Fatal("MaxBytes retention must delete something")
	}
	// 文件必须真的不存在。
	for _, id := range res.Removed {
		if _, err := os.Stat(st.segmentPath(id)); !os.IsNotExist(err) {
			t.Fatalf("deleted segment %d file still exists", id)
		}
	}
	// 清理后占用确实降到上限以内。
	if res.RetainedUsed > st.ret.MaxBytes {
		t.Fatalf("retained used %d > MaxBytes %d", res.RetainedUsed, st.ret.MaxBytes)
	}
	// 剩下的必须是最新段且仍可全量校验。
	if len(st.Segments()) != 1 || st.Segments()[0].ID != newestID {
		t.Fatalf("only newest segment %d should remain, got %v", newestID, st.Segments())
	}
	if rep := VerifyAll(st); !rep.OK {
		t.Fatalf("verify after bytes retention: %+v", rep.Segments)
	}
	t.Logf("结果: MaxBytes=%d 删除 %d 段（%v），释放 %d 字节，留存 %d 字节，校验通过",
		st.ret.MaxBytes, len(res.Removed), res.Removed, res.FreedBytes, res.RetainedUsed)
}

// TestRetentionCombinedAgeAndCount 覆盖业务：时间与数量条件取并集，且产出对账明细。
func TestRetentionCombinedAgeAndCount(t *testing.T) {
	t.Log("业务: 组合保留清理 | 用例: MaxAge 与 MaxSegments 同时配置，按最旧前缀清理并给出删/留明细")
	_, st := setupRetentionStore(t, 300, 30)
	now := baseTime().Add(10 * time.Hour)
	ageSealedSegments(t, st, now, time.Hour)
	segs := st.Segments()
	n := len(segs)

	st.ret.MaxAge = 3 * time.Hour // 仅最近 3 小时
	st.ret.MaxSegments = n - 1    // 只比上限多删 1 段；MaxAge 应主导
	res, err := st.ApplyRetentionDetailed(now)
	if err != nil {
		t.Fatal(err)
	}
	// MaxAge：SealedAt 严格早于 now-3h 的段被删（now-3h 当刻的保留），
	// n 段时间跨度为 0h..(n-1)h，因此删除 n-4 段。
	wantByAge := n - 4
	if len(res.Removed) != wantByAge {
		t.Fatalf("removed %d, want %d (by MaxAge)", len(res.Removed), wantByAge)
	}
	if len(res.Kept) != n-wantByAge {
		t.Fatalf("kept %d, want %d", len(res.Kept), n-wantByAge)
	}
	if len(res.Entries) != n {
		t.Fatalf("entries %d, want %d (account for every segment)", len(res.Entries), n)
	}
	for i, e := range res.Entries {
		if i < wantByAge && !e.Deleted {
			t.Fatalf("entry %d should be deleted: %+v", i, e)
		}
		if i >= wantByAge && e.Deleted {
			t.Fatalf("entry %d should be kept: %+v", i, e)
		}
	}
	if rep := VerifyAll(st); !rep.OK {
		t.Fatalf("verify after combined retention: %+v", rep.Segments)
	}
	// 增量校验：以最后一个被删段为锚点已不存在，应报错；以留存首段为锚点可继续。
	anchor := st.Segments()[0].ID
	inc := VerifyIncremental(st, anchor)
	if !inc.OK {
		t.Fatalf("incremental from retained anchor should pass: %+v", inc.Segments)
	}
	t.Logf("结果: 时间主导删除 %d 段、保留 %d 段，明细逐段可核对，全量+增量校验通过",
		len(res.Removed), len(res.Kept))
}

// TestRetentionConflictRejectsDeletion 覆盖业务：保留条件互相打架时明确拒绝，
// 不能悄悄把受保护数据删了当没事。
func TestRetentionConflictRejectsDeletion(t *testing.T) {
	t.Log("业务: 组合保留清理 | 用例: MinAge 要求保留与 MaxBytes 要求删除冲突时拒绝且不删任何数据")
	_, st := setupRetentionStore(t, 300, 30)
	now := baseTime().Add(2 * time.Hour)
	ageSealedSegments(t, st, now, time.Hour)

	// 所有段都在 MinAge 保护期内（最旧的才 1 小时多，MinAge 要留 24 小时），
	// 但 MaxBytes 小到必须删除 → 冲突。
	st.ret.MaxBytes = 1 // 几乎要删光
	st.ret.MinAge = 24 * time.Hour

	before := len(st.Segments())
	res, err := st.ApplyRetentionDetailed(now)
	if !errors.Is(err, ErrRetentionConflict) {
		t.Fatalf("want ErrRetentionConflict, got %v (res=%+v)", err, res)
	}
	if res == nil || !res.Conflict || res.ConflictMsg == "" {
		t.Fatalf("conflict result must explain: %+v", res)
	}
	if len(st.Segments()) != before || len(res.Removed) != 0 {
		t.Fatalf("conflict must not delete anything: before=%d after=%d", before, len(st.Segments()))
	}
	// 被保护的文件都还在且仍可校验。
	if rep := VerifyAll(st); !rep.OK {
		t.Fatalf("data must remain intact after rejected retention: %+v", rep.Segments)
	}
	t.Logf("结果: 检测到冲突并拒绝删除（%s），%d 段全部保留且校验通过", res.ConflictMsg, before)
}

// TestRetentionNoOpWhenWithinLimits 覆盖业务：本来就在限制内时一条都不该删，
// 但结果仍应可核对（避免“配了清理啥都没动”无法察觉）。
func TestRetentionNoOpWhenWithinLimits(t *testing.T) {
	t.Log("业务: 组合保留清理 | 用例: 未超限时 Removed 为空但结果完整、Kept 覆盖全部段")
	_, st := setupRetentionStore(t, 300, 30)
	now := baseTime().Add(time.Hour)
	res, err := st.ApplyRetentionDetailed(now)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Removed) != 0 || res.FreedBytes != 0 {
		t.Fatalf("nothing should be removed, got removed=%v freed=%d", res.Removed, res.FreedBytes)
	}
	if len(res.Kept) != len(st.Segments()) {
		t.Fatalf("kept %d, want %d", len(res.Kept), len(st.Segments()))
	}
	if len(res.Entries) != len(st.Segments()) {
		t.Fatalf("entries should cover all segments")
	}
	t.Logf("结果: 未超限无需删除，%d 段全部 retained，明细仍可核对", len(res.Kept))
}

// TestRetentionVerifyFullAndIncremental 覆盖业务：清理后全量与增量两种校验都要通过。
func TestRetentionVerifyFullAndIncremental(t *testing.T) {
	t.Log("业务: 组合保留清理 | 用例: 按空间清理后全量、增量校验均通过，留存事件可读")
	_, st := setupRetentionStore(t, 300, 40)
	segs := st.Segments()
	sizes := sealedSizes(t, st)
	// 保留最后 2 段。
	var cap int64
	cap += sizes[segs[len(segs)-1].ID] + sizes[segs[len(segs)-2].ID]
	st.ret.MaxBytes = cap

	if _, err := st.ApplyRetentionDetailed(baseTime().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	kept := st.Segments()
	if len(kept) != 2 {
		t.Fatalf("want 2 retained, got %d", len(kept))
	}
	if rep := VerifyAll(st); !rep.OK {
		t.Fatalf("full verify: %+v", rep.Segments)
	}
	// 增量：以留存的第一段为锚点，只校验其后。
	inc := VerifyIncremental(st, kept[0].ID)
	if !inc.OK || len(inc.Segments) != 1 {
		t.Fatalf("incremental verify: %+v", inc.Segments)
	}
	events, err := st.AllEvents()
	if err != nil {
		t.Fatal(err)
	}
	want := 0
	for _, seg := range kept {
		want += seg.Events
	}
	if len(events) != want {
		t.Fatalf("retained events %d, want %d", len(events), want)
	}
	t.Logf("结果: 留存 2 段 %d 事件，全量与增量校验通过", want)
}
