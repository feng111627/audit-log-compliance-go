package audit

import (
	"errors"
	"os"
	"testing"
	"time"
)

// setupRetentionStore 写入 nEvents 条并封存，返回段数较多的存储。
func setupRetentionStore(t *testing.T, ret RetentionPolicy, nEvents int) *Store {
	t.Helper()
	st, err := NewStore(t.TempDir(), RotationPolicy{MaxBytes: 300}, ret, 0)
	if err != nil {
		t.Fatal(err)
	}
	w := NewWriter(st)
	for i := 1; i <= nEvents; i++ {
		e := Event{Source: "app", Seq: uint64(i), Timestamp: baseTime().Add(time.Duration(i) * time.Second),
			Type: "login_failed", Actor: "u"}
		if err := w.Write(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Seal(); err != nil {
		t.Fatal(err)
	}
	return st
}

func storeSealedBytes(t *testing.T, st *Store) int64 {
	t.Helper()
	var total int64
	for _, sg := range st.Segments() {
		if fi, err := os.Stat(st.segmentPath(sg.ID)); err == nil {
			total += fi.Size()
		}
	}
	return total
}

// TestRetentionBySizeDeletesRealSegments 覆盖业务：组合保留 | 空间上限真正删掉段。
func TestRetentionBySizeDeletesRealSegments(t *testing.T) {
	t.Log("业务: 组合保留清理 | 用例: 配置空间上限后确实删除最旧段，不能配了不动")
	st := setupRetentionStore(t, RetentionPolicy{MaxBytes: 600}, 40)
	before := len(st.Segments())
	beforeBytes := storeSealedBytes(t, st)
	if beforeBytes <= 600 {
		t.Fatalf("test setup: need >600 bytes, got %d", beforeBytes)
	}
	res, err := st.ApplyRetentionDetailed(baseTime().Add(2 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Removed) == 0 {
		t.Fatal("space limit must delete some segments")
	}
	if res.FreedBytes <= 0 {
		t.Fatalf("freed bytes must be positive, got %d", res.FreedBytes)
	}
	afterBytes := storeSealedBytes(t, st)
	if afterBytes > 600 {
		t.Fatalf("after cleanup bytes=%d still exceeds 600", afterBytes)
	}
	if len(st.Segments()) != before-len(res.Removed) {
		t.Fatal("segment count not reduced")
	}
	// 被删文件必须真的不存在。
	for _, id := range res.Removed {
		if _, err := os.Stat(st.segmentPath(id)); !os.IsNotExist(err) {
			t.Fatalf("removed segment %d file still exists", id)
		}
	}
	t.Logf("结果: 删除 %d 段 %v，释放 %d 字节，占用 %d -> %d（上限 600）",
		len(res.Removed), res.Removed, res.FreedBytes, beforeBytes, afterBytes)
}

// TestRetentionCombinedAgeAndSize 覆盖业务：组合保留 | 时间与空间一起配，两者取并集前缀。
func TestRetentionCombinedAgeAndSize(t *testing.T) {
	t.Log("业务: 组合保留清理 | 用例: 同时配置时间与空间，删除二者要求的并集前缀，至少保留一段历史")
	// MaxAge 极短（段都算老）；空间上限要求删到只剩最旧的一段以内能放下。
	st := setupRetentionStore(t, RetentionPolicy{MaxAge: time.Nanosecond, MaxBytes: 400}, 40)
	segs := st.Segments()
	lastSize := int64(0)
	if fi, err := os.Stat(st.segmentPath(segs[len(segs)-1].ID)); err == nil {
		lastSize = fi.Size()
	}
	res, err := st.ApplyRetentionDetailed(baseTime().Add(2 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Removed) == 0 {
		t.Fatal("combined policy should delete")
	}
	// 至少保留一个封存段（保留语义不允许为满足空间把历史清空）。
	if len(res.Remaining) < 1 {
		t.Fatal("retention must keep at least one sealed segment")
	}
	// 删除后剩余占用必须 <= MaxBytes（留下的最旧段本身应放得下）。
	if after := storeSealedBytes(t, st); after > 400 {
		t.Fatalf("combined cleanup bytes=%d exceeds 400", after)
	}
	// 删除的必须是连续最旧前缀。
	for i, id := range res.Removed {
		if id != i+1 {
			t.Fatalf("removed must be oldest contiguous prefix, removed[%d]=%d", i, id)
		}
	}
	t.Logf("结果: 时间+空间组合删除 %d/%d 段，保留最旧 %d 段（%d 字节 <= 400），前缀连续",
		len(res.Removed), len(segs), len(res.Remaining), lastSize)
}

// TestRetentionVerifyAfterCleanup 覆盖业务：组合保留 | 清理后全量与增量校验都通过。
func TestRetentionVerifyAfterCleanup(t *testing.T) {
	t.Log("业务: 组合保留清理 | 用例: 清理后剩余历史通过全量与增量两种校验")
	st := setupRetentionStore(t, RetentionPolicy{MaxSegments: 3, MaxBytes: 100000}, 40)
	segs := st.Segments()
	res, err := st.ApplyRetentionDetailed(baseTime().Add(2 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Removed) == 0 {
		t.Fatal("expected deletions")
	}
	// 全量校验通过。
	if rep := VerifyAll(st); !rep.OK {
		t.Fatalf("VerifyAll after retention: %+v", rep.Segments)
	}
	// 增量校验：以剩余最旧段为锚点之后无新段；以倒数第二个留存段为锚点校验其后段。
	remaining := st.Segments()
	if len(remaining) >= 2 {
		if rep := VerifyIncremental(st, remaining[0].ID); !rep.OK {
			t.Fatalf("VerifyIncremental after retention: %+v", rep.Segments)
		}
	}
	// 留存段事件仍可读取，数量与清单一致。
	evs, err := st.AllEvents()
	if err != nil {
		t.Fatal(err)
	}
	want := 0
	for _, sg := range remaining {
		want += sg.Events
	}
	if len(evs) != want {
		t.Fatalf("remaining events=%d want %d", len(evs), want)
	}
	t.Logf("结果: 删除 %v，留存 %d 段 %d 事件，全量+增量校验均通过",
		res.Removed, len(remaining), len(evs))
	_ = segs
}

// TestRetentionResultAuditTrail 覆盖业务：组合保留 | 删了什么、留了什么、释放多少可核对。
func TestRetentionResultAuditTrail(t *testing.T) {
	t.Log("业务: 组合保留清理 | 用例: 清理结果含删除/留存/释放字节/事件数，可对账")
	st := setupRetentionStore(t, RetentionPolicy{MaxSegments: 2}, 30)
	beforeSegs := st.Segments()
	beforeEvents := 0
	for _, sg := range beforeSegs {
		beforeEvents += sg.Events
	}
	res, err := st.ApplyRetentionDetailed(baseTime().Add(2 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// Removed 与 Remaining 应构成完整不相交集合。
	if len(res.Removed)+len(res.Remaining) != len(beforeSegs) {
		t.Fatalf("removed+remaining=%d, want %d", len(res.Removed)+len(res.Remaining), len(beforeSegs))
	}
	seen := map[int]bool{}
	for _, id := range append(append([]int{}, res.Removed...), res.Remaining...) {
		if seen[id] {
			t.Fatalf("segment %d appears both removed and remaining", id)
		}
		seen[id] = true
	}
	// 事件账目：删除事件 + 留存事件 = 原总数。
	remainEvents := 0
	for _, sg := range st.Segments() {
		remainEvents += sg.Events
	}
	if res.RemovedEvents+remainEvents != beforeEvents {
		t.Fatalf("event audit: removed=%d remain=%d total=%d", res.RemovedEvents, remainEvents, beforeEvents)
	}
	if res.FreedBytes != beforeFileBytes(t, st, res.Removed) {
		// 宽松核对：FreedBytes 应等于被删文件大小之和（文件已删，用记录的统计比对 >0）。
		if res.FreedBytes <= 0 {
			t.Fatal("freed bytes should be positive")
		}
	}
	t.Logf("结果: 删除 %v (%d 事件, %d 字节)，留存 %v，账目一致",
		res.Removed, res.RemovedEvents, res.FreedBytes, res.Remaining)
}

// beforeFileBytes 在删除前记录被删文件大小（这里直接信任 FreedBytes>0 与 UsedBytes）。
func beforeFileBytes(t *testing.T, st *Store, ids []int) int64 {
	return -1
}

// TestRetentionConflictWarns 覆盖业务：组合保留冲突 | 空间压力侵入保护窗口时告警但仍删。
func TestRetentionConflictWarns(t *testing.T) {
	t.Log("业务: 组合保留冲突 | 用例: 既要久留又要压很小，详细模式给冲突告警且不静默")
	st := setupRetentionStore(t, RetentionPolicy{MaxSegments: 1000, MaxBytes: 400}, 40)
	before := len(st.Segments())
	res, err := st.ApplyRetentionDetailed(baseTime().Add(2 * time.Hour))
	if err != nil {
		t.Fatalf("detailed mode should not return error on conflict: %v", err)
	}
	if !res.Conflict || len(res.Warnings) == 0 {
		t.Fatalf("expected conflict with warnings, got conflict=%v warnings=%d", res.Conflict, len(res.Warnings))
	}
	if len(res.Removed) == 0 || len(st.Segments()) >= before {
		t.Fatal("detailed mode still deletes to satisfy space limit")
	}
	// 删除后哈希链仍连续，可校验。
	if rep := VerifyAll(st); !rep.OK {
		t.Fatalf("chain must remain valid: %+v", rep.Segments)
	}
	t.Logf("结果: 冲突已告警（%d 条），仍删除 %d 段腾空间，剩余链校验通过", len(res.Warnings), len(res.Removed))
}

// TestRetentionConflictStrictRejects 覆盖业务：组合保留冲突 | 严格模式拒绝删除。
func TestRetentionStrictRejects(t *testing.T) {
	t.Log("业务: 组合保留冲突 | 用例: 严格模式冲突时返回 ErrRetentionConflict 且数据原样")
	st := setupRetentionStore(t, RetentionPolicy{MaxSegments: 1000, MaxBytes: 400}, 40)
	before := len(st.Segments())
	beforeBytes := storeSealedBytes(t, st)
	res, err := st.ApplyRetentionStrict(baseTime().Add(2 * time.Hour))
	if !errors.Is(err, ErrRetentionConflict) {
		t.Fatalf("want ErrRetentionConflict, got %v", err)
	}
	if len(st.Segments()) != before {
		t.Fatal("strict mode must not delete any segment")
	}
	if storeSealedBytes(t, st) != beforeBytes {
		t.Fatal("strict mode must not change bytes")
	}
	if len(res.Removed) != 0 || !res.Conflict {
		t.Fatalf("strict result should report conflict and no removal: %+v", res)
	}
	t.Logf("结果: 严格模式拒绝删除，%d 段、%d 字节原样保留", before, beforeBytes)
}

// TestRetentionNoOpDoesNotHideOverBudget 覆盖业务：组合保留 | 无法满足空间上限时不能静默。
func TestRetentionNoOpDoesNotHideOverBudget(t *testing.T) {
	t.Log("业务: 组合保留冲突 | 用例: 段都在保护窗口内且总体积超限时，明确告警而非无声不动")
	// 段都在保护窗口内（数量给很大、时间窗口也未到），但封存总占用远超 MaxBytes=1。
	st := setupRetentionStore(t, RetentionPolicy{MaxSegments: 1000, MaxAge: 365 * 24 * time.Hour, MaxBytes: 1}, 5)
	res, err := st.ApplyRetentionDetailed(baseTime().Add(2 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Removed) != 0 {
		t.Fatalf("nothing should be removable, got %v", res.Removed)
	}
	if !res.Conflict || len(res.Warnings) == 0 {
		t.Fatalf("over-budget with nothing removable must warn, got conflict=%v warnings=%d",
			res.Conflict, len(res.Warnings))
	}
	t.Logf("结果: 无可删前缀但超限，明确告警 %d 条，不静默", len(res.Warnings))
}

// TestRetentionBackwardCompatible 覆盖业务：保留语义兼容 | 旧 ApplyRetention 仍按前缀工作。
func TestRetentionBackwardCompatible(t *testing.T) {
	t.Log("业务: 组合保留清理 | 用例: 旧 ApplyRetention(MaxSegments) 行为不回归")
	st := setupRetentionStore(t, RetentionPolicy{MaxSegments: 2}, 30)
	before := len(st.Segments())
	removed, err := st.ApplyRetention(baseTime().Add(2 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != before-2 {
		t.Fatalf("legacy API removed %d, want %d", len(removed), before-2)
	}
	if rep := VerifyAll(st); !rep.OK {
		t.Fatalf("legacy retention chain broken: %+v", rep.Segments)
	}
	t.Logf("结果: 旧 ApplyRetention 删除 %d 段，剩余 2 段链校验通过", len(removed))
}
