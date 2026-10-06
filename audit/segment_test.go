package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeNEvents 向存储写入 n 条事件（单来源，时间间隔 1s）。
func writeNEvents(t *testing.T, w *Writer, src string, n int, start time.Time) {
	t.Helper()
	for i := 1; i <= n; i++ {
		e := Event{
			Source:    src,
			Seq:       uint64(i),
			Timestamp: start.Add(time.Duration(i) * time.Second),
			Type:      "login_failed",
			Actor:     "u",
		}
		if err := w.Write(e); err != nil {
			t.Fatalf("write seq %d: %v", i, err)
		}
	}
}

// TestRotationBySizeAndTime 覆盖业务：按大小与按时间轮转。
func TestRotationBySizeAndTime(t *testing.T) {
	t.Log("业务: 段落轮转 | 用例: 大小轮转与时间轮转均产生多个封存段")
	// 大小轮转。
	dir := t.TempDir()
	store, err := NewStore(dir, RotationPolicy{MaxBytes: 500}, RetentionPolicy{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	w := NewWriter(store)
	writeNEvents(t, w, "app", 30, baseTime())
	if err := store.Seal(); err != nil {
		t.Fatal(err)
	}
	segs := store.Segments()
	if len(segs) < 2 {
		t.Fatalf("size rotation: got %d segments, want >= 2", len(segs))
	}
	total := 0
	for _, seg := range segs {
		total += seg.Events
	}
	if total != 30 {
		t.Fatalf("sealed events total %d, want 30", total)
	}
	t.Logf("结果: 大小轮转产生 %d 段，共 %d 事件", len(segs), total)

	// 时间轮转：窗口 10s，事件间隔 1s，30 条事件应产生多段。
	store2, err := NewStore(t.TempDir(), RotationPolicy{MaxAge: 10 * time.Second}, RetentionPolicy{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	w2 := NewWriter(store2)
	writeNEvents(t, w2, "app", 30, baseTime())
	if err := store2.Seal(); err != nil {
		t.Fatal(err)
	}
	segs2 := store2.Segments()
	if len(segs2) < 3 {
		t.Fatalf("time rotation: got %d segments, want >= 3", len(segs2))
	}
	t.Logf("结果: 时间轮转产生 %d 段", len(segs2))
}

// TestRetentionThenVerify 覆盖业务：保留清理后剩余数据仍可验证。
func TestRetentionThenVerify(t *testing.T) {
	t.Log("业务: 保留与完整性校验 | 用例: 按数量清理旧段后，剩余段落全量校验通过")
	dir := t.TempDir()
	store, err := NewStore(dir, RotationPolicy{MaxBytes: 300}, RetentionPolicy{MaxSegments: 2}, 0)
	if err != nil {
		t.Fatal(err)
	}
	w := NewWriter(store)
	writeNEvents(t, w, "app", 40, baseTime())
	if err := store.Seal(); err != nil {
		t.Fatal(err)
	}
	before := store.Segments()
	if len(before) < 4 {
		t.Fatalf("setup: got %d segments, want >= 4", len(before))
	}
	removed, err := store.ApplyRetention(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) == 0 {
		t.Fatal("expected some segments removed")
	}
	// 被清理的应是最旧的连续前缀。
	for i, id := range removed {
		if id != before[i].ID {
			t.Fatalf("removed[%d]=%d, want prefix id %d", i, id, before[i].ID)
		}
	}
	rep := VerifyAll(store)
	if !rep.OK {
		t.Fatalf("verify after retention failed: %+v", rep.Segments)
	}
	// 剩余事件仍可读取且数量正确。
	events, err := store.AllEvents()
	if err != nil {
		t.Fatal(err)
	}
	want := 0
	for _, seg := range store.Segments() {
		want += seg.Events
	}
	if len(events) != want {
		t.Fatalf("remaining events %d, want %d", len(events), want)
	}
	t.Logf("结果: 清理最旧 %d 段（ID %v），剩余 %d 段校验通过、%d 事件可读",
		len(removed), removed, len(store.Segments()), len(events))
}

// corruptSegment 用给定方式破坏指定段文件。
func corruptSegment(t *testing.T, dir string, id int, mode string) {
	t.Helper()
	path := filepath.Join(dir, segmentFileName(id))
	switch mode {
	case "tamper":
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		data[len(data)/2] ^= 0xFF // 原地翻转一字节，保持行数不变
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	case "truncate":
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data[:len(data)/2], 0o644); err != nil {
			t.Fatal(err)
		}
	case "missing":
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
}

// setupSealedStore 创建含 3 个封存段的存储。
func setupSealedStore(t *testing.T) (string, *Store) {
	t.Helper()
	dir := t.TempDir()
	store, err := NewStore(dir, RotationPolicy{MaxBytes: 300}, RetentionPolicy{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	w := NewWriter(store)
	writeNEvents(t, w, "app", 30, baseTime())
	if err := store.Seal(); err != nil {
		t.Fatal(err)
	}
	if got := len(store.Segments()); got < 3 {
		t.Fatalf("setup: got %d segments, want >= 3", got)
	}
	return dir, store
}

// TestVerifyDetectsCorruption 覆盖业务：篡改/截断/缺失段落在全量与增量校验下可区分。
func TestVerifyDetectsCorruption(t *testing.T) {
	t.Log("业务: 完整性校验 | 用例: 篡改/截断/缺失三种破坏在全量与增量校验下给出可区分原因")
	cases := []struct {
		mode   string
		reason VerifyReason
	}{
		{"tamper", ReasonTampered},
		{"truncate", ReasonTruncated},
		{"missing", ReasonSegmentMissing},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			dir, store := setupSealedStore(t)
			target := store.Segments()[1].ID // 破坏中间段
			corruptSegment(t, dir, target, tc.mode)

			full := VerifyAll(store)
			if full.OK {
				t.Fatalf("full verify should fail after %s", tc.mode)
			}
			assertReason(t, full, target, tc.reason, "full")

			incr := VerifyIncremental(store, 0)
			if incr.OK {
				t.Fatalf("incremental verify should fail after %s", tc.mode)
			}
			assertReason(t, incr, target, tc.reason, "incremental")
			t.Logf("结果: %s 破坏被全量与增量校验识别为 %s", tc.mode, tc.reason)
		})
	}
}

func assertReason(t *testing.T, rep VerifyReport, segID int, want VerifyReason, label string) {
	t.Helper()
	for _, sr := range rep.Segments {
		if sr.SegmentID == segID {
			if sr.Reason != want {
				t.Fatalf("%s verify segment %d: reason %s, want %s (%s)",
					label, segID, sr.Reason, want, sr.Detail)
			}
			return
		}
	}
	t.Fatalf("%s verify: no report for segment %d", label, segID)
}

// TestIncrementalVerifyChain 覆盖业务：增量校验的哈希链锚定。
func TestIncrementalVerifyChain(t *testing.T) {
	t.Log("业务: 完整性校验 | 用例: 增量校验锚定上一封存段，链断裂可识别")
	dir, store := setupSealedStore(t)
	segs := store.Segments()

	// 正常增量校验：锚定第 1 段，校验后续段。
	rep := VerifyIncremental(store, segs[0].ID)
	if !rep.OK {
		t.Fatalf("incremental verify failed: %+v", rep.Segments)
	}
	for _, sr := range rep.Segments {
		if sr.SegmentID <= segs[0].ID {
			t.Fatalf("incremental verify should skip segment %d", sr.SegmentID)
		}
	}

	// 破坏 manifest 中第 2 段的 prev_hash，模拟链断裂。
	mPath := filepath.Join(dir, "manifest.json")
	data, err := os.ReadFile(mPath)
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	m.Segments[1].PrevHash = strings.Repeat("0", 64)
	fixed, _ := json.Marshal(m)
	if err := os.WriteFile(mPath, fixed, 0o644); err != nil {
		t.Fatal(err)
	}
	store2, err := NewStore(dir, RotationPolicy{MaxBytes: 300}, RetentionPolicy{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	rep2 := VerifyIncremental(store2, segs[0].ID)
	if rep2.OK {
		t.Fatal("expected chain_broken")
	}
	assertReason(t, rep2, segs[1].ID, ReasonChainBroken, "incremental")
	t.Log("结果: 增量校验仅覆盖新段；prev_hash 被篡改时识别为 chain_broken")
}
