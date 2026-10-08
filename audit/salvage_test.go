package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// setupSalvageStore 构造含多个封存段（成组提交格式）+ 已全部封存的存储。
func setupSalvageStore(t *testing.T, nEvents int) (string, *Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := NewStore(dir, RotationPolicy{MaxBytes: 260}, RetentionPolicy{}, 0)
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
	return dir, st
}

// findIssue 在单段报告中查找指定分类的问题。
func findIssue(rep SegmentSalvageReport, kind IssueKind) (SegmentIssue, bool) {
	for _, iss := range rep.Issues {
		if iss.Kind == kind {
			return iss, true
		}
	}
	return SegmentIssue{}, false
}

func issueKinds(rep IntegrityReport) map[IssueKind]bool {
	m := map[IssueKind]bool{}
	for _, iss := range rep.Issues {
		m[iss.Kind] = true
	}
	return m
}

// TestSalvageHealthy 覆盖业务：部分损坏容忍读取 | 健康数据全部可信。
func TestSalvageHealthy(t *testing.T) {
	t.Log("业务: 部分损坏时的读取与报告 | 用例: 未损坏时全部段可信、事件全量捞回")
	_, st := setupSalvageStore(t, 12)
	rep := SalvageAll(st)
	totalEvents := 0
	for _, sr := range rep.Segments {
		if !sr.Trusted {
			t.Fatalf("segment %d should be trusted: %+v", sr.SegmentID, sr.Issues)
		}
		totalEvents += sr.Salvaged
	}
	if totalEvents != 12 {
		t.Fatalf("salvaged %d events, want 12", totalEvents)
	}
	if !rep.IncrementalCanContinue || rep.NextAnchorID == 0 {
		t.Fatalf("healthy store should allow incremental continue: %+v", rep)
	}
	t.Logf("结果: 全部段可信，捞回 %d 事件，增量锚点=%d", totalEvents, rep.NextAnchorID)
}

// TestSalvageTamperedBatch 覆盖业务：部分损坏容忍读取 | 批次内容被改可定位分类。
func TestSalvageTamperedBatch(t *testing.T) {
	t.Log("业务: 部分损坏时的读取与报告 | 用例: 篡改某段批次，识别为 record_tampered 且隔离不影响其他段")
	_, st := setupSalvageStore(t, 12)
	segs := st.Segments()
	target := segs[len(segs)/2].ID

	// 翻转提交标记行里的一个十六进制字符（破坏 digest/prev 字段），行仍有换行。
	p := st.segmentPath(target)
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-25] ^= 0x01 // 落在 marker 的摘要字段内
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}

	srep := SalvageSegment(st, target)
	if srep.Trusted {
		t.Fatal("tampered segment must not be trusted")
	}
	iss, ok := findIssue(srep, IssueTampered)
	if !ok {
		t.Fatalf("expected record_tampered issue, got %+v", srep.Issues)
	}
	if iss.SegmentID != target || iss.Line < 1 || iss.Offset < 0 {
		t.Fatalf("issue location wrong: %+v", iss)
	}

	all := SalvageAll(st)
	kinds := issueKinds(all)
	if !kinds[IssueTampered] {
		t.Fatal("aggregated report must include record_tampered")
	}
	// 其他未损坏段的事件仍应全部捞回。
	goodEvents := 0
	for _, sr := range all.Segments {
		if sr.SegmentID != target && sr.Trusted {
			goodEvents += sr.Salvaged
		}
	}
	wantGood := 0
	for _, sg := range segs {
		if sg.ID != target {
			wantGood += sg.Events
		}
	}
	if goodEvents != wantGood {
		t.Fatalf("good segments events=%d want %d", goodEvents, wantGood)
	}
	// 仍存在内容完好的封存段 => 增量可继续，且锚点不是坏段。
	if !all.IncrementalCanContinue || all.NextAnchorID == target {
		t.Fatalf("incremental anchor invalid: continue=%v anchor=%d", all.IncrementalCanContinue, all.NextAnchorID)
	}
	t.Logf("结果: 段 %d 定位为 record_tampered（行 %d，偏移 %d），其他 %d 条好数据全部捞回，新锚点=%d",
		target, iss.Line, iss.Offset, goodEvents, all.NextAnchorID)
}

// TestSalvageTruncatedTail 覆盖业务：部分损坏容忍读取 | 尾部截短分类与定位。
func TestSalvageTruncatedTail(t *testing.T) {
	t.Log("业务: 部分损坏时的读取与报告 | 用例: 尾部截断识别为 truncated_tail，坏尾前数据仍可信")
	dir, st := setupSalvageStore(t, 12)
	segs := st.Segments()
	target := segs[len(segs)-1].ID
	p := filepath.Join(dir, segmentFileName(target))
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	// 截掉后半段（可能落在提交标记或事件中间），且无换行收尾。
	if err := os.WriteFile(p, data[:len(data)/2], 0o644); err != nil {
		t.Fatal(err)
	}

	srep := SalvageSegment(st, target)
	if srep.Trusted {
		t.Fatal("truncated segment must not be trusted")
	}
	if _, ok := findIssue(srep, IssueTruncatedTail); !ok {
		t.Fatalf("expected truncated_tail issue, got %+v", srep.Issues)
	}
	t.Logf("结果: 段 %d 尾部截断识别为 truncated_tail，段内问题数=%d", target, len(srep.Issues))
}

// TestSalvageMissingSegment 覆盖业务：部分损坏容忍读取 | 整段缺失分类。
func TestSalvageMissingSegment(t *testing.T) {
	t.Log("业务: 部分损坏时的读取与报告 | 用例: 删除整段文件识别为 segment_missing，其余段可读")
	_, st := setupSalvageStore(t, 12)
	segs := st.Segments()
	target := segs[0].ID
	if err := os.Remove(st.segmentPath(target)); err != nil {
		t.Fatal(err)
	}
	srep := SalvageSegment(st, target)
	if _, ok := findIssue(srep, IssueMissing); !ok {
		t.Fatalf("expected segment_missing, got %+v", srep.Issues)
	}
	all := SalvageAll(st)
	if !issueKinds(all)[IssueMissing] {
		t.Fatal("aggregated report must include segment_missing")
	}
	// 其余段仍然可信。
	for _, sr := range all.Segments {
		if sr.SegmentID == target {
			continue
		}
		if !sr.Trusted {
			t.Fatalf("unaffected segment %d should be trusted", sr.SegmentID)
		}
	}
	t.Logf("结果: 缺失段 %d 识别为 segment_missing，其余段全部可信", target)
}

// TestSalvageCorruptRecord 覆盖业务：部分损坏容忍读取 | 记录内部结构损坏分类。
func TestSalvageCorruptRecord(t *testing.T) {
	t.Log("业务: 部分损坏时的读取与报告 | 用例: 旧格式段中插入坏 JSON 行识别为 record_corrupt 且后续可读")
	dir := t.TempDir()
	// 先打开创建目录，随后直接在磁盘上构造「好行、坏行、好行」的旧格式段文件，
	// 绕过打开时的自动恢复（容忍读取要分析的是磁盘上现存的损坏文件）。
	st, err := NewStore(dir, RotationPolicy{}, RetentionPolicy{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	id := st.ActiveSegmentID()
	p := st.segmentPath(id)
	good1, _ := json.Marshal(Event{Source: "x", Seq: 1, Timestamp: baseTime(), Type: "a"})
	good2, _ := json.Marshal(Event{Source: "x", Seq: 2, Timestamp: baseTime(), Type: "a"})
	content := string(good1) + "\n{not-json\n" + string(good2) + "\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	srep := SalvageSegment(st, id)
	if srep.Trusted {
		t.Fatal("segment with corrupt record must not be trusted")
	}
	iss, ok := findIssue(srep, IssueCorrupt)
	if !ok {
		t.Fatalf("expected record_corrupt, got %+v", srep.Issues)
	}
	if iss.Line != 2 {
		t.Fatalf("corrupt record should be located at line 2, got line %d", iss.Line)
	}
	// 坏行前后两条好记录仍被捞回（不因为一行坏就整段读不出）。
	if srep.Salvaged != 2 {
		t.Fatalf("should salvage 2 good records around corrupt line, got %d", srep.Salvaged)
	}
	t.Logf("结果: 旧格式段第 %d 行识别为 record_corrupt，坏行前后 2 条好记录仍捞回", iss.Line)
}

// TestSalvageActiveTruncated 覆盖业务：部分损坏容忍读取 | 活跃段尾部半成品分类。
func TestSalvageActiveTruncated(t *testing.T) {
	t.Log("业务: 部分损坏时的读取与报告 | 用例: 活跃段末尾未提交批次识别为 truncated_tail")
	dir := t.TempDir()
	st, _ := NewStore(dir, RotationPolicy{}, RetentionPolicy{}, 0)
	w := NewWriter(st)
	for i := uint64(1); i <= 3; i++ {
		if err := w.Write(Event{Source: "a", Seq: i, Timestamp: baseTime(), Type: "login_failed"}); err != nil {
			t.Fatal(err)
		}
	}
	// 追加没有提交标记收尾的事件行。
	appendRawToActive(t, st, `{"source":"a","seq":4,"timestamp":"2026-10-06T00:00:00Z","type":"x"}`+"\n")
	active := st.ActiveSegmentID()
	srep := SalvageSegment(st, active)
	if srep.Trusted {
		t.Fatal("active with uncommitted tail must not be trusted")
	}
	if _, ok := findIssue(srep, IssueTruncatedTail); !ok {
		t.Fatalf("expected truncated_tail for dangling batch, got %+v", srep.Issues)
	}
	// 已提交的 3 条仍捞回。
	if srep.Salvaged != 3 {
		t.Fatalf("committed events salvaged=%d want 3", srep.Salvaged)
	}
	t.Logf("结果: 活跃段未提交批次识别为 truncated_tail，已提交 %d 条仍捞回", srep.Salvaged)
}

// TestSalvageIncrementalAnchor 覆盖业务：部分损坏容忍读取 | 增量校验能否继续。
func TestSalvageIncrementalAnchor(t *testing.T) {
	t.Log("业务: 部分损坏时的读取与报告 | 用例: 尾段损坏时锚点指向倒数第二个好段；全部损坏则不可继续")
	_, st := setupSalvageStore(t, 12)
	segs := st.Segments()
	last := segs[len(segs)-1].ID

	// 破坏最后一个封存段。
	p := st.segmentPath(last)
	data, _ := os.ReadFile(p)
	data[len(data)/2] ^= 0xFF
	os.WriteFile(p, data, 0o644)
	rep := SalvageAll(st)
	wantAnchor := segs[len(segs)-2].ID
	if !rep.IncrementalCanContinue || rep.NextAnchorID != wantAnchor {
		t.Fatalf("anchor=%d want %d, continue=%v", rep.NextAnchorID, wantAnchor, rep.IncrementalCanContinue)
	}
	t.Logf("结果: 尾段 %d 损坏，增量锚点回退到完好段 %d，可继续增量校验", last, rep.NextAnchorID)

	// 删掉所有封存段文件 => 没有好锚点，不可继续。
	_, st2 := setupSalvageStore(t, 6)
	for _, sg := range st2.Segments() {
		os.Remove(st2.segmentPath(sg.ID))
	}
	rep2 := SalvageAll(st2)
	if rep2.IncrementalCanContinue || rep2.NextAnchorID != 0 {
		t.Fatalf("all segments missing: continue=%v anchor=%d, want false/0",
			rep2.IncrementalCanContinue, rep2.NextAnchorID)
	}
	t.Log("结果: 所有封存段缺失时 IncrementalCanContinue=false、NextAnchorID=0")
}
