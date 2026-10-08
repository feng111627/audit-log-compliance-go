package audit

import (
	"os"
	"path/filepath"
	"testing"
)

// corruptLineAt 用给定模式破坏封存段，返回受影响物理行范围信息。
func corruptLineAt(t *testing.T, dir string, id int, mode string) {
	t.Helper()
	path := filepath.Join(dir, segmentFileName(id))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	switch mode {
	case "record":
		// 记录内部结构损坏：把第二条完整 JSON 行替换成无法解析的内容，保持行数不变。
		lines := splitLines(data)
		if len(lines) < 2 {
			t.Fatalf("segment %d has %d lines, need >=2", id, len(lines))
		}
		lines[1] = []byte("{this-is-not-json")
		os.WriteFile(path, joinLines(lines), 0o644)
	case "truncate-tail":
		// 尾部截短：保留第一条完整行，截掉其余（尾部无换行或整行丢失）。
		lines := splitLines(data)
		if len(lines) < 2 {
			t.Fatalf("segment %d has %d lines, need >=2", id, len(lines))
		}
		keep := append([]byte{}, lines[0]...)
		keep = append(keep, '\n')
		// 再拼上第二行的前半段，制造“写到一半”的无换行尾行。
		half := len(lines[1]) / 2
		keep = append(keep, lines[1][:half]...)
		os.WriteFile(path, keep, 0o644)
	case "tamper":
		// 内容被外部改动：合法 JSON 但字段值变化，行数不变。
		out := replaceFirst(data, []byte(`"actor":"u"`), []byte(`"actor":"X"`))
		os.WriteFile(path, out, 0o644)
	case "missing":
		os.Remove(path)
	}
}

func splitLines(data []byte) [][]byte {
	var out [][]byte
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			out = append(out, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		out = append(out, data[start:])
	}
	return out
}

func joinLines(lines [][]byte) []byte {
	var out []byte
	for _, l := range lines {
		out = append(out, l...)
		out = append(out, '\n')
	}
	return out
}

func replaceFirst(s, old, repl []byte) []byte {
	idx := indexBytes(s, old)
	if idx < 0 {
		// 兜底翻转一个字符串区字节。
		s[len(s)/2] ^= 0x01
		return s
	}
	return append(append(append([]byte{}, s[:idx]...), repl...), s[idx+len(old):]...)
}

func indexBytes(s, sub []byte) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if string(s[i:i+len(sub)]) == string(sub) {
			return i
		}
	}
	return -1
}

// TestSalvageDamageClassification 覆盖业务：部分损坏时读取与报告。
// 四类情况（结构损坏 / 尾部截短 / 内容被外部改动 / 整段缺失）必须给出不同原因，
// 且其它段落的事件仍能抢救出来，不能一坏整批读不出。
func TestSalvageDamageClassification(t *testing.T) {
	t.Log("业务: 部分损坏抢救与完整性报告 | 用例: 四类损坏原因可区分，其余历史仍可读出")
	cases := []struct {
		mode string
		want VerifyReason
	}{
		{"record", ReasonRecordCorrupt},
		{"truncate-tail", ReasonTruncated},
		{"tamper", ReasonTampered},
		{"missing", ReasonSegmentMissing},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			dir, store := setupSealedStore(t)
			segs := store.Segments()
			target := segs[1].ID
			// 统计损坏前全部可信事件数（其它段 + 目标段）。
			corruptLineAt(t, dir, target, tc.mode)

			rep, err := Salvage(store, SalvageOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if rep.OK {
				t.Fatalf("%s: Salvage.OK should be false", tc.mode)
			}
			var got *SegmentSalvage
			for i := range rep.Segments {
				if rep.Segments[i].SegmentID == target {
					got = &rep.Segments[i]
				}
			}
			if got == nil {
				t.Fatalf("%s: no report for target segment %d", tc.mode, target)
			}
			if got.Reason != tc.want {
				t.Fatalf("%s: reason %s, want %s (%s)", tc.mode, got.Reason, tc.want, got.Detail)
			}
			// 其它未损坏段落必须仍有可信事件被抢救。
			otherGood := 0
			for _, sal := range rep.Segments {
				if sal.SegmentID != target && sal.Reason == ReasonOK {
					otherGood += sal.Good
				}
			}
			if otherGood == 0 {
				t.Fatalf("%s: healthy segments should still yield events", tc.mode)
			}
			// record / truncate / tamper 情况下，目标段里结构仍完好的行应被尽力读出。
			if tc.mode != "missing" && len(got.Events) == 0 {
				t.Fatalf("%s: expected salvageable events in damaged segment", tc.mode)
			}
			if tc.mode == "record" {
				if len(got.Issues) == 0 {
					t.Fatalf("record damage must report line-level issue")
				}
				if got.Issues[0].Line != 2 || got.Issues[0].Reason != ReasonRecordCorrupt {
					t.Fatalf("record issue should point to line 2: %+v", got.Issues[0])
				}
				// 结构损坏段抢救出的事件可信度必须降级。
				for _, se := range got.Events {
					if se.Trust != TrustSalvaged {
						t.Fatalf("salvaged event trust=%s, want salvaged", se.Trust)
					}
				}
			}
			t.Logf("结果: %s -> %s（%s）；其它段抢救出 %d 条可信事件，目标段抢救 %d 条",
				tc.mode, got.Reason, got.Detail, otherGood, len(got.Events))
		})
	}
}

// TestSalvageTrustedVsSalvaged 覆盖业务：完整性报告需区分哪些数据仍可信。
func TestSalvageTrustedVsSalvaged(t *testing.T) {
	t.Log("业务: 部分损坏抢救与完整性报告 | 用例: 可信事件(salvaged)与已验证事件(verified)分开报告")
	dir, store := setupSealedStore(t)
	target := store.Segments()[1].ID
	corruptLineAt(t, dir, target, "record")

	rep, err := Salvage(store, SalvageOptions{IncludeActive: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.TrustedEvents) == 0 {
		t.Fatal("expected some verified events from healthy segments")
	}
	hasVerified, hasSalvaged := false, false
	for _, se := range rep.Events {
		switch se.Trust {
		case TrustVerified:
			hasVerified = true
		case TrustSalvaged:
			hasSalvaged = true
		}
	}
	if !hasVerified {
		t.Fatal("healthy segments' events must be marked verified")
	}
	if !hasSalvaged {
		t.Fatal("damaged segment's good lines should be marked salvaged")
	}
	// verified 事件必须等于健康段好行总数（不能把损坏段事件算成 verified）。
	healthyVerified := 0
	for _, sal := range rep.Segments {
		if sal.SegmentID != target && sal.Reason == ReasonOK {
			healthyVerified += sal.Good
		}
	}
	if len(rep.TrustedEvents) != healthyVerified {
		t.Fatalf("trusted events %d, want %d from healthy segments",
			len(rep.TrustedEvents), healthyVerified)
	}
	t.Logf("结果: verified=%d 条（恰好来自完好段），损坏段好行降级为 salvaged", len(rep.TrustedEvents))
}

// TestSalvageIncrementalReadiness 覆盖业务：损坏后增量校验能否接着往下走。
func TestSalvageIncrementalReadiness(t *testing.T) {
	t.Log("业务: 部分损坏抢救与完整性报告 | 用例: 首个新段损坏则增量不可继续；完好则可继续")
	dir, store := setupSealedStore(t)
	segs := store.Segments()

	// 完好时：锚定第 1 段，增量可继续，LastVerifiedID 为最后一段。
	ok, err := Salvage(store, SalvageOptions{AfterSegmentID: segs[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	if !ok.IncrementalOK {
		t.Fatal("incremental should be OK when first new segment intact")
	}
	if ok.LastVerifiedID != segs[len(segs)-1].ID {
		t.Fatalf("LastVerifiedID=%d, want %d", ok.LastVerifiedID, segs[len(segs)-1].ID)
	}

	// 破坏锚点之后的第一个新段：增量不可继续，但报告仍给出最后一个连续完好段。
	corruptLineAt(t, dir, segs[1].ID, "tamper")
	bad, err := Salvage(store, SalvageOptions{AfterSegmentID: segs[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	if bad.IncrementalOK {
		t.Fatal("incremental must not be OK when first new segment damaged")
	}
	if bad.LastVerifiedID != segs[0].ID {
		t.Fatalf("LastVerifiedID=%d, want anchor %d", bad.LastVerifiedID, segs[0].ID)
	}
	t.Logf("结果: 完好时 IncrementalOK=true 至段 %d；首新段损坏后 IncrementalOK=false、锚点停在 %d",
		segs[len(segs)-1].ID, bad.LastVerifiedID)

	// 锚点本身已被保留清理：返回可区分错误。
	missing, err := Salvage(store, SalvageOptions{AfterSegmentID: 9999})
	if err == nil {
		t.Fatalf("missing anchor should error, got report=%+v", missing)
	}
	t.Logf("结果: 缺失增量锚点返回错误: %v", err)
}

// TestSalvageDoesNotAbortWholeHistory 覆盖业务：一坏不能整批读不出。
func TestSalvageDoesNotAbortWholeHistory(t *testing.T) {
	t.Log("业务: 部分损坏抢救与完整性报告 | 用例: 中段损坏时 AllEvents 仍返回前后健康数据")
	dir, store := setupSealedStore(t)
	target := store.Segments()[1].ID
	corruptLineAt(t, dir, target, "record")

	evs, err := store.AllEvents()
	if err != nil {
		t.Fatalf("AllEvents must not fail on partial corruption: %v", err)
	}
	if len(evs) == 0 {
		t.Fatal("AllEvents returned nothing despite healthy segments")
	}
	// 目标段坏行被剔除，其它段事件仍在。
	rep, _ := Salvage(store, SalvageOptions{})
	healthyCount := 0
	for _, sal := range rep.Segments {
		if sal.SegmentID != target {
			healthyCount += sal.Good
		}
	}
	if len(evs) < healthyCount {
		t.Fatalf("AllEvents %d < healthy-only %d", len(evs), healthyCount)
	}
	t.Logf("结果: 中段损坏后 AllEvents 仍读出 %d 条（其它完好段 %d 条）", len(evs), healthyCount)
}
