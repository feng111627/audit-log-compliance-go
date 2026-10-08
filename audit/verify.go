package audit

import (
	"fmt"
	"os"
)

// VerifyReason 是可区分的校验判定原因。
type VerifyReason string

const (
	ReasonOK             VerifyReason = "ok"
	ReasonSegmentMissing VerifyReason = "segment_missing" // 段落文件缺失（整段不见了）
	ReasonTampered       VerifyReason = "tampered"        // 行数与元数据一致但内容哈希不匹配（内容被外部改动）
	ReasonTruncated      VerifyReason = "truncated"       // 行数少于元数据记录（尾部被截短）
	ReasonChainBroken    VerifyReason = "chain_broken"    // 与相邻留存段落的哈希链断裂
	ReasonRecordCorrupt  VerifyReason = "record_corrupt"  // 记录内部结构损坏（行无法解析为合法事件）
)

// SegmentReport 是单个段落的校验结果。
type SegmentReport struct {
	SegmentID int
	Sealed    bool // false 表示这是尚未封存的活跃段
	Reason    VerifyReason
	Detail    string
}

// VerifyReport 是一次校验的汇总结果。
type VerifyReport struct {
	OK       bool
	Segments []SegmentReport
}

// VerifyAll 全量校验：校验存储中全部已封存段落的完整性与哈希链。
// 因保留清理造成的 ID 间断不计为链断裂（清理只删除连续前缀）。
func VerifyAll(s *Store) VerifyReport {
	return Verify(s, VerifyOptions{})
}

// VerifyIncremental 增量校验：仅校验 ID 大于 lastSealedID 的新封存段落，
// 并确认首个新段与 lastSealedID 段落的哈希链衔接。
func VerifyIncremental(s *Store, lastSealedID int) VerifyReport {
	return Verify(s, VerifyOptions{AfterSegmentID: lastSealedID})
}

// VerifyOptions 控制校验范围。
type VerifyOptions struct {
	AfterSegmentID int  // 仅校验该 ID 之后的封存段，0 表示全部
	IncludeActive  bool // 是否一并校验尚未封存的活跃段（仅做结构校验，无哈希）
}

// Verify 按选项执行全量或增量校验，可选择纳入活跃段。
func Verify(s *Store, opts VerifyOptions) VerifyReport {
	segs := s.Segments()
	sortSegments(segs)

	rep := VerifyReport{OK: true}
	prevByID := map[int]Segment{}
	for _, seg := range segs {
		prevByID[seg.ID] = seg
	}

	// 增量校验的锚点：afterID 段落必须存在。
	var anchor Segment
	if opts.AfterSegmentID > 0 {
		a, ok := prevByID[opts.AfterSegmentID]
		if !ok {
			rep.OK = false
			rep.Segments = append(rep.Segments, SegmentReport{
				SegmentID: opts.AfterSegmentID,
				Reason:    ReasonSegmentMissing,
				Detail:    "incremental anchor segment not found (may have been cleaned by retention)",
			})
			return rep
		}
		anchor = a
	}

	prev := anchor
	first := true
	for _, seg := range segs {
		if seg.ID <= opts.AfterSegmentID {
			continue
		}
		sr := SegmentReport{SegmentID: seg.ID, Sealed: true, Reason: ReasonOK}
		path := s.segmentPath(seg.ID)

		fi, err := os.Stat(path)
		switch {
		case os.IsNotExist(err):
			sr.Reason = ReasonSegmentMissing
			sr.Detail = fmt.Sprintf("file %s is missing", seg.FileName)
		case err != nil:
			sr.Reason = ReasonSegmentMissing
			sr.Detail = err.Error()
		default:
			// 优先做逐行结构检查，能精确定位坏记录；同时统计好行数量。
			pls, issues, trailing, scanErr := scanSegmentFile(path, seg.ID)
			events := 0
			corrupt := 0
			for _, ln := range pls {
				if ln.unterminated {
					continue // 末尾无换行半行属于截断
				}
				if ln.ok {
					events++
				} else {
					corrupt++
				}
			}
			switch {
			case corrupt > 0 && events < seg.Events:
				sr.Reason = ReasonRecordCorrupt
				sr.Detail = fmt.Sprintf("%d corrupt record(s), first: %s",
					corrupt, issues[0].Detail)
			case scanErr != nil:
				sr.Reason = ReasonRecordCorrupt
				sr.Detail = fmt.Sprintf("scan: %v", scanErr)
			case events < seg.Events:
				sr.Reason = ReasonTruncated
				detail := fmt.Sprintf("got %d events, manifest records %d", events, seg.Events)
				if trailing {
					detail += " (last line unterminated)"
				}
				sr.Detail = detail
			case events > seg.Events:
				sr.Reason = ReasonTampered
				sr.Detail = fmt.Sprintf("got %d events, manifest records %d (appended data)", events, seg.Events)
			default:
				// 行数与清单一致（即便个别行无法解析），再以哈希区分内容是否被外部改动。
				sum, herr := hashFile(path)
				switch {
				case herr != nil:
					sr.Reason = ReasonSegmentMissing
					sr.Detail = herr.Error()
				case sum != seg.Hash:
					sr.Reason = ReasonTampered
					if corrupt > 0 {
						sr.Detail = fmt.Sprintf("content altered and %d line(s) unparseable, first: %s",
							corrupt, issues[0].Detail)
					} else {
						sr.Detail = fmt.Sprintf("content hash %s != manifest %s", sum, seg.Hash)
					}
				case corrupt > 0:
					// 哈希一致却有坏行在理论上不会发生（哈希一致即内容未变），
					// 保守归类为结构损坏。
					sr.Reason = ReasonRecordCorrupt
					sr.Detail = issues[0].Detail
				case fi.Size() == 0 && seg.Events > 0:
					sr.Reason = ReasonTruncated
					sr.Detail = "file is empty"
				}
			}
		}

		// 哈希链检查：仅当与前一个留存段落 ID 连续时才校验链接
		// （保留清理只删除连续前缀，剩余段落 ID 连续）。
		if sr.Reason == ReasonOK {
			switch {
			case first && opts.AfterSegmentID > 0:
				if seg.PrevHash != anchor.Hash {
					sr.Reason = ReasonChainBroken
					sr.Detail = fmt.Sprintf("prev_hash does not match anchor segment %d hash", opts.AfterSegmentID)
				}
			case !first:
				if seg.ID == prev.ID+1 && seg.PrevHash != prev.Hash {
					sr.Reason = ReasonChainBroken
					sr.Detail = fmt.Sprintf("prev_hash does not match segment %d hash", prev.ID)
				}
			}
		}

		if sr.Reason != ReasonOK {
			rep.OK = false
		}
		rep.Segments = append(rep.Segments, sr)
		prev = seg
		first = false
	}

	// 活跃段：无哈希锚点，只做结构校验。
	if opts.IncludeActive {
		activeID := s.ActiveSegmentID()
		asr := SegmentReport{SegmentID: activeID, Sealed: false, Reason: ReasonOK}
		path := s.segmentPath(activeID)
		if fi, err := os.Stat(path); err == nil && fi.Size() > 0 {
			pls, issues, _, scanErr := scanSegmentFile(path, activeID)
			corrupt := 0
			for _, ln := range pls {
				if ln.unterminated {
					continue
				}
				if !ln.ok {
					corrupt++
				}
			}
			switch {
			case corrupt > 0:
				asr.Reason = ReasonRecordCorrupt
				asr.Detail = fmt.Sprintf("%d corrupt record(s) in active segment, first: %s",
					corrupt, issues[0].Detail)
				rep.OK = false
			case scanErr != nil:
				asr.Reason = ReasonRecordCorrupt
				asr.Detail = scanErr.Error()
				rep.OK = false
			}
		}
		rep.Segments = append(rep.Segments, asr)
	}
	return rep
}
