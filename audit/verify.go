package audit

import (
	"fmt"
	"os"
)

// VerifyReason 是可区分的校验判定原因。
type VerifyReason string

const (
	ReasonOK             VerifyReason = "ok"
	ReasonSegmentMissing VerifyReason = "segment_missing" // 段落文件缺失
	ReasonTampered       VerifyReason = "tampered"        // 行数与元数据一致但内容哈希不匹配（被篡改）
	ReasonTruncated      VerifyReason = "truncated"       // 行数少于元数据记录（被截断）
	ReasonChainBroken    VerifyReason = "chain_broken"    // 与相邻留存段落的哈希链断裂
)

// SegmentReport 是单个段落的校验结果。
type SegmentReport struct {
	SegmentID int
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
	return verify(s, 0)
}

// VerifyIncremental 增量校验：仅校验 ID 大于 lastSealedID 的新封存段落，
// 并确认首个新段与 lastSealedID 段落的哈希链衔接。
func VerifyIncremental(s *Store, lastSealedID int) VerifyReport {
	return verify(s, lastSealedID)
}

// verify 校验 ID 大于 afterID 的段落；afterID 为 0 时校验全部。
func verify(s *Store, afterID int) VerifyReport {
	segs := s.Segments()
	sortSegments(segs)

	rep := VerifyReport{OK: true}
	prevByID := map[int]Segment{}
	for _, seg := range segs {
		prevByID[seg.ID] = seg
	}

	// 增量校验的锚点：afterID 段落必须存在。
	var anchor Segment
	if afterID > 0 {
		a, ok := prevByID[afterID]
		if !ok {
			rep.OK = false
			rep.Segments = append(rep.Segments, SegmentReport{
				SegmentID: afterID,
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
		if seg.ID <= afterID {
			continue
		}
		sr := SegmentReport{SegmentID: seg.ID, Reason: ReasonOK}
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
			events, rerr := s.ReadEvents(seg.ID)
			switch {
			case rerr != nil:
				sr.Reason = ReasonTampered
				sr.Detail = fmt.Sprintf("unreadable content: %v", rerr)
			case len(events) < seg.Events:
				sr.Reason = ReasonTruncated
				sr.Detail = fmt.Sprintf("got %d events, manifest records %d", len(events), seg.Events)
			case len(events) > seg.Events:
				sr.Reason = ReasonTampered
				sr.Detail = fmt.Sprintf("got %d events, manifest records %d (appended data)", len(events), seg.Events)
			default:
				sum, herr := hashFile(path)
				switch {
				case herr != nil:
					sr.Reason = ReasonSegmentMissing
					sr.Detail = herr.Error()
				case sum != seg.Hash:
					sr.Reason = ReasonTampered
					sr.Detail = fmt.Sprintf("content hash %s != manifest %s", sum, seg.Hash)
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
			case first && afterID > 0:
				if seg.PrevHash != anchor.Hash {
					sr.Reason = ReasonChainBroken
					sr.Detail = fmt.Sprintf("prev_hash does not match anchor segment %d hash", afterID)
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
	return rep
}
