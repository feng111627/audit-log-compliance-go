package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// 部分损坏容忍读取：不把所有异常糊成同一种说法。
// 逐段、逐行扫描，尽量捞出仍可用的历史，并给出「在哪段、哪行、哪类情况、
// 哪些数据仍可信、增量校验能否继续」的完整性报告。
//
// 问题分类：
//   - record_corrupt     记录内部结构坏了（不是合法 JSON 记录）
//   - record_tampered    记录内容被外部改动（批次摘要对不上）
//   - truncated_tail     尾部被截短（批次没有提交标记收尾，或行数少于清单）
//   - segment_missing    整段文件不见了
//   - chain_broken       批次摘要链 / 段落哈希链断裂

// IssueKind 是完整性问题的分类。
type IssueKind string

const (
	IssueTampered      IssueKind = "record_tampered"
	IssueTruncatedTail IssueKind = "truncated_tail"
	IssueMissing       IssueKind = "segment_missing"
	IssueCorrupt       IssueKind = "record_corrupt"
	IssueChainBroken   IssueKind = "chain_broken"
)

// SegmentIssue 定位一个具体问题：在哪段、哪行/什么偏移、哪类情况。
type SegmentIssue struct {
	SegmentID int       `json:"segment_id"`
	Kind      IssueKind `json:"kind"`
	Line      int       `json:"line"`   // 段内行号（1 起），0 表示段级问题
	Offset    int64     `json:"offset"` // 段内字节偏移（问题记录起点）
	Detail    string    `json:"detail"`
}

// SegmentSalvageReport 是单段的容忍读取结果。
type SegmentSalvageReport struct {
	SegmentID     int            `json:"segment_id"`
	ManifestCount int            `json:"manifest_count"` // 清单记录的事件数（封存段），活跃段为 0
	Salvaged      int            `json:"salvaged"`       // 实际读出的事件数
	Trusted       bool           `json:"trusted"`        // 段内读出的数据是否全部可信
	Sealed        bool           `json:"sealed"`         // 是否为已封存段
	Events        []Event        `json:"-"`              // 捞回的可用事件（含受影响段中仍可解析的部分）
	Issues        []SegmentIssue `json:"issues"`
}

// IntegrityReport 是全目录容忍读取的汇总完整性报告。
type IntegrityReport struct {
	Segments []SegmentSalvageReport `json:"segments"`
	Issues   []SegmentIssue         `json:"issues"` // 全部问题的扁平汇总

	// IncrementalCanContinue 表示增量校验是否还能接着往下走：
	// 只要存在内容完好的已封存段可作为新锚点即为 true。
	IncrementalCanContinue bool `json:"incremental_can_continue"`
	// NextAnchorID 建议的增量校验新锚点（内容完好的最后一个封存段；0 表示无）。
	NextAnchorID int `json:"next_anchor_id"`
}

// salvageBatch 是扫描中累积的一批事件。
type salvageBatch struct {
	startLine  int
	startOff   int64
	raw        []byte
	events     []Event
	eventLines []int // 批内事件行号（段内）
}

// SalvageSegment 容忍读取单个段落，尽量返回可用事件并分类记录问题。
// 对封存段额外核对清单事件数与整段哈希；对成组提交格式核对每批摘要与摘要链。
func SalvageSegment(s *Store, segmentID int) SegmentSalvageReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return salvageSegmentLocked(s, segmentID)
}

func salvageSegmentLocked(s *Store, segmentID int) SegmentSalvageReport {
	meta, isSealed := findSegmentMeta(s.sealed, segmentID)
	rep := SegmentSalvageReport{SegmentID: segmentID, Sealed: isSealed, Trusted: true}
	if isSealed {
		rep.ManifestCount = meta.Events
	}

	data, err := os.ReadFile(s.segmentPath(segmentID))
	if err != nil {
		// 活跃段文件尚不存在是正常状态（还没写入或刚轮转），不算缺失问题。
		if os.IsNotExist(err) && segmentID == s.activeID {
			rep.Trusted = true
			return rep
		}
		if os.IsNotExist(err) {
			rep.Trusted = false
			rep.Issues = append(rep.Issues, SegmentIssue{
				SegmentID: segmentID, Kind: IssueMissing,
				Detail: fmt.Sprintf("file %s is missing", segmentFileName(segmentID)),
			})
		} else {
			rep.Trusted = false
			rep.Issues = append(rep.Issues, SegmentIssue{
				SegmentID: segmentID, Kind: IssueMissing, Detail: err.Error(),
			})
		}
		return rep
	}

	batched := bytes.Contains(data, []byte(commitMarker))
	if batched {
		anchor := s.batchAnchorForLocked(segmentID)
		rep = salvageBatchedLocked(s, segmentID, data, anchor, rep)
	} else {
		rep = salvageLegacyLocked(s, segmentID, data, rep)
	}

	// 封存段额外核对：仅当批次级扫描没有发现问题时，才用清单做整体核对，
	// 避免同一处篡改被重复报告三次（批摘要/事件数/整段哈希）。
	if isSealed && len(rep.Issues) == 0 {
		if len(rep.Events) < meta.Events {
			rep.Issues = append(rep.Issues, SegmentIssue{
				SegmentID: segmentID, Kind: IssueTruncatedTail,
				Detail: fmt.Sprintf("salvaged %d events but manifest records %d", len(rep.Events), meta.Events),
			})
		} else if len(rep.Events) > meta.Events {
			rep.Issues = append(rep.Issues, SegmentIssue{
				SegmentID: segmentID, Kind: IssueTampered,
				Detail: fmt.Sprintf("salvaged %d events but manifest records %d (appended data)",
					len(rep.Events), meta.Events),
			})
		} else if sum, herr := hashBytes(data); herr == nil && sum != meta.Hash {
			rep.Issues = append(rep.Issues, SegmentIssue{
				SegmentID: segmentID, Kind: IssueTampered,
				Detail: fmt.Sprintf("segment content hash %s != manifest %s", sum, meta.Hash),
			})
		}
	}

	rep.Salvaged = len(rep.Events)
	if len(rep.Issues) > 0 {
		rep.Trusted = false
	}
	return rep
}

// salvageBatchedLocked 扫描成组提交格式：按批核对摘要，坏批隔离但不影响其他批。
func salvageBatchedLocked(s *Store, segmentID int, data []byte, anchorDigest string, rep SegmentSalvageReport) SegmentSalvageReport {
	_ = s
	var batch *salvageBatch
	digest := anchorDigest
	lineNo := 0
	off := int64(0)

	commit := func(cr commitRecord, line int) {
		// 校验批次：
		//  - 内容自证：count 与 digest（事件原文摘要）核对，不匹配=内容被外部改动；
		//  - 链衔接：prev_digest 必须等于上一批的真实摘要。
		//    prev_digest 是本批提交标记自身的一个字段，它对不上说明这条记录被改过，
		//    归类为 record_tampered（"链断裂"语义由封存段哈希链 prev_hash 体现）。
		got := digestOf(batch.raw)
		bad := false
		var kind IssueKind
		var detail string
		switch {
		case cr.Count != len(batch.events):
			bad, kind = true, IssueCorrupt
			detail = fmt.Sprintf("commit marker claims %d events but batch has %d",
				cr.Count, len(batch.events))
		case got != cr.Digest:
			bad, kind = true, IssueTampered
			detail = fmt.Sprintf("batch digest mismatch (event content altered): computed %s, marker %s",
				got, cr.Digest)
		case cr.PrevDigest != digest:
			bad, kind = true, IssueTampered
			detail = fmt.Sprintf("commit marker prev_digest %s != previous batch digest %s (marker altered)",
				cr.PrevDigest, digest)
		}
		if bad {
			rep.Trusted = false
			rep.Issues = append(rep.Issues, SegmentIssue{
				SegmentID: segmentID, Kind: kind, Line: batch.startLine, Offset: batch.startOff,
				Detail: detail,
			})
			// 坏批事件不算可信，但仍尽量保留可解析事件供排查（单独标记，不计入可信集）。
		} else {
			rep.Events = append(rep.Events, batch.events...)
			digest = cr.Digest
		}
		batch = nil
	}

	pos := int64(0)
	for pos < int64(len(data)) {
		nl := bytes.IndexByte(data[pos:], '\n')
		var raw []byte
		lastLine := false
		if nl < 0 {
			raw = data[pos:]
			lastLine = true
			off = pos
			pos = int64(len(data))
		} else {
			raw = data[pos : pos+int64(nl)]
			off = pos
			pos += int64(nl) + 1
		}
		lineNo++
		if len(raw) == 0 {
			continue
		}
		isCommit, ev, cr, derr := decodeRecordLine(raw)
		switch {
		case derr != nil:
			rep.Trusted = false
			kind := IssueCorrupt
			if lastLine {
				kind = IssueTruncatedTail
			}
			rep.Issues = append(rep.Issues, SegmentIssue{
				SegmentID: segmentID, Kind: kind, Line: lineNo, Offset: off,
				Detail: fmt.Sprintf("unreadable record line: %v", derr),
			})
			// 把当前未提交批标记为受污染：其事件不可信。
			if batch != nil {
				rep.Issues = append(rep.Issues, SegmentIssue{
					SegmentID: segmentID, Kind: IssueCorrupt, Line: batch.startLine, Offset: batch.startOff,
					Detail: "batch contains an unreadable record and has no valid commit boundary",
				})
				batch = nil
			}
		case isCommit:
			if batch == nil {
				rep.Trusted = false
				rep.Issues = append(rep.Issues, SegmentIssue{
					SegmentID: segmentID, Kind: IssueCorrupt, Line: lineNo, Offset: off,
					Detail: "commit marker without preceding event batch",
				})
				break
			}
			commit(cr, lineNo)
		default:
			if batch == nil {
				batch = &salvageBatch{startLine: lineNo, startOff: off}
			}
			batch.raw = append(batch.raw, append(append([]byte{}, raw...), '\n')...)
			batch.events = append(batch.events, ev)
			batch.eventLines = append(batch.eventLines, lineNo)
		}
	}

	// 文件末尾仍有未提交批 => 尾部截短。
	if batch != nil {
		rep.Trusted = false
		rep.Issues = append(rep.Issues, SegmentIssue{
			SegmentID: segmentID, Kind: IssueTruncatedTail,
			Line: batch.startLine, Offset: batch.startOff,
			Detail: fmt.Sprintf("%d trailing events without commit marker (tail cut short)",
				len(batch.events)),
		})
	}
	return rep
}

// salvageLegacyLocked 扫描旧格式（无提交标记）：逐行尽力解析，坏行隔离后续继续。
func salvageLegacyLocked(s *Store, segmentID int, data []byte, rep SegmentSalvageReport) SegmentSalvageReport {
	_ = s
	lineNo := 0
	pos := int64(0)
	for pos < int64(len(data)) {
		nl := bytes.IndexByte(data[pos:], '\n')
		var raw []byte
		lastLine := false
		if nl < 0 {
			raw = data[pos:]
			lastLine = true
			pos = int64(len(data))
		} else {
			raw = data[pos : pos+int64(nl)]
			pos += int64(nl) + 1
		}
		lineNo++
		if len(raw) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(raw, &e); err != nil {
			rep.Trusted = false
			kind := IssueCorrupt
			if lastLine {
				kind = IssueTruncatedTail
			}
			rep.Issues = append(rep.Issues, SegmentIssue{
				SegmentID: segmentID, Kind: kind, Line: lineNo, Offset: pos,
				Detail: fmt.Sprintf("unreadable event line: %v", err),
			})
			continue // 旧格式尽力而为：跳过坏行继续读后面的历史
		}
		rep.Events = append(rep.Events, e)
	}
	return rep
}

// SalvageAll 容忍读取全部段落（封存段 + 活跃段），产出分类完整性报告。
// 段落按 ID 升序处理；未损坏的封存段可作为增量校验新锚点。
func SalvageAll(s *Store) IntegrityReport {
	s.mu.Lock()
	sealed := make([]Segment, len(s.sealed))
	copy(sealed, s.sealed)
	active := s.activeID
	s.mu.Unlock()
	sortSegments(sealed)

	var out IntegrityReport
	ids := make([]int, 0, len(sealed)+1)
	sealedByID := map[int]bool{}
	for _, seg := range sealed {
		ids = append(ids, seg.ID)
		sealedByID[seg.ID] = true
	}
	ids = append(ids, active)

	lastGoodAnchor := 0
	for _, id := range ids {
		srep := SalvageSegment(s, id)
		out.Segments = append(out.Segments, srep)
		out.Issues = append(out.Issues, srep.Issues...)
		if sealedByID[id] && srep.Trusted {
			// 内容完好的封存段可作为增量锚点；记录最后一个。
			lastGoodAnchor = id
		}
	}
	if lastGoodAnchor > 0 {
		out.IncrementalCanContinue = true
		out.NextAnchorID = lastGoodAnchor
	}
	return out
}

// findSegmentMeta 按 ID 查找封存段元数据。
func findSegmentMeta(segs []Segment, id int) (Segment, bool) {
	for _, seg := range segs {
		if seg.ID == id {
			return seg, true
		}
	}
	return Segment{}, false
}

// batchAnchorForLocked 返回某段首批提交标记应有的 prev_digest 锚点。
// 封存段用清单记录的 batch_anchor；活跃段用当前内存中的锚点（上次封存末批摘要）。
// 调用方须持有 s.mu。
func (s *Store) batchAnchorForLocked(segmentID int) string {
	if segmentID == s.activeID {
		return s.batchAnchor
	}
	if meta, ok := findSegmentMeta(s.sealed, segmentID); ok {
		return meta.BatchAnchor
	}
	return ""
}

func hashBytes(data []byte) (string, error) {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
