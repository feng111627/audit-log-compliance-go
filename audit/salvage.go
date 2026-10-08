package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// 完整性相关的可区分哨兵错误。
var (
	// ErrIntegrity 表示完整性校验类问题的总类。
	ErrIntegrity = errors.New("audit: integrity check failed")
	// ErrIntegritySegmentMissing 表示增量锚点或段落文件缺失。
	ErrIntegritySegmentMissing = errors.New("audit: segment missing")
)

// TrustLevel 表示抢救出来的事件的可信级别。
type TrustLevel string

const (
	// TrustVerified 来自哈希校验通过的封存段，密码学意义上可信。
	TrustVerified TrustLevel = "verified"
	// TrustSalvaged 结构完整可读但无法通过哈希/清单核对（段落本身已损坏）。
	TrustSalvaged TrustLevel = "salvaged"
	// TrustActive 来自尚未封存的活跃段，结构完整但尚无哈希锚点。
	TrustActive TrustLevel = "active"
)

// LineIssue 描述段落内某一行（记录）的问题。
type LineIssue struct {
	SegmentID int          `json:"segment_id"`
	Line      int          `json:"line"` // 从 1 开始的物理行号
	Offset    int64        `json:"offset"`
	Reason    VerifyReason `json:"reason"`
	Detail    string       `json:"detail"`
}

// SalvagedEvent 是一条抢救出来的事件及其可信级别。
type SalvagedEvent struct {
	Event Event
	Trust TrustLevel
}

// SegmentSalvage 是单个段落的抢救与完整性报告。
type SegmentSalvage struct {
	SegmentID int
	Sealed    bool
	Reason    VerifyReason
	Detail    string
	Good      int
	Dropped   int
	Trust     TrustLevel
	Events    []SalvagedEvent
	Issues    []LineIssue
}

// SalvageReport 是一次尽力抢救读取的汇总报告。
type SalvageReport struct {
	OK             bool             // 所有被检查的封存段均通过校验
	Segments       []SegmentSalvage // 按段落 ID 排序
	Events         []SalvagedEvent  // 全部抢救出的事件（含不可信但结构完整者）
	TrustedEvents  []Event          // 仅 TrustVerified 的事件
	IncrementalOK  bool             // 增量校验能否从 LastVerifiedID 接着往下走
	LastVerifiedID int              // 最后一个完全通过校验的连续封存段 ID（无则 0）
}

// SalvageOptions 控制抢救读取范围。
type SalvageOptions struct {
	AfterSegmentID int  // 仅抢救该 ID 之后的封存段（增量），0 表示全部
	IncludeActive  bool // 是否一并抢救尚未封存的活跃段
}

// parsedLine 是扫描得到的一行结构化结果。
type parsedLine struct {
	lineNo       int
	offset       int64
	event        Event
	ok           bool // 非空、可解析且通过事件校验
	unterminated bool // 该物理行没有以 '\n' 收尾（文件末尾被截断到行内）
}

// scanSegmentFile 逐行扫描段落文件，区分结构完好的行与损坏行，
// 不做哈希/清单层面的判定（那是封存段校验的职责）。
// 返回值 trailing 表示文件末尾是否存在一个没有 '\n' 收尾的半行。
func scanSegmentFile(path string, segmentID int) (lines []parsedLine, issues []LineIssue, trailing bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, false, err
	}
	defer f.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, false, err
	}
	trailing = len(data) > 0 && data[len(data)-1] != '\n'

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	lineNo := 0
	var offset int64
	for sc.Scan() {
		lineNo++
		raw := sc.Bytes()
		start := offset
		offset += int64(len(raw)) + 1
		if len(raw) == 0 {
			continue // 空行忽略
		}
		isLast := lineNo == countLines(data)
		pl := parsedLine{lineNo: lineNo, offset: start, unterminated: isLast && trailing}
		var e Event
		if perr := json.Unmarshal(raw, &e); perr != nil {
			issues = append(issues, LineIssue{
				SegmentID: segmentID, Line: lineNo, Offset: start,
				Reason: ReasonRecordCorrupt,
				Detail: fmt.Sprintf("line %d unparseable: %v", lineNo, perr),
			})
			lines = append(lines, pl)
			continue
		}
		if verr := e.Validate(); verr != nil {
			issues = append(issues, LineIssue{
				SegmentID: segmentID, Line: lineNo, Offset: start,
				Reason: ReasonRecordCorrupt,
				Detail: fmt.Sprintf("line %d invalid event: %v", lineNo, verr),
			})
			lines = append(lines, pl)
			continue
		}
		pl.event = e
		pl.ok = true
		lines = append(lines, pl)
	}
	return lines, issues, trailing, sc.Err()
}

// countLines 统计数据中的物理行数（以 '\n' 分隔）。
func countLines(data []byte) int {
	n := 0
	for _, b := range data {
		if b == '\n' {
			n++
		}
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		n++
	}
	return n
}

// Salvage 在段落可能部分损坏的情况下，尽力读出仍可用的事件并给出
// 人可读的完整性报告：问题出现在哪段哪行、属于哪类情况、哪些数据仍可信，
// 以及增量校验能否接着往下走。它不会因为单个段落损坏就让整批历史读不出来。
func Salvage(s *Store, opts SalvageOptions) (*SalvageReport, error) {
	s.mu.Lock()
	segs := make([]Segment, len(s.sealed))
	copy(segs, s.sealed)
	activeID := s.activeID
	s.mu.Unlock()
	sortSegments(segs)

	rep := &SalvageReport{OK: true}
	byID := map[int]Segment{}
	for _, seg := range segs {
		byID[seg.ID] = seg
	}

	// 增量锚点必须存在（可能已被保留清理）。
	if opts.AfterSegmentID > 0 {
		if _, ok := byID[opts.AfterSegmentID]; !ok {
			return nil, fmt.Errorf("%w: incremental anchor segment %d not found",
				ErrIntegritySegmentMissing, opts.AfterSegmentID)
		}
	}

	// chainPrev 记录 ID 连续意义上的上一段（用于哈希链判定）。
	// lastContinuousVerified 记录“损坏点之前”最后一个连续完好的封存段：
	// 一旦出现损坏，连续完好链即终止，其后的好段不再推进该锚点
	//（因为增量校验无法跨过损坏点接续）。
	var chainPrev *Segment
	lastContinuousVerified := 0
	chainBroken := false
	if opts.AfterSegmentID > 0 {
		a := byID[opts.AfterSegmentID]
		chainPrev = &a
		lastContinuousVerified = a.ID
	}

	for i := range segs {
		seg := segs[i]
		if seg.ID <= opts.AfterSegmentID {
			continue
		}
		sal := s.salvageOneSealed(seg, chainPrev)

		if sal.Reason == ReasonOK && !chainBroken {
			lastContinuousVerified = seg.ID
		} else if sal.Reason != ReasonOK {
			chainBroken = true
			rep.OK = false
		}
		cp := seg
		chainPrev = &cp
		rep.Segments = append(rep.Segments, sal)
	}

	// 活跃段抢救（独立，无哈希锚点）。
	if opts.IncludeActive {
		if sal := s.salvageActive(activeID); sal != nil {
			rep.Segments = append(rep.Segments, *sal)
		}
	}

	// 汇总事件（单次扫描的结果在 salvageOneSealed/Active 中已挂到 Events）。
	for i := range rep.Segments {
		sal := &rep.Segments[i]
		for _, se := range sal.Events {
			rep.Events = append(rep.Events, se)
			if se.Trust == TrustVerified {
				rep.TrustedEvents = append(rep.TrustedEvents, se.Event)
			}
		}
	}

	rep.LastVerifiedID = lastContinuousVerified
	if opts.AfterSegmentID > 0 {
		// 增量能否继续：首个新段必须完好（链未断）。
		rep.IncrementalOK = len(rep.Segments) > 0 &&
			rep.Segments[0].Sealed && rep.Segments[0].Reason == ReasonOK
	} else {
		rep.IncrementalOK = rep.OK
	}
	return rep, nil
}

// salvageOneSealed 抢救并校验单个封存段，prev 为 ID 连续意义上的上一段（可空）。
func (s *Store) salvageOneSealed(seg Segment, prev *Segment) SegmentSalvage {
	sal := SegmentSalvage{SegmentID: seg.ID, Sealed: true, Reason: ReasonOK}
	path := s.segmentPath(seg.ID)

	if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
		sal.Reason = ReasonSegmentMissing
		sal.Detail = fmt.Sprintf("file %s is missing", seg.FileName)
		return sal
	} else if statErr != nil {
		sal.Reason = ReasonSegmentMissing
		sal.Detail = statErr.Error()
		return sal
	}

	lines, issues, trailing, scanErr := scanSegmentFile(path, seg.ID)
	sal.Issues = issues
	var good []parsedLine
	for _, ln := range lines {
		// 封存段以 '\n' 结尾是完整记录的前提；末尾无换行的尾行属于被截断，
		// 既不算结构损坏的坏记录，也不算可信好行。
		if ln.unterminated {
			continue
		}
		if ln.ok {
			sal.Good++
			good = append(good, ln)
		} else {
			sal.Dropped++
		}
	}

	switch {
	case scanErr != nil:
		sal.Reason = ReasonRecordCorrupt
		sal.Detail = fmt.Sprintf("scan file: %v", scanErr)
	case sal.Good < seg.Events:
		// 好行少于清单：尾部截短（可能含一个无换行的半行）。
		sal.Reason = ReasonTruncated
		sal.Detail = fmt.Sprintf("got %d events, manifest records %d (tail truncated)",
			sal.Good, seg.Events)
		if len(issues) > 0 {
			sal.Detail = fmt.Sprintf("got %d events, manifest records %d; %d corrupt record(s) after truncation, first: %s",
				sal.Good, seg.Events, len(issues), issues[0].Detail)
		}
		if trailing {
			sal.Detail += "; last line has no terminating newline"
		}
		if sal.Dropped > 0 {
			sal.Reason = ReasonRecordCorrupt
		}
	case sal.Good > seg.Events:
		sal.Reason = ReasonTampered
		sal.Detail = fmt.Sprintf("got %d events, manifest records %d (data appended/altered)",
			sal.Good, seg.Events)
	default:
		sum, herr := hashFile(path)
		switch {
		case herr != nil:
			sal.Reason = ReasonSegmentMissing
			sal.Detail = herr.Error()
		case sum != seg.Hash:
			sal.Reason = ReasonTampered
			if sal.Dropped > 0 {
				sal.Detail = fmt.Sprintf("content altered and %d line(s) unparseable", sal.Dropped)
			} else {
				sal.Detail = fmt.Sprintf("content hash %s != manifest %s", sum, seg.Hash)
			}
		case sal.Dropped > 0:
			sal.Reason = ReasonRecordCorrupt
			sal.Detail = fmt.Sprintf("%d structurally corrupt record(s)", sal.Dropped)
		}
	}

	// 哈希链检查：仅在本段自身完好、且与前一段 ID 连续时比对。
	if sal.Reason == ReasonOK && prev != nil && seg.ID == prev.ID+1 &&
		seg.PrevHash != prev.Hash {
		sal.Reason = ReasonChainBroken
		sal.Detail = fmt.Sprintf("prev_hash does not match segment %d hash", prev.ID)
	}

	if sal.Reason == ReasonOK {
		sal.Trust = TrustVerified
	} else {
		sal.Trust = TrustSalvaged
	}
	for _, ln := range good {
		sal.Events = append(sal.Events, SalvagedEvent{Event: ln.event, Trust: sal.Trust})
	}
	return sal
}

// salvageActive 抢救尚未封存的活跃段。活跃段没有哈希与清单计数，
// 因此只能从结构层面判定：结构完好则事件以 active 可信级别给出；
// 出现坏行则报 record_corrupt，好行仍抢救出来。返回 nil 表示无活跃段文件。
func (s *Store) salvageActive(activeID int) *SegmentSalvage {
	path := s.segmentPath(activeID)
	fi, err := os.Stat(path)
	if err != nil || fi.Size() == 0 {
		return nil
	}
	lines, issues, _, scanErr := scanSegmentFile(path, activeID)
	sal := &SegmentSalvage{SegmentID: activeID, Sealed: false, Trust: TrustActive}
	sal.Issues = issues
	for _, ln := range lines {
		if ln.unterminated {
			continue // 活跃段尾部无换行：未写完的半行，忽略
		}
		if ln.ok {
			sal.Good++
			sal.Events = append(sal.Events, SalvagedEvent{Event: ln.event, Trust: TrustActive})
		} else {
			sal.Dropped++
		}
	}
	switch {
	case scanErr != nil:
		sal.Reason = ReasonRecordCorrupt
		sal.Detail = fmt.Sprintf("scan active: %v", scanErr)
	case sal.Dropped > 0:
		sal.Reason = ReasonRecordCorrupt
		sal.Detail = fmt.Sprintf("%d corrupt record(s) in active segment", sal.Dropped)
	default:
		sal.Reason = ReasonOK
	}
	return sal
}

// SalvedEvents 是 Salvage 的便捷封装：返回全部结构可读的事件（含不可信级别）。
func SalvedEvents(s *Store) ([]Event, error) {
	rep, err := Salvage(s, SalvageOptions{IncludeActive: true})
	if err != nil {
		return nil, err
	}
	out := make([]Event, 0, len(rep.Events))
	for _, se := range rep.Events {
		out = append(out, se.Event)
	}
	return out, nil
}
