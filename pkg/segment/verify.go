package segment

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Reason 是段落完整性判定原因。
type Reason string

const (
	ReasonOK        Reason = "ok"        // 完整
	ReasonTampered  Reason = "tampered"  // 内容被篡改：帧哈希或跨段链不匹配
	ReasonTruncated Reason = "truncated" // 被截断：封存段落缺少 footer 或末行残损
	ReasonMissing   Reason = "missing"   // 清单中存在但文件缺失
	ReasonCorrupt   Reason = "corrupt"   // 记录存在但无法解析
)

// SegmentReport 是单个段落的校验结论。
type SegmentReport struct {
	Name   string `json:"name"`
	Index  int    `json:"index"`
	Reason Reason `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

// Report 是全量/增量校验结论。OK 为 true 当且仅当没有任何异常段落。
type Report struct {
	OK       bool            `json:"ok"`
	Mode     string          `json:"mode"`
	Segments []SegmentReport `json:"segments"`
}

// lineKind 区分一行是事件帧还是 footer。
type lineKind int

const (
	lineFrame lineKind = iota
	lineFooter
)

func classifyLine(line []byte) (lineKind, error) {
	var probe struct {
		Footer *bool `json:"footer"`
	}
	if err := json.Unmarshal(line, &probe); err != nil {
		return lineFrame, err
	}
	if probe.Footer != nil && *probe.Footer {
		return lineFooter, nil
	}
	return lineFrame, nil
}

// verifySegment 校验单个段落内部哈希链并检查封存收尾。
// expectedPrev 是本段首帧应有的前驱（取自清单 first_prev，首段为空串）。
// 最后一帧哈希、事件数与判定结论一起返回。
func (s *Store) verifySegment(e Entry, expectedPrev string) (lastHash string, count int, rep SegmentReport) {
	rep = SegmentReport{Name: e.Name, Index: e.Index, Reason: ReasonOK}

	path := filepath.Join(s.dir, e.Name)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			rep.Reason = ReasonMissing
			rep.Detail = "manifest lists segment but file does not exist"
			return "", 0, rep
		}
		rep.Reason = ReasonMissing
		rep.Detail = fmt.Sprintf("open segment: %v", err)
		return "", 0, rep
	}
	defer f.Close()

	prev := expectedPrev
	sawFooter := false
	var footerDigest string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := sc.Bytes()
		// bufio.Scanner 无法感知缺少结尾换行的残行：借助行内 JSON 合法性
		// 与帧字段完整性判定，截断由 footer 缺失统一兜底。
		kind, perr := classifyLine(raw)
		if perr != nil {
			rep.Reason = ReasonCorrupt
			rep.Detail = fmt.Sprintf("line %d: unparseable record: %v", lineNo, perr)
			return prev, count, rep
		}
		if kind == lineFooter {
			var ft footer
			if err := json.Unmarshal(raw, &ft); err != nil {
				rep.Reason = ReasonCorrupt
				rep.Detail = fmt.Sprintf("line %d: bad footer: %v", lineNo, err)
				return prev, count, rep
			}
			if ft.Count != count {
				rep.Reason = ReasonTruncated
				rep.Detail = fmt.Sprintf("footer count %d != frames seen %d", ft.Count, count)
				return prev, count, rep
			}
			if ft.Digest != prev {
				rep.Reason = ReasonTampered
				rep.Detail = fmt.Sprintf("footer digest %s != recomputed last hash %s", ft.Digest, prev)
				return prev, count, rep
			}
			sawFooter = true
			footerDigest = ft.Digest
			continue
		}

		var fr frame
		if err := json.Unmarshal(raw, &fr); err != nil {
			rep.Reason = ReasonCorrupt
			rep.Detail = fmt.Sprintf("line %d: bad frame json: %v", lineNo, err)
			return prev, count, rep
		}
		if fr.Prev != prev {
			rep.Reason = ReasonTampered
			rep.Detail = fmt.Sprintf("line %d: prev link %q != expected %q (chain break / tamper)",
				lineNo, fr.Prev, prev)
			return prev, count, rep
		}
		want := digestFrame(fr.Prev, fr.Event)
		if fr.Hash != want {
			rep.Reason = ReasonTampered
			rep.Detail = fmt.Sprintf("line %d: frame hash %s != recomputed %s (record tampered)",
				lineNo, fr.Hash, want)
			return prev, count, rep
		}
		var probe struct{}
		if len(fr.Event) == 0 || json.Unmarshal(fr.Event, &probe) != nil {
			rep.Reason = ReasonCorrupt
			rep.Detail = fmt.Sprintf("line %d: embedded event is not valid json", lineNo)
			return prev, count, rep
		}
		prev = fr.Hash
		count++
	}
	if err := sc.Err(); err != nil {
		rep.Reason = ReasonCorrupt
		rep.Detail = fmt.Sprintf("scan: %v", err)
		return prev, count, rep
	}

	if e.Sealed {
		if !sawFooter {
			rep.Reason = ReasonTruncated
			rep.Detail = "sealed segment missing terminating footer (file truncated after frame " +
				fmt.Sprintf("%d", count) + ")"
			return prev, count, rep
		}
		lastHash = footerDigest
	} else {
		// 活动段落没有 footer 属正常，最后一帧哈希即链头。
		lastHash = prev
	}

	// 与清单记录交叉核对。
	if e.Count != count {
		rep.Reason = ReasonTruncated
		rep.Detail = fmt.Sprintf("manifest count %d != frames verified %d", e.Count, count)
		return lastHash, count, rep
	}
	if e.Sealed && e.Digest != lastHash {
		rep.Reason = ReasonTampered
		rep.Detail = fmt.Sprintf("manifest digest %s != segment tail %s", e.Digest, lastHash)
	}
	return lastHash, count, rep
}

// VerifyFull 对清单中的全部段落做全量校验，并验证跨段落哈希链。
func (s *Store) VerifyFull() (*Report, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.verifyLocked("full", 0, "")
}

// VerifyIncremental 自锚点起做增量校验：只重算锚点之后的段落，
// 并核对锚点段落的封存摘要是否仍与清单一致。
//
// 锚点格式为 "<segment-index>:<digest>"；空串等价于全量校验。
// 锚点对应的段落自身不重放帧，只比对 digest（O(1)），因此篡改早于锚点
// 的历史数据不会被增量校验发现——这是增量校验的固有边界，需周期性全量校验。
func (s *Store) VerifyIncremental(anchor string) (*Report, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if strings.TrimSpace(anchor) == "" {
		return s.verifyLocked("incremental", 0, "")
	}
	idx, digest, err := parseAnchor(anchor)
	if err != nil {
		return nil, err
	}
	var anchorEntry *Entry
	for i := range s.man.Segments {
		if s.man.Segments[i].Index == idx {
			anchorEntry = &s.man.Segments[i]
			break
		}
	}
	if anchorEntry == nil {
		return nil, fmt.Errorf("segment: anchor %q: segment index not found (already retained away?)", anchor)
	}
	if !anchorEntry.Sealed {
		return nil, fmt.Errorf("segment: anchor %q: segment is not sealed; seal it before anchoring", anchor)
	}
	if anchorEntry.Digest != digest {
		// 锚点本身已变：历史段落在上次锚定后被动过。
		r := &Report{
			OK:   false,
			Mode: "incremental",
			Segments: []SegmentReport{{
				Name:   anchorEntry.Name,
				Index:  anchorEntry.Index,
				Reason: ReasonTampered,
				Detail: fmt.Sprintf("anchor digest %s no longer matches manifest digest %s", digest, anchorEntry.Digest),
			}},
		}
		return r, nil
	}
	return s.verifyLocked("incremental", idx, anchorEntry.Digest)
}

// verifyLocked 执行实际校验。fromIndex 为增量起点（不含），prev 为其链摘要；
// fromIndex==0 时从头全量验证。
func (s *Store) verifyLocked(mode string, fromIndex int, prev string) (*Report, error) {
	r := &Report{OK: true, Mode: mode, Segments: []SegmentReport{}}

	started := fromIndex == 0
	expectedPrev := prev // 全量时为空串（链首），增量时为锚点摘要
	firstChecked := false

	for i := range s.man.Segments {
		e := s.man.Segments[i]
		if !started {
			if e.Index == fromIndex {
				started = true
			}
			continue
		}
		// 第一个现存段落即当前链首（保留策略只删除链前缀，
		// 其 first_prev 指向可能已被删除的更早段落，属正常溯源信息），
		// 以其 first_prev 作为内部帧链起点；其后的段落必须与上一段落摘要严格衔接。
		if firstChecked {
			if e.FirstPrev != expectedPrev {
				r.OK = false
				r.Segments = append(r.Segments, SegmentReport{
					Name:   e.Name,
					Index:  e.Index,
					Reason: ReasonTampered,
					Detail: fmt.Sprintf("manifest first_prev %q != previous segment digest %q (chain gap)",
						e.FirstPrev, expectedPrev),
				})
				// 链断开后仍继续检查后续段落文件本身是否可读，但链头以清单为准继续。
			}
		} else {
			// 增量校验时锚点后的第一个段落必须挂在锚点摘要上。
			if mode == "incremental" && e.FirstPrev != expectedPrev {
				r.OK = false
				r.Segments = append(r.Segments, SegmentReport{
					Name: e.Name, Index: e.Index, Reason: ReasonTampered,
					Detail: fmt.Sprintf("first segment after anchor: first_prev %q != anchor %q",
						e.FirstPrev, expectedPrev),
				})
			}
			expectedPrev = e.FirstPrev
		}
		firstChecked = true
		last, _, rep := s.verifySegment(e, expectedPrev)
		if rep.Reason != ReasonOK {
			r.OK = false
		}
		r.Segments = append(r.Segments, rep)
		expectedPrev = last
	}
	return r, nil
}

// parseAnchor 解析 "<index>:<digest>" 形式的锚点。
func parseAnchor(anchor string) (int, string, error) {
	pos := strings.IndexByte(anchor, ':')
	if pos <= 0 || pos == len(anchor)-1 {
		return 0, "", fmt.Errorf("segment: invalid anchor %q, want <index>:<digest>", anchor)
	}
	var idx int
	for _, c := range anchor[:pos] {
		if c < '0' || c > '9' {
			return 0, "", fmt.Errorf("segment: invalid anchor %q: bad index", anchor)
		}
		idx = idx*10 + int(c-'0')
	}
	return idx, anchor[pos+1:], nil
}
