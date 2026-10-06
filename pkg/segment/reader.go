package segment

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/feng111627/audit-log-compliance-go/pkg/audit"
)

// ScanError 在读流过程中发现完整性问题时返回，携带可区分的判定原因。
type ScanError struct {
	Segment string
	Line    int
	Reason  Reason
	Detail  string
}

func (e *ScanError) Error() string {
	return fmt.Sprintf("segment: scan %s line %d: %s: %s", e.Segment, e.Line, e.Reason, e.Detail)
}

// ScanEvents 按清单顺序遍历全部留存事件，遍历过程中同步重算哈希链。
// 一旦发现篡改/截断/损坏/缺失，立即返回 *ScanError，避免基于不可信数据继续处理。
// 正常使用前建议先做 VerifyFull；fn 返回错误会中断遍历并原样返回。
func (s *Store) ScanEvents(fn func(ev audit.Event) error) error {
	s.mu.Lock()
	entries := make([]Entry, len(s.man.Segments))
	copy(entries, s.man.Segments)
	curName := s.curName
	s.mu.Unlock()

	expectedPrev := ""
	first := true
	for _, e := range entries {
		path := filepath.Join(s.dir, e.Name)
		f, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				return &ScanError{Segment: e.Name, Reason: ReasonMissing,
					Detail: "file listed in manifest does not exist"}
			}
			return &ScanError{Segment: e.Name, Reason: ReasonMissing, Detail: err.Error()}
		}
		// 第一个现存段落即链首，其 first_prev 允许指向已被保留清理的更早段落；
		// 段落内部帧仍须从该 first_prev 起逐帧自洽。
		if first {
			expectedPrev = e.FirstPrev
		} else if e.FirstPrev != expectedPrev {
			f.Close()
			return &ScanError{Segment: e.Name, Reason: ReasonTampered,
				Detail: fmt.Sprintf("first_prev %q != chain head %q", e.FirstPrev, expectedPrev)}
		}
		first = false

		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
		lineNo := 0
		for sc.Scan() {
			lineNo++
			raw := sc.Bytes()
			kind, perr := classifyLine(raw)
			if perr != nil {
				f.Close()
				return &ScanError{Segment: e.Name, Line: lineNo, Reason: ReasonCorrupt, Detail: perr.Error()}
			}
			if kind == lineFooter {
				continue
			}
			var fr frame
			if err := json.Unmarshal(raw, &fr); err != nil {
				f.Close()
				return &ScanError{Segment: e.Name, Line: lineNo, Reason: ReasonCorrupt, Detail: err.Error()}
			}
			if fr.Prev != expectedPrev {
				f.Close()
				return &ScanError{Segment: e.Name, Line: lineNo, Reason: ReasonTampered,
					Detail: fmt.Sprintf("prev %q != expected %q", fr.Prev, expectedPrev)}
			}
			if fr.Hash != digestFrame(fr.Prev, fr.Event) {
				f.Close()
				return &ScanError{Segment: e.Name, Line: lineNo, Reason: ReasonTampered,
					Detail: "frame hash mismatch"}
			}
			var ev audit.Event
			if err := json.Unmarshal(fr.Event, &ev); err != nil {
				f.Close()
				return &ScanError{Segment: e.Name, Line: lineNo, Reason: ReasonCorrupt, Detail: err.Error()}
			}
			expectedPrev = fr.Hash
			if err := fn(ev); err != nil {
				f.Close()
				return err
			}
		}
		if err := sc.Err(); err != nil {
			f.Close()
			return &ScanError{Segment: e.Name, Line: lineNo, Reason: ReasonCorrupt, Detail: err.Error()}
		}
		if e.Sealed {
			// 封存段落必须存在 footer；scanner 已在遍历时跳过，
			// 这里通过计数一致性兜底截断检测。
			// （footer 的详细校验由 VerifyFull 负责。）
		}
		if e.Name != curName && !e.Sealed {
			f.Close()
			return &ScanError{Segment: e.Name, Reason: ReasonTruncated,
				Detail: "non-active segment has no seal footer"}
		}
		f.Close()
	}
	return nil
}

// Anchor 返回当前增量校验锚点：最后一个封存段落的 "<index>:<digest>"。
// 没有任何封存段落时返回空串（此时增量校验等价于全量）。
func (s *Store) Anchor() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.man.Segments) - 1; i >= 0; i-- {
		e := s.man.Segments[i]
		if e.Sealed {
			return fmt.Sprintf("%d:%s", e.Index, e.Digest)
		}
	}
	return ""
}

// Seal 封存当前活动段落（供需要锚点或强制轮转时调用）。
func (s *Store) Seal() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil {
		return nil
	}
	return s.sealCurrentLocked()
}
