package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// RecoveryReport 描述重新打开日志目录时，对上次未正常收尾（进程被杀等）的
// 活跃段做崩溃恢复的对账结果：重放保留了多少条、丢弃了多少条半完成记录。
type RecoveryReport struct {
	// Recovered 为 true 表示打开时确实发现并修复了不干净的活跃段。
	Recovered bool
	// ActiveSegmentID 被恢复的活跃段 ID。
	ActiveSegmentID int
	// ReplayedEvents 是活跃段中校验通过、被重放保留的完整事件数。
	ReplayedEvents int
	// DiscardedLines 是被丢弃的半完成/结构损坏行数。
	DiscardedLines int
	// TruncatedBytes 是修复后从活跃段尾部剔除的字节数。
	TruncatedBytes int64
	// SealedSegments 是打开时清单中已封存段落数（仅供对账）。
	SealedSegments int
	// Issues 逐条记录被丢弃行的位置与分类。
	Issues []LineIssue
}

// LastRecovery 返回本次打开存储时执行崩溃恢复的对账结果。
func (s *Store) LastRecovery() RecoveryReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastRecovery
}

// recoverActiveLocked 检查并修复当前活跃段，使目录回到可继续安全追加的状态：
//
// 逐行扫描活跃段。只有从段首开始的一段“连续、完整、可解析且通过事件校验”
// 的前缀是可信的——它们是上次运行已经落盘确认的事件，全部重放保留，一条不少。
// 一旦遇到第一条坏行（写了一半的尾行、截断的 JSON、或结构非法记录），
// 该行及其后的所有字节一律视为上次未正常收尾的半成品，整体丢弃，
// 避免半完成数据把后续记录拖坏。修复后用临时文件 + 原子替换重写活跃段。
//
// 返回非 nil error 表示检测到需要修复但无法安全完成（如重写失败），
// 调用方不应在该存储上继续追加。
func (s *Store) recoverActiveLocked() (RecoveryReport, error) {
	rep := RecoveryReport{
		ActiveSegmentID: s.activeID,
		SealedSegments:  len(s.sealed),
	}

	path := s.segmentPath(s.activeID)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return rep, nil // 全新目录，无活跃段
		}
		// 读失败无法安全恢复：拒绝打开而不是带着可疑状态继续。
		return rep, fmt.Errorf("recover active segment %d: read: %w", s.activeID, err)
	}
	if len(data) == 0 {
		return rep, nil
	}

	// 逐行解析，记录可信前缀。
	var good bytes.Buffer
	var goodEvents []Event
	var issues []LineIssue
	r := bufio.NewScanner(bytes.NewReader(data))
	r.Buffer(make([]byte, 0, 1<<20), 1<<20)
	r.Split(bufio.ScanLines)

	lineNo := 0
	offset := int64(0)
	corrupt := false
	discarded := 0 // 坏行及之后属于半成品批次的物理行数
	for r.Scan() {
		lineNo++
		raw := r.Bytes()
		lineStart := offset
		offset += int64(len(raw)) + 1 // ScanLines 吞掉了 '\n'
		if len(raw) == 0 {
			if !corrupt {
				good.WriteByte('\n') // 空行不影响解析，原样保留
			}
			continue
		}
		if corrupt {
			// 首个坏行之后的所有行都属于未正常收尾的批次，全部丢弃。
			discarded++
			continue
		}
		var e Event
		if perr := json.Unmarshal(raw, &e); perr != nil {
			corrupt = true
			discarded++
			issues = append(issues, LineIssue{
				SegmentID: s.activeID, Line: lineNo, Offset: lineStart,
				Reason: ReasonRecordCorrupt,
				Detail: fmt.Sprintf("unparseable record after crash: %v", perr),
			})
		} else if verr := e.Validate(); verr != nil {
			corrupt = true
			discarded++
			issues = append(issues, LineIssue{
				SegmentID: s.activeID, Line: lineNo, Offset: lineStart,
				Reason: ReasonRecordCorrupt,
				Detail: fmt.Sprintf("invalid event after crash: %v", verr),
			})
		} else {
			good.Write(raw)
			good.WriteByte('\n')
			goodEvents = append(goodEvents, e)
		}
	}

	// 扫描错误（如行过长）同样按结构损坏处理：此前的可信前缀已收集。
	if rerr := r.Err(); rerr != nil && !corrupt {
		corrupt = true
		issues = append(issues, LineIssue{
			SegmentID: s.activeID, Line: lineNo + 1, Offset: offset,
			Reason: ReasonRecordCorrupt,
			Detail: fmt.Sprintf("scan active segment: %v", rerr),
		})
	}

	rep.ReplayedEvents = len(goodEvents)
	rep.Issues = issues
	rep.DiscardedLines = discarded
	if good.Len() < len(data) {
		rep.TruncatedBytes = int64(len(data) - good.Len())
	}

	// 需要恢复的情形：出现坏行（含其后的半成品批次），或文件末尾缺少 '\n'
	// 收尾——正常写入路径每条事件都带换行，缺收尾说明上次没写完，
	// 重写以补齐（最后一行恰好是合法完整事件时）或截断该尾行（已在坏行处理）。
	missingFinalNewline := len(data) > 0 && data[len(data)-1] != '\n'
	rep.Recovered = corrupt || missingFinalNewline || good.Len() != len(data)

	// 原子重写活跃段为可信前缀，保证后续追加从干净位置开始。
	if rep.Recovered {
		tmp := path + ".recover"
		if werr := os.WriteFile(tmp, good.Bytes(), 0o644); werr != nil {
			return rep, fmt.Errorf("recover active segment %d: write temp: %w", s.activeID, werr)
		}
		if rerr := os.Rename(tmp, path); rerr != nil {
			return rep, fmt.Errorf("recover active segment %d: rename: %w", s.activeID, rerr)
		}
		// 同步恢复结果：段文件与目录项落盘，避免紧接着再崩溃时回到坏状态。
		if rf, oerr := os.Open(path); oerr == nil {
			_ = rf.Sync()
			_ = rf.Close()
		}
		if df, oerr := os.Open(s.dir); oerr == nil {
			_ = df.Sync()
			_ = df.Close()
		}
	}

	// 重建活跃段内存状态。
	s.activeCount = len(goodEvents)
	s.activeSize = int64(good.Len())
	if len(goodEvents) > 0 {
		s.activeStart = goodEvents[0].Timestamp
	}
	s.usedBytes += s.activeSize // 封存段占用已在 NewStore 统计，这里只加活跃段
	return rep, nil
}
