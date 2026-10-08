package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// 崩溃恢复协议（v1）
//
// 写入采用「成组提交」：每批事件的 JSON 行之后追加一行提交标记 commitRecord：
//
//	{"source":"auth",...}            <- 事件行
//	{"source":"auth",...}            <- 事件行
//	{"_audit_commit":"v1","count":2,"digest":"...","prev_digest":"..."}  <- 提交标记
//
// digest = SHA-256(本批全部事件行原文拼接，含每行结尾换行)；
// prev_digest 指向上一批的 digest，跨段落构成全局摘要链（锚点存于 manifest.last_digest）。
//
// 只有带「结构合法且摘要匹配」提交标记的事件才算确认数据。进程在写一批的中途
// 被杀掉时，文件尾部留下的是没有提交标记收尾的半成品，重新打开目录会被整组
// 截断丢弃，此前已确认的批次一行不少。
//
// 兼容：不含任何提交标记的活跃段视为旧版本（v0）格式，沿用旧语义——
// 恢复到最后一个可解析事件行，仅截掉坏尾，无法区分提交与否。

// commitMarker 是提交标记行的标识值。
const commitMarker = "_audit_commit"
const commitVersion = "v1"

// commitRecord 是追加在每批事件之后的提交标记（JSON Lines 中的一行）。
type commitRecord struct {
	Marker     string `json:"_audit_commit"` // 恒为 "v1"
	BatchID    string `json:"batch_id"`      // 批次标识，便于对账
	Count      int    `json:"count"`         // 本批事件行数
	Digest     string `json:"digest"`        // 本批全部事件行原文（含换行）拼接后的 SHA-256
	PrevDigest string `json:"prev_digest"`   // 上一批摘要，跨段落构成摘要链
}

// RecoveryReport 是一次打开目录后崩溃恢复的对账结果。
type RecoveryReport struct {
	ActiveSegmentID int      `json:"active_segment_id"`
	RecoveredEvents int      `json:"recovered_events"` // 重放确认存活的事件条数（此前已确认成功的数据）
	DiscardedEvents int      `json:"discarded_events"` // 丢弃的半成品事件条数（未正常收尾的那一批）
	TruncatedBytes  int64    `json:"truncated_bytes"`  // 从活跃段尾部截断掉的字节数
	LegacyActive    bool     `json:"legacy_active"`    // 活跃段为旧版本（v0）格式
	Details         []string `json:"details"`          // 人可读的恢复过程说明
}

// pendingBatch 是扫描中尚未见到提交标记的一批事件。
type pendingBatch struct {
	startOffset int64
	raw         []byte
	events      []Event
}

// recoverActiveLocked 在打开存储时恢复活跃段：
// 重放已确认批次、丢弃半成品批次并截断坏尾，同时重建活跃段计数与摘要链锚点。
func (s *Store) recoverActiveLocked() (RecoveryReport, error) {
	rep := RecoveryReport{ActiveSegmentID: s.activeID}
	path := s.segmentPath(s.activeID)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return rep, nil // 没有活跃段，全新目录
		}
		return rep, err
	}
	if len(data) == 0 {
		return rep, nil
	}

	// 先扫一遍判断文件中是否出现过任何提交标记。
	anyMarker := scanHasCommitMarker(data)
	if !anyMarker {
		return s.recoverLegacyActiveLocked(path, data, rep)
	}
	return s.recoverBatchedActiveLocked(path, data, rep)
}

// scanHasCommitMarker 判断文件内容中是否存在提交标记行。
func scanHasCommitMarker(data []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 1<<20), 1<<22)
	for sc.Scan() {
		var head struct {
			Marker *string `json:"_audit_commit"`
		}
		if err := json.Unmarshal(sc.Bytes(), &head); err == nil && head.Marker != nil {
			return true
		}
	}
	return false
}

// recoverLegacyActiveLocked 处理旧版本（无提交标记）活跃段：
// 信任可解析前缀，仅截掉尾部坏行，沿用旧语义。
func (s *Store) recoverLegacyActiveLocked(path string, data []byte, rep RecoveryReport) (RecoveryReport, error) {
	rep.LegacyActive = true
	var goodOffset int64
	var recovered int
	var firstTS time.Time
	var linesAfter int64

	off := int64(0)
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 1<<20), 1<<22)
	lineNo := 0
	for sc.Scan() {
		line := sc.Bytes()
		lineStart := off
		off = lineStart + int64(len(line)) + 1 // Scanner 去掉了 '\n'
		lineNo++
		if len(line) == 0 {
			break
		}
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			break
		}
		goodOffset = off
		recovered++
		if recovered == 1 {
			firstTS = e.Timestamp
		}
		s.lastSeqs[e.Source] = maxUint64(s.lastSeqs[e.Source], e.Seq)
	}
	// 末尾无换行的半截行也算坏尾。
	if goodOffset < int64(len(data)) {
		linesAfter = countNonEmptyLines(data[goodOffset:])
		if err := s.truncateActiveLocked(path, goodOffset); err != nil {
			return rep, err
		}
	}

	rep.RecoveredEvents = recovered
	rep.DiscardedEvents = int(linesAfter)
	rep.TruncatedBytes = int64(len(data)) - goodOffset
	if recovered > 0 {
		rep.Details = append(rep.Details, fmt.Sprintf(
			"active segment %d 为旧格式（无提交标记）：按旧语义恢复可解析前缀 %d 条", s.activeID, recovered))
	}
	if rep.TruncatedBytes > 0 {
		rep.Details = append(rep.Details, fmt.Sprintf(
			"旧格式活跃段尾部存在不可解析内容：丢弃约 %d 条半成品/坏行，截断 %d 字节",
			linesAfter, rep.TruncatedBytes))
	}
	s.activeSize = goodOffset
	s.activeCount = recovered
	if recovered > 0 {
		s.activeStart = firstTS
	}
	s.usedBytes += goodOffset
	return rep, nil
}

// recoverBatchedActiveLocked 处理成组提交格式的活跃段。
func (s *Store) recoverBatchedActiveLocked(path string, data []byte, rep RecoveryReport) (RecoveryReport, error) {
	// 活跃段首批的 prev_digest 锚点：若该段从未封存过，则是上次封存时记录的
	// batch_anchor；manifest.last_digest 是最近封存段末批摘要，二者一致。
	var (
		goodOffset int64 = 0
		goodLen          = int64(len(data))
		pending    *pendingBatch
		recovered  int
		firstTS    time.Time
		digest     = s.activeBatchAnchor()
		off        int64
		lineNo     int
		aborted    bool
		abortWhy   string
	)

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 1<<20), 1<<22)
	for sc.Scan() && !aborted {
		raw := sc.Bytes()
		lineStart := off
		off = lineStart + int64(len(raw)) + 1
		lineNo++
		if len(raw) == 0 {
			aborted = true
			abortWhy = "出现空行，批次结构损坏"
			break
		}
		isCommit, ev, cr, derr := decodeRecordLine(raw)
		switch {
		case derr != nil:
			aborted = true
			abortWhy = fmt.Sprintf("第 %d 行不是合法 JSON 记录（半成品写入）: %v", lineNo, derr)
		case isCommit:
			if pending == nil {
				aborted = true
				abortWhy = fmt.Sprintf("第 %d 行提交标记前没有对应批次", lineNo)
				break
			}
			if cr.Marker != commitVersion {
				aborted = true
				abortWhy = fmt.Sprintf("提交标记版本不支持: %q", cr.Marker)
				break
			}
			if cr.Count != len(pending.events) {
				aborted = true
				abortWhy = fmt.Sprintf("批次 %s 声明 %d 条，实际 %d 条", cr.BatchID, cr.Count, len(pending.events))
				break
			}
			want := digestOf(pending.raw)
			if cr.Digest != want {
				aborted = true
				abortWhy = fmt.Sprintf("批次 %s 摘要不匹配（内容被改动或写入未完成）", cr.BatchID)
				break
			}
			if cr.PrevDigest != digest {
				// 摘要链断裂：内容自洽但与上一批对不上，属于外部改动迹象，按未确认处理。
				aborted = true
				abortWhy = fmt.Sprintf("批次 %s 摘要链断裂（prev_digest 与已恢复锚点不一致）", cr.BatchID)
				break
			}
			// 批次确认提交。
			goodOffset = off
			digest = cr.Digest
			recovered += len(pending.events)
			for _, e := range pending.events {
				s.lastSeqs[e.Source] = maxUint64(s.lastSeqs[e.Source], e.Seq)
			}
			if firstTS.IsZero() {
				firstTS = pending.events[0].Timestamp
			}
			pending = nil
		default:
			if pending == nil {
				pending = &pendingBatch{startOffset: lineStart}
			}
			pending.raw = append(pending.raw, append(append([]byte{}, raw...), '\n')...)
			pending.events = append(pending.events, ev)
		}
	}

	// 末尾无换行的半截行：Scan 读不到最后一段，它必然属于未提交的半成品。
	tornTail := goodOffset < int64(len(data)) && pending == nil && !aborted
	if pending != nil {
		aborted = true
		if abortWhy == "" {
			if !bytes.HasSuffix(data, []byte("\n")) {
				abortWhy = "最后一批在提交标记落盘前被中断（尾部无换行）"
				tornTail = true
			} else {
				abortWhy = fmt.Sprintf("最后 %d 条事件没有提交标记收尾（进程未正常收尾）", len(pending.events))
			}
		}
	}

	if aborted {
		goodLen = goodOffset
		if pending != nil {
			rep.DiscardedEvents = len(pending.events)
		}
		rep.Details = append(rep.Details, fmt.Sprintf(
			"活跃段 %d 中断批次处理: %s；丢弃 %d 条未确认事件",
			s.activeID, abortWhy, rep.DiscardedEvents))
	}
	if tornTail && rep.DiscardedEvents == 0 {
		rep.DiscardedEvents = int(countNonEmptyLines(data[goodOffset:]))
	}

	if goodLen < int64(len(data)) {
		if err := s.truncateActiveLocked(path, goodLen); err != nil {
			return rep, err
		}
		rep.TruncatedBytes = int64(len(data)) - goodLen
	}

	rep.RecoveredEvents = recovered
	if recovered > 0 {
		rep.Details = append(rep.Details, fmt.Sprintf(
			"活跃段 %d 重放确认 %d 条已提交事件，摘要链锚点有效", s.activeID, recovered))
		s.activeStart = firstTS
	}
	s.activeSize = goodLen
	s.activeCount = recovered
	s.usedBytes += goodLen
	s.lastDigest = digest
	s.batchAnchor = s.activeBatchAnchor()
	return rep, nil
}

// truncateActiveLocked 将活跃段截断到指定长度并持久化。
func (s *Store) truncateActiveLocked(path string, length int64) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if err := f.Truncate(length); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fsyncDir(s.dir) // 截断后的长度变更需要目录项持久化保证
	return nil
}

// rebuildSealedSeqsLocked 从已封存段重建各来源的已提交最大序号。
// 封存段受文件哈希保护，这里只做保守的前缀解析，损坏处停止。
func (s *Store) rebuildSealedSeqsLocked() {
	for _, seg := range s.sealed {
		data, err := os.ReadFile(s.segmentPath(seg.ID))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 0, 1<<20), 1<<22)
		for sc.Scan() {
			line := sc.Bytes()
			if len(line) == 0 {
				return
			}
			isCommit, ev, _, err := decodeRecordLine(line)
			if err != nil {
				return
			}
			if !isCommit {
				s.lastSeqs[ev.Source] = maxUint64(s.lastSeqs[ev.Source], ev.Seq)
			}
		}
	}
}

// errInvalidCommit 表示提交标记是完整 JSON 但关键字段自相矛盾（被改动）。
var errInvalidCommit = errors.New("invalid commit marker")

// decodeRecordLine 解析一行 JSONL，区分提交标记行与事件行。
// 调用方负责结合「坏行是否文件最后一行且无换行」区分截断（没写完）与篡改（行完整但被改）。
// 注意：JSON 意外结束时 Unmarshal 不会部分填充字段，因此先用原始字节特征识别记录类型。
func decodeRecordLine(line []byte) (isCommit bool, ev Event, cr commitRecord, err error) {
	isCommitLine := bytes.Contains(line, []byte(commitMarker))
	if isCommitLine {
		if err = json.Unmarshal(line, &cr); err != nil {
			return true, Event{}, commitRecord{}, err
		}
		if cr.Marker == "" || cr.Count <= 0 || cr.Digest == "" || cr.BatchID == "" {
			return true, Event{}, commitRecord{}, errInvalidCommit
		}
		return true, Event{}, cr, nil
	}
	if err = json.Unmarshal(line, &ev); err != nil {
		return false, Event{}, commitRecord{}, err
	}
	return false, ev, commitRecord{}, nil
}

// digestOf 计算批次原文（事件行拼接，含换行）的 SHA-256 十六进制摘要。
func digestOf(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func countNonEmptyLines(data []byte) int64 {
	n := int64(0)
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 1<<20), 1<<22)
	for sc.Scan() {
		if len(sc.Bytes()) > 0 {
			n++
		}
	}
	return n
}

func maxUint64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

// fsyncDir 持久化目录项变化（新建文件、rename、截断）。非 Linux 平台尽力而为。
func fsyncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// WriteBatch 以成组提交方式原子写入一批事件：要么整批确认，要么整批不可见。
// 序号连续性由 Writer 校验；Store 只负责轮转、容量与提交标记协议。
func (s *Store) WriteBatch(events []Event) error {
	if len(events) == 0 {
		return nil
	}
	var raw []byte
	for _, e := range events {
		line, err := json.Marshal(e)
		if err != nil {
			return fmt.Errorf("%w: marshal event: %v", ErrValidation, err)
		}
		raw = append(raw, line...)
		raw = append(raw, '\n')
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	first := events[0]
	total := int64(len(raw))

	// 轮转：以首批首事件时间戳衡量时间跨度，以整批字节数衡量大小。
	if s.activeCount > 0 {
		if s.rot.MaxAge > 0 && first.Timestamp.Sub(s.activeStart) >= s.rot.MaxAge {
			if err := s.sealLocked(first.Timestamp); err != nil {
				return err
			}
		}
		if s.rot.MaxBytes > 0 && s.activeSize+total > s.rot.MaxBytes {
			if err := s.sealLocked(first.Timestamp); err != nil {
				return err
			}
		}
	}

	cr := commitRecord{
		Marker:     commitVersion,
		BatchID:    fmt.Sprintf("seg%d@%d", s.activeID, s.activeSize),
		Count:      len(events),
		Digest:     digestOf(raw),
		PrevDigest: s.lastDigest,
	}
	markerLine, err := json.Marshal(cr)
	if err != nil {
		return err
	}
	markerLine = append(markerLine, '\n')
	total += int64(len(markerLine))

	// 容量检查（含提交标记）。
	if s.maxBytes > 0 && s.usedBytes+total > s.maxBytes {
		return fmt.Errorf("%w: batch need %d bytes, used %d of %d",
			ErrCapacity, total, s.usedBytes, s.maxBytes)
	}

	existed := true
	if _, err := os.Stat(s.segmentPath(s.activeID)); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		existed = false
	}
	f, err := os.OpenFile(s.segmentPath(s.activeID), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(markerLine); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil { // 事件与提交标记一起落盘后才算确认
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if !existed {
		fsyncDir(s.dir)
	}

	if s.activeCount == 0 {
		s.activeStart = first.Timestamp
	}
	s.activeSize += total
	s.activeCount += len(events)
	s.usedBytes += total
	s.lastDigest = cr.Digest
	return nil
}
