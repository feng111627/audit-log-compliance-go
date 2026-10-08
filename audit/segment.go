package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Segment 描述一个日志段落的元数据。
type Segment struct {
	ID          int       `json:"id"`
	Events      int       `json:"events"`
	Hash        string    `json:"hash"`         // 本段文件内容的 SHA-256
	PrevHash    string    `json:"prev_hash"`    // 前一封存段的哈希，构成链
	BatchAnchor string    `json:"batch_anchor"` // 本段首批提交标记的 prev_digest（段内摘要链起点）
	SealedAt    time.Time `json:"sealed_at"`
	FileName    string    `json:"file_name"`
}

// RotationPolicy 控制何时轮转段落。
type RotationPolicy struct {
	MaxBytes int64         // 段落最大字节数，0 表示不按大小轮转
	MaxAge   time.Duration // 段落最大时间跨度（按事件时间戳），0 表示不按时间轮转
}

// RetentionPolicy 控制保留策略。三个维度同时生效，删除的仍是最旧连续前缀。
type RetentionPolicy struct {
	MaxSegments int           // 最多保留的已封存段落数，0 表示不限
	MaxAge      time.Duration // 已封存段落最大保留时长（相对 SealedAt），0 表示不限
	MaxBytes    int64         // 已封存段落总占用字节上限，超出则从最旧段开始删除，0 表示不限
}

// manifest 是落盘的段落清单。
type manifest struct {
	Segments   []Segment `json:"segments"`
	LastDigest string    `json:"last_digest,omitempty"` // 最近一次成组提交的摘要（摘要链锚点）
}

// Store 管理段落文件的写入、轮转、保留与读取。
// 保留策略只清理最旧的连续前缀，因此剩余段落的哈希链保持连续可验证。
type Store struct {
	mu       sync.Mutex
	dir      string
	rot      RotationPolicy
	ret      RetentionPolicy
	maxBytes int64 // 总容量上限，0 表示不限

	sealed      []Segment
	activeID    int
	activeSize  int64
	activeCount int
	activeStart time.Time // 活跃段首条事件时间戳
	usedBytes   int64

	lastSeqs    map[string]uint64 // 恢复得到的各来源已提交最大序号（供 Writer 续写）
	lastDigest  string            // 最近一批的摘要（摘要链锚点）
	batchAnchor string            // 当前活跃段首批的 prev_digest 锚点
	recovery    RecoveryReport    // 打开时的崩溃恢复对账结果
}

// NewStore 创建或打开存储。maxBytes 为总容量上限（0 不限）。
// 若目录下已有清单与段落文件，则加载之（支持重启后继续校验）。
func NewStore(dir string, rot RotationPolicy, ret RetentionPolicy, maxBytes int64) (*Store, error) {
	if rot.MaxBytes < 0 || rot.MaxAge < 0 || ret.MaxSegments < 0 || ret.MaxAge < 0 || ret.MaxBytes < 0 || maxBytes < 0 {
		return nil, fmt.Errorf("%w: negative store policy value", ErrValidation)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{
		dir:      dir,
		rot:      rot,
		ret:      ret,
		maxBytes: maxBytes,
		activeID: 1,
		lastSeqs: map[string]uint64{},
	}
	// 加载已有清单。
	data, err := os.ReadFile(s.manifestPath())
	if err == nil {
		var m manifest
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("load manifest: %w", err)
		}
		s.sealed = m.Segments
		s.lastDigest = m.LastDigest
		if len(s.sealed) > 0 {
			s.activeID = s.sealed[len(s.sealed)-1].ID + 1
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	// 从已封存段重建各来源序号快照（封存段受哈希保护，损坏处保守停止）。
	s.rebuildSealedSeqsLocked()
	// 恢复活跃段：重放已确认批次、丢弃半成品并截断坏尾，回到可继续追加的正常状态。
	rep, err := s.recoverActiveLocked()
	if err != nil {
		return nil, fmt.Errorf("recover active segment: %w", err)
	}
	s.recovery = rep
	// 统计已封存段磁盘占用（活跃段占用已在恢复阶段计入）。
	for _, seg := range s.sealed {
		if fi, err := os.Stat(s.segmentPath(seg.ID)); err == nil {
			s.usedBytes += fi.Size()
		}
	}
	return s, nil
}

func (s *Store) manifestPath() string { return filepath.Join(s.dir, "manifest.json") }

func segmentFileName(id int) string { return fmt.Sprintf("segment-%06d.jsonl", id) }

func (s *Store) segmentPath(id int) string { return filepath.Join(s.dir, segmentFileName(id)) }

// Append 追加一条事件。单条事件即一个提交批次（事件行 + 提交标记），
// 容量不足时返回 ErrCapacity。批量原子提交请用 WriteBatch。
func (s *Store) Append(e Event) error {
	return s.WriteBatch([]Event{e})
}

// RecoveryReport 返回打开存储时崩溃恢复的对账结果。
func (s *Store) RecoveryReport() RecoveryReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recovery
}

// activeBatchAnchor 返回当前活跃段首批提交标记应有的 prev_digest 锚点：
// 取最近封存段开启时记录的锚点（即该段之后、新段首批之前的摘要位置）。
func (s *Store) activeBatchAnchor() string {
	if len(s.sealed) > 0 {
		// 最近封存段开启时的锚点是该段首批 prev；新活跃段紧接其后，
		// 其首批 prev 等于封存段最后一批 digest——打开时由 lastDigest 体现。
		return s.lastDigest
	}
	return "" // 没有封存段，从头开始
}

// SourceSeqs 返回恢复得到的各来源已提交最大序号快照。
func (s *Store) SourceSeqs() map[string]uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]uint64, len(s.lastSeqs))
	for k, v := range s.lastSeqs {
		out[k] = v
	}
	return out
}

// Seal 封存当前活跃段落。
func (s *Store) Seal() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sealLocked(time.Now())
}

// sealLocked 计算活跃段哈希并写入清单。空段不封存。
func (s *Store) sealLocked(at time.Time) error {
	if s.activeCount == 0 {
		return nil
	}
	sum, err := hashFile(s.segmentPath(s.activeID))
	if err != nil {
		return err
	}
	prev := ""
	if len(s.sealed) > 0 {
		prev = s.sealed[len(s.sealed)-1].Hash
	}
	s.sealed = append(s.sealed, Segment{
		ID:          s.activeID,
		Events:      s.activeCount,
		Hash:        sum,
		PrevHash:    prev,
		BatchAnchor: s.batchAnchor,
		SealedAt:    at,
		FileName:    segmentFileName(s.activeID),
	})
	s.activeID++
	s.activeSize = 0
	s.activeCount = 0
	s.activeStart = time.Time{}
	// 新活跃段首批的 prev_digest 锚点 = 刚封存段最后一批的摘要。
	s.batchAnchor = s.lastDigest
	return s.saveManifestLocked()
}

func (s *Store) saveManifestLocked() error {
	data, err := json.MarshalIndent(manifest{Segments: s.sealed, LastDigest: s.lastDigest}, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.manifestPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.manifestPath()); err != nil {
		return err
	}
	fsyncDir(s.dir) // rename 是目录项变更，需 fsync 目录保证崩溃后生效
	return nil
}

// ApplyRetention 按保留策略（数量 + 时间 + 空间）清理最旧连续前缀，返回被删除的段落 ID。
// 只删除连续前缀，保证剩余段落哈希链连续。
// 需要冲突告警/释放字节等可核对明细时，请用 ApplyRetentionDetailed 或 ApplyRetentionStrict。
func (s *Store) ApplyRetention(now time.Time) ([]int, error) {
	s.mu.Lock()
	res, err := s.applyRetentionLocked(now, false)
	s.mu.Unlock()
	return res.Removed, err
}

// Segments 返回当前全部已封存段落元数据。
func (s *Store) Segments() []Segment {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Segment, len(s.sealed))
	copy(out, s.sealed)
	return out
}

// ActiveSegmentID 返回当前活跃段落 ID。
func (s *Store) ActiveSegmentID() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeID
}

// ReadEvents 读取指定段落的全部事件。
func (s *Store) ReadEvents(segmentID int) ([]Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readEventsLocked(segmentID)
}

func (s *Store) readEventsLocked(segmentID int) ([]Event, error) {
	var events []Event
	data, err := os.ReadFile(s.segmentPath(segmentID))
	if err != nil {
		return nil, err
	}
	pos := 0
	for pos < len(data) {
		nl := bytes.IndexByte(data[pos:], '\n')
		var raw []byte
		lastLine := false
		if nl < 0 {
			raw = data[pos:]
			lastLine = true
			pos = len(data)
		} else {
			raw = data[pos : pos+nl]
			pos += nl + 1
		}
		if len(raw) == 0 {
			continue
		}
		isCommit, ev, _, derr := decodeRecordLine(raw)
		if derr != nil {
			// 坏行性质分类（关键信号是坏行是否文件最后一行且无换行）：
			//  - 在文件末尾且没有换行收尾 => 写入被拦腰打断 => truncated
			//  - 有完整换行收尾（语法错误、提交标记字段被改等）=> tampered
			if lastLine {
				return events, fmt.Errorf("%w: segment %d last record cut short (no trailing newline)",
					ErrTruncatedRead, segmentID)
			}
			if isCommit {
				return events, fmt.Errorf("segment %d: commit marker damaged: %w", segmentID, derr)
			}
			return events, fmt.Errorf("segment %d: corrupt event line: %w", segmentID, derr)
		}
		if !isCommit {
			events = append(events, ev)
		}
	}
	return events, nil
}

// AllEvents 按段落顺序读取全部未清理事件（含活跃段）。
func (s *Store) AllEvents() ([]Event, error) {
	s.mu.Lock()
	ids := make([]int, 0, len(s.sealed)+1)
	for _, seg := range s.sealed {
		ids = append(ids, seg.ID)
	}
	active := s.activeID
	s.mu.Unlock()

	var all []Event
	for _, id := range append(ids, active) {
		evs, err := s.ReadEvents(id)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		all = append(all, evs...)
	}
	return all, nil
}

// hashFile 计算文件内容的 SHA-256。
func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// 确保 sort 被使用（按 ID 排序段落供校验使用）。
func sortSegments(segs []Segment) {
	sort.Slice(segs, func(i, j int) bool { return segs[i].ID < segs[j].ID })
}
