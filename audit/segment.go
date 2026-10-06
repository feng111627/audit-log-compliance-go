package audit

import (
	"bufio"
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
	ID       int       `json:"id"`
	Events   int       `json:"events"`
	Hash     string    `json:"hash"`      // 本段文件内容的 SHA-256
	PrevHash string    `json:"prev_hash"` // 前一封存段的哈希，构成链
	SealedAt time.Time `json:"sealed_at"`
	FileName string    `json:"file_name"`
}

// RotationPolicy 控制何时轮转段落。
type RotationPolicy struct {
	MaxBytes int64         // 段落最大字节数，0 表示不按大小轮转
	MaxAge   time.Duration // 段落最大时间跨度（按事件时间戳），0 表示不按时间轮转
}

// RetentionPolicy 控制保留策略。
type RetentionPolicy struct {
	MaxSegments int           // 最多保留的已封存段落数，0 表示不限
	MaxAge      time.Duration // 已封存段落最大保留时长（相对 SealedAt），0 表示不限
}

// manifest 是落盘的段落清单。
type manifest struct {
	Segments []Segment `json:"segments"`
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
}

// NewStore 创建或打开存储。maxBytes 为总容量上限（0 不限）。
// 若目录下已有清单与段落文件，则加载之（支持重启后继续校验）。
func NewStore(dir string, rot RotationPolicy, ret RetentionPolicy, maxBytes int64) (*Store, error) {
	if rot.MaxBytes < 0 || rot.MaxAge < 0 || ret.MaxSegments < 0 || ret.MaxAge < 0 || maxBytes < 0 {
		return nil, fmt.Errorf("%w: negative store policy value", ErrValidation)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, rot: rot, ret: ret, maxBytes: maxBytes, activeID: 1}
	// 加载已有清单。
	data, err := os.ReadFile(s.manifestPath())
	if err == nil {
		var m manifest
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("load manifest: %w", err)
		}
		s.sealed = m.Segments
		if len(s.sealed) > 0 {
			s.activeID = s.sealed[len(s.sealed)-1].ID + 1
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	// 统计磁盘占用。
	for _, seg := range s.sealed {
		if fi, err := os.Stat(s.segmentPath(seg.ID)); err == nil {
			s.usedBytes += fi.Size()
		}
	}
	if fi, err := os.Stat(s.segmentPath(s.activeID)); err == nil {
		s.activeSize = fi.Size()
		s.usedBytes += fi.Size()
	}
	return s, nil
}

func (s *Store) manifestPath() string { return filepath.Join(s.dir, "manifest.json") }

func segmentFileName(id int) string { return fmt.Sprintf("segment-%06d.jsonl", id) }

func (s *Store) segmentPath(id int) string { return filepath.Join(s.dir, segmentFileName(id)) }

// Append 追加一条事件，必要时先触发轮转。容量不足时返回 ErrCapacity。
func (s *Store) Append(e Event) error {
	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("%w: marshal event: %v", ErrValidation, err)
	}
	line = append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	// 时间轮转：以事件时间戳衡量活跃段时间跨度，保证重放结果确定。
	if s.rot.MaxAge > 0 && s.activeCount > 0 && e.Timestamp.Sub(s.activeStart) >= s.rot.MaxAge {
		if err := s.sealLocked(e.Timestamp); err != nil {
			return err
		}
	}
	// 大小轮转。
	if s.rot.MaxBytes > 0 && s.activeCount > 0 && s.activeSize+int64(len(line)) > s.rot.MaxBytes {
		if err := s.sealLocked(e.Timestamp); err != nil {
			return err
		}
	}
	// 容量检查。
	if s.maxBytes > 0 && s.usedBytes+int64(len(line)) > s.maxBytes {
		return fmt.Errorf("%w: need %d bytes, used %d of %d", ErrCapacity, len(line), s.usedBytes, s.maxBytes)
	}

	f, err := os.OpenFile(s.segmentPath(s.activeID), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(line); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if s.activeCount == 0 {
		s.activeStart = e.Timestamp
	}
	s.activeSize += int64(len(line))
	s.activeCount++
	s.usedBytes += int64(len(line))
	return nil
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
		ID:       s.activeID,
		Events:   s.activeCount,
		Hash:     sum,
		PrevHash: prev,
		SealedAt: at,
		FileName: segmentFileName(s.activeID),
	})
	s.activeID++
	s.activeSize = 0
	s.activeCount = 0
	s.activeStart = time.Time{}
	return s.saveManifestLocked()
}

func (s *Store) saveManifestLocked() error {
	data, err := json.MarshalIndent(manifest{Segments: s.sealed}, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.manifestPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.manifestPath())
}

// ApplyRetention 按保留策略清理最旧的已封存段落，返回被删除的段落 ID。
// 只删除连续前缀，保证剩余段落哈希链连续。
func (s *Store) ApplyRetention(now time.Time) ([]int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	remove := 0
	// 按数量：超出 MaxSegments 的最旧段落。
	if s.ret.MaxSegments > 0 && len(s.sealed) > s.ret.MaxSegments {
		remove = len(s.sealed) - s.ret.MaxSegments
	}
	// 按时间：SealedAt 早于 now-MaxAge 的连续前缀。
	if s.ret.MaxAge > 0 {
		cutoff := now.Add(-s.ret.MaxAge)
		n := 0
		for n < len(s.sealed) && s.sealed[n].SealedAt.Before(cutoff) {
			n++
		}
		if n > remove {
			remove = n
		}
	}
	if remove == 0 {
		return nil, nil
	}
	var removed []int
	for _, seg := range s.sealed[:remove] {
		if fi, err := os.Stat(s.segmentPath(seg.ID)); err == nil {
			s.usedBytes -= fi.Size()
		}
		if err := os.Remove(s.segmentPath(seg.ID)); err != nil && !os.IsNotExist(err) {
			return removed, err
		}
		removed = append(removed, seg.ID)
	}
	s.sealed = s.sealed[remove:]
	return removed, s.saveManifestLocked()
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
	f, err := os.Open(s.segmentPath(segmentID))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var events []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("segment %d: corrupt line: %w", segmentID, err)
		}
		events = append(events, e)
	}
	return events, sc.Err()
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
