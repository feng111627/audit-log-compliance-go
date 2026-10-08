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

// RetentionPolicy 控制保留策略。可同时配置时间、数量与空间上限，
// 清理时按最旧连续前缀删除以同时满足全部上限。
type RetentionPolicy struct {
	MaxSegments int           // 最多保留的已封存段落数，0 表示不限
	MaxAge      time.Duration // 已封存段落最大保留时长（相对 SealedAt），0 表示不限
	MaxBytes    int64         // 已封存段落总占用上限（字节），0 表示不限
	MinAge      time.Duration // 封存段落至少保留时长（受保护，0 表示无下限）；
	// 若为满足 MaxBytes 而必须删除尚在 MinAge 保护期内的段落，判为策略冲突
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

	sealed       []Segment
	activeID     int
	activeSize   int64
	activeCount  int
	activeStart  time.Time // 活跃段首条事件时间戳
	usedBytes    int64
	lastRecovery RecoveryReport
}

// NewStore 创建或打开存储。maxBytes 为总容量上限（0 不限）。
// 若目录下已有清单与段落文件，则加载之（支持重启后继续校验）。
func NewStore(dir string, rot RotationPolicy, ret RetentionPolicy, maxBytes int64) (*Store, error) {
	if rot.MaxBytes < 0 || rot.MaxAge < 0 || ret.MaxSegments < 0 || ret.MaxAge < 0 || ret.MaxBytes < 0 || ret.MinAge < 0 || maxBytes < 0 {
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
	// 崩溃恢复：检查活跃段是否有写了一半的尾行/坏行，修复为可继续追加状态，
	// 并重建活跃段的计数、起始时间与占用统计。修复失败则拒绝打开，
	// 避免在可疑数据上继续追加造成序号冲突或数据污染。
	rec, rerr := s.recoverActiveLocked()
	if rerr != nil {
		return nil, rerr
	}
	s.lastRecovery = rec
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
	// 每条已确认事件落盘后 fsync：只有 Sync 成功返回，调用方才视为写入成功，
	// 进程随后被强杀时该事件不丢（不依赖 OS 页缓存的延迟回写）。
	if err := f.Sync(); err != nil {
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
	// 封存前确保段文件内容已落盘（Append 已逐条 Sync，这里为经其他途径写入兜底）。
	if sf, err := os.Open(s.segmentPath(s.activeID)); err == nil {
		_ = sf.Sync()
		_ = sf.Close()
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
	if err := os.Rename(tmp, s.manifestPath()); err != nil {
		return err
	}
	// 同步目录项，确保 rename 在崩溃前落盘。
	if df, err := os.Open(s.dir); err == nil {
		_ = df.Sync()
		_ = df.Close()
	}
	return nil
}

// ApplyRetention 按保留策略清理最旧的已封存段落，返回被删除的段落 ID。
// 只删除连续前缀，保证剩余段落哈希链连续。
// 组合策略的可核对明细与冲突检测请使用 ApplyRetentionDetailed。
func (s *Store) ApplyRetention(now time.Time) ([]int, error) {
	res, err := s.ApplyRetentionDetailed(now)
	if err != nil {
		return nil, err
	}
	return res.Removed, nil
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

// ActiveSegmentPath 返回当前活跃段落文件的绝对路径。
func (s *Store) ActiveSegmentPath() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.segmentPath(s.activeID)
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
// 单个段落部分损坏不会让整批历史读不出来：结构仍完好的事件照常返回，
// 损坏行被跳过；需要问题位置、分类与可信范围时请改用 Salvage。
func (s *Store) AllEvents() ([]Event, error) {
	rep, err := Salvage(s, SalvageOptions{IncludeActive: true})
	if err != nil {
		return nil, err
	}
	all := make([]Event, 0, len(rep.Events))
	for _, se := range rep.Events {
		all = append(all, se.Event)
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
