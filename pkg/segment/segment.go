// Package segment 实现审计日志的本地段落存储：顺序追加、哈希链防篡改、
// 按大小/时间轮转、按策略保留，并提供全量与增量完整性校验。
//
// 磁盘布局（全部位于存储目录内）：
//
//	manifest.json        段落清单（顺序、首帧前驱、封存摘要、时间范围）
//	segment-000001.log   数据段落，每行一帧，封存段落以 footer 行收尾
//
// 帧格式（单行 JSON，落盘即定形，校验直接按原始字节重算哈希）：
//
//	{"event":"<事件 JSON 原始字节>","prev":"<上一帧哈希，十六进制>","hash":"<sha256(prev|event) 十六进制>"}
//
// 封存段落最后一行是 footer：
//
//	{"footer":true,"count":N,"digest":"<最后一帧哈希>"}
//
// 哈希链跨段落延续：新段落第一帧的 prev 等于上一段落 footer 的 digest。
// 段落被保留策略删除后，剩余段落仍以清单中的 first_prev 为链首独立可验。
package segment

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/feng111627/audit-log-compliance-go/pkg/audit"
)

const (
	manifestName   = "manifest.json"
	segmentNameFmt = "segment-%06d.log"
)

// Entry 是清单中的段落元数据。Digest 为空表示段落尚未封存（仍在写入）。
type Entry struct {
	Name      string    `json:"name"`
	Index     int       `json:"index"`
	FirstPrev string    `json:"first_prev"`
	Digest    string    `json:"digest,omitempty"`
	Count     int       `json:"count"`
	Size      int64     `json:"size"`
	Sealed    bool      `json:"sealed"`
	MinTime   time.Time `json:"min_time,omitempty"`
	MaxTime   time.Time `json:"max_time,omitempty"`
}

type manifest struct {
	Segments  []Entry `json:"segments"`
	NextIndex int     `json:"next_index"`
}

// frame 是段落文件中的单行记录。Event 保留落盘原始字节，
// 任何字节级篡改都会使重算哈希与 frame.Hash 不一致。
type frame struct {
	Event json.RawMessage `json:"event"`
	Prev  string          `json:"prev"`
	Hash  string          `json:"hash"`
}

type footer struct {
	Footer bool   `json:"footer"`
	Count  int    `json:"count"`
	Digest string `json:"digest"`
}

// Store 基于本地目录的审计日志段落存储，实现 audit.Sink。
// Append 并发安全；同来源事件的物理顺序由 audit.Writer 持锁保证。
type Store struct {
	dir    string
	policy RotationPolicy
	now    func() time.Time

	mu sync.Mutex

	man *manifest
	cur *os.File
	// 当前（未封存）段落的内存状态
	curName  string
	curIndex int
	curFirst string // 本段首帧的前驱
	lastHash string // 最后一帧哈希，同时是全局链头
	count    int
	bytes    int64
	minTime  time.Time
	maxTime  time.Time
}

// Open 打开（或初始化）一个段落存储目录。now 为 nil 时使用系统时钟，
// 传入固定时钟可让时间轮转与保留行为可复现。
func Open(dir string, policy RotationPolicy, now func() time.Time) (*Store, error) {
	if now == nil {
		now = time.Now
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("segment: create dir: %w", err)
	}
	s := &Store{dir: dir, policy: policy, now: now}
	if err := s.loadManifest(); err != nil {
		return nil, err
	}
	if err := s.reopenLast(); err != nil {
		return nil, err
	}
	return s, nil
}

// Policy 返回当前轮转保留策略。
func (s *Store) Policy() RotationPolicy { return s.policy }

func manifestPath(dir string) string { return filepath.Join(dir, manifestName) }

func (s *Store) loadManifest() error {
	b, err := os.ReadFile(manifestPath(s.dir))
	if os.IsNotExist(err) {
		s.man = &manifest{Segments: []Entry{}, NextIndex: 1}
		return nil
	}
	if err != nil {
		return fmt.Errorf("segment: read manifest: %w", err)
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("segment: parse manifest: %w", err)
	}
	if m.NextIndex < 1 {
		m.NextIndex = 1
	}
	if m.Segments == nil {
		m.Segments = []Entry{}
	}
	s.man = &m
	return nil
}

// saveManifest 以临时文件原子替换方式落盘清单。
func (s *Store) saveManifestLocked() error {
	b, err := json.MarshalIndent(s.man, "", "  ")
	if err != nil {
		return fmt.Errorf("segment: encode manifest: %w", err)
	}
	tmp := manifestPath(s.dir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return fmt.Errorf("segment: write manifest: %w", err)
	}
	if err := os.Rename(tmp, manifestPath(s.dir)); err != nil {
		return fmt.Errorf("segment: replace manifest: %w", err)
	}
	return nil
}

// reopenLast 重开清单中最后一个未封存段落；若末段落已封存则保持关闭，
// 等待下一次 Append 创建新段落。
func (s *Store) reopenLast() error {
	if len(s.man.Segments) == 0 {
		return nil
	}
	last := s.man.Segments[len(s.man.Segments)-1]
	if last.Sealed {
		s.lastHash = s.man.Segments[len(s.man.Segments)-1].Digest
		return nil
	}
	f, err := os.OpenFile(filepath.Join(s.dir, last.Name), os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("segment: reopen %s: %w", last.Name, err)
	}
	// 扫描恢复链头、计数与字节数。
	lastDigest, n, size, mn, mx, err := scanTail(filepath.Join(s.dir, last.Name))
	if err != nil {
		f.Close()
		return err
	}
	s.cur = f
	s.curName = last.Name
	s.curIndex = last.Index
	s.curFirst = last.FirstPrev
	s.lastHash = lastDigest
	s.count = n
	s.bytes = size
	s.minTime = mn
	s.maxTime = mx
	return nil
}

// scanTail 顺序解析一个未封存段落，返回最后一帧哈希等可恢复状态。
func scanTail(path string) (lastHash string, count int, size int64, mn, mx time.Time, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, 0, mn, mx, fmt.Errorf("segment: open for recovery %s: %w", path, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	prev := ""
	for sc.Scan() {
		line := sc.Bytes()
		size += int64(len(line)) + 1
		var fr frame
		if err := json.Unmarshal(line, &fr); err != nil {
			return "", 0, 0, mn, mx, fmt.Errorf("segment: recovery parse frame in %s: %w", path, err)
		}
		if fr.Prev != prev {
			return "", 0, 0, mn, mx, fmt.Errorf("segment: recovery chain broken in %s", path)
		}
		if fr.Hash != digestFrame(fr.Prev, fr.Event) {
			return "", 0, 0, mn, mx, fmt.Errorf("segment: recovery hash mismatch in %s", path)
		}
		var ev audit.Event
		if err := json.Unmarshal(fr.Event, &ev); err != nil {
			return "", 0, 0, mn, mx, fmt.Errorf("segment: recovery event parse in %s: %w", path, err)
		}
		if mn.IsZero() || ev.Time.Before(mn) {
			mn = ev.Time
		}
		if mx.IsZero() || ev.Time.After(mx) {
			mx = ev.Time
		}
		prev = fr.Hash
		count++
	}
	return prev, count, size, mn, mx, sc.Err()
}

// digestFrame 计算帧哈希：sha256(prev + "|" + 事件原始 JSON)。
func digestFrame(prev string, eventJSON []byte) string {
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write([]byte("|"))
	h.Write(eventJSON)
	return hex.EncodeToString(h.Sum(nil))
}

// Append 追加一条已通过校验的事件，实现 audit.Sink。
func (s *Store) Append(ev audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.maybeRotateLocked(ev.Time); err != nil {
		return err
	}
	if err := s.enforceCapacityLocked(); err != nil {
		return err
	}
	if s.cur == nil {
		if err := s.createSegmentLocked(); err != nil {
			return err
		}
	}

	raw, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("segment: encode event %s: %w", ev.ID, err)
	}
	fr := frame{Event: raw, Prev: s.lastHash, Hash: digestFrame(s.lastHash, raw)}
	line, err := json.Marshal(fr)
	if err != nil {
		return fmt.Errorf("segment: encode frame %s: %w", ev.ID, err)
	}
	if _, err := s.cur.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("segment: write frame %s: %w", ev.ID, err)
	}

	s.lastHash = fr.Hash
	s.count++
	s.bytes += int64(len(line)) + 1
	if s.minTime.IsZero() || ev.Time.Before(s.minTime) {
		s.minTime = ev.Time
	}
	if s.maxTime.IsZero() || ev.Time.After(s.maxTime) {
		s.maxTime = ev.Time
	}
	s.updateCurEntryLocked()
	return nil
}

func (s *Store) createSegmentLocked() error {
	idx := s.man.NextIndex
	name := fmt.Sprintf(segmentNameFmt, idx)
	f, err := os.OpenFile(filepath.Join(s.dir, name), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("segment: create %s: %w", name, err)
	}
	s.man.NextIndex = idx + 1
	s.man.Segments = append(s.man.Segments, Entry{
		Name:      name,
		Index:     idx,
		FirstPrev: s.lastHash,
	})
	if err := s.saveManifestLocked(); err != nil {
		f.Close()
		return err
	}
	s.cur = f
	s.curName = name
	s.curIndex = idx
	s.curFirst = s.lastHash
	s.count = 0
	s.bytes = 0
	s.minTime = time.Time{}
	s.maxTime = time.Time{}
	return nil
}

func (s *Store) updateCurEntryLocked() {
	for i := range s.man.Segments {
		if s.man.Segments[i].Name == s.curName {
			s.man.Segments[i].Count = s.count
			s.man.Segments[i].Size = s.bytes
			s.man.Segments[i].MinTime = s.minTime
			s.man.Segments[i].MaxTime = s.maxTime
			return
		}
	}
}

// sealCurrentLocked 写入 footer、封存当前段落并落盘清单。
func (s *Store) sealCurrentLocked() error {
	if s.cur == nil || s.count == 0 {
		// 空段落直接丢弃，不产生 footer。
		if s.cur != nil {
			s.cur.Close()
			s.removeLastEntryLocked(s.curName)
			os.Remove(filepath.Join(s.dir, s.curName))
			s.resetCurLocked()
		}
		return nil
	}
	ft := footer{Footer: true, Count: s.count, Digest: s.lastHash}
	line, err := json.Marshal(ft)
	if err != nil {
		return err
	}
	if _, err := s.cur.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("segment: write footer: %w", err)
	}
	if err := s.cur.Close(); err != nil {
		return fmt.Errorf("segment: close sealed: %w", err)
	}
	for i := range s.man.Segments {
		if s.man.Segments[i].Name == s.curName {
			s.man.Segments[i].Sealed = true
			s.man.Segments[i].Digest = s.lastHash
			s.man.Segments[i].Count = s.count
			s.man.Segments[i].Size = s.bytes + int64(len(line)) + 1
			s.man.Segments[i].MinTime = s.minTime
			s.man.Segments[i].MaxTime = s.maxTime
		}
	}
	name := s.curName
	if err := s.saveManifestLocked(); err != nil {
		return fmt.Errorf("segment: persist seal %s: %w", name, err)
	}
	s.resetCurLocked()
	// 封存后统一执行保留策略（数量/年龄），保证 Close 与轮转路径行为一致。
	if err := s.enforceRetentionLocked(s.policy); err != nil {
		return fmt.Errorf("segment: retention after seal: %w", err)
	}
	return nil
}

func (s *Store) resetCurLocked() {
	s.cur = nil
	s.curName = ""
	s.curIndex = 0
	s.curFirst = ""
	s.count = 0
	s.bytes = 0
	s.minTime = time.Time{}
	s.maxTime = time.Time{}
	// lastHash 保留，作为下一段落的链头。
}

func (s *Store) removeLastEntryLocked(name string) {
	for i := len(s.man.Segments) - 1; i >= 0; i-- {
		if s.man.Segments[i].Name == name {
			s.man.Segments = append(s.man.Segments[:i], s.man.Segments[i+1:]...)
			return
		}
	}
}

// Close 封存活动段落并关闭存储。
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil {
		return nil
	}
	return s.sealCurrentLocked()
}
