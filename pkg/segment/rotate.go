package segment

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/feng111627/audit-log-compliance-go/pkg/audit"
)

// RotationPolicy 描述轮转与保留策略。零值表示该维度不生效。
type RotationPolicy struct {
	// MaxSegmentBytes 单段落字节数达到该值即轮转。0 表示不按大小轮转。
	MaxSegmentBytes int64 `json:"max_segment_bytes,omitempty"`
	// MaxSegmentAge 当前段落首事件距下一个事件的时间跨度达到该值即轮转。
	// 判定使用事件时间（而非墙钟），保证固定时钟下行为可复现。0 表示不按时间轮转。
	MaxSegmentAge time.Duration `json:"max_segment_age,omitempty"`
	// MaxSegments 最多保留的段落数（封存时清理最旧段落）。0 表示不按数量保留。
	MaxSegments int `json:"max_segments,omitempty"`
	// MaxAge 封存时删除最大事件时间早于 (now - MaxAge) 的段落。
	// 活动段落不参与年龄删除，避免删除正在写入的数据。
	MaxAge time.Duration `json:"max_age,omitempty"`
	// MaxTotalBytes 全部段落总字节上限。0 表示不限。
	// 保留策略清理后仍超限，则本次写入返回 audit.ErrCapacityExceeded，
	// 已提交数据不受影响，调用方可在外部腾出空间后重试。
	MaxTotalBytes int64 `json:"max_total_bytes,omitempty"`
}

// maybeRotateLocked 在追加前判断是否需要轮转：大小或时间任一条件满足即封存。
func (s *Store) maybeRotateLocked(nextEventTime time.Time) error {
	if s.cur == nil {
		return nil
	}
	rotate := false
	if s.policy.MaxSegmentBytes > 0 && s.bytes >= s.policy.MaxSegmentBytes {
		rotate = true
	}
	if s.policy.MaxSegmentAge > 0 && !s.minTime.IsZero() {
		if nextEventTime.Sub(s.minTime) >= s.policy.MaxSegmentAge {
			rotate = true
		}
	}
	if !rotate {
		return nil
	}
	// sealCurrentLocked 封存后会统一执行保留策略。
	if err := s.sealCurrentLocked(); err != nil {
		return fmt.Errorf("segment: rotate seal: %w", err)
	}
	return nil
}

// maybeRotate 保留无参入口供外部（如定时器/测试）按需触发。
func (s *Store) maybeRotate() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil {
		return nil
	}
	return s.sealCurrentLocked()
}

// enforceRetentionLocked 按数量与年龄删除旧段落并更新清单。
// 只删除已封存段落；链上的删除是安全的，因为每个段落都记录了首帧前驱，
// 删除后剩余段落以各自 first_prev 为链首仍可完整验证。
func (s *Store) enforceRetentionLocked(p RotationPolicy) error {
	cutoff := time.Time{}
	if p.MaxAge > 0 {
		cutoff = s.now().Add(-p.MaxAge)
	}

	// 数量保留只在封存段落之间计数（活动段落不计入、永不删除）：
	// 保留最新的 MaxSegments 个封存段落，其余列入删除集。
	drop := map[string]bool{}
	if p.MaxSegments > 0 {
		var sealedNames []string
		for _, e := range s.man.Segments {
			if e.Sealed && !(s.cur != nil && e.Name == s.curName) {
				sealedNames = append(sealedNames, e.Name)
			}
		}
		if excess := len(sealedNames) - p.MaxSegments; excess > 0 {
			for _, name := range sealedNames[:excess] {
				drop[name] = true
			}
		}
	}

	kept := make([]Entry, 0, len(s.man.Segments))
	var removed []string
	for _, e := range s.man.Segments {
		if s.cur != nil && e.Name == s.curName {
			kept = append(kept, e) // 活动段落永不清理
			continue
		}
		dropByAge := !cutoff.IsZero() && e.Sealed && !e.MaxTime.IsZero() && e.MaxTime.Before(cutoff)
		if drop[e.Name] || dropByAge {
			removed = append(removed, e.Name)
			continue
		}
		kept = append(kept, e)
	}
	if len(removed) == 0 {
		return nil
	}
	for _, name := range removed {
		if err := os.Remove(filepath.Join(s.dir, name)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("segment: remove %s: %w", name, err)
		}
	}
	s.man.Segments = kept
	if err := s.saveManifestLocked(); err != nil {
		return fmt.Errorf("segment: persist retention: %w", err)
	}
	// 链头随剩余最旧段落的 first_prev 而定，不依赖被删段落。
	if s.cur == nil && len(s.man.Segments) > 0 {
		last := s.man.Segments[len(s.man.Segments)-1]
		if last.Sealed {
			s.lastHash = last.Digest
		}
	}
	return nil
}

// EnforceRetention 对外的保留策略清理入口（加锁包装）。
func (s *Store) EnforceRetention(p RotationPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enforceRetentionLocked(p)
}

// totalBytesLocked 统计清单中段落记录的总字节数。
func (s *Store) totalBytesLocked() int64 {
	var total int64
	for _, e := range s.man.Segments {
		total += e.Size
	}
	return total
}

// enforceCapacityLocked 在保留清理后检查总容量；仍超限则拒绝本次写入，
// 返回可被 errors.Is(err, audit.ErrCapacityExceeded) 识别的错误。
func (s *Store) enforceCapacityLocked() error {
	if s.policy.MaxTotalBytes <= 0 {
		return nil
	}
	if s.totalBytesLocked() >= s.policy.MaxTotalBytes {
		return fmt.Errorf("%w: store total bytes at limit", audit.ErrCapacityExceeded)
	}
	return nil
}
