package audit

import (
	"errors"
	"fmt"
	"os"
	"time"
)

// ErrRetentionConflict 表示保留策略自相矛盾，无法同时满足
// （如既要求把某段留满 MinAge，又要求把封存段总占用压到 MaxBytes 以下）。
// 此时拒绝清理，绝不悄悄删数据。
var ErrRetentionConflict = errors.New("audit: retention policy conflict")

// RetentionEntry 是一次保留清理中单个段落的处置对账。
type RetentionEntry struct {
	SegmentID int       `json:"segment_id"`
	SealedAt  time.Time `json:"sealed_at"`
	Size      int64     `json:"size"`
	Deleted   bool      `json:"deleted"`
	Reason    string    `json:"reason"` // deleted-by-age / deleted-by-count / deleted-by-bytes / retained / protected-by-min-age
}

// RetentionResult 是一次组合保留清理的可核对结果。
type RetentionResult struct {
	Now          time.Time
	Removed      []int
	Kept         []int
	Entries      []RetentionEntry
	FreedBytes   int64
	RetainedUsed int64 // 清理后封存段总占用
	Conflict     bool
	ConflictMsg  string
}

// ApplyRetentionDetailed 按“时间 + 数量 + 空间”组合策略清理最旧连续前缀，
// 并产出删了什么、留了什么的可核对结果。
//
// 三类上限（MaxAge / MaxSegments / MaxBytes）取并集：删除最旧的连续前缀，
// 直到同时满足全部上限。MinAge 是受保护下限：若要满足某上限就必须删除仍在
// MinAge 保护期内的段落，则判定策略冲突，返回 ErrRetentionConflict 且不删任何数据。
func (s *Store) ApplyRetentionDetailed(now time.Time) (*RetentionResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := validateRetentionLocked(s.ret); err != nil {
		return nil, err
	}
	res := &RetentionResult{Now: now}
	n := len(s.sealed)
	if n == 0 {
		return res, nil
	}

	// 各段落文件大小（缺失按 0 计）。
	sizes := make([]int64, n)
	totalSize := int64(0)
	for i, seg := range s.sealed {
		if fi, err := os.Stat(s.segmentPath(seg.ID)); err == nil {
			sizes[i] = fi.Size()
			totalSize += fi.Size()
		}
	}

	cutoff := now.Add(-s.ret.MaxAge)
	protected := now.Add(-s.ret.MinAge) // SealedAt 晚于此值的段落受 MinAge 保护

	// needDelete[i] 表示段落 i 是否必须因某上限被删。删除只能是连续前缀，
	// 因此计算每个上限要求的前缀长度，取最大者。
	want := 0
	if s.ret.MaxSegments > 0 && n > s.ret.MaxSegments {
		want = n - s.ret.MaxSegments
	}
	if s.ret.MaxAge > 0 {
		c := 0
		for c < n && s.sealed[c].SealedAt.Before(cutoff) {
			c++
		}
		if c > want {
			want = c
		}
	}
	if s.ret.MaxBytes > 0 && totalSize > s.ret.MaxBytes {
		used := totalSize
		c := 0
		for c < n && used > s.ret.MaxBytes {
			used -= sizes[c]
			c++
		}
		if c > want {
			want = c
		}
	}

	// 冲突检测：被要求删除的前缀中，是否存在仍受 MinAge 保护的段落。
	if s.ret.MinAge > 0 && want > 0 {
		for i := 0; i < want; i++ {
			if !s.sealed[i].SealedAt.Before(protected) {
				res.Conflict = true
				res.ConflictMsg = fmt.Sprintf(
					"retention conflict: must delete segment %d (sealed %s) to satisfy limits, "+
						"but MinAge %s requires keeping it until %s",
					s.sealed[i].ID, s.sealed[i].SealedAt.Format(time.RFC3339),
					s.ret.MinAge, protected.Format(time.RFC3339))
				return res, fmt.Errorf("%w: %s", ErrRetentionConflict, res.ConflictMsg)
			}
		}
	}

	// 构建对账明细。
	entries := make([]RetentionEntry, 0, n)
	freed := int64(0)
	for i, seg := range s.sealed {
		e := RetentionEntry{SegmentID: seg.ID, SealedAt: seg.SealedAt, Size: sizes[i]}
		switch {
		case i < want:
			e.Deleted = true
			switch {
			case s.ret.MaxAge > 0 && seg.SealedAt.Before(cutoff):
				e.Reason = "deleted-by-age"
			case s.ret.MaxSegments > 0 && n-i > s.ret.MaxSegments:
				e.Reason = "deleted-by-count"
			default:
				e.Reason = "deleted-by-bytes"
			}
			res.Removed = append(res.Removed, seg.ID)
			freed += sizes[i]
		case s.ret.MinAge > 0 && !seg.SealedAt.Before(protected):
			e.Reason = "protected-by-min-age"
			res.Kept = append(res.Kept, seg.ID)
		default:
			e.Reason = "retained"
			res.Kept = append(res.Kept, seg.ID)
		}
		entries = append(entries, e)
	}
	res.Entries = entries
	res.FreedBytes = freed
	res.RetainedUsed = totalSize - freed

	if want == 0 {
		return res, nil
	}

	// 实际删除连续前缀。
	deleted := 0
	for i := 0; i < want; i++ {
		seg := s.sealed[i]
		if err := os.Remove(s.segmentPath(seg.ID)); err != nil && !os.IsNotExist(err) {
			// 部分删除失败：提交已删部分并返回错误，已删部分仍记在结果里。
			s.sealed = s.sealed[deleted:]
			s.usedBytes -= freedUpTo(sizes, deleted)
			_ = s.saveManifestLocked()
			return res, err
		}
		deleted++
	}
	s.sealed = s.sealed[deleted:]
	s.usedBytes -= freedUpTo(sizes, deleted)
	if s.usedBytes < 0 {
		s.usedBytes = 0
	}
	return res, s.saveManifestLocked()
}

// freedUpTo 计算前 n 个段落文件占用之和。
func freedUpTo(sizes []int64, n int) int64 {
	var sum int64
	for i := 0; i < n && i < len(sizes); i++ {
		sum += sizes[i]
	}
	return sum
}

// validateRetentionLocked 校验保留策略本身的非法值。
func validateRetentionLocked(ret RetentionPolicy) error {
	if ret.MaxSegments < 0 || ret.MaxAge < 0 || ret.MaxBytes < 0 || ret.MinAge < 0 {
		return fmt.Errorf("%w: negative retention policy value", ErrValidation)
	}
	return nil
}
