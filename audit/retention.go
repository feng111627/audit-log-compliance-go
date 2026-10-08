package audit

import (
	"fmt"
	"os"
	"time"
)

// 组合保留清理：在原有「按数量 / 按封存时间」之外，新增「按总占用空间」维度。
// 三个维度同时生效，删除的仍是最旧的连续前缀，因此剩余段落的哈希链保持连续。
//
// 冲突语义：当「空间上限」要求删除的段落越过了「数量 / 时间」窗口本该保留的
// 边界时，视为保留条件互相打架（既想留很久又想压到很小）。
//   - ApplyRetentionDetailed：仍执行删除以腾空间，但在结果里 Conflict=true
//     并给出明确 Warnings（不允许静默删掉当没事）；
//   - ApplyRetentionStrict：拒绝删除，返回 ErrRetentionConflict，保留数据原样。

// ErrRetentionConflict 表示保留条件互相打架。
var ErrRetentionConflict = fmt.Errorf("audit: retention policy conflict")

// RetentionResult 是一次保留清理的可核对结果。
type RetentionResult struct {
	Removed       []int    `json:"removed"`        // 实际删除的段落 ID（连续前缀）
	Remaining     []int    `json:"remaining"`      // 清理后留存的段落 ID
	FreedBytes    int64    `json:"freed_bytes"`    // 实际释放的字节数
	UsedBytes     int64    `json:"used_bytes"`     // 清理后封存段占用字节
	RemovedEvents int      `json:"removed_events"` // 被删除段落的事件总数
	Conflict      bool     `json:"conflict"`       // 是否发生保留条件冲突
	Warnings      []string `json:"warnings"`       // 冲突/告警说明（绝不静默）
}

// retentionPlan 是清理决策的内部结果。
type retentionPlan struct {
	countRemove     int  // 数量维度要求删除的前缀数
	ageRemove       int  // 时间维度要求删除的前缀数
	keepCutoff      int  // 数量+时间窗口「受保护」的边界：索引 >= keepCutoff 的段必须保留
	sizeRemove      int  // 空间维度要求删除到的前缀数
	sizeUnreachable bool // 即使删光全部封存段仍达不到空间上限
	needRemove      int  // 最终实际应删除的前缀数（三者最大值）
}

// planRetentionLocked 根据当前封存段与策略计算清理决策。
func (s *Store) planRetentionLocked(now time.Time) retentionPlan {
	plan := retentionPlan{}
	n := len(s.sealed)

	// 数量维度：超出 MaxSegments 的最旧前缀。
	if s.ret.MaxSegments > 0 && n > s.ret.MaxSegments {
		plan.countRemove = n - s.ret.MaxSegments
	}
	// 时间维度：SealedAt 早于 now-MaxAge 的连续前缀。
	if s.ret.MaxAge > 0 {
		cutoff := now.Add(-s.ret.MaxAge)
		for plan.ageRemove < n && s.sealed[plan.ageRemove].SealedAt.Before(cutoff) {
			plan.ageRemove++
		}
	}
	// 数量+时间窗口共同保护的边界：二者都会删的才是"自然过期"，
	// 超出这个边界继续删就是空间压力侵入了受保护窗口。
	plan.keepCutoff = plan.countRemove
	if plan.ageRemove > plan.keepCutoff {
		plan.keepCutoff = plan.ageRemove
	}

	// 空间维度：从最旧段开始，计算"删到占用 <= MaxBytes"需要删掉多少前缀。
	// 纯计算（不真删）。若要满足上限必须删光全部封存段（一个历史段都留不下），
	// 视为配置不可满足（空间与保留语义打架），标记 sizeUnreachable 交由上层告警。
	plan.sizeUnreachable = false
	if s.ret.MaxBytes > 0 {
		projected := s.sealedBytesLocked()
		cnt := 0
		if projected > s.ret.MaxBytes {
			for cnt < n {
				// 再删一段就没有封存段可留了：保留语义要求至少留住历史，
				// 不应为了满足空间上限把封存段清空 => 不可达。
				if cnt == n-1 {
					plan.sizeUnreachable = true
					break
				}
				if fi, err := os.Stat(s.segmentPath(s.sealed[cnt].ID)); err == nil {
					projected -= fi.Size()
				}
				cnt++
				if projected <= s.ret.MaxBytes {
					plan.sizeRemove = cnt
					break
				}
			}
		}
	}

	plan.needRemove = plan.keepCutoff
	if plan.sizeRemove > plan.needRemove {
		plan.needRemove = plan.sizeRemove
	}
	return plan
}

// ApplyRetentionDetailed 按数量+时间+空间组合策略清理，返回可核对结果与冲突告警。
// 发生冲突时（空间压力侵入数量/时间保护窗口）仍删除以满足空间上限，
// 但结果中 Conflict=true 且 Warnings 明确说明，绝不静默。
func (s *Store) ApplyRetentionDetailed(now time.Time) (RetentionResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applyRetentionLocked(now, false)
}

// ApplyRetentionStrict 严格模式：发生保留冲突时拒绝删除并返回 ErrRetentionConflict，
// 数据原样保留，由调用方决定如何处理（调大空间或缩短窗口）。
func (s *Store) ApplyRetentionStrict(now time.Time) (RetentionResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applyRetentionLocked(now, true)
}

func (s *Store) applyRetentionLocked(now time.Time, strict bool) (RetentionResult, error) {
	res := RetentionResult{}
	plan := s.planRetentionLocked(now)

	// 即使删光全部封存段仍达不到空间上限：这是不可满足的配置。
	// 不删除受保护窗口内的数据，只明确告警，由调用方调整空间上限或轮转大小。
	if plan.sizeUnreachable {
		res.Conflict = true
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"空间上限 %d 字节不可满足：即使清空全部 %d 个封存段（占用 %d 字节）仍超限；"+
				"建议调大 MaxBytes 或调小轮转 MaxBytes，本次不删除受保护数据",
			s.ret.MaxBytes, len(s.sealed), s.sealedBytesLocked()))
		plan.sizeRemove = plan.keepCutoff // 只允许删自然过期前缀
	}

	// 冲突判定：空间维度要求删除的段，越过了数量/时间窗口本应保护的边界。
	if plan.sizeRemove > plan.keepCutoff {
		res.Conflict = true
		msg := fmt.Sprintf(
			"保留条件冲突：空间上限 %d 字节要求删除 %d 个最旧段，但数量/时间窗口只允许删除 %d 个；"+
				"段 %d..%d 处于受保护窗口内",
			s.ret.MaxBytes, plan.sizeRemove, plan.keepCutoff,
			s.sealed[plan.keepCutoff].ID, s.sealed[plan.sizeRemove-1].ID)
		res.Warnings = append(res.Warnings, msg)
		if strict {
			// 严格模式：一个都不删，原样返回并报错。
			for _, seg := range s.sealed {
				res.Remaining = append(res.Remaining, seg.ID)
			}
			return res, fmt.Errorf("%w: %s", ErrRetentionConflict, msg)
		}
	}

	if plan.needRemove == 0 {
		// 没有可删的：若空间仍超限（段都在保护窗口里但总体积超标），也要告警，
		// 不能"配了清理结果啥都没动"还无声无息。
		if s.ret.MaxBytes > 0 {
			used := s.sealedBytesLocked()
			if used > s.ret.MaxBytes {
				res.Warnings = append(res.Warnings, fmt.Sprintf(
					"封存段占用 %d 字节仍超过空间上限 %d，但所有段落都在保留窗口内，无可删除前缀",
					used, s.ret.MaxBytes))
				res.Conflict = true
			}
		}
		for _, seg := range s.sealed {
			res.Remaining = append(res.Remaining, seg.ID)
		}
		res.UsedBytes = s.sealedBytesLocked()
		return res, nil
	}

	// 执行删除（连续前缀）。
	for i := 0; i < plan.needRemove; i++ {
		seg := s.sealed[i]
		size := int64(0)
		if fi, err := os.Stat(s.segmentPath(seg.ID)); err == nil {
			size = fi.Size()
		}
		if err := os.Remove(s.segmentPath(seg.ID)); err != nil && !os.IsNotExist(err) {
			// 中途失败：返回已删除部分，保证结果可核对。
			s.sealed = s.sealed[i:]
			_ = s.saveManifestLocked()
			s.fillRemainingLocked(&res)
			return res, err
		}
		res.Removed = append(res.Removed, seg.ID)
		res.FreedBytes += size
		res.RemovedEvents += seg.Events
		s.usedBytes -= size
	}
	fsyncDir(s.dir)
	s.sealed = s.sealed[plan.needRemove:]
	if err := s.saveManifestLocked(); err != nil {
		return res, err
	}
	s.fillRemainingLocked(&res)
	return res, nil
}

// sealedBytesLocked 统计当前封存段实际磁盘占用。
func (s *Store) sealedBytesLocked() int64 {
	var total int64
	for _, seg := range s.sealed {
		if fi, err := os.Stat(s.segmentPath(seg.ID)); err == nil {
			total += fi.Size()
		}
	}
	return total
}

// fillRemainingLocked 填充删除后留存段与占用信息。
func (s *Store) fillRemainingLocked(res *RetentionResult) {
	res.Remaining = res.Remaining[:0]
	for _, seg := range s.sealed {
		res.Remaining = append(res.Remaining, seg.ID)
	}
	res.UsedBytes = s.sealedBytesLocked()
}
