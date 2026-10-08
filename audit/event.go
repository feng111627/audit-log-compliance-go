// Package audit 实现本地审计日志采集与合规检测流水线。
package audit

import (
	"errors"
	"fmt"
	"time"
)

// 写入失败的可区分原因。
var (
	// ErrValidation 事件校验不通过（字段缺失、序号重复或乱序等）。
	ErrValidation = errors.New("audit: validation failed")
	// ErrSourceClosed 来源已关闭，拒绝继续写入。
	ErrSourceClosed = errors.New("audit: source closed")
	// ErrCapacity 存储容量受限，拒绝写入。
	ErrCapacity = errors.New("audit: capacity exceeded")
	// ErrTruncatedRead 读取时遇到尾部不可解析行（被截短），已解析前缀随结果返回。
	ErrTruncatedRead = errors.New("audit: truncated read")
)

// Event 是一条审计事件。Seq 在同一 Source 内必须单调且连续（从 1 开始）。
type Event struct {
	Source    string    `json:"source"`
	Seq       uint64    `json:"seq"`
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"` // 如 login_failed / privilege_escalation / ...
	Actor     string    `json:"actor"`
	Detail    string    `json:"detail"`
}

// Validate 校验事件字段合法性（不含序号连续性，连续性由 Writer 按来源判定）。
func (e Event) Validate() error {
	if e.Source == "" {
		return fmt.Errorf("%w: empty source", ErrValidation)
	}
	if e.Seq == 0 {
		return fmt.Errorf("%w: seq must start from 1", ErrValidation)
	}
	if e.Type == "" {
		return fmt.Errorf("%w: empty type", ErrValidation)
	}
	if e.Timestamp.IsZero() {
		return fmt.Errorf("%w: zero timestamp", ErrValidation)
	}
	return nil
}
