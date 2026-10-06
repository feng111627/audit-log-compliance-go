package audit

import (
	"errors"
	"fmt"
	"time"
)

// Event 是一条审计事件。同一 Source 内 Seq 必须从 1 开始单调连续。
// 该结构同时是段落文件中的记录格式（JSON）。
type Event struct {
	// ID 事件唯一标识，用于在告警中引用与去重排查。
	ID string `json:"id"`
	// Source 事件来源标识；同一来源内序号必须单调连续。
	Source string `json:"source"`
	// Seq 来源内单调连续序号，首个事件为 1。
	Seq int64 `json:"seq"`
	// Type 事件类型，如 login_failed / privilege_granted。
	Type string `json:"type"`
	// Actor 事件关联主体（用户/服务账号）。
	Actor string `json:"actor,omitempty"`
	// Time 事件发生时间（UTC 存储以保证重放确定性）。
	Time time.Time `json:"time"`
	// Payload 附加属性，规则匹配可引用其中键值。
	Payload map[string]any `json:"payload,omitempty"`
}

// 提交失败的三类可区分原因。判定方可用 errors.Is 区分。
var (
	// ErrInvalidEvent 事件校验不通过（字段非法、序号重复或乱序等）。
	ErrInvalidEvent = errors.New("audit: invalid event")
	// ErrSourceClosed 来源已关闭，拒绝新的提交。
	ErrSourceClosed = errors.New("audit: source closed")
	// ErrCapacityExceeded 容量受限（段落大小等）导致写入失败。
	ErrCapacityExceeded = errors.New("audit: capacity exceeded")
)

// Validate 校验单条事件自身字段是否合法（不涉及来源序号状态）。
func (ev Event) Validate() error {
	if ev.ID == "" {
		return fmt.Errorf("%w: empty id", ErrInvalidEvent)
	}
	if ev.Source == "" {
		return fmt.Errorf("%w: event %s: empty source", ErrInvalidEvent, ev.ID)
	}
	if ev.Seq < 1 {
		return fmt.Errorf("%w: event %s source %s: seq must be >= 1, got %d",
			ErrInvalidEvent, ev.ID, ev.Source, ev.Seq)
	}
	if ev.Type == "" {
		return fmt.Errorf("%w: event %s source %s: empty type", ErrInvalidEvent, ev.ID, ev.Source)
	}
	if ev.Time.IsZero() {
		return fmt.Errorf("%w: event %s source %s: zero time", ErrInvalidEvent, ev.ID, ev.Source)
	}
	return nil
}

// 以下 getter 让 Event 满足规则匹配所需的最小接口（rule.eventLike）。
func (ev Event) GetSource() string          { return ev.Source }
func (ev Event) GetType() string            { return ev.Type }
func (ev Event) GetActor() string           { return ev.Actor }
func (ev Event) GetPayload() map[string]any { return ev.Payload }
