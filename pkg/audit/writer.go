package audit

import (
	"errors"
	"fmt"
	"sync"
)

// Sink 是事件通过校验后的落地目标，由段落存储实现。
// Append 必须并发安全，且同来源事件的落地顺序与提交顺序一致。
type Sink interface {
	Append(ev Event) error
}

type sourceState struct {
	next   int64 // 期望的下一个序号（首个为 1）
	closed bool
}

// Writer 负责并发提交的顺序保证与来源生命周期管理。
//
// 语义：
//   - 同一来源序号必须从 1 开始单调连续；
//   - 重复提交（seq < 期望值）或乱序提交（seq > 期望值）一律拒绝，
//     且绝不落地，不会污染已提交数据；
//   - 来源关闭后再提交返回 ErrSourceClosed；
//   - 字段非法返回 ErrInvalidEvent；
//   - 底层容量受限透传 ErrCapacityExceeded，且序号不前移，允许重试。
type Writer struct {
	mu      sync.Mutex
	sources map[string]*sourceState
	sink    Sink
}

// NewWriter 创建一个写入器。
func NewWriter(sink Sink) *Writer {
	return &Writer{
		sources: make(map[string]*sourceState),
		sink:    sink,
	}
}

// Submit 提交一条事件。多个 goroutine 可并发调用；
// 同一来源内会被串行化，保证落地顺序与序号顺序一致。
func (w *Writer) Submit(ev Event) error {
	if err := ev.Validate(); err != nil {
		return err
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	st, ok := w.sources[ev.Source]
	if !ok {
		st = &sourceState{next: 1}
		w.sources[ev.Source] = st
	}
	if st.closed {
		return fmt.Errorf("%w: source %s rejected event %s", ErrSourceClosed, ev.Source, ev.ID)
	}
	switch {
	case ev.Seq < st.next:
		return fmt.Errorf("%w: source %s duplicate seq %d, expected %d (event %s)",
			ErrInvalidEvent, ev.Source, ev.Seq, st.next, ev.ID)
	case ev.Seq > st.next:
		return fmt.Errorf("%w: source %s out-of-order seq %d, expected %d (event %s); "+
			"gap would corrupt committed sequence",
			ErrInvalidEvent, ev.Source, ev.Seq, st.next, ev.ID)
	}

	// 持锁落地：保证同来源事件在存储中的物理顺序与序号一致。
	if err := w.sink.Append(ev); err != nil {
		// 落地失败不前移序号，调用方可原样重试同一事件。
		if errors.Is(err, ErrCapacityExceeded) {
			return err
		}
		return err
	}
	st.next++
	return nil
}

// CloseSource 关闭一个来源；关闭后该来源的提交一律返回 ErrSourceClosed。
// 对已关闭来源重复调用是幂等的；对从未出现过的来源调用会直接登记为关闭，
// 以拒绝随后到来的任何提交。
func (w *Writer) CloseSource(source string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	st, ok := w.sources[source]
	if !ok {
		st = &sourceState{next: 1}
		w.sources[source] = st
	}
	st.closed = true
}
