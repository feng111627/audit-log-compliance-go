package audit

import (
	"fmt"
	"sync"
)

// Writer 接收多来源并发写入，保证同一来源内序号单调连续，
// 并将通过校验的事件追加到存储中。Writer 可安全并发使用。
type Writer struct {
	mu      sync.Mutex
	store   *Store
	lastSeq map[string]uint64
	closed  map[string]bool
}

// NewWriter 基于存储创建写入器。
func NewWriter(store *Store) *Writer {
	return &Writer{store: store, lastSeq: map[string]uint64{}, closed: map[string]bool{}}
}

// Write 提交一条事件。返回值可用 errors.Is 区分：
//   - ErrValidation：字段非法、序号重复或乱序（不污染已提交数据）
//   - ErrSourceClosed：来源已关闭
//   - ErrCapacity：存储容量受限
func (w *Writer) Write(e Event) error {
	if err := e.Validate(); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed[e.Source] {
		return fmt.Errorf("%w: source %q", ErrSourceClosed, e.Source)
	}
	want := w.lastSeq[e.Source] + 1
	if e.Seq < want {
		return fmt.Errorf("%w: source %q duplicate seq %d (already committed)", ErrValidation, e.Source, e.Seq)
	}
	if e.Seq > want {
		return fmt.Errorf("%w: source %q out-of-order seq %d, want %d", ErrValidation, e.Source, e.Seq, want)
	}
	if err := w.store.Append(e); err != nil {
		return err // ErrCapacity 等原样透传，不更新序号
	}
	w.lastSeq[e.Source] = e.Seq
	return nil
}

// CloseSource 关闭指定来源，后续该来源的写入返回 ErrSourceClosed。
func (w *Writer) CloseSource(source string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed[source] = true
}

// LastSeq 返回指定来源已提交的最大序号（无提交时为 0）。
func (w *Writer) LastSeq(source string) uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastSeq[source]
}
