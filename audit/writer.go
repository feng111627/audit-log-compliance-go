package audit

import (
	"fmt"
	"sync"
)

// Writer 接收多来源并发写入，保证同一来源内序号单调连续，
// 并将通过校验的事件以成组提交方式追加到存储中。Writer 可安全并发使用。
//
// 重启续写：NewWriter 会从 Store 恢复出的各来源已提交最大序号继续编号，
// 因此重新打开同一日志目录后可以直接按原序号接着写。
type Writer struct {
	mu      sync.Mutex
	store   *Store
	lastSeq map[string]uint64
	closed  map[string]bool
}

// NewWriter 基于存储创建写入器，并用存储恢复出的序号快照初始化续写位置。
func NewWriter(store *Store) *Writer {
	w := &Writer{store: store, lastSeq: map[string]uint64{}, closed: map[string]bool{}}
	for src, seq := range store.SourceSeqs() {
		w.lastSeq[src] = seq
	}
	return w
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

	if err := w.checkSeqLocked(e.Source, e.Seq); err != nil {
		return err
	}
	if err := w.store.Append(e); err != nil {
		return err // ErrCapacity 等原样透传，不更新序号
	}
	w.lastSeq[e.Source] = e.Seq
	return nil
}

// WriteBatch 原子提交一批事件：同一批次内各来源序号必须连续且按序号升序，
// 任一条不合法则整批拒绝（存储中不留任何半成品），全部通过才整组成组提交。
// 适用「一批要么全有、要么全无」的对账场景。
func (w *Writer) WriteBatch(events []Event) error {
	if len(events) == 0 {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	// 先在内存中完整校验整批，任何一条不通过都不触盘。
	type srcState struct {
		next uint64
	}
	next := map[string]uint64{}
	for _, e := range events {
		if err := e.Validate(); err != nil {
			return err
		}
		if w.closed[e.Source] {
			return fmt.Errorf("%w: source %q", ErrSourceClosed, e.Source)
		}
		want, seen := next[e.Source]
		if !seen {
			want = w.lastSeq[e.Source] + 1
		}
		if e.Seq < want {
			if e.Seq <= w.lastSeq[e.Source] {
				return fmt.Errorf("%w: source %q duplicate seq %d (already committed)",
					ErrValidation, e.Source, e.Seq)
			}
			return fmt.Errorf("%w: source %q out-of-order seq %d within batch, want %d",
				ErrValidation, e.Source, e.Seq, want)
		}
		if e.Seq > want {
			return fmt.Errorf("%w: source %q gap in batch at seq %d, want %d",
				ErrValidation, e.Source, e.Seq, want)
		}
		next[e.Source] = e.Seq + 1
	}

	if err := w.store.WriteBatch(events); err != nil {
		return err // 整批未落盘，序号全部不前进
	}
	for src, n := range next {
		w.lastSeq[src] = n - 1
	}
	return nil
}

// checkSeqLocked 校验单来源序号连续性（调用方持锁）。
func (w *Writer) checkSeqLocked(source string, seq uint64) error {
	if w.closed[source] {
		return fmt.Errorf("%w: source %q", ErrSourceClosed, source)
	}
	want := w.lastSeq[source] + 1
	if seq < want {
		return fmt.Errorf("%w: source %q duplicate seq %d (already committed)", ErrValidation, source, seq)
	}
	if seq > want {
		return fmt.Errorf("%w: source %q out-of-order seq %d, want %d", ErrValidation, source, seq, want)
	}
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
