package audit

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func baseTime() time.Time { return time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC) }

func newTestStore(t *testing.T, maxBytes int64) *Store {
	t.Helper()
	s, err := NewStore(t.TempDir(), RotationPolicy{}, RetentionPolicy{}, maxBytes)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s
}

// TestConcurrentWriteOrdering 覆盖业务：并发写入与顺序保证。
// 多个来源并发提交事件，同一来源内序号必须单调且连续。
func TestConcurrentWriteOrdering(t *testing.T) {
	t.Log("业务: 并发写入与顺序保证 | 用例: 8 来源 x 50 事件并发提交")
	store := newTestStore(t, 0)
	w := NewWriter(store)

	const sources = 8
	const perSource = 50
	var wg sync.WaitGroup
	for s := 0; s < sources; s++ {
		wg.Add(1)
		go func(s int) {
			defer wg.Done()
			src := fmt.Sprintf("host-%d", s)
			for i := 1; i <= perSource; i++ {
				e := Event{
					Source:    src,
					Seq:       uint64(i),
					Timestamp: baseTime().Add(time.Duration(i) * time.Second),
					Type:      "login_failed",
					Actor:     "user",
				}
				if err := w.Write(e); err != nil {
					t.Errorf("write %s seq %d: %v", src, i, err)
				}
			}
		}(s)
	}
	wg.Wait()

	events, err := store.AllEvents()
	if err != nil {
		t.Fatalf("AllEvents: %v", err)
	}
	if got, want := len(events), sources*perSource; got != want {
		t.Fatalf("committed %d events, want %d", got, want)
	}
	// 每个来源的序号必须恰好覆盖 1..perSource。
	seen := map[string]map[uint64]bool{}
	for _, e := range events {
		if seen[e.Source] == nil {
			seen[e.Source] = map[uint64]bool{}
		}
		if seen[e.Source][e.Seq] {
			t.Fatalf("duplicate committed seq %d for %s", e.Seq, e.Source)
		}
		seen[e.Source][e.Seq] = true
	}
	for s := 0; s < sources; s++ {
		src := fmt.Sprintf("host-%d", s)
		for i := 1; i <= perSource; i++ {
			if !seen[src][uint64(i)] {
				t.Fatalf("missing committed seq %d for %s", i, src)
			}
		}
		if got := w.LastSeq(src); got != perSource {
			t.Fatalf("LastSeq(%s)=%d, want %d", src, got, perSource)
		}
	}
	t.Logf("结果: %d 个事件全部提交，各来源序号 1..%d 单调连续无重复", len(events), perSource)
}

// TestDuplicateAndOutOfOrderRejected 覆盖业务：重复或乱序提交不得污染已提交数据。
func TestDuplicateAndOutOfOrderRejected(t *testing.T) {
	t.Log("业务: 并发写入与顺序保证 | 用例: 重复/乱序提交被拒绝且已提交数据不受污染")
	store := newTestStore(t, 0)
	w := NewWriter(store)
	mk := func(seq uint64) Event {
		return Event{Source: "app", Seq: seq, Timestamp: baseTime(), Type: "login_failed", Actor: "u"}
	}
	if err := w.Write(mk(1)); err != nil {
		t.Fatalf("seq1: %v", err)
	}
	if err := w.Write(mk(1)); !errors.Is(err, ErrValidation) {
		t.Fatalf("duplicate seq1: got %v, want ErrValidation", err)
	}
	if err := w.Write(mk(3)); !errors.Is(err, ErrValidation) {
		t.Fatalf("out-of-order seq3: got %v, want ErrValidation", err)
	}
	if err := w.Write(mk(2)); err != nil {
		t.Fatalf("seq2: %v", err)
	}
	events, _ := store.AllEvents()
	if len(events) != 2 || events[0].Seq != 1 || events[1].Seq != 2 {
		t.Fatalf("committed data polluted: %+v", events)
	}
	t.Log("结果: 重复与乱序提交均返回 ErrValidation，已提交数据仅含 seq 1,2")
}

// TestWriteFailureReasons 覆盖业务：写入失败原因可区分（校验/来源关闭/容量）。
func TestWriteFailureReasons(t *testing.T) {
	t.Log("业务: 并发写入与顺序保证 | 用例: 三类写入失败原因可 errors.Is 区分")
	store := newTestStore(t, 0)
	w := NewWriter(store)

	// 校验失败：字段缺失。
	bad := Event{Source: "app", Seq: 1, Timestamp: baseTime()}
	if err := w.Write(bad); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid event: got %v, want ErrValidation", err)
	}
	// 来源关闭。
	w.CloseSource("app")
	good := Event{Source: "app", Seq: 1, Timestamp: baseTime(), Type: "login_failed"}
	if err := w.Write(good); !errors.Is(err, ErrSourceClosed) {
		t.Fatalf("closed source: got %v, want ErrSourceClosed", err)
	}
	// 容量受限：容量只够一条带提交标记的事件（格式开销按提交标记行计入）。
	small, err := NewStore(t.TempDir(), RotationPolicy{}, RetentionPolicy{}, 600)
	if err != nil {
		t.Fatal(err)
	}
	w2 := NewWriter(small)
	e1 := Event{Source: "s", Seq: 1, Timestamp: baseTime(), Type: "login_failed", Actor: "a", Detail: "padding-padding-padding"}
	if err := w2.Write(e1); err != nil {
		t.Fatalf("first write: %v", err)
	}
	e2 := e1
	e2.Seq = 2
	if err := w2.Write(e2); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity: got %v, want ErrCapacity", err)
	}
	// 容量拒绝后序号不前进，缩小事件后仍可写入（提交标记更短）。
	e2small := Event{Source: "s", Seq: 2, Timestamp: baseTime(), Type: "login_failed"}
	if err := w2.Write(e2small); err != nil {
		t.Fatalf("retry after capacity rejection: %v", err)
	}
	t.Log("结果: ErrValidation / ErrSourceClosed / ErrCapacity 均可区分；容量拒绝不推进序号")
}
