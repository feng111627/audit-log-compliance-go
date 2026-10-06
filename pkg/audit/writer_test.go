package audit

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

// recordingSink 按落地顺序记录事件，并可注入容量错误。
type recordingSink struct {
	mu      sync.Mutex
	events  []Event
	failSeq int64 // >0 时该序号的 Append 返回容量错误（模拟）
	failSrc string
}

func (r *recordingSink) Append(ev Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failSrc != "" && ev.Source == r.failSrc && ev.Seq == r.failSeq {
		return fmt.Errorf("%w: simulated disk quota", ErrCapacityExceeded)
	}
	r.events = append(r.events, ev)
	return nil
}

func (r *recordingSink) snapshot() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Event, len(r.events))
	copy(out, r.events)
	return out
}

func mkEvent(id, src string, seq int64, typ string) Event {
	return Event{ID: id, Source: src, Seq: seq, Type: typ, Time: parseTestTime(seq)}
}

// TestWriterConcurrentSequentiality 业务：并发写入与同来源顺序保证。
func TestWriterConcurrentSequentiality(t *testing.T) {
	t.Log("【业务:并发写入】多来源 goroutine 并发提交，校验同来源序号单调连续、落地顺序一致")
	sink := &recordingSink{}
	w := NewWriter(sink)

	const sources = 8
	const perSource = 200
	var wg sync.WaitGroup
	errCh := make(chan error, sources*perSource)
	for s := 0; s < sources; s++ {
		wg.Add(1)
		go func(s int) {
			defer wg.Done()
			src := fmt.Sprintf("host-%d", s)
			for i := int64(1); i <= perSource; i++ {
				ev := mkEvent(fmt.Sprintf("%s-%d", src, i), src, i, "login_ok")
				if err := w.Submit(ev); err != nil {
					errCh <- err
				}
			}
		}(s)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("【业务:并发写入】顺序提交不应失败: %v", err)
	}

	got := sink.snapshot()
	if len(got) != sources*perSource {
		t.Fatalf("【业务:并发写入】落地事件数 = %d, 期望 %d", len(got), sources*perSource)
	}

	// 按来源分组验证：每个来源落地序号恰好 1..N 且物理顺序单调。
	seen := map[string]int64{}
	for _, ev := range got {
		next := seen[ev.Source] + 1
		if ev.Seq != next {
			t.Fatalf("【业务:并发写入】来源 %s 物理顺序乱序: 出现 seq=%d, 期望 %d",
				ev.Source, ev.Seq, next)
		}
		seen[ev.Source] = ev.Seq
	}
	for s := 0; s < sources; s++ {
		src := fmt.Sprintf("host-%d", s)
		if seen[src] != perSource {
			t.Fatalf("【业务:并发写入】来源 %s 落地 %d 条, 期望 %d", src, seen[src], perSource)
		}
	}
	t.Logf("【业务:并发写入】通过: %d 个来源共 %d 条事件全部按序落地", sources, len(got))
}

// TestWriterRejectsDuplicateAndGap 业务：重复/乱序提交拒绝且不污染已提交数据。
func TestWriterRejectsDuplicateAndGap(t *testing.T) {
	cases := []struct {
		name string
		seq  int64
	}{
		{"用例:重复提交 seq=1", 1},
		{"用例:回跳乱序 seq=2(已到3)", 2},
		{"用例:跳号乱序 seq=99", 99},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("【业务:写入校验】%s：必须返回 ErrInvalidEvent 且不落地", tc.name)
			sink := &recordingSink{}
			w := NewWriter(sink)
			for _, seq := range []int64{1, 2, 3} {
				if err := w.Submit(mkEvent(fmt.Sprintf("e%d", seq), "s", seq, "x")); err != nil {
					t.Fatal(err)
				}
			}
			err := w.Submit(mkEvent("bad", "s", tc.seq, "x"))
			if !errors.Is(err, ErrInvalidEvent) {
				t.Fatalf("期望 ErrInvalidEvent, 得到 %v", err)
			}
			if len(sink.snapshot()) != 3 {
				t.Fatalf("非法提交污染了已提交数据: 落地 %d 条", len(sink.snapshot()))
			}
			// 正确序号 4 仍可继续提交，证明状态未被污染。
			if err := w.Submit(mkEvent("e4", "s", 4, "x")); err != nil {
				t.Fatalf("污染后无法继续顺序提交: %v", err)
			}
		})
	}
}

// TestWriterClosedSource 业务：来源关闭后拒绝提交，错误可区分为 ErrSourceClosed。
func TestWriterClosedSource(t *testing.T) {
	t.Log("【业务:来源生命周期】关闭后提交返回 ErrSourceClosed；关闭幂等；不影响其他来源")
	sink := &recordingSink{}
	w := NewWriter(sink)
	if err := w.Submit(mkEvent("e1", "s1", 1, "x")); err != nil {
		t.Fatal(err)
	}
	w.CloseSource("s1")
	w.CloseSource("s1")
	err := w.Submit(mkEvent("e2", "s1", 2, "x"))
	if !errors.Is(err, ErrSourceClosed) {
		t.Fatalf("期望 ErrSourceClosed, 得到 %v", err)
	}
	// 先登记关闭、再提交也必须拒绝。
	w.CloseSource("s2")
	if err := w.Submit(mkEvent("x", "s2", 1, "x")); !errors.Is(err, ErrSourceClosed) {
		t.Fatalf("先关后写期望 ErrSourceClosed, 得到 %v", err)
	}
	// 其他来源不受影响。
	if err := w.Submit(mkEvent("o1", "s3", 1, "x")); err != nil {
		t.Fatal(err)
	}
}

// TestWriterCapacityFailure 业务：容量受限错误可区分且序号不前移、可重试。
func TestWriterCapacityFailure(t *testing.T) {
	t.Log("【业务:容量受限】底层返回容量错误时透传 ErrCapacityExceeded，序号不前移，重试成功")
	sink := &recordingSink{failSrc: "s", failSeq: 2}
	w := NewWriter(sink)
	if err := w.Submit(mkEvent("e1", "s", 1, "x")); err != nil {
		t.Fatal(err)
	}
	err := w.Submit(mkEvent("e2", "s", 2, "x"))
	if !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("期望 ErrCapacityExceeded, 得到 %v", err)
	}
	// 解除容量限制后原样重试。
	sink.mu.Lock()
	sink.failSrc = ""
	sink.mu.Unlock()
	if err := w.Submit(mkEvent("e2", "s", 2, "x")); err != nil {
		t.Fatalf("容量恢复后重试应成功: %v", err)
	}
	if got := sink.snapshot(); len(got) != 2 || got[1].Seq != 2 {
		t.Fatalf("重试后落地数据不符: %+v", got)
	}
}

// TestWriterFieldValidation 业务：事件字段非法带原因拒绝。
func TestWriterFieldValidation(t *testing.T) {
	t.Log("【业务:写入校验】空 ID/来源/类型、序号越界、零时间均返回 ErrInvalidEvent 且带原因")
	sink := &recordingSink{}
	w := NewWriter(sink)
	bad := []Event{
		{Source: "s", Seq: 1, Type: "x", Time: parseTestTime(1)},
		{ID: "i", Seq: 1, Type: "x", Time: parseTestTime(1)},
		{ID: "i", Source: "s", Seq: 1, Time: parseTestTime(1)},
		{ID: "i", Source: "s", Seq: 0, Type: "x", Time: parseTestTime(1)},
		{ID: "i", Source: "s", Seq: 1, Type: "x"},
	}
	for i, ev := range bad {
		if err := w.Submit(ev); !errors.Is(err, ErrInvalidEvent) {
			t.Fatalf("用例 #%d 期望 ErrInvalidEvent, 得到 %v", i+1, err)
		}
	}
	if len(sink.snapshot()) != 0 {
		t.Fatal("非法字段事件不得落地")
	}
}
