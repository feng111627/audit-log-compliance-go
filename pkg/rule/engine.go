package rule

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/feng111627/audit-log-compliance-go/pkg/audit"
)

// Alert 是一条确定性的合规告警。
type Alert struct {
	// RuleID 命中的规则。
	RuleID string `json:"rule_id"`
	// Reason 人类可读的判定原因。
	Reason string `json:"reason"`
	// Group 告警分组键（如按主体聚集时的 actor）。
	Group string `json:"group"`
	// WindowStart / WindowEnd 触发窗口的起止事件时间。
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
	// EventIDs 参与触发的事件 ID，按时间顺序。
	EventIDs []string `json:"event_ids"`
	// Fingerprint 由规则、窗口与事件集确定，相同数据重放必然相同，
	// 用于重启/重放后的结论比对与去重。
	Fingerprint string `json:"fingerprint"`
}

// hit 是窗口内一条命中事件。
type hit struct {
	t  time.Time
	id string
}

type thresholdState struct {
	hits []hit // 当前聚集窗口，已按时间清理过期项
}

type gapState struct {
	last    *hit
	emitted bool // 与同一 last 配对的尾段空档只报一次
}

type ruleState struct {
	r *Rule
	t thresholdState
	g gapState
}

// Engine 基于规则对事件流做窗口判定。
// 单引擎不是并发安全的；并发写入场景下应先落盘，再通过 Replay 统一判定。
type Engine struct {
	states []ruleState
}

// NewEngine 创建告警引擎。
func NewEngine(rules []Rule) *Engine {
	states := make([]ruleState, len(rules))
	for i := range rules {
		r := rules[i]
		states[i] = ruleState{r: &r}
	}
	return &Engine{states: states}
}

// groupKey 返回规则的聚集分组：声明了 actor 时恒为该 actor，
// 否则按事件 actor 分组（actor 为空归为 ""，即全局聚集）。
func (r *Rule) groupKey(ev audit.Event) string {
	if r.Actor != "" {
		return r.Actor
	}
	return ev.Actor
}

// Process 喂入一条事件，返回该事件直接触发的零条或多条告警。
// 事件必须按事件时间非递减喂入（Replay 已保证）。
func (e *Engine) Process(ev audit.Event) []Alert {
	var alerts []Alert
	for i := range e.states {
		st := &e.states[i]
		r := st.r
		if !r.Matches(ev) {
			continue
		}
		switch r.Kind {
		case KindThreshold:
			if a := st.feedThreshold(r, ev); a != nil {
				alerts = append(alerts, *a)
			}
		case KindGap:
			if a := st.feedGap(r, ev); a != nil {
				alerts = append(alerts, *a)
			}
		}
	}
	return alerts
}

// feedThreshold 维护滑动窗口并在首次达到阈值时告警一次。
// 触发后窗口内事件整体“消费”，后续事件重新聚集，
// 从而同一批事件不会因窗口重叠产生重复告警。
func (st *ruleState) feedThreshold(r *Rule, ev audit.Event) *Alert {
	cutoff := ev.Time.Add(-r.Window)
	kept := st.t.hits[:0]
	for _, h := range st.t.hits {
		if h.t.After(cutoff) { // 保留 t > evTime-window（边界外即过期）
			kept = append(kept, h)
		}
	}
	kept = append(kept, hit{t: ev.Time, id: ev.ID})
	st.t.hits = kept

	if len(kept) < r.Threshold {
		return nil
	}
	ids := make([]string, len(kept))
	for i, h := range kept {
		ids[i] = h.id
	}
	a := &Alert{
		RuleID:      r.ID,
		Reason:      fmt.Sprintf("%d matching events within %s", len(kept), r.Window),
		Group:       r.groupKey(ev),
		WindowStart: kept[0].t,
		WindowEnd:   kept[len(kept)-1].t,
		EventIDs:    ids,
	}
	a.Fingerprint = fingerprint(r.ID, a.WindowStart, a.WindowEnd, ids)
	st.t.hits = st.t.hits[:0] // 消费窗口
	return a
}

// feedGap 比较相邻命中事件，时间差 >= gap 即告警。
func (st *ruleState) feedGap(r *Rule, ev audit.Event) *Alert {
	cur := hit{t: ev.Time, id: ev.ID}
	prev := st.g.last
	st.g.emitted = false
	st.g.last = &cur
	if prev == nil {
		return nil
	}
	diff := cur.t.Sub(prev.t)
	if diff < r.Gap {
		return nil
	}
	ids := []string{prev.id, cur.id}
	a := &Alert{
		RuleID:      r.ID,
		Reason:      fmt.Sprintf("no matching event for %s (gap %s)", r.Gap, diff),
		Group:       r.groupKey(ev),
		WindowStart: prev.t,
		WindowEnd:   cur.t,
		EventIDs:    ids,
	}
	a.Fingerprint = fingerprint(r.ID, a.WindowStart, a.WindowEnd, ids)
	return a
}

// Flush 处理需要外部时钟才能成立的告警：gap 规则距最后一条命中事件
// 已超过 gap（日志持续空档）。now 之前不会再到达比 now 更新的事件时
// 调用（如停机、定时检查）；纯历史重放请用 Replay，它不产生尾段告警。
func (e *Engine) Flush(now time.Time) []Alert {
	var alerts []Alert
	for i := range e.states {
		st := &e.states[i]
		r := st.r
		if r.Kind != KindGap || st.g.last == nil || st.g.emitted {
			continue
		}
		if now.Sub(st.g.last.t) < r.Gap {
			continue
		}
		ids := []string{st.g.last.id}
		a := Alert{
			RuleID:      r.ID,
			Reason:      fmt.Sprintf("no matching event for %s up to %s", r.Gap, now.Sub(st.g.last.t)),
			Group:       "",
			WindowStart: st.g.last.t,
			WindowEnd:   now,
			EventIDs:    ids,
		}
		a.Fingerprint = fingerprint(r.ID, a.WindowStart, a.WindowEnd, ids)
		st.g.emitted = true
		alerts = append(alerts, a)
	}
	return alerts
}

// Replay 重放一批事件并得到确定性告警结论：
// 先按 (时间, 来源, 序号) 归并排序，消除并发到达顺序的影响，
// 再逐条喂入全新引擎。因此对相同的留存数据，重启或多次重放的
// 告警集合（含指纹）必然一致。
func (e *Engine) Replay(events []audit.Event) []Alert {
	sorted := make([]audit.Event, len(events))
	copy(sorted, events)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if !a.Time.Equal(b.Time) {
			return a.Time.Before(b.Time)
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.Seq < b.Seq
	})

	fresh := NewEngine(rulesOf(e))
	var alerts []Alert
	for _, ev := range sorted {
		alerts = append(alerts, fresh.Process(ev)...)
	}
	return alerts
}

func rulesOf(e *Engine) []Rule {
	out := make([]Rule, len(e.states))
	for i, st := range e.states {
		out[i] = *st.r
	}
	return out
}

// fingerprint 计算告警的确定性指纹。
func fingerprint(ruleID string, start, end time.Time, ids []string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%d|%d|%d", ruleID, start.UnixNano(), end.UnixNano(), len(ids))
	for _, id := range ids {
		h.Write([]byte("|" + id))
	}
	return hex.EncodeToString(h.Sum(nil))
}
