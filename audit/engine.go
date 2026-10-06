package audit

import (
	"fmt"
	"sort"
	"time"
)

// Alert 是一条告警结论。
type Alert struct {
	Rule    string    `json:"rule"`
	Actor   string    `json:"actor,omitempty"`
	Start   time.Time `json:"start"`
	End     time.Time `json:"end"`
	Count   int       `json:"count"`
	Message string    `json:"message"`
}

// Engine 按规则对事件流求值。求值是确定性的：
// 事件先按 (Timestamp, Source, Seq) 规范排序，相同输入重放后告警结论一致。
type Engine struct {
	rules []Rule
}

// NewEngine 用已校验的规则创建引擎。
func NewEngine(rules []Rule) *Engine {
	return &Engine{rules: rules}
}

// canonicalOrder 返回按 (Timestamp, Source, Seq) 排序的事件副本。
func canonicalOrder(events []Event) []Event {
	out := make([]Event, len(events))
	copy(out, events)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if !a.Timestamp.Equal(b.Timestamp) {
			return a.Timestamp.Before(b.Timestamp)
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.Seq < b.Seq
	})
	return out
}

// Evaluate 对事件求值并返回全部告警，告警按 (Start, Rule, Actor) 排序。
func (e *Engine) Evaluate(events []Event) []Alert {
	sorted := canonicalOrder(events)
	var alerts []Alert
	for _, r := range e.rules {
		switch r.Kind {
		case RuleFailedLoginBurst:
			alerts = append(alerts, evalFailedLoginBurst(r, sorted)...)
		case RulePrivilegeEscalation:
			alerts = append(alerts, evalPrivilegeEscalation(r, sorted)...)
		case RuleLogGap:
			alerts = append(alerts, evalLogGap(r, sorted)...)
		}
	}
	sort.SliceStable(alerts, func(i, j int) bool {
		a, b := alerts[i], alerts[j]
		if !a.Start.Equal(b.Start) {
			return a.Start.Before(b.Start)
		}
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		return a.Actor < b.Actor
	})
	return alerts
}

// evalFailedLoginBurst 对每个 actor 的登录失败事件做滑动窗口计数：
// 窗口内失败数达到阈值即告警，告警后从触发事件之后重新计数（不重叠）。
func evalFailedLoginBurst(r Rule, events []Event) []Alert {
	byActor := map[string][]Event{}
	for _, e := range events {
		if e.Type == EventTypeLoginFailed {
			byActor[e.Actor] = append(byActor[e.Actor], e)
		}
	}
	actors := make([]string, 0, len(byActor))
	for a := range byActor {
		actors = append(actors, a)
	}
	sort.Strings(actors) // 确定性遍历顺序

	var alerts []Alert
	for _, actor := range actors {
		evs := byActor[actor]
		for start := 0; start < len(evs); {
			triggered := false
			for end := start; end < len(evs); end++ {
				if evs[end].Timestamp.Sub(evs[start].Timestamp) > r.Window {
					break
				}
				if end-start+1 >= r.Threshold {
					alerts = append(alerts, Alert{
						Rule:  r.Name,
						Actor: actor,
						Start: evs[start].Timestamp,
						End:   evs[end].Timestamp,
						Count: end - start + 1,
						Message: fmt.Sprintf("actor %q had %d failed logins within %v",
							actor, end-start+1, r.Window),
					})
					start = end + 1
					triggered = true
					break
				}
			}
			if !triggered {
				start++
			}
		}
	}
	return alerts
}

// evalPrivilegeEscalation 每条权限提升事件产生一条告警。
func evalPrivilegeEscalation(r Rule, events []Event) []Alert {
	var alerts []Alert
	for _, e := range events {
		if e.Type != EventTypePrivilegeEscalation {
			continue
		}
		alerts = append(alerts, Alert{
			Rule:    r.Name,
			Actor:   e.Actor,
			Start:   e.Timestamp,
			End:     e.Timestamp,
			Count:   1,
			Message: fmt.Sprintf("actor %q performed privilege escalation: %s", e.Actor, e.Detail),
		})
	}
	return alerts
}

// evalLogGap 相邻事件（全局规范序）时间间隔超过窗口阈值即告警。
func evalLogGap(r Rule, events []Event) []Alert {
	var alerts []Alert
	for i := 1; i < len(events); i++ {
		gap := events[i].Timestamp.Sub(events[i-1].Timestamp)
		if gap > r.Window {
			alerts = append(alerts, Alert{
				Rule:  r.Name,
				Start: events[i-1].Timestamp,
				End:   events[i].Timestamp,
				Count: 1,
				Message: fmt.Sprintf("log gap of %v between %s and %s exceeds %v",
					gap, events[i-1].Timestamp.Format(time.RFC3339),
					events[i].Timestamp.Format(time.RFC3339), r.Window),
			})
		}
	}
	return alerts
}
