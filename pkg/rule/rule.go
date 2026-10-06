// Package rule 提供声明式合规规则的解析与确定性告警判定。
//
// 规则 JSON 格式（示例）：
//
//	{
//	  "id": "burst-login-failed",
//	  "description": "5 分钟内登录失败聚集",
//	  "kind": "threshold",
//	  "event_type": "login_failed",
//	  "actor": "",
//	  "window": "5m",
//	  "threshold": 5
//	}
//
// 空档规则：
//
//	{"id":"no-log","kind":"gap","window":"10m","gap":"10m"}
//
// 时间长度统一使用 Go duration 字符串（"90s"、"5m"、"1h30m"）。
package rule

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Kind 是规则判定类型。
type Kind string

const (
	// KindThreshold 时间窗口内匹配事件数量达到阈值（登录失败聚集、权限提升等）。
	KindThreshold Kind = "threshold"
	// KindGap 相邻匹配事件的时间差达到 gap（日志空档）。
	KindGap Kind = "gap"
)

// Matcher 是对 payload 键值的等值匹配（全部条件满足才算匹配）。
type Matcher map[string]string

// Rule 是一条声明式合规规则。
type Rule struct {
	ID          string        `json:"id"`
	Description string        `json:"description,omitempty"`
	Kind        Kind          `json:"kind"`
	Source      string        `json:"source,omitempty"`     // 空表示不限来源
	EventType   string        `json:"event_type,omitempty"` // 空表示匹配全部类型
	Actor       string        `json:"actor,omitempty"`      // 空表示不限主体
	Payload     Matcher       `json:"payload,omitempty"`    // payload 等值条件
	Window      time.Duration `json:"-"`                    // threshold: 滑动窗口；gap: 判定的时钟推进步长
	Threshold   int           `json:"threshold,omitempty"`  // KindThreshold 必需
	Gap         time.Duration `json:"-"`                    // KindGap 必需
}

// wireRule 是 JSON 传输形态：duration 使用字符串以保证可读、无歧义。
type wireRule struct {
	ID          string  `json:"id"`
	Description string  `json:"description,omitempty"`
	Kind        string  `json:"kind"`
	Source      string  `json:"source,omitempty"`
	EventType   string  `json:"event_type,omitempty"`
	Actor       string  `json:"actor,omitempty"`
	Payload     Matcher `json:"payload,omitempty"`
	Window      string  `json:"window,omitempty"`
	Threshold   *int    `json:"threshold,omitempty"`
	Gap         string  `json:"gap,omitempty"`
}

func parseDuration(field, raw string) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return 0, fmt.Errorf("field %q is required", field)
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("field %q invalid duration %q: %v", field, raw, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("field %q must be positive, got %q", field, raw)
	}
	return d, nil
}

// Matches 判断一条事件是否满足规则的过滤条件。
func (r *Rule) Matches(ev eventLike) bool {
	if r.Source != "" && ev.GetSource() != r.Source {
		return false
	}
	if r.EventType != "" && ev.GetType() != r.EventType {
		return false
	}
	if r.Actor != "" && ev.GetActor() != r.Actor {
		return false
	}
	for k, v := range r.Payload {
		if got, ok := ev.GetPayload()[k]; !ok || fmt.Sprint(got) != v {
			return false
		}
	}
	return true
}

// eventLike 抽象事件的可匹配字段，避免与 audit 包产生循环外的额外耦合。
type eventLike interface {
	GetSource() string
	GetType() string
	GetActor() string
	GetPayload() map[string]any
}

func (w *wireRule) toRule() (*Rule, error) {
	if strings.TrimSpace(w.ID) == "" {
		return nil, fmt.Errorf("rule rejected: field \"id\" is required")
	}
	r := &Rule{
		ID:          w.ID,
		Description: w.Description,
		Kind:        Kind(w.Kind),
		Source:      w.Source,
		EventType:   w.EventType,
		Actor:       w.Actor,
		Payload:     w.Payload,
	}
	switch r.Kind {
	case KindThreshold:
		if w.Threshold == nil {
			return nil, fmt.Errorf("rule %q rejected: kind %q requires field \"threshold\"", w.ID, w.Kind)
		}
		if *w.Threshold < 1 {
			return nil, fmt.Errorf("rule %q rejected: \"threshold\" must be >= 1, got %d", w.ID, *w.Threshold)
		}
		r.Threshold = *w.Threshold
		d, err := parseDuration("window", w.Window)
		if err != nil {
			return nil, fmt.Errorf("rule %q rejected: %v", w.ID, err)
		}
		r.Window = d
	case KindGap:
		d, err := parseDuration("gap", w.Gap)
		if err != nil {
			return nil, fmt.Errorf("rule %q rejected: %v", w.ID, err)
		}
		r.Gap = d
		// window 可选：存在时要求 >= gap，作为重放窗口推进参数。
		if strings.TrimSpace(w.Window) != "" {
			wd, err := parseDuration("window", w.Window)
			if err != nil {
				return nil, fmt.Errorf("rule %q rejected: %v", w.ID, err)
			}
			if wd < d {
				return nil, fmt.Errorf("rule %q rejected: window %s must be >= gap %s",
					w.ID, wd, d)
			}
			r.Window = wd
		} else {
			r.Window = d
		}
	default:
		return nil, fmt.Errorf("rule %q rejected: unknown kind %q (want %q or %q)",
			w.ID, w.Kind, KindThreshold, KindGap)
	}
	return r, nil
}

// ParseRule 解析并校验单条规则；任何非法或无法解析的输入都返回带原因的错误，
// 绝不静默跳过。
func ParseRule(data []byte) (*Rule, error) {
	var w wireRule
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		return nil, fmt.Errorf("rule parse rejected: %v", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("rule parse rejected: multiple JSON values, want exactly one rule")
	}
	return w.toRule()
}

// wireEnvelope 支持两种顶层形态：单条规则对象 或 {"rules":[...]} / 裸数组。
type wireEnvelope struct {
	Rules []json.RawMessage `json:"rules"`
}

// ParseRules 解析规则集（裸数组或 {"rules":[...]}），逐条严格校验。
// 任一条非法即整体拒绝并指明第几条、原因是什么，防止规则被静默忽略。
func ParseRules(data []byte) ([]Rule, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, fmt.Errorf("rules parse rejected: empty input")
	}
	var raws []json.RawMessage
	switch trimmed[0] {
	case '[':
		if err := json.Unmarshal(data, &raws); err != nil {
			return nil, fmt.Errorf("rules parse rejected: %v", err)
		}
	case '{':
		// 也可能是单条规则对象：尝试先按单条解析。
		if isSingleRule(data) {
			r, err := ParseRule(data)
			if err != nil {
				return nil, err
			}
			return []Rule{*r}, nil
		}
		var env wireEnvelope
		dec := json.NewDecoder(strings.NewReader(string(data)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&env); err != nil {
			return nil, fmt.Errorf("rules parse rejected: %v", err)
		}
		raws = env.Rules
	default:
		return nil, fmt.Errorf("rules parse rejected: unexpected leading character %q", trimmed[0])
	}
	if len(raws) == 0 {
		return nil, fmt.Errorf("rules parse rejected: rule set is empty")
	}

	rules := make([]Rule, 0, len(raws))
	seen := map[string]int{}
	for i, raw := range raws {
		r, err := ParseRule(raw)
		if err != nil {
			return nil, fmt.Errorf("rules parse rejected at rule #%d: %v", i+1, err)
		}
		if prev, dup := seen[r.ID]; dup {
			return nil, fmt.Errorf("rules parse rejected: duplicate rule id %q (#%d and #%d)",
				r.ID, prev+1, i+1)
		}
		seen[r.ID] = i
		rules = append(rules, *r)
	}
	return rules, nil
}

func isSingleRule(data []byte) bool {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	_, hasRules := probe["rules"]
	return !hasRules
}
