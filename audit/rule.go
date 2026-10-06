package audit

import (
	"encoding/json"
	"fmt"
	"time"
)

// RuleKind 是支持的规则类型。
type RuleKind string

const (
	// RuleFailedLoginBurst 时间窗口内同一 actor 登录失败次数达到阈值。
	RuleFailedLoginBurst RuleKind = "failed_login_burst"
	// RulePrivilegeEscalation 窗口内出现权限提升事件即告警。
	RulePrivilegeEscalation RuleKind = "privilege_escalation"
	// RuleLogGap 相邻事件时间间隔超过窗口阈值（日志空档）。
	RuleLogGap RuleKind = "log_gap"
)

// 规则判定依赖的事件类型名。
const (
	EventTypeLoginFailed         = "login_failed"
	EventTypePrivilegeEscalation = "privilege_escalation"
)

// Rule 是一条声明式合规规则（JSON 可解析）。
//
//	{"name":"login-burst","kind":"failed_login_burst","window":60000000000,"threshold":3}
//
// window 以纳秒整数表示（time.Duration）。
type Rule struct {
	Name      string        `json:"name"`
	Kind      RuleKind      `json:"kind"`
	Window    time.Duration `json:"window"`
	Threshold int           `json:"threshold"`
}

// ParseRule 解析并校验单条规则；非法规则返回带原因的错误，绝不静默跳过。
func ParseRule(data []byte) (Rule, error) {
	var r Rule
	if err := json.Unmarshal(data, &r); err != nil {
		return Rule{}, fmt.Errorf("rule parse error: %w", err)
	}
	if err := r.validate(); err != nil {
		return Rule{}, err
	}
	return r, nil
}

// ParseRules 解析规则数组；任一规则非法则整体返回带原因与下标的错误。
func ParseRules(data []byte) ([]Rule, error) {
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("rules parse error: %w", err)
	}
	rules := make([]Rule, 0, len(raw))
	for i, item := range raw {
		r, err := ParseRule(item)
		if err != nil {
			return nil, fmt.Errorf("rule[%d]: %w", i, err)
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// validate 校验规则字段，返回带原因的错误。
func (r Rule) validate() error {
	if r.Name == "" {
		return fmt.Errorf("rule invalid: empty name")
	}
	switch r.Kind {
	case RuleFailedLoginBurst:
		if r.Window <= 0 {
			return fmt.Errorf("rule %q invalid: failed_login_burst requires window > 0, got %v", r.Name, r.Window)
		}
		if r.Threshold < 2 {
			return fmt.Errorf("rule %q invalid: failed_login_burst requires threshold >= 2, got %d", r.Name, r.Threshold)
		}
	case RulePrivilegeEscalation:
		// 单事件触发，无需窗口与阈值；若填写须非负。
		if r.Window < 0 || r.Threshold < 0 {
			return fmt.Errorf("rule %q invalid: negative window/threshold", r.Name)
		}
	case RuleLogGap:
		if r.Window <= 0 {
			return fmt.Errorf("rule %q invalid: log_gap requires window > 0 as gap threshold, got %v", r.Name, r.Window)
		}
	default:
		return fmt.Errorf("rule %q invalid: unknown kind %q", r.Name, r.Kind)
	}
	return nil
}
