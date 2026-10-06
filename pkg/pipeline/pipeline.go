// Package pipeline 把并发写入、轮转保留、完整性校验与合规告警组合为
// 一条可本地复现的流水线。
package pipeline

import (
	"fmt"
	"time"

	"github.com/feng111627/audit-log-compliance-go/pkg/audit"
	"github.com/feng111627/audit-log-compliance-go/pkg/rule"
	"github.com/feng111627/audit-log-compliance-go/pkg/segment"
)

// Config 是流水线配置。
type Config struct {
	// Dir 本地存储目录。
	Dir string
	// Policy 轮转与保留策略。
	Policy segment.RotationPolicy
	// Rules 合规规则集，应通过 rule.ParseRules 获得。
	Rules []rule.Rule
	// Now 可注入时钟；nil 使用系统时钟。测试/重放固定为虚拟时钟可复现。
	Now func() time.Time
}

// Pipeline 组合写入、轮转保留、校验与告警。
type Pipeline struct {
	writer *audit.Writer
	store  *segment.Store
	rules  []rule.Rule
}

// New 创建并打开流水线（恢复历史段落与哈希链）。
func New(cfg Config) (*Pipeline, error) {
	if cfg.Dir == "" {
		return nil, fmt.Errorf("pipeline: empty dir")
	}
	st, err := segment.Open(cfg.Dir, cfg.Policy, cfg.Now)
	if err != nil {
		return nil, err
	}
	return &Pipeline{
		writer: audit.NewWriter(st),
		store:  st,
		rules:  cfg.Rules,
	}, nil
}

// Submit 提交审计事件。错误可用 errors.Is 区分：
// audit.ErrInvalidEvent / audit.ErrSourceClosed / audit.ErrCapacityExceeded。
func (p *Pipeline) Submit(ev audit.Event) error {
	return p.writer.Submit(ev)
}

// CloseSource 关闭事件来源，之后该来源提交返回 ErrSourceClosed。
func (p *Pipeline) CloseSource(source string) { p.writer.CloseSource(source) }

// VerifyFull 全量完整性校验。
func (p *Pipeline) VerifyFull() (*segment.Report, error) { return p.store.VerifyFull() }

// VerifyIncremental 自锚点起增量完整性校验。
func (p *Pipeline) VerifyIncremental(anchor string) (*segment.Report, error) {
	return p.store.VerifyIncremental(anchor)
}

// Anchor 返回当前增量校验锚点（最后封存段落的 index:digest）。
func (p *Pipeline) Anchor() string { return p.store.Anchor() }

// Seal 封存当前活动段落（轮转后即可获得新锚点）。
func (p *Pipeline) Seal() error { return p.store.Seal() }

// EnforceRetention 立即按给定策略执行一次保留清理。
func (p *Pipeline) EnforceRetention(pol segment.RotationPolicy) error {
	return p.store.EnforceRetention(pol)
}

// ReplayAlerts 扫描全部留存事件并重放规则，得到确定性告警结论。
// 扫描会同步校验哈希链；若留存数据不完整，返回 *segment.ScanError，
// 不会对不可信数据产出告警。
func (p *Pipeline) ReplayAlerts() ([]rule.Alert, error) {
	var events []audit.Event
	if err := p.store.ScanEvents(func(ev audit.Event) error {
		events = append(events, ev)
		return nil
	}); err != nil {
		return nil, err
	}
	eng := rule.NewEngine(p.rules)
	return eng.Replay(events), nil
}

// Close 封存活动段落并释放资源。
func (p *Pipeline) Close() error { return p.store.Close() }
