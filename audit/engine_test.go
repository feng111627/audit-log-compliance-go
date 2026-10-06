package audit

import (
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"time"
)

// TestParseRuleRejectsInvalid 覆盖业务：非法规则带原因拒绝，不静默跳过。
func TestParseRuleRejectsInvalid(t *testing.T) {
	t.Log("业务: 声明式规则 | 用例: 各类非法规则均返回带原因的错误")
	cases := []struct {
		name string
		data string
	}{
		{"语法错误", `{"name":`},
		{"缺名称", `{"kind":"log_gap","window":1000}`},
		{"未知类型", `{"name":"r","kind":"no_such_kind"}`},
		{"窗口缺失", `{"name":"r","kind":"failed_login_burst","threshold":3}`},
		{"阈值过小", `{"name":"r","kind":"failed_login_burst","window":1000,"threshold":1}`},
		{"空档窗口为负", `{"name":"r","kind":"log_gap","window":-5}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseRule([]byte(tc.data))
			if err == nil {
				t.Fatalf("rule %q should be rejected", tc.data)
			}
			t.Logf("拒绝: %s -> %v", tc.name, err)
		})
	}
	// 批量解析：任一非法则整体拒绝并指明下标。
	_, err := ParseRules([]byte(`[
		{"name":"ok","kind":"log_gap","window":1000},
		{"name":"","kind":"log_gap","window":1000}
	]`))
	if err == nil {
		t.Fatal("ParseRules should reject batch containing invalid rule")
	}
	t.Logf("结果: 批量解析整体拒绝并定位非法规则: %v", err)
}

func mustRule(t *testing.T, data string) Rule {
	t.Helper()
	r, err := ParseRule([]byte(data))
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}
	return r
}

// sampleEvents 构造覆盖三类规则的确定性事件集。
func sampleEvents() []Event {
	base := baseTime()
	var events []Event
	add := func(src string, seq uint64, ts time.Time, typ, actor string) {
		events = append(events, Event{Source: src, Seq: seq, Timestamp: ts, Type: typ, Actor: actor})
	}
	// actor alice 在 1 分钟内 3 次登录失败（触发 failed_login_burst）。
	add("auth", 1, base.Add(1*time.Second), "login_failed", "alice")
	add("auth", 2, base.Add(10*time.Second), "login_failed", "alice")
	add("auth", 3, base.Add(50*time.Second), "login_failed", "alice")
	// actor bob 分散的失败（不触发：窗口 1 分钟内不足 3 次）。
	add("auth", 4, base.Add(2*time.Second), "login_failed", "bob")
	add("auth", 5, base.Add(5*time.Minute), "login_failed", "bob")
	// 权限提升。
	add("sudo", 1, base.Add(2*time.Minute), "privilege_escalation", "mallory")
	// 日志空档：最后一条事件距前一条超过 10 分钟。
	add("cron", 1, base.Add(30*time.Minute), "job_run", "system")
	return events
}

// TestEngineAlerts 覆盖业务：三类规则各自产生预期告警。
func TestEngineAlerts(t *testing.T) {
	t.Log("业务: 合规告警 | 用例: 登录失败聚集/权限提升/日志空档各产生预期告警")
	rules := []Rule{
		mustRule(t, `{"name":"login-burst","kind":"failed_login_burst","window":60000000000,"threshold":3}`),
		mustRule(t, `{"name":"priv-esc","kind":"privilege_escalation"}`),
		mustRule(t, `{"name":"gap","kind":"log_gap","window":600000000000}`),
	}
	eng := NewEngine(rules)
	alerts := eng.Evaluate(sampleEvents())

	var burst, priv, gap []Alert
	for _, a := range alerts {
		switch a.Rule {
		case "login-burst":
			burst = append(burst, a)
		case "priv-esc":
			priv = append(priv, a)
		case "gap":
			gap = append(gap, a)
		}
	}
	if len(burst) != 1 || burst[0].Actor != "alice" || burst[0].Count != 3 {
		t.Fatalf("login-burst alerts wrong: %+v", burst)
	}
	if len(priv) != 1 || priv[0].Actor != "mallory" {
		t.Fatalf("priv-esc alerts wrong: %+v", priv)
	}
	if len(gap) != 1 {
		t.Fatalf("gap alerts wrong: %+v", gap)
	}
	for _, a := range alerts {
		t.Logf("告警: [%s] actor=%s count=%d %s", a.Rule, a.Actor, a.Count, a.Message)
	}
	t.Log("结果: 三类规则各产生 1 条预期告警，bob 的分散失败未误报")
}

// TestEngineReplayDeterminism 覆盖业务：重启/重放相同数据告警结论一致。
func TestEngineReplayDeterminism(t *testing.T) {
	t.Log("业务: 合规告警 | 用例: 相同数据乱序重放与重复求值，告警结论完全一致")
	rules := []Rule{
		mustRule(t, `{"name":"login-burst","kind":"failed_login_burst","window":60000000000,"threshold":3}`),
		mustRule(t, `{"name":"priv-esc","kind":"privilege_escalation"}`),
		mustRule(t, `{"name":"gap","kind":"log_gap","window":600000000000}`),
	}
	events := sampleEvents()
	base := NewEngine(rules).Evaluate(events)

	// 1) 重复求值（模拟重启后重放）。
	for i := 0; i < 3; i++ {
		got := NewEngine(rules).Evaluate(events)
		if !reflect.DeepEqual(base, got) {
			t.Fatalf("replay %d differs:\nbase=%+v\ngot=%+v", i, base, got)
		}
	}
	// 2) 乱序输入（模拟并发落盘后的读取顺序）结论一致。
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 5; i++ {
		shuffled := make([]Event, len(events))
		copy(shuffled, events)
		rng.Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })
		got := NewEngine(rules).Evaluate(shuffled)
		if !reflect.DeepEqual(base, got) {
			t.Fatalf("shuffled replay %d differs:\nbase=%+v\ngot=%+v", i, base, got)
		}
	}
	t.Logf("结果: 3 次重复求值 + 5 次乱序重放，%d 条告警结论完全一致", len(base))
}

// TestEngineReplayFromStore 覆盖业务：写入落盘后重新打开存储重放，告警一致。
func TestEngineReplayFromStore(t *testing.T) {
	t.Log("业务: 合规告警 | 用例: 事件经存储落盘、重启重载后重放，告警结论一致")
	dir := t.TempDir()
	rot := RotationPolicy{MaxBytes: 400}
	rules := []Rule{
		mustRule(t, `{"name":"login-burst","kind":"failed_login_burst","window":60000000000,"threshold":3}`),
		mustRule(t, `{"name":"gap","kind":"log_gap","window":600000000000}`),
	}

	// 按来源分组写入（保证每来源序号连续），来源间交错模拟并发。
	events := sampleEvents()
	bySrc := map[string][]Event{}
	for _, e := range events {
		bySrc[e.Source] = append(bySrc[e.Source], e)
	}
	store, err := NewStore(dir, rot, RetentionPolicy{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	w := NewWriter(store)
	for i := 0; i < len(events); i++ {
		for _, evs := range bySrc {
			if i < len(evs) {
				if err := w.Write(evs[i]); err != nil {
					t.Fatalf("write: %v", err)
				}
			}
		}
	}
	if err := store.Seal(); err != nil {
		t.Fatal(err)
	}
	want := NewEngine(rules).Evaluate(events)

	// 模拟重启：重新打开存储并校验后重放。
	store2, err := NewStore(dir, rot, RetentionPolicy{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if rep := VerifyAll(store2); !rep.OK {
		t.Fatalf("verify after reopen: %+v", rep.Segments)
	}
	loaded, err := store2.AllEvents()
	if err != nil {
		t.Fatal(err)
	}
	got := NewEngine(rules).Evaluate(loaded)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("replayed alerts differ:\nwant=%+v\ngot=%+v", want, got)
	}
	t.Logf("结果: 落盘重载后重放产生相同 %d 条告警", len(got))
}

// TestFailedLoginBurstWindowBoundary 覆盖业务：窗口边界行为确定。
func TestFailedLoginBurstWindowBoundary(t *testing.T) {
	t.Log("业务: 合规告警 | 用例: 窗口边界（恰好 window 内触发、超出 window 不触发）")
	rule := mustRule(t, `{"name":"b","kind":"failed_login_burst","window":10000000000,"threshold":2}`) // 10s
	base := baseTime()
	mk := func(at time.Duration) Event {
		return Event{Source: "s", Seq: 1, Timestamp: base.Add(at), Type: "login_failed", Actor: "a"}
	}
	// 恰好 10s 间隔：在窗口内（含边界），触发。
	in := []Event{mk(0), mk(10 * time.Second)}
	if got := NewEngine([]Rule{rule}).Evaluate(in); len(got) != 1 {
		t.Fatalf("boundary inside window: got %d alerts, want 1", len(got))
	}
	// 10.000000001s：超出窗口，不触发。
	out := []Event{mk(0), mk(10*time.Second + time.Nanosecond)}
	if got := NewEngine([]Rule{rule}).Evaluate(out); len(got) != 0 {
		t.Fatalf("outside window: got %d alerts, want 0", len(got))
	}
	t.Log("结果: 窗口为闭区间，边界行为确定")
}

var _ = fmt.Sprintf // 保留 fmt 引用（调试用）
