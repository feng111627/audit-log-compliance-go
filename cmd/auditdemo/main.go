// auditdemo 本地验证入口：写入事件 -> 轮转 -> 保留 -> 校验 -> 规则告警。
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	audit "github.com/feng111627/audit-log-compliance-go/audit"
)

func main() {
	dir := flag.String("dir", "", "日志存储目录（留空则使用临时目录）")
	flag.Parse()
	if *dir == "" {
		var err error
		*dir, err = mkTempDir()
		if err != nil {
			log.Fatal(err)
		}
	}

	rot := audit.RotationPolicy{MaxBytes: 1024}
	ret := audit.RetentionPolicy{MaxSegments: 3}
	store, err := audit.NewStore(*dir, rot, ret, 0)
	if err != nil {
		log.Fatal(err)
	}
	w := audit.NewWriter(store)

	base := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	// 两个来源并发语义下的顺序写入（demo 串行模拟）。
	seqs := map[string]uint64{}
	put := func(src string, ts time.Time, typ, actor string) {
		seqs[src]++
		e := audit.Event{Source: src, Seq: seqs[src], Timestamp: ts, Type: typ, Actor: actor}
		if err := w.Write(e); err != nil {
			fmt.Printf("write rejected: %v\n", err)
		}
	}
	for i := 0; i < 3; i++ {
		put("auth", base.Add(time.Duration(i+1)*10*time.Second), "login_failed", "alice")
	}
	put("sudo", base.Add(2*time.Minute), "privilege_escalation", "mallory")
	for i := 0; i < 20; i++ {
		put("app", base.Add(3*time.Minute+time.Duration(i)*time.Second), "request", "svc")
	}
	put("cron", base.Add(40*time.Minute), "job_run", "system")

	if err := store.Seal(); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("segments sealed: %d\n", len(store.Segments()))

	removed, err := store.ApplyRetention(time.Now())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("retention removed segment IDs: %v\n", removed)

	rep := audit.VerifyAll(store)
	fmt.Printf("verify ok=%v\n", rep.OK)
	for _, sr := range rep.Segments {
		fmt.Printf("  segment %d: %s %s\n", sr.SegmentID, sr.Reason, sr.Detail)
	}

	rules, err := audit.ParseRules([]byte(`[
		{"name":"login-burst","kind":"failed_login_burst","window":60000000000,"threshold":3},
		{"name":"priv-esc","kind":"privilege_escalation"},
		{"name":"gap","kind":"log_gap","window":600000000000}
	]`))
	if err != nil {
		log.Fatal(err)
	}
	events, err := store.AllEvents()
	if err != nil {
		log.Fatal(err)
	}
	for _, a := range audit.NewEngine(rules).Evaluate(events) {
		fmt.Printf("ALERT [%s] actor=%s count=%d: %s\n", a.Rule, a.Actor, a.Count, a.Message)
	}
	fmt.Printf("demo data dir: %s\n", *dir)
}

func mkTempDir() (string, error) {
	return os.MkdirTemp("", "auditdemo-")
}
