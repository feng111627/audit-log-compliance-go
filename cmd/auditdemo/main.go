// auditdemo 本地验证入口：写入 ->（模拟崩溃）-> 恢复续写 -> 轮转 ->
// 组合保留 -> 全量/增量校验与部分损坏抢救报告 -> 规则告警。
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
	crash := flag.Bool("crash", true, "是否在演示中模拟进程被杀（活跃段写一半）")
	flag.Parse()
	if *dir == "" {
		var err error
		*dir, err = mkTempDir()
		if err != nil {
			log.Fatal(err)
		}
	}

	rot := audit.RotationPolicy{MaxBytes: 1024}
	// 组合保留：最多 5 段、封存超过 30 天清理、封存段总占用不超过 4KB，
	// 且任何段至少保留 1 小时（MinAge）。冲突时 ApplyRetentionDetailed 会拒绝。
	ret := audit.RetentionPolicy{
		MaxSegments: 5,
		MaxAge:      30 * 24 * time.Hour,
		MaxBytes:    4096,
		MinAge:      time.Hour,
	}
	store, err := audit.NewStore(*dir, rot, ret, 0)
	if err != nil {
		log.Fatal(err)
	}

	// 若目录是重开的，先看上次崩溃恢复的对账结果。
	if rec := store.LastRecovery(); rec.Recovered {
		fmt.Printf("[recovery] 活跃段 %d 恢复：重放 %d 条、丢弃 %d 条半成品、剔除 %d 字节\n",
			rec.ActiveSegmentID, rec.ReplayedEvents, rec.DiscardedLines, rec.TruncatedBytes)
	}

	w, err := audit.NewWriterFromStore(store)
	if err != nil {
		log.Fatal(err)
	}

	base := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	seqs := map[string]uint64{}
	put := func(src string, ts time.Time, typ, actor string) {
		seqs[src] = w.LastSeq(src) + 1
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

	// 模拟进程被杀：直接往活跃段尾部写半截 JSON（正常代码路径绝不会这样写）。
	if *crash {
		active := store.ActiveSegmentPath()
		f, ferr := os.OpenFile(active, os.O_APPEND|os.O_WRONLY, 0o644)
		if ferr == nil {
			_, _ = f.WriteString("\n{\"source\":\"cron\",\"seq\":1,\"timestamp\":\"2026-10-06T0")
			_ = f.Close()
			fmt.Println("[crash] 模拟进程被杀：活跃段尾部留下半截记录")
		}
		// 重开同一目录，触发自动恢复与序号续接。
		store, err = audit.NewStore(*dir, rot, ret, 0)
		if err != nil {
			log.Fatal(err)
		}
		rec := store.LastRecovery()
		fmt.Printf("[recovery] 重开恢复：重放 %d 条、丢弃 %d 条半成品\n",
			rec.ReplayedEvents, rec.DiscardedLines)
		w, err = audit.NewWriterFromStore(store)
		if err != nil {
			log.Fatal(err)
		}
	}

	put("cron", base.Add(40*time.Minute), "job_run", "system")
	if err := store.Seal(); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("segments sealed: %d\n", len(store.Segments()))

	// 组合保留（带删/留对账与冲突检测）。
	rres, err := store.ApplyRetentionDetailed(time.Now())
	if err != nil {
		fmt.Printf("[retention] 策略冲突，已拒绝清理: %v\n", err)
	} else {
		fmt.Printf("[retention] 删除 %d 段 %v，保留 %d 段，释放 %d 字节，留存占用 %d\n",
			len(rres.Removed), rres.Removed, len(rres.Kept), rres.FreedBytes, rres.RetainedUsed)
	}

	rep := audit.VerifyAll(store)
	fmt.Printf("verify full ok=%v\n", rep.OK)
	for _, sr := range rep.Segments {
		fmt.Printf("  segment %d: %s %s\n", sr.SegmentID, sr.Reason, sr.Detail)
	}

	// 部分损坏抢救报告（本 demo 数据健康，用于展示结构）。
	sal, serr := audit.Salvage(store, audit.SalvageOptions{IncludeActive: true})
	if serr != nil {
		log.Fatal(serr)
	}
	fmt.Printf("salvage ok=%v incrementalOK=%v lastVerified=%d events=%d verified=%d\n",
		sal.OK, sal.IncrementalOK, sal.LastVerifiedID, len(sal.Events), len(sal.TrustedEvents))
	for _, seg := range sal.Segments {
		marker := ""
		if seg.Sealed {
			marker = "sealed"
		} else {
			marker = "active"
		}
		fmt.Printf("  [%s] segment %d: %s good=%d dropped=%d %s\n",
			marker, seg.SegmentID, seg.Reason, seg.Good, seg.Dropped, seg.Detail)
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
