// auditdemo 本地验证入口：写入事件 -> 轮转 -> 保留 -> 校验 -> 规则告警，
// 并演示崩溃恢复对账、部分损坏容忍读取报告、时间+空间组合保留与冲突告警。
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

	// 组合保留：数量 + 封存时间 + 总占用空间三者一起配。
	rot := audit.RotationPolicy{MaxBytes: 1024}
	ret := audit.RetentionPolicy{MaxSegments: 5, MaxAge: 0, MaxBytes: 4096}
	store, err := audit.NewStore(*dir, rot, ret, 0)
	if err != nil {
		log.Fatal(err)
	}
	w := audit.NewWriter(store)

	// 重启续写：从存储恢复出的各来源最大序号继续编号，重开同一目录不会撞号。
	seqs := map[string]uint64{}
	for src, seq := range store.SourceSeqs() {
		seqs[src] = seq
	}
	base := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
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

	// 演示成组批量提交（要么整批可见，要么整批不可见）。
	batch := []audit.Event{
		{Source: "pay", Seq: 1, Timestamp: base.Add(45 * time.Minute), Type: "transfer", Actor: "bob"},
		{Source: "pay", Seq: 2, Timestamp: base.Add(46 * time.Minute), Type: "transfer", Actor: "bob"},
	}
	if err := w.WriteBatch(batch); err != nil {
		fmt.Printf("batch rejected: %v\n", err)
	}

	// 崩溃恢复对账：NewStore 打开时已自动完成活跃段恢复。
	if rr := store.RecoveryReport(); rr.RecoveredEvents > 0 || rr.DiscardedEvents > 0 || rr.TruncatedBytes > 0 {
		fmt.Printf("crash recovery: recovered=%d discarded=%d truncatedBytes=%d legacy=%v\n",
			rr.RecoveredEvents, rr.DiscardedEvents, rr.TruncatedBytes, rr.LegacyActive)
		for _, d := range rr.Details {
			fmt.Printf("  - %s\n", d)
		}
	} else {
		fmt.Println("crash recovery: clean open (nothing to recover)")
	}

	if err := store.Seal(); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("segments sealed: %d\n", len(store.Segments()))

	// 组合保留清理（详细结果 + 冲突告警）。
	rres, err := store.ApplyRetentionDetailed(time.Now())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("retention: removed=%v remaining=%v freedBytes=%d conflict=%v\n",
		rres.Removed, rres.Remaining, rres.FreedBytes, rres.Conflict)
	for _, wmsg := range rres.Warnings {
		fmt.Printf("  WARNING: %s\n", wmsg)
	}

	// 全量校验。
	rep := audit.VerifyAll(store)
	fmt.Printf("verify ok=%v\n", rep.OK)
	for _, sr := range rep.Segments {
		fmt.Printf("  segment %d: %s %s\n", sr.SegmentID, sr.Reason, sr.Detail)
	}

	// 部分损坏容忍读取报告（对当前健康数据也可运行，作为完整性快照）。
	irep := audit.SalvageAll(store)
	fmt.Printf("integrity: issues=%d incrementalCanContinue=%v nextAnchor=%d\n",
		len(irep.Issues), irep.IncrementalCanContinue, irep.NextAnchorID)
	for _, iss := range irep.Issues {
		fmt.Printf("  ISSUE seg=%d kind=%s line=%d: %s\n", iss.SegmentID, iss.Kind, iss.Line, iss.Detail)
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
