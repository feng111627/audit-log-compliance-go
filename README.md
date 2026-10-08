# audit-log-compliance-go

本地审计日志采集与合规检测流水线：用本地文件模拟日志来源，提供并发写入与顺序保证、
段落轮转/保留/完整性校验、异常中断后的崩溃恢复、部分损坏下的尽力抢救读取，
以及声明式规则的确定性合规告警。

## 结构

- `audit/event.go` — 事件模型与校验、可区分的写入失败原因
- `audit/writer.go` — 并发写入器，按来源保证序号单调连续；`NewWriterFromStore` 支持重启序号续接
- `audit/segment.go` — 段落存储：轮转、哈希链清单、fsync 落盘
- `audit/recovery.go` — **崩溃恢复**：重开目录时修复写一半的活跃段，给出重放/丢弃对账
- `audit/salvage.go` — **部分损坏抢救**：尽力读出可用历史并给出分类完整性报告
- `audit/retention.go` — **组合保留**：时间+数量+空间清理、冲突拒绝、删/留对账
- `audit/verify.go` — 全量 / 增量 / 含活跃段完整性校验，给出可区分判定原因
- `audit/rule.go` — 声明式规则解析与校验（非法规则带原因拒绝）
- `audit/engine.go` — 确定性告警引擎
- `cmd/auditdemo` — 本地端到端验证入口（含模拟崩溃→恢复续写）

## 事件格式

事件以 JSON Lines 追加到段落文件（`segment-000001.jsonl` …）：

```json
{"source":"auth","seq":1,"timestamp":"2026-10-06T00:00:01Z","type":"login_failed","actor":"alice","detail":"..."}
```

| 字段 | 说明 |
|---|---|
| `source` | 来源标识，非空 |
| `seq` | 来源内序号，从 1 开始，必须单调且连续 |
| `timestamp` | RFC3339 时间戳，非零 |
| `type` | 事件类型，如 `login_failed` / `privilege_escalation` |
| `actor` / `detail` | 行为主体与补充说明 |

文件格式向后兼容：本版本不改变既有 JSONL 行格式与 `manifest.json` 结构，
老数据目录可直接被新版 `NewStore` 打开。

## 崩溃恢复（异常中断后重启续写）

`Writer.Write` 只有在事件行写入 **并 fsync 成功** 后才返回成功；封存清单通过
`tmp + rename + 目录 fsync` 原子更新。因此进程在任意时刻被强杀后：

- **已确认事件一条不少**：重开目录时，`NewStore` 自动扫描活跃段，
  从头开始保留“连续、完整、可解析且通过事件校验”的前缀，这些都是上次已落盘确认的数据。
- **半成品不拖坏整批**：一旦遇到第一条坏行（写一半的截断 JSON、结构非法记录、
  无换行收尾的尾行），该行及其后的所有字节被视为未正常收尾的批次整体丢弃，
  并用临时文件 + 原子替换把活跃段重写回干净状态。
- **恢复后续写可一起通过校验**：恢复只改活跃段，绝不动已封存段；后续新写入与
  重放出的旧数据混合轮转封存后，全量/增量校验仍通过，不会因“上次没正常结束”被当成篡改。
- **对账可见**：`store.LastRecovery()` 返回 `RecoveryReport`：
  `Recovered` / `ReplayedEvents`（重放条数）/ `DiscardedLines`（丢弃条数）/
  `TruncatedBytes` / 逐条 `Issues`（坏行位置与分类）/ `SealedSegments`。
- **序号续接**：`audit.NewWriterFromStore(store)` 从现存事件（含恢复重放的活跃段）
  重建各来源最大序号，重启后用正确的下一个序号继续追加；重复提交仍按 `ErrValidation` 拒绝。

## 部分损坏抢救与完整性报告

段落被外部改动、尾部截短、整段丢失或单条记录结构损坏时，`audit.Salvage`
不会“一坏整批读不出来”，而是尽量读出其它段落乃至损坏段中仍完好的记录：

```go
rep, err := audit.Salvage(store, audit.SalvageOptions{
    AfterSegmentID: 0,    // 增量抢救：只看该 ID 之后；0 表示全量
    IncludeActive:  true, // 是否一并抢救未封存活跃段
})
```

`SalvageReport` 给出人可读的对账：

- `Segments[i].Reason` / `Detail`：问题出现在哪段；`Issues` 给出坏记录的**物理行号与字节偏移**。
- 损坏分类（`VerifyReason`）彼此可区分，不糊成一种说法：

  | 原因 | 含义 |
  |---|---|
  | `segment_missing` | 段落文件缺失（整段不见了） |
  | `tampered` | 行数与清单一致但内容哈希不匹配（内容被外部改动） |
  | `truncated` | 行数少于清单记录（尾部被截短，含无换行收尾的半行） |
  | `record_corrupt` | 记录内部结构损坏（某行无法解析为合法事件） |
  | `chain_broken` | 与相邻留存段落的哈希链断裂 |
  | `ok` | 通过 |

- 可信范围：好事件带 `TrustLevel`：`verified`（封存段哈希校验通过，密码学可信）、
  `salvaged`（结构完整但段落已损坏，无法哈希核对）、`active`（活跃段，尚无哈希锚点）。
  `TrustedEvents` 只含 verified 事件。
- 增量能否继续：`IncrementalOK` 为真表示锚点之后第一个新段完好、可接着增量校验；
  `LastVerifiedID` 给出损坏点之前最后一个连续完好段。锚点已被保留清理时返回
  `ErrIntegritySegmentMissing`（`errors.Is` 可判）。
- `store.AllEvents()` 也改为基于抢救读取：中段损坏时仍返回前后健康数据，坏行跳过。

`VerifyAll` / `VerifyIncremental` 保持原有签名与判定，并新增 `record_corrupt`；
需要把未封存活跃段也纳入结构校验时用 `audit.Verify(store, audit.VerifyOptions{IncludeActive: true})`。

## 轮转、保留与完整性校验

**轮转**（`RotationPolicy`）：段落按大小（`MaxBytes`）或时间跨度（`MaxAge`，按事件
时间戳衡量，保证重放确定）封存。封存时计算文件 SHA-256 写入 `manifest.json`，
并记录前一段哈希构成链（`prev_hash`）。

**保留**（`RetentionPolicy`）支持时间、数量、空间三类上限同时配置：

| 字段 | 含义 |
|---|---|
| `MaxSegments` | 最多保留的封存段数，0 不限 |
| `MaxAge` | 封存段最大保留时长（相对 `SealedAt`），0 不限 |
| `MaxBytes` | 封存段总占用字节上限，0 不限（按空间清理） |
| `MinAge` | 封存段至少保留时长（受保护下限），0 不限 |

`ApplyRetentionDetailed(now)` 取三类上限的并集，删除**最旧连续前缀**直到同时满足，
因此剩余段落哈希链连续、`VerifyAll` 与 `VerifyIncremental` 仍通过。返回 `RetentionResult`
可逐条核对：`Removed` / `Kept` / `Entries`（每段 deleted/retained/protected 及原因）/
`FreedBytes` / `RetainedUsed`。配置后确有超限会**真实删除文件**；未超限时 `Removed`
为空但 `Entries` 仍覆盖全部段，便于确认“是否真的执行过清理”。

**策略冲突拒绝**：若为满足 `MaxBytes`/`MaxSegments` 必须删除仍在 `MinAge`
保护期内的段落，判定为自相矛盾，返回 `audit.ErrRetentionConflict`
（可用 `errors.Is` 判），`RetentionResult.Conflict/ConflictMsg` 说明冲突段与边界，
**不删任何数据**，绝不悄悄把数据删了当没事。

`ApplyRetention(now)` 旧签名保留（委托给详细版本），只返回被删 ID，老代码无需改动。

**校验**：

- `VerifyAll(store)` — 全量校验所有已封存段落
- `VerifyIncremental(store, lastSealedID)` — 仅校验 `lastSealedID` 之后的新段，并锚定哈希链
- `Verify(store, VerifyOptions{IncludeActive: true})` — 额外对活跃段做结构校验

## 规则格式与告警

规则为 JSON，`window` 以纳秒整数表示：

```json
{"name":"login-burst","kind":"failed_login_burst","window":60000000000,"threshold":3}
```

支持的 `kind`：

- `failed_login_burst` — 窗口内同一 actor 的 `login_failed` 达到 `threshold`（≥2）即告警
- `privilege_escalation` — 出现 `privilege_escalation` 事件即告警
- `log_gap` — 相邻事件（全局规范序）间隔超过 `window` 即告警

`ParseRule` / `ParseRules` 对非法规则返回带原因的错误（未知类型、缺窗口、阈值过小等），
绝不静默跳过；批量解析任一非法即整体拒绝并指明下标。

**确定性**：求值前事件按 `(timestamp, source, seq)` 规范排序，告警按
`(start, rule, actor)` 排序；重启、乱序读取或重放相同数据，告警结论完全一致。

## 本地验证

```bash
# 运行全部单测（-v 日志按“业务: … | 用例: …”打印覆盖与通过情况）
go test ./... -v

# 含竞态检测
go test ./... -race

# 端到端 demo：写入 -> 模拟崩溃 -> 恢复续写 -> 轮转 -> 组合保留 -> 校验/抢救 -> 告警
go run ./cmd/auditdemo                      # 临时目录，默认模拟一次崩溃
go run ./cmd/auditdemo -crash=false         # 不模拟崩溃
go run ./cmd/auditdemo -dir /tmp/auditlog   # 指定目录，重复运行可观察重启续写
```

### 新能力对应的单测

| 业务 | 用例（测试函数） |
|---|---|
| 异常中断后重启续写 | `TestCrashRecoveryTornTail`（重放不丢/丢弃半成品/续写后全量校验）、`TestCrashRecoveryThenRotateAndIncremental`（跨恢复点轮转+全量增量）、`TestCrashRecoveryCleanShutdown`、`TestRecoveryDoesNotTouchSealedSegments`、`TestNewWriterFromStoreSeqResume` |
| 部分损坏读取与报告 | `TestSalvageDamageClassification`（四类损坏可区分）、`TestSalvageTrustedVsSalvaged`（可信范围）、`TestSalvageIncrementalReadiness`（增量能否继续）、`TestSalvageDoesNotAbortWholeHistory` |
| 组合保留清理与校验 | `TestRetentionByBytesActuallyDeletes`、`TestRetentionCombinedAgeAndCount`、`TestRetentionConflictRejectsDeletion`、`TestRetentionNoOpWhenWithinLimits`、`TestRetentionVerifyFullAndIncremental` |
| 老能力不回归 | `TestConcurrentWriteOrdering`、`TestDuplicateAndOutOfOrderRejected`、`TestWriteFailureReasons`、`TestRotationBySizeAndTime`、`TestRetentionThenVerify`、`TestVerifyDetectsCorruption`、`TestIncrementalVerifyChain` 及 `engine_test.go` 全部规则用例 |
