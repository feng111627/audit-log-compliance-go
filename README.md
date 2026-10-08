# audit-log-compliance-go

本地审计日志采集与合规检测流水线：用本地文件模拟日志来源，提供并发写入与顺序保证、
段落轮转/保留/完整性校验、声明式规则的确定性合规告警，并在此基础上提供贴近线上运维的
崩溃恢复续写、部分损坏容忍读取与完整性报告、时间+空间组合保留能力。

## 结构

- `audit/event.go` — 事件模型与校验、可区分的写入/读取失败原因
- `audit/writer.go` — 并发写入器，按来源保证序号单调连续，重启后续写，支持成组批量提交
- `audit/segment.go` — 段落存储：轮转、保留、哈希链清单、崩溃自动恢复
- `audit/recovery.go` — 成组提交协议与崩溃恢复（提交标记、摘要链、对账报告）
- `audit/salvage.go` — 部分损坏容忍读取与分类完整性报告
- `audit/retention.go` — 数量+时间+空间组合保留、冲突拒绝/告警、可核对结果
- `audit/verify.go` — 全量 / 增量完整性校验，给出可区分判定原因
- `audit/rule.go` — 声明式规则解析与校验（非法规则带原因拒绝）
- `audit/engine.go` — 确定性告警引擎
- `cmd/auditdemo` — 本地端到端验证入口

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

## 并发写入与失败语义

`Writer` 可并发使用。同一 `source` 的 `seq` 必须严格连续；重复或乱序提交被拒绝且
**不污染已提交数据**（序号不前进）。写入失败可用 `errors.Is` 区分：

- `audit.ErrValidation` — 字段非法、序号重复或乱序
- `audit.ErrSourceClosed` — 来源已通过 `CloseSource` 关闭
- `audit.ErrCapacity` — 存储总容量（`maxBytes`）受限

`Writer.WriteBatch([]Event)` 提供**成组原子提交**：一批事件要么整批可见，要么整批
不可见；批内任一来源序号不连续/重复，整批拒绝且不触盘。单条 `Write` 等价于一批一条。

## 崩溃恢复与重启续写（新）

进程在写入过程中被强杀（正好写到一半、上一批没正常收尾）时，重新 `NewStore`
打开同一日志目录会**自动恢复**到可继续追加的正常状态。

### 落盘协议（v1）

每批事件行之后追加一行**提交标记**，只有带「结构合法且摘要匹配」提交标记的事件才算确认数据：

```
{"source":"auth",...}                                         <- 事件行
{"source":"auth",...}                                         <- 事件行
{"_audit_commit":"v1","batch_id":"seg1@0","count":2,
 "digest":"<本批事件行原文的 SHA-256>","prev_digest":"<上一批摘要>"}   <- 提交标记
```

- `digest` = 本批全部事件行原文（含换行）拼接后的 SHA-256
- `prev_digest` 指向上一批摘要，跨段落构成全局摘要链；封存段在 `manifest.json`
  记录 `batch_anchor`（该段首批的锚点）与 `last_digest`（链尾）
- 事件与提交标记在同一次 `fsync` 落盘，`manifest.json` 通过 `tmp + rename + fsync(dir)` 原子更新

### 恢复保证

- **已确认数据一条不少**：恢复只截断「最后一个有效提交标记之后」的内容。
- **半成品不拖坏整批**：没有提交标记收尾的事件行整组丢弃（all-or-nothing），
  含写到一半、没有换行收尾的半行。
- **续写不被当篡改**：恢复后用正确序号继续写，新旧数据封存后 `VerifyAll` 仍通过，
  不会因为"上次没正常结束"就报外部改动。
- **恢复幂等**：截断只发生一次，再次打开结果稳定。
- **重启续写**：`NewWriter` 从存储恢复各来源已提交最大序号（`Store.SourceSeqs()`），
  重开目录后直接按原序号接着写。
- **对账报告**：`Store.RecoveryReport()` 返回重放条数 `RecoveredEvents`、
  丢弃条数 `DiscardedEvents`、截断字节 `TruncatedBytes` 及人可读 `Details`。

### 兼容范围

- 旧版本写出的**活跃段**（不含任何提交标记，v0）按旧语义恢复：信任可解析前缀，
  仅截掉尾部坏行，`RecoveryReport.LegacyActive=true`。
- 旧版本**已封存段**继续受 `manifest.json` 的整段 SHA-256 与 `prev_hash` 哈希链保护，
  无需迁移即可读取与校验。
- 新写入一律采用提交标记格式；封存段哈希现在覆盖「事件行 + 提交标记行」。
  因此混用期间，不要用旧版本二进制去重新封存新版本写出的活跃段。

## 部分损坏容忍读取与完整性报告（新）

当部分数据出问题时，`SalvageAll(store)` / `SalvageSegment(store, id)` 逐段、
逐批/逐行扫描，**尽量捞出仍可用的历史**，不因为一处坏就整批读不出，并给出
人看得懂的 `IntegrityReport`：问题在哪段、哪行/什么偏移、哪类情况、
哪些数据仍可信、增量校验能否接着往下走。

问题分类（`SegmentIssue.Kind`，不把异常糊成一种说法）：

| 分类 | 含义 |
|---|---|
| `record_corrupt` | 记录内部结构已坏（不是合法 JSON Lines 记录） |
| `record_tampered` | 内容被外部改动（批次摘要 / 提交标记字段对不上、整段哈希不匹配） |
| `truncated_tail` | 尾部被截短（批次没有提交标记收尾、最后一行无换行、行数少于清单） |
| `segment_missing` | 整段文件不见了 |
| `chain_broken` | 哈希链/摘要链断裂 |

报告要点：

- `SegmentSalvageReport`：单段 `Salvaged`（捞回事件数）、`Trusted`（数据是否全可信）、
  `Events`（可解析事件，含受影响段中的可用部分）、`Issues`（带行号与字节偏移的定位）。
- `IntegrityReport`：全部问题的扁平汇总 `Issues`，以及
  `IncrementalCanContinue` / `NextAnchorID`——只要存在内容完好的封存段，
  就建议以它为新锚点继续增量校验；全部封存段都坏/缺失时为 `false`/`0`。
- 成组提交格式按批隔离：一个批次被改只影响该批，其他批次与其他段的数据照常可信；
  旧格式段则跳过坏行继续读后面的历史。

> 说明：`Salvage*` 是只读分析，读取磁盘上现存内容；它与 `NewStore` 的自动恢复
> 相互独立——正常打开时活跃段已被自动截到最后一个提交标记，想分析损坏现场可直接
> 对文件运行 Salvage（不经过重新打开）。

## 轮转、保留与完整性校验

**轮转**（`RotationPolicy`）：段落按大小（`MaxBytes`）或时间跨度（`MaxAge`，按事件
时间戳衡量，保证重放确定）封存。封存时计算文件 SHA-256 写入 `manifest.json`，
并记录前一段哈希构成链（`prev_hash`）。

**组合保留**（`RetentionPolicy`）：三个维度同时生效，删除的仍是**最旧的连续前缀**，
因此剩余段落哈希链保持连续：

- `MaxSegments` — 最多保留的封存段数
- `MaxAge` — 封存段相对 `SealedAt` 的最大保留时长
- `MaxBytes` — 封存段总占用字节上限（**新**），超出则从最旧段开始删除

清理接口：

- `ApplyRetention(now) ([]int, error)` — 旧接口，返回被删段 ID（内部已走组合策略）。
- `ApplyRetentionDetailed(now) (RetentionResult, error)` — 返回可核对结果：
  `Removed` / `Remaining`、`FreedBytes`、`UsedBytes`、`RemovedEvents`。
- `ApplyRetentionStrict(now)` — 严格模式，发生冲突时拒绝删除并返回
  `audit.ErrRetentionConflict`（用 `errors.Is` 判断），数据原样保留。

**保留条件冲突**：当空间上限要求删除的段越过了数量/时间窗口本该保护的边界
（既要求留很久又要求压到很小），明确处理而不是悄悄删掉当没事：

- 详细模式：仍删除以腾空间，但 `RetentionResult.Conflict=true` 且 `Warnings`
  说明哪些受保护段被迫删除；
- 严格模式：返回 `ErrRetentionConflict`，一个都不删；
- 若所有段都在保护窗口内、或要满足空间必须把封存历史清空，则不删数据只告警。

清理完成后，未被清掉的历史仍通过 `VerifyAll` 与 `VerifyIncremental` 两种校验，
且事件数与释放字节可对账。

**校验**：

- `VerifyAll(store)` — 全量校验所有已封存段落
- `VerifyIncremental(store, lastSealedID)` — 仅校验 `lastSealedID` 之后的新段，
  并以该段为锚点校验哈希链衔接

判定原因可区分（`SegmentReport.Reason`）：

| 原因 | 含义 |
|---|---|
| `ok` | 通过 |
| `segment_missing` | 段落文件缺失 |
| `truncated` | 行数少于清单记录或末尾记录被截短 |
| `tampered` | 内容哈希不匹配 / 提交标记被改 / 行数多于清单 |
| `chain_broken` | 与相邻留存段落的哈希链断裂 |

读取时若遇到末尾被截短的记录，返回包装了 `audit.ErrTruncatedRead` 的错误并附带
已解析前缀（`errors.Is` 判断），供上层区分别一整段读不出来。

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
# 运行全部单测（-v 日志中可见每条用例覆盖的业务与通过情况）
go test ./... -v

# 含竞态检测
go test ./... -race

# 端到端 demo：写入/批量提交 -> 恢复对账 -> 轮转 -> 组合保留(冲突告警) -> 校验 -> 完整性报告 -> 告警
go run ./cmd/auditdemo                        # 临时目录
go run ./cmd/auditdemo -dir /tmp/auditlog     # 指定目录，重复运行可观察重启续写与重载
```

### 测试覆盖的业务

- 异常中断后重启续写：已确认数据不丢、半成品批次整组丢弃、半行截断、恢复后续写
  与旧数据一起通过校验、恢复幂等、多来源序号快照重建、`WriteBatch` 原子性、恢复对账计数
- 部分损坏读取与报告：健康全可信、批次篡改定位为 `record_tampered` 且隔离、
  尾部截短 `truncated_tail`、整段缺失 `segment_missing`、坏 JSON 行
  `record_corrupt` 且前后好数据仍可读、活跃段悬尾、增量锚点能否继续
- 组合保留清理：空间上限真实删段、时间+空间组合、清理后全量与增量校验通过、
  删除/留存/释放字节账目、冲突详细告警、严格模式 `ErrRetentionConflict`、
  不可满足时不静默、旧 `ApplyRetention` 兼容
- 老能力不回归：并发写入序号连续、重复/乱序拒绝、三类写入失败原因、
  大小/时间轮转、保留后校验、篡改/截断/缺失可区分、增量锚定、三类规则告警与重放确定性
