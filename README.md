# audit-log-compliance-go

本地审计日志采集与合规检测流水线：用本地文件模拟日志来源，提供并发写入与顺序保证、
段落轮转/保留/完整性校验，以及声明式规则的确定性合规告警。

## 结构

- `audit/event.go` — 事件模型与校验、可区分的写入失败原因
- `audit/writer.go` — 并发写入器，按来源保证序号单调连续
- `audit/segment.go` — 段落存储：轮转、保留、哈希链清单
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

## 轮转、保留与完整性校验

**轮转**（`RotationPolicy`）：段落按大小（`MaxBytes`）或时间跨度（`MaxAge`，按事件
时间戳衡量，保证重放确定）封存。封存时计算文件 SHA-256 写入 `manifest.json`，
并记录前一段哈希构成链（`prev_hash`）。

**保留**（`RetentionPolicy`）：`ApplyRetention(now)` 按 `MaxSegments` / `MaxAge`
清理**最旧的连续前缀**段落，因此剩余段落的哈希链保持连续，清理后 `VerifyAll`
仍可通过。

**校验**：

- `VerifyAll(store)` — 全量校验所有已封存段落
- `VerifyIncremental(store, lastSealedID)` — 仅校验 `lastSealedID` 之后的新段，
  并以该段为锚点校验哈希链衔接

判定原因可区分（`SegmentReport.Reason`）：

| 原因 | 含义 |
|---|---|
| `ok` | 通过 |
| `segment_missing` | 段落文件缺失 |
| `truncated` | 行数少于清单记录（被截断） |
| `tampered` | 行数一致但内容哈希不匹配（被篡改） |
| `chain_broken` | 与相邻留存段落的哈希链断裂 |

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
# 运行全部单测（日志中可见各业务用例与结果）
go test ./... -v

# 含竞态检测
go test ./... -race

# 端到端 demo：写入 -> 轮转 -> 保留 -> 校验 -> 告警
go run ./cmd/auditdemo            # 临时目录
go run ./cmd/auditdemo -dir /tmp/auditlog   # 指定目录，可重复运行观察重载
```
