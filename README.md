# 本地审计日志采集与合规检测流水线

用本地文件模拟审计日志来源，提供：

1. **并发写入与顺序保证**：多来源并发提交，同一来源内序号单调连续；重复、乱序、
   字段非法、来源关闭、容量受限分别返回可区分的错误。
2. **段落轮转、保留与完整性校验**：按大小/事件时间轮转，按数量/年龄/总容量保留；
   哈希链 + 封存 footer + 清单支持全量与增量校验，篡改/截断/缺失/损坏给出可区分原因。
3. **声明式合规规则告警**：窗口阈值（登录失败聚集、权限提升）与日志空档；
   重放相同数据（含重启后）告警集合与指纹完全一致；非法规则带原因拒绝。

## 架构与包

| 包 | 职责 |
| --- | --- |
| `pkg/audit` | 事件模型、字段校验、并发写入器（序号状态机、来源生命周期） |
| `pkg/segment` | 本地段落存储、哈希链帧、轮转保留、全量/增量校验、事件扫描 |
| `pkg/rule` | 声明式规则解析、滑动窗口/空档判定、确定性指纹、重放 |
| `pkg/pipeline` | 组合上述能力的端到端流水线 |

## 事件格式

段落文件每行一帧，事件本体是 JSON：

```json
{
  "id": "host-a-00042",
  "source": "host-a",
  "seq": 42,
  "type": "login_failed",
  "actor": "bob",
  "time": "2026-10-06T10:00:42Z",
  "payload": {"ip": "10.0.0.9"}
}
```

- `id`：事件唯一标识（必填）；
- `source`：来源标识（必填），**同一来源内 `seq` 从 1 开始单调连续**；
- `seq`：来源内序号（必填，>= 1）；
- `type`：事件类型（必填），规则按它过滤；
- `actor`：主体，可用于聚集分组；
- `time`：事件时间（必填，RFC3339；建议统一 UTC）；
- `payload`：附加键值，规则支持等值匹配。

### 写入错误分类（`errors.Is` 可判定）

| 哨兵错误 | 触发条件 | 对状态的影响 |
| --- | --- | --- |
| `audit.ErrInvalidEvent` | 字段非法 / 序号重复（小于期望值）/ 跳号乱序（大于期望值） | 不落地，已提交数据不被污染 |
| `audit.ErrSourceClosed` | 来源已被 `CloseSource` 关闭 | 状态不变，可用于拒绝迟到提交 |
| `audit.ErrCapacityExceeded` | 总容量达到 `MaxTotalBytes` 且保留策略无可清理 | **序号不前移**，腾出空间后可用同一事件重试 |

并发语义：写入器对同来源提交串行化（持锁落地），因此该来源事件的物理顺序
恒等于序号顺序；不同来源之间不保证全局顺序，但规则重放按
`(time, source, seq)` 归并，故告警结论与物理交错无关。

## 段落文件与完整性

磁盘布局：

```
<dir>/manifest.json       # 段落清单（原子替换写入）
<dir>/segment-000001.log  # 数据段落，每行一帧；封存段落以 footer 行收尾
<dir>/segment-000002.log
```

帧（单行 JSON）：

```json
{"event":"<事件 JSON 原始字节>","prev":"<上一帧哈希>","hash":"<sha256(prev|event)>"}
```

封存段落末尾 footer：

```json
{"footer":true,"count":128,"digest":"<最后一帧哈希>"}
```

要点：

- **哈希链**：`hash = sha256(prev + "|" + 事件原始 JSON)`，按落盘原始字节重算，
  任何字节级篡改都会失配；链跨段落延续，新段落首帧的 `prev` 等于上一段落 footer 摘要。
- **封存 footer**：段落轮转/关闭时写入，记录帧数与链尾摘要。
- **清单 manifest**：记录每个段落的 `first_prev`、`digest`、计数、时间范围等；
  清单以临时文件 + rename 原子落盘。

### 校验模式与判定原因

| 原因 | 含义 |
| --- | --- |
| `ok` | 完整 |
| `tampered` | 帧哈希不匹配、跨段落链断裂、footer/锚点摘要不一致 |
| `truncated` | 封存段落缺少 footer，或帧数与 footer/清单记录不符 |
| `missing` | 清单中登记但文件不存在 |
| `corrupt` | 行无法解析为帧/footer，或内嵌事件不是合法 JSON |

- **全量校验** `VerifyFull()`：重放清单中所有段落的哈希链与 footer。
- **增量校验** `VerifyIncremental(anchor)`：锚点格式 `"<段号>:<digest>"`，
  来自 `Anchor()`（最后封存段落）。只重放锚点之后的段落，并 O(1) 比对锚点摘要；
  锚点本身变化也判 `tampered`。锚点之前的历史改动不被增量校验发现，
  因此需周期性执行全量校验。
- **扫描即校验** `ScanEvents`：规则重放等读路径同样逐帧重算哈希，
  发现问题返回带 `Reason` 的 `*segment.ScanError`，不会对不可信数据产出告警。

## 轮转与保留语义

`segment.RotationPolicy`（零值表示该维度不启用）：

| 字段 | 语义 |
| --- | --- |
| `MaxSegmentBytes` | 当前段落字节数达到该值，**下一次写入前**轮转（因此单段可略超阈值） |
| `MaxSegmentAge` | 下一个事件时间与本段首事件时间差 >= 该值时轮转；按事件时间判定，注入固定时钟即可复现 |
| `MaxSegments` | 仅在**封存段落**间计数，保留最新 N 段；活动段落永不参与删除 |
| `MaxAge` | 删除最大事件时间早于 `now - MaxAge` 的封存段落（可通过 `EnforceRetention` 主动触发） |
| `MaxTotalBytes` | 保留清理后总量仍超限，本次写入返回 `ErrCapacityExceeded` |

语义保证：

- 保留策略只删除**链前缀上的旧封存段落**；每个段落都记录自己的 `first_prev`，
  因此删除后剩余段落以自身 `first_prev` 为链首仍可独立验证与扫描。
- 活动（未封存）段落永不被保留策略删除。
- 封存路径（轮转、`Seal`、`Close`）统一在封存后执行一次保留清理。
- 异常退出留下的未封存段落可在重新 `Open` 时通过重放帧恢复链头与计数，
  随后继续追加或补封存。

## 规则格式

支持裸数组或 `{"rules":[...]}` 两种顶层形态；时长统一为 Go duration 字符串
（`"30s"`、`"5m"`、`"1h30m"`）。

阈值规则（窗口内匹配事件数达到阈值）：

```json
{
  "id": "login-failed-burst",
  "description": "5 分钟内登录失败 5 次",
  "kind": "threshold",
  "event_type": "login_failed",
  "actor": "",
  "payload": {},
  "window": "5m",
  "threshold": 5
}
```

权限提升示例（`event_type` + `payload` 等值匹配）：

```json
{"id":"admin-grant","kind":"threshold","event_type":"privilege_granted",
 "window":"1h","threshold":1,"payload":{"role":"admin"}}
```

空档规则（相邻匹配事件间隔 >= `gap`）：

```json
{"id":"silence-gap","kind":"gap","gap":"10m","window":"10m"}
```

过滤字段（均可空，空表示不过滤）：`source` / `event_type` / `actor` / `payload`。
阈值规则声明了非空 `actor` 时分组键恒为该主体，否则按事件 `actor` 分组。

### 告警语义与可复现性

- 阈值规则在窗口内**首次达到**阈值时告警一次，随后消费窗口内事件重新聚集，
  避免滑动窗口重叠造成重复告警；边界为严格的 `t > 窗口左端`（即恰好等宽不累计）。
- 空档规则在相邻事件间隔 `>= gap` 时告警；`Engine.Flush(now)` 可报告
  “距最后一条事件持续无日志”的尾段空档，同一状态不重复报告。
- 每条告警携带 `Fingerprint = sha256(ruleID|窗口起|窗口止|事件ID序列)`。
- `Replay(events)` 先按 `(time, source, seq)` 稳定归并再判定，
  **重启重放或并发乱序到达，相同留存数据产出的告警集合与指纹完全一致**。
- 规则解析严格拒绝：未知字段、未知 kind、缺失/非正 duration、threshold 缺失或
  <= 0、window < gap、规则集为空、id 重复、JSON 不可解析等，错误信息包含
  `rejected` 与具体原因（规则集还会指明第几条），绝不静默跳过。

## 本地验证方法

```bash
# 全部测试（带竞态检测）
go test -race -count=1 ./...

# 查看各业务用例与结果（日志含【业务:...】与【用例:...】标记）
go test -v ./...

# 覆盖率
go test -cover ./...

# 或使用 Makefile
make test      # go test -race -count=1 ./...
make cover     # 生成 coverage.out 并输出函数级覆盖率
make vet
```

测试覆盖的业务：

- `pkg/audit`：并发顺序保证、重复/乱序拒绝且不污染、来源关闭、容量受限可重试、字段校验；
- `pkg/segment`：按大小/时间轮转、按数量/年龄保留后仍可验证、重启恢复（含未封存段落）、
  篡改/截断/缺失/损坏在全量与增量下的可区分判定、锚点失配、容量上限、并发落地；
- `pkg/rule`：登录失败聚集、权限提升 payload 匹配、空档与尾段空档、
  乱序/重启重放指纹一致、13 类非法规则带原因拒绝；
- `pkg/pipeline`：真实目录下端到端并发写入→轮转保留→全量/增量校验→
  重启重放三类告警一致，以及篡改数据下拒绝产出告警。

## 最小使用示例

```go
rules, _ := rule.ParseRules(ruleJSON)
p, _ := pipeline.New(pipeline.Config{
    Dir:    "./audit-data",
    Policy: segment.RotationPolicy{MaxSegmentBytes: 1 << 20, MaxSegments: 7, MaxAge: 24 * time.Hour},
    Rules:  rules,
})
defer p.Close()

err := p.Submit(audit.Event{ID: "1", Source: "host-a", Seq: 1,
    Type: "login_failed", Actor: "bob", Time: time.Now().UTC()})
switch {
case errors.Is(err, audit.ErrInvalidEvent):     // 校验不通过
case errors.Is(err, audit.ErrSourceClosed):     // 来源已关闭
case errors.Is(err, audit.ErrCapacityExceeded): // 容量受限，可重试
}

if r, err := p.VerifyFull(); err != nil || !r.OK { /* 处理 r.Segments 中的原因 */ }
alerts, err := p.ReplayAlerts() // 确定性告警；数据不可信时返回 *segment.ScanError
```
