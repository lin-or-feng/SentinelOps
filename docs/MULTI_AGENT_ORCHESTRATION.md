# SentinelOps 有界多 Agent 协作

## 1. 准确定义

0.4.0 提供的是**确定性多 Agent 编排基线**，不是“多个 LLM 自由聊天”。每个 Agent 拥有独立角色、受限工具范围、结构化任务与结构化结果；Supervisor 负责派工和全局预算；Reviewer 负责合并证据并作最终门控。

```text
                     +----------------------+
IncidentTask ------> | MultiAgentSupervisor |
                     +----------+-----------+
                                |
                      bounded wave (default 2)
              +-----------------+-----------------+
              |                 |                 |
      MetricsInvestigator  LogsInvestigator  Trace/Change Investigator
              |                 |                 |
              +---------- EvidenceGateway --------+
                                |
                         structured findings
                                |
                       +--------v--------+
                       | EvidenceReviewer |
                       +--------+--------+
                                |
                  diagnosed or needs_human
```

## 2. 协作如何体现

### Supervisor

- 根据症状确定数据源优先级；
- 按波次分派，默认每波最多两个并发调查员；
- 共享事故级查询预算与截止时间，不允许每个 Agent 各自无限扩张；
- 第一波证据通过 Reviewer 后立即停止，证据不足才进入下一波；
- 单个 Worker 失败时隔离故障并记录降级，不让整个调查异常退出。

### 专项调查员

`metrics-investigator`、`logs-investigator`、`traces-investigator`、`changes-investigator` 每次只接收一个 `InvestigatorAssignment`，只能查询自己负责的 `EvidenceSource`。任务中包含唯一 assignment ID、固定 `QuerySpec` 和截止时间。

Worker 只能返回 `InvestigatorFinding`：状态、来源、Evidence 列表、错误类型和耗时。领域校验会拒绝跨事故、跨服务或跨来源 Evidence；Gateway 同时执行第二层范围校验。

### Evidence Reviewer

Reviewer 不调用外部工具，只处理已归一化证据：

1. 先核对 `evidence_id`：同名同内容才去重，同名异内容立即升级人工；
2. 对候选根因确定性排序；
3. 验证置信度；
4. 验证至少两个独立来源支持；
5. 不满足条件时返回 `needs_human`。

因此最终决定不依赖某个 Worker 的自由文本结论，避免“多个 Agent 一起自信地犯错”。

## 3. 并发、异步与背压

当前 Provider 契约是同步接口，所以 Worker 使用**有界 `ThreadPoolExecutor` 并发**，不是伪装成异步的阻塞 `async def`。并发上限为 4，每波默认 2，查询总数默认不超过 4；API 外层还有全局在途请求上限。

未来只有在 Provider 全部迁移 `httpx.AsyncClient` 后，才适合改为 `asyncio.TaskGroup`。届时仍需保留 Semaphore、超时、取消传播和持久化任务队列；单纯改成 `async def` 不会自动获得吞吐提升。

## 4. 审计与可解释性

一次多 Agent 调查会记录：

- `investigation_started`：模式、预算、计划 Worker 数；
- `worker_dispatched`：assignment 与角色；
- `tool_query`：真实数据源调用、尝试次数、结果数和熔断状态；
- `worker_completed`：角色状态、结果数、错误类型和耗时；
- `evidence_reviewed`：候选、证据数和独立来源；
- `investigation_completed`：最终状态与降级组件。

API 返回的 `InvestigationResult` 包含 `orchestration_mode`；每个 TraceStep 包含 `actor`，因此可以直接区分 Supervisor、专项调查员和 Reviewer。

## 5. 单 Agent / 多 Agent 消融

运行：

```powershell
.\.venv\Scripts\python.exe -m sentinelops orchestration-eval --provider-delay-ms 25
```

当前 4 条固定事故集的实测：

| 模式 | Top-1 | 证据有效率 | 平均查询 | 平均耗时（25 ms/查询模拟） |
|---|---:|---:|---:|---:|
| Single | 100% | 100% | 2.5 | 74.23 ms |
| Multi | 100% | 100% | 3.0 | 61.47 ms |
| Auto | 100% | 100% | 2.5 | 88.98 ms |

强制多 Agent 在该小数据集上**没有提升准确率**，平均多用 0.5 次查询；有网络等待时通过波内并发在本轮减少 12.76 ms。Auto 判断 4 条都是简单事故，选择 multi 为 0 次，保持了 single 的查询成本，但本轮增加约 14.75 ms 路由与本机调度抖动。Fixture 数值只证明调度路径，不能代替真实 Provider 压测。

## 6. 0.4.1 成本感知自动路由

`auto` 在每次调查前产生严格 `OrchestrationDecision`。查询预算少于 2 时强制 single；满足以下任一条件才选择 multi：截止时间不超过 10 秒、至少两条症状明确跨越两个观测域、或存在三条以上独立症状。

路由决定以 `orchestration-router / orchestration_selected` 写入同一个 Trace，包含请求模式、实际选择和固定原因码。测试同时验证简单事故选择 single、复杂 Metrics + Logs 事故选择 multi，以及预算不足覆盖复杂度信号。

## 7. 0.4.2 模型如何参与，但不接管 Agent

可选 `ControlledModelPolicy` 只调整第一优先数据源；其余计划保持启发式顺序。模型不会分别注入每个 Worker，也不会产生角色间自由对话。Supervisor 仍负责波次、共享预算和截止时间，Worker 仍绑定单一 EvidenceSource，Reviewer 仍独立执行双来源门控。

模型输出解析失败、来源越权或命中隐私规则时，整次建议被丢弃并使用原计划。没有独立评测收益前，不增加 Agent 自建工具、自动修复权限或模型决定终止条件。控制面细节见 [受控模型策略](CONTROLLED_MODEL_POLICY.md)。

## 8. 0.4.15 冲突裁决：从并行查询到受控协作

旧 Reviewer 只验证最高分候选的置信度与双来源支持；两种根因同样充分时，排序中的偶然先后可能导致过早诊断。现在增加候选分差门槛：若第二候选也达到置信度和双来源要求，且与第一候选的分差小于 0.15，Reviewer 输出 `needs_human / competing_candidates`。Supervisor 依据该结构化结果继续下一波，只使用未查询来源且不突破共享预算；证据仍冲突时升级人工。审计 `evidence_reviewed` 记录固定 `reason_code`，不写入证据原文。

端到端测试构造 Metrics + Logs 同时支持“连接池耗尽”和“缓存未命中”的冲突：第一波不能定论，第三个 Traces 专项调查员补充独立证据后才确诊连接池耗尽；若预算只有 2 次查询，则保持 `needs_human`。这说明协作决策改变了执行路径，而非仅给并发函数取 Agent 名称。0.15 是保守初始值，尚缺真实事故集的误诊率/人工升级率校准。

0.4.16 补上更高优先级的身份冲突：两名 Worker 返回相同 Evidence ID 但内容不同时，Reviewer 不再让后一个覆盖前一个，而是输出 `evidence_identity_conflict`。Supervisor 不再派下一波，因为追加证据无法证明哪份同名记录可信；最终升级人工，结果包含 `evidence_integrity` 降级标记。完全一致的重复记录仍按一份计算。审计仅保存固定原因码，不写入冲突原文。

## 9. 面向真正模型辅助多 Agent 的顶层设计

```text
入口准入 / 租户权限 / 限流
          ↓
Router（single/multi；保留可解释原因）
          ↓
Supervisor（有限状态机、共享预算、波次、截止时间）
          ↓ 结构化 Assignment；每角色只读单一来源
Metrics / Logs / Traces / Changes Specialists
          ↓ 结构化 Finding；必须引用具体 Evidence ID
Reviewer（去重、证据来源独立性、竞争假设、安全门禁）
          ↓
Diagnosis 或 needs_human；Trace / 审计 / 指标
```

0.6.0 之前只有**受限、确定性 Specialist** 和独立 Reviewer；LLM 最多在可选策略中建议首查数据源。0.6.0 增加默认关闭的 Specialist 影子实验：确定性结论落盘后，模型最多观察两个成功 Worker 的单来源、脱敏证据摘要，只返回固定 Schema 的候选假设、临时证据引用和不确定性。模型没有写权限、任意查询语言、自行派工或裁决权限；影子输出不会进入 Reviewer。若未来考虑提升为裁决参与者，Reviewer 必须重新从原始标准化证据核验，且先通过独立标注集的准入门禁。

推荐顺序与验收标准：

1. **P0，当前安全闭环**：冲突不误判、证据身份冲突拒收、角色越权拒绝、失败隔离、共享预算、审计原因码。已由离线契约和端到端测试覆盖；仍需真实事故校准冲突阈值。
2. **P1，任务与证据状态**：0.5.0 已实现 Assignment 元数据持久化与单向状态机、事故级运行原子预留、Review 后 Evidence 哈希账本和结果先落盘的安全重放。遗留预留不会自动释放，因此同一事故重启后不自动重复调用 Provider；代价是人工核实前不可续跑。跨进程租约、自动恢复和 Provider 侧幂等仍未实现。
3. **P2，可选模型 Specialist**：0.6.0 已交付默认关闭的影子通路、严格契约、角色级最小上下文、引用校验、安全回退与元数据报告。0.7.0 增加开发标签上的逐角色正确率、身份绑定和只读门禁。0.8.0 增加封存 holdout 的一次性多轮资格流程，但只有合成数据测试；影子汇总的一致率仍不是正确率，真实标注独立性与来源审批须由人负责。未具备真实代表性与审批前不进入裁决链。

### 0.8.0 封存 holdout 的重复运行

资格路径不会事后读取已经调过参的影子结果：先验证人工提供的数据集与模型 digest、原子预留 sealed holdout，再在 2–10 个独立临时数据库中重新运行只读 Fixture、多 Agent 和影子 Specialist。每轮以全部模型尝试为分母记录逐来源/总体正确率、失败码、P95 和 Token；多轮核对 `(事故, 来源)` 的预测稳定性，并要求确定性最终诊断不回退。预留后崩溃保持 reserved，不自动重开；结束后通过与拒绝均 consumed。此流程只授予“离线技术门禁”结论，不修改 Reviewer 权限，也不提供真实事故独立性的自动证明。

### 0.7.0 影子评测边界

模型调用与标签评测分离：Supervisor 只记录影子观察；离线 `specialist-shadow-eval` 用事故 ID 找到已完成调查的 Trace，再读取逐角色记录与人工提供的开发标签。每条记录需匹配固定模型名/digest 和 Prompt ID/hash；旧版缺失 provenance 的观察不可比。输出逐来源、全尝试口径的模型/规则正确率与失败原因分布，不输出证据正文。开发门禁通过也只代表当前开发标签上的对照，`production_qualified` 始终为 false，Reviewer 继续忽略模型假设。

### 0.6.0 影子数据流与准入边界

```text
只读 Worker Finding → Reviewer 最终裁决 → 结果与审计落盘
                                      ↓ 可选，最多两个成功 Worker
单来源 Evidence 摘要 → 脱敏/临时 E1… 引用 → 本机模型严格 JSON 假设
                                      ↓ 引用与隐私校验
固定原因码 / 假设代码 / Token / 时延 → 影子账本与汇总报告
```

启用配置为 `SENTINELOPS_SPECIALIST_SHADOW=ollama`，仅适用于 `multi` 或 `auto`；默认 `off`。模型调用沿用 loopback 限制、响应字节上限、超时、并发与滑动窗口 RPM 准入。只有通过上下文引用白名单与隐私检查的假设才记为 accepted，其他情况只留下固定失败码。证据身份冲突时完全跳过影子调用。影子结果不写入 `DiagnosisReport`、不影响后续派工或 Reviewer；影子账本故障也不能推翻已落盘结论。由于在请求线程内同步观察，启用后可能增加 API 返回延迟，不是异步无成本旁路。

同步 Provider 当前无法强制中断已开始的线程；`deadline_seconds` 是停止派发与拒收过期 Finding 的**软截止时间**，并非进程级硬超时或 API 延迟上界。下一阶段应统一 Provider 级超时、迟到结果隔离与可恢复任务状态，之后再评估异步迁移。不要仅把同步代码包进 `async def` 就宣称获得取消语义。

### 0.5.0 持久化派工与证据骨架

```text
created --start--> running --worker ok----> completed
                           |--worker error-> failed
                           `--soft timeout-> expired

created/running --显式核实旧执行者已停止后清理--> expired
```

`AssignmentJournal` 用 SQLite 条件更新防止终态回退和重复完成，存储 assignment ID、Trace ID、事故 ID、角色、来源与状态，不写症状和证据正文。Supervisor 在每波提交前创建并启动，在接收 Finding 后固化终态；读取接口可检查某条 Trace 是否遗留未完成派工。`expire_incomplete` 是显式恢复辅助操作，**不能在另一个执行者可能仍运行时调用**。当前没有工作队列、租约或自动断点续跑，账本与 AuditLog 分别提交，需在生产化阶段使用同事务/outbox 设计。

`InvestigationRunJournal` 在服务入口以 incident ID 预留一次运行，先于任何 Provider 查询；并发重入和重启后的 running/abandoned 状态都返回冲突，不会重启同一事故的派工。完整结果先写 `InvestigationStore`，之后更新运行状态；中间崩溃时优先重放已有结果并修复运行状态。没有结果的遗留预留不会自动清理，人工确认后应使用新的 incident ID 重新调查。`EvidenceJournal` 按 Trace 存 Review 后的 Evidence ID/规范化内容哈希与来源；同名异内容整批回滚，身份冲突的波次不入账。哈希账本只证明本地观察到的内容一致，不证明 Provider 原始数据可信，也不能替代审计链或完整 Evidence 存储。

派工前先规范化来源计划：重复来源去重，非枚举值或不属于确定性来源顺序的值丢弃，再补回缺失的确定性备选；最后按事故级预算截断。若计划被调整，审计只记录固定来源名及去重/越界数量。这样外部策略不能通过重复来源占满任务槽位，Reviewer 仍可获得独立来源的证据。
