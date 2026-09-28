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

1. 按 `evidence_id` 去重；
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
| Single | 100% | 100% | 2.5 | 73.22 ms |
| Multi | 100% | 100% | 3.0 | 57.90 ms |
| Auto | 100% | 100% | 2.5 | 76.72 ms |

强制多 Agent 在该小数据集上**没有提升准确率**，平均多用 0.5 次查询；有网络等待时通过波内并发在本轮减少 15.32 ms。Auto 判断 4 条都是简单事故，选择 multi 为 0 次，保持了 single 的查询成本，但增加约 3.50 ms 路由与本机调度抖动。Fixture 数值只证明调度路径，不能代替真实 Provider 压测。

## 6. 0.4.1 成本感知自动路由

`auto` 在每次调查前产生严格 `OrchestrationDecision`。查询预算少于 2 时强制 single；满足以下任一条件才选择 multi：截止时间不超过 10 秒、至少两条症状明确跨越两个观测域、或存在三条以上独立症状。

路由决定以 `orchestration-router / orchestration_selected` 写入同一个 Trace，包含请求模式、实际选择和固定原因码。测试同时验证简单事故选择 single、复杂 Metrics + Logs 事故选择 multi，以及预算不足覆盖复杂度信号。

## 7. 0.4.2 模型如何参与，但不接管 Agent

可选 `ControlledModelPolicy` 只调整第一优先数据源；其余计划保持启发式顺序。模型不会分别注入每个 Worker，也不会产生角色间自由对话。Supervisor 仍负责波次、共享预算和截止时间，Worker 仍绑定单一 EvidenceSource，Reviewer 仍独立执行双来源门控。

模型输出解析失败、来源越权或命中隐私规则时，整次建议被丢弃并使用原计划。没有独立评测收益前，不增加 Agent 自建工具、自动修复权限或模型决定终止条件。控制面细节见 [受控模型策略](CONTROLLED_MODEL_POLICY.md)。
