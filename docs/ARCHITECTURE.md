# SentinelOps 0.4.4 架构

## 1. 设计目标与非目标

目标是把事故调查变成可验证、可终止、可审计的读取流程。系统接收 `IncidentTask`，通过只读工具收集标准化 `Evidence`，给出 `DiagnosisReport` 或明确升级人工。

非目标：自动执行 Shell、SSH、重启、扩缩容、回滚或配置修改；默认模式不连接外部监控，显式配置的真实适配器仍只读；当前版本不承诺高可用，也不把自然语言模型放进默认决策路径。可选 Ollama 只参与数据源优先级建议。

## 2. 分层与依赖方向

```text
Presentation: CLI / API Edge / FastAPI
            |
Application: Service / Single Agent / Multi-Agent Supervisor / Reviewer / Evaluation
            |
Domain: strict Pydantic contracts
            |
Ports: EvidenceTool
            |
Adapters: fixture / Prometheus / Loki / Tempo

Cross-cutting: SQLite Store / AuditLog / Runtime Budget / Controlled Model Guard
```

领域层不依赖 FastAPI、数据库、模型 SDK 或具体监控产品。外部证据先通过端口归一化，编排层只处理领域对象。

## 3. 调查状态机

```text
START
  -> policy.decide(state)
      -> QUERY(source)
          -> budget.consume
          -> gateway authorize / retry / circuit-break / bound / audit
          -> merge evidence by evidence_id
          -> loop
      -> FINISH
          -> require candidate + >= 2 independent sources
      -> ESCALATE
          -> needs_human + unresolved reason
  -> persist result
  -> append completion audit event
```

`InvestigationBudget` 同时约束步骤、查询数、时间和重复动作。任何上限触发后都停止调查并升级人工，避免无限循环和工具放大。

可选 `ControlledModelPolicy` 先运行确定性 Policy：若结果是 FINISH/ESCALATE，模型完全不会被调用；只有下一步需要 QUERY 时，才向 loopback Ollama 发送最小脱敏上下文。模型只能返回一个来源建议，随后仍经过并发/RPM 准入、Schema、字节、隐私、allowlist 和已查询来源校验。失败使用原确定性动作，故模型不可改变安全状态机的可终止性。

`EvidenceGateway` 为 metrics/logs/traces/changes 分别维护熔断状态。连续终态失败达到阈值后进入 open；冷却期结束后通过锁只保留一个 half-open 探针。状态携带 generation，旧请求完成后不能错误关闭新一代熔断器。熔断事件写入审计，但不记录上游错误正文或凭据。

## 4. 证据与结论约束

- `Evidence` 带唯一 ID、事故、服务、来源、观测时间、摘要和原始引用；
- Query 限制事故、服务、来源、关键词和条数；
- 候选根因由确定性规则对证据信号评分；
- Policy 只在置信度达到阈值且至少两个独立来源支持时完成；
- 报告的 `selected_code` 必须指向候选集合，引用 ID 必须来自已查询证据；
- 工具失败、预算耗尽或证据不足均返回 `needs_human`，不伪造成功。

## 5. 信任边界

| 边界 | 当前控制 | 仍需生产化 |
|---|---|---|
| API 调用方 | 可选静态 Bearer、常量时间比较、精确 Host/CORS、请求体/RPM/并发边界、安全响应头 | OIDC、租户 RBAC、密钥轮换、TLS、跨副本租户配额与 DDoS 防护 |
| 工具调用 | read-only 标志、来源白名单、Pydantic 参数、结果上限 | 每个真实提供方的最小权限凭据与 egress 控制 |
| Agent 运行时 | 单 Agent 循环；可选 Supervisor/专项 Worker/Reviewer；共享查询/时间预算、按来源熔断 | 持久化异步任务、租户配额、强制取消与跨副本背压 |
| 本地模型 | 默认关闭；loopback only、最小脱敏上下文、JSON Schema、禁代理/重定向、响应上限、单并发 + RPM、失败回退；60 条独立策略评测集 | 模型/Prompt 版本登记、组织真实事故集、跨副本配额与 Token SLO |
| 持久化 | SQLite 参数化 SQL、事故 ID 幂等 | PostgreSQL 事务、租户行级安全、备份恢复 |
| 审计 | 脱敏、前向哈希链、可选 HMAC | KMS 托管密钥、不可变外部归档、多副本串行化 |
| 容器 | non-root、只读 rootfs、drop capabilities | 镜像签名、SBOM、漏洞扫描、网络策略 |

FastAPI lifespan 在退出时关闭自有 HTTP 连接池。`/healthz` 是不访问依赖的存活探针；`/readyz` 仅检查本地 SQLite，不对外部 provider 发请求，避免探针放大故障或消耗监控配额。

Provider 契约另有一条完全离线的回放路径：`ReplaySuite -> 隐私扫描 -> 严格契约 -> 结构指纹 -> MockTransport -> Provider -> Evidence/受控异常`。回放不经过真实 DNS 或网络，不包含认证头，并在统一发布门禁中先于事故基线执行。结构指纹只散列字段名和 JSON 类型，不散列业务值；任何形状变化都要求人工评审后更新批准指纹。

自身可观测性是旁路能力，不参与诊断决策：HTTP middleware 生成或校验请求 ID，记录固定路由模板、状态和耗时；Service 记录调查结果；Gateway 记录 Provider 结果、耗时和熔断 Gauge。三层共享进程内线程安全 Registry，并通过显式开启的 `/metrics` 输出 Prometheus 0.0.4 文本。所有 label 都来自代码内有限枚举，不接收事故、租户、请求 ID 或异常正文。

API 边界同样位于领域逻辑之外：请求先经过全局并发准入与 60 秒滑动窗口，再经过实际请求字节上限、精确 CORS 和 Trusted Host。拒绝结果仍进入请求关联、固定安全响应头和低基数指标。当前计数状态只在单进程内共享，故与 `--workers 1` 部署契约一致；多副本前必须迁移到入口网关/Redis 和经过认证的租户配额键。

## 6. 单 Agent 与多 Agent 的边界

默认 `single` 使用同一个有界循环动态选择来源，在证据充分时提前停止，查询成本较低。可选 `multi` 使用 Supervisor 每波并发派发两个来源受限的专项调查员，并由独立 EvidenceReviewer 合并证据。`auto` 在查询预算允许的前提下，只对紧截止时间、多条跨域症状或多项独立症状选择 multi。三种配置共享 Domain、Gateway、Store、Audit 和评测集，不存在多套安全边界。

Multi 模式中的消息是 `InvestigatorAssignment -> InvestigatorFinding -> EvidenceReview`，不是无限聊天历史。Worker 只能访问一个 EvidenceSource；Supervisor 共享事故级查询预算与截止时间；Reviewer 至少要求两个独立来源。单 Worker 故障被记录为降级，必要时进入下一波。

当前 4 条 Fixture 消融中三种配置准确率和证据有效率均为 100%；强制 multi 平均多用 0.5 次查询，auto 对全部简单案例保留 single，因此查询成本与 single 一致。另有复杂跨域契约测试确认 auto 会选择 multi。由于 Fixture 规模很小，默认仍保持 single；真实环境切换前必须用组织自己的 Provider 延迟和事故集复测。

## 7. 受控模型边界

模型适配器不实现 Agent 自治，只实现 `SourceProposer`。Single 模式每次 QUERY 前可采纳一个来源；Multi 模式最多用它调整第一优先来源，其余顺序仍来自启发式策略。查询关键词、查询窗口和 Provider 查询语言保持确定性。审计只存接受/回退结果与固定原因码，不保存 Prompt、响应或异常正文。完整说明见 [受控模型策略](CONTROLLED_MODEL_POLICY.md)。

0.4.4 增加独立策略评测路径：`PolicyEvalSuite -> 隐私/Schema 门禁 -> heuristic 与 candidate 对照 -> 来源准确率/安全率/越权执行率 -> 4 条下游事故非回归`。回放模式使用批准的结构化响应验证控制面并进入 CI；真实 Ollama 模式才衡量指定模型效果。两种结果通过 `evaluation_type` 强制区分，避免把回放 100% 写成模型 100%。

## 8. 演进路线

- Prometheus/Loki/Tempo 已通过统一 `EvidenceTool` 接入，并由脱敏回放集验证 Schema 与错误分类；下一步扩展未知字段、超时和冲突证据样本；
- SQLite -> PostgreSQL，使用租户键、唯一约束与事务 outbox；
- 同步请求 -> 持久化任务队列，支持取消、重试、死信和背压；
- 静态 Bearer -> OIDC/OAuth2 + RBAC；
- 本地日志 -> OpenTelemetry traces/metrics/logs 和独立审计归档；
- 受控来源建议已有 60 条独立策略评测集；下一步登记模型/Prompt 哈希并接入组织真实事故集，在严格准入门槛达标前保持默认关闭。
