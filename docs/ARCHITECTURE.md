# SentinelOps 0.11.0 架构

## 1. 设计目标与非目标

目标是把事故调查变成可验证、可终止、可审计的读取流程。系统接收 `IncidentTask`，通过只读工具收集标准化 `Evidence`，给出 `DiagnosisReport` 或明确升级人工。

非目标：自动执行 Shell、SSH、重启、扩缩容、回滚或配置修改；默认模式不连接外部监控，显式配置的真实适配器仍只读；当前版本不承诺高可用，也不把自然语言模型放进默认决策路径。可选 Ollama 可建议数据源优先级；另有显式启用的 Specialist 影子假设，但不进入最终裁决。0.9.0 本地验证台是与正式 API 分离的合成夹具演示入口，固定启发式策略、临时数据库和本机访问边界，不提供生产操作或模型资格判定。

0.10.0 的 `incident-intake-check` 属于离线数据治理工具，不进入事故调查请求路径：候选元数据 → 结构/隐私检查 → 时间点证据、分类范围和复核缺口原因码。它既不读取事故正文也不调用模型/Provider，不写评测 registry；即使机器预检零阻断，仍需独立人工做来源许可、历史可见性、标签与事故级隔离审查。

0.11.0 增加独立于正式 API 和 Reviewer 的本地辅助解释链：`合成调查完成 → 短期内存绑定 run_id/incident_id → 提取最终引用证据 → 可选 loopback Ollama 结构化回答 → 校验原裁决/引用/隐私 → 页面标为 advisory`。助手默认关闭，不读预期答案或未引用证据，不能发工具调用、改变结论或写生产状态；它是交互预览，不是模型诊断资格。

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
  -> one SQLite transaction: persist result + append completion audit event
```

`InvestigationBudget` 同时约束步骤、查询数、时间和重复动作。任何上限触发后都停止调查并升级人工，避免无限循环和工具放大。

当前未发布的 P2 可靠性增量将最终结果与 `investigation_completed` 事件放在同一 SQLite `BEGIN IMMEDIATE` 事务内：事件计算前取得写锁，在事务内读取前一条哈希并追加，任一写入失败都回滚结果和完成事件。单/多 Agent 共用此路径。运行预留先于 Provider 查询；运行终态、派工/Evidence 账本及过程事件仍独立提交。若最终事务已提交但运行终态未写入，同事故重放仅修复运行状态、不重查 Provider。这里没有跨 Provider 的 exactly-once、完整事件 outbox 或多副本恢复承诺。

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
| 本地模型 | 默认关闭；loopback only、最小脱敏上下文、JSON Schema、禁代理/重定向、响应上限、单并发 + RPM、失败回退；60 条开发/隐藏分层策略集；Prompt/数据集/Ollama digest 追踪；调用成功率、grouped bootstrap、重复运行稳定性与数据集生命周期门禁 | 组织真实事故集、跨副本配额与 Token SLO |
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

0.4.15 新增冲突裁决：最高候选即使满足双来源和置信度门槛，只要另一个候选也满足同样门槛、分差小于 0.15，Reviewer 就输出 `needs_human / competing_candidates`，Supervisor 在余量内继续下一波而不是立即结束；仍不收敛则人工接管。`evidence_reviewed` 审计事件记录固定原因码。此阈值为保守工程策略，须用组织事故集校准，不能当作经统计证明的生产阈值。

0.4.16 在跨 Worker Evidence 合并前验证同名 ID 的内容一致性：完全相同的重复记录可去重；同名但内容不同则输出 `evidence_identity_conflict`，既不评分也不再次派工，最终升级人工并标记 `evidence_integrity` 降级。审计只记录固定原因码，不保存冲突内容。

0.5.0 为多 Agent 增加 SQLite Assignment 状态账本：Supervisor 创建、启动、完成每个角色任务时执行条件状态转移；身份唯一、不可逆终态，按 Trace 可读。来源计划在派工前去重和范围约束，再以确定性顺序补全，避免重复来源消耗预算。服务入口在任何 Provider 查询前以事故 ID 原子预留运行；完成结果先持久化，再将预留置为 completed。崩溃后若已有完整结果，则重放结果并修复状态；若只有 running/abandoned 预留，则失败关闭、不自动重新消费预算。Reviewer 检查后每波 Evidence 的 ID/内容哈希按 Trace 持久化，同名异内容的整波拒收。上述机制不是可恢复队列：不保存可安全重放的完整输入，不自动续跑，也没有租约、账本与审计的原子提交或 Provider 侧幂等保证。

0.6.0 将模型辅助 Specialist 接在**已落盘的确定性结论之后**：最多两个成功 Worker 的单来源摘要被脱敏并映射为临时证据引用，严格输出枚举根因、引用、置信度与不确定性。引用越界、隐私命中或模型错误只产生固定原因码。影子账本只存分类、规则基线一致性、时延和可用 Token 计数；不保存输入摘要或模型自由文本。模型不影响查询/终止/Reviewer。同步影子调用会增加响应时延；当前仅用于开发阶段观察，不能据单来源规则一致率声称准确率。

0.7.0 为影子记录增加独立 provenance 表，模型名/digest 与 Prompt ID/hash 在一次 SQLite 事务中绑定至 Assignment。开发集评测只读：事故级标签 → 已落盘调查 Trace → 逐角色影子记录 → 身份核对 → 按来源/总体指标与保守门禁。缺记录、身份漂移和未受治理的 holdout 都失败关闭；开发门禁不会改变模型权限或生成生产资格。旧版无 provenance 的影子记录可看汇总，但不能用于身份可验证对照。

0.8.0 的资格路径与线上 API 隔离：`人工复核的本地夹具 → 指纹登记 sealed → 模型身份预检 → 原子 reserved → 每轮独立临时 SQLite + 只读 FixtureEvidenceTool + multi Agent + 影子 Specialist → 逐轮脱敏汇总 → consumed`。在登记、预留及最终消费时复核路径、数据指纹与身份；多轮前后刷新模型 digest。报告先写预备身份，再逐轮更新指标，最终先写待固化结论、后更新注册表、最后标记报告 consumed。中断时不回滚 reserved；即使报告最终更新失败，也不可重复解封。这个技术门禁不具有生产授权权力，也无法自动证明人工标注的独立性。

当前 4 条 Fixture 消融中三种配置准确率和证据有效率均为 100%；强制 multi 平均多用 0.5 次查询，auto 对全部简单案例保留 single，因此查询成本与 single 一致。另有复杂跨域契约测试确认 auto 会选择 multi。由于 Fixture 规模很小，默认仍保持 single；真实环境切换前必须用组织自己的 Provider 延迟和事故集复测。

## 7. 受控模型边界

模型适配器不实现 Agent 自治，只实现 `SourceProposer`。Single 模式每次 QUERY 前可采纳一个来源；Multi 模式最多用它调整第一优先来源，其余顺序仍来自启发式策略。查询关键词、查询窗口和 Provider 查询语言保持确定性。审计只存接受/回退结果与固定原因码，不保存 Prompt、响应或异常正文。完整说明见 [受控模型策略](CONTROLLED_MODEL_POLICY.md)。

0.4.4 增加独立策略评测路径：`PolicyEvalSuite -> 隐私/Schema 门禁 -> heuristic 与 candidate 对照 -> 来源准确率/安全率/越权执行率 -> 4 条下游事故非回归`。回放模式使用批准的结构化响应验证控制面并进入 CI；真实 Ollama 模式才衡量指定模型效果。两种结果通过 `evaluation_type` 强制区分，避免把回放 100% 写成模型 100%。

0.4.5 将评测输入与结果变成可审计工件：数据集采用规范化 JSON 哈希，系统 Prompt 采用稳定 ID + SHA-256，真实 Ollama 通过受限 `/api/tags` 只读请求解析本地模型 digest；每组准确率、回退率、安全率和来源混淆矩阵随报告输出。报告写入前再次执行隐私扫描，通过同目录临时文件与原子替换避免留下半写文件。

0.4.6 将 15 个场景组内的文字变体固定拆成 30 条 development 与 30 条 holdout：Prompt 只允许根据 development 调整，holdout 负责最终准入。评测器以整个 `group_id` 为抽样单位执行 2,000 次 paired clustered bootstrap，防止把同一语义的改写当成独立样本；live 模式还要求候选调用成功率至少 95%，模型不可用导致的启发式回退不能伪装成模型效果。

0.4.7 在单次评测上增加 campaign 控制面：同一 `OllamaSourceProposer` 跨 2–10 轮复用资源准入，每轮只执行 holdout，并把共享 usage observation 按轮切片。每轮前后重新解析模型 digest，捕获轮内或跨轮标签漂移；报告通过无症状正文的 `case_id -> candidate_source` 记录计算预测翻转率，再以运行通过率、Top-1 极差、逐案例一致率和身份一致性共同裁决；首调用与稳态时延分开输出，但不主动修改模型驻留状态。

0.4.8 在 campaign 前增加评测 registry 信任边界。registry 以严格契约登记数据集相对路径、规范化 SHA-256、Schema、development/holdout 数量和 `sealed|reserved|consumed` 状态，并检查跨版本数据集指纹与隐藏输入重复。资格评测只允许 sealed holdout；相邻独占锁在推理前完成 `sealed -> reserved` 原子转换，完整评测后再固化 `consumed` 结果。消费后仅允许登记记录中的模型、digest、Prompt ID 与 Prompt 哈希做 regression；崩溃遗留 reserved 状态默认阻断重开。路径逃逸、数据漂移、未知数据集、无 digest 或候选身份变化都会在模型调用前失败关闭。单次 live `policy-eval` 只允许 development，holdout 由 campaign 授权。

0.4.9 将命令行成功码与最终资格判定绑定：qualification 仅在 registry 写入 `accepted` 后返回 0，regression 仍按 campaign 门禁返回。资格接受还要求每轮评测门禁均通过、汇总运行通过率为 100%，避免宽松实验阈值掩盖单轮下游回归失败。

0.4.10 补充新数据集登记边界：候选 JSON 必须位于 registry 目录内，经现有加载器完成隐私扫描和 Schema 检查；在 registry 独占锁内校验所有已登记数据集与新候选的指纹、拆分数量和隐藏输入去重，全部通过后原子添加 sealed 记录。登记不触发模型推理，也不会自动认定数据来源已经获批。

0.4.11 补齐资格证据持久化顺序：资格命令必须提供新的报告路径，先拒绝目标冲突；campaign 完成后原子写入带 reservation ID 的预备报告，成功后才允许 `reserved -> consumed`，最后把最终裁决写回报告。若最终写盘失败，registry 的 consumed 事实与预备报告仍可用于人工核对；CLI 不得错误提示“仍为 reserved”。这不是跨两个文件的原子事务，故保留显式恢复/审查边界。

0.4.12 在数据契约与 Prompt 身份上做双线调整：Schema `0.3` 将一个事故组固定到单一拆分，防止同一事故的文字变体同时落入开发与隐藏集；`0.2` 维持历史回放。Prompt v1–v4 各自具有固定 ID 与内容哈希，开发评测可显式选择，服务组合根仅接受 v1，避免把未获资格的实验 Prompt 带入运行路径。

0.4.13 将跨数据集完全相同输入检查扩展为“旧全集 ∩ 新 holdout”及“旧 holdout ∩ 新全集”，避免旧开发数据借新版本转成隐藏数据。开发报告比较器只读本地 JSON，先限制字节数、扫描隐私，再校验同一数据集、模型 digest 与逐案例定义，报告改善/退步而不访问 holdout；此工具不是资格门禁。

0.4.14 为下游 Fixture 集生成有序内容指纹。开发报告比较器只在相同运行版本、相同夹具指纹及案例数的条件下计算下游 Top-1 差值；旧报告没有夹具指纹时仍标记不可比。指纹仅证明输入字节语义一致，不证明样本代表性或线上收益。

## 8. 演进路线

- Prometheus/Loki/Tempo 已通过统一 `EvidenceTool` 接入，并由脱敏回放集验证 Schema 与错误分类；下一步扩展未知字段、超时和冲突证据样本；
- SQLite -> PostgreSQL，使用租户键、唯一约束与事务 outbox；
- 同步请求 -> 持久化任务队列，支持取消、重试、死信和背压；
- 静态 Bearer -> OIDC/OAuth2 + RBAC；
- 本地日志 -> OpenTelemetry traces/metrics/logs 和独立审计归档；
- 受控来源建议已有 60 条分层策略评测集、可追溯哈希、模型 digest、调用有效性门禁、grouped bootstrap、重复运行 campaign 与一次性 holdout 生命周期；下一步登记独立 sealed 数据集并补受控冷启动/GPU 资源观测，在严格准入门槛达标前保持默认关闭。
