# SentinelOps 0.11.0

SentinelOps 是一个证据优先、默认只读的事故调查 Agent。它围绕真实生产约束设计：Agent 只能查询指标、日志、链路和变更记录；每次调查受步骤、查询次数和截止时间限制；结论必须引用证据；证据不足时升级人工，而不是编造根因。

当前版本提供**可复现的单 Agent 基线 + 可选有界多 Agent 协作 + 成本感知自动路由 + 受控本地模型策略 + Specialist 影子实验**，不是生产事故平台。默认使用 Fixture 与确定性策略做离线评测，不访问外部系统；显式启用 observability 模式后，可通过同一领域契约连接 Prometheus、Loki、Tempo 的只读 API。

当前 1.0 前进度见 [发布资格验收](docs/RELEASE_READINESS.md) 与 [变更记录](CHANGELOG.md)。版本仍是 0.11.0；代码推送不等于 1.0 发布，尚未打 1.0 标签或进行正式发布。

## 未发布：本机真实只读调查台

新增与 `8765` 合成验证台分离的本机入口 `python -m sentinelops.operator_web --db <仓库外绝对路径>`（默认 `127.0.0.1:8767`）。它只接受真实 observability 适配器，启动前执行 pilot 静态安全预检；页面强制 Token、同任务来源预检与人工确认，展示调查结论、证据 ID、Trace 和审计，还可按事故 ID 只读找回已保存结果，不重复查询 Provider。不启用 AI 裁决，也不回退夹具。真实凭据和获批事故样本仍需操作者提供，故不能将此入口视为已完成真实联调。配置、失败定位与复核见[本机真实调查台](docs/OPERATOR_DESK.md)。

上线前的浏览器流程可用 `.\.venv\Scripts\python.exe -m scripts.operator_offline_acceptance` 一键在**假来源**下复现：自动完成连接、预检、显式确认、审计、刷新找回及关页后恢复；报告与截图仅写入忽略目录 `.sentinelops/`，明确标记 `OFFLINE TEST`，不构成真实联调或发布资格。前置条件和结果见[离线浏览器验收](docs/OPERATOR_OFFLINE_ACCEPTANCE.md)。

## 0.11.0 只读 AI 辅助解释预览

- 本地验证台增加针对**已完成合成事故**的单轮提问。默认关闭；显式启用后，助手只读取当前运行中最终结论已引用的最多 8 条合成证据、症状与规则结论，不接收夹具预期答案、审计原文、工具权限或外部 URL。回答必须给出原结论、证据 ID 与不确定性；根因改写、越界/重复引用、隐私命中、无效结构均失败关闭。AI 输出不回写调查结果或审计，不触发新查询或修复动作。
- 保留每次运行的短期本机内存索引（最多 12 次、10 分钟），仅用于把追问绑定到正确的运行和事故；不存模型回答、不新增聊天记忆或持久化数据库。此预览不代表 AI 已通过真实事故诊断资格。
- 在 `D:\agents` 的 PowerShell 中显式开启本机 Ollama（另开终端保持 Ollama 运行），然后重启验证台：

```powershell
$env:SENTINELOPS_DEMO_ASSISTANT = "ollama"
$env:SENTINELOPS_OLLAMA_MODEL = "<本机已安装的模型名>"
$env:SENTINELOPS_OLLAMA_TIMEOUT_SECONDS = "20"
.\.venv\Scripts\python.exe -m sentinelops.demo_web
```

访问 `http://127.0.0.1:8765/`，先运行案例，再在详情下方提问。若旧验证台仍占用 8765，先在原窗口按 `Ctrl+C`，再启动新版本；不必改变正式 API。关闭 `SENTINELOPS_DEMO_ASSISTANT` 或设为 `off` 并重启，即恢复完全不调用模型的演示。见[验证台说明](docs/DEMO_VERIFICATION.md)。

## 0.10.0 公开事故数据准入预检

- 新增只读 `incident-intake-check`：只读取有界 JSON 元数据，不下载复盘、不调用模型、不登记或消费 holdout。检查独立事故分组、现有 Specialist 根因分类是否适配、证据是否在设定决策时刻前可用，以及许可、脱敏、独立标注的外部复核编号。输出固定原因码，不回显证据正文。
- 首批两条官方公开复盘仅列为 **development 候选**。一条暂列分类范围外，一条暂列多因素标签不明确；均缺乏经核实的同时点证据和审批，因此预检返回 `blocked`，不能拿来宣称真实事故准确率。即使所有机器可查条件满足，状态也只会是 `manual_review_required`，不会自动批准数据集。
- 运行 `python -m sentinelops incident-intake-check --manifest evals/public_incident_candidates.json` 可查看逐例阻断原因；返回码 `1` 表示候选仍被阻断，当前样例预期如此。准入流程、不可由程序验证的事项见[公开事故候选池](docs/PUBLIC_INCIDENT_INTAKE.md)。

## 0.9.0 本地可视化验证台

- 新增独立 FastAPI 演示页：选择四条合成事故之一或全部，切换 `single` / `multi` / `auto`，查看实际路由、专项 Worker 派工、证据引用、执行 Trace 和哈希链审计事件。
- 每次点击都在独立临时 SQLite 中重新调查；页面逐例核验预期根因、证据作用域、审计链、结果持久化和运行终态，并显示通过数。临时数据保存在项目忽略目录 `.sentinelops/demo-temp`，结束后清理。
- 演示服务只接受本机客户端、固定合成夹具和确定性策略，强制关闭模型/真实 Provider；限制请求体、频率和并发，前端无外部资源。它不是生产监控台，也不读取或消耗封存 holdout。

在 `D:\agents` 目录保持命令行窗口打开，运行：

```powershell
.\.venv\Scripts\python.exe -m sentinelops.demo_web
```

浏览器打开 `http://127.0.0.1:8765/`；结束时在命令行按 `Ctrl+C`。可视化验收步骤与边界见[本地验证台说明](docs/DEMO_VERIFICATION.md)。

## 0.8.0 Specialist 独立资格评测框架

- 新增只读离线资格数据集契约：每例包含事故任务、限定作用域的证据、预期根因、事故组和 `development|holdout`；同组不得跨拆分。登记前执行限长、隐私扫描、路径约束、规范化 SHA-256 与跨数据集完全相同输入重叠检查。真实标签来源和语义近似污染仍需人工审核；登记时要求填写外部审批编号，但程序无法证明审批真实性。
- 独立 SQLite 注册表实现 `sealed → reserved → consumed`。每次资格活动在模型调用前原子预留封存 holdout，之后不可自动重开；至少 20 条 holdout、固定模型 digest/Prompt 哈希、2–10 轮新建的离线调查。每轮重新检查模型 digest，并保留结构化中间报告；中断后停在 `reserved`，需要人工核查。完成后无论通过还是拒绝，holdout 都标记 `consumed`。
- 门禁按**所有影子调用**计算正确率与接受率，要求确定性最终结论、模型 Top-1、引用边界、跨轮预测稳定性全部通过，并限制影子调用 P95 和单次 Token 用量。资格结果仅为离线技术证据；即使 `accepted`，报告仍固定 `production_qualified=false`，不会改变 Reviewer 权限、启用生产 Provider 或自动发布。
- 命令：`specialist-shadow-register` 登记人工复核数据集，`specialist-shadow-registry-check` 只读检查，`specialist-shadow-campaign` 显式运行一次性多轮资格测试。完整流程、数据格式和失败处理见[影子评测说明](docs/SHADOW_EVALUATION.md)。目前仓库**没有**可声称独立的真实事故资格集；本轮合成测试只验证流程，不证明模型质量。

## 0.7.0 Specialist 影子评测骨架

- 影子记录增加独立的模型/Prompt 身份元数据：模型名、可解析的 digest、Prompt ID 与 SHA-256。已有 0.6.0 记录若缺少身份信息，仍可做普通汇总，但不能进入新的开发集对照。
- 新增严格的事故级标签契约与只读 `specialist-shadow-eval`：对每条标签查找已完成调查和对应影子记录，核对同一模型 digest 与 Prompt 哈希；按来源输出全尝试口径的模型/规则 Top-1、接受率、越界引用次数、P95 与可用 Token 计数。缺失事故、缺失影子记录、身份漂移、重复标签或隐私命中均拒绝评测。
- 0.7.0 的开发对照命令**只允许 development 标签**；未经治理的 holdout 被阻断。开发门禁要求最低事故数、模型调用接受率、零越界引用和不低于规则基线的正确率，但输出始终标记 `production_qualified=false`。标签是否由独立人工标注无法由代码自行证明；没有真实独立数据就不宣称模型已达生产标准。数据格式与局限见[影子评测说明](docs/SHADOW_EVALUATION.md)。
- 运行示例：`python -m sentinelops specialist-shadow-eval --labels <开发标签.json> --db .sentinelops/shadow.db --model-name <已安装模型名> --model-digest <64位模型摘要> --min-cases 20`。此命令不调用模型或 Provider，也不写报告文件；需要先显式启用 0.6.0 影子运行积累记录。

## 0.6.0 模型辅助 Specialist 影子框架

- 新增严格的 `ShadowContext → ShadowHypothesis` 契约：模型每次只看到单个来源最多 25 条脱敏摘要和 `E1` 等临时引用号；不接收租户、事故 ID、原始引用、查询语言或工具权限。假设代码只能取固定枚举，必须引用该次上下文中的证据，并说明不确定性。
- `multi` / `auto` 模式可显式启用本机 Ollama 影子推理。确定性 Reviewer 的结论先落盘，模型之后才运行；模型失败、越界引用或异常输出只记原因码，**不能修改最终诊断、继续派工或触发修复动作**。证据身份冲突时不调用影子模型。默认关闭。
- `ShadowJournal` 只存每角色的来源、固定原因码、模型假设代码、单来源规则基线代码、是否一致、耗时与可用 Token 计数；不存 Prompt、摘要或自由文本。`specialist-shadow-report` 汇总接受率、基线一致率、P95 与 Token 用量。**基线一致率不是正确率**，目前没有独立真实事故标注可用于准入。
- 在项目根目录、已配置 `SENTINELOPS_OLLAMA_MODEL` 且本机 Ollama 可用时，可设置 `SENTINELOPS_SPECIALIST_SHADOW=ollama`，用 `python -m sentinelops investigate --orchestration-mode multi --incident-id inc-deploy-001 --db .sentinelops/shadow.db` 运行；随后用 `python -m sentinelops specialist-shadow-report --db .sentinelops/shadow.db` 查看元数据。源码工作树运行前需安装项目或设置 `PYTHONPATH=src`。影子调用在结果落盘后同步执行，仍会增加本次请求返回时延；它不是生产流量无成本旁路。

## 0.5.0 多 Agent 执行状态框架

- 新增持久化 `AssignmentJournal`：每个专项任务只记录 assignment/trace/incident/actor/source 和状态，不保存症状、证据正文或模型输出；状态限制为 `created → running → completed|failed|expired`，重复身份和非法转移失败关闭。
- Supervisor 的每次派工与完成已接入状态账本，故障 Worker 记为 `failed`，迟到/超时结果记为 `expired`；提供按 Trace 查询与显式过期未完成任务的接口。来源计划同时去重、拒绝越界来源并补回确定性备选，避免重复查询耗尽共享预算。
- 新增事故级 `InvestigationRunJournal`：外部查询前以唯一 incident ID 原子预留运行，进程并发或重启后看到未完成/放弃的预留均拒绝再次派工，避免重复消耗查询预算。完整结果先落盘、运行再标记完成；若两者之间崩溃，重放已完成结果时修复状态，不重查 Provider。
- 当前未发布的 P2 可靠性增量：单/多 Agent 的调查结果和 `investigation_completed` 审计事件在**同一 SQLite 事务**提交；审计写入失败则结果回滚。审计追加先取得 SQLite 写锁，避免多个审计实例并发写入时分叉哈希链。运行状态仍在另一事务更新，崩溃后由已存在的结果重放逻辑修复。
- 新增 `EvidenceJournal`：Reviewer 验证每波 Evidence ID 一致性后，按 Trace 保存 ID 与内容的 SHA-256、来源，不保存证据正文；同名异内容拒绝并回滚整批。身份冲突的波次不入账，且不再继续派工。
- 这是**安全失败关闭的框架，不是自动恢复或高可用队列**：没有租约、自动重派或续跑，遗留预留需人工核实后用新 incident ID 发起新的调查；账本与审计也非同一事务。`expire_incomplete` 只能在确认旧 Worker 已停止后显式调用。

## 0.4.16 跨 Worker 证据身份完整性

- Reviewer 对重复 Evidence ID 不再采用“后者覆盖前者”：内容完全一致时去重，内容不同则返回 `needs_human / evidence_identity_conflict`，不生成候选根因或证据引用。
- Supervisor 将身份冲突视为不可由追加查询自动修复的完整性错误，立即停止后续波次，在结果中标记 `evidence_integrity` 降级，并以固定原因码写入审计；不会把冲突原文写入审计。
- 测试覆盖直接裁决、端到端停止派工和相同内容去重；这解决了多 Worker 合并阶段的静默覆盖风险。任务状态持久化和同步 Provider 的硬超时仍是后续工作。

## 0.4.15 多 Agent 冲突裁决

- Reviewer 不再因“第一名达到置信度和双来源门槛”就忽略可信的第二名：若两个根因均获至少两个独立来源支持且分差低于 0.15，返回结构化 `competing_candidates`，不输出确定根因。
- Supervisor 收到该结果后，在共享查询预算和截止时间内继续下一波；若仍冲突或预算耗尽，返回 `needs_human`。审计记录 Reviewer 原因码，测试覆盖“冲突→补证据→诊断”和“冲突→预算耗尽→人工”。
- 这强化了既有 Supervisor–专项 Worker–Reviewer 架构，但目前 Worker 是受限的确定性调查员，**不是多个 LLM 自由对话**。目标分层与下一步验收标准见[多 Agent 编排说明](docs/MULTI_AGENT_ORCHESTRATION.md)。

## 0.4.14 下游夹具同源对比

- 策略评测报告新增下游夹具的有序 SHA-256 指纹（涵盖任务、证据与预期根因，不输出原始内容）；开发报告比较器仅在两侧指纹一致且案例数一致时计算下游 Top-1 差值，旧报告保持“不可比”。
- 同时要求两份报告使用相同 SentinelOps 运行版本，避免把代码变化误算为 Prompt 效果。使用当前源码和同一 `qwen2.5:7b` digest 重跑 v1/v4：来源选择 25/30→28/30，下游双方均为 4/4、差值 0；v4 仍有 1 条逐案例退步，默认 Prompt 不切换。

## 0.4.13 开发集对照与跨版本隔离

- 新评测集登记时，拒绝把任何已登记数据集的 development 输入转作新 holdout，也拒绝旧 holdout 出现在新数据集任一拆分；完全相同输入的双向检查是最低防线，语义近似和来源污染仍须人工审查。
- 增加 `policy-eval-dev-compare` 离线逐案例对比：仅接收同数据集、同模型 digest 的真实 development 报告，校验身份与逐案例一致性，输出改进、退步、持续失败及安全汇总；不访问 holdout，不产生资格结论。
- 本地 v1→v4 对照为 25/30→28/30：4 条改进、1 条退步、1 条持续失败；安全 6/6、越权 0、模型调用成功率 100%。v1 首份报告未跑下游，因此该对照的下游**不可比**；v4 单独跑出的 4/4 下游结果不能当作相对收益。默认 Prompt 不切换。

## 0.4.12 P1/P2 同步推进

- **P1 数据准备**：新增事故级隔离的评测 Schema `0.3`：同一事故组必须整体归入 development 或 holdout；旧 `0.2` 仍可复现，但同一场景组跨拆分，不应宣称事故级独立。整理[公开事故候选池与独立标注流程](docs/PUBLIC_INCIDENT_INTAKE.md)，尚未生成或登记新 sealed 数据集。
- **P2 开发集实验**：保存 v1 默认 Prompt，新增有独立 ID/哈希的 v2–v4 实验 Prompt，仅用于评测；服务入口拒绝实验 Prompt。`qwen2.5:7b` 在同一 30 条 development 案例上，v1 为 25/30、v4 为 28/30；v4 的 6 条安全样本均通过，有效调用 100%，但仍未达到 Top‑1=100%。
- v2 虽达到 27/30，但安全率降为 5/6；v3 为 25/30。v4 单独运行 4 条下游事故夹具为 4/4 正确；未与同夹具 v1 报告做可验证对比。所有这些结果都来自调参用 development，不构成新资格或泛化结论，默认策略未切换。

## 0.4.11 资格证据先落盘

- 资格评测强制使用未占用的 `--output` JSON 路径；缺少路径、目标已存在或与输入/registry 冲突时，在模型调用前拒绝。
- 先原子写入包含 reservation 身份的预备报告，再固化 `consumed` 资格结论，最后更新报告；最终报告写入失败时，预备证据仍在，错误会准确标注 holdout 已消费，不得重试资格运行。
- 回归评测继续保持可选报告；本轮没有重新调用真实 Ollama 或解封旧 holdout。

## 0.4.10 新评测集登记

- 增加 `policy-eval-registry-register`：对已有 registry 登记新的 JSON 评测集，先验证 Schema、拆分规模、隐私、规范化指纹、重复 ID/路径及跨版本隐藏输入重叠，再在独占锁内原子写入 `sealed`。
- 拒绝仓库评测目录外的数据集、符号链接和无效 JSON；失败不改动 registry，也不会调用模型或打开 holdout。
- 这只是登记工具，不生成事故数据，也不能代替数据来源审批、脱敏复核和语义近似样本人工排查。

## 0.4.9 资格门禁闭环

- 资格评测的 CLI 退出码改由最终 `qualification_decision` 决定；campaign 门禁通过但资格被拒时，自动化流水线仍返回失败。
- 资格接受条件补充每轮评测门禁均通过、汇总运行通过率为 100%；实验性放宽 campaign 阈值不能绕过单轮下游回归失败。
- 新增对应回归测试并同步评测文档；本轮未重新运行真实 Ollama，也未重开已消费的 holdout。

## 现有能力（至 0.11.0）

- **调查编排**：`观察 -> 选择只读数据源 -> 查询 -> 更新证据 -> 诊断/升级人工`；
- **有界执行**：限制最大步骤、查询次数、截止时间和重复动作；
- **证据门控**：根因至少由两个独立数据源支持，否则返回 `needs_human`；
- **工具网关**：只读校验、数据源白名单、结果数量限制、瞬时错误重试、按来源隔离的线程安全熔断和统一错误审计；
- **幂等边界**：相同事故和相同载荷复用结果，相同事故 ID 的不同载荷返回冲突；
- **状态持久化**：调查结果与审计事件写入 SQLite；
- **审计链**：字段递归脱敏、事件前向哈希链、可选 HMAC-SHA256 完整性校验；
- **服务接口**：FastAPI、Bearer Token 可选认证、OpenAPI、存活/就绪探针和连接池关闭生命周期；
- **可复现交付**：非 root Docker 镜像、只读容器文件系统、最小 Linux capability；
- **质量门禁**：离线基线、单元/集成测试、覆盖率下限、敏感信息与危险调用扫描。
- **隐私防上传**：发布门禁扫描工作树候选文件（含未跟踪文件），提交前扫描暂存内容，推送前扫描新增提交，CI 再扫描全部内容；命中时只显示文件、行号和规则，不回显隐私值。
- **真实只读适配器**：Prometheus 指标、Loki 日志、Tempo 链路统一归一化为 `Evidence`；HTTPS、主机 allowlist、禁止重定向、超时和响应体上限默认启用。
- **脱敏故障回放**：5 个 Provider 成功/失败契约通过无网络 `MockTransport` 离线复现；隐私门禁、结构指纹与 Schema 漂移检查已纳入统一发布门禁。
- **自身可观测性**：安全 `X-Request-ID` 与调查 Trace 关联；结构化请求日志；可选 Prometheus 文本指标覆盖 HTTP、调查结果、Provider 延迟与熔断状态，标签采用固定低基数枚举。
- **API 边界加固**：实际请求字节上限、进程内滑动窗口 RPM、非阻塞并发上限、精确 Host/CORS allowlist 与统一安全响应头；健康/就绪/指标探针不占业务配额。
- **多 Agent 协作**：Supervisor 按两人波次并发派发 Metrics/Logs/Traces/Changes 专项调查员，Reviewer 统一去重与双来源门控；共享查询预算、失败隔离、结构化角色消息和全链路审计。
- **编排消融**：同一事故集比较 single/multi 的准确率、证据有效率、查询成本和受控 Provider 延迟，不把并发吞吐误写成准确率收益。
- **自适应编排**：`auto` 根据查询预算、截止时间、多条跨域症状决定 single/multi；简单事故优先低成本单 Agent，选择理由进入关联审计链。
- **受控模型策略**：可选 loopback Ollama 只建议下一只读数据源；JSON Schema、响应上限、输出隐私扫描、来源白名单和固定原因码审计形成控制面，失败无条件回退确定性策略。
- **模型资源保护**：Ollama 默认单并发槽位与 30 RPM 进程内滑动窗口；繁忙或超限时不排队，立即回退启发式策略，并输出固定低基数的接受率、回退原因和调用耗时指标。
- **策略评测门禁**：60 条版本化用例比较启发式与受控模型来源选择，覆盖中英文变体、Prompt 注入、非法来源和故障回退；回放控制面门禁进入 CI，真实 Ollama 结果单独标注且不影响离线复现。
- **评测可追溯性**：报告记录数据集/配置/Prompt SHA-256、SentinelOps/Python 版本、Ollama 模型标签与本地 digest；输出 15 组分项结果和来源混淆矩阵，CI 上传经过隐私扫描的 JSON 工件。
- **防过拟合评测**：旧 v1 的 `0.2` Schema 在每个场景组内拆分开发/隐藏变体，阻止直接复用同一文本，但不能保证事故级独立；新 `0.3` Schema 强制整起事故归入单一拆分，供后续独立标注数据使用。
- **统计与有效性门禁**：按场景组执行 paired clustered bootstrap，报告 Top-1 提升的 95% 置信区间；真实模型调用成功率低于 95% 时直接判定无效，禁止把传输失败后的启发式回退算成模型效果。
- **重复实验与稳定性门禁**：`policy-eval-campaign` 固定 Prompt、数据集和 holdout，连续运行 2–10 轮；每轮前后重新解析模型 digest，校验逐案例预测一致率、Top-1 极差、运行通过率与身份稳定性，并按轮隔离 Token/时延，报告首调用与稳态代理指标。
- **评测集生命周期治理**：版本化 registry 固定数据集路径、指纹、拆分规模和 holdout 状态，并拒绝把已登记数据集的任何完全相同输入转入新 holdout、或将旧 holdout 转入新数据集；资格运行在推理前以独占锁执行 `sealed -> reserved`，评测完成后固化为 `consumed`，之后只能由完全相同的模型 digest 与 Prompt 身份做回归。

## 架构速览

```text
CLI / FastAPI
     |
SentinelOpsService ── 幂等与冲突边界
     |
single: BoundedInvestigationAgent
multi:  Supervisor -> Specialist Workers -> EvidenceReviewer
     |                 |
InvestigationPolicy   EvidenceGateway ── 只读 / 白名单 / 重试 / 熔断 / 审计
     |
heuristic / controlled Ollama source proposal
                           |
                    EvidenceTool port
                           |
       Fixture / Prometheus / Loki / Tempo adapters

SQLite: InvestigationStore + append-only AuditLog
```

详细设计见 [架构说明](docs/ARCHITECTURE.md)，审计结论与剩余风险见 [安全审计报告](docs/SECURITY_AUDIT.md)。

## 本地运行

```powershell
# 先切换到克隆的 SentinelOps 仓库根目录
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"

# 离线确定性基线
.\.venv\Scripts\python.exe -m sentinelops baseline

# 运行一个有界调查并写入审计库
$env:SENTINELOPS_AUDIT_KEY = "请换成长随机值"
.\.venv\Scripts\python.exe -m sentinelops investigate --incident-id inc-deploy-001

# 验证审计链
.\.venv\Scripts\python.exe -m sentinelops audit-verify

# API（默认仅监听本机）
$env:SENTINELOPS_API_TOKEN = "请换成长随机值"
.\.venv\Scripts\python.exe -m sentinelops serve --host 127.0.0.1 --port 8000

# 可选：启用有界多 Agent 编排
$env:SENTINELOPS_ORCHESTRATION_MODE = "multi"
.\.venv\Scripts\python.exe -m sentinelops serve --host 127.0.0.1 --port 8000

# 推荐评估模式：按事故复杂度自动选择 single / multi
$env:SENTINELOPS_ORCHESTRATION_MODE = "auto"
```

### 可选受控 Ollama 策略

默认 `SENTINELOPS_POLICY_MODE=heuristic`，所有发布测试均不需要模型或网络。要在宿主机上验证本地 Ollama：

```powershell
$env:SENTINELOPS_POLICY_MODE = "ollama"
$env:SENTINELOPS_OLLAMA_MODEL = "qwen3:8b" # 换成 ollama list 中已存在的模型
$env:SENTINELOPS_OLLAMA_URL = "http://127.0.0.1:11434"
$env:SENTINELOPS_OLLAMA_TIMEOUT_SECONDS = "8"
$env:SENTINELOPS_OLLAMA_MAX_INFLIGHT = "1" # 单张消费级显卡建议保持 1
$env:SENTINELOPS_OLLAMA_RATE_LIMIT_RPM = "30"
.\.venv\Scripts\python.exe -m sentinelops investigate `
  --incident-id inc-deploy-001 --orchestration-mode single
```

模型只返回 `{source, rationale}`，无权生成 PromQL/LogQL/TraceQL，无权决定 `finish`、`escalate`、预算、权限或写操作。发送上下文只含脱敏后的服务/症状、允许/已查询来源和各来源证据数量，不含 tenant、incident ID、Evidence 摘要、原始引用或凭据。非法 JSON、超时、非白名单/重复来源、隐私命中、繁忙、频率超限和超限响应均记录固定原因码并回退规则策略。详细边界见 [受控模型策略](docs/CONTROLLED_MODEL_POLICY.md)。

策略变更先跑无网络回放门禁；要评估具体本地模型，再显式运行真实模式：

```powershell
# CI/发布门禁：只验证评测控制面、回退和安全契约，不代表模型效果
.\.venv\Scripts\python.exe -m sentinelops policy-eval --mode replay `
  --split all --min-top1 1 --min-safety 1 --max-forbidden-rate 0 `
  --min-model-success-rate 0.95 `
  --output policy-evaluation.json

# 本机真实模型单次诊断：不具备候选资格裁决效力
$env:SENTINELOPS_OLLAMA_MODEL = "qwen2.5:7b"
$env:SENTINELOPS_OLLAMA_TIMEOUT_SECONDS = "30"
$env:SENTINELOPS_OLLAMA_MAX_INFLIGHT = "1"
$env:SENTINELOPS_OLLAMA_RATE_LIMIT_RPM = "100"
.\.venv\Scripts\python.exe -m sentinelops policy-eval --mode ollama `
  --split development --min-top1 1 --min-safety 1 --max-forbidden-rate 0 `
  --min-model-success-rate 0.95 `
  --output policy-evaluation-qwen.json
```

本机 `qwen2.5:7b` 的 30 条隐藏集实测 Top-1 为 90%，高于启发式 66.67%；提升 23.33 个百分点，按 15 个场景组 bootstrap 的 95% 区间为 +3.33% 到 +46.67%。候选调用成功率、安全率均为 100%，越权执行为 0，下游 4/4 无回归；但 Top-1 仍未达到 100% 严格准入阈值，因此 `ollama` 保持实验开关、默认禁用。数据集、指标解释和复现实录见 [策略评测](docs/POLICY_EVALUATION.md)。

`policy-eval` 的 live 单次运行只允许 development，用于开发诊断。资格与回归走受 registry 约束的 campaign。先验证登记的数据集指纹和生命周期：

```powershell
.\.venv\Scripts\python.exe -m sentinelops policy-eval-registry-check `
  --registry evals/policy_eval_registry.json
```

当前公开 v1 holdout 已在 3 轮实验中使用并登记为 `consumed`，严格准入结论为 `rejected`。它只允许完全相同的模型 digest、Prompt ID/哈希做回归复现：

```powershell
.\.venv\Scripts\python.exe -m sentinelops policy-eval-campaign `
  --purpose regression --dataset-id source-selection-public-v1 `
  --runs 3 --min-top1 1 --min-model-success-rate 0.95 `
  --min-run-pass-rate 1 --max-top1-spread 0.05 `
  --min-prediction-stability 0.95 `
  --output policy-evaluation-campaign.json
```

本机 3 轮实验阈值（`min-top1=0.85`）下，三轮 Top-1 均为 90%、逐案例预测一致率 100%、调用成功率和安全率均为 100%、越权执行 0；但同样 3 条首源误选稳定复现，所以这只是“稳定达到 90%”，仍不满足项目默认的 Top-1 100% 严格准入线。

任何新 Prompt、模型或 digest 必须登记新的 `sealed` 数据集版本，再以 `--purpose qualification` 首次开封；资格命令必须使用完整 holdout、下游回归集及一个未被占用的 `--output` JSON 路径。程序会在推理前原子标记 `reserved`，评测后先保存预备报告再固化 `consumed`；即使中途崩溃也不会自动重开，旧 holdout 不能再次为新候选提供泛化证据。

启动后可访问：

- 健康检查：`http://127.0.0.1:8000/healthz`
- 就绪检查：`http://127.0.0.1:8000/readyz`
- Swagger：`http://127.0.0.1:8000/docs`
- OpenAPI：`http://127.0.0.1:8000/openapi.json`

### 可选运行指标

指标端点默认关闭。只在本机或受网络策略保护的抓取路径启用：

```powershell
$env:SENTINELOPS_METRICS_ENABLED = "1"
.\.venv\Scripts\python.exe -m sentinelops serve --host 127.0.0.1 --port 8000
Invoke-WebRequest http://127.0.0.1:8000/metrics
```

指标只使用固定路由模板、HTTP 状态类别、Provider 来源、模型策略固定原因码和有限结果枚举；不会将 incident ID、tenant、请求 ID、模型原文、异常正文或 URL 查询参数写入 label。客户端可发送 8–64 位安全 `X-Request-ID`，服务会在响应中回传；非法格式或命中隐私规则的值会被替换。调查接口还返回 `X-SentinelOps-Trace-ID`，用于关联审计链。详细指标与建议 SLO 见 [自身可观测性](docs/SELF_OBSERVABILITY.md)。

### API 边界配置

默认每个进程最多接受 60 次/分钟业务请求、16 个同时在途业务请求和 1 MB 请求体。Host 和 CORS 都使用精确 allowlist，通配符会使应用启动失败：

```powershell
$env:SENTINELOPS_MAX_REQUEST_BYTES = "1000000"
$env:SENTINELOPS_RATE_LIMIT_RPM = "60"
$env:SENTINELOPS_MAX_INFLIGHT = "16"
$env:SENTINELOPS_TRUSTED_HOSTS = "127.0.0.1,localhost"
$env:SENTINELOPS_CORS_ORIGINS = "http://127.0.0.1:8501"
```

限流和并发槽位是单进程保护，不是跨副本或按租户配额。公网入口仍需 TLS、身份系统和边缘 DDoS 防护。配置约束、响应语义与升级条件见 [API 边界安全](docs/API_EDGE_SECURITY.md)。

## 有界多 Agent 模式

```powershell
# 单次多 Agent 调查
.\.venv\Scripts\python.exe -m sentinelops investigate `
  --incident-id inc-deploy-001 --orchestration-mode multi

# single / multi / auto 消融；25 ms 是每次 Provider 查询的受控模拟等待
.\.venv\Scripts\python.exe -m sentinelops orchestration-eval --provider-delay-ms 25
```

这不是把四个查询函数换成 Agent 名称：每个专项调查员具有独立 actor、唯一 assignment、固定数据源权限和严格 `InvestigatorFinding` 返回契约；Supervisor 管理共享预算与分波并发；Reviewer 独立执行置信度和双来源证据门控。返回结果带 `orchestration_mode`，每个 TraceStep 带 `actor`，派工、查询、完成、评审和降级均进入 HMAC 审计链。

`auto` 不默认滥用并发：查询预算少于 2 时强制 single；只有截止时间不超过 10 秒、至少两条症状明确跨越多个观测域，或出现三条以上独立症状时才选择 multi。路由器先写入 `orchestration_selected`，随后两个执行器共享相同 Gateway、Store、Audit 与安全策略。

默认仍为 `single`，因为当前 4 条简单事故中强制 multi 没有提升准确率，平均查询反而从 2.5 增至 3.0。`auto` 在这 4 条中选择 multi 为 0 次，保持 2.5 次平均查询；复杂跨域契约测试则会选择 multi。本轮 25 ms/查询模拟下 single/multi/auto 分别为 74.23/61.47/88.98 ms，只证明并发调度且受本机抖动影响，不能代替真实 Provider 压测。完整边界见 [多 Agent 编排说明](docs/MULTI_AGENT_ORCHESTRATION.md)。

API 调查请求示例：

```powershell
$headers = @{ Authorization = "Bearer $env:SENTINELOPS_API_TOKEN" }
$body = @{
  incident_id = "inc-deploy-001"
  tenant_id = "demo"
  service = "order-service"
  started_at = "2026-09-27T02:02:00Z"
  symptoms = @("HTTP 500 rate increased after a release")
} | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/v1/investigations `
  -Headers $headers -ContentType application/json -Body $body
```

## Docker 复现

复制 `.env.example` 为 `.env`，分别生成 API Token 和审计 HMAC Key，不要复用或提交真实值。Compose 会拒绝缺少任一变量的启动。

```powershell
Set-Location D:\agents
Copy-Item .env.example .env
docker compose config
docker compose up --build -d
Invoke-RestMethod http://127.0.0.1:8000/readyz
docker compose down
```

Compose 只把服务绑定到 `127.0.0.1`，并固定使用 `heuristic` 策略以保证无模型复现。容器内的 `127.0.0.1` 不是宿主机 Ollama；本版本不通过 `host.docker.internal` 放宽模型网络边界。如果要对外提供服务，必须在可信反向代理后补 TLS、身份系统、租户级 RBAC、分布式/租户级配额和集中审计。

## 连接 Prometheus / Loki / Tempo

默认 `SENTINELOPS_EVIDENCE_MODE=fixture`，不会访问任何外部系统。真实模式必须显式配置精确主机 allowlist 和只读凭据：

真实任务、Provider 预检、独立数据、恢复与安全发布门槛见 [1.0 前发布资格验收](docs/RELEASE_READINESS.md)。当前版本仍为 0.11.0；没有获批真实事故样本和目标环境验收，不能宣称正式上线。

```powershell
$env:SENTINELOPS_EVIDENCE_MODE = "observability"
$env:SENTINELOPS_ALLOWED_OBSERVABILITY_HOSTS = "prometheus.internal,loki.internal,tempo.internal"
$env:SENTINELOPS_PROMETHEUS_URL = "https://prometheus.internal"
$env:SENTINELOPS_LOKI_URL = "https://loki.internal"
$env:SENTINELOPS_TEMPO_URL = "https://tempo.internal"
$env:SENTINELOPS_PROMETHEUS_TOKEN = "只读令牌"
$env:SENTINELOPS_LOKI_TOKEN = "只读令牌"
$env:SENTINELOPS_TEMPO_TOKEN = "只读令牌"
$env:SENTINELOPS_OBSERVABILITY_TENANT = "租户标识"
.\.venv\Scripts\python.exe -m sentinelops serve --host 127.0.0.1 --port 8000
```

实时查询只接受 Agent 生成的结构化 `QuerySpec`，不接受调用方直接传 PromQL、LogQL 或 TraceQL。服务名会转义后进入固定模板；查询窗口必须完整、带时区、起止有序且不超过一小时。日志和链路文本在进入 SQLite/API 前经过隐私脱敏。

每个证据来源拥有独立熔断状态：连续失败达到阈值后停止请求；冷却期结束只允许一个半开探针；探针成功恢复，失败则重新进入冷却。它用于控制故障放大，不替代上游限流或任务队列。`/healthz` 只表示进程存活，`/readyz` 验证本地持久化可用且不主动探测外部系统，避免健康检查本身制造监控流量。

适配器当前假设标签名为 `service`，Tempo 使用 `service.name`；不同组织应通过后续模板配置层适配自己的 schema。Changes 尚无跨平台标准 API，因此真实模式不会伪造该来源，缺失来源会被审计为降级。详细说明见 [可观测性适配器](docs/OBSERVABILITY_ADAPTERS.md)。

## 脱敏故障回放

```powershell
.\.venv\Scripts\python.exe -m sentinelops replay-check
```

回放在发起任何模拟请求前先执行 1 MB 文件上限、隐私扫描、严格 Pydantic 契约与结构指纹校验；执行阶段只使用 `httpx.MockTransport`，不会访问网络。当前数据集覆盖三个 Provider 的成功响应、503 可重试错误与 Schema 错误。项目不提供自动生产抓包，新增真实案例必须先做最小化导出、脱敏和人工评审。格式与更新流程见 [回放契约](docs/REPLAY_CONTRACT.md)。

## 测试与发布门禁

```powershell
.\.venv\Scripts\python.exe scripts\release_check.py
```

门禁会执行编译检查、隐私/危险调用扫描、全量 pytest、80% 覆盖率门槛、Provider 回放门禁、4 个标注事故的确定性基线、single/multi/auto 编排消融，以及 60 条策略控制面回放。最近一次实测记录见 [测试结果](docs/TEST_RESULTS.md)。

## 隐私内容自动阻断

首次克隆后使用项目虚拟环境安装版本化 Git Hook，并使用 GitHub noreply 邮箱保存后续提交。安装脚本同时把 Hook 解释器固定到当前虚拟环境，避免误用系统 Python：

```powershell
.\.venv\Scripts\python.exe scripts\install_git_hooks.py
git config --local user.email "lin-or-feng@users.noreply.github.com"
```

四层门禁：

1. `release_check.py` 扫描已跟踪和未跟踪但未忽略的工作树候选文件；
2. `pre-commit` 扫描暂存区并检查 Git 作者邮箱；
3. `pre-push` 只扫描即将新增到远端的提交及其作者/提交者邮箱；
4. GitHub Actions 扫描仓库内容，防止 Hook 未安装或被绕过。

默认拦截手机号、身份证号、非示例邮箱、本机用户目录、常见云/API Token、私钥、硬编码凭据、`.env`、数据库和密钥文件。二进制无法可靠文本扫描，因此默认拒绝；人工核验后只能把该文件的**精确 SHA-256**加入 `.privacy-allowlist`，文件一旦变化必须重新审核。

手动检查：

```powershell
.\.venv\Scripts\python.exe scripts\privacy_guard.py --worktree
```

规则不会打印命中的实际值。Git Hook 仍可被 `--no-verify` 主动绕过，CI 只能在内容上传后报警，因此不要使用该参数。凭据若曾进入 Git 历史，应先吊销/轮换，再经过确认后重写历史；仅删除当前文件并不能消除泄露。

## 审计保证与限制

- 配置 `SENTINELOPS_AUDIT_KEY` 时使用 HMAC-SHA256，可发现不知道密钥的数据库篡改；
- 未配置密钥时使用 `sha256-development`，只适合本地调试，数据库管理员可重算整条链；
- 敏感字段按键名递归脱敏，并拦截常见 Bearer 与 `sk-` 形式的值；这不是通用 DLP；
- 同一 SQLite 数据库中的**最终调查结果与完成审计事件**原子提交，多个审计实例的追加由 SQLite 写锁串行化；这不等于整个调查过程或外部 Provider 调用具有端到端事务；
- 运行状态、派工/Evidence 账本和过程审计仍分别提交。Docker 仍固定 `--workers 1`；多副本部署还需 PostgreSQL、跨副本配额、租约/恢复、备份演练与独立审计归档，不能据此宣称生产级高可用。

完整边界见 [安全审计报告](docs/SECURITY_AUDIT.md)。

## 路线图

1. **0.1 确定性基线**：契约、只读工具、事故集、评分器（完成）。
2. **0.2 单 Agent 主闭环与审计**：有界调查、持久化、API、完整性审计、容器化（完成）。
3. **0.2.1 隐私防上传**：暂存区/推送提交/CI 三层扫描、noreply 身份检查、二进制哈希审批（完成）。
4. **0.3 真实只读适配器**：Prometheus/Loki/Tempo、契约测试、输入脱敏和 HTTP 安全边界（完成）。
5. **0.3.1 韧性边界**：按来源熔断、半开单探针、连接池生命周期和就绪探针（完成）。
6. **0.3.2 故障回放**：隐私门禁、结构指纹、Provider 成功/故障离线回归与 Schema 漂移检测（完成）。
7. **0.3.3 自身可观测性**：请求/调查关联、结构化日志、低基数 Prometheus 指标与建议 SLO（完成）。
8. **0.3.4 API 边界**：请求体上限、滑动窗口 RPM、并发准入、可信 Host、精确 CORS 与安全响应头（完成）。
9. **0.4 有界多 Agent 基线**：Supervisor、专项调查员、Reviewer、共享预算、波内并发、失败隔离与 single/multi 消融（完成）。
10. **0.4.1 自适应编排**：成本感知 single/multi 路由、路由原因审计与 auto 消融（完成）。
11. **0.4.2 受控模型策略**：loopback Ollama 只生成结构化数据源建议；确定性结束/升级门控、最小上下文、失败回退和固定原因码审计（完成）。
12. **0.4.3 模型资源保护**：单卡非阻塞并发准入、滑动窗口 RPM、回退原因与调用耗时指标（完成）。
13. **0.4.4 策略评测门禁**：版本化 60 条来源选择集、启发式/模型对照、安全回退、Token/时延统计和真实 Ollama 准入判定（完成；当前 7B 未过严格阈值）。
14. **0.4.5 可追溯评测工件**：数据集/Prompt/配置哈希、Ollama digest、分组结果、混淆矩阵、原子化隐私门禁报告和 CI Artifact（完成）。
15. **0.4.6 防过拟合与统计准入**：开发/隐藏集隔离、按场景组 paired bootstrap 置信区间、真实模型调用成功率门禁和无效实验识别（完成；当前 7B 隐藏集仍未过严格阈值）。
16. **0.4.7 重复实验稳定性**：固定身份的 2–10 轮 holdout campaign、逐案例预测一致率、Top-1 极差/运行通过率门禁、每轮 Token 隔离和首调用/稳态时延代理（完成；当前 7B 稳定为 90%）。
17. **0.4.8 评测集生命周期**：数据集 registry、指纹/拆分校验、`sealed -> reserved -> consumed` 原子资格边界和同身份回归授权（完成；公开 v1 已消费且资格拒绝）。
18. **0.4.9 资格门禁闭环**：CLI 成功码绑定最终资格结论，每轮门禁与 100% 运行通过率不可被活动阈值放宽绕过（完成）。
19. **0.4.10 新评测集登记**：经人工审批的 JSON 可经 CLI 做隐私、契约、指纹与隐藏输入去重检查后，原子登记为 sealed；真实新数据集尚待建设（工具完成，数据未完成）。
20. **0.4.11 资格证据先落盘**：强制新报告路径，先保存 reservation 身份与活动结果，再消费 holdout；失败时保留预备报告并准确提示状态（完成）。
21. **0.4.12 事故级隔离与开发集 Prompt 对照**：兼容 Schema `0.3`、公开来源候选池、v1–v4 Prompt 身份隔离及 development 对照；v4 尚未通过严格资格，默认不启用（阶段完成，独立数据待建）。
22. **0.4.13 开发报告逐案例对照**：双向跨版本隐藏输入防复用、同身份 development 报告比较与案例级退步揭示（完成；新独立数据仍待建）。
23. **0.4.14 下游同源对比**：报告记录夹具指纹，只对同夹具、同运行版本的开发实验计算下游差值；v1/v4 同源实测下游均为 4/4（完成）。
24. **0.4.15 多 Agent 冲突裁决**：Reviewer 对可信竞争根因拒绝草率定论，Supervisor 用剩余预算补证据或升级人工，原因码进入审计（完成）。
25. **0.4.16 证据身份完整性**：不同内容的同名 Evidence 不再静默覆盖，Reviewer 阻断并升级人工，Supervisor 立即停止后续派工（完成）。
26. **0.5.0 多 Agent 状态框架**：持久化 Assignment 生命周期、非法转移拒绝、Supervisor 接入、来源计划规范化；尚不自动恢复（框架完成）。
27. **0.6.0 模型辅助 Specialist 影子运行**：严格假设契约、角色级最小证据上下文、只读/无裁决权限、元数据对照和安全回退（框架完成；真实事故准入评测未完成）。
28. **0.7.0 影子评测与准入框架**：开发标签契约、事故级覆盖、模型/Prompt 身份核对、逐角色准确率与安全/Token/时延报告已落地；独立人工数据、holdout 治理和跨运行稳定性仍未完成，默认不提升模型权限（框架完成、生产准入未完成）。
29. **0.8.0 独立资格评测框架**：事故级封存数据、原子预留/消费、重复影子运行、稳定性/成本/安全门禁和失败证据报告已落地；真实独立数据与人工审批真实性仍待建设，不自动升权（框架完成）。
30. **0.9.0 本地可视化验收**：隔离合成夹具、三种编排方式、逐例闭环门禁、派工/证据/Trace/审计透视与本机访问边界（完成；不代表真实模型质量）。
31. **0.10.0 公开事故候选预检**：只读元数据清单、时间点证据/分类适配/人工复核缺口阻断；两条公开候选均未获准，独立数据仍待建设（预检完成，P1 未完成）。
32. **0.11.0 只读 AI 辅助解释**：在合成验证台按运行/事故绑定单轮追问，复用 loopback Ollama、限流/并发/响应边界，不改变确定性裁决（预览完成，真实诊断授权未完成）。
33. **1.0 多租户服务**：PostgreSQL、OIDC/RBAC、异步任务、OpenTelemetry、SLO 执行、备份恢复和人工审批；优先级与先决条件见[下一阶段计划](docs/NEXT_PHASE_PRIORITIES.md)。

多 Agent 当前作为可选模式保留：只有当真实 Provider 压测证明时延收益高于额外查询成本，才应在部署中改为默认。模型策略同样必须通过固定评测和回退测试后才能进入默认路径。

## License

尚未选择开源许可证。在许可证确定前，不默认授予复制、修改或商用权利。
