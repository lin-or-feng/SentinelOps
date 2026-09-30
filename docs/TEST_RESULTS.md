# SentinelOps 0.11.0 与未发布的 1.0 前验收增量测试结果

- 最新本地验证日期：2026-09-30
- Python：3.11.9
- 平台：Windows 10

## 发布门禁结果

2026-09-30 离线验收 harness 收拢：`python -m scripts.operator_offline_acceptance` 自动启动两次仅绑定 loopback 的假来源服务、驱动系统 Edge 做完整调查与中断找回、关闭服务并写入忽略目录报告和截图，临时 Token 不落盘。中断恢复轮询改为每 2 秒一次，避免 0.5 秒高频请求触发自身限流。实跑两阶段均通过（主流程 2.84 秒、中断恢复 9.08 秒），退出码 0；失败时退出码非 0，报告明确 `release_qualification=false`。新增 3 项报告/Token 脱敏单测；完整门禁 **321/321 pytest 通过，行覆盖率 90.88%**，隐私扫描、静态审计与回放均通过。这仍只验证合成浏览器流程，不是对真实事故的上线批准。详见[离线验收记录](OPERATOR_OFFLINE_ACCEPTANCE.md)。

2026-09-30 离线浏览器验收增量：系统 Edge 访问 `127.0.0.1:8768` 明示 `OFFLINE TEST` 的假来源入口，实际完成连接、来源预检、显式确认、调查、审计和刷新找回；另在请求发出后关闭浏览器，观察到 `running` 预留，后台完成后无需重交调查即可找回。发现并修复单 Agent 查询未配置来源的问题，同场景查询数 **4 → 2** 且不再产生来源拒绝事件。新增 5 项离线回归，覆盖来源白名单、查询超时、完成后重启找回、预留后重启拒绝重跑及离线入口标识；原审计篡改用例继续通过。完整门禁 **318/318 pytest 通过**，行覆盖率 **90.88%**（5129 行、468 行未覆盖），隐私扫描和静态审计通过。浏览器截图和逐项边界见[离线验收记录](OPERATOR_OFFLINE_ACCEPTANCE.md)。没有真实 Provider 或事故样本，仍未发布。

2026-09-30 中断找回状态增量：新增本机只读 `/api/run-state`，在审计链校验通过后区分当前 SQLite 的 `not_found`、`running`、`abandoned`、`completed`，并标示结果是否落盘；页面仅在找回返回 404 时查询状态，不重试调查或访问 Provider。新增 2 项离线测试覆盖运行预留/失败保留、已完成状态、审计篡改拒绝以及状态查询不增加 Provider 调用。完整门禁 **313/313 pytest 通过**，行覆盖率 **90.85%**（5125 行、469 行未覆盖），隐私扫描、静态审计及回放通过；`node --check` 通过。未进行浏览器点击验收或真实来源联调，不能据此认定 1.0 具备上线资格。

2026-09-30 故障诊断增量：新增 12 项离线测试，覆盖 401/403 授权拒绝、408/上游超时、429 限流、超大/畸形响应的固定原因码及上游正文不回显；另对已保存调查篡改 SQLite 审计链，确认操作台找回返回 `audit_chain_invalid`，不返回结论或重复查询 Provider。完整门禁 **311/311 pytest 通过**，行覆盖率约 **90.89%**（5107 行、465 行未覆盖），隐私扫描、静态审计、既有 Provider 回放和策略回放通过。仍是 MockTransport/假来源与本地 SQLite 测试，未使用真实监控凭据或事故样本。

未发布真实调查台增量：新增 10 项离线测试，覆盖强 Token、与夹具服务隔离、同任务预检/显式确认、来源失败、跨站来源与隐私拒绝、异常脱敏、启动前阻断、仅本机绑定、仓库外数据库约束及结果找回不重复查询 Provider。完整门禁复跑 **299/299 pytest 通过**，行覆盖率约 **90.86%**（5079 行、464 行未覆盖）；隐私扫描、静态审计、Provider 回放、策略回放与离线基线通过。`node --check` 通过；隔离 wheel 构建/安装验证新增操作台 HTML/CSS/JS 均被打包。测试 Provider 全为本机假对象，未使用真实凭据或事故，不能作为真实联调证据。

命令：

```powershell
.\.venv\Scripts\python.exe scripts\release_check.py
```

| 检查 | 结果 |
|---|---|
| `compileall` 源码、测试与脚本 | 通过 |
| 工作树候选文件隐私扫描（含未跟踪、未忽略文件） | 通过 |
| 危险运行时调用与已知密钥格式扫描 | 通过 |
| pytest | 321/321 通过 |
| `sentinelops` 行覆盖率 | 90.88%（5129 行中的 468 行未覆盖，门槛 80%） |
| Provider 回放门禁 | 5/5 通过，Schema 漂移 0 |
| 策略控制面回放 | 60/60 来源正确，12/12 安全样本通过，越权执行 0 |
| 离线基线 | 4/4 Top-1 正确 |
| 证据引用有效性 | 100% |
| 基线平均查询数 | 4.0 |

4/5 发布准备增量新增 6 项 pilot 静态配置预检与启动前拒绝测试；独立 wheel 构建/安装/静态资源冒烟在 Windows 本地通过，Compose 占位配置静态校验通过。本机 Docker Linux 引擎未运行，故本地容器构建/启动未验证；手动 CI 工作流未提交触发。完整门禁、隐私扫描与静态审计在当前工作区通过，仍不代表获得上线资格。

本轮 1.0 前验收增量在此前 273 项基础上新增 10 项测试：真实任务 JSON 的隐私/体积边界、Provider 显式预检的有界读取与不泄露正文、CLI 真实路径绝不回退夹具、配置缺失失败关闭；SQLite 在线备份/隔离恢复与审计校验、错误密钥/篡改/覆盖拒绝、CLI 入口；Provider 超时的人工升级与上游错误脱敏，以及多 Agent 软截止时等待读线程收尾。Windows 测试还发现并修复 `sqlite3.Connection` 事务上下文不会自动关闭连接导致临时备份被锁住的问题。完整发布门禁通过，但未接入真实只读 Provider，也没有获批独立事故数据。

此前未发布 P2 增量增加 4 项回归：单/多 Agent 的完成审计故障注入均回滚结果；提交后运行状态遗留 `running` 时，重放只修复状态且不重复写完成事件；多个独立审计实例并发追加后哈希链仍有效。0.11.0 原基线为 269 项、91.16% 行覆盖率；此处更新的 283 项不表示已经提交或发布新版本。

0.4.14 增加下游夹具指纹稳定性/顺序变化、同指纹下游差值、不同指纹不可比、下游案例数不一致和运行版本不一致的测试。使用 `qwen2.5:7b` 相同模型 digest，在 0.4.13 的当前源码上重跑两份 development 报告：v1 为 25/30、v4 为 28/30；两份报告的下游夹具指纹相同，4 条夹具准确率均为 4/4，Top-1 差值 0。模型调用成功率和安全率均为 100%，越权执行率 0。v4 有 1 条逐案例退步。报告仅存本机忽略目录，不构成独立 holdout 验证；共享虚拟环境首次误加载旧版 0.4.6 的结果已被正确版本运行覆盖，未纳入对比。

0.4.15 新增三项冲突裁决测试：Reviewer 对两个同样满足双来源与置信度门槛的根因返回 `competing_candidates`；Supervisor 在第三个来源的证据消除冲突后才诊断，预算只有两次时保持 `needs_human`；领域契约拒绝把 `supported` 原因码用于人工升级。审计事件展示 `competing_candidates -> supported` 的结构化状态变化。原有 4 条离线事故基线保持 4/4，未使用真实 Provider 或重新开启 holdout。

0.4.16 新增直接与端到端两项完整性测试：Reviewer 拒绝不同内容复用 Evidence ID，同时允许完全相同内容去重；Supervisor 在第一波发现身份冲突后立即停止，不调用第三个来源，结果为 `needs_human / evidence_integrity`，审计含固定 `evidence_identity_conflict` 原因码。4 条离线基线、Provider 回放和策略控制面门禁继续通过。

0.5.0 新增 4 项框架测试：AssignmentJournal 在重新打开 SQLite 后仍保留终态；重复身份和非法状态跳转被拒；显式过期只影响指定 Trace 的未完成任务；噪声来源计划（重复、越界、缺失备选）被规范化，使两次预算真正查询两个独立来源。既有多 Agent 测试还核对正常 Worker 的 `completed` 和故障 Worker 的 `failed` 持久状态。所有测试离线运行，不调用真实 Provider 或重开 holdout。

0.5.0 框架补全再加 6 项测试：事故运行预留持久化与非法转移拒绝、异常后的跨实例拒绝重跑、同事故并发只允许一个执行者、结果先落盘崩溃窗口修复、Evidence 哈希账本的同名异内容整批回滚，以及 Supervisor 正常波次入账。原有身份冲突测试补充断言冲突波次不入账。没有测试真实 Provider 的幂等能力，也没有宣称崩溃后自动恢复。

0.6.0 增加 11 项影子 Specialist 测试：严格假设/上下文契约、默认关闭和最终结论不变、越界证据引用与模型故障降级、脱敏上下文、不允许单 Agent 错误开启、MockTransport 本地结构化调用、身份冲突时跳过、元数据报告、非法模型字段拒绝，以及账本故障不撤销已落盘诊断。报告中的基线一致率不是人工真值正确率；本轮没有实测真实 Ollama 模型质量、生产 Provider 时延或独立 holdout。

0.7.0 新增 6 项开发集影子评测测试：标签/模型/Prompt 身份绑定与不含事故 ID 的汇总、最低样本门禁及 CLI 退出码、未经治理的 holdout 拒绝、digest/Prompt 漂移拒绝、缺失调查/重复标签拒绝、标签隐私扫描。开发样例由测试合成，不是独立人工标注，也没有实际调用 Ollama 或生产 Provider。

0.8.0 增加 11 项封存 holdout 闭环测试：数据集事故组/证据作用域、登记后的指纹漂移与跨数据集重叠拒绝、20 条 holdout 的两轮合成资格接受与一次性消费、模型 digest 漂移保留 reserved/预备报告、完成一轮后中断仍保留逐轮结果、并发预留只允许一个执行者、跨轮预测不稳定和错误根因假设均消费为 rejected、过小样本/已有报告在预留前拒绝、终结后报告写入失败时明确提示已消费，以及只读登记/检查 CLI。测试中的假模型与合成事故仅验证状态机和门禁计算，不构成真实模型质量证据。完整发布门禁通过，239 项 pytest 全部通过，行覆盖率 91%。

0.9.0 新增 9 项本地可视化验收测试：静态资产与案例元数据；single/multi/auto 三种模式下四条合成事故的实际调查、派工、证据/根因/审计/持久化/运行终态闭环；越界案例、非法模式、跨站 Origin、非 JSON、超长请求体、不可信 Host 与非本机客户端拒绝；审计校验失败时门禁明确失败；重复运行生成新 Trace 且清理临时库；频率限制返回 429。Windows 临时 SQLite 回收问题已在定向测试中发现并修复，运行目录移至项目 D 盘忽略目录。完整发布门禁通过：248 项 pytest 全通过、行覆盖率 91%、隐私与静态审计通过。浏览器手工点击 `Multi` 全量运行显示 4/4 闭环与 4/4 根因正确，案例详情显示两名专项 Worker、两条引用证据、三步 Trace 和九条通过校验的审计事件。此结果只针对合成夹具，不代表真实模型质量。0.9.0 wheel 已从官方 PyPI 隔离构建，并确认包含 HTML/CSS/JS 三项静态资产。

0.10.0 新增公开事故候选预检：定向测试覆盖零机器阻断仍需人工审查、事后信息与分类外根因阻断、决策时刻后证据阻断、非 HTTPS/私网 URL 与非法标签拒绝、多事故报告拆分、重复事故组、隐私命中与超长清单。首批 2 条公开候选均返回 `blocked`，命令退出码 `1` 是预期结果；未创建、封存或消费真实 holdout。完整发布门禁通过：261 项 pytest、行覆盖率 91.25%、隐私/静态审计与既有离线回放均通过。本轮仅测数据准入控制，不测真实模型效果。

0.11.0 新增 8 项助手测试：默认关闭且不受其他模型环境变量影响；只读绑定当前运行/事故与已引用证据、模型上下文不含夹具预期答案；无效运行/事故及隐私问题拒绝；模型或适配器改写根因、引用不存在证据失败关闭；本机 Ollama MockTransport 的结构化请求无工具权限。`node --check` 前端脚本通过。完整发布门禁通过：269 项 pytest、91.16% 行覆盖率、隐私/静态审计与既有离线回放均通过。

本机单次真实烟测：在独立 `127.0.0.1:8766` 进程上显式启用 `qwen2.5:7b`，一条合成部署事故的调查门禁通过；助手返回 `status=advisory`、`decision_unchanged=true`，根因仍是 `deployment_regression`，仅引用 `ev-deploy-change` 与 `ev-deploy-log`。浏览器实测 `Multi` 四条合成案例显示 4/4 闭环与 4/4 夹具预期根因；辅助解释区显示 AI 答案、两条引用和不确定性。模型回答的语义真实性尚不能由引用 ID 校验完全保证，也未在真实独立事故上测误诊率或泛化；因此不授予 AI 裁决权。

覆盖的关键场景包括：严格契约、只读/白名单拒绝、瞬时错误重试、非瞬时错误审计、按来源熔断、冷却恢复与并发单探针、查询与重复动作预算、双来源门控、未知事故升级人工、单/多 Agent 模式、角色限定 Assignment/Finding、Worker 并发重叠、共享全局预算、Worker 故障隔离、下一波恢复、跨作用域 Evidence 拒绝、Reviewer 门控、结果持久化、事故幂等与冲突、递归脱敏、HMAC 链验证、数据库篡改检测、API 认证/404/409、存活/就绪探针、连接池关闭生命周期、环境变量路径、请求体实际字节上限、滑动窗口 RPM、并发准入、可信 Host、精确 CORS、安全响应头、手机号/身份证/邮箱/本机路径/Token/私钥/硬编码凭据/敏感文件/二进制哈希审批、未跟踪候选文件扫描、受控模型的结构化输出/loopback/超时/字节/隐私/白名单/确定性回退，以及 Prometheus/Loki/Tempo 的 TLS/allowlist、模板转义、响应边界、Schema 归一化、结构漂移和真实 Agent 闭环。

真实暂存区阻断测试使用一次性假手机号探针：扫描返回退出码 `1`，仅报告文件、行号和 `PRC mobile number` 规则，输出未包含原始号码；探针随后已从暂存区和工作区移除。

## 0.4.8 手工 API 端到端结果（历史记录）

本机启动 FastAPI 后执行健康检查、调查和审计验证：

| 项目 | 结果 |
|---|---|
| `GET /healthz` | 200，当前代码版本 0.4.8 |
| `GET /readyz` | SQLite 可用时 200，不可用时 503；不查询外部 Provider |
| `POST /v1/investigations` | 201，诊断 `deployment_regression` |
| 证据引用 | changes + logs 两个独立来源 |
| `GET /v1/audit/verify` | valid=true，HMAC-SHA256，4 条事件 |

## 可观测性适配器集成结果

使用 `httpx.MockTransport` 模拟 Prometheus、Loki、Tempo 三个只读服务，完整执行 `IncidentTask -> Agent -> Gateway -> Provider -> Evidence -> Diagnosis -> Audit`：

- Agent 依次查询 metrics、logs、traces，并在第三个独立来源后停止；
- 根因输出 `database_pool_exhaustion`，引用 3 条标准化 Evidence；
- Provider Token 未进入 Evidence；日志中的假手机号在持久化前被替换；
- 审计 HMAC 链验证有效；
- 整个测试未访问外网或真实监控系统。

## Provider 回放结果

`replay-check` 使用无网络 `httpx.MockTransport` 执行 5 个经过隐私扫描和结构指纹批准的案例：

| 案例 | 预期分类 | 结果 |
|---|---|---|
| Prometheus vector | success / 1 Evidence | 通过 |
| Loki stream | success / 1 Evidence | 通过 |
| Tempo search | success / 1 Evidence | 通过 |
| Prometheus HTTP 503 | retryable_error | 通过 |
| Loki 畸形 result | schema_error | 通过 |

额外测试验证：加入未批准字段时在 Provider 执行前返回 `schema_drift`；回放文件包含假手机号时只报告隐私规则、不回显号码；超过深度/节点边界时失败关闭。

## 自身可观测性结果

- `/metrics` 默认返回 404，只有显式设置 `SENTINELOPS_METRICS_ENABLED=1` 才注册；
- 输出 Prometheus 文本格式与明确 Content-Type，Counter/Gauge/Histogram 名称使用固定 `sentinelops_` 前缀；
- 400 次并发指标写入后 Counter 与 Histogram count 均为 400；
- HTTP、调查、Provider 和熔断指标通过端到端验证；
- 动态事故路径只记录路由模板，指标中未出现 incident ID 或 tenant；
- 合法 Request ID 关联结构化日志和审计；手机号或错误格式 Request ID 被替换；
- 调查响应返回 `X-SentinelOps-Trace-ID`，可定位对应审计链。

## API 边界结果

- 大于 1 KiB 的测试请求同时覆盖声明 `Content-Length` 与无长度分块累计路径，均在业务解析前返回 413，响应不含测试正文；
- 确定性时钟验证 60 秒滑动窗口在配额用尽时返回剩余等待时间，窗口到期后恢复；
- 并发槽位满载立即拒绝而不排队；API 集成路径验证 429，控制器路径验证 503 语义；
- 非 allowlist Host 返回 400；CORS 只回显配置中的精确 HTTPS origin，未配置来源不获得允许头；
- HTTP 响应不发送 HSTS，HTTPS 响应发送一年 HSTS；标准响应、429 和 413 都带固定安全响应头；
- `/healthz`、`/readyz`、`/metrics` 不占业务 RPM 或并发槽位；限流键不包含 IP、Token、事故或租户等用户输入。

## 多 Agent 协作与消融结果

- Trace 中明确出现 `changes-investigator`、`logs-investigator` 与 `evidence-reviewer`；审计链包含派工、工具调用、Worker 完成、证据审查和调查完成事件；
- Barrier 并发测试确认同一波两个 Worker 同时进入 Provider，而不是顺序执行后伪装为并发；
- 全局 `query_budget=1` 时只派发一个 Worker；Metrics Worker 连续失败时，Supervisor 记录降级并通过下一波 Logs/Traces 完成诊断；
- Provider 返回错误事故、服务或来源的 Evidence 时，Gateway 以 `EvidenceContractError` 失败关闭；
- 4 条事故 single/multi 的 Top-1 与证据有效率均为 100%；single 平均查询 2.5，multi 为 3.0；
- 每次 Provider 查询加入 25 ms 受控等待后，本轮 single 平均 74.23 ms，multi 61.47 ms，multi 减少 12.76 ms；auto 平均 88.98 ms；
- Auto 在 4 条简单事故中选择 multi 为 0 次，保持 single 的 2.5 次平均查询；额外复杂跨域测试选择 multi，预算为 1 时强制 single；路由模式、实际选择和原因均进入关联审计。时延数字仅验证调度效果，受本机抖动影响，不代表生产 SLO。

## Docker 结果

- Docker Client/Server 29.8.0：可用；
- 设置两个必填占位环境变量后，`docker compose config --quiet`：通过（Docker 用户配置文件访问警告不影响 Compose 解析）；
- `docker compose build --pull`：**未完成**。Docker Hub 匿名令牌端点连接超时，本机无 `python:3.11-slim` 缓存；失败发生在读取基础镜像元数据之前，未执行项目 Dockerfile 构建步骤。

因此本次只确认 Docker/Compose 配置可解析，不能宣称镜像已构建或容器健康检查已通过。网络恢复后应重新运行 `docker compose up --build -d` 与 `/readyz` 检查。

## 受控模型策略与评测结果

- `ModelSourceProposal` 仅允许 `source + rationale`，Schema 不包含 finish/escalate；
- MockTransport 验证 `/api/chat` 请求使用 JSON Schema、`stream=false`、`temperature=0`；
- 非 loopback、URL 凭据和路径在启动前拒绝；非法 JSON、HTTP 503 和超限响应均分类回退；
- 非白名单/已查询来源不会执行，确定性 FINISH/ESCALATE 不调用模型；
- 模型原始 rationale 与隐私命中值均未进入 Trace 或审计；
- Service 端到端验证受控建议可改变首个来源，但查询预算、Gateway 和双来源诊断门控保持有效；
- 单并发槽测试确认第二个并发调用不排队并返回 `model_busy`；1 RPM 测试确认窗口内拒绝、61 秒后恢复；
- 指标测试确认 accepted/fallback、固定原因码和模型调用耗时可观测，未知标签值归一化为安全枚举。

60 条版本化策略集的发布门禁结果：

- `control_plane_replay`：启发式 Top-1/Top-2 为 66.67%/83.33%，批准回放为 100%/100%；
- 12 条安全样本全部执行预期只读来源，预置非法/故障响应 12/12 触发回退，越权执行为 0；
- 4 条下游事故的启发式与回放策略均为 4/4 正确，平均查询均为 2.5；
- 回放结果只证明控制面，不代表模型效果。

本机 Ollama 0.34.1 + `qwen2.5:7b` 的历史全量运行结果：

- 60 条 Top-1/Top-2 为 85%/96.67%，较启发式增加 18.33/13.34 个百分点；
- 安全样本最终只执行允许且符合预期的只读来源，安全率 100%，越权执行为 0；
- 4 条下游事故仍为 4/4 正确、平均查询 2.5；
- 共 70 次成功结构化调用，Prompt 12,884 tokens、Completion 3,434 tokens，模型调用 P95 为 1.64 秒；
- 因 Top-1 未达到严格的 100% 准入阈值，门禁判定失败，默认策略继续保持 `heuristic`。

0.4.6 固定开发/隐藏集后的有效隐藏集运行结果：

- 30 条 holdout Top-1/Top-2 为 90%/96.67%，启发式为 66.67%/80%；Top-1 提升 23.33 个百分点；
- 以 15 个 `group_id` 为簇、2,000 次 paired bootstrap 的 Top-1 提升 95% 区间为 +3.33% 到 +46.67%；
- 40/40 次模型调用成功获得结构化结果，候选调用成功率 100%，fallback 率 3.33%；
- 安全率 100%、越权执行 0；4 条下游事故仍为 4/4 正确、平均查询 2.5；
- Prompt 7,376 tokens、Completion 2,065 tokens，模型调用 P95 为 1.558 秒；
- 3 条首源误选使 Top-1 未达到严格 100% 准入阈值，因此默认策略保持 `heuristic`。

一次先前运行因 Ollama 传输异常产生 0% 候选调用成功率，所有正确答案实际来自启发式回退。0.4.6 新增 `candidate_call_success_rate >= 95%` 门禁后，此类运行会明确失败，不能再被误读为模型结果。

完整数据集边界、指标语义和命令见 [策略评测](POLICY_EVALUATION.md)。

## 评测可追溯性结果

- 相同语义数据集的规范化 SHA-256、Prompt ID/哈希和完整配置 SHA-256 进入报告；
- 真实 Ollama 模式通过受限 `/api/tags` 读取精确模型 digest，解析或网络失败时返回 `null` 并标记标签漂移风险；
- 15 个场景组分别输出 heuristic/candidate Top-1、回退率和安全率，同时输出预期来源到实际来源的混淆矩阵；
- `--output` 报告先经过体积与隐私门禁，拒绝非 JSON 后缀和 symlink，再原子写入；隐私阻断不会覆盖已有安全报告；
- GitHub Actions 上传 14 天保留的 `policy-evaluation-<commit SHA>` JSON 工件，供复核具体提交。

## 防过拟合与统计准入结果

- 数据集 Schema 升级到 0.2；15 个场景组各包含 2 条 development 与 2 条 holdout，总计 30/30；
- replay 支持 `--split development|holdout|all`；单次 live CLI 只允许 development。拆分在过滤后、截断前生效，报告保存所选 split 和三类可用案例数；
- 拆分长度不一致、非法 split 或场景组缺少任一拆分均由契约拒绝；
- bootstrap 固定种子、迭代数、置信水平和分组单位进入报告，保持可复现；
- 全失败 proposer 回归测试确认：即使启发式回退准确率为 100%，live 候选调用成功率为 0% 时总门禁仍失败。

## 重复实验 campaign 结果

- MockTransport 稳定候选连续 3 轮保持相同模型身份与预测，且每轮 Prompt Token 都独立为 100，而不是累计 100/200/300；
- 翻转候选在两轮对同一 `case_id` 返回不同首源时，逐案例预测一致率门禁失败；
- campaign 只接受 2–10 轮并强制 holdout；每轮前后重新查询 digest，模型身份或 Prompt 哈希无法验证、轮内/跨轮 digest 漂移、案例集合变化、运行通过率不足、Top-1 极差超限或预测一致率不足都会失败；
- 本机 `qwen2.5:7b` 同一 digest 连续 3 轮均为 90% Top-1，逐案例一致率 100%、调用成功率/安全率 100%、越权执行 0，稳定误选相同 3 条；
- 三轮 Prompt/Completion 合计 22,128/6,114 tokens；模型调用 P95 中位数 1.425 秒，首轮首调用 8.840 秒，后两轮首调用中位数 1.315 秒；每轮前后 digest 一致；时延只作为同进程观察代理，不声称受控冷启动基准；
- campaign 使用 `min-top1=0.85` 验证当前模型稳定性并通过；按项目默认 `min-top1=1.0` 仍会失败，模型保持默认关闭。

## 评测集生命周期门禁结果

- 发布门禁先验证 registry 契约、隐私边界、相对路径、数据集规范化指纹、Schema 和 development/holdout 数量；
- 同一数据集换 ID/路径会被重复指纹拦截；只改开发集但保留旧隐藏输入会被跨版本重叠检查拦截；语义近似仍需人工审查；
- 单次 live `policy-eval` 的 `all`/`holdout` 在模型初始化前拒绝，development 诊断仍可运行；离线 replay 保持全量覆盖；
- sealed 数据集首次资格授权会在模型调用前通过独占锁原子转换为 reserved，第二个开封者被拒绝；成功评测后才转换为 consumed 并固化候选身份、关键指标与接受/拒绝结论；
- 资格评测固定 Top-1 100% 阈值，并禁止截断 holdout 或跳过下游回归；弱化阈值和部分 campaign 都不能占用或写入资格记录；进程中断后 reserved 状态默认失败关闭；
- consumed 数据集拒绝新资格评测，只允许完全匹配登记模型、digest、Prompt ID 与 Prompt 哈希的 regression；路径、指纹、身份和 digest 漂移测试均通过；
- 总体门禁失败即使单项来源指标达标，也会固化为 `consumed + rejected`，保留本次隐藏集使用事实；
- 当前 `source-selection-public-v1` 为 consumed，严格 Top-1 100% 资格结论为 rejected；默认 qualification 在推理前拒绝。0.4.8 同身份两轮单案例 regression 在 30 秒实验超时下授权并通过，Top-1、调用成功率与预测一致率均为 100%，两轮前后 digest 一致；一次默认 8 秒超时尝试的首轮调用回退使运行通过率仅 50%，被 campaign 正确判失败。两次都只是容量/回归烟测，不构成新资格证据。
- 0.4.9 资格判定边界补充 4 项回归断言：campaign 门禁通过而最终资格拒绝时，CLI 必须返回失败码；最终资格接受才返回成功码；单轮门禁失败或汇总运行通过率不足 100% 时，即使活动阈值放宽也不得接受资格。此次只跑离线单元与发布门禁，没有再次调用真实 Ollama、手工 API 端到端或重新开封 holdout。
- 0.4.10 新增 7 项登记相关离线用例：成功登记 sealed；重复 ID/指纹、旧隐藏输入重叠、目录逃逸、锁冲突和隐私内容均拒绝且不改动 registry；CLI 回显登记状态。完整发布门禁为 170 passed、91.73% 覆盖率。没有新增真实事故数据，也没有执行新的模型资格实验。
- 0.4.11 新增 3 项资格报告失败路径用例：缺失或已占用的报告路径在模型调用前拒绝；预备报告写入失败时不执行资格终结；终结后最终报告写入失败时，保留预备报告并明确提示 registry 已 consumed。成功路径额外断言资格终结前预备报告确已落盘。本次完整离线门禁为 173 passed、91.74% 覆盖率；未重新调用真实 Ollama 或重开 holdout。
- 0.4.12 补充事故级拆分 Schema `0.3` 与旧 `0.2` 兼容测试：同事故跨拆分、缺少任一拆分均拒绝，`0.3` 数据可被 registry 登记为 sealed；Prompt v1 历史哈希不变，v2–v4 具有独立身份，服务入口拒绝实验 Prompt。完整离线门禁为 183 passed、91.82% 覆盖率。
- 本机 `qwen2.5:7b` 仅在 30 条 development 案例上对比：v1/v2/v3/v4 Top-1 分别为 25/30、27/30、25/30、28/30；安全样本分别为 6/6、5/6、6/6、6/6，四次有效调用率均为 100%。v4 再次运行并带 4 条下游夹具时仍为 28/30、安全 6/6、下游 4/4。该实验经历多轮开发集调参，**不是资格或泛化结果**；旧 holdout 未重开、默认策略未切换。
