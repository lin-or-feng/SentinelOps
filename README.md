# SentinelOps 0.4.4

SentinelOps 是一个证据优先、默认只读的事故调查 Agent。它围绕真实生产约束设计：Agent 只能查询指标、日志、链路和变更记录；每次调查受步骤、查询次数和截止时间限制；结论必须引用证据；证据不足时升级人工，而不是编造根因。

当前版本提供**可复现的单 Agent 基线 + 可选有界多 Agent 协作 + 成本感知自动路由 + 受控本地模型策略**，不是生产事故平台。默认使用 Fixture 与确定性策略做离线评测，不访问外部系统；显式启用 observability 模式后，可通过同一领域契约连接 Prometheus、Loki、Tempo 的只读 API。

## 0.4.4 已完成能力

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
Set-Location D:\agents
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
  --min-top1 1 --min-safety 1 --max-forbidden-rate 0

# 本机真实模型：结果只对当前模型、Prompt、数据集和硬件负责
$env:SENTINELOPS_OLLAMA_MODEL = "qwen2.5:7b"
$env:SENTINELOPS_OLLAMA_TIMEOUT_SECONDS = "30"
$env:SENTINELOPS_OLLAMA_MAX_INFLIGHT = "1"
$env:SENTINELOPS_OLLAMA_RATE_LIMIT_RPM = "100"
.\.venv\Scripts\python.exe -m sentinelops policy-eval --mode ollama `
  --min-top1 1 --min-safety 1 --max-forbidden-rate 0
```

本机 `qwen2.5:7b` 的 60 条实测 Top-1 为 85%，高于启发式 66.67%，但没有达到 100% 准入阈值，因此 `ollama` 仍保持实验开关、默认禁用。数据集、指标解释和复现实录见 [策略评测](docs/POLICY_EVALUATION.md)。

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
- 当前保证范围是**单进程写入**，Docker 固定 `--workers 1`。多副本部署需迁移 PostgreSQL，并用事务锁或独立审计写入器串行化；
- 审计事件与调查结果同库但非同一原子事务；生产版需 outbox/事务事件方案。

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
14. **1.0 多租户服务**：PostgreSQL、OIDC/RBAC、异步任务、OpenTelemetry、SLO 执行、备份恢复和人工审批。

多 Agent 当前作为可选模式保留：只有当真实 Provider 压测证明时延收益高于额外查询成本，才应在部署中改为默认。模型策略同样必须通过固定评测和回退测试后才能进入默认路径。

## License

尚未选择开源许可证。在许可证确定前，不默认授予复制、修改或商用权利。
