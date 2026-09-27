# SentinelOps 0.3.0

SentinelOps 是一个证据优先、默认只读的事故调查 Agent。它围绕真实生产约束设计：Agent 只能查询指标、日志、链路和变更记录；每次调查受步骤、查询次数和截止时间限制；结论必须引用证据；证据不足时升级人工，而不是编造根因。

当前版本是**可复现的单 Agent 主体闭环**，不是生产事故平台，也没有连接真实监控系统。Fixture 适配器用于离线评测，未来接入 Prometheus、Loki、Tempo 等系统时不改变领域契约。

## 0.3.0 已完成能力

- **调查编排**：`观察 -> 选择只读数据源 -> 查询 -> 更新证据 -> 诊断/升级人工`；
- **有界执行**：限制最大步骤、查询次数、截止时间和重复动作；
- **证据门控**：根因至少由两个独立数据源支持，否则返回 `needs_human`；
- **工具网关**：只读校验、数据源白名单、结果数量限制、瞬时错误重试、统一错误审计；
- **幂等边界**：相同事故和相同载荷复用结果，相同事故 ID 的不同载荷返回冲突；
- **状态持久化**：调查结果与审计事件写入 SQLite；
- **审计链**：字段递归脱敏、事件前向哈希链、可选 HMAC-SHA256 完整性校验；
- **服务接口**：FastAPI、Bearer Token 可选认证、OpenAPI、健康检查；
- **可复现交付**：非 root Docker 镜像、只读容器文件系统、最小 Linux capability；
- **质量门禁**：离线基线、单元/集成测试、覆盖率下限、敏感信息与危险调用扫描。
- **隐私防上传**：提交前扫描暂存内容，推送前扫描新增提交，CI 再扫描全部跟踪文件；命中时只显示文件、行号和规则，不回显隐私值。
- **真实只读适配器**：Prometheus 指标、Loki 日志、Tempo 链路统一归一化为 `Evidence`；HTTPS、主机 allowlist、禁止重定向、超时和响应体上限默认启用。

## 架构速览

```text
CLI / FastAPI
     |
SentinelOpsService ── 幂等与冲突边界
     |
BoundedInvestigationAgent ── 步数 / 查询 / 时间预算
     |                 |
InvestigationPolicy   EvidenceGateway ── 只读 / 白名单 / 重试 / 审计
                           |
                    EvidenceTool port
                           |
                    Fixture adapter（当前）

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
```

启动后可访问：

- 健康检查：`http://127.0.0.1:8000/healthz`
- Swagger：`http://127.0.0.1:8000/docs`
- OpenAPI：`http://127.0.0.1:8000/openapi.json`

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
Invoke-RestMethod http://127.0.0.1:8000/healthz
docker compose down
```

Compose 只把服务绑定到 `127.0.0.1`。如果要对外提供服务，必须在可信反向代理后补 TLS、身份系统、租户级 RBAC、限流和集中审计。

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

适配器当前假设标签名为 `service`，Tempo 使用 `service.name`；不同组织应通过后续模板配置层适配自己的 schema。Changes 尚无跨平台标准 API，因此真实模式不会伪造该来源，缺失来源会被审计为降级。详细说明见 [可观测性适配器](docs/OBSERVABILITY_ADAPTERS.md)。

## 测试与发布门禁

```powershell
.\.venv\Scripts\python.exe scripts\release_check.py
```

门禁会执行编译检查、全量 pytest、80% 覆盖率门槛和 4 个标注事故的确定性基线。最近一次实测记录见 [测试结果](docs/TEST_RESULTS.md)。

## 隐私内容自动阻断

首次克隆后使用项目虚拟环境安装版本化 Git Hook，并使用 GitHub noreply 邮箱保存后续提交。安装脚本同时把 Hook 解释器固定到当前虚拟环境，避免误用系统 Python：

```powershell
.\.venv\Scripts\python.exe scripts\install_git_hooks.py
git config --local user.email "lin-or-feng@users.noreply.github.com"
```

三层门禁：

1. `pre-commit` 扫描暂存区并检查 Git 作者邮箱；
2. `pre-push` 只扫描即将新增到远端的提交及其作者/提交者邮箱；
3. GitHub Actions 扫描全部跟踪文件，防止 Hook 未安装或被绕过。

默认拦截手机号、身份证号、非示例邮箱、本机用户目录、常见云/API Token、私钥、硬编码凭据、`.env`、数据库和密钥文件。二进制无法可靠文本扫描，因此默认拒绝；人工核验后只能把该文件的**精确 SHA-256**加入 `.privacy-allowlist`，文件一旦变化必须重新审核。

手动检查：

```powershell
.\.venv\Scripts\python.exe scripts\privacy_guard.py --tracked
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
5. **0.3.1 故障回放**：录制脱敏后的 provider 响应，建立真实事故离线回归与 schema 漂移检测。
6. **0.4 受控模型策略**：LLM 只生成结构化 `InvestigationAction`，策略失败回退规则策略，并与基线做消融。
7. **1.0 多租户服务**：PostgreSQL、OIDC/RBAC、异步任务、OpenTelemetry、SLO、备份恢复和人工审批。

只有当单 Agent 在固定评测集上无法达到召回或时延目标，且多 Agent 消融证明收益高于成本，才引入并行调查者。

## License

尚未选择开源许可证。在许可证确定前，不默认授予复制、修改或商用权利。
