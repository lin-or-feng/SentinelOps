# SentinelOps 0.2

SentinelOps 是一个证据优先、默认只读的事故调查 Agent。它围绕真实生产约束设计：Agent 只能查询指标、日志、链路和变更记录；每次调查受步骤、查询次数和截止时间限制；结论必须引用证据；证据不足时升级人工，而不是编造根因。

当前版本是**可复现的单 Agent 主体闭环**，不是生产事故平台，也没有连接真实监控系统。Fixture 适配器用于离线评测，未来接入 Prometheus、Loki、Tempo 等系统时不改变领域契约。

## 0.2 已完成能力

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

## 测试与发布门禁

```powershell
.\.venv\Scripts\python.exe scripts\release_check.py
```

门禁会执行编译检查、全量 pytest、80% 覆盖率门槛和 4 个标注事故的确定性基线。最近一次实测记录见 [测试结果](docs/TEST_RESULTS.md)。

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
3. **0.3 真实只读适配器**：Prometheus/Loki/Tempo，契约测试、故障注入和离线回放。
4. **0.4 受控模型策略**：LLM 只生成结构化 `InvestigationAction`，策略失败回退确定性规则，并与基线做消融。
5. **1.0 多租户服务**：PostgreSQL、OIDC/RBAC、异步任务、OpenTelemetry、SLO、备份恢复和人工审批。

只有当单 Agent 在固定评测集上无法达到召回或时延目标，且多 Agent 消融证明收益高于成本，才引入并行调查者。

## License

尚未选择开源许可证。在许可证确定前，不默认授予复制、修改或商用权利。
