# SentinelOps 1.0 前发布资格验收

状态：**工作区实现中，未发布，版本仍为 0.11.0**。1.0 仅在限定部署范围内具备真实上线资格、全部门槛验收后命名；当前 pilot 配置只是本机/内网验证辅助，不等于上线批准。目标是单组织、单实例、只读事故调查；AI 仅辅助解释，任何处置由人决定。合成演示与真实接入严格分离，不把 4 条夹具的正确率写成真实事故效果。

## 1. 真实接入闭环

已实现：正式 API `/v1/investigations` 原本可接收任意 `IncidentTask`；本轮增加 `investigate --task-file`，直接使用 `observability` 适配器，绝不回退到夹具。新增 `provider-check --task-file`，对配置的每个来源发起一次时间窗受限、`limit=1` 的**实际只读查询**，仅报告状态、异常类型和证据条数，不打印证据正文。任务文件须为小于 64 KiB 的普通 JSON，过隐私扫描与严格契约。此检查不会验证证据相关性，也不持久化审计；正式调查才产生审计。

示例任务（仅示意，实际事故应使用新的 `incident_id`、真实时点和已审批的服务标识）：

```json
{
  "incident_id": "inc-pilot-001",
  "tenant_id": "pilot",
  "service": "order-service",
  "started_at": "2026-09-29T09:00:00Z",
  "symptoms": ["HTTP 5xx rate increased"],
  "deadline_seconds": 30,
  "query_budget": 8
}
```

只在受控终端设置 `SENTINELOPS_ALLOWED_OBSERVABILITY_HOSTS`、Provider HTTPS URL 和只读 Token 等环境变量，勿把凭据写入任务文件或仓库。配置见 README 的 Prometheus/Loki/Tempo 段。将任务存入仓库外的受控目录后执行：

```powershell
Set-Location D:\agents
.\.venv\Scripts\python.exe -m sentinelops provider-check --task-file D:\pilot-data\incident.json
.\.venv\Scripts\python.exe -m sentinelops investigate --task-file D:\pilot-data\incident.json --db D:\pilot-data\sentinelops.db --orchestration-mode auto
.\.venv\Scripts\python.exe -m sentinelops audit-verify --db D:\pilot-data\sentinelops.db
```

若使用现有 FastAPI `/docs` 作为可视化请求入口，先显式设置 `SENTINELOPS_EVIDENCE_MODE=observability`，只在本机/可信内网启动并配置 API Token。`8765` 演示页仍只使用合成夹具，不能用于真实事故。**待验收**：使用获批的真实只读凭据和至少一条非夹具事故，从连接检查、调查、证据引用、人工升级/结论到审计校验全程通过；当前未获得该环境，故不能宣称已完成真实联调。

未发布工作区另有独立的 `8767` [本机真实调查台](OPERATOR_DESK.md)：复用真实 observability 工具，启动前过 pilot 静态门禁；页面按同一任务执行来源检查、显式确认、调查和审计展示，不回退到 `8765` 夹具。离线测试使用假 Provider 验证闭环，**不等于**真实联调或已获授权使用真实事故。

## 2. 独立样本与效果验收

现有 `incident-intake-check` 仅做机器预检；公开候选当前仍被阻断。开发者不能替代来源授权人或独立标注人签字，也不能根据事后复盘伪造事故时点证据。请由有权限的人员在仓库外准备：

1. 每起事故独立 ID、来源/使用许可、决策时刻和当时可见的只读证据；原始日志先最小化与脱敏。
2. 与开发者分离的标注人与复核人，记录争议和分类外案例；同一连锁事故不可跨 development/holdout。
3. 冻结模型 digest、Prompt、规则和代码版本后再开封 holdout。现有策略资格门禁要求至少 20 条 holdout；它只验证“首查来源策略”，**不能代替全链路根因准确率**。
4. 全链路验收单独统计正确根因、误诊、人工升级、引用有效性、Provider 失败与 P95；逐例复核后才能写发布声明。

**当前阻断**：尚无获批、独立标注的事故输入与标签。因此本轮不生成真实效果数字，不消费新的 holdout，不调整模型权力。

## 3. 故障与恢复

已实现：`backup-drill` 使用 SQLite 在线备份 API 取一致性快照，检查 SQLite 完整性和 HMAC 审计链，再恢复到隔离临时库逐表核对；目标存在则拒绝覆盖，失败不留下目标备份。备份可能包含事故信息，应存入受控目录，按组织要求加密、限制访问并制定保留期。

```powershell
.\.venv\Scripts\python.exe -m sentinelops backup-drill --db D:\pilot-data\sentinelops.db --output D:\pilot-backups\sentinelops-20260929.db
```

新增故障测试验证 Provider 超时转 `needs_human`、不泄露上游错误正文；多 Agent 截止后不采纳迟到证据，待同步读取线程收尾再写完成审计；以及备份恢复、密钥错误、审计篡改和覆盖拒绝。**限制**：Python 同步 HTTP/线程不能被 `Future.cancel()` 强行中断，当前是软截止；真实 Provider 每次请求有超时，但总耗时可超过任务 deadline。正式发布前还需在隔离真实环境验证最坏延迟、进程中断后人工核查、备份文件权限/恢复步骤与 SLO，不得宣称硬取消或高可用。

## 4. 安全部署

已实现：`deployment-check` 对显式 pilot 配置做**离线**预检：不同的足长 API Token/HMAC Key、至少两个配置完整的 HTTPS 只读来源、仅本机可信 Host、禁 CORS/不安全 HTTP、确定性策略与影子关闭。`SENTINELOPS_DEPLOYMENT_PROFILE=pilot` 时，API 在创建数据库和 Provider 前检查，不合格则拒绝启动。此检查不触网，也无法证明凭据确实只读、密钥随机性、证书链、反向代理 TLS、防火墙或外部身份系统。

```powershell
.\.venv\Scripts\python.exe -m sentinelops deployment-check
```

**上线前未完成**：在目标环境验证凭据最小权限与轮换、TLS/身份接入、网络隔离、备份权限与保留期、真实多进程/跨实例边界，以及变更后安全回归。当前 Compose 仍只绑定 `127.0.0.1`，不能直接作为公网或多租户部署方案。

## 5. 可复现发布物

已实现：独立 `package_check.py` 从源码构建 wheel、安装至临时目录并验证模块与演示资源；新增仅手动触发的发布准备 CI，运行质量门禁、wheel 检查、容器构建与无网络 CLI 冒烟测试，但**不会发布包、镜像或 GitHub Release**。本地 wheel 检查通过；`docker compose --env-file .env.example config --quiet` 通过。当前本机 Docker Linux 引擎未运行，因此容器构建与启动尚未本机实测；CI 工作流也未提交触发。

**上线前未完成**：指定并核对 LICENSE、锁定依赖与镜像基线、干净机器容器运行测试、升级/回退演练、漏洞/SBOM 审查、变更记录和明确的发布标签。许可证尚待项目所有者选择；版本号、Git 标签、远端仓库与发布渠道均保持不变。

## 发布判定

只有 1 的真实联调、2 的独立验收数据与逐例结果、3 的隔离恢复与故障演练，以及 4/5 的目标环境安全和可复现发布证据均齐全，才讨论 1.0。任何单项代码检查通过都不是上线批准。多租户、自动修复和 AI 最终裁决不在当前只读目标范围。
