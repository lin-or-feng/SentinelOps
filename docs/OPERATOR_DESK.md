# 本机真实调查台（未发布 Pilot）

这是一个与 `8765` 合成验证台**分离**的入口，只在本机 `127.0.0.1:8767` 提供页面。它直接使用已配置的 Prometheus/Loki/Tempo 只读适配器，不读取合成夹具、不调用 AI，也不执行修复动作。当前仍是单实例预览，不是公网或多租户上线方案。

## 启动前

1. 获得监控系统所有者授权的只读凭据，确认事故/日志可用于调试且已按组织要求最小化脱敏。没有真实来源时不要用测试 URL 或夹具伪装真实验收。
2. 在受控终端设置 `.env.example` 中的 `SENTINELOPS_API_TOKEN`、独立的 `SENTINELOPS_AUDIT_KEY`、至少两个 HTTPS Provider URL/Token、`SENTINELOPS_ALLOWED_OBSERVABILITY_HOSTS`，以及 `SENTINELOPS_EVIDENCE_MODE=observability`。保持 `SENTINELOPS_POLICY_MODE=heuristic`、`SENTINELOPS_SPECIALIST_SHADOW=off`、可信 Host 仅本机、CORS 为空。不要把真实值放入仓库、任务文件或命令行参数。
3. 使用**仓库外**已受控的绝对 SQLite 路径，例如 `D:\pilot-data\sentinelops.db`。源码启动入口会拒绝仓库内路径；备份、权限与保留期由操作者负责。不要将此数据库与合成验证台共用。

在 `D:\agents` 下先运行：

```powershell
.\.venv\Scripts\python.exe -m sentinelops deployment-check
.\.venv\Scripts\python.exe -m sentinelops.operator_web --db D:\pilot-data\sentinelops.db
```

只有静态预检通过才启动；预检不访问网络、不证明只读权限或 TLS 终止。浏览器打开 `http://127.0.0.1:8767/`，输入本机 API Token 后，按“检查只读来源 → 人工确认 → 开始真实只读调查”操作。Token 不保存在浏览器存储；刷新需重新输入。页面只显示来源状态、最终结论、证据 ID、Trace 与审计事件，不持久化或回显证据正文；应在原监控系统核对引用。来源检查虽可读取，仍不等于证据相关或根因正确。

刷新页面后可以输入事故 ID，点击“按事故 ID 找回已保存结果”。此操作只读取本机 SQLite 并校验审计链，不再次查询 Provider。如果没有完成结果，页面会再做一次只读运行状态查询，区分 `not_found`、`running`、`abandoned` 和 `completed`，并显示是否已保存结果。`running` 可能是仍在执行，也可能是进程中断后遗留；`not_found` 只表示**当前数据库**没有预留，不能证明其他数据库或旧进程从未查询来源。任何预留状态都不能据此直接删除或重用事故 ID，必须结合进程、审计和原监控系统人工核查。审计链失效时状态接口也拒绝返回状态。

## 失败时怎么查

| 页面状态 | 含义与下一步 |
|---|---|
| `pilot preflight failed` | 按返回的固定阻断码检查环境变量；不要降低门槛来使启动通过。 |
| `invalid_bearer_token` | 检查本机 Token；页面不会回显或保存 Token。 |
| `authorization_denied` | Provider 拒绝只读凭据（如 401/403）；先核对授权范围，不要改用高权限 Token。 |
| `rate_limited` / `timeout` | 来源限流或超时；稍后按组织规则重试，并核对时间窗、服务负载及查询配额。 |
| `invalid_response` / `response_too_large` | 来源返回非预期结构、状态或过大响应；检查适配器 Schema 与上游版本，不直接放宽字节限制。 |
| `network_or_server_error` / `unexpected_provider_error` | 核对网络、TLS、来源健康状态和服务端记录的异常类别；页面不展示上游错误正文。 |
| `matching_provider_check_required` | 任务已修改、检查已超过 5 分钟或预检已消费；重新检查完全相同的任务。 |
| `incident_id_conflict_or_reserved` | 事故 ID 已关联其他任务或未完成预留；先人工检查数据库/审计，不要直接删除或重用 ID。 |
| `investigation_failed_review_server_logs` | 可能已有部分只读查询和运行预留；查看服务端固定错误类别、运行状态与审计，再决定是否新建事故。不要盲目重复。 |
| `audit_chain_invalid` | 结果可能已经落盘，但审计完整性检查未通过；页面拒绝返回结论。先停止使用并隔离核查数据库和备份。 |
| `completed_investigation_not_found` | 没有已落盘的完成结果；页面随后查询本机运行状态，不等于 Provider 没有被查询过。 |
| `running` / `abandoned` | 前者可能仍在执行或已中断；后者表示运行失败但保留预留。都禁止直接重复提交相同事故 ID。 |
| `completed` 但无结果 | 运行账本与结果存储不一致；停止使用该结论并核查数据库、审计及备份。 |

执行后可另开受控终端做独立复核：

```powershell
.\.venv\Scripts\python.exe -m sentinelops audit-verify --db D:\pilot-data\sentinelops.db
.\.venv\Scripts\python.exe -m sentinelops backup-drill --db D:\pilot-data\sentinelops.db --output D:\pilot-backups\sentinelops-drill.db
```

`backup-drill` 输出可能包含事故信息，不能上传仓库。旧路径已存在时会拒绝覆盖，演练前请选新的受控路径。

## 尚未完成的验收

本地操作台只补齐“有授权时可手动跑通”的交互入口。仍需获批真实事故、独立标注和目标环境测试；当前 Provider 的截止时间为软截止，页面等待可能超过任务 deadline。容器、TLS、凭据轮换、恢复时长及生产 SLO 均未因这个页面而自动得到验证。详见[1.0 前发布资格验收](RELEASE_READINESS.md)。
