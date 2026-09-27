# SentinelOps 0.4.1 测试结果

- 日期：2026-09-27
- Python：3.11.9
- 平台：Windows 10

## 发布门禁结果

命令：

```powershell
.\.venv\Scripts\python.exe scripts\release_check.py
```

| 检查 | 结果 |
|---|---|
| `compileall` 源码、测试与脚本 | 通过 |
| 工作树候选文件隐私扫描（含未跟踪、未忽略文件） | 通过 |
| 危险运行时调用与已知密钥格式扫描 | 通过 |
| pytest | 80 passed |
| `sentinelops` 行覆盖率 | 91.51%（门槛 80%） |
| Provider 回放门禁 | 5/5 通过，Schema 漂移 0 |
| 离线基线 | 4/4 Top-1 正确 |
| 证据引用有效性 | 100% |
| 基线平均查询数 | 4.0 |

覆盖的关键场景包括：严格契约、只读/白名单拒绝、瞬时错误重试、非瞬时错误审计、按来源熔断、冷却恢复与并发单探针、查询与重复动作预算、双来源门控、未知事故升级人工、单/多 Agent 模式、角色限定 Assignment/Finding、Worker 并发重叠、共享全局预算、Worker 故障隔离、下一波恢复、跨作用域 Evidence 拒绝、Reviewer 门控、结果持久化、事故幂等与冲突、递归脱敏、HMAC 链验证、数据库篡改检测、API 认证/404/409、存活/就绪探针、连接池关闭生命周期、环境变量路径、请求体实际字节上限、滑动窗口 RPM、并发准入、可信 Host、精确 CORS、安全响应头、手机号/身份证/邮箱/本机路径/Token/私钥/硬编码凭据/敏感文件/二进制哈希审批、未跟踪候选文件扫描，以及 Prometheus/Loki/Tempo 的 TLS/allowlist、模板转义、响应边界、Schema 归一化、结构漂移和真实 Agent 闭环。

真实暂存区阻断测试使用一次性假手机号探针：扫描返回退出码 `1`，仅报告文件、行号和 `PRC mobile number` 规则，输出未包含原始号码；探针随后已从暂存区和工作区移除。

## API 端到端结果

本机启动 FastAPI 后执行健康检查、调查和审计验证：

| 项目 | 结果 |
|---|---|
| `GET /healthz` | 200，当前代码版本 0.4.1 |
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
- 每次 Provider 查询加入 25 ms 受控等待后，本轮 single 平均 72.77 ms，multi 60.34 ms，multi 减少 12.43 ms；auto 平均 78.34 ms；
- Auto 在 4 条简单事故中选择 multi 为 0 次，保持 single 的 2.5 次平均查询；额外复杂跨域测试选择 multi，预算为 1 时强制 single；路由模式、实际选择和原因均进入关联审计。时延数字仅验证调度效果，受本机抖动影响，不代表生产 SLO。

## Docker 结果

- Docker Client/Server 29.8.0：可用；
- 设置两个必填占位环境变量后，`docker compose config --quiet`：通过（Docker 用户配置文件访问警告不影响 Compose 解析）；
- `docker compose build --pull`：**未完成**。Docker Hub 匿名令牌端点连接超时，本机无 `python:3.11-slim` 缓存；失败发生在读取基础镜像元数据之前，未执行项目 Dockerfile 构建步骤。

因此本次只确认 Docker/Compose 配置可解析，不能宣称镜像已构建或容器健康检查已通过。网络恢复后应重新运行 `docker compose up --build -d` 与 `/readyz` 检查。
