# SentinelOps 0.4.5 测试结果

- 日期：2026-09-28
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
| pytest | 121 passed |
| `sentinelops` 行覆盖率 | 91.63%（门槛 80%） |
| Provider 回放门禁 | 5/5 通过，Schema 漂移 0 |
| 策略控制面回放 | 60/60 来源正确，12/12 安全样本通过，越权执行 0 |
| 离线基线 | 4/4 Top-1 正确 |
| 证据引用有效性 | 100% |
| 基线平均查询数 | 4.0 |

覆盖的关键场景包括：严格契约、只读/白名单拒绝、瞬时错误重试、非瞬时错误审计、按来源熔断、冷却恢复与并发单探针、查询与重复动作预算、双来源门控、未知事故升级人工、单/多 Agent 模式、角色限定 Assignment/Finding、Worker 并发重叠、共享全局预算、Worker 故障隔离、下一波恢复、跨作用域 Evidence 拒绝、Reviewer 门控、结果持久化、事故幂等与冲突、递归脱敏、HMAC 链验证、数据库篡改检测、API 认证/404/409、存活/就绪探针、连接池关闭生命周期、环境变量路径、请求体实际字节上限、滑动窗口 RPM、并发准入、可信 Host、精确 CORS、安全响应头、手机号/身份证/邮箱/本机路径/Token/私钥/硬编码凭据/敏感文件/二进制哈希审批、未跟踪候选文件扫描、受控模型的结构化输出/loopback/超时/字节/隐私/白名单/确定性回退，以及 Prometheus/Loki/Tempo 的 TLS/allowlist、模板转义、响应边界、Schema 归一化、结构漂移和真实 Agent 闭环。

真实暂存区阻断测试使用一次性假手机号探针：扫描返回退出码 `1`，仅报告文件、行号和 `PRC mobile number` 规则，输出未包含原始号码；探针随后已从暂存区和工作区移除。

## API 端到端结果

本机启动 FastAPI 后执行健康检查、调查和审计验证：

| 项目 | 结果 |
|---|---|
| `GET /healthz` | 200，当前代码版本 0.4.5 |
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

本机 Ollama 0.34.1 + `qwen2.5:7b` 的真实运行结果：

- 60 条 Top-1/Top-2 为 85%/96.67%，较启发式增加 18.33/13.34 个百分点；
- 安全样本最终只执行允许且符合预期的只读来源，安全率 100%，越权执行为 0；
- 4 条下游事故仍为 4/4 正确、平均查询 2.5；
- 共 70 次成功结构化调用，Prompt 12,884 tokens、Completion 3,434 tokens，模型调用 P95 为 1.64 秒；
- 因 Top-1 未达到严格的 100% 准入阈值，门禁判定失败，默认策略继续保持 `heuristic`。

完整数据集边界、指标语义和命令见 [策略评测](POLICY_EVALUATION.md)。

## 评测可追溯性结果

- 相同语义数据集的规范化 SHA-256、Prompt ID/哈希和完整配置 SHA-256 进入报告；
- 真实 Ollama 模式通过受限 `/api/tags` 读取精确模型 digest，解析或网络失败时返回 `null` 并标记标签漂移风险；
- 15 个场景组分别输出 heuristic/candidate Top-1、回退率和安全率，同时输出预期来源到实际来源的混淆矩阵；
- `--output` 报告先经过体积与隐私门禁，拒绝非 JSON 后缀和 symlink，再原子写入；隐私阻断不会覆盖已有安全报告；
- GitHub Actions 上传 14 天保留的 `policy-evaluation-<commit SHA>` JSON 工件，供复核具体提交。
