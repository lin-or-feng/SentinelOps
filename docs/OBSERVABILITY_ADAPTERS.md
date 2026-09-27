# Prometheus、Loki、Tempo 只读适配器

## 1. 目标

0.3 系列把 `EvidenceTool` 从 Fixture 扩展到真实可观测性后端，同时保持领域层和 Agent 不依赖具体产品。默认仍是 Fixture；只有设置 `SENTINELOPS_EVIDENCE_MODE=observability` 才创建 HTTP Provider。

采用的官方只读 API：

- Prometheus `GET /api/v1/query`：[HTTP API](https://prometheus.io/docs/prometheus/latest/querying/api/)
- Loki `GET /loki/api/v1/query_range`：[Loki HTTP API](https://grafana.com/docs/loki/latest/reference/loki-http-api/)
- Tempo `GET /api/search`：[Tempo HTTP API](https://grafana.com/docs/tempo/latest/api_docs/)

## 2. 数据流

```text
IncidentTask
  -> Agent 生成结构化 QuerySpec
  -> QuerySpec 时间窗校验（必须带时区，<= 1h）
  -> EvidenceGateway 来源 allowlist / 重试 / 按来源熔断 / 审计
  -> Provider 固定查询模板 + service 转义
  -> HTTPS GET（禁止重定向）
  -> 状态码 / Content-Length / 实际字节上限 / JSON schema 检查
  -> 最小字段提取 + 隐私脱敏
  -> 标准 Evidence
```

调用方不能提交原始 PromQL、LogQL 或 TraceQL。`keywords` 只用于 Agent 决策，Provider 不把它拼接到查询语言中，从边界上减少查询注入和高成本任意查询。

## 3. Provider 契约

| 来源 | 固定入口 | 时间参数 | 提取内容 |
|---|---|---|---|
| Metrics | Prometheus `/api/v1/query` | `time` | metric name、最新值、时间戳 |
| Logs | Loki `/loki/api/v1/query_range` | 纳秒 `start/end` | 限量错误日志、level/job/service |
| Traces | Tempo `/api/search` | 秒 `start/end` | trace id、根 span 名、duration |

所有返回都绑定原事故 ID、服务、来源、观测时间和可追踪 `raw_ref`。Evidence ID 使用稳定 SHA-256 摘要生成，避免把原始日志内容或 Token 放进标识符。

## 4. 安全边界

- URL 必须是绝对 HTTP(S)，默认只允许 HTTPS；
- hostname 必须精确命中 `SENTINELOPS_ALLOWED_OBSERVABILITY_HOSTS`；
- base URL 禁止内嵌用户名、密码、query 或 fragment；
- 只使用常量 GET 路径，禁止跨主机重定向；
- 默认 5 秒超时、1 MB 响应上限，硬上限分别为 30 秒和 5 MB；
- 408、429、5xx 映射为可重试连接错误，4xx/schema 错误不重试；
- 连续终态失败触发按来源隔离的熔断，冷却后只放行一个半开探针；
- Bearer Token 使用 `SecretStr`，不进入 Evidence、审计 details 或异常文本；
- 日志、trace name 与保留标签在持久化前执行手机号、身份证、邮箱、Token、私钥等脱敏；
- Provider 只能声明一个 EvidenceSource，重复来源配置直接失败。
- FastAPI lifespan 关闭适配器自有连接池；调用方注入的 `httpx.Client` 所有权仍归调用方。

精确主机 allowlist 可防止 Agent 选择任意 URL，但不能单独解决 DNS rebinding、宿主代理或已失陷 DNS。生产部署仍需 egress firewall、内部 DNS 策略、只读服务账户和网络级身份验证。

## 5. 有意限制

- 默认 Prometheus/Loki 服务标签使用 `service`，不同 schema 尚未配置化；
- Tempo 使用 `service.name` tag search；
- Changes 没有通用标准 Provider，不在 0.3 系列伪造；
- 适配器当前同步执行，适合有界单请求；高并发版需要持久化任务、连接池容量和租户背压；
- 尚未录制真实响应回放集，当前契约测试使用 `httpx.MockTransport`；
- 脱敏是最小披露防线，不替代上游日志治理或企业 DLP。

## 6. 验证范围

契约测试覆盖 TLS/allowlist、URL 凭据拒绝、模板转义、认证头、时间窗、响应归一化、日志隐私脱敏、重定向拒绝、响应体超限、未配置来源拒绝、重复 Provider、环境变量工厂、熔断恢复、单半开探针和连接池关闭生命周期。
