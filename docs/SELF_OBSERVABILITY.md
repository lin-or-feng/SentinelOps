# SentinelOps 自身可观测性与建议 SLO

## 1. 设计原则

自身可观测性只回答“服务运行得怎么样”，不参与根因判断。实现遵循以下约束：

- 指标名称使用 `sentinelops_` 前缀，累计计数以 `_total` 结尾，耗时统一使用秒；
- 指标 label 只接受代码内固定枚举，不接收 incident ID、tenant、request ID、服务名、URL 或异常正文；
- `/metrics` 默认关闭，必须设置 `SENTINELOPS_METRICS_ENABLED=1`；
- 指标端点不复用业务 API Token，部署方应通过 loopback、独立抓取网络或反向代理策略限制访问；
- 请求日志不记录 body、query string、客户端地址、认证头或 User-Agent；
- 当前只提供进程内指标，重启后归零，多 Worker/多副本由 Prometheus 按实例抓取聚合。

指标格式遵循 [Prometheus 文本 exposition 0.0.4](https://prometheus.io/docs/instrumenting/exposition_formats/)，命名和 label 设计遵循 [Prometheus metric and label naming](https://prometheus.io/docs/practices/naming/)。

## 2. 关联标识

客户端可以发送 `X-Request-ID`。仅接受 8–64 位字母、数字、点、下划线和连字符，并再次经过隐私规则扫描；其他值由服务生成。正常生成的 HTTP 响应会回传安全 Request ID。

创建或复用调查时，响应包含 `X-SentinelOps-Trace-ID`。新调查的 Request ID 会写入开始/完成审计事件；幂等复用和冲突事件也记录当前 Request ID。这样可以沿着：

```text
客户端请求 -> X-Request-ID -> 结构化 HTTP 日志
                         -> X-SentinelOps-Trace-ID -> AuditLog / InvestigationResult
```

当前关联 ID 不是 W3C Trace Context，也没有冒充 OpenTelemetry span。迁移到多服务后应接入标准 trace/span context，并继续禁止 baggage 进入指标 label。

## 3. 指标契约

| 指标 | 类型 | 固定标签 | 含义 |
|---|---|---|---|
| `sentinelops_build_info` | Gauge | `version` | 当前构建版本 |
| `sentinelops_http_requests_total` | Counter | `method, route, status_class` | HTTP 请求量 |
| `sentinelops_http_request_duration_seconds` | Histogram | `method, route` | HTTP 耗时 |
| `sentinelops_provider_queries_total` | Counter | `source, status` | Provider 查询结果 |
| `sentinelops_provider_query_duration_seconds` | Histogram | `source, status` | Provider 查询耗时 |
| `sentinelops_investigations_total` | Counter | `outcome` | 调查完成、冲突和复用数量 |
| `sentinelops_investigation_duration_seconds` | Histogram | `outcome` | 调查端到端耗时 |
| `sentinelops_provider_circuit_open` | Gauge | `source` | 对应来源熔断是否打开 |

允许的 route 是代码注册的模板，例如 `/v1/investigations/{incident_id}`；未知路径统一为 `unmatched`。HTTP 状态只保留 `2xx` 等类别。Provider status 只允许 `ok/error/denied/circuit_open`。

## 4. 结构化日志

`sentinelops.http` logger 每个请求产生一条 JSON message：

```json
{"duration_ms":12.3,"event":"http_request_completed","method":"POST","request_id":"req-example-001","route":"/v1/investigations","status_code":201}
```

生产环境应让日志采集器补充 timestamp、deployment、environment 等资源属性，不应在应用内加入用户、租户或事故正文。

## 5. 建议 SLI/SLO

以下只是进入压测和试运行阶段的初始目标，不是当前版本已经达成的生产承诺：

| SLI | 建议初始目标 | 说明 |
|---|---:|---|
| API 非 5xx 可用率 | 30 天 >= 99.5% | 不把客户端 4xx算服务故障 |
| 调查接口 P95 | <= 10 秒 | 当前同步架构，需用压测确认 |
| Provider 查询 P95 | <= 5 秒 | 与默认单次超时一致 |
| 熔断持续打开 | < 5 分钟 | 超时应通知人工检查上游 |
| `needs_human` 比率 | 建立基线后设阈值 | 它可能表示正确拒答，不能直接当错误率 |

不建议直接对单个实例 Counter 告警；应在 Prometheus 中按实例聚合 rate，并结合最小流量窗口。`needs_human` 是安全行为，需要和事故类型、证据覆盖率共同分析。

## 6. 当前限制

- 指标仅保存在进程内，重启归零；
- Docker 固定单 Worker，多进程尚无共享 Registry；
- 尚未接入 OpenTelemetry SDK、远端 Collector、Dashboard 或真实告警规则；
- 尚未进行容量压测，因此文档中的 SLO 是设计目标，不是实测保证；
- `/metrics` 本身不带认证，启用时必须使用独立网络边界保护。
