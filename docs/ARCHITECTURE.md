# SentinelOps 架构基线

## 1. 分层

```text
CLI / Future API
        |
Application: baseline diagnosis and evaluation
        |
Domain: strict contracts and error vocabulary
        |
Ports: read-only evidence query interfaces
        |
Adapters: fixture data now; metrics/log/trace providers later
```

依赖必须指向领域层。领域层不依赖 FastAPI、LangGraph、数据库、模型 SDK 或具体监控产品。

## 2. 当前执行流

```text
IncidentTask
  -> query metrics/logs/traces/changes through EvidenceTool
  -> normalize Evidence
  -> score deterministic root-cause rules
  -> DiagnosisReport with evidence IDs
  -> EvaluationSummary against labeled fixtures
```

## 3. 未来 Agent 边界

0.2 版本只增加一个有界调查 Agent。模型只能选择只读查询和提出假设，不能执行修复。每一轮必须消费步数、查询次数、时间和 Token 预算。

0.3 版本仅在评测证明有效时拆分 Metrics、Logs 和 Changes 调查者。Agent 之间传递 `Evidence`、`Hypothesis` 等结构化对象，不共享无限聊天记录。

## 4. 企业化演进

- SQLite/Fixture 仅用于本地开发；多用户事实存储迁移 PostgreSQL；
- Redis 只承载短期缓存、限流和分布式锁，不作为事故事实来源；
- OpenTelemetry 统一模型、工具和状态图 Trace；
- API 请求携带 tenant、user、trace 和 idempotency 边界；
- 高风险处置必须持久化审批，且审批绑定不可变计划指纹；
- CI 同时检查单测、契约、故障注入、安全边界和离线评测。
