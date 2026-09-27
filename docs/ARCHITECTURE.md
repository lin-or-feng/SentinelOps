# SentinelOps 0.2 架构

## 1. 设计目标与非目标

目标是把事故调查变成可验证、可终止、可审计的读取流程。系统接收 `IncidentTask`，通过只读工具收集标准化 `Evidence`，给出 `DiagnosisReport` 或明确升级人工。

非目标：自动执行 Shell、SSH、重启、扩缩容、回滚或配置修改；当前版本不连接生产监控、不承诺高可用，也不把自然语言模型放进默认决策路径。

## 2. 分层与依赖方向

```text
Presentation: CLI / FastAPI
            |
Application: Service / Bounded Agent / Policy / Evaluation
            |
Domain: strict Pydantic contracts
            |
Ports: EvidenceTool
            |
Adapters: fixture now, observability providers later

Cross-cutting: SQLite Store / AuditLog / Runtime Budget
```

领域层不依赖 FastAPI、数据库、模型 SDK 或具体监控产品。外部证据先通过端口归一化，编排层只处理领域对象。

## 3. 调查状态机

```text
START
  -> policy.decide(state)
      -> QUERY(source)
          -> budget.consume
          -> gateway authorize / retry / bound / audit
          -> merge evidence by evidence_id
          -> loop
      -> FINISH
          -> require candidate + >= 2 independent sources
      -> ESCALATE
          -> needs_human + unresolved reason
  -> persist result
  -> append completion audit event
```

`InvestigationBudget` 同时约束步骤、查询数、时间和重复动作。任何上限触发后都停止调查并升级人工，避免无限循环和工具放大。

## 4. 证据与结论约束

- `Evidence` 带唯一 ID、事故、服务、来源、观测时间、摘要和原始引用；
- Query 限制事故、服务、来源、关键词和条数；
- 候选根因由确定性规则对证据信号评分；
- Policy 只在置信度达到阈值且至少两个独立来源支持时完成；
- 报告的 `selected_code` 必须指向候选集合，引用 ID 必须来自已查询证据；
- 工具失败、预算耗尽或证据不足均返回 `needs_human`，不伪造成功。

## 5. 信任边界

| 边界 | 当前控制 | 仍需生产化 |
|---|---|---|
| API 调用方 | 可选静态 Bearer、常量时间比较 | OIDC、租户 RBAC、密钥轮换、速率限制 |
| 工具调用 | read-only 标志、来源白名单、Pydantic 参数、结果上限 | 每个真实提供方的最小权限凭据与 egress 控制 |
| Agent 运行时 | 步骤/查询/时间/重复动作预算 | 异步任务、租户配额、取消与背压 |
| 持久化 | SQLite 参数化 SQL、事故 ID 幂等 | PostgreSQL 事务、租户行级安全、备份恢复 |
| 审计 | 脱敏、前向哈希链、可选 HMAC | KMS 托管密钥、不可变外部归档、多副本串行化 |
| 容器 | non-root、只读 rootfs、drop capabilities | 镜像签名、SBOM、漏洞扫描、网络策略 |

## 6. 为什么现在仍是单 Agent

当前问题是有条件分支的只读调查，并不天然要求多 Agent。单 Agent 已能动态选择数据源、在证据充分时提前停止，并提供统一预算和审计。过早拆分会增加消息协议、并发冲突、重复查询、审计合并和成本归因难度。

0.3 以后只有在固定评测证明“单 Agent 无法同时达到召回、时延与查询成本目标”时，才拆出 Metrics/Logs/Changes 调查者；它们必须共享结构化证据存储，不共享无限聊天历史。

## 7. 演进路线

- Fixture -> Prometheus/Loki/Tempo 只读适配器，保持 `EvidenceTool` 契约；
- SQLite -> PostgreSQL，使用租户键、唯一约束与事务 outbox；
- 同步请求 -> 持久化任务队列，支持取消、重试、死信和背压；
- 静态 Bearer -> OIDC/OAuth2 + RBAC；
- 本地日志 -> OpenTelemetry traces/metrics/logs 和独立审计归档；
- 确定性 Policy -> 受约束模型 Policy，输出结构化动作，验证失败回退规则策略。
