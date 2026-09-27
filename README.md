# SentinelOps 0.1

SentinelOps 是一个从零构建的、证据优先的企业事故诊断项目。它的目标不是让大模型直接操作服务器，而是让系统在只读边界内查询指标、日志、链路和变更记录，形成可验证的根因报告。

当前 `0.1` 版本刻意**不实现 Agent**。它先建立确定性基线、领域契约、只读工具端口、模拟事故集和评测器，后续所有 Agent 优化都必须与这条基线比较。

## 当前能力

- Pydantic 严格领域契约，拒绝未知字段；
- 只读 `EvidenceTool` 端口与内存 Fixture 适配器；
- 基于证据信号的确定性根因排序；
- 4 类可复现模拟事故；
- Top-1、证据引用有效性和工具查询次数评测；
- pytest、覆盖率门槛和 GitHub Actions 质量门禁；
- ADR 记录为什么第一版不直接使用多 Agent。

## 本地运行

```powershell
Set-Location D:\agents
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest --cov=sentinelops --cov-fail-under=80
.\.venv\Scripts\python.exe -m sentinelops
```

评测默认读取 `evals/incidents.json`，成功时输出 JSON 报告并返回退出码 `0`。

## 版本路线

1. **0.1 确定性基线**：契约、只读工具、事故集、评分器。
2. **0.2 单 Agent 调查循环**：观察、查询、假设、验证和有界停止。
3. **0.3 多 Agent 调查**：Metrics、Logs、Changes 并行调查，统一证据存储。
4. **1.0 企业化服务**：FastAPI、PostgreSQL、Redis、OpenTelemetry、RBAC、持久化任务与人工审批。

详细分层见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。

## 安全边界

- 当前工具全部只读；
- 不执行 Shell、SSH、重启、扩缩容或配置修改；
- Fixture 数据是测试资料，不连接任何生产系统；
- 后续处置能力也必须先生成建议，再由人类审批。

## License

尚未选择开源许可证。在许可证确定前，不默认授予复制、修改或商用权利。
