# SentinelOps 受控模型策略

## 1. 为什么引入模型，但不把控制权交给模型

确定性规则适合执行权限、预算、证据门控和终止条件；模型更适合在症状表达不稳定时给数据源排序。0.4.2 因此采用“模型建议、规则裁决”：本地模型只能建议下一只读 `EvidenceSource`，不能决定完成、升级、工具参数、查询语言或任何写操作。0.4.3 增加模型专用并发与频率准入；0.4.4 用独立数据集和严格阈值决定它能否进入默认路径；0.4.5 固定 Prompt 哈希和本地模型 digest；0.4.6 再隔离开发/隐藏集，并加入调用成功率与按场景组 bootstrap，防止数据泄漏和伪模型收益。

默认仍是 `heuristic`。`ollama` 是显式选择的宿主机实验能力，不是发布门禁、Docker 复现或生产运行的前置依赖。

```text
InvestigationState
      |
      +--> deterministic guard
      |      +--> FINISH / ESCALATE ----------> execute directly
      |      |
      |      +--> QUERY candidate
      |               |
      |        minimal redacted context
      |               v
      |       loopback Ollama / JSON Schema
      |               |
      |       validate size / schema / privacy
      |               |
      +<-- source allowlist + queried-source guard
                    |
          accepted source or deterministic fallback
```

## 2. 权限矩阵

| 决策 | 模型 | 确定性控制面 |
|---|---:|---:|
| 建议下一 EvidenceSource | 是 | 校验并可拒绝 |
| 生成查询关键词 | 否 | 是 |
| 生成 PromQL/LogQL/TraceQL | 否 | 固定适配器模板 |
| 决定 FINISH / ESCALATE | 否 | 是 |
| 修改查询/时间/步骤预算 | 否 | 是 |
| 放宽来源白名单 | 否 | Gateway + Policy |
| 执行写操作或自动修复 | 否 | 系统无此端口 |

模型输出契约只有：

```json
{
  "source": "logs",
  "rationale": "short explanation"
}
```

`rationale` 只用于验证，不进入 Trace 或审计。系统保存的是固定模板和固定原因码，避免模型原文携带隐私、注入内容或高基数字段。

## 3. 最小上下文与隐私

允许发送：

- 已脱敏并截断的 service 与 symptoms；
- 当前允许的数据源；
- 已查询数据源；
- 每个来源的 Evidence 数量。

禁止发送：

- tenant ID、incident ID；
- Evidence summary、attributes、raw_ref；
- Provider URL、Token、认证头；
- 审计详情和数据库内容。

模型响应在解析前受字节上限约束；结构化内容再次经过项目隐私扫描。命中隐私规则时丢弃整个建议，只记录 `private_output_rejected`，不回显命中值。

## 4. 网络与供应链边界

`SENTINELOPS_OLLAMA_URL` 只接受 `localhost` 或 loopback IP，拒绝远端域名、用户信息、路径、查询参数和重定向。HTTP 客户端禁用系统代理环境变量，避免请求被透明转发。默认超时 8 秒，最大响应 64 KiB，可在安全范围内下调。

此限制意味着 Docker 容器不能用 `host.docker.internal` 访问宿主机 Ollama。Compose 因此固定 `heuristic`，优先保证离线可复现。若未来需要容器化模型，应新增独立受控网络、明确服务身份、模型镜像锁定和 egress 策略，而不是放宽到任意主机。

## 5. 失败语义

以下情况全部回退确定性策略：

- HTTP/超时/状态码失败：`transport_failure`；
- 非 JSON 或不符合 Schema：`invalid_structured_output`；
- 响应超过上限：`response_too_large`；
- 输出含隐私：`private_output_rejected`；
- 建议不在白名单或已查询：`source_outside_guard`；
- 未分类适配器失败：`unexpected_model_failure`。
- 模型并发槽已占满：`model_busy`；
- 60 秒滑动窗口已达上限：`model_rate_limited`。

每次接受、回退或确定性终止都写入 `controlled-model-policy / model_source_proposed` 审计事件。事件只含 `outcome`、`reason_code` 和被接受的来源，不含 Prompt、模型响应或异常正文。

## 6. 配置与验证

```powershell
$env:SENTINELOPS_POLICY_MODE = "ollama"
$env:SENTINELOPS_OLLAMA_MODEL = "qwen3:8b"
$env:SENTINELOPS_OLLAMA_URL = "http://127.0.0.1:11434"
$env:SENTINELOPS_OLLAMA_TIMEOUT_SECONDS = "8"
$env:SENTINELOPS_OLLAMA_MAX_RESPONSE_BYTES = "65536"
$env:SENTINELOPS_OLLAMA_MAX_INFLIGHT = "1"
$env:SENTINELOPS_OLLAMA_RATE_LIMIT_RPM = "30"
.\.venv\Scripts\python.exe -m sentinelops investigate `
  --incident-id inc-deploy-001 --orchestration-mode auto
```

配置在创建数据库和 HTTP 客户端前校验。模型名必须显式给出；URL 不是 loopback 时启动失败。测试使用 `httpx.MockTransport`，验证请求包含 JSON Schema、`stream=false` 与 `temperature=0`，不会依赖真实模型或网络。

真实评测结束时会通过同一 loopback、禁代理、禁止重定向和响应上限约束读取 `/api/tags`，只提取匹配模型的 64 位十六进制 digest。查询失败不会改变评测结论，但报告会明确标记同名模型标签可能漂移。

并发槽使用非阻塞 `BoundedSemaphore`：默认只允许一个在途推理，槽满不等待，直接让本次调查使用规则策略。RPM 使用线程安全的进程内 60 秒滑动窗口，默认 30 次；仅成功取得并发槽的模型尝试才消耗配额。该控制保护单进程和单卡，不是多副本分布式限流。

可观测指标包括：

- `sentinelops_model_policy_decisions_total{outcome,reason_code}`；
- `sentinelops_model_policy_call_duration_seconds{outcome}`。

标签值来自代码内固定枚举，不包含模型名、Prompt、响应、事故或租户字段。可用回退率和 P95 判断模型策略是否值得保留，而不是只看演示是否成功。

## 7. 评测结论与下一步

0.4.6 将 60 条策略集按每个场景组固定拆为 30 条 development 与 30 条 holdout，并把回放控制面与真实模型结果强制分型。本机 `qwen2.5:7b` 在隐藏集 Top-1 为 90%，高于启发式 66.67%；按组 bootstrap 的 95% 提升区间为 +3.33% 到 +46.67%，调用成功率与安全率均为 100%、越权执行 0、下游 4 条事故无回归。但它仍未达到 Top-1 100% 的严格准入线，因此默认保持 `heuristic`。完整指标与复现命令见 [策略评测](POLICY_EVALUATION.md)。

进入默认路径前仍需要：

1. 用经脱敏和人工批准的真实事故扩充模糊症状、冲突信号与未知故障；
2. 固定模型 digest、Prompt 版本、数据集哈希和 development/holdout 边界；
3. 对模型升级执行离线回归、人工抽检和 shadow/canary；
4. 只有收益稳定且成本可接受时，才考虑从实验开关升级为可部署选项。

## 8. 实现参考

- [Ollama Structured Outputs](https://docs.ollama.com/capabilities/structured-outputs)
- [Ollama Chat API](https://docs.ollama.com/api/chat)
