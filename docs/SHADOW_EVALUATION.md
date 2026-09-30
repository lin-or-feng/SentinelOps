# Specialist 影子评测：0.7.0 开发对照与 0.8.0 资格活动

0.7.0 的开发对照命令只读取已记录的影子观察，不重新请求模型或 Provider；它回答“在一份开发标签上，按角色的模型假设与规则基线各有多少次正确”。0.8.0 的资格活动则显式重新请求本机模型，在只读夹具中重复调查封存数据。两条路径都不回答“模型可以接管生产裁决”。

## 数据边界

输入标签格式：

```json
{
  "schema_version": "0.1",
  "split": "development",
  "cases": [
    {
      "incident_id": "inc-example-001",
      "group_id": "example-scenario",
      "expected_code": "deployment_regression"
    }
  ]
}
```

`expected_code` 允许四类既有根因或 `unknown`。标签应由未参与 Prompt 调参的人复核，并按事故组隔离；当前程序只能检查结构、重复、大小和隐私，**不能证明标注独立性**。此示例不是已审批数据集，也不应改名为 holdout。请勿把真实事故正文、个人信息或凭据放进标签文件。

影子观察写入时，把模型名、Ollama 可解析 digest、Prompt ID/hash 存入独立 provenance 表；旧记录缺失这些字段时，开发评测拒绝它。评测要求标签事故在同一 SQLite 中已有完成的调查及影子记录，并逐条核对模型和 Prompt 身份。

## 命令与指标

在项目根目录、已安装项目或设置 `PYTHONPATH=src` 后执行：

```powershell
python -m sentinelops specialist-shadow-eval --labels .sentinelops\shadow-development.json --db .sentinelops\shadow.db --model-name qwen2.5:7b --model-digest <实际64位digest> --min-cases 20
```

命令只打印汇总：标签/观察数量、逐来源及总体模型与规则 Top-1、模型接受率、越界引用次数、影子调用 P95、可用 Token 计数、标签指纹和开发门禁结果。不输出事故 ID 或证据摘要。模型 Top-1 以**所有尝试**为分母，失败和无效输出都计入，避免只报告成功调用的选择性偏差。开发门禁要求事故数量达标、接受率达到 95%、零越界引用且模型总体正确率不低于同记录的单来源规则基线。阈值仅供开发比较，不是统计显著性或生产 SLO。

`specialist-shadow-eval` 仍直接拒绝 `split=holdout`；不能把开发门禁改名为资格。报告固定 `production_qualified=false`。

## 0.8.0 一次性资格活动

新资格数据集是另一种 Schema，不复用上面的“只有标签”JSON：

```json
{
  "schema_version": "0.1",
  "cases": [
    {
      "group_id": "incident-group-a",
      "split": "development",
      "task": {"incident_id": "inc-example-a", "tenant_id": "demo", "service": "service-a", "started_at": "2026-09-01T00:00:00Z", "symptoms": ["example alert"]},
      "evidence": [{"evidence_id": "ev-example-a", "incident_id": "inc-example-a", "service": "service-a", "source": "metrics", "observed_at": "2026-09-01T00:01:00Z", "summary": "example signal", "raw_ref": "fixture://example-a"}],
      "expected_code": "unknown"
    },
    {
      "group_id": "incident-group-b",
      "split": "holdout",
      "task": {"incident_id": "inc-example-b", "tenant_id": "demo", "service": "service-b", "started_at": "2026-09-01T00:00:00Z", "symptoms": ["example alert"]},
      "evidence": [{"evidence_id": "ev-example-b", "incident_id": "inc-example-b", "service": "service-b", "source": "metrics", "observed_at": "2026-09-01T00:01:00Z", "summary": "example signal", "raw_ref": "fixture://example-b"}],
      "expected_code": "unknown"
    }
  ]
}
```

示例只展示字段，不满足正式资格的最少 20 条 holdout，也未经人工复核，**不可直接登记为合格数据**。正式文件应放在本地忽略目录 `.sentinelops/`，与注册表同目录或其子目录；不要提交包含真实事故的文件。`group_id` 不得跨 development/holdout，证据须与事故/服务同域，注册表会拒绝新旧数据集之间完全相同的 holdout 输入。语义相似污染、标签真伪与来源授权仍需人工审查。

人工完成脱敏和来源审批后，可执行：

```powershell
python -m sentinelops specialist-shadow-register --registry .sentinelops\shadow-registry.db --dataset .sentinelops\shadow-v1.json --dataset-id shadow-v1 --approval-ref review-ticket-001
python -m sentinelops specialist-shadow-registry-check --registry .sentinelops\shadow-registry.db
python -m sentinelops specialist-shadow-campaign --registry .sentinelops\shadow-registry.db --dataset-id shadow-v1 --report .sentinelops\shadow-campaign-v1.json --runs 3
```

最后一条会请求已配置的本机 Ollama：必须设置 `SENTINELOPS_OLLAMA_MODEL`，并确保该模型 digest 可从 `/api/tags` 解析。只有显式执行 campaign 才会消耗 holdout；登记和检查命令不调用模型。资格开始前报告路径必须是注册表目录内尚不存在的 JSON 文件，数据集须处于 sealed 且含至少 20 条 holdout；随后**先原子预留，再运行**。每轮在独立临时 SQLite 中按只读夹具重新调查，不读取已有影子账本。预留后、终结前若 digest 漂移、写入失败或进程中断，holdout 保持 reserved，不自动恢复或重开；已写出的报告保留 reservation ID 和已完成轮次。终结后无论门禁接受还是拒绝，holdout 均 consumed；若最终报告更新失败，注册表仍为 consumed，预备报告可供人工核对，绝不能重跑资格活动。

严格技术门禁要求每轮模型全尝试 Top-1 与确定性最终结论均为 100%、影子调用接受率 100%、零越界引用、跨轮预测稳定率 100%、P95 单次影子调用不超过 8 秒、单次 Token 不超过 2048 且用量可观测。报告只有总体/逐来源聚合，不输出事故文本或逐案例预测。`accepted` **仅表示这套离线门禁通过**，不等于真实组织审批或生产授权；`production_qualified=false` 始终不变。当前仓库没有可信独立事故集，本轮合成测试只验证状态机和计算逻辑。
