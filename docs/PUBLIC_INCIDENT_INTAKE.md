# 公开事故候选池与独立标注流程

状态：**development 候选来源清单**，不是评测数据集、不是 sealed holdout，也不证明模型泛化能力。整理日期：2026-09-29。以下只记录公开复盘的链接与可观察的故障类型；不复制原文、日志、凭据或客户信息。

## 候选来源

| 候选 ID | 官方复盘 | 可用于人工标注的故障类型 | 入库前关注点 |
|---|---|---|---|
| CF-2025-09-12 | [Cloudflare Dashboard/API 中断](https://blog.cloudflare.com/deep-dive-into-cloudflares-sept-12-dashboard-and-api-outage/) | 前端请求放大、服务过载、鉴权依赖造成的 API 5xx | 多因素事故；不能仅凭事后根因把首个证据源定为 changes。 |
| CF-2025-03-21 | [Cloudflare R2 服务中断](https://blog.cloudflare.com/cloudflare-incident-march-21-2025/) | 凭据轮换中的环境部署错误、存储网关认证失败 | 不能把公开复盘中的凭据、内部命令或最终原因直接写进模型输入。 |
| GH-2025-12 | [GitHub 2025 年 12 月可用性报告](https://github.blog/news-insights/company-news/github-availability-report-december-2025/) | 配置漂移、模型依赖超时与队列背压、网络丢包、数据库 Schema 漂移 | 月报包含多起独立事故，须拆成不同 incident ID，不能把整篇当一组。 |
| GH-2026-05 | [GitHub 2026 年 5 月可用性报告](https://github.blog/news-insights/company-news/github-availability-report-may-2026/) | 数据库迁移压力、连接容量耗尽、托管 runner 扩容限流、路由配置问题 | 同日连锁事件须注明共同原因；不能把强相关事故拆到 development 与 holdout 两边。 |

这些链接来自发布事故复盘的组织本身。网页公开可读不等于允许整篇转载或自动再分发；本项目只保留链接和简要自写摘要。任何拟写入数据集的案例均须再次做来源与使用许可复核。

## 0.10.0 可复核的候选预检

`evals/public_incident_candidates.json` 仅记录两条已人工初筛的 Cloudflare 官方复盘 URL 和治理元数据，**没有事故输入、标签真值或文章正文**。`python -m sentinelops incident-intake-check` 对其返回码预期为 `1`（候选被阻断），并输出固定原因码。JSON 结构错误或隐私扫描命中返回 `2`；若全部机器条件满足才返回 `0`，但状态仍为 `manual_review_required`，绝不代表获得 holdout 资格。

| 候选 | 初筛结论 | 为什么暂不能入评测 |
|---|---|---|
| CF-2025-09-12 | `label_ambiguous` | 官方复盘描述前端请求放大与服务更新叠加，且影响扩散至鉴权依赖；不能把多因素链条强压成一个 Specialist 根因标签。 |
| CF-2025-03-21 | `label_out_of_taxonomy` | 官方复盘的凭据轮换/环境配置错误不是当前四个具名 Specialist 标签的清晰实例；`unknown` 表示证据不足，不是“已知根因但枚举缺失”的替代标签。 |

两条来源都是事后复盘，尚未找到可核实的事故决策时刻前就已发布或可访问的证据快照；不得从复盘的最终根因倒推症状。预检的 `available_at`、外部审批编号和 `label_status` 都是**申报元数据**，程序无法证明网页历史可见性、许可授权、复核者独立性或语义去重。真实候选仍需有权限的人员核对源系统时间戳、审批记录和独立标注。GitHub 月报候选未进入本轮机器清单，因为一篇报告含多场事故，须先逐起拆分。

## 从候选到可用评测集

1. **选样**：按独立事故而非文字变体分组，记录来源 URL、事件时间、服务边界和可确认的事前症状。不得从事后根因、修复动作或“正确答案”反推模型输入。
2. **双人复核**：一人根据事故当时可见信息提出首查只读证据源及理由；另一人独立复核 `expected_sources`、可选源、是否需要回退与争议点。若存在多个合理首源，按多标签标注或剔除，不强行制造唯一答案。
3. **拆分**：新版 `schema_version=0.3` 要求一个 `group_id`（一个独立事故）只属于 development 或 holdout，两个集合都必须存在。近因相同、同一连锁事件、同一复盘的改写不得跨拆分；不能仅靠字符串去重判定独立性。
4. **隔离**：开发者仅看 development 文本与错误分析。holdout 的来源选择、标注及封存由未参与 Prompt 调优的人完成；新 holdout 在首次资格运行前不得用于手工试探、提示词迭代或公开演示。
5. **门禁**：脱敏、许可与人工复核后，再使用 `policy-eval-registry-register` 执行 Schema、指纹、拆分和跨版本完全相同输入检查：旧任意输入不得成为新 holdout，旧 holdout 不得出现在新数据集任一拆分。自动通过不代表语义独立或人工审批完成。

当前仅完成候选来源筛选、只读预检与支持事故级拆分的契约；**没有产出或登记新的 sealed 真实事故集**。公开旧 v1 已消费，不可为新的 Prompt v2/v3 提供资格证据。
