# 可观测性故障回放契约

## 1. 目标与边界

回放用于把 Provider 响应兼容性和故障分类变成可重复的 CI 证据。它验证：Prometheus、Loki、Tempo 响应能否继续归一化为 `Evidence`；503 是否仍被分类为可重试错误；畸形响应是否被拒绝；上游 Schema 改变是否经过评审。

它不是抓包器，也不是生产数据归档系统。项目不会后台监听流量、保存请求头、复制 Bearer Token 或主动连接生产系统。默认数据集全部标记为 `synthetic`。

## 2. 信任链

```text
人工最小化 JSON
  -> 文件大小 <= 1 MB
  -> 隐私规则扫描（不回显命中值）
  -> ReplaySuite 严格契约
  -> provider/source/时间窗一致性
  -> JSON 结构指纹比对
  -> httpx.MockTransport（无网络）
  -> 真实 Provider 解析代码
  -> Evidence 数量 / 错误分类断言
  -> 发布门禁
```

校验顺序很重要：隐私扫描在 JSON 解析错误输出之前执行，避免异常信息回显原始内容。测试和 CLI 结果只输出 case ID、结果分类、证据数量和 SHA-256 结构指纹。

## 3. 数据契约

Suite 固定包含：

- `schema_version=1.0`；
- `privacy_policy=sentinelops-privacy-v1`；
- 1 到 100 个唯一案例。

每个案例必须声明：

- `origin`：`synthetic` 或经过审批的 `sanitized_export`；
- Provider 与匹配的 `EvidenceSource`；
- 带时区且不超过一小时的查询窗口；
- HTTP 状态码和 JSON object 响应；
- 已批准的结构指纹；
- 预期分类：`success`、`retryable_error` 或 `schema_error`；
- 成功时预期的 Evidence 数量。

不允许额外字段。载荷结构递归深度最多 20 层、节点最多 10,000 个，整个文件受统一 1 MB 隐私扫描上限约束。

## 4. 结构指纹

结构指纹把响应转换成“字段名 + JSON 类型”的规范形状后计算 SHA-256。字符串、数值等业务值不进入摘要，因此 CLI 不会通过指纹泄露原值。

新增字段、删除字段、字段类型改变或数组元素形状改变都会产生新指纹。发现漂移时回放不会调用 Provider 解析逻辑，而是返回 `schema_drift`。新指纹不能自动批准，必须确认：

1. 上游变更是否有官方依据；
2. 解析器是否仍保持最小字段提取；
3. 新字段是否包含隐私或高基数内容；
4. 成功、失败和空结果路径是否都有测试；
5. 完成代码评审后才更新批准指纹。

## 5. 新增真实案例流程

1. 由数据所有者在隔离环境导出最小 JSON body，不导出 headers、URL query 或凭据；
2. 删除与故障无关的标签、日志行和 Trace 属性；
3. 用不可逆占位值替换用户、设备、订单、IP、内部主机和组织标识；
4. 标记 `origin=sanitized_export`，不得填写个人审批者姓名或邮箱；
5. 先运行 `privacy_guard.py --worktree`，确保尚未暂存的新案例也被扫描，再运行 `replay-check`；
6. 对结构变化做人工评审，最后执行完整 `release_check.py`。

当前扫描器不是企业 DLP 的替代品。真实生产导出在进入仓库前仍需遵守组织的数据分类、保留期限和审批制度。

## 6. 执行

```powershell
.\.venv\Scripts\python.exe -m sentinelops replay-check
.\.venv\Scripts\python.exe scripts\release_check.py
```

`replay-check` 返回码：`0` 全部通过；`1` 契约结果或结构指纹不匹配；`2` 文件不可读、隐私阻断或数据契约无效。
