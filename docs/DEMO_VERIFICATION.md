# 0.11.0 本地可视化闭环与辅助解释预览

## 启动与操作

在 `D:\agents` 打开 PowerShell（或 CMD），保持窗口不要关闭：

```powershell
.\.venv\Scripts\python.exe -m sentinelops.demo_web
```

访问 `http://127.0.0.1:8765/`。默认选择“全部案例”和 `Multi`，点击“运行闭环验证”。页面应显示 `4 / 4` 闭环通过、`4 / 4` 根因正确；点击案例可查看 Worker 派工、使用的证据、Trace 和审计事件。再切换 `Single` 与 `Auto` 重跑：请求模式和实际路由分别显示，`Single` 不会伪造 Worker 派工。每次都重新运行，因此 Trace ID、审计哈希和耗时会变化。

如果 8765 端口被占用，可在同一项目目录运行：

```powershell
.\.venv\Scripts\python.exe -m uvicorn sentinelops.demo_web:create_demo_app --factory --host 127.0.0.1 --port 8766 --workers 1
```

随后访问 `http://127.0.0.1:8766/`。页面不需要 Ollama、Docker、API Token 或外部监控服务；退出时按 `Ctrl+C`。

默认模式仍不调用模型。若要试用 0.11.0 的单轮辅助解释，请在已启动本机 Ollama、已安装所选模型的前提下，在同一个终端显式设置 `SENTINELOPS_DEMO_ASSISTANT=ollama`、`SENTINELOPS_OLLAMA_MODEL=<本机模型名>`，建议将 `SENTINELOPS_OLLAMA_TIMEOUT_SECONDS` 设为 `20`，再运行 `python -m sentinelops.demo_web`。**必须重启旧验证台进程**；`uvicorn --factory` 的默认工厂始终禁用助手，不会因环境变量意外打开。打开后先运行合成案例、选择单例，再在第 04 区提问。停用时设为 `off` 后重启即可。

## 后端闭环

```text
已发布的合成案例 → 固定 FixtureEvidenceTool → single/multi/auto 调查
  → SQLite 保存结果、派工和审计 → 检查根因/证据/哈希链/落盘/终态
  → 返回逐例检查项、角色/证据/Trace/审计事件 → 页面可视化
```

每个案例使用新建的临时数据库，不复用上轮结果。门禁不只比较根因：还要求最终证据 ID 属于当前夹具、审计链校验有效、结果可从数据库读回、运行账本已完成。任一检查失败即显示失败，不把流程跑完等同于通过。页面只回传合成夹具内容和本次审计，不接收用户自定义案例、URL、文件路径或脚本。可选助手另收最长 300 字的单轮问题；服务器只从本机 10 分钟短期缓存取对应已完成运行，不相信浏览器提交的证据或根因。

## 安全边界与局限

- 独立于正式 API：仅绑定 `127.0.0.1`，同时验证客户端和 Host；没有真实 Provider、修复动作或 holdout 入口。环境变量即使设置为真实监控/模型策略，调查仍显式覆盖为 Fixture/启发式/影子关闭；**只有演示助手显式开关**才对已完成结果调用本机 Ollama，且不改变调查。
- 请求体最多 4 KiB，最多 12 次运行/分钟，单次只允许运行一个请求。POST 仅接受 JSON，带 `Origin` 的请求必须同源；前端静态资源本地提供，页面使用文本节点渲染并设置限制性 CSP。
- `4/4` 只表示仓库自带四条**合成**事故在当前确定性规则下通过，不是独立测试集、模型正确率、真实事故泛化或生产准入。临时数据库用完即清理，页面不保存历史报告；如需可复现的发布证据，以 `scripts/release_check.py` 和 `docs/TEST_RESULTS.md` 为准。
- 助手只解释已引用证据，不读取夹具的预期根因；回答有严格 Schema、引用白名单和原结论一致性校验。语义真实性仍不能靠结构化输出完全证明，因此页面显著标为“AI 辅助解释”；无答案、超时或模型越界时显示失败原因，不改变原调查结果。无长期对话记忆，模型质量未由真实事故独立评测验证。

## 自动化检查

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_demo_web.py -q
.\.venv\Scripts\python.exe scripts\release_check.py
```

前者覆盖三种模式的四条事故端到端调查、资产加载、恶意来源/Host/客户端/请求体与无效输入拒绝，以及审计失败时门禁失败。后者还运行项目整体隐私、静态审计、测试、回放和评测门禁。
