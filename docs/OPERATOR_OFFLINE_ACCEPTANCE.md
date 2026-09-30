# 操作台离线浏览器与故障验收（2026-09-30）

本验收只使用进程内空数据假来源，明确显示 `OFFLINE TEST · 假来源`。服务仅绑定 `127.0.0.1:8768`，不读取真实监控配置、不连接外部 Provider，也不把结果当作真实事故诊断。测试数据库为 D 盘临时文件，进程正常退出后自动清理；报告与截图在项目忽略目录 `.sentinelops/`，不应上传。

## 复现

在 `D:\agents` 的虚拟环境中按需安装 Playwright Python 包；浏览器测试使用系统已安装的 Microsoft Edge，不执行浏览器下载。本机此次安装在 D 盘虚拟环境中，未修改 `pyproject.toml` 的运行依赖。进入项目后运行一个命令即可自动启动两次假来源服务、完成浏览器验收、关闭服务并写报告；不需要复制临时 Token。

```powershell
.\.venv\Scripts\python.exe -m pip install --no-cache-dir --index-url https://pypi.org/simple playwright
.\.venv\Scripts\python.exe -m scripts.operator_offline_acceptance
```

退出码 `0` 表示两项离线浏览器验收均通过；`1` 表示某项失败，`2` 表示缺少 Playwright。JSON 报告为 `.sentinelops/operator-offline-acceptance.json`，截图为 `.sentinelops/operator-harness-browser.png` 和 `.sentinelops/operator-harness-interruption.png`。报告只记录测试状态、耗时、截图路径、受限的错误摘要与明确的非发布资格声明；不记录临时 Token。脚本先确认 `8768` 没有被其他服务占用，绝不连接已有监听者。

需要逐项调试时，仍可单独启动假来源夹具，再把启动输出中的**临时假来源 Token** 仅用于本机脚本，不使用正式 API Token：

```powershell
.\.venv\Scripts\python.exe scripts\operator_offline_smoke.py
# 另一个终端：
.\.venv\Scripts\python.exe scripts\operator_browser_acceptance.py --token <临时测试Token>
```

单独调试中断测试须先停止上面的离线进程，再用 `--query-delay-seconds 3` 重新启动（Token 会更新），运行：

```powershell
.\.venv\Scripts\python.exe scripts\operator_offline_smoke.py --query-delay-seconds 3
.\.venv\Scripts\python.exe scripts\operator_browser_interruption.py --token <新临时测试Token>
```

脚本只接受离线 `8768` 页面；不要改 URL 指向真实操作台。浏览器脚本在无头 Edge 中实际点击和读取页面，检查 JS 执行、显式确认、预检、调查、审计、刷新找回和未找到状态。中断脚本在调查请求发出后关闭页面，重新连接后先看到 `running` 预留，待后台结束再只读找回，过程中不再次提交调查。

## 本轮结果与边界

| 场景 | 方式 | 结果 |
|---|---|---|
| 一键 harness 主流程 + 中断恢复 | `python -m scripts.operator_offline_acceptance`，两次独立假来源进程内服务 | 通过；两阶段均记录在忽略目录 JSON 报告，服务停止后临时数据库清理；不含临时 Token |
| 连接 → 预检 → 确认 → 调查 → 审计 → 刷新找回 | 系统 Edge 真正执行页面 JS 与点击 | 通过；假来源无证据，正确返回 `needs_human`、审计链有效；截图见 `.sentinelops/operator-offline-browser.png` |
| 浏览器在调查请求后关闭 | 系统 Edge + 每次查询 3 秒的假来源 | 通过；重新打开先见 `running`，完成后找回结果，查询数为 2；截图见 `.sentinelops/operator-offline-interruption.png` |
| Provider 查询超时 | `tests/test_operator_web.py` 假来源 | 通过；预检成功、调查降级 `needs_human`，不回显上游错误正文 |
| 审计数据库被篡改 | `tests/test_operator_web.py` 临时 SQLite | 通过；找回与运行状态接口均拒绝返回可信结论或状态 |
| 完成后重启服务 | `tests/test_operator_web.py` 同一临时 SQLite 新服务实例 | 通过；只读找回相同 Trace，不重查 Provider |
| 预留后进程中断并重启 | `tests/test_operator_web.py` 同一临时 SQLite 新服务实例 | 通过；`running` 保留且同事故 ID 调查被拒，未自动重跑 |

浏览器实测发现：仅配置 metrics/logs 时，单 Agent 原先仍尝试 traces/changes，产生拒绝事件并消耗查询预算。本轮将单 Agent 的来源选择限制在服务已配置的白名单；相同无证据假来源场景的调查查询由 4 次降为 2 次，拒绝事件消失，最终仍交给人工。多 Agent 原有来源过滤与现有离线基线保持不变。

本轮完整门禁：**321/321 pytest 通过，行覆盖率 90.88%**，隐私扫描、静态审计、Provider 回放与策略回放通过。上述浏览器验收不覆盖真实凭据、真实事故准确率、强制取消、进程崩溃时的硬超时、目标环境 TLS/权限或容器恢复；这些仍是 [1.0 发布资格阻断项](RELEASE_READINESS.md)。
