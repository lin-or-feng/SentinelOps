# SentinelOps 0.2.1 测试结果

- 日期：2026-09-27
- Python：3.11.9
- 平台：Windows 10

## 发布门禁结果

命令：

```powershell
.\.venv\Scripts\python.exe scripts\release_check.py
```

| 检查 | 结果 |
|---|---|
| `compileall` 源码、测试与脚本 | 通过 |
| 全部跟踪文件隐私扫描 | 通过 |
| 危险运行时调用与已知密钥格式扫描 | 通过 |
| pytest | 35 passed |
| `sentinelops` 行覆盖率 | 92.12%（门槛 80%） |
| 离线基线 | 4/4 Top-1 正确 |
| 证据引用有效性 | 100% |
| 基线平均查询数 | 4.0 |

覆盖的关键场景包括：严格契约、只读/白名单拒绝、瞬时错误重试、非瞬时错误审计、查询与重复动作预算、双来源门控、未知事故升级人工、结果持久化、事故幂等与冲突、递归脱敏、HMAC 链验证、数据库篡改检测、API 认证/404/409、环境变量路径，以及手机号/身份证/邮箱/本机路径/Token/私钥/硬编码凭据/敏感文件/二进制哈希审批。

真实暂存区阻断测试使用一次性假手机号探针：扫描返回退出码 `1`，仅报告文件、行号和 `PRC mobile number` 规则，输出未包含原始号码；探针随后已从暂存区和工作区移除。

## API 端到端结果

本机启动 FastAPI 后执行健康检查、调查和审计验证：

| 项目 | 结果 |
|---|---|
| `GET /healthz` | 200，当前代码版本 0.2.1 |
| `POST /v1/investigations` | 201，诊断 `deployment_regression` |
| 证据引用 | changes + logs 两个独立来源 |
| `GET /v1/audit/verify` | valid=true，HMAC-SHA256，4 条事件 |

## Docker 结果

- Docker Client/Server 29.8.0：可用；
- `docker compose config --quiet`：通过；
- `docker compose build --pull`：**未完成**。Docker Hub 匿名令牌端点连接超时，本机无 `python:3.11-slim` 缓存；失败发生在读取基础镜像元数据之前，未执行项目 Dockerfile 构建步骤。

因此本次只确认 Docker/Compose 配置可解析，不能宣称镜像已构建或容器健康检查已通过。网络恢复后应重新运行 `docker compose up --build -d` 与 `/healthz` 检查。
