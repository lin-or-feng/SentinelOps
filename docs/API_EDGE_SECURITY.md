# SentinelOps API 边界安全

## 1. 目标

0.3.4 在业务代码之前建立一个可测试、失败关闭的 HTTP 边界。它用于限制意外大请求、突发调用、并发耗尽、伪造 Host 和跨域误配，不替代反向代理、WAF、OIDC 或分布式网关。

## 2. 请求路径

```text
Request
  -> Request ID / 结构化访问日志 / 固定安全响应头
  -> 全局并发准入 + 60 秒滑动窗口 RPM
  -> 请求体实际字节上限
  -> 精确 CORS origin
  -> Trusted Host
  -> FastAPI 路由 / Pydantic 领域契约
```

`/healthz`、`/readyz` 和可选 `/metrics` 不占业务限流与并发槽位，避免流量高峰时探针失效。它们仍受 Host 校验、安全响应头和请求体边界保护。

## 3. 配置

| 环境变量 | 默认值 | 边界 |
|---|---:|---|
| `SENTINELOPS_MAX_REQUEST_BYTES` | `1000000` | 1 KiB–5 MB |
| `SENTINELOPS_RATE_LIMIT_RPM` | `60` | 1–6000 次/60 秒/进程 |
| `SENTINELOPS_MAX_INFLIGHT` | `16` | 1–256 个业务请求/进程 |
| `SENTINELOPS_TRUSTED_HOSTS` | `127.0.0.1,localhost,testserver` | 精确主机/IP，拒绝 `*` |
| `SENTINELOPS_CORS_ORIGINS` | 空 | 精确 HTTPS origin；仅 loopback 可用 HTTP |

配置在应用创建时校验，错误值导致启动失败，不在运行时静默降级。生产容器应显式配置 `SENTINELOPS_TRUSTED_HOSTS`；`testserver` 只存在于代码默认值，Compose 默认不包含它。

## 4. 控制语义

- **请求体上限**：先校验 `Content-Length`，再按实际收到的字节累计；分块传输和虚假小长度不能绕过上限。超限固定返回 413，不回显正文。
- **滑动窗口限流**：使用进程内线程安全时间戳窗口；超限返回 429 和 `Retry-After`。当前是整体实例配额，不以用户输入、Token 或 IP 建立无界状态。
- **并发保护**：非阻塞获取固定槽位；满载立即返回 503 和 `Retry-After`，不在内存中排无界等待队列。
- **Host/CORS**：Host 和跨域 origin 都必须显式列举。CORS 不启用凭据模式，允许的方法和请求头也为固定集合。
- **响应头**：所有 HTTP 结果统一增加 `nosniff`、`DENY`、`frame-ancestors 'none'`、`no-referrer`、受限 Permissions Policy 和 `no-store`；HSTS 只在 HTTPS 请求上发送。

## 5. 已知限制与升级条件

限流器和并发计数器是**单进程**状态，符合当前 `--workers 1` 和单容器约束。它不声称提供按租户公平性、跨副本一致配额或 DDoS 防护。

只有进入多副本阶段后才应引入 Redis/网关限流：使用经过认证的租户 ID 作为配额键，在入口代理处做连接与体积保护，在应用层保留租户级并发和任务配额。异步长任务还需要持久化队列、取消、超时、背压和死信，不能简单把同步端点改成 `async def`。

## 6. 验证范围

自动化测试覆盖配置失败关闭、滑动窗口到期、并发拒绝、伪造 Host、精确 CORS、声明长度和实际流式字节超限、安全响应头、HTTP 不发送 HSTS 与 HTTPS 发送 HSTS。统一发布门禁同时执行隐私扫描、静态危险调用审计、全量测试、Provider 回放和事故基线。
