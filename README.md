# sluice

隧道与路径转发二合一代理。单二进制、静态链接、零 `unsafe`。

- **隧道模式**：把本地端口暴露成公网地址，子域名随机生成。
- **转发模式**：本地监听 `127.0.0.1:1234`，请求路径里带完整目标 URL，转发到目标站点。
- **直连转发**（可选）：不开客户端，直接访问 `https://入口/https://目标/路径`，由服务器出网。默认关闭。

```
# 隧道：把本地 8080 暴露出去
sluice expose 8080 --server host:7835

# 转发：请求路径即目标 URL
curl http://127.0.0.1:1234/https://api.deepseek.com/chat/completions -d '{...}'
```

## 快速开始

### 服务端（Alpine / OpenRC）

```sh
apk add --no-cache ca-certificates
sh deploy/install.sh
```

最小配置 `/etc/sluice/server.toml`：

```toml
base_domain = "xxx.duckdns.org"
token       = "用 openssl rand -hex 24 生成"
dns_token   = "DNS 服务商的 API token"

# 可选：入口直连转发，默认 off
# [forward]
# direct = "token"   # off | token | open
```

其余字段全部有默认值，不需要写。

### 客户端

```sh
sluice expose 8080 --server host:7835     # token 首次交互输入并缓存
sluice forward --server host:7835         # 默认 127.0.0.1:1234
```

## 直连转发（可选）

不开客户端也能转发：访问 `<入口>/https://目标/路径`，服务器直接出网。由服务端 `[forward].direct` 控制：

| 档位 | 行为 |
| --- | --- |
| `off`（默认） | 关闭。路径里带 URL 的请求照常按子域名走隧道。 |
| `token` | 需要 `Authorization: Bearer <token>` 头或 `?__token=<token>` 查询参数，否则 401。 |
| `open` | 无需任何凭据，任何人可用。**有被第三方借道刷流量的风险**，仅在明确知晓后果时开启。 |

示例（`token` 档）：

```sh
curl https://example-domain:8443/https://www.deepseek.com/ \
  -H "Authorization: Bearer $SLUICE_TOKEN"
```

路径支持 `/https://host/path` 与折叠形式 `/https/host/path`；query 原样透传，不做百分号解码。SSRF 防护与 `allow_hosts` / `allow_private` / `max_body_mib` 与转发模式共用同一套规则。入口同时支持 HTTP/1.1 与 HTTP/2（TLS ALPN 协商）；WebSocket 请走 HTTP/1.1。

## 命令

| 命令 | 说明 |
| --- | --- |
| `sluice server` | 服务器端：控制面 + 80/8443 入口 + 证书 |
| `sluice expose <PORT>` | 隧道模式 |
| `sluice forward` | 转发模式 |
| `sluice doctor` | 自检：DNS、端口、证书、权限、内存 |
| `sluice bench` | 性能基准，产出 markdown 报告 |

## 配置优先级

`命令行参数 > 环境变量 > 配置文件 > 内置默认值`

环境变量：`SLUICE_SERVER`、`SLUICE_TOKEN`、`SLUICE_BASE_DOMAIN`、`SLUICE_DNS_TOKEN`、`SLUICE_CONF`、`SLUICE_LOG`。

## 平台支持与资源画像

客户端与服务端是同一个二进制，全部平台共用同一套纯 Rust 依赖（零 `unsafe`、无 C 工具链）：

| 平台 | 构建方式 | 验证状态 |
| --- | --- | --- |
| macOS（arm64 / x86_64） | `cargo build --release` | expose / forward / 直连转发全链路冒烟通过 |
| Linux x86_64（musl 静态） | `./scripts/build-musl.sh` | Alpine 实跑验证 |
| Linux aarch64（musl 静态） | `./scripts/build-musl.sh` | 同一依赖树交叉编译，静态链接校验通过 |

资源画像（实测，见 [docs/BENCH.md](docs/BENCH.md)）：

- 客户端常驻 RSS ≈ 5 MB，空闲 CPU ≈ 0。
- 大响应（MiB 级）流式传输后 RSS 不增长——全程流式转发，不缓冲整包。
- 单连接多路复用：一个 agent 只占一条 TCP 连接，不管并发多少请求。
- 客户端首连自带重试（服务端未就绪时最多等 5 秒），适配服务冷启动。

## 端口

| 端口 | 用途 |
| --- | --- |
| 80 | HTTP 入口 |
| 8443 | HTTPS 入口（443 通常被其他服务占用） |
| 7835 | 控制面（agent 出站连接） |

## 排查

```sh
sluice doctor                 # 逐项自检
SLUICE_LOG=debug sluice ...   # 打开调试日志
rc-service sluice status      # OpenRC 状态
ls /var/log/sluice/           # 日志按天滚动，保留 7 天
tail -f /var/log/sluice/sluice.log.$(date +%F)
```

常见问题：

- **子域名访问 404**：该子域名未分配。确认 agent 还在跑，且 `base_domain` 与客户端一致。
- **502 Tunnel offline**：子域名存在但会话已断开。agent 会在 60 秒内重连并复用同一子域名。
- **证书签发失败**：DNS TXT 传播需要 30–60 秒；同一域名同时只能有一条 TXT，不要并发签发。
- **转发模式 403**：目标落在私有网段被 SSRF 防护拦截；确需访问时在服务端配 `forward.allow_hosts`。
- **直连转发 401**：`direct = "token"` 时需要 Bearer 头或 `__token=` 查询参数。

## 文档

- [ARCHITECTURE.md](ARCHITECTURE.md)：分层、协议、数据流、配置契约
- [docs/DEPLOY.md](docs/DEPLOY.md)：Alpine 部署
- [docs/MIGRATE-DOMAIN.md](docs/MIGRATE-DOMAIN.md)：换域名
- [docs/BENCH.md](docs/BENCH.md)：性能报告

## 许可

MIT
