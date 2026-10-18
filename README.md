# sluice

隧道与路径转发二合一代理。单二进制、静态链接、零 `unsafe`。

- **隧道模式**：把本地端口暴露成公网地址，子域名随机生成。
- **转发模式**：本地监听 `127.0.0.1:1234`，请求路径里带完整目标 URL，转发到目标站点。

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
```

其余字段全部有默认值，不需要写。

### 客户端

```sh
sluice expose 8080 --server host:7835     # token 首次交互输入并缓存
sluice forward --server host:7835         # 默认 127.0.0.1:1234
```

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
tail -f /var/log/sluice.log
```

常见问题：

- **子域名访问 404**：该子域名未分配。确认 agent 还在跑，且 `base_domain` 与客户端一致。
- **502 Tunnel offline**：子域名存在但会话已断开。agent 会在 60 秒内重连并复用同一子域名。
- **证书签发失败**：DNS TXT 传播需要 30–60 秒；同一域名同时只能有一条 TXT，不要并发签发。
- **转发模式 403**：目标落在私有网段被 SSRF 防护拦截；确需访问时在服务端配 `forward.allow_hosts`。

## 文档

- [ARCHITECTURE.md](ARCHITECTURE.md)：分层、协议、数据流、配置契约
- [docs/DEPLOY.md](docs/DEPLOY.md)：Alpine 部署
- [docs/MIGRATE-DOMAIN.md](docs/MIGRATE-DOMAIN.md)：换域名
- [docs/BENCH.md](docs/BENCH.md)：性能报告

## 许可

MIT
