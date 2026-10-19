# Alpine 部署

> 目标环境：Alpine Linux + OpenRC，静态 musl 二进制。
> TLS 后端是纯 Rust（rustls-rustcrypto），交叉编译不需要 zig 或任何 C 工具链。

## 1. 构建

在开发机（不是服务器）上交叉编译：

```sh
./scripts/build-musl.sh
```

脚本自动补装缺失的 rustup target，用 `rust-lld` 完成 musl 链接。产物：
`target/x86_64-unknown-linux-musl/release/sluice`（约 6 MB，static-pie），
脚本会校验它是静态链接，否则直接失败。

## 2. 上传与安装

```sh
mkdir -p /tmp/sluice-pkg
scp target/x86_64-unknown-linux-musl/release/sluice \
    deploy/install.sh deploy/sluice.initd deploy/sluice.confd \
    "$SLUICE_HOST":/tmp/sluice-pkg/

ssh "$SLUICE_HOST" 'cd /tmp/sluice-pkg && sh install.sh'
```

`install.sh` 做的事：

1. 校验 root、`rc-service` 存在、二进制为静态链接
2. 创建 `sluice` 系统用户与 `/var/lib/sluice`（0700）
3. 安装二进制、initd、confd
4. **不覆盖**已存在的 `/etc/sluice/server.toml`
5. `rc-update add sluice default`

## 3. 配置

`/etc/sluice/server.toml`，最少三个字段：

```toml
base_domain = "xxx.duckdns.org"
token       = "openssl rand -hex 24 的输出"
dns_token   = "DuckDNS 的 token"
```

生成 token：

```sh
openssl rand -hex 24
```

权限：`chown root:sluice` + `chmod 640`（安装脚本已设置）。启动时若发现权限过宽
会打告警。

## 4. 启动与排障

```sh
rc-service sluice start
rc-status
tail -f /var/log/sluice.log
```

常见问题：

| 现象 | 原因 |
| --- | --- |
| `bind: permission denied` | 缺少 `cap_net_bind_service`，检查 `/etc/init.d/sluice` 的 `capabilities` |
| 启动即退出，日志有字段名 | 配置校验失败，按提示补字段 |
| 80 端口被占用 | 先 `ss -lntp \| grep :80` 看是谁 |
| 客户端连不上控制面 | 云安全组是否放行 7835 |
| ACME 报 `TXT 传播超时` | 见下方「DuckDNS TXT 注意事项」 |
| ACME 报 `POST-as-GET requests must have an empty payload` | 客户端把 CSR 发到了 order 端点——确认客户端从订单对象读 `finalize` 字段，而不是拼接 `{order_url}/finalize` |
| 外部访问 80 端口被重置（本机正常） | 上游 ISP/托管防火墙拦截入站 HTTP。改用 8443 入口（证书链完整，浏览器可直接访问） |

### DuckDNS TXT 注意事项（ACME DNS-01）

- 权威 NS 是最终一致的多副本，写入后**全部副本同步需要 1–2 分钟**；sluice
  会直查所有权威副本确认一致后才触发校验，等待预算 5 分钟。
- 对同一域名**高频写入会被静默丢弃**（返回 OK 但不生效）。签发只在首次与
  剩余 <30 天时发生，正常使用不会触发；手动反复测试时注意间隔 ≥5 分钟。
- 首次签发约 10 秒～2 分钟（取决于 DNS 传播）；日志关键字 `证书签发成功`。
- staging 试跑：`/etc/conf.d/sluice` 加 `SLUICE_ACME_STAGING=1`，通过后删除并
  **同时删除 `/var/lib/sluice/certs/` 下的 pem 文件**（staging 证书有 90 天
  有效期，缓存机制不会自动重签），再 `rc-service sluice restart`。

## 5. 与既有服务共存

- 不要占用 443：部署环境里该端口通常已有服务。
- 日志独立在 `/var/log/sluice.log`，不与既有服务混写。
- `apk -U upgrade` 之后确认既有服务仍然 `started`。

## 6. 升级

```sh
rc-service sluice stop
install -m 755 sluice /usr/local/bin/sluice
rc-service sluice start
```

配置与证书不会被触碰。
