# Alpine 部署

> 目标环境：Alpine Linux + OpenRC，静态 musl 二进制。
> **注意**：HTTPS 入口（8443）与 ACME 通配证书尚未实现（M6）。当前版本只监听
> HTTP 入口，控制通道也是明文，仅适合内网或临时联调，不要直接暴露到公网。

## 1. 构建

在开发机（不是服务器）上交叉编译：

```sh
brew install zig
cargo install cargo-zigbuild
./scripts/build-musl.sh
```

产物：`target/x86_64-unknown-linux-musl/release/sluice`，脚本会校验它是
`statically linked`，否则直接失败。

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
