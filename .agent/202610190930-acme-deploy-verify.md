# ACME 部署验证与上线收尾

- 日期：2026-10-19
- 状态：进行中
- 关联：`202610181230-acme-bench-doctor.md`（已完成主体，本计划是服务器端验证的延续）

## 背景

自写 ACME DNS-01 客户端（DuckDNS）在本地联调中发现并已修复四类问题：

1. **finalize URL 错误**（致命）：此前拼接 `{order_url}/finalize`，而 Let's Encrypt
   的 finalize 端点是订单对象里的独立 URL（`/acme/finalize/...`）。拼接结果落进
   order 端点——该端点只允许 POST-as-GET，携带 CSR payload 触发
   `400 malformed: POST-as-GET requests must have an empty payload`。
   修复：从订单对象读取 `finalize` 字段。
2. **TXT 传播误判**：DuckDNS 权威 NS 是最终一致多副本（同步需 1–2 分钟），
   单副本查询会误报。新增 `src/server/dnstxt.rs`：直查权威 NS、
   要求全部可达副本一致（LE 校验随机询问任意一台）。
3. **DoH 单点**：dns.google 在部分网络不可达。改为 Google → Cloudflare → Quad9
   依次回退。
4. **badNonce**：POST 收到 400 badNonce 时换新 nonce 重试一次（RFC 8555 §6.5）。

另修复配置缺陷：`listen.https = false` 无法关闭 HTTPS 入口（文档声称支持但
解析失败），已支持 `false` / 地址字符串 / 缺省三种写法。

本地经验教训：DuckDNS 对同一域名的高频 TXT 写入会**静默丢弃**（返回 OK 但不生效），
测试期反复 set/clear 导致本地长时间签发失败。生产环境签发只发生在首次与续期，
不会触发。

## 已完成

- [x] ACME 客户端修复（提交 `b41e94a` / `acee682`），全量测试通过
- [x] musl 静态产物重编（rust-lld，6.3 MB static-pie）
- [x] 服务器安装与基础验证：OpenRC 服务、doctor 0 失败、
      expose 模式（含 HTTPS 8443、指纹固定、断线保留期 502、重连接管）与
      forward 模式（server/local 双出口、出口 IP 隐藏、SSRF 拦截）全部通过
- [x] 服务器配置已切换：真实 DuckDNS 域名 + `tls.mode = "acme"`（密钥在服务器，
      不入库）
- [x] 新二进制已上传服务器并以 **staging** 环境启动（`/etc/conf.d/sluice` 里
      `SLUICE_ACME_STAGING=1`）

## 待办

### T1 staging 签发验证（首要）

1. 观察 `/var/log/sluice.log` 直到出现「证书签发成功」或按错误定位
   （可能需等待 DuckDNS 对该域名的写入节流冷却，间隔 ≥5 分钟再重试）。
2. 验证证书内容：

   ```sh
   openssl x509 -in /var/lib/sluice/certs/fullchain.pem -noout \
     -issuer -subject -enddate
   # 期望 issuer 含 "(STAGING) Let's Encrypt"，SAN 为 *.域名
   ```

3. HTTPS 入口返回 staging 证书（自签兜底被热替换）：

   ```sh
   curl -sk -H "Host: demo.<域名>" https://$SLUICE_HOST:8443/
   ```

### T2 切换正式环境

1. 删除 `/etc/conf.d/sluice` 中的 `SLUICE_ACME_STAGING` 两行，`rc-service sluice restart`。
2. 确认日志走 `acme-v02`（正式）签发成功，证书 issuer 不含 STAGING。
3. 浏览器级验证：`curl -H "Host: demo.<域名>" https://$SLUICE_HOST:8443/`
   **不带 -k** 应通过证书校验。

### T3 自动续期确认

- 机制已内置：每 6 小时巡检 `CertStore::days_left`，剩余 <30 天触发重签，
  失败按 60s·2ⁿ（上限 6h，±20% 抖动）退避，证书热替换无需重启。
- 验证手段：对比 `certs/fullchain.pem` 的 mtime 与服务启动时间（首次签发后
  会写入）；30 天内观察续期日志 `证书已热替换`。
- 可选加速验证：临时把证书目录换成 7 天自签证书，观察后台自动重签。

### T4 真实域名回归两种客户端模式

以 `demo.<域名>`（随机子域名）重跑一遍，替代此前的测试用基础域名：

| 项 | 命令要点 |
| --- | --- |
| expose + HTTPS | `sluice expose <port> --server $SLUICE_HOST:7835 --token … --subdomain demo`；`curl -H "Host: demo.<域名>" https://$SLUICE_HOST:8443/` |
| forward · server 出口 | `sluice forward --port 1234 --server $SLUICE_HOST:7835 --token … --egress server`；trace 站点确认出口 IP = 服务器 |
| forward · local 出口 | `--egress local`；trace 站点确认出口 IP = 本机 |
| SSRF 拦截 | `/http://127.0.0.1/` 应被拒 |

### T5 收尾

- [ ] 服务器端清理：安装临时目录 `/tmp/sluice-pkg`、日志脱敏复查
- [ ] 文档同步：`docs/DEPLOY.md` 补充「DuckDNS TXT 传播 1–2 分钟 / 高频写入会被
      静默丢弃」排障条目；`ARCHITECTURE.md` 若 ACME 章节有 URL 拼接描述需更正
- [ ] 全量验证：`cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
- [ ] 提交并推送

## 约束提醒

- 密钥与真实服务器地址一律用 `$SLUICE_HOST` / 环境变量，禁止入库。
- staging 通过前不进正式环境（正式环境每域名每周 5 张证书的限速）。
- DuckDNS 写入节流：签发重试间隔 ≥5 分钟为安全值（当前退避已满足）。
