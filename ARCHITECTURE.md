# sluice 架构

## 1. 一句话

一条 TLS 长连接上跑 yamux 多路复用，两个功能共用同一套流处理代码：隧道模式由服务器开流把请求灌进本地端口，转发模式由 agent 开流把请求交给服务器出网。

## 2. 分层

```
L1 接入层  ingress     :80 明文 / :8443 TLS / :7835 控制面
L2 会话层  session     Hello 握手、token 校验、会话表、子域名分配
L3 复用层  mux         yamux 连接、双向开流、每流一个 HTTP 请求
L4 转发层  forwarding  expose 灌入本地 / forward 解析 path 并出网
L5 基础层  infra       config、logging、tls/acme、error、net
```

依赖方向严格自上而下。L4 不依赖 L1 的具体监听器；L3 不感知 HTTP 语义。

## 3. 协议

### 3.1 控制流

连接建立后 agent 开 stream 0 作为控制流，帧格式：

```
+--------+---------------+------------------+
| type   | len (u32 BE)  | payload (JSON)   |
| 1 byte | 4 bytes       | len bytes        |
+--------+---------------+------------------+
```

| type | 名称 | 方向 | 载荷 |
| --- | --- | --- | --- |
| 0x01 | Hello | agent→server | `{ver, token, mode, want_subdomain?, local_port}` |
| 0x02 | HelloAck | server→agent | `{subdomain, public_url, session_id, heartbeat_secs}` |
| 0x03 | Ping | 双向 | `{}` |
| 0x04 | Pong | 双向 | `{}` |
| 0x05 | Error | server→agent | `{code, message}` |

长度上限 64 KB，超长直接拒绝且不预分配内存。

### 3.2 数据流

每条 yamux 流承载一个 HTTP/1.1 请求-响应对：

```
[1 byte kind][kind=1 时 4 byte len + JSON meta][HTTP/1.1 原始字节...]
```

- `kind=0` expose：server 写请求，agent 以 hyper server 承接并转发到本地端口。
- `kind=1` forward：meta 为 `{target, client_ip}`，agent 写请求，server 出网。

用 HTTP/1.1 over stream 而不是自定义二进制，是因为 hyper 已经处理好 chunked、trailer、流式 body 和 upgrade；自己写等于重造轮子且必在 SSE 上出错。

**开流方向**：expose 由 server 开流，forward 由 agent 开流。

实现细节：yamux 0.12/0.13 没有独立的 `Control` 句柄，开流与收流必须由同一个
持有 `Connection` 的循环来 poll。`src/transport.rs` 用「单任务三事件」的
`poll_fn` 把 `poll_next_inbound` / `poll_new_outbound` / 开流命令通道合在一起，
先 poll 入站以保证 ACK 及时处理。双向开流已由 `tests/spike_yamux.rs` 验证。

### 3.3 状态机

```
Session:   Dialing → Handshaking → Active → Draining → Closed
               └── 失败 ──→ Backoff(1s,2s,4s…30s,±20%) ──→ Dialing

Subdomain: Free → Assigned → Reserved(60s) → Released → Free
                                └─ 同 token 重连 ─→ Assigned
```

## 4. 请求生命周期

### expose

```
accept(TCP) → TLS?(8443) → hyper serve_connection
  → Host 首标签 → registry.lookup
      ├─ miss → 404
      └─ hit  → ctrl.open_stream() → [kind=0][HTTP/1.1]
                → agent serve_connection → connect 127.0.0.1:port
                → 响应流回灌
```

### forward（server 出口）

```
accept(127.0.0.1:1234) → parse_target(path)
  → ctrl.open_stream() → [kind=1][meta][HTTP/1.1]
  → server 侧 SSRF 校验 + pin IP → reqwest 出网 → 响应流回灌
```

### forward（local 出口）

同上，去掉开流，agent 直接 reqwest 出网，不连服务器。

## 5. 关键决策

| 决策 | 选择 | 理由 |
| --- | --- | --- |
| 传输 | TCP + TLS 1.3（rustls/ring） | UDP 在部分网络被限速；TLS 自带加密 |
| 复用 | yamux + 单任务驱动 | 双向开流已验证；比「每连接一条 TCP」省握手，比 QUIC 简单 |
| 控制端口 | 7835 独立 | 443 被既有服务占用，先解耦 |
| 服务器认证 | Hello 帧内 bearer token + 常数时间比较 | TLS 已保证机密性 |
| 服务器证书校验 | SPKI 指纹 TOFU | 控制面走 IP/自签，域名校验不适用 |
| ALPN | 只开 http/1.1 | h2 无 Upgrade（RFC 8441 hyper 不支持），与 WebSocket 冲突 |
| 子域名 | 6 位 31 字符表 | 31^6 ≈ 8.9 亿，够用且好念 |
| 证书 | 通配 + DNS-01 | 随机子域名无法逐张 HTTP-01 |
| 入口 | 80 + 8443 | 443 让给既有服务；80 直接服务不强制跳转 |

## 6. 性能约束

- 出口带宽上行约 3 Mbps：10 MB 响应物理下限 ≈22.5 s，这是链路决定的，不是实现问题。
- 固定 16 KB 读写块（BDP ≈14 KB），放大缓冲只会加剧 bufferbloat。
- 全链路 `TCP_NODELAY`；`SO_SNDBUF/RCVBUF` 保持系统默认。
- yamux：receive_window 256 KB、max_streams 128、split_send_size 16 KB。
- 单核：`worker_threads = 1`，避免上下文切换。
- 响应体全程流式，**禁止 `collect()`**——这是 SSE 能不能用的分界线。

## 7. 安全

| 面 | 措施 |
| --- | --- |
| 控制通道 | TLS 1.3 + token + SPKI 指纹固定 |
| 开放代理 | 非回环监听强制 token；默认仅 127.0.0.1 |
| SSRF | 内网/元数据网段拒绝 + 可选白名单 + 重定向跳数限制 + 解析结果 pin IP |
| 密钥落盘 | 配置与私钥 0600，启动检查权限 |
| 信息泄露 | `Server` 头统一为 `sluice` |
