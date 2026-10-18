# sluice 收尾计划：M5 / M6 / M8 / M9

> 归档位置：执行时复制到 `<repo>/.agent/202610181215-remaining-milestones.md`
> 约定：**所有计划文档统一放项目 `.agent/` 目录，文件名前缀 `YYYYMMDDHHMM`**。
> **本文件不含任何凭证、域名、服务器地址**：这些一律通过环境变量在运行时注入，见 §10。

---

## 0. 先修正现有代码与文档的 6 处冲突

| # | 问题 | 位置 | 处理 |
| --- | --- | --- | --- |
| 1 | `strip_hop_by_hop` 无条件删 `connection`/`upgrade`，WebSocket 握手必坏 | `src/common/headers.rs:37`、`server/tunnel.rs:48` | 新增保留升级语义的变体，见 P1 |
| 2 | 注释写「设为 false 可关闭 HTTPS」，字段却是 `Option<SocketAddr>` | `src/config.rs:107` | 自定义 `deserialize_with` 支持 `false` |
| 3 | ARCHITECTURE 声称控制通道有 TLS + SPKI 固定，实际是裸 TCP、token 明文 | `src/server/control.rs` | P2 补上 |
| 4 | 文档写 forward meta 是 `{target, client_ip}`，代码是 `{path, client_ip}` | `ARCHITECTURE.md` §3.2 | 改文档 |
| 5 | `max_streams_per_session` / `max_body_mib` 只校验不生效 | `transport::default_config` | 从配置注入 |
| 6 | `rust-version = "1.85"`，rcgen 0.14 要 1.88 | `Cargo.toml` | 若走纯 Rust 路线则不需要 rcgen，保持 1.85 |


---

## 1. P0 门禁：纯 Rust TLS 可行性 spike（**先做，决定后续全部路线**）

用户要求不引入 C 依赖（不用 zig、不用 ring）。必须先证明这条路成立，否则一切白写。

### 1.1 要验证的四件事

写 `tests/spike_pure_tls.rs`，逐条断言：

1. `rustls-rustcrypto` 0.0.2-alpha 能编译，且能与 `rustls` 0.23 的 `CryptoProvider` API 对接。
2. 用它起一个 **TLS 1.3 服务端**，客户端用同一 provider 握手成功。
3. 用纯 Rust 生成自签证书（`x509-cert` builder + `p256`），rustls 能加载并完成握手。
4. `cargo tree -i ring` **无输出**（证明整棵依赖树没有 ring）。

### 1.2 依赖清单（仅 spike 用）

```
rustls = { version = "0.23", default-features = false, features = ["std", "tls12"] }
rustls-rustcrypto = "0.0.2-alpha"
x509-cert = { version = "0.2", features = ["builder"] }
p256 = { version = "0.13", features = ["ecdsa", "pkcs8"] }
signature = "2"
spki = "0.7"
der = "0.7"
rand_core = { version = "0.6", features = ["getrandom"] }
```

### 1.3 门禁判定

- **全绿** → 进入 P2 的纯 Rust 实现。
- **任一条失败** → **立即停止，附上失败证据（编译错误 / 握手错误 / `cargo tree` 输出）向用户汇报**，并给出两个备选：手动装 zig（不动 brew），或服务器上 rustup 编译。不再自行猜测。

> 已知风险，写进计划不是免责：`rustls-rustcrypto` 最后更新 2024-04，版本号 `0.0.2-alpha`，且 `rcgen` 无纯 Rust 后端（这正是不用 rcgen、改手写 X.509 的原因）。ACME 的 `instant-acme` 默认依赖 `rcgen`，纯 Rust 路线下必须用 `finalize_csr` + 自建 CSR，或自己写最小 ACME 客户端。

---

## 2. P1 M5：WebSocket 升级

### 2.1 改动

```rust
// src/common/headers.rs
pub fn wants_upgrade(h: &HeaderMap) -> bool;
pub fn strip_hop_by_hop_preserving_upgrade(h: &mut HeaderMap);

// src/transport.rs
pub fn bridge<A, B>(a: A, b: B) -> JoinHandle<io::Result<u64>>
where A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
      B: AsyncRead + AsyncWrite + Unpin + Send + 'static;
```

`bridge` 内部 `copy_bidirectional(&mut TokioIo::new(a), &mut TokioIo::new(b))`——`Upgraded` 只实现 hyper 的 rt trait，必须先包 `TokioIo`。

### 2.2 四个桥接点

统一模式：请求进代理前 `hyper::upgrade::on(&mut req)` 拿客户端句柄，响应回来从 extensions 取 `OnUpgrade`，两者都拿到就 spawn `bridge`。

- `server/ingress.rs::handle`（外部 ↔ 隧道）
- `agent/expose.rs::serve_stream`（隧道 ↔ 本地）
- `server/forward.rs::handle`（隧道 ↔ 出网）
- `agent/forward.rs::handle`（外部 ↔ 隧道/直连）

### 2.3 验收

`tests/ws_upgrade.rs`（dev-dep `tokio-tungstenite = "0.24"`）：起 ws echo、`ServerHandle::start` 绑 0 端口、agent 连上去，客户端 `connect_async` 断言 101 + `Sec-WebSocket-Accept` + 1 KiB 回显一致；负例断言普通 `strip_hop_by_hop` 仍然剥离 upgrade。

```sh
cargo test --test ws_upgrade
```

---

## 3. P2 M6：TLS + 证书

### 3.1 模块

```
src/server/tls.rs      CertStore（ArcSwap）+ ResolvesServerCert + 自签/文件加载
src/server/certgen.rs  纯 Rust 自签证书生成（x509-cert + p256）
src/server/acme.rs     DNS-01 + DuckDNS + DoH 传播轮询
```

```rust
// tls.rs
pub struct CertStore { /* ArcSwap<CertifiedKey> + ArcSwap<SystemTime> */ }
impl CertStore {
    pub fn new(cert_pem: &str, key_pem: &str) -> anyhow::Result<Arc<Self>>;
    pub fn replace(&self, cert_pem: &str, key_pem: &str) -> anyhow::Result<SystemTime>;
    pub fn days_left(&self) -> i64;
}
impl rustls::server::ResolvesServerCert for CertStore { /* 恒返回当前证书 */ }
pub fn acceptor(store: Arc<CertStore>) -> tokio_rustls::TlsAcceptor;
pub fn load_files(dir: &Path) -> anyhow::Result<(String, String)>; // fullchain.pem + privkey.pem
```

- `ServerConfig` 只构建一次，用 `with_cert_resolver(store)`；换证只 `ArcSwap::store`，不重建 config、不重绑监听。
- 续期任务：`sleep_until(not_after - 30d)`，成功后 `replace`，失败退避 1h；启动时 `days_left() < 30` 立即续。

### 3.2 8443 复用路由

```rust
pub async fn serve_listener<S, A, F>(app, listener: TcpListener, scheme: &'static str, accept: A)
where A: Fn(TcpStream, SocketAddr) -> F + Clone + Send + 'static,
      F: Future<Output = io::Result<S>> + Send,
      S: AsyncRead + AsyncWrite + Unpin + Send + 'static;
```

`handle` 增加 `scheme` 参数（现在硬编码 `"http"`，8443 必须传 `"https"`，否则 `X-Forwarded-Proto` 全错）。

### 3.3 控制通道也上 TLS

`control::serve(app, listener, Option<TlsAcceptor>)`；agent 侧用 `ClientConfig.spki_sha256` 做 TOFU：首连记录、之后比对、不匹配拒绝并提示 `--accept-new-pin`。

### 3.4 ACME（凭证已就绪，可端到端验证）

- 基础域名与 DNS token 通过 `SLUICE_BASE_DOMAIN` / `SLUICE_DNS_TOKEN` 注入，**不落盘、不入库**。
- 只申请 `*.base`，一条 authorization，天然无并发 TXT 冲突。
- DuckDNS：`GET https://www.duckdns.org/update?domains={sub}&token={t}&txt={v}`，响应必须为 `OK`，签完 `clear=true`。
- 传播等待：DoH JSON（`dns.google/resolve`，备选 `cloudflare-dns.com`），5s 一次、总超时 120s，命中才 `set_ready()`。
- 账号凭据存 `cert_dir/account.json`（0600），复用避免撞账号限速。
- 验证顺序：先打 Let's Encrypt **staging**（`LetsEncrypt::Staging.url()`）确认全流程，再切 production，避免撞生产限速。

### 3.5 验收

```sh
cargo test --test cert_store          # 自签证书 SAN、公私钥不匹配报错、not_after 解析
cargo test --test tls_ingress         # 8443 握手 + X-Forwarded-Proto=https + 热替换后指纹变化
curl -sk --http1.1 https://127.0.0.1:8443/__sluice/health -H 'Host: x.bench.local'
```

---

## 4. P3 M8：doctor + 向导

```rust
// src/doctor.rs
pub enum Status { Ok, Warn, Fail, Skip }
pub struct Check { name: &'static str, status: Status, detail: String, hint: Option<String> }
pub async fn run(cfg_path: &Path) -> anyhow::Result<Vec<Check>>;
pub fn render(checks: &[Check]) -> String;

// src/sys.rs（零 unsafe）
pub fn rss_kib() -> Option<u64>;   // macOS: ps -o rss= -p PID；Linux: /proc/self/status
pub fn cpu_ticks() -> Option<u64>;
```

检查项：DNS 指向、80/8443/7835 端口占用、证书剩余天数、配置权限、RSS、既有服务存活。

向导：`main` 的 `command` 改 `Option<Command>`；`None` 且非 TTY → 打印帮助并返回，**绝不进 dialoguer**（非 TTY 会挂）。

```sh
cargo run -- doctor -c dev/server.toml; echo $?   # Fail→1, Warn→0, 配置错→2
cargo run -- < /dev/null | head -5                # 非 TTY 打帮助
```

---

## 5. P4 M9：benchmark

### 5.1 可测试的启动器

```rust
pub struct ServerHandle { http: SocketAddr, https: Option<SocketAddr>, control: SocketAddr, .. }
impl ServerHandle { pub async fn start(cfg: ServerConfig) -> Result<Self>; pub async fn shutdown(self); }
pub async fn agent::expose::connect(server, token, port, want) -> Result<(HelloAck, JoinHandle<()>)>;
```

监听端口写 `:0`，回填 `local_addr()`。

### 5.2 场景与指标

B1 本地直连 / B2 公网直连静态 / T1 expose / T2 forward-server / T3 forward-local。
每场景 warmup 100 + 正式 1000 次，payload 1 KiB / 64 KiB；采集 p50/p95/p99、MB/s、TTFB（首帧时刻）、RSS、CPU。
报告 `docs/BENCH.md`：硬件/日期/commit、方法学、五场景表、结论。

```sh
cargo run --release -- bench --out docs/BENCH.md
cargo test --test bench_smoke      # n=20，只断言场景齐全与字段完整
```

---

## 6. 性能验证口径（用户已定：服务器）

本地先跑通功能与 smoke bench；**真实链路数据在服务器上取**，约束：

1. 只用 **80 / 8443 / 7835**，绝不监听 443，不重启、不修改既有代理服务。
2. 不执行 `apk -U upgrade`（可能影响既有服务），只做 `apk add` 必要包。
3. 单核：benchmark 期间不并发跑既有服务的大流量任务，报告注明环境。
4. 服务器只放静态二进制，不在上面编译（除非 P0 门禁失败且用户改选该路线）。

---

## 7. 测试矩阵

| 文件 | 覆盖 |
| --- | --- |
| `tests/ws_upgrade.rs` | 101 握手、回显、Accept 头、头剥离负例 |
| `tests/cert_store.rs` | 自签 SAN、密钥不匹配、not_after 解析、热替换 |
| `tests/tls_ingress.rs` | 8443 握手、X-Forwarded-Proto、SPKI 固定 |
| `tests/doctor.rs` | 六项检查与退出码 |
| `tests/bench_smoke.rs` | 五场景齐全、报告字段完整 |
| 现有 62 单测 + `tests/spike_yamux.rs` | 回归 |


每个里程碑结束必须：`cargo test` 全绿、`cargo clippy --all-targets -- -D warnings`、`cargo fmt --check`。

---

## 8. 计划归档规范（用户要求）

1. 执行第一步：`mkdir -p .agent`，把本计划复制为 `.agent/202610181145-remaining-milestones.md`。
2. 把已有的 `.agents/plans/20261018-sluice.md` 迁移为 `.agent/202610181030-initial-plan.md`，删除空的 `.agents/`。
3. 之后每个里程碑的独立计划/报告也放 `.agent/`，命名 `YYYYMMDDHHMM-<slug>.md`。
4. `AGENTS.md` 的文档地图同步更新为新路径。

---

## 9. 风险与停止条件

| 风险 | 触发条件 | 处理 |
| --- | --- | --- |
| `rustls-rustcrypto` 不可用 | P0 门禁任一条失败 | **停止并汇报**，附证据与备选（zig / 服务器编译） |
| 纯 Rust X.509 生成过于复杂 | certgen 超过 200 行仍握手失败 | 停止，汇报是否接受 rcgen+ring |
| ACME 撞限速 | staging 通过、production 失败 | 检查账号复用与订单频率，退避重试 |
| 8443 外网不可达 | 服务器实测不通 | 记录并在 `doctor` 里给出明确提示 |
| 单核编译 OOM | 若改走服务器编译 | 先加 512MB swap |


---

## 10. 凭证与隐私（硬约束）

1. **任何凭证、域名、服务器地址都不写入仓库**：包括本计划、`design.md`、`ARCHITECTURE.md`、`docs/*`、示例配置。
2. 运行期一律通过环境变量注入：`SLUICE_BASE_DOMAIN`、`SLUICE_DNS_TOKEN`、`SLUICE_SERVER`、`SLUICE_TOKEN`。
3. 本地验证用的配置放 `dev/server.local.toml`，该路径已在 `.gitignore` 中（`server.toml` 规则覆盖），文件权限 0600。
4. 提交前检查：`git status --porcelain | grep -E '(\.key|\.pem|\.env|local\.toml)` 必须为空。
5. **建议在验证完成后轮换 DNS token**：它已在聊天中出现过，属于已暴露凭证。轮换只需在 DuckDNS 后台重置，然后更新环境变量。