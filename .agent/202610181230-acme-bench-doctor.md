# sluice 收尾：ACME / bench / doctor / 构建

> 归档：执行时复制为 `<repo>/.agent/202610181230-acme-bench-doctor.md`
> 凭证、域名、服务器地址不入库；运行时由 `SLUICE_BASE_DOMAIN` / `SLUICE_DNS_TOKEN` 注入。

---

## 0. 已完成（不要重做）

- P0 门禁：纯 Rust TLS 全绿（`rustls-rustcrypto` + `x509-cert` + `p256`），依赖树无 ring / aws-lc-rs
- P1 WebSocket：101 + 回显打通，`strip_hop_by_hop_preserving_upgrade` 修复 Upgrade 头被误删
- 8443 TLS 入口 + `CertStore`（ArcSwap 热替换）+ 证书公私钥配对校验
- 控制通道 TLS + SPKI 指纹固定（`SLUICE_SPKI_SHA256`）
- 6 个 commit 已推送，67 单测 + 6 集成测试全绿

**关键结论**：`instant-acme 0.8.5` 用 `default-features = false, features = ["hyper-rustls"]` **不会**拉 ring / aws-lc-rs；`finalize_csr(&[u8])` 存在且不受 rcgen 门控 → 可用自建 CSR 走纯 Rust 路线。

---

## 1. 先修一个设计缺陷：控制面证书独立

现状 `control` 与 `https` 共用同一个 `CertStore`。ACME 每 60 天续期会改变控制面证书的 SPKI，**所有 pin 过的 agent 会集体失联**。

- `server/mod.rs::build_cert_store` 拆成两个：`ingress_store`（按 `tls.mode`）与 `control_store`（固定自签，10 年）。
- `control::serve` 用 `control_store` 的 acceptor；`ingress::serve` 用 `ingress_store`。

**验收**：`openssl s_client -connect :8443` 与 `-connect :7835` 的证书指纹不同；替换 ingress 证书后控制面指纹不变。

---

## 2. ACME 自动签发（`src/server/acme.rs` 新增）

依赖：`instant-acme = { version = "0.8", default-features = false, features = ["hyper-rustls"] }`。

```rust
pub struct Issued { pub cert_der: Vec<u8>, pub key_der: Vec<u8> }
pub fn spawn(cfg: Arc<ServerConfig>, store: Arc<CertStore>, bootstrap: bool) -> JoinHandle<()>;
async fn issue(cfg: &ServerConfig) -> Result<Issued>;
async fn account(cfg: &ServerConfig) -> Result<Account>;
fn build_csr(wildcard: &str) -> Result<(Vec<u8>, Vec<u8>)>;   // (csr_der, pkcs8_der)
async fn duckdns_set(label: &str, token: &str, txt: Option<&str>) -> Result<()>;
async fn wait_txt(fqdn: &str, expect: &str, budget: Duration) -> Result<()>;
pub fn days_left(cert_der: &[u8]) -> Result<i64>;
fn write_secure(path: &Path, bytes: &[u8]) -> Result<()>;     // 0600
```

流程要点：

1. **先 `crypto::install()`**——instant-acme 内部用 `ClientConfig::builder()`，没装 provider 会运行时 panic。
2. 目录选择：`SLUICE_ACME_DIRECTORY` > `SLUICE_ACME_STAGING=1 ? Staging : Production`。账号存 `cert_dir/account.json`（含 directory），目录变更则重建。
3. **只签 `*.base`，不带 apex**：两者 DNS-01 都落在 `_acme-challenge.base` 同一名字，DuckDNS 一名只存一条 TXT，必然互相覆盖。
4. DuckDNS：`GET https://www.duckdns.org/update?domains={首标签}&token={t}&txt={v}`，响应必须等于 `OK`；清理用 `&txt=&clear=true`。
5. 传播等待：`GET https://dns.google/resolve?name=_acme-challenge.{base}&type=TXT`，比对 `Answer[].data`（去引号），5s 一次、总 120s、单请求 5s 超时。复用 `common/upstream.rs` 新增的 `pub async fn get_text(url, timeout) -> Result<String>`。
6. 自建 CSR：`RequestBuilder::new(Name::from_str("CN=*.base")?, &signer)` + `add_extension(&SubjectAltName(..))` + `build::<DerSignature>()` → `to_der()`。
7. `finalize_csr(&csr_der)` → 轮询 Valid → `certificate()` 拿 PEM 链 → 解析叶子 DER → **先落盘再 `store.replace`**。
8. 续期：`days_left < 30` 立即签，之后 6h 巡检；失败退避 60s·2ⁿ 上限 6h，±20% 抖动；`tokio::sync::Mutex` 保证单飞。

`server/mod.rs`：`build_cert_store` 返回 `(store, bootstrap: bool)`；Acme 分支有缓存证书→`false`，无→先用 7 天自签并置 `true`，由 `acme::spawn` 后台签发后热替换。

**验收**：`cargo test --test acme_units`（CSR SAN、DuckDNS URL 拼接、DoH 解析、超时路径，全部用本地 mock）；真实签发手工跑 staging 一次，再切 production。

---

## 3. benchmark（`src/bench.rs`）

前置改造：

- `control::serve_listener(app, listener, acceptor)`（与 ingress 对称）。
- `server::ServerHandle { control, http, app, tasks }` + `start(cfg) -> Result<Self>`，全部绑 `127.0.0.1:0` 并回填 `local_addr`；`shutdown()` 用 abort。
- `agent::expose` 拆 `connect(...) -> ExposeSession`（含 ack / mux / inbound / join）与 `ExposeSession::serve()`；`run()` 变薄包装。
- `agent::forward` 暴露 `serve_listener(listener, token, egress)` 与 `connect_egress(...)`，`Egress` 改 `pub`。

场景（bench 配置：`SelfSigned` + `https: None` + `forward.allow_private = true`）：

| 场景 | 链路 |
| --- | --- |
| B1 | client → 静态服务 |
| B2 | client → ingress `/__sluice/health` |
| T1 | ingress（Host `bench.bench.local`）→ yamux → expose → 静态服务 |
| T2 | forward → yamux → 服务器出网 → 静态服务 |
| T3 | forward（egress local）→ 静态服务 |


```rust
pub struct Stat { name, n, lat: Vec<Duration>, ttfb: Vec<Duration>, bytes, wall, rss_kb, cpu_pct }
fn pct(v: &mut [Duration], p: f64) -> Duration;   // 排序后 (n*p).ceil()-1
```

规模：warmup 20 丢弃 + 正式 200 次（1 KiB）；1 MiB 场景 30 次；串行、单请求 10s 超时。目标本机 30s 内跑完。
RSS：macOS `ps -o rss= -p <pid>`，Linux `/proc/self/status` 的 `VmRSS`；CPU 场景首尾采样取峰值。

报告 `docs/BENCH.md`：环境头 → 五场景表（p50/p95/p99、req/s、TTFB p50、峰值 RSS）→ 「T1−B1 增量」「T2 vs T3」→ 方法说明。

**验收**：`cargo run --release -- bench --out docs/BENCH.md` 产出完整表格；`tests/bench_smoke.rs`（n=20）只断言五场景齐全与字段完整。

---

## 4. doctor（`src/doctor.rs`）

```rust
pub enum Level { Ok, Warn, Fail }
pub struct Check { name: &'static str, level: Level, detail: String }
pub async fn run(cfg: &ServerConfig, cfg_path: &Path) -> Result<Vec<Check>>;
pub fn print(checks: &[Check], tty: bool);
```

检查项：配置 `validate()`；文件权限（`mode & 0o077 != 0` → Warn）；DNS 解析与 `public_ip` 比对；80/8443/7835 逐个 `bind` 后立即 drop（`AddrInUse` → Warn，`PermissionDenied` → Fail）；证书剩余天数（<30 Warn，<7 Fail）；RSS（信息项）；443 是否被既有服务占用（connect 探测，仅提示）。

退出码：有 Fail → 1，仅 Warn → 0，配置错误 → 2。非 TTY（`std::io::IsTerminal`）关颜色、纯行输出。

**验收**：`cargo run -- doctor -c dev/server.local.toml; echo $?`；`cargo run -- < /dev/null | head -5` 不阻塞。

---

## 5. musl 构建（现在应该不需要 zig）

纯 Rust 依赖树 → 直接 `rust-lld`：

```
[target.x86_64-unknown-linux-musl]
linker = "rust-lld"
```

`scripts/build-musl.sh` 改为 `cargo build --release --target x86_64-unknown-linux-musl`，去掉 zig 检查，保留 `file` 静态链接断言。

**验收**：`file target/x86_64-unknown-linux-musl/release/sluice` 含 `statically linked`；`cargo tree -i ring` 无输出。

---

## 6. 服务器验证（不打扰线上）

约束：只用 80/8443/7835，不碰 443、不重启既有服务、不跑 `apk -U upgrade`。

1. 静态二进制 + `deploy/install.sh` 部署，`rc-service sluice status` 确认。
2. `curl -k https://<server>:8443/__sluice/health` 验证外网可达（若被安全组挡住，记录到 doctor 提示）。
3. 真实链路跑一遍 bench（B2/T1/T2），数据补进 `docs/BENCH.md` 单独一节，标注单核与带宽。
4. ACME 真实签发：staging 通过后切 production，`openssl s_client` 校验证书链。

---

## 7. 风险

| 风险 | 处理 |
| --- | --- |
| `rustls-platform-verifier` 在 musl 下编译失败 | 改用 `webpki-roots` 自建 ClientConfig，或给 instant-acme 打 feature 补丁 |
| `instant-acme` 0.8 的 `authorizations()`/`set_challenge_ready` 名称与预期不符 | 以 `cargo doc` 为准，先写最小签发脚本验证 |
| DuckDNS TXT 传播慢 | 预算 120s + 每 5s 轮询；超时给出明确提示 |
| 单核服务器编译/压测 OOM | 只在服务器跑二进制，不编译；bench 串行 |
| ACME 换证影响已 pin 的 agent | 已在 §1 用独立控制面证书解决 |


---

## 8. 提交节奏

每个里程碑：`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check` 全绿后提交，中文 conventional commit。提交前跑密钥检查（`.key` / `.pem` / `.env` / `local.toml` 必须为空）。