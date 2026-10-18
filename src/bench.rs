//! 性能基准子命令。
//!
//! 在进程内起一套完整链路（服务器 + expose agent + 两个 forward 代理 + 静态目标），
//! 对五个场景串行采样：
//!
//! | 场景 | 链路 |
//! | --- | --- |
//! | B1 | client → 静态服务（本地直连基线） |
//! | B2 | client → ingress `/__sluice/health`（服务器基线） |
//! | T1 | client → ingress → yamux → expose agent → 静态服务（主场景） |
//! | T2 | client → forward 代理 → yamux → 服务器出网 → 静态服务（主场景） |
//! | T3 | client → forward 代理（local 出口）→ 静态服务（对照） |
//!
//! 每场景先 warmup 再正式采样，报告写入 `docs/BENCH.md`。

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};

use crate::agent::expose;
use crate::agent::forward::{self, Egress};
use crate::config::{DnsKind, ForwardConfig, ListenConfig, ServerConfig, TlsConfig, TlsMode};
use crate::server::ServerHandle;
use crate::sys;

const TOKEN: &str = "bench-token-0123456789abcdef";
const BASE_DOMAIN: &str = "bench.local";
const EXPOSE_SUBDOMAIN: &str = "bench";
const PATH_SMALL: &str = "/1k";
const PATH_BIG: &str = "/1m";
const REQ_TIMEOUT: Duration = Duration::from_secs(10);

/// 采样规模。默认值让整机跑完控制在约 30 秒。
#[derive(Debug, Clone, Copy)]
pub struct Opts {
    /// 预热次数，结果丢弃。
    pub warmup: usize,
    /// 小 payload（1 KiB）正式采样次数。
    pub n_small: usize,
    /// 大 payload（1 MiB）正式采样次数。
    pub n_big: usize,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            warmup: 20,
            n_small: 200,
            n_big: 30,
        }
    }
}

/// 单场景统计。
struct Stat {
    /// 每次请求总耗时。
    lat: Vec<Duration>,
    /// 每次请求 TTFB（响应头到达）。
    ttfb: Vec<Duration>,
    bytes_total: u64,
    /// 场景总耗时（含全部请求）。
    wall: Duration,
    /// 场景期间观测到的峰值 RSS（KiB）。
    rss_kb: u64,
    /// 场景期间观测到的峰值 CPU 占用（%）。
    cpu_pct: f64,
}

impl Stat {
    fn new() -> Self {
        Self {
            lat: Vec::new(),
            ttfb: Vec::new(),
            bytes_total: 0,
            wall: Duration::ZERO,
            rss_kb: 0,
            cpu_pct: 0.0,
        }
    }

    fn req_per_sec(&self) -> f64 {
        if self.wall.is_zero() {
            return 0.0;
        }
        self.lat.len() as f64 / self.wall.as_secs_f64()
    }

    fn mb_per_sec(&self) -> f64 {
        if self.wall.is_zero() {
            return 0.0;
        }
        self.bytes_total as f64 / (1024.0 * 1024.0) / self.wall.as_secs_f64()
    }
}

fn pct(v: &[Duration], p: f64) -> Duration {
    if v.is_empty() {
        return Duration::ZERO;
    }
    let mut sorted = v.to_vec();
    sorted.sort();
    let idx = ((sorted.len() as f64) * p).ceil() as usize;
    sorted[idx.saturating_sub(1).min(sorted.len() - 1)]
}

/// 一个场景的请求描述。
struct Scenario {
    name: &'static str,
    addr: SocketAddr,
    /// Host 头（ingress 按它路由子域名）。
    host: String,
    /// 路径前缀（forward 代理在路径里携带完整目标 URL）。
    prefix: String,
}

/// 运行全部场景并生成报告。
pub async fn run(out: &Path, opts: Opts) -> Result<()> {
    println!("==> 搭建链路");
    let bench = Bench::start().await?;

    println!(
        "==> 采样（warmup={} small={} big={}）",
        opts.warmup, opts.n_small, opts.n_big
    );
    let mut stats = Vec::new();
    for scenario in bench.scenarios() {
        let small = sample(&scenario, PATH_SMALL, opts.warmup, opts.n_small).await;
        let big = sample(&scenario, PATH_BIG, 2, opts.n_big).await;
        println!(
            "    {} 完成：1KiB p50={:?}  1MiB p50={:?}",
            scenario.name,
            pct(&small.lat, 0.5),
            pct(&big.lat, 0.5)
        );
        stats.push((scenario.name, small, big));
    }

    bench.server.shutdown().await;

    println!("==> 写报告 {}", out.display());
    let report = render(&stats, &opts);
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(out, report.as_bytes())
        .map_err(|e| anyhow::anyhow!("写报告失败 {}: {e}", out.display()))?;
    println!("==> 完成");
    Ok(())
}

async fn sample(scenario: &Scenario, path: &str, warmup: usize, n: usize) -> Stat {
    let mut stat = Stat::new();

    let rss_before = sys::rss_kib().unwrap_or(0);
    let cpu_before = sys::cpu_pct().unwrap_or(0.0);
    let started = Instant::now();
    let full_path = format!("{}{path}", scenario.prefix);

    for i in 0..warmup + n {
        let record = i >= warmup;
        match request_once(scenario.addr, &scenario.host, &full_path).await {
            Ok((ttfb, total, bytes)) => {
                if record {
                    stat.lat.push(total);
                    stat.ttfb.push(ttfb);
                    stat.bytes_total += bytes as u64;
                }
            }
            Err(e) => {
                if record {
                    tracing::warn!(scenario = scenario.name, error = %e, "采样请求失败");
                }
            }
        }
    }

    stat.wall = started.elapsed();
    stat.rss_kb = sys::rss_kib().unwrap_or(0).max(rss_before);
    stat.cpu_pct = sys::cpu_pct().unwrap_or(0.0).max(cpu_before);
    stat
}

// ───────────────────────── 链路搭建 ─────────────────────────

struct Bench {
    server: ServerHandle,
    /// 静态目标服务地址。
    target: SocketAddr,
    /// forward 代理（server 出口）。
    fwd_server: SocketAddr,
    /// forward 代理（local 出口）。
    fwd_local: SocketAddr,
    /// expose 会话的服务循环（保活 mux 驱动并处理入站流）。
    _serve: tokio::task::JoinHandle<anyhow::Result<()>>,
}

const SMALL_BODY: [u8; 1024] = [0x61; 1024];
static BIG_BODY: [u8; 1024 * 1024] = [0x62; 1024 * 1024];

/// 静态目标：按路径返回固定内容（`/1k`、`/1m`）。
async fn serve_static(listener: TcpListener) {
    loop {
        let Ok((socket, _)) = listener.accept().await else {
            break;
        };
        let _ = socket.set_nodelay(true);
        tokio::spawn(async move {
            let service = service_fn(|req: Request<hyper::body::Incoming>| async move {
                let body: &'static [u8] = match req.uri().path() {
                    PATH_BIG => &BIG_BODY,
                    _ => &SMALL_BODY,
                };
                Ok::<_, std::convert::Infallible>(
                    http::Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/octet-stream")
                        .body(http_body_util::Full::new(bytes::Bytes::from_static(body)))
                        .unwrap(),
                )
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(socket), service)
                .await;
        });
    }
}

impl Bench {
    async fn start() -> Result<Self> {
        // 1. 静态目标服务
        let target_listener = TcpListener::bind("127.0.0.1:0").await?;
        let target = target_listener.local_addr()?;
        tokio::spawn(serve_static(target_listener));

        // 2. 服务器（自签证书、随机端口、允许转发私有网段以便打到本机目标）
        let cfg = ServerConfig {
            base_domain: BASE_DOMAIN.into(),
            token: TOKEN.into(),
            dns_token: Some("bench-dns-token".into()),
            public_ip: None,
            listen: ListenConfig {
                control: "127.0.0.1:0".parse().unwrap(),
                http: "127.0.0.1:0".parse().unwrap(),
                https: None,
            },
            tls: TlsConfig {
                mode: TlsMode::SelfSigned,
                email: None,
                dns: DnsKind::Duckdns,
                cert_dir: std::env::temp_dir().join("sluice-bench-certs"),
            },
            forward: ForwardConfig {
                allow_private: true,
                allow_hosts: Vec::new(),
                max_body_mib: 100,
            },
            limits: Default::default(),
        };
        let server = ServerHandle::start(cfg).await?;

        // 3. expose agent：把静态目标暴露成 bench.<base_domain>
        let session = expose::connect(
            &server.control.to_string(),
            TOKEN,
            target.port(),
            Some(EXPOSE_SUBDOMAIN.into()),
        )
        .await?;
        // 会话必须真的在服务：不跑 serve() 就没人处理入站流，请求会全部超时
        let _serve = tokio::spawn(session.serve());

        // 4. forward 代理 ×2
        let egress_server = forward::connect_egress(&server.control.to_string(), TOKEN).await?;
        let fwd_server = spawn_forward(egress_server).await?;
        let fwd_local = spawn_forward(Egress::Local).await?;

        Ok(Bench {
            server,
            target,
            fwd_server,
            fwd_local,
            _serve,
        })
    }

    fn scenarios(&self) -> Vec<Scenario> {
        let ingress = self.server.http;
        let host = format!("{EXPOSE_SUBDOMAIN}.{BASE_DOMAIN}");
        vec![
            Scenario {
                name: "B1",
                addr: self.target,
                host: self.target.to_string(),
                prefix: String::new(),
            },
            Scenario {
                name: "B2",
                addr: ingress,
                host: ingress.to_string(),
                prefix: String::new(),
            },
            Scenario {
                name: "T1",
                addr: ingress,
                host: host.clone(),
                prefix: String::new(),
            },
            Scenario {
                name: "T2",
                addr: self.fwd_server,
                host: self.fwd_server.to_string(),
                prefix: format!("/http://{}", self.target),
            },
            Scenario {
                name: "T3",
                addr: self.fwd_local,
                host: self.fwd_local.to_string(),
                prefix: format!("/http://{}", self.target),
            },
        ]
    }
}

async fn spawn_forward(egress: Egress) -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(forward::serve_listener(
        listener,
        Arc::new(None),
        Arc::new(egress),
    ));
    Ok(addr)
}

/// 发一次请求，返回 (TTFB, 总耗时, 响应字节数)。
async fn request_once(
    addr: SocketAddr,
    host: &str,
    path: &str,
) -> Result<(Duration, Duration, usize)> {
    let started = Instant::now();

    let socket = tokio::time::timeout(REQ_TIMEOUT, TcpStream::connect(addr)).await??;
    let _ = socket.set_nodelay(true);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(socket)).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let request = Request::builder()
        .method("GET")
        .uri(path)
        .header("host", host)
        .body(http_body_util::Empty::<bytes::Bytes>::new())?;

    let response = tokio::time::timeout(REQ_TIMEOUT, sender.send_request(request)).await??;
    let ttfb = started.elapsed();

    let body: bytes::Bytes = tokio::time::timeout(REQ_TIMEOUT, response.into_body().collect())
        .await??
        .to_bytes();
    let total = started.elapsed();

    Ok((ttfb, total, body.len()))
}

// ───────────────────────── 报告 ─────────────────────────

fn git_commit() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn now_string() -> String {
    std::process::Command::new("date")
        .arg("+%Y-%m-%d %H:%M")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn render(stats: &[(&'static str, Stat, Stat)], opts: &Opts) -> String {
    let mut out = String::new();
    out.push_str("# sluice 性能基准\n\n");
    out.push_str("## 环境\n\n");
    out.push_str(&format!("- 日期：{}\n", now_string()));
    out.push_str(&format!(
        "- 平台：{} {}\n",
        std::env::consts::OS,
        std::env::consts::ARCH
    ));
    out.push_str(&format!(
        "- 版本：sluice {} @ {}\n",
        crate::VERSION,
        git_commit()
    ));
    out.push_str(&format!(
        "- 规模：warmup {} + 正式 {}（1 KiB）/ {}（1 MiB），串行采样\n",
        opts.warmup, opts.n_small, opts.n_big
    ));
    out.push_str("- 说明：本机 in-process 链路，无真实网络；真实链路数据见部署后的补充章节。\n\n");

    out.push_str("## 小 payload（1 KiB）\n\n");
    out.push_str("| 场景 | n | p50 | p95 | p99 | req/s | TTFB p50 | 峰值 RSS | 峰值 CPU |\n");
    out.push_str("| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n");
    for (name, small, _) in stats {
        out.push_str(&format!(
            "| {name} | {} | {:?} | {:?} | {:?} | {:.0} | {:?} | {} KiB | {:.1}% |\n",
            small.lat.len(),
            pct(&small.lat, 0.5),
            pct(&small.lat, 0.95),
            pct(&small.lat, 0.99),
            small.req_per_sec(),
            pct(&small.ttfb, 0.5),
            small.rss_kb,
            small.cpu_pct,
        ));
    }

    out.push_str("\n## 大 payload（1 MiB）\n\n");
    out.push_str("| 场景 | n | p50 | p95 | 吞吐 | TTFB p50 |\n");
    out.push_str("| --- | --- | --- | --- | --- | --- |\n");
    for (name, _, big) in stats {
        out.push_str(&format!(
            "| {name} | {} | {:?} | {:?} | {:.2} MB/s | {:?} |\n",
            big.lat.len(),
            pct(&big.lat, 0.5),
            pct(&big.lat, 0.95),
            big.mb_per_sec(),
            pct(&big.ttfb, 0.5),
        ));
    }

    // 结论行：T1−B1、T2 vs T3
    let find = |key: &str| stats.iter().find(|(n, _, _)| *n == key);
    out.push_str("\n## 结论\n\n");
    if let (Some((_, b1, _)), Some((_, t1, _))) = (find("B1"), find("T1")) {
        let delta =
            pct(&t1.lat, 0.5).as_secs_f64() * 1000.0 - pct(&b1.lat, 0.5).as_secs_f64() * 1000.0;
        out.push_str(&format!(
            "- T1 相对 B1 的 p50 增量：{delta:+.2} ms（隧道开销）\n"
        ));
    }
    if let (Some((_, t2, _)), Some((_, t3, _))) = (find("T2"), find("T3")) {
        out.push_str(&format!(
            "- T2（server 出口）p50 {:?} vs T3（local 出口）p50 {:?}：多一跳的代价\n",
            pct(&t2.lat, 0.5),
            pct(&t3.lat, 0.5),
        ));
    }
    if let Some((_, b2, _)) = find("B2") {
        out.push_str(&format!(
            "- B2（ingress health）p50 {:?}，作为服务器基线\n",
            pct(&b2.lat, 0.5),
        ));
    }

    out.push_str("\n## 方法\n\n");
    out.push_str("- 每请求新建 TCP 连接，测量响应头到达（TTFB）与响应体收完（总耗时）。\n");
    out.push_str(
        "- B2 走 `/__sluice/health`（2 字节响应），大 payload 表中它的吞吐列不具比较意义。\n",
    );
    out.push_str("- RSS / CPU 在场景首尾用 `ps` 采样取峰值；串行执行避免相互干扰。\n");
    out.push_str("- 复现：`cargo run --release -- bench --out docs/BENCH.md`。\n");

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_of_trivial_inputs() {
        let v = vec![Duration::from_millis(1); 10];
        assert_eq!(pct(&v, 0.5), Duration::from_millis(1));
        // 空输入不 panic
        assert_eq!(pct(&[], 0.99), Duration::ZERO);
    }

    #[test]
    fn stat_rates_guard_zero_wall() {
        let stat = Stat::new();
        assert_eq!(stat.req_per_sec(), 0.0);
        assert_eq!(stat.mb_per_sec(), 0.0);
    }
}
