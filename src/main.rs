//! sluice 命令行入口。只负责参数解析与分发，业务逻辑都在 lib 的模块里。

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use sluice::config::{self, ClientConfig, EgressMode, ServerConfig};

#[derive(Debug, Parser)]
#[command(
    name = "sluice",
    version,
    about = "隧道与路径转发二合一代理",
    long_about = "sluice 把本地端口暴露成公网地址（隧道模式），或把带完整 URL 的请求路径转发到目标站点（转发模式）。"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// 运行服务器端：控制面 + HTTP/HTTPS 入口 + 证书管理
    Server {
        /// 配置文件路径
        #[arg(short, long, env = "SLUICE_CONF", default_value = config::DEFAULT_CONFIG_PATH)]
        config: PathBuf,
    },

    /// 隧道模式：把本地端口暴露成公网地址
    Expose {
        /// 要暴露的本地端口
        port: u16,

        /// 服务器控制面地址，形如 host:7835
        #[arg(short, long, env = "SLUICE_SERVER")]
        server: Option<String>,

        /// 认证 token
        #[arg(short, long, env = "SLUICE_TOKEN")]
        token: Option<String>,

        /// 指定子域名（省略则随机生成）
        #[arg(long)]
        subdomain: Option<String>,
    },

    /// 转发模式：本地监听一个端口，按请求路径里的完整 URL 转发
    Forward {
        /// 本地监听端口
        #[arg(short, long, default_value_t = 1234)]
        port: u16,

        /// 监听地址，默认仅本机
        #[arg(short, long, default_value = "127.0.0.1")]
        bind: String,

        /// 服务器控制面地址
        #[arg(short, long, env = "SLUICE_SERVER")]
        server: Option<String>,

        /// 认证 token
        #[arg(short, long, env = "SLUICE_TOKEN")]
        token: Option<String>,

        /// 出口位置：server（经服务器，隐藏本机 IP）或 local（本机直连）
        #[arg(short, long, value_name = "server|local")]
        egress: Option<String>,
    },

    /// 自检：DNS、端口、证书、权限、内存
    Doctor {
        /// 配置文件路径
        #[arg(short, long, env = "SLUICE_CONF", default_value = config::DEFAULT_CONFIG_PATH)]
        config: PathBuf,
    },

    /// 性能基准，产出 markdown 报告
    Bench {
        /// 报告输出路径
        #[arg(short, long, default_value = "docs/BENCH.md")]
        out: PathBuf,
    },
}

fn main() -> ExitCode {
    init_tracing();

    let cli = Cli::parse();

    let result = match cli.command {
        Command::Server { config } => run_server(&config),
        Command::Expose {
            port,
            server,
            token,
            subdomain,
        } => run_expose(port, server, token, subdomain),
        Command::Forward {
            port,
            bind,
            server,
            token,
            egress,
        } => run_forward(port, &bind, server, token, egress.as_deref()),
        Command::Doctor { config } => run_doctor(&config),
        Command::Bench { out } => run_bench(&out),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // 配置类错误用退出码 2，便于 OpenRC 与脚本区分「配置问题」和「运行期故障」
            if err.downcast_ref::<config::ConfigError>().is_some() {
                eprintln!("配置错误：{err}");
                ExitCode::from(2)
            } else {
                eprintln!("错误：{err:#}");
                ExitCode::FAILURE
            }
        }
    }
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_env("SLUICE_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

fn run_server(path: &Path) -> anyhow::Result<()> {
    let cfg = ServerConfig::load(path)?;
    config::check_permissions(path);

    println!("sluice {} 服务器配置", sluice::VERSION);
    println!("  基础域名   {}", cfg.base_domain);
    println!("  入口地址   http://{}", cfg.listen.http);
    match cfg.listen.https {
        Some(addr) => println!("             https://{addr}"),
        None => println!("             （HTTPS 入口已关闭）"),
    }
    println!("  控制面     {}", cfg.listen.control);
    println!("  证书模式   {:?}", cfg.tls.mode);
    println!("  访问模板   {}/", cfg.public_url_template());
    println!("  token      {}", cfg.token_hint());

    runtime()?.block_on(sluice::server::run(cfg))
}

fn run_expose(
    port: u16,
    server: Option<String>,
    token: Option<String>,
    subdomain: Option<String>,
) -> anyhow::Result<()> {
    let (server, token) = resolve_client(server, token)?;
    runtime()?.block_on(sluice::agent::expose::run(
        &server,
        &token,
        port,
        subdomain,
    ))
}

fn run_forward(
    port: u16,
    bind: &str,
    server: Option<String>,
    token: Option<String>,
    egress: Option<&str>,
) -> anyhow::Result<()> {
    let mut cfg = ClientConfig::load_default();
    cfg.apply_env_overrides();

    let server = server.or(cfg.server);
    let token = token.or(cfg.token);

    let egress = match egress {
        Some("local") => EgressMode::Local,
        Some("server") => EgressMode::Server,
        Some(other) => anyhow::bail!("未知出口 `{other}`，只能是 server 或 local"),
        None => cfg.egress,
    };

    runtime()?.block_on(sluice::agent::forward::run(
        server,
        token,
        bind.to_string(),
        port,
        egress,
    ))
}

fn run_doctor(_path: &Path) -> anyhow::Result<()> {
    anyhow::bail!("doctor 尚未实现（M8）")
}

fn run_bench(_out: &Path) -> anyhow::Result<()> {
    anyhow::bail!("bench 尚未实现（M9）")
}

/// 单核服务器：固定一个 worker，避免线程切换开销。
fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()?)
}

/// 解析客户端连接参数：命令行 > 环境变量 > 配置文件。
fn resolve_client(
    server: Option<String>,
    token: Option<String>,
) -> anyhow::Result<(String, String)> {
    let mut cfg = ClientConfig::load_default();
    cfg.apply_env_overrides();

    let server = server.or(cfg.server).ok_or_else(|| {
        anyhow::anyhow!("缺少服务器地址：用 --server host:7835 指定，或设置 SLUICE_SERVER")
    })?;

    let token = token.or(cfg.token).ok_or_else(|| {
        anyhow::anyhow!("缺少 token：用 --token 指定，或设置 SLUICE_TOKEN")
    })?;

    Ok((server, token))
}
