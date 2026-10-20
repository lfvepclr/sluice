//! 服务器端：控制面、入口路由、隧道转发。
//!
//! `ServerHandle::start` 负责绑定与任务编排，`run` 只是在它之上等待退出信号——
//! 这样测试与 bench 可以在进程内起一个完整服务器。

pub mod acme;
pub mod certgen;
pub mod control;
pub mod direct;
pub mod dnstxt;
pub mod forward;
pub mod ingress;
pub mod tls;
pub mod tunnel;

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::config::ServerConfig;

/// 进程级共享状态。
pub struct App {
    pub cfg: Arc<ServerConfig>,
    pub registry: Arc<control::Registry>,
}

/// 运行中的服务器：监听地址（`:0` 会回填实际端口）+ 全部后台任务。
pub struct ServerHandle {
    /// 控制面地址（agent 连这里）。
    pub control: SocketAddr,
    /// HTTP 入口地址。
    pub http: SocketAddr,
    /// HTTPS 入口地址（未启用时为 `None`）。
    pub https: Option<SocketAddr>,
    pub app: Arc<App>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl ServerHandle {
    /// 启动服务器。监听地址取自 `cfg.listen`，绑 `:0` 可以拿到随机端口。
    pub async fn start(cfg: ServerConfig) -> anyhow::Result<Self> {
        let app = Arc::new(App {
            cfg: Arc::new(cfg),
            registry: Arc::new(control::Registry::new()),
        });

        let (cert_store, acme_bootstrap) = build_cert_store(&app.cfg)?;

        let control_listener = TcpListener::bind(app.cfg.listen.control).await?;
        let control = control_listener.local_addr()?;
        let http_listener = TcpListener::bind(app.cfg.listen.http).await?;
        let http = http_listener.local_addr()?;

        let https_listener = match app.cfg.listen.https {
            Some(addr) => {
                let listener = TcpListener::bind(addr).await?;
                let addr = listener.local_addr()?;
                Some((listener, addr))
            }
            None => None,
        };
        let https = https_listener.as_ref().map(|(_, addr)| *addr);
        let https_acceptor: Option<TlsAcceptor> = match &https_listener {
            Some(_) => Some(tls::acceptor(cert_store.clone())?),
            None => None,
        };

        // ACME 后台任务要在进入事件循环之前启动，否则监听不退出就永远轮不到它
        if app.cfg.tls.mode == crate::config::TlsMode::Acme {
            acme::spawn(app.cfg.clone(), cert_store.clone(), acme_bootstrap);
        }

        let mut tasks = Vec::new();
        // 控制面用独立的长效自签证书：入口证书走 ACME 续期时会换 SPKI，
        // 若与控制面共用，所有 pin 过指纹的 agent 会集体失联。
        let control_wildcard = format!("*.{}", app.cfg.base_domain);
        let control_store = tls::CertStore::self_signed(
            &[
                app.cfg.base_domain.as_str(),
                control_wildcard.as_str(),
                "localhost",
            ],
            3650,
        )?;
        let control_acceptor = Some(tls::acceptor(control_store)?);
        let control_app = app.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(e) =
                control::serve_listener(control_app, control_listener, control_acceptor).await
            {
                tracing::error!(error = %e, "控制面任务出错");
            }
        }));

        let ingress_app = app.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = ingress::serve_listener(ingress_app, http_listener, "http", None).await
            {
                tracing::error!(error = %e, "HTTP 入口任务出错");
            }
        }));

        if let (Some((listener, _)), Some(acceptor)) = (https_listener, https_acceptor) {
            let https_app = app.clone();
            tasks.push(tokio::spawn(async move {
                if let Err(e) =
                    ingress::serve_listener(https_app, listener, "https", Some(acceptor)).await
                {
                    tracing::error!(error = %e, "HTTPS 入口任务出错");
                }
            }));
        }

        Ok(Self {
            control,
            http,
            https,
            app,
            tasks,
        })
    }

    /// 停止全部监听任务。
    pub async fn shutdown(mut self) {
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }
}

/// 启动服务器：控制面 + HTTP/HTTPS 入口，等待退出信号。
pub async fn run(cfg: ServerConfig) -> anyhow::Result<()> {
    let template = cfg.public_url_template();
    let handle = ServerHandle::start(cfg).await?;

    println!("sluice {} 服务器启动", crate::VERSION);
    println!("  访问模板   http://{template}/");

    // 监听任务异常退出时各自打日志并结束进程由 OpenRC 兜底重启
    tokio::signal::ctrl_c().await.ok();
    tracing::info!("收到退出信号，正在关闭");

    handle.shutdown().await;
    Ok(())
}

/// 按 `tls.mode` 准备证书。
fn build_cert_store(cfg: &ServerConfig) -> anyhow::Result<(Arc<tls::CertStore>, bool)> {
    use crate::config::TlsMode;

    let wildcard = format!("*.{}", cfg.base_domain);

    match cfg.tls.mode {
        TlsMode::SelfSigned => {
            tracing::warn!("使用自签证书：浏览器会提示不安全，仅适合本地联调");
            let store = tls::CertStore::self_signed(
                &[cfg.base_domain.as_str(), wildcard.as_str(), "localhost"],
                365,
            )?;
            Ok((store, false))
        }
        TlsMode::Files => {
            let (chain, key) = tls::load_files(&cfg.tls.cert_dir)?;
            Ok((tls::CertStore::from_der_chain(chain, key)?, false))
        }
        TlsMode::Acme => {
            // 有缓存证书就直接用，后台再按剩余天数决定是否续期
            if let Ok((chain, key)) = tls::load_files(&cfg.tls.cert_dir) {
                return Ok((tls::CertStore::from_der_chain(chain, key)?, false));
            }
            // 没有证书：先用 7 天自签顶住，后台立即签发并热替换
            tracing::warn!("尚无证书，先用临时自签证书，后台正在向 Let's Encrypt 申请");
            let store = tls::CertStore::self_signed(
                &[cfg.base_domain.as_str(), wildcard.as_str(), "localhost"],
                7,
            )?;
            Ok((store, true))
        }
    }
}
