//! 服务器端：控制面、入口路由、隧道转发。
//!
//! M4 阶段只做明文 HTTP 入口；8443 的 TLS 入口与 ACME 在 M6 接入，届时只需
//! 把 `serve` 的 IO 换成 TLS 流，路由逻辑完全复用。

pub mod acme;
pub mod certgen;
pub mod control;
pub mod forward;
pub mod ingress;
pub mod tls;
pub mod tunnel;

use std::sync::Arc;

use crate::config::ServerConfig;

/// 进程级共享状态。
pub struct App {
    pub cfg: Arc<ServerConfig>,
    pub registry: Arc<control::Registry>,
}

/// 启动服务器：控制面 + HTTP 入口，等待退出信号。
pub async fn run(cfg: ServerConfig) -> anyhow::Result<()> {
    let control_addr = cfg.listen.control;
    let http_addr = cfg.listen.http;
    let template = cfg.public_url_template();

    let app = Arc::new(App {
        cfg: Arc::new(cfg),
        registry: Arc::new(control::Registry::new()),
    });

    println!("sluice {} 服务器启动", crate::VERSION);
    println!("  访问模板   http://{template}/");

    let (cert_store, acme_bootstrap) = build_cert_store(&app.cfg)?;

    let control_app = app.clone();
    let ingress_app = app.clone();
    let https_app = app.clone();
    let https_acceptor = match &app.cfg.listen.https {
        Some(_) => Some(tls::acceptor(cert_store.clone())?),
        None => None,
    };
    let https_addr = app.cfg.listen.https;

    // ACME 后台任务要在进入事件循环之前启动，否则监听不退出就永远轮不到它
    if app.cfg.tls.mode == crate::config::TlsMode::Acme {
        acme::spawn(app.cfg.clone(), cert_store.clone(), acme_bootstrap);
    }

    let mut tasks = tokio::task::JoinSet::new();
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
    tasks.spawn(async move { control::serve(control_app, control_addr, control_acceptor).await });
    tasks.spawn(async move { ingress::serve(ingress_app, http_addr, "http", None).await });
    if let (Some(addr), Some(acceptor)) = (https_addr, https_acceptor) {
        tasks.spawn(async move { ingress::serve(https_app, addr, "https", Some(acceptor)).await });
    }

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("收到退出信号，正在关闭");
        }
        Some(result) = tasks.join_next() => {
            match result {
                Ok(Ok(())) => tracing::warn!("某个监听任务提前结束"),
                Ok(Err(e)) => tracing::error!(error = %e, "监听任务出错"),
                Err(e) => tracing::error!(error = %e, "监听任务 panic"),
            }
        }
    }

    tasks.shutdown().await;
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
            let (cert, key) = tls::load_files(&cfg.tls.cert_dir)?;
            Ok((tls::CertStore::from_der(cert, key)?, false))
        }
        TlsMode::Acme => {
            // 有缓存证书就直接用，后台再按剩余天数决定是否续期
            if let Ok((cert, key)) = tls::load_files(&cfg.tls.cert_dir) {
                return Ok((tls::CertStore::from_der(cert, key)?, false));
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
