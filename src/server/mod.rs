//! 服务器端：控制面、入口路由、隧道转发。
//!
//! M4 阶段只做明文 HTTP 入口；8443 的 TLS 入口与 ACME 在 M6 接入，届时只需
//! 把 `serve` 的 IO 换成 TLS 流，路由逻辑完全复用。

pub mod certgen;
pub mod control;
pub mod forward;
pub mod ingress;
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

    if app.cfg.listen.https.is_some() {
        tracing::warn!("HTTPS 入口尚未实现（M6），当前只有 HTTP 入口；控制通道也是明文");
    }

    let control_app = app.clone();
    let ingress_app = app.clone();

    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async move { control::serve(control_app, control_addr).await });
    tasks.spawn(async move { ingress::serve(ingress_app, http_addr).await });

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
