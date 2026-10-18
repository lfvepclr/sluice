//! HTTP 入口：按 `Host` 首标签路由到会话。

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use http::{Request, Response, StatusCode, header::HOST};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use super::{App, tunnel};
use crate::common::body::{BoxedBody, text};
use crate::common::upgrade;

/// 健康检查路径，用于外部探测与 benchmark 基线。
pub const HEALTH_PATH: &str = "/__sluice/health";

/// 监听并服务 HTTP 入口。
pub async fn serve(app: Arc<App>, addr: SocketAddr) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "HTTP 入口就绪");

    loop {
        let (socket, peer) = listener.accept().await?;
        let _ = socket.set_nodelay(true);

        let app = app.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let app = app.clone();
                async move { Ok::<_, Infallible>(handle(app, req, peer).await) }
            });

            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(socket), service)
                .with_upgrades()
                .await
            {
                tracing::debug!(%peer, error = %e, "连接结束");
            }
        });
    }
}

async fn handle(
    app: Arc<App>,
    mut req: Request<Incoming>,
    peer: SocketAddr,
) -> Response<BoxedBody> {
    if req.uri().path() == HEALTH_PATH {
        return text(StatusCode::OK, "ok");
    }

    let Some(host) = req
        .headers()
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase())
    else {
        return text(StatusCode::BAD_REQUEST, "缺少 Host 头");
    };

    // 去掉可能的端口后缀，取第一段标签作为子域名
    let hostname = host.split(':').next().unwrap_or("");
    let subdomain = hostname.split('.').next().unwrap_or("");

    let Some(session) = app.registry.get(subdomain) else {
        return text(
            StatusCode::NOT_FOUND,
            format!(
                "子域名 `{subdomain}` 未分配。确认 agent 已启动，且 base_domain 与客户端一致。"
            ),
        );
    };

    if !session.is_online() {
        return text(
            StatusCode::BAD_GATEWAY,
            "Tunnel offline：会话已断开，子域名保留中，等待 agent 重连",
        );
    }

    let client_upgrade = upgrade::take_client(&mut req);

    let mut response = match tunnel::proxy(&session, req, peer, "http").await {
        Ok(response) => response,
        Err(e) => {
            tracing::warn!(%subdomain, error = %e, "隧道转发失败");
            return text(StatusCode::BAD_GATEWAY, "Tunnel offline：会话已断开");
        }
    };

    upgrade::bridge_if_upgraded(client_upgrade, &mut response);
    response
}
