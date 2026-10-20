//! HTTP/HTTPS 入口：按 `Host` 首标签路由到会话。

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use http::{Request, Response, StatusCode, header::HOST};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::{App, direct, tunnel};
use crate::common::body::{BoxedBody, text};
use crate::common::upgrade;
use crate::config::DirectMode;

/// 健康检查路径，用于外部探测与 benchmark 基线。
pub const HEALTH_PATH: &str = "/__sluice/health";

/// 绑定地址并开始服务。`acceptor` 为 `None` 时是明文 HTTP。
pub async fn serve(
    app: Arc<App>,
    addr: SocketAddr,
    scheme: &'static str,
    acceptor: Option<TlsAcceptor>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    tracing::info!(%local, scheme, "入口就绪");
    serve_listener(app, listener, scheme, acceptor).await
}

/// 使用已绑定的监听器服务（便于测试与 benchmark 用 `:0` 端口）。
pub async fn serve_listener(
    app: Arc<App>,
    listener: TcpListener,
    scheme: &'static str,
    acceptor: Option<TlsAcceptor>,
) -> anyhow::Result<()> {
    loop {
        let (socket, peer) = listener.accept().await?;
        let _ = socket.set_nodelay(true);

        let app = app.clone();
        let acceptor = acceptor.clone();

        tokio::spawn(async move {
            match acceptor {
                None => serve_connection(app, TokioIo::new(socket), peer, scheme).await,
                Some(acceptor) => match acceptor.accept(socket).await {
                    Ok(tls) => serve_connection(app, TokioIo::new(tls), peer, scheme).await,
                    Err(e) => tracing::debug!(%peer, error = %e, "TLS 握手失败"),
                },
            }
        });
    }
}

async fn serve_connection<I>(app: Arc<App>, io: TokioIo<I>, peer: SocketAddr, scheme: &'static str)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |req| {
        let app = app.clone();
        async move { Ok::<_, Infallible>(handle(app, req, peer, scheme).await) }
    });

    // auto Builder 同时承接 HTTP/1.1 与 HTTP/2（TLS 侧 ALPN + preface 嗅探双保险），
    // WebSocket 等升级经 with_upgrades 透传。
    if let Err(e) = auto::Builder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(io, service)
        .await
    {
        tracing::debug!(%peer, error = %e, "连接结束");
    }
}

async fn handle(
    app: Arc<App>,
    mut req: Request<Incoming>,
    peer: SocketAddr,
    scheme: &'static str,
) -> Response<BoxedBody> {
    if req.uri().path() == HEALTH_PATH {
        return text(StatusCode::OK, "ok");
    }

    // 直连转发热词：direct=off 时不拦截，保持隧道语义
    if app.cfg.forward.direct != DirectMode::Off && direct::matches(req.uri().path()) {
        return direct::handle(app, req, peer).await;
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

    let mut response = match tunnel::proxy(&session, req, peer, scheme).await {
        Ok(response) => response,
        Err(e) => {
            tracing::warn!(%subdomain, error = %e, "隧道转发失败");
            return text(StatusCode::BAD_GATEWAY, "Tunnel offline：会话已断开");
        }
    };

    upgrade::bridge_if_upgraded(client_upgrade, &mut response);
    response
}
