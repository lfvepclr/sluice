//! 出网客户端：把解析后的目标请求发出去。
//!
//! 不用 reqwest：它的 `rustls-tls` 默认拉 `aws-lc-rs`（C + cmake），会破坏
//! 交叉编译的简单性。这里直接用 hyper + tokio-rustls + webpki-roots，
//! 与隧道侧复用同一套 HTTP 栈。

use std::sync::{Arc, Once};
use std::time::Duration;

use http::{Request, Response, header::HOST};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use super::body::{BoxError, BoxedBody};
use super::urlpath::{Scheme, Target};

/// 连接超时：3 Mbps 链路下 10 秒足够，太长只会让调用方干等。
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

fn install_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// 按目标发起请求，返回上游响应（body 保持流式）。
///
/// `pin` 用于把 SSRF 校验时解析出的 IP 固定下来，避免「校验用的 IP」与
/// 「连接用的 IP」不一致（DNS rebinding）。
pub async fn fetch(
    target: &Target,
    req: Request<Incoming>,
    pin: Option<std::net::IpAddr>,
) -> anyhow::Result<Response<BoxedBody>> {
    let port = target.effective_port();
    let host = target.host.trim_start_matches('[').trim_end_matches(']');
    let addr = match pin {
        Some(ip) => format!("{ip}:{port}"),
        None => format!("{host}:{port}"),
    };

    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&addr))
        .await
        .map_err(|_| anyhow::anyhow!("连接 {addr} 超时"))??;
    let _ = tcp.set_nodelay(true);

    match target.scheme {
        Scheme::Http => send(tcp, target, req).await,
        Scheme::Https => {
            let tls = tls_connect(tcp, host).await?;
            send(tls, target, req).await
        }
    }
}

async fn tls_connect(
    tcp: TcpStream,
    host: &str,
) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    install_provider();

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| anyhow::anyhow!("非法的主机名：{host}"))?;

    Ok(connector.connect(server_name, tcp).await?)
}

async fn send<T>(io: T, target: &Target, req: Request<Incoming>) -> anyhow::Result<Response<BoxedBody>>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await?;
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });

    let (parts, body) = req.into_parts();
    let mut headers = parts.headers;
    headers.insert(
        HOST,
        http::HeaderValue::from_str(&target.authority())
            .map_err(|_| anyhow::anyhow!("非法的 Host 头：{}", target.authority()))?,
    );

    let mut builder = Request::builder()
        .method(parts.method)
        .uri(target.path_and_query.clone());
    *builder
        .headers_mut()
        .expect("builder 在 body 之前总是可写") = headers;

    let outbound = builder.body(body.map_err(|e| -> BoxError { Box::new(e) }).boxed())?;
    let response = sender.send_request(outbound).await?;
    Ok(response.map(|b| b.map_err(|e| -> BoxError { Box::new(e) }).boxed()))
}
