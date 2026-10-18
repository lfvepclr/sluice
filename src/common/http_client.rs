//! 极简 HTTP 客户端，供 ACME 与 DoH 使用。
//!
//! 只处理「小请求、小响应」：把响应体收完再返回。不复用 `upstream::fetch`，
//! 因为那个入口绑定在 hyper 的 `Incoming` 上，不适合发程序自己构造的请求。

use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use http::{HeaderMap, Method, Request, StatusCode, header::HOST};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use url::Url;

/// 一次完整响应。
pub struct Response {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl Response {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }
}

/// 发一个请求并把响应体读完。
pub async fn request(
    method: Method,
    url: &str,
    headers: &[(&str, String)],
    body: Option<Bytes>,
    timeout: Duration,
) -> Result<Response> {
    let parsed = Url::parse(url).with_context(|| format!("非法 URL：{url}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL 缺少主机名：{url}"))?
        .to_string();
    let port = parsed.port_or_known_default().unwrap_or(443);
    let https = parsed.scheme() == "https";

    let socket = tokio::time::timeout(timeout, TcpStream::connect((host.as_str(), port)))
        .await
        .map_err(|_| anyhow::anyhow!("连接 {host}:{port} 超时"))?
        .with_context(|| format!("连接 {host}:{port} 失败"))?;
    let _ = socket.set_nodelay(true);

    let path = match parsed.query() {
        Some(q) => format!("{}?{q}", parsed.path()),
        None => parsed.path().to_string(),
    };

    let fut = async move {
        if https {
            let tls = crate::common::upstream::tls_connect(socket, &host).await?;
            send(tls, method, &host, &path, headers, body).await
        } else {
            send(socket, method, &host, &path, headers, body).await
        }
    };

    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| anyhow::anyhow!("请求 {url} 超时"))?
}

async fn send<T>(
    io: T,
    method: Method,
    host: &str,
    path: &str,
    headers: &[(&str, String)],
    body: Option<Bytes>,
) -> Result<Response>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = Request::builder().method(method).uri(path);
    builder = builder.header(HOST, host);
    for (name, value) in headers {
        builder = builder.header(*name, value);
    }

    let payload = Full::new(body.unwrap_or_default());
    let request = builder.body(payload)?;

    let response = sender.send_request(request).await?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await?.to_bytes();

    Ok(Response {
        status,
        headers,
        body,
    })
}
