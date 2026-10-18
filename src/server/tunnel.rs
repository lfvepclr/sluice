//! 隧道转发：把外部请求写进 yamux 流，交给 agent。

use std::net::SocketAddr;

use http::{Request, Response, header::HOST};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use tokio::io::AsyncWriteExt;

use super::control::Session;
use crate::common::body::{BoxError, BoxedBody};
use crate::common::headers;
use crate::transport;

/// 流首字节：隧道模式（服务器开流）。
pub const KIND_EXPOSE: u8 = 0;
/// 流首字节：转发模式（agent 开流，带目标元信息）。
pub const KIND_FORWARD: u8 = 1;

/// 把一个外部请求代理到 agent，并返回上游响应。
pub async fn proxy(
    session: &Session,
    req: Request<Incoming>,
    peer: SocketAddr,
    scheme: &'static str,
) -> anyhow::Result<Response<BoxedBody>> {
    let stream = session.mux.open().await?;
    let mut io = transport::into_tokio(stream);

    // 先写流类型，agent 据此决定怎么处理后续字节
    io.write_all(&[KIND_EXPOSE]).await?;

    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await?;
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });

    let (parts, body) = req.into_parts();
    let mut out_headers = parts.headers;

    let original_host = out_headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();

    headers::strip_hop_by_hop_preserving_upgrade(&mut out_headers);
    headers::append_forwarded_for(&mut out_headers, peer.ip());
    headers::set_forwarded_proto(&mut out_headers, scheme);
    if !original_host.is_empty() {
        headers::set_forwarded_host(&mut out_headers, &original_host);
    }

    let path = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    let mut builder = Request::builder().method(parts.method).uri(path);
    *builder.headers_mut().expect("builder 在 body 之前总是可写") = out_headers;

    let outbound = builder.body(body.map_err(|e| -> BoxError { Box::new(e) }).boxed())?;

    let response = sender.send_request(outbound).await?;
    Ok(response.map(|b| b.map_err(|e| -> BoxError { Box::new(e) }).boxed()))
}
