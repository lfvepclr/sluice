//! 隧道模式：把服务器推来的请求转给本地端口。

use std::convert::Infallible;

use http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use yamux::{Mode as YamuxMode, Stream};

use crate::common::body::{BoxError, BoxedBody, text};
use crate::common::upgrade;
use crate::proto::{self, Frame, Hello, MAX_FRAME_LEN, Mode};
use crate::transport;

/// 连接服务器并把本地端口暴露出去。函数在会话期间一直不返回。
pub async fn run(
    server: &str,
    token: &str,
    local_port: u16,
    want_subdomain: Option<String>,
) -> anyhow::Result<()> {
    let socket = TcpStream::connect(server).await?;
    let _ = socket.set_nodelay(true);

    let (mux, mut inbound, join) =
        transport::spawn(socket, YamuxMode::Client, transport::default_config());

    let mut control = transport::into_tokio(mux.open().await?);
    let mut hello = Hello::new(token, Mode::Expose);
    hello.want_subdomain = want_subdomain;
    hello.local_port = Some(local_port);
    proto::write_frame(&mut control, &Frame::Hello(hello)).await?;

    match proto::read_frame(&mut control, MAX_FRAME_LEN).await? {
        Frame::HelloAck(ack) => {
            println!("✓ {}", ack.public_url);
            println!("  → http://127.0.0.1:{local_port}");
            tracing::info!(url = %ack.public_url, "隧道已建立");
        }
        Frame::Error(err) => {
            anyhow::bail!("服务器拒绝连接：{:?} {}", err.code, err.message);
        }
        other => anyhow::bail!("意外的应答帧：{:?}", other.frame_type()),
    }

    let local = format!("127.0.0.1:{local_port}");

    while let Some(stream) = inbound.recv().await {
        let local = local.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_stream(stream, local).await {
                tracing::debug!(error = %e, "单条隧道流结束");
            }
        });
    }

    let _ = join.await;
    anyhow::bail!("与服务器的连接已断开")
}

async fn serve_stream(stream: Stream, local: String) -> anyhow::Result<()> {
    let mut io = transport::into_tokio(stream);

    let mut kind = [0u8; 1];
    io.read_exact(&mut kind).await?;

    let service = service_fn(move |req| {
        let local = local.clone();
        async move { Ok::<_, Infallible>(forward_local(req, local).await) }
    });

    hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(io), service)
        .with_upgrades()
        .await?;

    Ok(())
}

async fn forward_local(mut req: Request<Incoming>, local: String) -> Response<BoxedBody> {
    let client_upgrade = upgrade::take_client(&mut req);

    let mut response = match try_forward(req, &local).await {
        Ok(response) => response,
        Err(e) => {
            tracing::warn!(%local, error = %e, "本地服务不可达");
            return text(
                StatusCode::BAD_GATEWAY,
                format!("本地服务 {local} 不可达：{e}"),
            );
        }
    };

    upgrade::bridge_if_upgraded(client_upgrade, &mut response);
    response
}

async fn try_forward(req: Request<Incoming>, local: &str) -> anyhow::Result<Response<BoxedBody>> {
    let socket = TcpStream::connect(local).await?;
    let _ = socket.set_nodelay(true);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(socket)).await?;
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });

    let (parts, body) = req.into_parts();
    let path = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    let mut builder = Request::builder().method(parts.method).uri(path);
    *builder.headers_mut().expect("builder 在 body 之前总是可写") = parts.headers;

    let outbound = builder.body(body.map_err(|e| -> BoxError { Box::new(e) }).boxed())?;
    let response = sender.send_request(outbound).await?;
    Ok(response.map(|b| b.map_err(|e| -> BoxError { Box::new(e) }).boxed()))
}
