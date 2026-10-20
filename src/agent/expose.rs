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

/// 已建立的 expose 会话：握手完成，等待入站流并转发到本地端口。
pub struct ExposeSession {
    /// 服务器的握手应答（含分配的子域名与公网地址）。
    pub ack: proto::HelloAck,
    /// 保活多路复用驱动：句柄被丢弃时驱动循环会退出、连接随即关闭。
    _mux: transport::MuxHandle,
    inbound: tokio::sync::mpsc::UnboundedReceiver<yamux::Stream>,
    join: tokio::task::JoinHandle<()>,
    local_port: u16,
}

impl ExposeSession {
    /// 消费会话：逐条把入站流转发到本地端口，直到与服务器断开。
    pub async fn serve(mut self) -> anyhow::Result<()> {
        let local = format!("127.0.0.1:{}", self.local_port);

        while let Some(stream) = self.inbound.recv().await {
            let local = local.clone();
            tokio::spawn(async move {
                if let Err(e) = serve_stream(stream, local).await {
                    tracing::debug!(error = %e, "单条隧道流结束");
                }
            });
        }

        let _ = self.join.await;
        anyhow::bail!("与服务器的连接已断开")
    }
}

/// 连接服务器并完成握手，返回可服务的会话。
pub async fn connect(
    server: &str,
    token: &str,
    local_port: u16,
    want_subdomain: Option<String>,
) -> anyhow::Result<ExposeSession> {
    let expected_pin = std::env::var("SLUICE_SPKI_SHA256").ok();
    let (socket, pin) = crate::agent::tls::connect_retry(server, expected_pin.as_deref()).await?;
    if expected_pin.is_none() {
        tracing::info!(pin = %pin, "服务器证书指纹（写入 SLUICE_SPKI_SHA256 可固定）");
    }

    let (mux, inbound, join) =
        transport::spawn(socket, YamuxMode::Client, transport::default_config());

    let mut control = transport::into_tokio(mux.open().await?);
    let mut hello = Hello::new(token, Mode::Expose);
    hello.want_subdomain = want_subdomain;
    hello.local_port = Some(local_port);
    proto::write_frame(&mut control, &Frame::Hello(hello)).await?;

    let ack = match proto::read_frame(&mut control, MAX_FRAME_LEN).await? {
        Frame::HelloAck(ack) => {
            println!("✓ {}", ack.public_url);
            println!("  → http://127.0.0.1:{local_port}");
            tracing::info!(url = %ack.public_url, "隧道已建立");
            ack
        }
        Frame::Error(err) => {
            anyhow::bail!("服务器拒绝连接：{:?} {}", err.code, err.message);
        }
        other => anyhow::bail!("意外的应答帧：{:?}", other.frame_type()),
    };

    Ok(ExposeSession {
        ack,
        _mux: mux,
        inbound,
        join,
        local_port,
    })
}

/// 连接服务器并把本地端口暴露出去。函数在会话期间一直不返回。
pub async fn run(
    server: &str,
    token: &str,
    local_port: u16,
    want_subdomain: Option<String>,
) -> anyhow::Result<()> {
    connect(server, token, local_port, want_subdomain)
        .await?
        .serve()
        .await
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
