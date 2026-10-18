//! 转发模式：本地监听一个端口，把带完整 URL 的请求路径转发到目标。
//!
//! 两种出口：
//! - `server`：请求经 yamux 流交给服务器出网，隐藏本机 IP
//! - `local`：本机直接出网，延迟最低但暴露本机 IP

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use http::{Request, Response, StatusCode, header::AUTHORIZATION};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use yamux::{Mode as YamuxMode, Stream};

use crate::common::body::{BoxError, BoxedBody, text};
use crate::common::headers;
use crate::common::upgrade;
use crate::common::upstream;
use crate::common::urlpath::{self, Target};
use crate::config::EgressMode;
use crate::proto::{self, Frame, Hello, MAX_FRAME_LEN, Mode};
use crate::server::tunnel::KIND_FORWARD;
use crate::transport::{self, MuxHandle};

/// 转发流的元信息，由 agent 写在流首。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ForwardMeta {
    /// 原始请求路径，形如 `/https://host/path`。
    pub path: String,
    /// 调用方地址，仅用于日志。
    pub client_ip: String,
}

enum Egress {
    Local,
    Server { mux: MuxHandle },
}

/// 启动本地转发代理。
pub async fn run(
    server: Option<String>,
    token: Option<String>,
    bind: String,
    port: u16,
    egress: EgressMode,
) -> anyhow::Result<()> {
    let loopback = is_loopback(&bind);
    if !loopback && token.is_none() {
        anyhow::bail!(
            "监听 {bind} 是非回环地址，必须提供 token（--token 或 SLUICE_TOKEN），\
             否则会变成任何人都能用的开放代理"
        );
    }

    let egress = match egress {
        EgressMode::Local => Egress::Local,
        EgressMode::Server => {
            let server = server
                .ok_or_else(|| anyhow::anyhow!("出口设为 server 时必须指定 --server host:7835"))?;
            let token = token
                .clone()
                .ok_or_else(|| anyhow::anyhow!("出口设为 server 时必须提供 token"))?;
            let mux = connect(&server, &token).await?;
            Egress::Server { mux }
        }
    };

    let listener = TcpListener::bind((bind.as_str(), port)).await?;
    println!("转发代理已监听 http://{bind}:{port}");
    println!("用法：curl http://{bind}:{port}/https://api.example.com/path");
    println!("出口：{}", egress_name(&egress));

    // 回环监听不需要请求级鉴权：token 只用于和服务器握手。
    // 一旦监听非回环地址，必须要求调用方带 token，否则就是开放代理。
    let client_token = if loopback { None } else { token.clone() };
    let token = Arc::new(client_token);
    let egress = Arc::new(egress);

    loop {
        let (socket, peer) = listener.accept().await?;
        let _ = socket.set_nodelay(true);
        let token = token.clone();
        let egress = egress.clone();

        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let token = token.clone();
                let egress = egress.clone();
                async move { Ok::<_, Infallible>(handle(req, peer, token, egress).await) }
            });

            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(socket), service)
                .with_upgrades()
                .await
            {
                tracing::debug!(%peer, error = %e, "转发连接结束");
            }
        });
    }
}

fn egress_name(egress: &Egress) -> &'static str {
    match egress {
        Egress::Local => "本机直连",
        Egress::Server { .. } => "经服务器",
    }
}

fn is_loopback(bind: &str) -> bool {
    if bind == "localhost" {
        return true;
    }
    IpAddr::from_str(bind)
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

async fn connect(server: &str, token: &str) -> anyhow::Result<MuxHandle> {
    let socket = TcpStream::connect(server).await?;
    let _ = socket.set_nodelay(true);

    let (mux, _inbound, _join) =
        transport::spawn(socket, YamuxMode::Client, transport::default_config());

    let mut control = transport::into_tokio(mux.open().await?);
    proto::write_frame(
        &mut control,
        &Frame::Hello(Hello::new(token, Mode::Forward)),
    )
    .await?;

    match proto::read_frame(&mut control, MAX_FRAME_LEN).await? {
        Frame::HelloAck(_) => Ok(mux),
        Frame::Error(err) => anyhow::bail!("服务器拒绝：{:?} {}", err.code, err.message),
        other => anyhow::bail!("意外应答：{:?}", other.frame_type()),
    }
}

async fn handle(
    mut req: Request<Incoming>,
    peer: SocketAddr,
    token: Arc<Option<String>>,
    egress: Arc<Egress>,
) -> Response<BoxedBody> {
    if let Some(expected) = token.as_ref()
        && !authorized(&req, expected)
    {
        return text(StatusCode::UNAUTHORIZED, "缺少或错误的 token");
    }

    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    let target = match urlpath::parse_target(&path) {
        Ok(t) => t,
        Err(e) => {
            return text(
                StatusCode::BAD_REQUEST,
                format!("路径解析失败：{e}\n用法：/https://host/path"),
            );
        }
    };

    let client_upgrade = upgrade::take_client(&mut req);

    let (parts, body) = req.into_parts();
    let mut out_headers = parts.headers;
    headers::strip_hop_by_hop(&mut out_headers);
    let rebuilt = {
        let mut builder = Request::builder().method(parts.method).uri(path.clone());
        *builder.headers_mut().expect("builder 在 body 之前总是可写") = out_headers;
        match builder.body(body) {
            Ok(r) => r,
            Err(e) => return text(StatusCode::BAD_REQUEST, format!("请求构造失败：{e}")),
        }
    };

    let result = match egress.as_ref() {
        Egress::Local => upstream::fetch(&target, rebuilt, None).await,
        Egress::Server { mux } => via_server(mux, &target, &path, peer, rebuilt).await,
    };

    let mut response = match result {
        Ok(response) => response,
        Err(e) => {
            tracing::warn!(target = %target.url(), error = %e, "转发失败");
            return text(StatusCode::BAD_GATEWAY, format!("转发失败：{e}"));
        }
    };

    upgrade::bridge_if_upgraded(client_upgrade, &mut response);
    response
}

fn authorized(req: &Request<Incoming>, expected: &str) -> bool {
    if let Some(value) = req.headers().get(AUTHORIZATION)
        && let Ok(text) = value.to_str()
        && let Some(token) = text.strip_prefix("Bearer ")
    {
        return token == expected;
    }
    if let Some(query) = req.uri().query() {
        for pair in query.split('&') {
            if let Some(value) = pair.strip_prefix("__token=") {
                return value == expected;
            }
        }
    }
    false
}

async fn via_server(
    mux: &MuxHandle,
    target: &Target,
    path: &str,
    peer: SocketAddr,
    req: Request<Incoming>,
) -> anyhow::Result<Response<BoxedBody>> {
    let stream: Stream = mux.open().await?;
    let mut io = transport::into_tokio(stream);

    io.write_all(&[KIND_FORWARD]).await?;

    let meta = ForwardMeta {
        path: path.to_string(),
        client_ip: peer.ip().to_string(),
    };
    let payload = serde_json::to_vec(&meta)?;
    io.write_all(&(payload.len() as u32).to_be_bytes()).await?;
    io.write_all(&payload).await?;

    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await?;
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });

    let (parts, body) = req.into_parts();
    let mut headers = parts.headers;
    headers.insert(
        http::header::HOST,
        http::HeaderValue::from_str(&target.authority())
            .map_err(|_| anyhow::anyhow!("非法 Host"))?,
    );

    let mut builder = Request::builder()
        .method(parts.method)
        .uri(target.path_and_query.clone());
    *builder.headers_mut().expect("builder 在 body 之前总是可写") = headers;

    let outbound = builder.body(body.map_err(|e| -> BoxError { Box::new(e) }).boxed())?;
    let response = sender.send_request(outbound).await?;
    Ok(response.map(|b| b.map_err(|e| -> BoxError { Box::new(e) }).boxed()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_detection() {
        assert!(is_loopback("127.0.0.1"));
        assert!(is_loopback("::1"));
        assert!(is_loopback("localhost"));
        assert!(!is_loopback("0.0.0.0"));
        assert!(!is_loopback("192.168.1.10"));
    }

    #[test]
    fn forward_meta_roundtrip() {
        let meta = ForwardMeta {
            path: "/https://example.com/x".into(),
            client_ip: "1.2.3.4".into(),
        };
        let bytes = serde_json::to_vec(&meta).unwrap();
        let back: ForwardMeta = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.path, meta.path);
        assert_eq!(back.client_ip, meta.client_ip);
    }
}
