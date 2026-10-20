//! 端到端测试：两个方向的数据面全链路（真实 TCP/TLS/yamux，无 mock）。
//!
//! forward 方向：本地调用方 → forward 代理 → yamux（agent→server 开流）
//!               → server SSRF 关卡 → 外网 target
//! expose 方向： 外部调用方 → ingress(HTTP/HTTPS) → yamux（server→agent 开流）
//!               → agent → 本地 target
//!
//! 用例清单见 `.agent/202610201030-e2e-test-plan.md`。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use sluice::agent::expose;
use sluice::agent::forward;
use sluice::config::{
    DirectMode, DnsKind, ForwardConfig, ListenConfig, ServerConfig, TlsConfig, TlsMode,
};
use sluice::server::ServerHandle;

const TOKEN: &str = "e2e-token-0123456789abcdef";
const BASE: &str = "e2e.local";
const MIB: usize = 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(15);

// ───────────────────────── 基础设施 ─────────────────────────

/// 本地 target：`/echo` POST 回显、`/1m` 1 MiB 下行、其余 200 "e2e-ok"。
async fn spawn_target() -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            let _ = socket.set_nodelay(true);
            tokio::spawn(async move {
                let service = service_fn(|req: Request<hyper::body::Incoming>| async move {
                    let response = match (req.method(), req.uri().path()) {
                        (&Method::POST, "/echo") => {
                            let bytes = req.into_body().collect().await.unwrap().to_bytes();
                            http::Response::new(Full::new(bytes))
                        }
                        (_, "/1m") => {
                            http::Response::new(Full::new(bytes::Bytes::from(vec![0x5au8; MIB])))
                        }
                        _ => http::Response::new(Full::new(bytes::Bytes::from_static(b"e2e-ok"))),
                    };
                    Ok::<_, std::convert::Infallible>(response)
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(socket), service)
                    .await;
            });
        }
    });
    Ok(addr)
}

/// 带身份标签的本地 target：所有响应都携带 tag 前缀/填充，
/// 用于多主机隔离测试——任何跨主机串流都会表现为标签错位。
///
/// `/id` 返回 `target-<tag>`；`/echo` POST 返回 `<tag> ++ payload`；`/1m` 返回 tag 填充。
async fn spawn_target_tagged(tag: u8) -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            let _ = socket.set_nodelay(true);
            tokio::spawn(async move {
                let service = service_fn(|req: Request<hyper::body::Incoming>| async move {
                    let response = match (req.method(), req.uri().path()) {
                        (&Method::POST, "/echo") => {
                            let bytes = req.into_body().collect().await.unwrap().to_bytes();
                            let mut tagged = vec![tag];
                            tagged.extend_from_slice(&bytes);
                            http::Response::new(Full::new(bytes::Bytes::from(tagged)))
                        }
                        (_, "/1m") => {
                            http::Response::new(Full::new(bytes::Bytes::from(vec![tag; MIB])))
                        }
                        (_, "/id") => http::Response::new(Full::new(bytes::Bytes::from(format!(
                            "target-{}",
                            tag as char
                        )))),
                        _ => http::Response::new(Full::new(bytes::Bytes::from_static(b"e2e-ok"))),
                    };
                    Ok::<_, std::convert::Infallible>(response)
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(socket), service)
                    .await;
            });
        }
    });
    Ok(addr)
}

async fn start_server(https: bool, allow_private: bool) -> Result<ServerHandle> {
    start_server_direct(https, allow_private, DirectMode::Off).await
}

async fn start_server_direct(
    https: bool,
    allow_private: bool,
    direct: DirectMode,
) -> Result<ServerHandle> {
    let cfg = ServerConfig {
        base_domain: BASE.into(),
        token: TOKEN.into(),
        dns_token: None,
        public_ip: None,
        listen: ListenConfig {
            control: "127.0.0.1:0".parse().unwrap(),
            http: "127.0.0.1:0".parse().unwrap(),
            https: if https {
                Some("127.0.0.1:0".parse().unwrap())
            } else {
                None
            },
        },
        tls: TlsConfig {
            mode: TlsMode::SelfSigned,
            email: None,
            dns: DnsKind::Duckdns,
            cert_dir: std::env::temp_dir().join("sluice-e2e-certs"),
        },
        forward: ForwardConfig {
            allow_private,
            allow_hosts: Vec::new(),
            max_body_mib: 100,
            direct,
        },
        limits: Default::default(),
    };
    ServerHandle::start(cfg).await
}

/// 建立 expose 会话并后台服务。返回 JoinHandle 便于在保留期用例中 abort。
async fn start_expose(
    server: &ServerHandle,
    local_port: u16,
    subdomain: &str,
) -> Result<tokio::task::JoinHandle<anyhow::Result<()>>> {
    let session = expose::connect(
        &server.control.to_string(),
        TOKEN,
        local_port,
        Some(subdomain.into()),
    )
    .await?;
    Ok(tokio::spawn(session.serve()))
}

/// forward 代理（server 出口）。
async fn start_forward(server: &ServerHandle) -> Result<SocketAddr> {
    let egress = forward::connect_egress(&server.control.to_string(), TOKEN).await?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(forward::serve_listener(
        listener,
        Arc::new(None),
        Arc::new(egress),
    ));
    Ok(addr)
}

/// forward 代理（local 出口，不经过服务器）。
async fn start_forward_local() -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(forward::serve_listener(
        listener,
        Arc::new(None),
        Arc::new(forward::Egress::Local),
    ));
    Ok(addr)
}

// ───────────────────────── HTTP 客户端 ─────────────────────────

#[derive(Debug, Clone, Copy)]
enum Scheme {
    Http,
    Https,
}

/// 接受任意服务端证书（测试自签入口；等价于 agent 侧的 TOFU 首连语义）。
#[derive(Debug)]
struct AcceptAny;

impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// 测试用 IO：明文 TCP 或 TLS 流的统一封装。
enum TestIo {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl tokio::io::AsyncRead for TestIo {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            TestIo::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            TestIo::Tls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for TestIo {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            TestIo::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            TestIo::Tls(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            TestIo::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            TestIo::Tls(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            TestIo::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            TestIo::Tls(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// 发一次请求，返回 (状态码, body)。
async fn http_once(
    scheme: Scheme,
    addr: SocketAddr,
    host: &str,
    method: Method,
    path: &str,
    body: Option<Vec<u8>>,
) -> Result<(StatusCode, Vec<u8>)> {
    http_once_auth(scheme, addr, host, method, path, body, None).await
}

/// 同 [`http_once`]，可附带 `Authorization: Bearer` 头（直连转发 token 档用）。
async fn http_once_auth(
    scheme: Scheme,
    addr: SocketAddr,
    host: &str,
    method: Method,
    path: &str,
    body: Option<Vec<u8>>,
    bearer: Option<&str>,
) -> Result<(StatusCode, Vec<u8>)> {
    let socket = tokio::time::timeout(TIMEOUT, TcpStream::connect(addr)).await??;
    let _ = socket.set_nodelay(true);

    let io = match scheme {
        Scheme::Http => TestIo::Plain(socket),
        Scheme::Https => {
            sluice::common::crypto::install();
            let config =
                rustls::ClientConfig::builder_with_provider(sluice::common::crypto::provider())
                    .with_safe_default_protocol_versions()?
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(AcceptAny))
                    .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(config));
            let name = rustls::pki_types::ServerName::try_from(host.to_string())?;
            let tls = tokio::time::timeout(TIMEOUT, connector.connect(name, socket)).await??;
            TestIo::Tls(Box::new(tls))
        }
    };

    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let builder = Request::builder()
        .method(method)
        .uri(path)
        .header("host", host);
    let builder = match bearer {
        Some(t) => builder.header("authorization", format!("Bearer {t}")),
        None => builder,
    };
    let request = match body {
        Some(b) => builder
            .header("content-length", b.len())
            .body(Full::new(bytes::Bytes::from(b)))?,
        None => builder.body(Full::new(bytes::Bytes::new()))?,
    };

    let response = tokio::time::timeout(TIMEOUT, sender.send_request(request)).await??;
    let status = response.status();
    let bytes = response.into_body().collect().await?.to_bytes();
    Ok((status, bytes.to_vec()))
}

/// 带形状的 1 MiB payload（位置相关，防止纯重复字节掩盖错位）。
fn shaped_payload() -> Vec<u8> {
    (0..MIB).map(|i| (i % 251) as u8).collect()
}

// ───────────────────────── T1 expose 方向 ─────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t1_expose_full_chain() {
    let target = spawn_target().await.unwrap();
    let server = start_server(true, false).await.unwrap();
    let ingress = server.http;
    let ingress_tls = server.https.unwrap();
    let host = "app1.e2e.local";

    let app1 = start_expose(&server, target.port(), "app1").await.unwrap();

    // 1.1 HTTP 入口 GET
    let (st, body) = http_once(Scheme::Http, ingress, host, Method::GET, "/", None)
        .await
        .unwrap();
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, b"e2e-ok");

    // 1.2 HTTPS 入口 GET（自签链）
    let (st, body) = http_once(Scheme::Https, ingress_tls, host, Method::GET, "/", None)
        .await
        .unwrap();
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, b"e2e-ok");

    // 1.3 POST 1 MiB 上行回显
    let payload = shaped_payload();
    let (st, body) = http_once(
        Scheme::Http,
        ingress,
        host,
        Method::POST,
        "/echo",
        Some(payload.clone()),
    )
    .await
    .unwrap();
    assert_eq!(st, StatusCode::OK, "POST 回显应成功");
    assert_eq!(body, payload, "1 MiB 上行回显必须逐字节一致");

    // 1.4 GET 1 MiB 下行
    let (st, body) = http_once(Scheme::Http, ingress, host, Method::GET, "/1m", None)
        .await
        .unwrap();
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body.len(), MIB);

    // 1.5 未注册子域名 → 404
    let (st, _) = http_once(
        Scheme::Http,
        ingress,
        "nobody.e2e.local",
        Method::GET,
        "/",
        None,
    )
    .await
    .unwrap();
    assert_eq!(st, StatusCode::NOT_FOUND);

    // 1.7 target 无人监听 → 502（agent 在，但本地端口不通）
    let _app2 = start_expose(&server, 1, "app2").await.unwrap();
    let (st, _) = http_once(
        Scheme::Http,
        ingress,
        "app2.e2e.local",
        Method::GET,
        "/",
        None,
    )
    .await
    .unwrap();
    assert_eq!(st, StatusCode::BAD_GATEWAY);
    drop(_app2);

    // 1.6 agent 断开后保留期 → 502
    app1.abort(); // abort 掉 serve 任务 → ExposeSession 连同 mux 一起释放
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (st, _) = http_once(Scheme::Http, ingress, host, Method::GET, "/", None)
        .await
        .unwrap();
    assert_eq!(st, StatusCode::BAD_GATEWAY, "保留期内应 502 而非 404");

    server.shutdown().await;
}

// ───────────────────────── T2 forward 方向 ─────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t2_forward_full_chain() {
    let target = spawn_target().await.unwrap();
    let server = start_server(false, true).await.unwrap(); // allow_private
    let fwd = start_forward(&server).await.unwrap();
    let fwd_local = start_forward_local().await.unwrap();
    let host = fwd.to_string();

    // 2.1 server 出口 GET
    let path = format!("/http://{target}/");
    let (st, body) = http_once(Scheme::Http, fwd, &host, Method::GET, &path, None)
        .await
        .unwrap();
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, b"e2e-ok");

    // 2.2 server 出口 POST 1 MiB 回显
    let payload = shaped_payload();
    let path = format!("/http://{target}/echo");
    let (st, body) = http_once(
        Scheme::Http,
        fwd,
        &host,
        Method::POST,
        &path,
        Some(payload.clone()),
    )
    .await
    .unwrap();
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, payload, "经服务器出网的 1 MiB 回显必须一致");

    // 2.3 server 出口 GET 1 MiB
    let path = format!("/http://{target}/1m");
    let (st, body) = http_once(Scheme::Http, fwd, &host, Method::GET, &path, None)
        .await
        .unwrap();
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body.len(), MIB);

    // 2.4 local 出口对照（不经服务器）
    let path = format!("/http://{target}/");
    let (st, body) = http_once(Scheme::Http, fwd_local, "local", Method::GET, &path, None)
        .await
        .unwrap();
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, b"e2e-ok");

    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t2_ssrf_denied_by_default() {
    let target = spawn_target().await.unwrap();
    // allow_private = false：打内网 target 必须被拒
    let server = start_server(false, false).await.unwrap();
    let fwd = start_forward(&server).await.unwrap();

    let path = format!("/http://{target}/");
    let (st, _) = http_once(
        Scheme::Http,
        fwd,
        &fwd.to_string(),
        Method::GET,
        &path,
        None,
    )
    .await
    .unwrap();
    assert_eq!(st, StatusCode::FORBIDDEN, "默认拒绝内网 target");

    server.shutdown().await;
}

// ───────────────────────── T3 双方向并存 ─────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t3_both_directions_concurrent() {
    let target = spawn_target().await.unwrap();
    let server = start_server(true, true).await.unwrap();
    let _expose = start_expose(&server, target.port(), "app1").await.unwrap();
    let fwd = start_forward(&server).await.unwrap();
    let ingress = server.http;

    // 交错并发：expose 方向（server→agent 开流）与 forward 方向（agent→server
    // 开流）同时各拉 1 MiB
    let expose_req = http_once(
        Scheme::Http,
        ingress,
        "app1.e2e.local",
        Method::GET,
        "/1m",
        None,
    );
    let fwd_path = format!("/http://{target}/1m");
    let fwd_host = fwd.to_string();
    let forward_req = http_once(Scheme::Http, fwd, &fwd_host, Method::GET, &fwd_path, None);
    let (a, b) = tokio::join!(expose_req, forward_req);

    let (st_a, body_a) = a.unwrap();
    let (st_b, body_b) = b.unwrap();
    assert_eq!(st_a, StatusCode::OK, "expose 方向失败");
    assert_eq!(st_b, StatusCode::OK, "forward 方向失败");
    assert_eq!(body_a.len(), MIB);
    assert_eq!(body_b.len(), MIB);

    server.shutdown().await;
}

// ───────────────────────── T4 控制通道安全 ─────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t4_wrong_token_rejected() {
    let target = spawn_target().await.unwrap();
    let server = start_server(false, false).await.unwrap();

    let result = expose::connect(
        &server.control.to_string(),
        "wrong-token-0123456789",
        target.port(),
        Some("app1".into()),
    )
    .await;
    let err = result.err().expect("错误 token 必须被拒绝");
    assert!(
        err.to_string().contains("AuthFailed") || err.to_string().contains("token"),
        "错误信息应指明认证失败：{err}"
    );

    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t4_wrong_spki_pin_rejected() {
    let server = start_server(false, false).await.unwrap();

    // 直连 agent::tls（不经环境变量），指纹不匹配必须握手失败
    let result = sluice::agent::tls::connect(
        &server.control.to_string(),
        Some("WRONGPIN000000000000000000000000000000000="),
    )
    .await;
    let err = result.expect_err("错误指纹必须握手失败");
    let chain = format!("{err:#}");
    assert!(
        chain.contains("指纹不匹配"),
        "错误链应包含指纹拒绝原因：{chain}"
    );

    server.shutdown().await;
}

// ───────────────────────── T5 入口直连转发 ─────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t5_direct_open_full_chain() {
    let target = spawn_target().await.unwrap();
    let server = start_server_direct(true, true, DirectMode::Open)
        .await
        .unwrap();
    let ingress = server.http;
    let host = "e2e.local";

    // 5.1 open 档 GET（无凭据）
    let path = format!("/http://{target}/");
    let (st, body) = http_once(Scheme::Http, ingress, host, Method::GET, &path, None)
        .await
        .unwrap();
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, b"e2e-ok");

    // 5.2 open 档 POST 1 MiB 回显
    let payload = shaped_payload();
    let path = format!("/http://{target}/echo");
    let (st, body) = http_once(
        Scheme::Http,
        ingress,
        host,
        Method::POST,
        &path,
        Some(payload.clone()),
    )
    .await
    .unwrap();
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, payload, "直连转发 1 MiB 回显必须一致");

    // 5.3 折叠斜杠形式 /http/target/
    let path = format!("/http/{target}/");
    let (st, body) = http_once(Scheme::Http, ingress, host, Method::GET, &path, None)
        .await
        .unwrap();
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, b"e2e-ok");

    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t5_direct_token_auth() {
    let target = spawn_target().await.unwrap();
    let server = start_server_direct(false, true, DirectMode::Token)
        .await
        .unwrap();
    let ingress = server.http;
    let host = "e2e.local";
    let path = format!("/http://{target}/");

    // 5.4 无 token → 401
    let (st, _) = http_once(Scheme::Http, ingress, host, Method::GET, &path, None)
        .await
        .unwrap();
    assert_eq!(st, StatusCode::UNAUTHORIZED, "token 档无凭据必须 401");

    // 5.5 错 token → 401
    let (st, _) = http_once_auth(
        Scheme::Http,
        ingress,
        host,
        Method::GET,
        &path,
        None,
        Some("wrong-token-0123456789"),
    )
    .await
    .unwrap();
    assert_eq!(st, StatusCode::UNAUTHORIZED, "token 档错凭据必须 401");

    // 5.6 正确 Bearer → 200
    let (st, body) = http_once_auth(
        Scheme::Http,
        ingress,
        host,
        Method::GET,
        &path,
        None,
        Some(TOKEN),
    )
    .await
    .unwrap();
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, b"e2e-ok");

    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t5_direct_ssrf_denied() {
    let target = spawn_target().await.unwrap();
    // open 档但 allow_private=false：直连打内网 target 必须与 forward 流同判
    let server = start_server_direct(false, false, DirectMode::Open)
        .await
        .unwrap();

    let path = format!("/http://{target}/");
    let (st, _) = http_once(
        Scheme::Http,
        server.http,
        "e2e.local",
        Method::GET,
        &path,
        None,
    )
    .await
    .unwrap();
    assert_eq!(st, StatusCode::FORBIDDEN, "直连转发默认拒绝内网 target");

    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t5_direct_off_falls_through() {
    // off（默认）：直连热词不拦截，走原有子域名路由 → 404
    let server = start_server(false, true).await.unwrap();

    let (st, _) = http_once(
        Scheme::Http,
        server.http,
        "e2e.local",
        Method::GET,
        "/http://example.com/",
        None,
    )
    .await
    .unwrap();
    assert_eq!(st, StatusCode::NOT_FOUND, "off 档应保持隧道语义");

    server.shutdown().await;
}

// ───────────────────────── T6 HTTP/2 入口 ─────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t6_h2_ingress() -> Result<()> {
    use hyper_util::rt::TokioExecutor;

    let target = spawn_target().await.unwrap();
    let server = start_server_direct(true, true, DirectMode::Open)
        .await
        .unwrap();
    let ingress_tls = server.https.unwrap();

    let socket = tokio::time::timeout(TIMEOUT, TcpStream::connect(ingress_tls)).await??;
    sluice::common::crypto::install();
    let config = rustls::ClientConfig::builder_with_provider(sluice::common::crypto::provider())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_no_client_auth();
    let mut config = config;
    config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));
    let name = rustls::pki_types::ServerName::try_from("e2e.local".to_string())?;
    let tls = tokio::time::timeout(TIMEOUT, connector.connect(name, socket)).await??;
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(&b"h2"[..]),
        "ALPN 应协商出 h2"
    );

    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls)).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    // h2 请求走直连转发 1 MiB 下行，验证 h2 解析 + 流式 body 全链路
    let path = format!("/http://{target}/1m");
    let request = Request::builder()
        .method(Method::GET)
        .uri(&path)
        .header("host", "e2e.local")
        .body(Full::new(bytes::Bytes::new()))?;
    let response = tokio::time::timeout(TIMEOUT, sender.send_request(request)).await??;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await?.to_bytes();
    assert_eq!(bytes.len(), MIB, "h2 入口 1 MiB 下行长度必须一致");

    server.shutdown().await;
    Ok(())
}

// ───────────────────────── T7 多主机串流隔离 ─────────────────────────
//
// 每个 agent 一条独立 TLS+yamux 连接；同连接内流按 stream ID 分路。
// 本用例用带标签 target 验证：任何跨主机/跨流串流都会表现为标签错位。

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t7_multi_host_isolation() {
    const HALF_MIB: usize = 512 * 1024;
    let target_a = spawn_target_tagged(b'A').await.unwrap();
    let target_b = spawn_target_tagged(b'B').await.unwrap();
    let server = start_server(false, true).await.unwrap();
    let ingress = server.http;

    let _a = start_expose(&server, target_a.port(), "hosta")
        .await
        .unwrap();
    let _b = start_expose(&server, target_b.port(), "hostb")
        .await
        .unwrap();

    // 7.1 路由不串：两台主机的 /id 交替查询，各自返回自己的标签
    for _ in 0..3 {
        let (st_a, body_a) = http_once(
            Scheme::Http,
            ingress,
            "hosta.e2e.local",
            Method::GET,
            "/id",
            None,
        )
        .await
        .unwrap();
        let (st_b, body_b) = http_once(
            Scheme::Http,
            ingress,
            "hostb.e2e.local",
            Method::GET,
            "/id",
            None,
        )
        .await
        .unwrap();
        assert_eq!(st_a, StatusCode::OK);
        assert_eq!(st_b, StatusCode::OK);
        assert_eq!(body_a, b"target-A", "hosta 的请求被串到了别的 target");
        assert_eq!(body_b, b"target-B", "hostb 的请求被串到了别的 target");
    }

    // 7.2 并发大响应交错：两边同时各拉 512 KiB，回显带各自 tag 前缀，
    // 逐字节校验——跨流混流必然导致 payload/tag 错位
    let payload_a: Vec<u8> = (0..HALF_MIB).map(|i| (i % 251) as u8).collect();
    let payload_b: Vec<u8> = (0..HALF_MIB).map(|i| (250 - (i % 251)) as u8).collect();

    let req_a1 = http_once(
        Scheme::Http,
        ingress,
        "hosta.e2e.local",
        Method::POST,
        "/echo",
        Some(payload_a.clone()),
    );
    let req_b1 = http_once(
        Scheme::Http,
        ingress,
        "hostb.e2e.local",
        Method::POST,
        "/echo",
        Some(payload_b.clone()),
    );
    let req_a2 = http_once(
        Scheme::Http,
        ingress,
        "hosta.e2e.local",
        Method::GET,
        "/1m",
        None,
    );
    let req_b2 = http_once(
        Scheme::Http,
        ingress,
        "hostb.e2e.local",
        Method::GET,
        "/1m",
        None,
    );
    let (ra1, rb1, ra2, rb2) = tokio::join!(req_a1, req_b1, req_a2, req_b2);

    let (st, body) = ra1.unwrap();
    assert_eq!(st, StatusCode::OK);
    let mut expect = vec![b'A'];
    expect.extend_from_slice(&payload_a);
    assert_eq!(body, expect, "hosta 回显串流");

    let (st, body) = rb1.unwrap();
    assert_eq!(st, StatusCode::OK);
    let mut expect = vec![b'B'];
    expect.extend_from_slice(&payload_b);
    assert_eq!(body, expect, "hostb 回显串流");

    let (st, body) = ra2.unwrap();
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, vec![b'A'; MIB], "hosta 下行串流");

    let (st, body) = rb2.unwrap();
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, vec![b'B'; MIB], "hostb 下行串流");

    // 7.3 同一主机多并发流：单 agent 连接内 4 条流同时回显，流间不混
    let small: Vec<u8> = (0..64 * 1024).map(|i| (i % 127) as u8).collect();
    let mut futs = Vec::new();
    for _ in 0..4 {
        let s = small.clone();
        futs.push(http_once(
            Scheme::Http,
            ingress,
            "hosta.e2e.local",
            Method::POST,
            "/echo",
            Some(s.clone()),
        ));
    }
    let results = futures_util::future::join_all(futs).await;
    let mut expect = vec![b'A'];
    expect.extend_from_slice(&small);
    for r in results {
        let (st, body) = r.unwrap();
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body, expect, "同主机并发流串流");
    }

    server.shutdown().await;
}
