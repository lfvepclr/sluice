//! M5 验收：WebSocket 能否穿过「入口 → 隧道 → agent → 本地服务」整条链路。
//!
//! 链路上任何一跳把 `Connection: upgrade` / `Upgrade: websocket` 剥掉，
//! 这个测试就会失败——它正是为了守住这个不变量。

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use sluice::config::{DnsKind, LimitsConfig, ListenConfig, ServerConfig, TlsConfig, TlsMode};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

const TOKEN: &str = "0123456789abcdef";
const INGRESS: u16 = 28180;
const CONTROL: u16 = 28181;
const LOCAL_WS: u16 = 28182;

fn test_config() -> ServerConfig {
    ServerConfig {
        base_domain: "bench.local".into(),
        token: TOKEN.into(),
        dns_token: None,
        public_ip: None,
        listen: ListenConfig {
            control: format!("127.0.0.1:{CONTROL}").parse().unwrap(),
            http: format!("127.0.0.1:{INGRESS}").parse().unwrap(),
            https: None,
        },
        tls: TlsConfig {
            mode: TlsMode::SelfSigned,
            email: None,
            dns: DnsKind::Duckdns,
            cert_dir: std::env::temp_dir().join("sluice-ws-test"),
        },
        forward: Default::default(),
        limits: LimitsConfig::default(),
    }
}

/// 本地 WS echo 服务：把收到的消息原样回写。
async fn spawn_local_ws_echo() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", LOCAL_WS)).await.unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                while let Some(Ok(msg)) = ws.next().await {
                    if msg.is_close() {
                        break;
                    }
                    let _ = ws.send(msg).await;
                }
            });
        }
    });
    LOCAL_WS
}

async fn wait_until<F, Fut>(mut probe: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..60 {
        if probe().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("等待超时：依赖的服务没有就绪");
}

#[tokio::test]
async fn websocket_echo_through_tunnel() {
    let local_port = spawn_local_ws_echo().await;

    let cfg = test_config();
    tokio::spawn(async move {
        let _ = sluice::server::run(cfg).await;
    });

    wait_until(|| async {
        tokio::net::TcpStream::connect(("127.0.0.1", INGRESS))
            .await
            .is_ok()
    })
    .await;

    tokio::spawn(async move {
        if let Err(e) = sluice::agent::expose::run(
            &format!("127.0.0.1:{CONTROL}"),
            TOKEN,
            local_port,
            Some("wsapp".into()),
        )
        .await
        {
            eprintln!("agent 退出：{e:#}");
        }
    });

    // 等会话注册完成：健康检查通不代表隧道通，直接用 WS 连接重试
    // 自己建 TCP 再交给 tungstenite：这样才能完全控制 Host 头（用于子域名路由）
    let mut connected = None;
    for _ in 0..40 {
        let mut request =
            tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(
                "ws://wsapp.bench.local/",
            )
            .unwrap();
        request
            .headers_mut()
            .insert("host", "wsapp.bench.local".parse().unwrap());

        match tokio::net::TcpStream::connect(("127.0.0.1", INGRESS)).await {
            Ok(stream) => match tokio_tungstenite::client_async(request, stream).await {
                Ok(pair) => {
                    connected = Some(pair);
                    break;
                }
                Err(e) => {
                    eprintln!("握手重试：{e}");
                    tokio::time::sleep(Duration::from_millis(100)).await
                }
            },
            Err(e) => {
                eprintln!("连接失败：{e}");
                tokio::time::sleep(Duration::from_millis(100)).await
            }
        }
    }
    let (mut ws, response) = connected.expect("WebSocket 握手失败");

    assert_eq!(
        response.status().as_u16(),
        101,
        "应返回 101 Switching Protocols"
    );
    let accept = response
        .headers()
        .get("sec-websocket-accept")
        .expect("缺少 Sec-WebSocket-Accept");
    assert!(!accept.is_empty());

    let payload = vec![7u8; 1024];
    ws.send(Message::Binary(payload.clone())).await.unwrap();

    let echoed = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("回显超时")
        .expect("连接已关闭")
        .expect("回显出错");

    match echoed {
        Message::Binary(data) => assert_eq!(&data[..], payload.as_slice()),
        other => panic!("期望二进制回显，得到 {other:?}"),
    }
}
