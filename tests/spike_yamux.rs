//! yamux 双向开流 spike（集成测试版）。
//!
//! 结论：yamux 0.12/0.13 都没有独立 `Control`，开流必须由持有 `Connection`
//! 的驱动循环完成。`src/transport.rs` 用「单任务三事件」的 poll 循环解决了这点，
//! 两个方向都能开流，因此 expose（服务器开流）与 forward（agent 开流）共用
//! 同一套复用层成立。

use std::time::Duration;

use sluice::transport;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use yamux::Mode;

#[tokio::test]
async fn server_side_can_open_stream_towards_agent() {
    let (a, b) = tokio::io::duplex(128 * 1024);
    let (_agent, _agent_in, _aj) = transport::spawn(a, Mode::Client, transport::default_config());
    let (server, mut server_in, _sj) =
        transport::spawn(b, Mode::Server, transport::default_config());

    // forward 模式依赖这个方向：agent 发起，服务器侧收流
    let mut stream = transport::into_tokio(server.open().await.expect("服务器应能开流"));
    stream.write_all(b"hello").await.unwrap();
    stream.flush().await.unwrap();
    drop(stream);

    // 让驱动把帧刷出去
    let _ = tokio::time::timeout(Duration::from_millis(200), server_in.recv()).await;
}

#[tokio::test]
async fn agent_side_can_open_stream_towards_server() {
    let (a, b) = tokio::io::duplex(128 * 1024);
    let (agent, mut agent_in, _aj) = transport::spawn(a, Mode::Client, transport::default_config());
    let (_server, _server_in, _sj) = transport::spawn(b, Mode::Server, transport::default_config());

    let mut stream = transport::into_tokio(agent.open().await.expect("agent 应能开流"));
    stream.write_all(b"hello").await.unwrap();
    stream.flush().await.unwrap();
    drop(stream);

    let _ = tokio::time::timeout(Duration::from_millis(200), agent_in.recv()).await;
}

#[tokio::test]
async fn stream_payload_roundtrip() {
    let (a, b) = tokio::io::duplex(128 * 1024);
    let (agent, _agent_in, _aj) = transport::spawn(a, Mode::Client, transport::default_config());
    let (_server, mut server_in, _sj) =
        transport::spawn(b, Mode::Server, transport::default_config());

    let mut out = transport::into_tokio(agent.open().await.unwrap());
    out.write_all(b"payload").await.unwrap();
    out.flush().await.unwrap();

    let inbound = tokio::time::timeout(Duration::from_secs(5), server_in.recv())
        .await
        .unwrap()
        .unwrap();
    let mut inbound = transport::into_tokio(inbound);
    let mut buf = [0u8; 7];
    inbound.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"payload");
}
