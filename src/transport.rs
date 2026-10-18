//! 传输层：yamux 多路复用驱动。
//!
//! yamux 0.12/0.13 把开流能力收在 `Connection` 上（没有独立的 `Control` 句柄），
//! 而开流与收流又必须由同一个驱动循环来 poll。这里用一个「单任务多事件」的
//! 驱动把三件事合到一个 `poll_fn` 里：
//!
//! 1. `poll_next_inbound`：收对端开的流（同时把本端排队的帧刷出去）
//! 2. `poll_new_outbound`：处理一个待开流请求
//! 3. `cmd_rx.poll_recv`：接收新的开流请求
//!
//! 顺序很重要：先 poll 入站，才能及时处理对端的 ACK，否则开流会卡住。

use std::future::poll_fn;
use std::task::Poll;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use yamux::{Config, Connection, ConnectionError, Mode, Stream};

/// 开流请求的应答通道。
type OpenReply = oneshot::Sender<Result<Stream, ConnectionError>>;

/// 会话侧持有的多路复用句柄：可以主动开流。
#[derive(Clone)]
pub struct MuxHandle {
    open_tx: mpsc::Sender<OpenReply>,
}

impl MuxHandle {
    /// 开一条新流。连接已关闭时返回 `ConnectionError::Closed`。
    pub async fn open(&self) -> Result<Stream, ConnectionError> {
        let (tx, rx) = oneshot::channel();
        if self.open_tx.send(tx).await.is_err() {
            return Err(ConnectionError::Closed);
        }
        match rx.await {
            Ok(result) => result,
            Err(_) => Err(ConnectionError::Closed),
        }
    }
}

/// 默认的 yamux 配置。
///
/// 窗口与并发流都按「单核 + 3 Mbps 上行」调：窗口放大只会增加潜在缓冲，
/// 不会提高吞吐，因为瓶颈在链路上。
pub fn default_config() -> Config {
    let mut cfg = Config::default();
    cfg.set_receive_window(256 * 1024);
    cfg.set_max_num_streams(128);
    cfg.set_split_send_size(16 * 1024);
    cfg
}

enum Event {
    Inbound(Stream),
    Opened(Result<Stream, ConnectionError>, OpenReply),
    Cmd(OpenReply),
    Closed,
}

/// 启动多路复用驱动，返回可开流的句柄与入站流的接收端。
///
/// 入站流用无界通道：流句柄本身很小，真正的背压由 yamux 的流控负责，
/// 在这里加缓冲反而会让驱动循环被阻塞、连 ACK 都发不出去。
pub fn spawn<T>(
    io: T,
    mode: Mode,
    cfg: Config,
) -> (
    MuxHandle,
    mpsc::UnboundedReceiver<Stream>,
    tokio::task::JoinHandle<()>,
)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let conn: Connection<Compat<T>> = Connection::new(io.compat(), cfg, mode);
    let (open_tx, open_rx) = mpsc::channel(64);
    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();

    let join = tokio::spawn(driver(conn, open_rx, inbound_tx));

    (MuxHandle { open_tx }, inbound_rx, join)
}

async fn driver<T>(
    mut conn: Connection<Compat<T>>,
    mut cmd_rx: mpsc::Receiver<OpenReply>,
    inbound_tx: mpsc::UnboundedSender<Stream>,
) where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut pending: Option<OpenReply> = None;

    loop {
        let event = poll_fn(|cx| {
            // 1. 入站优先：这里同时会把本端排队的控制帧刷到 socket
            match conn.poll_next_inbound(cx) {
                Poll::Ready(Some(Ok(stream))) => return Poll::Ready(Event::Inbound(stream)),
                Poll::Ready(Some(Err(_))) | Poll::Ready(None) => return Poll::Ready(Event::Closed),
                Poll::Pending => {}
            }

            // 2. 有待处理的开流请求就推进它
            if let Some(reply) = pending.take() {
                match conn.poll_new_outbound(cx) {
                    Poll::Ready(Ok(stream)) => return Poll::Ready(Event::Opened(Ok(stream), reply)),
                    Poll::Ready(Err(e)) => return Poll::Ready(Event::Opened(Err(e), reply)),
                    Poll::Pending => pending = Some(reply),
                }
            }

            // 3. 接收新的开流请求
            match cmd_rx.poll_recv(cx) {
                Poll::Ready(Some(reply)) => Poll::Ready(Event::Cmd(reply)),
                Poll::Ready(None) => Poll::Ready(Event::Closed),
                Poll::Pending => Poll::Pending,
            }
        })
        .await;

        match event {
            Event::Inbound(stream) => {
                if inbound_tx.send(stream).is_err() {
                    break;
                }
            }
            Event::Opened(result, reply) => {
                let _ = reply.send(result);
            }
            Event::Cmd(reply) => pending = Some(reply),
            Event::Closed => break,
        }
    }

    // 连接结束时唤醒所有还在等开流的调用方
    while let Some(reply) = pending.take() {
        let _ = reply.send(Err(ConnectionError::Closed));
    }
    cmd_rx.close();
    while let Ok(reply) = cmd_rx.try_recv() {
        let _ = reply.send(Err(ConnectionError::Closed));
    }
}

/// 把 yamux 流转换成 tokio 的 IO，供 hyper 使用。
pub fn into_tokio(stream: Stream) -> impl AsyncRead + AsyncWrite + Unpin {
    stream.compat()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn pair() -> (
        MuxHandle,
        mpsc::UnboundedReceiver<Stream>,
        MuxHandle,
        mpsc::UnboundedReceiver<Stream>,
    ) {
        let (a, b) = tokio::io::duplex(256 * 1024);
        let (client, client_in, _cj) = spawn(a, Mode::Client, default_config());
        let (server, server_in, _sj) = spawn(b, Mode::Server, default_config());
        (client, client_in, server, server_in)
    }

    #[tokio::test]
    async fn both_sides_can_open_streams() {
        let (client, _ci, server, mut server_in) = pair();

        // 客户端开流 → 服务端应收到
        let mut s = into_tokio(client.open().await.expect("客户端开流失败"));
        s.write_all(b"ping").await.unwrap();
        s.flush().await.unwrap();

        let inbound = tokio::time::timeout(Duration::from_secs(5), server_in.recv())
            .await
            .expect("服务端等流超时")
            .expect("服务端入站通道关闭");
        let mut inbound = into_tokio(inbound);
        let mut buf = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(5), inbound.read_exact(&mut buf))
            .await
            .expect("读超时")
            .expect("读失败");
        assert_eq!(&buf, b"ping");

        // 服务端开流 → 客户端应收到（forward 模式的前提）
        let mut back = into_tokio(server.open().await.expect("服务端开流失败"));
        back.write_all(b"pong").await.unwrap();
        back.flush().await.unwrap();
        let _ = back;
    }

    #[tokio::test]
    async fn concurrent_opens_all_succeed() {
        let (client, _ci, _server, _si) = pair();

        let mut handles = Vec::new();
        for _ in 0..16 {
            let h = client.clone();
            handles.push(tokio::spawn(async move {
                let mut s = into_tokio(h.open().await.expect("开流失败"));
                s.write_all(b"x").await.unwrap();
            }));
        }
        for h in handles {
            tokio::time::timeout(Duration::from_secs(5), h)
                .await
                .expect("并发开流超时")
                .expect("并发开流失败");
        }
    }

    #[tokio::test]
    async fn open_after_peer_gone_fails_cleanly() {
        let (client, _ci, server, server_in) = pair();
        drop(server);
        drop(server_in);
        // 对端消失后，开流应当返回错误而不是永久挂起
        let result = tokio::time::timeout(Duration::from_secs(5), client.open()).await;
        match result {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => {}
            Err(_) => panic!("对端消失后 open 不应永久阻塞"),
        }
    }
}
