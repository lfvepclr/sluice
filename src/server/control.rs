//! 控制面：握手、认证、子域名分配、会话表。

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use dashmap::DashMap;
use subtle::ConstantTimeEq;
use tokio::net::{TcpListener, TcpStream};
use yamux::Mode;

use super::App;
use crate::common::subdomain;
use crate::proto::{
    self, ErrorCode, ErrorFrame, Frame, HelloAck, MAX_FRAME_LEN, PROTOCOL_VERSION,
};
use crate::transport::{self, MuxHandle};

/// 心跳间隔与超时（M4 先由 TCP 断连检测，心跳在 M6 与 TLS 一起接）。
pub const HEARTBEAT_SECS: u64 = 15;

/// 一条活跃会话。
pub struct Session {
    pub subdomain: String,
    pub mode: proto::Mode,
    pub mux: MuxHandle,
    /// 会话是否在线。断线后置 false，但在保留期内仍占用子域名。
    online: AtomicBool,
}

impl Session {
    fn new(subdomain: String, mode: proto::Mode, mux: MuxHandle) -> Self {
        Self {
            subdomain,
            mode,
            mux,
            online: AtomicBool::new(true),
        }
    }

    pub fn is_online(&self) -> bool {
        self.online.load(Ordering::Relaxed)
    }

    fn mark_offline(&self) {
        self.online.store(false, Ordering::Relaxed);
    }
}

/// 子域名 → 会话。
pub struct Registry {
    inner: DashMap<String, Arc<Session>>,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
        }
    }

    pub fn get(&self, subdomain: &str) -> Option<Arc<Session>> {
        self.inner.get(subdomain).map(|entry| entry.value().clone())
    }

    pub fn contains(&self, subdomain: &str) -> bool {
        self.inner.contains_key(subdomain)
    }

    pub fn insert(&self, session: Arc<Session>) {
        self.inner.insert(session.subdomain.clone(), session);
    }

    /// 只有当注册表里还是同一个会话时才移除，避免误删刚接管的新会话。
    pub fn remove_if_same(&self, subdomain: &str, session: &Arc<Session>) {
        if let Some(entry) = self.inner.get(subdomain)
            && Arc::ptr_eq(entry.value(), session)
        {
            drop(entry);
            self.inner.remove(subdomain);
        }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

/// 控制面监听循环。
pub async fn serve(app: Arc<App>, addr: SocketAddr) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "控制面就绪");

    loop {
        let (socket, peer) = listener.accept().await?;
        let app = app.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(app, socket, peer).await {
                tracing::debug!(%peer, error = %e, "会话结束");
            }
        });
    }
}

async fn handle_connection(app: Arc<App>, socket: TcpStream, peer: SocketAddr) -> anyhow::Result<()> {
    let _ = socket.set_nodelay(true);

    let (mux, mut inbound, join) = transport::spawn(socket, Mode::Server, transport::default_config());

    // 第一条入站流固定是控制流
    let Some(control_stream) = inbound.recv().await else {
        return Ok(());
    };
    let mut control = transport::into_tokio(control_stream);

    let hello = match proto::read_frame(&mut control, MAX_FRAME_LEN).await {
        Ok(Frame::Hello(hello)) => hello,
        Ok(other) => {
            tracing::warn!(%peer, "首帧不是 Hello：{:?}", other.frame_type());
            return Ok(());
        }
        Err(e) => {
            tracing::debug!(%peer, error = %e, "读取 Hello 失败");
            return Ok(());
        }
    };

    if hello.ver != PROTOCOL_VERSION {
        reject(&mut control, ErrorCode::ProtocolMismatch, "协议版本不匹配").await;
        return Ok(());
    }

    if !token_matches(&app.cfg.token, &hello.token) {
        tracing::warn!(%peer, "token 校验失败");
        reject(&mut control, ErrorCode::AuthFailed, "token 不正确").await;
        return Ok(());
    }

    if app.registry.len() >= app.cfg.limits.max_sessions {
        reject(&mut control, ErrorCode::TooManySessions, "会话数已达上限").await;
        return Ok(());
    }

    // forward 模式不需要公网子域名，只借用同一条控制通道
    let is_forward = hello.mode == proto::Mode::Forward;
    let subdomain = if is_forward {
        String::new()
    } else {
        match allocate(&app.registry, hello.want_subdomain.as_deref()) {
            Ok(s) => s,
            Err(code) => {
                let msg = match code {
                    ErrorCode::SubdomainTaken => "子域名已被占用",
                    ErrorCode::SubdomainReserved => "子域名不可用（格式错误或为保留词）",
                    _ => "无法分配子域名",
                };
                reject(&mut control, code, msg).await;
                return Ok(());
            }
        }
    };

    let public_url = if is_forward {
        format!("forward://{peer}")
    } else {
        format!("http://{}.{}", subdomain, app.cfg.base_domain)
    };
    let session = Arc::new(Session::new(subdomain.clone(), hello.mode, mux));
    if !is_forward {
        app.registry.insert(session.clone());
    }

    let ack = HelloAck {
        subdomain: subdomain.clone(),
        public_url: public_url.clone(),
        session_id: format!("{peer}"),
        heartbeat_secs: HEARTBEAT_SECS,
    };
    proto::write_frame(&mut control, &Frame::HelloAck(ack)).await?;

    tracing::info!(%peer, %public_url, mode = ?hello.mode, "会话已建立");

    // agent 开的入站流有两种来源：forward 模式的请求流（M7），
    // 以及 expose 模式下不应该出现的流（直接丢弃）。
    let fwd_app = app.clone();
    let drain = tokio::spawn(async move {
        while let Some(stream) = inbound.recv().await {
            let app = fwd_app.clone();
            tokio::spawn(async move {
                super::forward::serve_stream(stream, app).await;
            });
        }
    });

    // 连接关闭（对端断开或网络中断）时驱动任务结束
    let _ = join.await;
    drain.abort();

    // 断线后保留子域名一段时间：agent 重连可复用同一个地址，
    // 期间访问该子域名返回 502 而不是 404，语义更准确。
    session.mark_offline();
    if !is_forward {
        let registry = app.registry.clone();
        let reserved = app.cfg.limits.reserved_secs;
        let sub = subdomain.clone();
        let this = session.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(reserved)).await;
            registry.remove_if_same(&sub, &this);
            tracing::info!(subdomain = %sub, "保留期结束，子域名已释放");
        });
    }

    tracing::info!(%public_url, "会话断开");
    Ok(())
}

fn token_matches(expected: &str, provided: &str) -> bool {
    expected.as_bytes().ct_eq(provided.as_bytes()).into()
}

async fn reject(control: &mut (impl tokio::io::AsyncWrite + Unpin), code: ErrorCode, message: &str) {
    let frame = Frame::Error(ErrorFrame {
        code,
        message: message.to_string(),
    });
    let _ = proto::write_frame(control, &frame).await;
}

/// 分配子域名：自定义名要做校验，随机名要避开已占用。
fn allocate(registry: &Registry, want: Option<&str>) -> Result<String, ErrorCode> {
    if let Some(name) = want {
        if !subdomain::validate(name) {
            return Err(ErrorCode::SubdomainReserved);
        }
        if let Some(existing) = registry.get(name)
            && existing.is_online()
        {
            return Err(ErrorCode::SubdomainTaken);
        }
        // 离线且仍在保留期内：允许新会话接管，重连体验更好
        return Ok(name.to_string());
    }

    for _ in 0..5 {
        let candidate = subdomain::generate();
        if !registry.contains(&candidate) {
            return Ok(candidate);
        }
    }
    Err(ErrorCode::SubdomainTaken)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_comparison_works() {
        assert!(token_matches("abc", "abc"));
        assert!(!token_matches("abc", "abd"));
        assert!(!token_matches("abc", "abcd"));
        assert!(!token_matches("abc", ""));
    }

    #[test]
    fn allocate_random_is_not_reserved() {
        let reg = Registry::new();
        let name = allocate(&reg, None).unwrap();
        assert!(subdomain::validate(&name));
    }

    #[test]
    fn allocate_rejects_reserved_custom_name() {
        let reg = Registry::new();
        assert_eq!(allocate(&reg, Some("api")), Err(ErrorCode::SubdomainReserved));
    }

    #[test]
    fn allocate_accepts_custom_name() {
        let reg = Registry::new();
        assert_eq!(allocate(&reg, Some("myapp")).unwrap(), "myapp");
    }
}
