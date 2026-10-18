//! 控制面帧协议：`[type:1][len:u32 BE][payload]`。
//!
//! 控制流上只跑这几类小帧，数据流走 yamux 的独立 stream，两者互不干扰。
//! 长度上限 64 KB：先读长度再决定是否分配，避免恶意长度把内存打爆。

use std::io;

use bytes::{BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// 协议版本。字段或语义不兼容变更时递增。
pub const PROTOCOL_VERSION: u16 = 1;
/// 单帧载荷上限（字节）。
pub const MAX_FRAME_LEN: u32 = 64 * 1024;
/// 帧头长度：1 字节类型 + 4 字节大端长度。
pub const HEADER_LEN: usize = 5;

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("IO 错误：{0}")]
    Io(#[from] io::Error),

    #[error("帧长度 {len} 超过上限 {max}")]
    FrameTooLong { len: u32, max: u32 },

    #[error("未知帧类型 0x{0:02x}")]
    UnknownType(u8),

    #[error("帧载荷解析失败：{0}")]
    Json(#[from] serde_json::Error),

    #[error("连接在帧边界处关闭")]
    Closed,
}

/// 帧类型。数值是线格式的一部分，改动即破坏兼容。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Hello = 0x01,
    HelloAck = 0x02,
    Ping = 0x03,
    Pong = 0x04,
    Error = 0x05,
}

impl FrameType {
    pub fn from_u8(v: u8) -> Result<Self, ProtoError> {
        Ok(match v {
            0x01 => Self::Hello,
            0x02 => Self::HelloAck,
            0x03 => Self::Ping,
            0x04 => Self::Pong,
            0x05 => Self::Error,
            other => return Err(ProtoError::UnknownType(other)),
        })
    }
}

/// 会话模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// 隧道：服务器开流，把外部请求灌进本地端口。
    Expose,
    /// 转发：agent 开流，由服务器出网。
    Forward,
}

/// agent 发往服务器的第一个帧。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub ver: u16,
    pub token: String,
    pub mode: Mode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub want_subdomain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_port: Option<u16>,
}

impl Hello {
    pub fn new(token: impl Into<String>, mode: Mode) -> Self {
        Self {
            ver: PROTOCOL_VERSION,
            token: token.into(),
            mode,
            want_subdomain: None,
            local_port: None,
        }
    }
}

/// 服务器对 [`Hello`] 的应答。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloAck {
    pub subdomain: String,
    pub public_url: String,
    pub session_id: String,
    pub heartbeat_secs: u64,
}

/// 错误码。客户端据此决定是否重试：认证类重试无意义，直接退出。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    AuthFailed,
    SubdomainTaken,
    SubdomainReserved,
    TooManySessions,
    ProtocolMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorFrame {
    pub code: ErrorCode,
    pub message: String,
}

/// 控制流上的一个完整帧。
#[derive(Debug, Clone)]
pub enum Frame {
    Hello(Hello),
    HelloAck(HelloAck),
    Ping,
    Pong,
    Error(ErrorFrame),
}

impl Frame {
    pub fn frame_type(&self) -> FrameType {
        match self {
            Self::Hello(_) => FrameType::Hello,
            Self::HelloAck(_) => FrameType::HelloAck,
            Self::Ping => FrameType::Ping,
            Self::Pong => FrameType::Pong,
            Self::Error(_) => FrameType::Error,
        }
    }
}

/// 编码为线格式字节。
pub fn encode(frame: &Frame) -> Bytes {
    let (ty, payload) = match frame {
        Frame::Hello(h) => (FrameType::Hello, serde_json::to_vec(h)),
        Frame::HelloAck(a) => (FrameType::HelloAck, serde_json::to_vec(a)),
        Frame::Ping => (FrameType::Ping, Ok(b"{}".to_vec())),
        Frame::Pong => (FrameType::Pong, Ok(b"{}".to_vec())),
        Frame::Error(e) => (FrameType::Error, serde_json::to_vec(e)),
    };

    // 控制帧都是小对象，序列化失败只可能是类型定义写错，直接退化为空对象
    let payload = payload.unwrap_or_else(|_| b"{}".to_vec());

    let mut buf = BytesMut::with_capacity(HEADER_LEN + payload.len());
    buf.put_u8(ty as u8);
    buf.put_u32(payload.len() as u32);
    buf.put_slice(&payload);
    buf.freeze()
}

/// 解码载荷（帧头已由调用方读掉）。
pub fn decode(ty: FrameType, payload: &[u8]) -> Result<Frame, ProtoError> {
    Ok(match ty {
        FrameType::Hello => Frame::Hello(serde_json::from_slice(payload)?),
        FrameType::HelloAck => Frame::HelloAck(serde_json::from_slice(payload)?),
        FrameType::Ping => Frame::Ping,
        FrameType::Pong => Frame::Pong,
        FrameType::Error => Frame::Error(serde_json::from_slice(payload)?),
    })
}

/// 从异步读端读一个帧。
///
/// 先校验长度再分配，`len > max_len` 时立即返回错误。
pub async fn read_frame<R>(reader: &mut R, max_len: u32) -> Result<Frame, ProtoError>
where
    R: AsyncRead + Unpin,
{
    let mut head = [0u8; HEADER_LEN];
    match reader.read_exact(&mut head[..1]).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Err(ProtoError::Closed),
        Err(e) => return Err(ProtoError::Io(e)),
    }
    reader.read_exact(&mut head[1..]).await?;

    let ty = FrameType::from_u8(head[0])?;
    let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]);

    if len > max_len {
        return Err(ProtoError::FrameTooLong { len, max: max_len });
    }

    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await?;
    decode(ty, &payload)
}

/// 往异步写端写一个帧。
pub async fn write_frame<W>(writer: &mut W, frame: &Frame) -> Result<(), ProtoError>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(&encode(frame)).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_hello() -> Hello {
        let mut h = Hello::new("0123456789abcdef", Mode::Expose);
        h.want_subdomain = Some("demo".into());
        h.local_port = Some(8080);
        h
    }

    #[test]
    fn hello_roundtrip() {
        let bytes = encode(&Frame::Hello(sample_hello()));
        assert_eq!(bytes[0], FrameType::Hello as u8);
        let len = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
        assert_eq!(len, bytes.len() - HEADER_LEN);

        let frame = decode(FrameType::Hello, &bytes[HEADER_LEN..]).unwrap();
        match frame {
            Frame::Hello(h) => {
                assert_eq!(h.ver, PROTOCOL_VERSION);
                assert_eq!(h.mode, Mode::Expose);
                assert_eq!(h.want_subdomain.as_deref(), Some("demo"));
                assert_eq!(h.local_port, Some(8080));
            }
            other => panic!("期望 Hello，得到 {other:?}"),
        }
    }

    #[test]
    fn hello_ack_roundtrip() {
        let ack = HelloAck {
            subdomain: "k3m9xq".into(),
            public_url: "http://k3m9xq.demo.duckdns.org".into(),
            session_id: "abc".into(),
            heartbeat_secs: 15,
        };
        let frame = decode(FrameType::HelloAck, &serde_json::to_vec(&ack).unwrap()).unwrap();
        match frame {
            Frame::HelloAck(a) => assert_eq!(a.subdomain, "k3m9xq"),
            other => panic!("期望 HelloAck，得到 {other:?}"),
        }
    }

    #[test]
    fn ping_pong_have_empty_payload() {
        let ping = encode(&Frame::Ping);
        assert_eq!(ping.len(), HEADER_LEN + 2);
        assert!(matches!(decode(FrameType::Ping, b"{}").unwrap(), Frame::Ping));
        assert!(matches!(decode(FrameType::Pong, b"{}").unwrap(), Frame::Pong));
    }

    #[test]
    fn error_frame_roundtrip() {
        let err = ErrorFrame {
            code: ErrorCode::SubdomainTaken,
            message: "已被占用".into(),
        };
        let frame = decode(FrameType::Error, &serde_json::to_vec(&err).unwrap()).unwrap();
        match frame {
            Frame::Error(e) => {
                assert_eq!(e.code, ErrorCode::SubdomainTaken);
                assert_eq!(e.message, "已被占用");
            }
            other => panic!("期望 Error，得到 {other:?}"),
        }
    }

    #[test]
    fn unknown_type_is_rejected() {
        let e = FrameType::from_u8(0x7f).unwrap_err();
        assert!(matches!(e, ProtoError::UnknownType(0x7f)));
    }

    #[tokio::test]
    async fn read_rejects_oversized_length_without_allocating() {
        // 只有 5 字节帧头，长度声明为上限 + 1，不应进入载荷读取
        let mut head = Vec::new();
        head.push(FrameType::Hello as u8);
        head.extend_from_slice(&(MAX_FRAME_LEN + 1).to_be_bytes());

        let mut cursor = &head[..];
        let err = read_frame(&mut cursor, MAX_FRAME_LEN).await.unwrap_err();
        assert!(matches!(err, ProtoError::FrameTooLong { .. }));
    }

    #[tokio::test]
    async fn read_truncated_payload_reports_io_error() {
        let mut data = vec![FrameType::Hello as u8];
        data.extend_from_slice(&64u32.to_be_bytes());
        data.extend_from_slice(b"{\"ver\":1"); // 明显不足 64 字节

        let mut cursor = &data[..];
        let err = read_frame(&mut cursor, MAX_FRAME_LEN).await.unwrap_err();
        assert!(matches!(err, ProtoError::Io(_)), "实际：{err:?}");
    }

    #[tokio::test]
    async fn read_at_eof_is_closed() {
        let mut empty = &b""[..];
        let err = read_frame(&mut empty, MAX_FRAME_LEN).await.unwrap_err();
        assert!(matches!(err, ProtoError::Closed));
    }

    #[tokio::test]
    async fn write_then_read() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        write_frame(&mut a, &Frame::Hello(sample_hello())).await.unwrap();
        let frame = read_frame(&mut b, MAX_FRAME_LEN).await.unwrap();
        assert!(matches!(frame, Frame::Hello(_)));
    }
}
