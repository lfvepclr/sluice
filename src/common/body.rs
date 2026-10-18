//! HTTP body 类型与常用响应构造。
//!
//! 统一用 `BoxedBody`：代理链路的两端都只关心「字节流 + 错误」，把错误类型
//! 擦成 `BoxError` 之后，hyper 的 server/client 与 reqwest 都能直接吃。

use bytes::Bytes;
use http::{Response, StatusCode, header};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};

/// 擦除后的错误类型。
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// 统一的响应体类型。
pub type BoxedBody = BoxBody<Bytes, BoxError>;

/// 空 body。
pub fn empty() -> BoxedBody {
    Full::new(Bytes::new())
        .map_err(|never| match never {})
        .boxed()
}

/// 纯文本响应。
pub fn text(status: StatusCode, message: impl Into<Bytes>) -> Response<BoxedBody> {
    let body = Full::new(message.into())
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::SERVER, "sluice")
        .body(body)
        .expect("静态构造的响应不会失败")
}
