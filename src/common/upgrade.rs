//! 协议升级（WebSocket）桥接。
//!
//! 升级的本质是「101 之后这条连接不再属于 HTTP」。代理两侧各拿到一个
//! `Upgraded` 句柄后，把它们当成一对裸字节流对接即可。

use http::{Request, Response};
use hyper::body::Incoming;
use hyper::upgrade::OnUpgrade;

use super::body::BoxedBody;
use super::headers;
use crate::transport;

/// 如果请求要求升级，取走客户端的升级句柄。
///
/// 必须在请求被消费（送进代理）之前调用。
pub fn take_client(req: &mut Request<Incoming>) -> Option<OnUpgrade> {
    if headers::wants_upgrade(req.headers()) {
        Some(hyper::upgrade::on(req))
    } else {
        None
    }
}

/// 如果响应是 101 且双方都有升级句柄，就开一条双向桥。
pub fn bridge_if_upgraded(client: Option<OnUpgrade>, response: &mut Response<BoxedBody>) {
    let Some(client) = client else {
        return;
    };
    let Some(server) = response.extensions_mut().remove::<OnUpgrade>() else {
        return;
    };

    tokio::spawn(async move {
        match tokio::try_join!(client, server) {
            Ok((client, server)) => {
                if let Err(e) = transport::bridge(client, server).await {
                    tracing::debug!(error = %e, "升级连接桥接结束");
                }
            }
            Err(e) => tracing::debug!(error = %e, "升级握手失败"),
        }
    });
}
