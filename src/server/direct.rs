//! 入口直连转发：`GET /https://host/path` 不经 agent，由服务器直接出网。
//!
//! 这是转发模式的「无客户端」形态，由 `[forward].direct` 控制档位：
//! `off`（默认，不进入本模块）/ `token`（Bearer 头或 `__token=` 查询参数）/
//! `open`（无鉴权）。SSRF 校验与 forward 流共用同一道关口（`forward::check_target`）。

use std::net::SocketAddr;
use std::sync::Arc;

use http::{Request, Response, StatusCode, header::AUTHORIZATION};
use hyper::body::Incoming;
use subtle::ConstantTimeEq;

use super::App;
use super::forward;
use crate::common::body::{BoxedBody, text};
use crate::common::upgrade;
use crate::common::upstream;
use crate::common::urlpath;
use crate::config::DirectMode;

/// 该路径是否是直连转发热词（`/http(s)://…` 或折叠形式）。
pub fn matches(path: &str) -> bool {
    urlpath::parse_target(path).is_ok()
}

/// 处理一条直连转发请求。调用前应确认 `cfg.forward.direct != Off`。
pub async fn handle(
    app: Arc<App>,
    mut req: Request<Incoming>,
    peer: SocketAddr,
) -> Response<BoxedBody> {
    match app.cfg.forward.direct {
        DirectMode::Off => {
            return text(StatusCode::NOT_FOUND, "直连转发未开启");
        }
        DirectMode::Token => {
            if !authorized(&req, &app.cfg.token) {
                tracing::warn!(%peer, "直连转发鉴权失败");
                return text(
                    StatusCode::UNAUTHORIZED,
                    "需要 token：Authorization: Bearer <token> 头或 __token= 查询参数",
                );
            }
        }
        DirectMode::Open => {}
    }

    let path = req.uri().path().to_string();
    let target = match urlpath::parse_target(&path) {
        Ok(t) => t,
        Err(e) => return text(StatusCode::BAD_REQUEST, format!("路径解析失败：{e}")),
    };

    // 请求体上限：直连入口与 forward 流执行同一条 forward.max_body_mib
    let max_bytes = app.cfg.forward.max_body_mib * 1024 * 1024;
    if let Some(len) = content_length(&req)
        && len > max_bytes
    {
        return text(
            StatusCode::PAYLOAD_TOO_LARGE,
            "请求体超过 forward.max_body_mib",
        );
    }

    let pinned = match forward::check_target(&app, &target).await {
        Ok(ip) => ip,
        Err(reason) => {
            tracing::warn!(client = %peer, target = %target.url(), %reason, "拒绝直连转发");
            return text(StatusCode::FORBIDDEN, format!("拒绝转发：{reason}"));
        }
    };

    tracing::info!(client = %peer, target = %target.url(), "直连转发");

    let client_upgrade = upgrade::take_client(&mut req);

    let mut response = match upstream::fetch(&target, req, pinned).await {
        Ok(response) => response,
        Err(e) => return text(StatusCode::BAD_GATEWAY, format!("上游请求失败：{e}")),
    };

    upgrade::bridge_if_upgraded(client_upgrade, &mut response);
    response
}

/// Bearer 头或 `__token=` 查询参数，常数时间比较。
fn authorized<B>(req: &Request<B>, expected: &str) -> bool {
    if let Some(value) = req.headers().get(AUTHORIZATION)
        && let Ok(text) = value.to_str()
        && let Some(token) = text.strip_prefix("Bearer ")
    {
        return ct_eq(token, expected);
    }
    if let Some(query) = req.uri().query() {
        for pair in query.split('&') {
            if let Some(value) = pair.strip_prefix("__token=") {
                return ct_eq(value, expected);
            }
        }
    }
    false
}

fn ct_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

fn content_length(req: &Request<Incoming>) -> Option<u64> {
    req.headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(path: &str, bearer: Option<&str>) -> Request<()> {
        let mut builder = Request::builder().uri(path);
        if let Some(b) = bearer {
            builder = builder.header(AUTHORIZATION, format!("Bearer {b}"));
        }
        builder.body(()).unwrap()
    }

    #[test]
    fn hot_word_detection() {
        assert!(matches("/https://example.com/a"));
        assert!(matches("/http/example.com"));
        assert!(matches("/https:/example.com/x"));
        // 隧道与普通路径不拦截
        assert!(!matches("/"));
        assert!(!matches("/api/v1"));
        assert!(!matches("/__sluice/health"));
    }

    #[test]
    fn bearer_and_query_token() {
        let expected = "0123456789abcdef";
        assert!(authorized(&req("/x", Some(expected)), expected));
        assert!(!authorized(
            &req("/x", Some("wrong-token-012345")),
            expected
        ));
        assert!(!authorized(&req("/x", None), expected));
        assert!(authorized(
            &req("/x?__token=0123456789abcdef", None),
            expected
        ));
        assert!(!authorized(&req("/x?__token=nope&a=1", None), expected));
    }
}
