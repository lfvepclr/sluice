//! 转发模式的服务器侧：接住 agent 开来的流，由服务器出网。
//!
//! 这里是 SSRF 防护的唯一关口：解析目标、判定网段、把解析结果固定下来，
//! 再交给 `upstream` 发起请求。

use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::Arc;

use http::{Request, Response, StatusCode};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::AsyncReadExt;
use yamux::Stream;

use super::App;
use super::tunnel::KIND_FORWARD;
use crate::agent::forward::ForwardMeta;
use crate::common::body::{BoxedBody, text};
use crate::common::ssrf;
use crate::common::upgrade;
use crate::common::upstream;
use crate::common::urlpath::{self, Target};
use crate::transport;

/// 元信息长度上限，防止恶意客户端塞一个巨大的 JSON。
const MAX_META_LEN: u32 = 8 * 1024;

/// 处理一条 forward 流。
pub async fn serve_stream(stream: Stream, app: Arc<App>) {
    if let Err(e) = handle_stream(stream, app).await {
        tracing::debug!(error = %e, "forward 流结束");
    }
}

async fn handle_stream(stream: Stream, app: Arc<App>) -> anyhow::Result<()> {
    let mut io = transport::into_tokio(stream);

    let mut kind = [0u8; 1];
    io.read_exact(&mut kind).await?;
    if kind[0] != KIND_FORWARD {
        anyhow::bail!("流类型 {} 不是 forward", kind[0]);
    }

    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_META_LEN {
        anyhow::bail!("元信息过长：{len}");
    }

    let mut payload = vec![0u8; len as usize];
    io.read_exact(&mut payload).await?;
    let meta: ForwardMeta = serde_json::from_slice(&payload)?;

    let service = service_fn(move |req| {
        let app = app.clone();
        let path = meta.path.clone();
        let client_ip = meta.client_ip.clone();
        async move { Ok::<_, Infallible>(handle(app, req, path, client_ip).await) }
    });

    hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(io), service)
        .with_upgrades()
        .await?;

    Ok(())
}

async fn handle(
    app: Arc<App>,
    mut req: Request<hyper::body::Incoming>,
    path: String,
    client_ip: String,
) -> Response<BoxedBody> {
    let target = match urlpath::parse_target(&path) {
        Ok(t) => t,
        Err(e) => return text(StatusCode::BAD_REQUEST, format!("路径解析失败：{e}")),
    };

    let pinned = match check_target(&app, &target).await {
        Ok(ip) => ip,
        Err(reason) => {
            tracing::warn!(client = %client_ip, target = %target.url(), %reason, "拒绝转发");
            return text(StatusCode::FORBIDDEN, format!("拒绝转发：{reason}"));
        }
    };

    tracing::info!(client = %client_ip, target = %target.url(), "转发请求");

    let client_upgrade = upgrade::take_client(&mut req);

    let mut response = match upstream::fetch(&target, req, pinned).await {
        Ok(response) => response,
        Err(e) => return text(StatusCode::BAD_GATEWAY, format!("上游请求失败：{e}")),
    };

    upgrade::bridge_if_upgraded(client_upgrade, &mut response);
    response
}

/// 白名单与网段校验。返回需要固定的 IP（防 DNS rebinding）。
///
/// forward 流与入口直连转发共用这一道 SSRF 关口。
pub(crate) async fn check_target(app: &App, target: &Target) -> Result<Option<IpAddr>, String> {
    if !app.cfg.forward.allow_hosts.is_empty() {
        let allowed = app
            .cfg
            .forward
            .allow_hosts
            .iter()
            .any(|h| h.eq_ignore_ascii_case(&target.host));
        if !allowed {
            return Err(format!("`{}` 不在 allow_hosts 白名单内", target.host));
        }
    }

    if app.cfg.forward.allow_private {
        return Ok(None);
    }

    let host = target.host.trim_start_matches('[').trim_end_matches(']');
    let addrs = tokio::net::lookup_host((host, target.effective_port()))
        .await
        .map_err(|e| format!("DNS 解析 `{host}` 失败：{e}"))?
        .collect::<Vec<_>>();

    if addrs.is_empty() {
        return Err(format!("`{host}` 没有解析结果"));
    }

    for addr in &addrs {
        if ssrf::is_metadata_ip(addr.ip()) {
            return Err("目标是云元数据地址".to_string());
        }
        if ssrf::is_forbidden_ip(addr.ip()) {
            return Err(format!("目标解析到内网/保留地址 {}", addr.ip()));
        }
    }

    Ok(Some(addrs[0].ip()))
}
