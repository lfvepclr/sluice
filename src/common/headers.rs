//! HTTP 头部处理：hop-by-hop 剥离与 `X-Forwarded-*` 注入。
//!
//! 代理必须剥掉 hop-by-hop 头，否则会把「只对当前这一跳有效」的语义
//! 传给下一跳，典型后果是 `Transfer-Encoding` 与 `Connection` 打架。

use std::net::IpAddr;

use http::header::{CONNECTION, HeaderMap, HeaderName, HeaderValue};

/// 固定要剥掉的 hop-by-hop 头（RFC 7230 §6.1）。
const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// 剥掉 hop-by-hop 头，以及 `Connection` 头里点名的自定义头。
pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    // 先收集，再删除：`Connection` 本身也在删除列表里
    let mut listed: Vec<String> = Vec::new();
    if let Some(value) = headers.get(CONNECTION)
        && let Ok(text) = value.to_str()
    {
        for token in text.split(',') {
            let token = token.trim();
            if !token.is_empty() {
                listed.push(token.to_ascii_lowercase());
            }
        }
    }

    for name in HOP_BY_HOP {
        headers.remove(name);
    }

    for token in listed {
        if let Ok(name) = HeaderName::from_bytes(token.as_bytes()) {
            headers.remove(&name);
        }
    }
}

/// 是否是一次协议升级请求（WebSocket 等）。
pub fn wants_upgrade(headers: &HeaderMap) -> bool {
    let connection_says_upgrade = headers
        .get(CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        })
        .unwrap_or(false);

    connection_says_upgrade && headers.contains_key("upgrade")
}

/// 剥离 hop-by-hop 头，但保留升级语义。
///
/// 升级请求必须把 `Connection: upgrade` 与 `Upgrade: websocket` 原样带到下一跳，
/// 否则本地服务看不到升级意图，握手永远失败。
pub fn strip_hop_by_hop_preserving_upgrade(headers: &mut HeaderMap) {
    let upgrade_requested = wants_upgrade(headers);
    // Upgrade 头本身也在剥离列表里，先留存再恢复，否则对端看不到协议名
    let upgrade_value = headers.get(http::header::UPGRADE).cloned();

    strip_hop_by_hop(headers);

    if upgrade_requested {
        headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
        if let Some(value) = upgrade_value {
            headers.insert(http::header::UPGRADE, value);
        }
    }
}

/// 追加 `X-Forwarded-For`：已有值则逗号拼接，保留上游链路。
pub fn append_forwarded_for(headers: &mut HeaderMap, client: IpAddr) {
    let entry = headers
        .entry("x-forwarded-for")
        .or_insert_with(|| HeaderValue::from_static(""));

    let existing = entry.to_str().unwrap_or("").trim().to_string();
    let value = if existing.is_empty() {
        client.to_string()
    } else {
        format!("{existing}, {client}")
    };

    if let Ok(v) = HeaderValue::from_str(&value) {
        *entry = v;
    }
}

/// 设置 `X-Forwarded-Proto`。
pub fn set_forwarded_proto(headers: &mut HeaderMap, proto: &'static str) {
    headers.insert("x-forwarded-proto", HeaderValue::from_static(proto));
}

/// 设置 `X-Forwarded-Host`（原始 Host）。
pub fn set_forwarded_host(headers: &mut HeaderMap, host: &str) {
    if let Ok(v) = HeaderValue::from_str(host) {
        headers.insert("x-forwarded-host", v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn map(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.append(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        m
    }

    #[test]
    fn strips_fixed_hop_by_hop_headers() {
        let mut m = map(&[
            ("keep-alive", "timeout=5"),
            ("transfer-encoding", "chunked"),
            ("upgrade", "websocket"),
            ("te", "trailers"),
            ("trailer", "x-checksum"),
            ("proxy-authorization", "Basic x"),
            ("proxy-authenticate", "Basic"),
            ("connection", "close"),
            ("content-type", "application/json"),
        ]);
        strip_hop_by_hop(&mut m);

        for gone in [
            "keep-alive",
            "transfer-encoding",
            "upgrade",
            "te",
            "trailer",
            "proxy-authorization",
            "proxy-authenticate",
            "connection",
        ] {
            assert!(!m.contains_key(gone), "{gone} 应被剥掉");
        }
        assert_eq!(m.get("content-type").unwrap(), "application/json");
    }

    #[test]
    fn strips_headers_listed_in_connection() {
        let mut m = map(&[
            ("connection", "keep-alive, X-Custom-Hop"),
            ("x-custom-hop", "1"),
            ("x-keep", "2"),
        ]);
        strip_hop_by_hop(&mut m);
        assert!(!m.contains_key("x-custom-hop"));
        assert_eq!(m.get("x-keep").unwrap(), "2");
    }

    #[test]
    fn connection_token_matching_is_case_insensitive() {
        let mut m = map(&[("connection", "X-CUSTOM-HOP"), ("x-custom-hop", "1")]);
        strip_hop_by_hop(&mut m);
        assert!(!m.contains_key("x-custom-hop"));
    }

    #[test]
    fn forwarded_for_appends() {
        let mut m = map(&[("x-forwarded-for", "1.1.1.1")]);
        append_forwarded_for(&mut m, "2.2.2.2".parse().unwrap());
        assert_eq!(m.get("x-forwarded-for").unwrap(), "1.1.1.1, 2.2.2.2");
    }

    #[test]
    fn forwarded_for_sets_when_absent() {
        let mut m = HeaderMap::new();
        append_forwarded_for(&mut m, "9.9.9.9".parse().unwrap());
        assert_eq!(m.get("x-forwarded-for").unwrap(), "9.9.9.9");
    }

    #[test]
    fn forwarded_proto_and_host() {
        let mut m = HeaderMap::new();
        set_forwarded_proto(&mut m, "https");
        set_forwarded_host(&mut m, "a.example.com");
        assert_eq!(m.get("x-forwarded-proto").unwrap(), "https");
        assert_eq!(m.get("x-forwarded-host").unwrap(), "a.example.com");
    }
}
