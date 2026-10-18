//! 路径式转发的目标解析：`/https://host/path` 与 `/https/host/path`。
//!
//! 两种形式都要支持：URL 里的 `//` 会被一部分 HTTP 客户端和框架折叠成 `/`，
//! 只认一种形式会在真实调用里莫名 400。
//!
//! 解析过程**不做百分号解码**，path 与 query 原样透传——解码后再拼回去会
//! 破坏上游对原始字节的语义（尤其是签名类接口）。

use std::fmt;

use thiserror::Error;

/// 目标协议。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 解析后的转发目标。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub scheme: Scheme,
    pub host: String,
    pub port: Option<u16>,
    /// 始终以 `/` 开头的 path + query 原始字节。
    pub path_and_query: String,
}

impl Target {
    /// `host[:port]`，用于 Host 头。
    pub fn authority(&self) -> String {
        match self.port {
            Some(p) => format!("{}:{}", self.host, p),
            None => self.host.clone(),
        }
    }

    /// 完整 URL，用于日志与出网请求。
    pub fn url(&self) -> String {
        format!(
            "{}://{}{}",
            self.scheme.as_str(),
            self.authority(),
            self.path_and_query
        )
    }

    /// 默认端口。
    pub fn default_port(&self) -> u16 {
        match self.scheme {
            Scheme::Http => 80,
            Scheme::Https => 443,
        }
    }

    /// 实际连接端口。
    pub fn effective_port(&self) -> u16 {
        self.port.unwrap_or_else(|| self.default_port())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PathError {
    #[error("路径必须以 / 开头")]
    NotAbsolute,

    #[error("缺少协议前缀：路径应以 /https/ 或 /http/ 开头")]
    MissingScheme,

    #[error("目标主机为空")]
    EmptyHost,

    #[error("目标主机含非法字符：{0}")]
    InvalidHost(String),

    #[error("目标端口非法：{0}")]
    InvalidPort(String),
}

/// 大小写不敏感地剥掉前缀，返回剩余部分。
fn strip_prefix_ci<'a>(input: &'a str, prefix: &str) -> Option<&'a str> {
    if input.len() >= prefix.len() && input[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&input[prefix.len()..])
    } else {
        None
    }
}

/// 解析 `/https://host/path` 这类路径。
pub fn parse_target(input: &str) -> Result<Target, PathError> {
    let rest = input.strip_prefix('/').ok_or(PathError::NotAbsolute)?;

    // 先认带冒号的规范形式，再认被折叠掉一个斜杠的形式
    let (scheme, after) = if let Some(r) = strip_prefix_ci(rest, "https:") {
        (Scheme::Https, r)
    } else if let Some(r) = strip_prefix_ci(rest, "http:") {
        (Scheme::Http, r)
    } else if let Some(r) = strip_prefix_ci(rest, "https/") {
        (Scheme::Https, r)
    } else if let Some(r) = strip_prefix_ci(rest, "http/") {
        (Scheme::Http, r)
    } else {
        return Err(PathError::MissingScheme);
    };

    // `https://host` → `//host`；`https:/host` → `/host`；`https/host` → `host`
    // 最多剥两个斜杠：`https:///x` 这种畸形写法要留一个，好让下面判定空主机
    let after = after.strip_prefix('/').unwrap_or(after);
    let after = after.strip_prefix('/').unwrap_or(after);

    let split_at = after.find(['/', '?']).unwrap_or(after.len());
    let host_part = &after[..split_at];
    let tail = &after[split_at..];

    if host_part.is_empty() {
        return Err(PathError::EmptyHost);
    }

    let (host, port) = split_host_port(host_part)?;

    if host.is_empty() {
        return Err(PathError::EmptyHost);
    }
    if host
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == '@' || c == '/' || c == '\\')
    {
        return Err(PathError::InvalidHost(host.to_string()));
    }

    let path_and_query = if tail.is_empty() {
        "/".to_string()
    } else if tail.starts_with('?') {
        format!("/{tail}")
    } else {
        tail.to_string()
    };

    Ok(Target {
        scheme,
        host,
        port,
        path_and_query,
    })
}

fn split_host_port(host_part: &str) -> Result<(String, Option<u16>), PathError> {
    // 支持 `[::1]:8080` 这种带方括号的 IPv6 字面量
    if let Some(rest) = host_part.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return Err(PathError::InvalidHost(host_part.to_string()));
        };
        let host = &rest[..end];
        let after = &rest[end + 1..];
        let port = match after.strip_prefix(':') {
            Some(p) if !p.is_empty() => Some(parse_port(p)?),
            Some(_) => return Err(PathError::InvalidPort(String::new())),
            None if after.is_empty() => None,
            None => return Err(PathError::InvalidHost(host_part.to_string())),
        };
        return Ok((format!("[{host}]"), port));
    }

    match host_part.rsplit_once(':') {
        Some((h, p)) => Ok((h.to_string(), Some(parse_port(p)?))),
        None => Ok((host_part.to_string(), None)),
    }
}

fn parse_port(raw: &str) -> Result<u16, PathError> {
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PathError::InvalidPort(raw.to_string()));
    }
    raw.parse::<u16>()
        .map_err(|_| PathError::InvalidPort(raw.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_form() {
        let t = parse_target("/https://api.deepseek.com/chat/completions").unwrap();
        assert_eq!(t.scheme, Scheme::Https);
        assert_eq!(t.host, "api.deepseek.com");
        assert_eq!(t.port, None);
        assert_eq!(t.path_and_query, "/chat/completions");
        assert_eq!(t.url(), "https://api.deepseek.com/chat/completions");
    }

    #[test]
    fn collapsed_slashes_form() {
        // 部分客户端会把 `//` 折叠成 `/`
        let t = parse_target("/https/api.deepseek.com/chat/completions").unwrap();
        assert_eq!(t.host, "api.deepseek.com");
        assert_eq!(t.path_and_query, "/chat/completions");

        let t2 = parse_target("/https:/api.deepseek.com/chat").unwrap();
        assert_eq!(t2.host, "api.deepseek.com");
        assert_eq!(t2.path_and_query, "/chat");
    }

    #[test]
    fn query_is_preserved_raw() {
        let t = parse_target("/http/example.com/a?b=1&c=%2F").unwrap();
        assert_eq!(t.scheme, Scheme::Http);
        assert_eq!(t.path_and_query, "/a?b=1&c=%2F");
    }

    #[test]
    fn query_without_path() {
        let t = parse_target("/https/example.com?x=1").unwrap();
        assert_eq!(t.path_and_query, "/?x=1");
    }

    #[test]
    fn host_only_becomes_root() {
        let t = parse_target("/https://example.com").unwrap();
        assert_eq!(t.path_and_query, "/");
        assert_eq!(t.authority(), "example.com");
    }

    #[test]
    fn explicit_port() {
        let t = parse_target("/http/localhost:8080/x").unwrap();
        assert_eq!(t.host, "localhost");
        assert_eq!(t.port, Some(8080));
        assert_eq!(t.effective_port(), 8080);
        assert_eq!(t.authority(), "localhost:8080");
    }

    #[test]
    fn default_ports() {
        let t = parse_target("/https/example.com/").unwrap();
        assert_eq!(t.effective_port(), 443);
        let t = parse_target("/http/example.com/").unwrap();
        assert_eq!(t.effective_port(), 80);
    }

    #[test]
    fn scheme_is_case_insensitive() {
        let t = parse_target("/HTTPS://Example.COM/Path").unwrap();
        assert_eq!(t.scheme, Scheme::Https);
        assert_eq!(t.host, "Example.COM");
        assert_eq!(t.path_and_query, "/Path");
    }

    #[test]
    fn ipv6_literal() {
        let t = parse_target("/https/[2001:db8::1]:8443/x").unwrap();
        assert_eq!(t.host, "[2001:db8::1]");
        assert_eq!(t.port, Some(8443));
    }

    #[test]
    fn rejects_relative_path() {
        assert_eq!(parse_target("https://x/y"), Err(PathError::NotAbsolute));
    }

    #[test]
    fn rejects_missing_scheme() {
        assert_eq!(parse_target("/api/v1/x"), Err(PathError::MissingScheme));
    }

    #[test]
    fn rejects_empty_host() {
        assert_eq!(parse_target("/https:///x"), Err(PathError::EmptyHost));
        assert_eq!(parse_target("/https/"), Err(PathError::EmptyHost));
    }

    #[test]
    fn rejects_bad_port() {
        assert_eq!(
            parse_target("/http/example.com:abc/x"),
            Err(PathError::InvalidPort("abc".into()))
        );
        assert_eq!(
            parse_target("/http/example.com:99999/x"),
            Err(PathError::InvalidPort("99999".into()))
        );
    }

    #[test]
    fn rejects_userinfo_and_spaces() {
        assert!(matches!(
            parse_target("/http/user@host/x"),
            Err(PathError::InvalidHost(_))
        ));
        assert!(matches!(
            parse_target("/http/ho st/x"),
            Err(PathError::InvalidHost(_))
        ));
    }

    #[test]
    fn keeps_double_slash_in_path() {
        let t = parse_target("/https/example.com//a//b").unwrap();
        assert_eq!(t.path_and_query, "//a//b");
    }
}
