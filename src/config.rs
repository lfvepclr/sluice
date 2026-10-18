//! 配置加载：命令行 > 环境变量 > 配置文件 > 内置默认值。
//!
//! 设计原则是「极简」：服务端配置文件最少只需三个字段
//! （`base_domain` / `token` / `dns_token`），其余全部有合理默认值。
//! 不暴露缓冲区大小、流控窗口、超时、连接池等调参项——这些值在代码里
//! 就是性能最优值，让用户调只会把性能调坏。

use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// 服务端默认配置路径。
pub const DEFAULT_CONFIG_PATH: &str = "/etc/sluice/server.toml";
/// 控制面默认监听地址。
pub const DEFAULT_CONTROL: &str = "0.0.0.0:7835";
/// HTTP 入口默认监听地址。
pub const DEFAULT_HTTP: &str = "0.0.0.0:80";
/// HTTPS 入口默认监听地址（443 留给既有服务，这里用 8443）。
pub const DEFAULT_HTTPS: &str = "0.0.0.0:8443";
/// 证书默认存放目录。
pub const DEFAULT_CERT_DIR: &str = "/var/lib/sluice/certs";
/// token 最小长度。
pub const MIN_TOKEN_LEN: usize = 16;

// ───────────────────────────── 错误 ─────────────────────────────

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("配置文件不存在：{0}\n提示：最少需要 base_domain、token、dns_token 三个字段")]
    NotFound(PathBuf),

    #[error("读取配置失败 {path}：{source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("解析配置失败 {path}：{source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    #[error("字段 `{field}` 无效：{problem}")]
    Invalid {
        field: &'static str,
        problem: String,
    },
}

impl ConfigError {
    fn invalid(field: &'static str, problem: impl Into<String>) -> Self {
        Self::Invalid {
            field,
            problem: problem.into(),
        }
    }
}

// ───────────────────────────── 服务端配置 ─────────────────────────────

/// 服务端配置。除前三个字段外全部可省略。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// 基础域名，例如 `xxx.duckdns.org`。子域名形如 `<random>.<base_domain>`。
    pub base_domain: String,

    /// 客户端与服务器共享的认证 token。
    pub token: String,

    /// DNS 服务商 API token，用于 DNS-01 签发通配证书。
    /// `tls.mode = "acme"` 时必填。
    #[serde(default)]
    pub dns_token: Option<String>,

    /// 公网 IP，用于 doctor 校验 DNS 是否指对地方。可省略。
    #[serde(default)]
    pub public_ip: Option<std::net::IpAddr>,

    #[serde(default)]
    pub listen: ListenConfig,

    #[serde(default)]
    pub tls: TlsConfig,

    #[serde(default)]
    pub forward: ForwardConfig,

    #[serde(default)]
    pub limits: LimitsConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenConfig {
    #[serde(default = "default_control")]
    pub control: SocketAddr,
    #[serde(default = "default_http")]
    pub http: SocketAddr,
    /// 设为 false 可关闭 HTTPS 入口。
    #[serde(default = "default_https")]
    pub https: Option<SocketAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsMode {
    /// 通过 ACME DNS-01 自动签发通配证书。
    Acme,
    /// 现生成自签证书，仅用于本地联调。
    SelfSigned,
    /// 从 `cert_dir` 读取已备好的证书。
    Files,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsKind {
    Duckdns,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    #[serde(default = "default_tls_mode")]
    pub mode: TlsMode,
    /// ACME 账号邮箱，可省略。
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default = "default_dns_kind")]
    pub dns: DnsKind,
    #[serde(default = "default_cert_dir")]
    pub cert_dir: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardConfig {
    /// 是否允许转发到私有网段。默认禁止（SSRF 防护）。
    #[serde(default)]
    pub allow_private: bool,
    /// 目标域名白名单。非空时只放行名单内域名。
    #[serde(default)]
    pub allow_hosts: Vec<String>,
    /// 请求体上限（MiB）。
    #[serde(default = "default_max_body_mib")]
    pub max_body_mib: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
    /// 每会话并发流上限。单核 3 Mbps 环境下不宜放大。
    #[serde(default = "default_max_streams")]
    pub max_streams_per_session: usize,
    /// 会话断开后子域名保留时长（秒）。
    #[serde(default = "default_reserved_secs")]
    pub reserved_secs: u64,
}

// ───────────────────────────── 默认值 ─────────────────────────────

fn default_control() -> SocketAddr {
    DEFAULT_CONTROL.parse().expect("常量地址合法")
}
fn default_http() -> SocketAddr {
    DEFAULT_HTTP.parse().expect("常量地址合法")
}
fn default_https() -> Option<SocketAddr> {
    Some(DEFAULT_HTTPS.parse().expect("常量地址合法"))
}
fn default_tls_mode() -> TlsMode {
    TlsMode::Acme
}
fn default_dns_kind() -> DnsKind {
    DnsKind::Duckdns
}
fn default_cert_dir() -> PathBuf {
    PathBuf::from(DEFAULT_CERT_DIR)
}
fn default_max_body_mib() -> u64 {
    100
}
fn default_max_sessions() -> usize {
    256
}
fn default_max_streams() -> usize {
    128
}
fn default_reserved_secs() -> u64 {
    60
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            control: default_control(),
            http: default_http(),
            https: default_https(),
        }
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            mode: default_tls_mode(),
            email: None,
            dns: default_dns_kind(),
            cert_dir: default_cert_dir(),
        }
    }
}

impl Default for ForwardConfig {
    fn default() -> Self {
        Self {
            allow_private: false,
            allow_hosts: Vec::new(),
            max_body_mib: default_max_body_mib(),
        }
    }
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_sessions: default_max_sessions(),
            max_streams_per_session: default_max_streams(),
            reserved_secs: default_reserved_secs(),
        }
    }
}

// ───────────────────────────── 加载与校验 ─────────────────────────────

impl ServerConfig {
    /// 从文件加载。文件不存在时返回 [`ConfigError::NotFound`]。
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ConfigError::NotFound(path.to_path_buf())
            } else {
                ConfigError::Io {
                    path: path.to_path_buf(),
                    source: e,
                }
            }
        })?;

        let mut cfg: Self = toml::from_str(&text).map_err(|e| ConfigError::Parse {
            path: path.to_path_buf(),
            source: e,
        })?;

        cfg.apply_env_overrides();
        cfg.validate()?;
        Ok(cfg)
    }

    /// 环境变量覆盖：`SLUICE_BASE_DOMAIN` / `SLUICE_TOKEN` / `SLUICE_DNS_TOKEN`。
    /// 便于在容器或 CI 中免配置文件启动。
    pub fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("SLUICE_BASE_DOMAIN") {
            self.base_domain = v;
        }
        if let Ok(v) = std::env::var("SLUICE_TOKEN") {
            self.token = v;
        }
        if let Ok(v) = std::env::var("SLUICE_DNS_TOKEN") {
            self.dns_token = Some(v);
        }
    }

    /// 校验字段合法性。错误信息必须指明**具体字段名**，这是排查配置问题的关键。
    pub fn validate(&self) -> Result<(), ConfigError> {
        let domain = self.base_domain.trim();
        if domain.is_empty() {
            return Err(ConfigError::invalid(
                "base_domain",
                "不能为空，例如 \"myapp.duckdns.org\"",
            ));
        }
        if !domain.contains('.') {
            return Err(ConfigError::invalid(
                "base_domain",
                format!("`{domain}` 不是完整域名，至少要有一个点"),
            ));
        }
        if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
            return Err(ConfigError::invalid(
                "base_domain",
                format!("`{domain}` 有点号位置错误"),
            ));
        }
        if !domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        {
            return Err(ConfigError::invalid(
                "base_domain",
                format!("`{domain}` 含非法字符，只允许字母、数字、连字符和点"),
            ));
        }

        if self.token.len() < MIN_TOKEN_LEN {
            return Err(ConfigError::invalid(
                "token",
                format!("长度不足 {MIN_TOKEN_LEN} 字节，建议用 `openssl rand -hex 24` 生成"),
            ));
        }

        if self.tls.mode == TlsMode::Acme && self.dns_token.as_deref().unwrap_or("").is_empty() {
            return Err(ConfigError::invalid(
                "dns_token",
                "tls.mode = \"acme\" 时必须提供 DNS 服务商 API token",
            ));
        }

        if self.limits.max_sessions == 0 {
            return Err(ConfigError::invalid("limits.max_sessions", "不能为 0"));
        }
        if !(1..=4096).contains(&self.limits.max_streams_per_session) {
            return Err(ConfigError::invalid(
                "limits.max_streams_per_session",
                "取值范围 1..=4096",
            ));
        }
        if !(1..=4096).contains(&self.forward.max_body_mib) {
            return Err(ConfigError::invalid(
                "forward.max_body_mib",
                "取值范围 1..=4096",
            ));
        }

        Ok(())
    }

    /// 打码后的 token，用于日志与启动摘要。
    pub fn token_hint(&self) -> String {
        redact(&self.token)
    }

    /// 公网入口地址模板，用于启动时打印。
    pub fn public_url_template(&self) -> String {
        format!("<subdomain>.{}", self.base_domain)
    }
}

/// 把敏感串打码成 `abcd…wxyz` 形式，长度不足时全掩。
pub fn redact(s: &str) -> String {
    let n = s.chars().count();
    if n <= 8 {
        return "****".to_string();
    }
    let head: String = s.chars().take(4).collect();
    let tail: String = s.chars().skip(n - 4).collect();
    format!("{head}…{tail}")
}

/// 检查配置文件权限，宽于 0600 时给出告警（不阻断启动）。
#[cfg(unix)]
pub fn check_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            tracing::warn!(
                path = %path.display(),
                mode = format!("{mode:o}"),
                "配置文件对其他用户可读，建议 chmod 600"
            );
        }
    }
}

#[cfg(not(unix))]
pub fn check_permissions(_path: &Path) {}

// ───────────────────────────── 客户端配置 ─────────────────────────────

/// 转发模式出口位置。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EgressMode {
    /// 经服务器出网：隐藏本机 IP，代价是多一跳延迟。
    #[default]
    Server,
    /// 本机直连出网：延迟最低，但本机 IP 暴露给上游。
    Local,
}

impl fmt::Display for EgressMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Server => f.write_str("server"),
            Self::Local => f.write_str("local"),
        }
    }
}

/// 客户端配置，落在 `~/.config/sluice/config.toml`。
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct ClientConfig {
    /// 服务器控制面地址，形如 `host:7835`。
    pub server: Option<String>,
    pub token: Option<String>,
    /// 首次连接时记录的服务器证书 SPKI 指纹（TOFU）。
    pub spki_sha256: Option<String>,
    pub egress: EgressMode,
    /// 转发模式本地监听端口。
    pub forward_port: u16,
    /// expose 模式默认本地端口。
    pub local_port: Option<u16>,
    /// 期望的子域名，省略则随机分配。
    pub subdomain: Option<String>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server: None,
            token: None,
            spki_sha256: None,
            egress: EgressMode::Server,
            forward_port: 1234,
            local_port: None,
            subdomain: None,
        }
    }
}

impl ClientConfig {
    /// 默认配置目录：`$XDG_CONFIG_HOME/sluice` 或 `~/.config/sluice`。
    pub fn default_dir() -> Option<PathBuf> {
        if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME") {
            return Some(PathBuf::from(dir).join("sluice"));
        }
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config").join("sluice"))
    }

    /// 默认配置文件路径。
    pub fn default_path() -> Option<PathBuf> {
        Self::default_dir().map(|d| d.join("config.toml"))
    }

    /// 从默认路径加载；文件不存在或解析失败时返回默认值（客户端不应因此启动失败）。
    pub fn load_default() -> Self {
        let Some(path) = Self::default_path() else {
            return Self::default();
        };
        match std::fs::read_to_string(&path) {
            Ok(text) => toml::from_str(&text).unwrap_or_else(|e| {
                tracing::warn!(path = %path.display(), error = %e, "客户端配置解析失败，使用默认值");
                Self::default()
            }),
            Err(_) => Self::default(),
        }
    }

    /// 环境变量覆盖：`SLUICE_SERVER` / `SLUICE_TOKEN`。
    pub fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("SLUICE_SERVER") {
            self.server = Some(v);
        }
        if let Ok(v) = std::env::var("SLUICE_TOKEN") {
            self.token = Some(v);
        }
    }

    /// 写回磁盘（首次输入 token 后缓存）。
    pub fn save(&self) -> std::io::Result<PathBuf> {
        let dir = Self::default_dir().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "无法确定配置目录")
        })?;
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("config.toml");
        let text = toml::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&path, text)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(path)
    }
}

// ───────────────────────────── 测试 ─────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> ServerConfig {
        ServerConfig {
            base_domain: "demo.duckdns.org".into(),
            token: "0123456789abcdef".into(),
            dns_token: Some("dns-token".into()),
            public_ip: None,
            listen: ListenConfig::default(),
            tls: TlsConfig::default(),
            forward: ForwardConfig::default(),
            limits: LimitsConfig::default(),
        }
    }

    #[test]
    fn defaults_are_sane() {
        let cfg = base();
        assert_eq!(cfg.listen.http.to_string(), DEFAULT_HTTP);
        assert_eq!(cfg.listen.https.map(|a| a.to_string()).as_deref(), Some(DEFAULT_HTTPS));
        assert_eq!(cfg.listen.control.to_string(), DEFAULT_CONTROL);
        assert_eq!(cfg.limits.reserved_secs, 60);
        assert!(!cfg.forward.allow_private);
    }

    #[test]
    fn minimal_toml_parses() {
        let text = r#"
base_domain = "demo.duckdns.org"
token = "0123456789abcdef"
dns_token = "dns-token"
"#;
        let cfg: ServerConfig = toml::from_str(text).expect("应能解析");
        assert_eq!(cfg.listen.http.port(), 80);
        assert_eq!(cfg.tls.mode, TlsMode::Acme);
        assert_eq!(cfg.limits.max_streams_per_session, 128);
    }

    #[test]
    fn empty_domain_is_rejected_with_field_name() {
        let mut cfg = base();
        cfg.base_domain = "  ".into();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("base_domain"), "错误信息应指明字段：{err}");
    }

    #[test]
    fn domain_without_dot_is_rejected() {
        let mut cfg = base();
        cfg.base_domain = "localhost".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn short_token_is_rejected() {
        let mut cfg = base();
        cfg.token = "short".into();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("token"));
    }

    #[test]
    fn acme_requires_dns_token() {
        let mut cfg = base();
        cfg.dns_token = None;
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("dns_token"), "应指明 dns_token：{err}");
    }

    #[test]
    fn self_signed_does_not_require_dns_token() {
        let mut cfg = base();
        cfg.dns_token = None;
        cfg.tls.mode = TlsMode::SelfSigned;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn redact_hides_middle() {
        assert_eq!(redact("abcdefghijkl"), "abcd…ijkl");
        assert_eq!(redact("short"), "****");
    }

    #[test]
    fn unknown_field_is_rejected() {
        let text = r#"
base_domain = "demo.duckdns.org"
token = "0123456789abcdef"
dns_token = "x"
typo_field = 1
"#;
        assert!(toml::from_str::<ServerConfig>(text).is_err());
    }

    #[test]
    fn egress_mode_roundtrip() {
        assert_eq!(EgressMode::default(), EgressMode::Server);
        assert_eq!(EgressMode::Local.to_string(), "local");
    }
}
