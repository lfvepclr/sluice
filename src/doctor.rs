//! 自检子命令：配置、权限、DNS、端口、证书、内存逐项体检。
//!
//! 结果分三档：`Ok` / `Warn` / `Fail`。有 `Fail` 退出码 1，只有 `Warn` 退出码 0，
//! 配置加载失败由 `main` 统一映射为退出码 2。

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use tokio::net::{TcpListener, TcpStream};

use crate::config::{ServerConfig, TlsMode};
use crate::server::tls;

/// 单项检查结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

/// 一项检查：名称、结论、说明。
#[derive(Debug, Clone)]
pub struct Check {
    pub name: &'static str,
    pub level: Level,
    pub detail: String,
}

impl Check {
    fn new(name: &'static str, level: Level, detail: impl Into<String>) -> Self {
        Self {
            name,
            level,
            detail: detail.into(),
        }
    }
}

/// 退出码：有 Fail → 1，否则 0（配置错误在加载阶段就已被 `main` 映射为 2）。
pub fn exit_code(checks: &[Check]) -> u8 {
    if checks.iter().any(|c| c.level == Level::Fail) {
        1
    } else {
        0
    }
}

/// 执行全部检查。
pub async fn run(cfg: &ServerConfig, cfg_path: &Path) -> Result<Vec<Check>> {
    let mut checks = Vec::new();
    checks.push(check_permissions(cfg_path));
    checks.push(check_dns(cfg).await);
    checks.extend(check_ports(cfg).await);
    checks.push(check_certificate(cfg));
    checks.push(check_rss());
    checks.push(check_legacy_443().await);
    Ok(checks)
}

/// 配置文件权限：宽于 0600 时告警。
fn check_permissions(path: &Path) -> Check {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        match std::fs::metadata(path) {
            Ok(meta) => {
                let mode = meta.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    Check::new(
                        "配置权限",
                        Level::Warn,
                        format!(
                            "{} 权限 {mode:o} 对其他用户开放，建议 chmod 600",
                            path.display()
                        ),
                    )
                } else {
                    Check::new("配置权限", Level::Ok, format!("{mode:o}（{path:?}）"))
                }
            }
            Err(e) => Check::new("配置权限", Level::Warn, format!("无法读取：{e}")),
        }
    }

    #[cfg(not(unix))]
    {
        Check::new("配置权限", Level::Ok, "当前平台不检查")
    }
}

/// DNS：基础域名应能解析；配置了 `public_ip` 时必须一致。
async fn check_dns(cfg: &ServerConfig) -> Check {
    match tokio::net::lookup_host((cfg.base_domain.as_str(), 80)).await {
        Err(e) => Check::new(
            "DNS 解析",
            Level::Warn,
            format!(
                "{} 解析失败：{e}（本地联调或 DNS 未生效时可忽略）",
                cfg.base_domain
            ),
        ),
        Ok(addrs) => {
            let ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
            match cfg.public_ip {
                Some(expected) => {
                    if ips.iter().any(|ip| ip == &expected.to_string()) {
                        Check::new(
                            "DNS 解析",
                            Level::Ok,
                            format!("{} → {ips:?} 与 public_ip 一致", cfg.base_domain),
                        )
                    } else {
                        Check::new(
                            "DNS 解析",
                            Level::Fail,
                            format!(
                                "{} → {ips:?}，与配置的 public_ip {expected} 不一致",
                                cfg.base_domain
                            ),
                        )
                    }
                }
                None => Check::new(
                    "DNS 解析",
                    Level::Ok,
                    format!("{} → {ips:?}（未配置 public_ip，不比对）", cfg.base_domain),
                ),
            }
        }
    }
}

/// 端口：逐个尝试绑定配置的监听地址。
async fn check_ports(cfg: &ServerConfig) -> Vec<Check> {
    let mut checks = Vec::new();
    for (name, addr) in [
        ("端口 7835（控制面）", cfg.listen.control),
        ("端口 80（HTTP 入口）", cfg.listen.http),
    ] {
        checks.push(bind_check(name, addr).await);
    }
    if let Some(addr) = cfg.listen.https {
        checks.push(bind_check("端口 8443（HTTPS 入口）", addr).await);
    }
    checks
}

async fn bind_check(name: &'static str, addr: SocketAddr) -> Check {
    match TcpListener::bind(addr).await {
        // 绑定成功后立即 drop，不留占位
        Ok(listener) => {
            drop(listener);
            Check::new(name, Level::Ok, format!("{addr} 可绑定"))
        }
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => Check::new(
            name,
            Level::Warn,
            format!("{addr} 已被占用——若为 sluice 自身在运行则属正常"),
        ),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Check::new(
            name,
            Level::Fail,
            format!("{addr} 无权绑定（特权端口需要 root 或 cap_net_bind_service）"),
        ),
        Err(e) => Check::new(name, Level::Warn, format!("{addr} 绑定失败：{e}")),
    }
}

/// 证书：剩余 <7 天 Fail、<30 天 Warn；Files 模式缺证书算 Fail。
fn check_certificate(cfg: &ServerConfig) -> Check {
    let name = "证书有效期";

    let (cert_pem, key_pem) = match tls::load_files(&cfg.tls.cert_dir) {
        Ok((cert, key)) => (cert, key),
        Err(e) => {
            let level = match cfg.tls.mode {
                // ACME 模式会用 7 天自签顶住并自动签发，缺证书只是暂态
                TlsMode::Acme | TlsMode::SelfSigned => Level::Warn,
                TlsMode::Files => Level::Fail,
            };
            return Check::new(name, level, format!("读取证书失败：{e:#}"));
        }
    };

    match tls::CertStore::from_der(cert_pem, key_pem) {
        Ok(store) => match store.days_left() {
            Ok(days) if days < 7 => {
                Check::new(name, Level::Fail, format!("仅剩 {days} 天，须立即续期"))
            }
            Ok(days) if days < 30 => {
                Check::new(name, Level::Warn, format!("仅剩 {days} 天，即将续期"))
            }
            Ok(days) => Check::new(name, Level::Ok, format!("剩余 {days} 天")),
            Err(e) => Check::new(name, Level::Warn, format!("有效期解析失败：{e:#}")),
        },
        Err(e) => Check::new(name, Level::Fail, format!("证书装载失败：{e:#}")),
    }
}

/// 内存：信息项，只在拿得到时展示。
fn check_rss() -> Check {
    match crate::sys::rss_kib() {
        Some(kib) => Check::new("内存 RSS", Level::Ok, format!("{kib} KiB")),
        None => Check::new("内存 RSS", Level::Ok, "无法采集"),
    }
}

/// 443 探测：仅提示既有服务占用情况，sluice 永不使用 443。
async fn check_legacy_443() -> Check {
    let name = "端口 443";
    match tokio::time::timeout(
        Duration::from_secs(2),
        TcpStream::connect(("127.0.0.1", 443)),
    )
    .await
    {
        Ok(Ok(_)) => Check::new(name, Level::Ok, "被既有服务占用（预期，sluice 不使用 443）"),
        Ok(Err(_)) | Err(_) => Check::new(name, Level::Ok, "本机 443 无监听"),
    }
}

/// 逐行打印。`tty` 为 false 时输出纯行（无颜色、无 emoji），便于重定向与 CI。
pub fn print(checks: &[Check], tty: bool) {
    for check in checks {
        let (mark, color) = match check.level {
            Level::Ok => ("OK", "\x1b[32m"),
            Level::Warn => ("WARN", "\x1b[33m"),
            Level::Fail => ("FAIL", "\x1b[31m"),
        };
        if tty {
            println!("{color}[{mark}]\x1b[0m {:<24} {}", check.name, check.detail);
        } else {
            println!("[{mark}] {} {}", check.name, check.detail);
        }
    }

    let fail = checks.iter().filter(|c| c.level == Level::Fail).count();
    let warn = checks.iter().filter(|c| c.level == Level::Warn).count();
    let summary = format!("检查完成：{} 项，{fail} 失败，{warn} 警告", checks.len());
    if tty {
        let color = if fail > 0 { "\x1b[31m" } else { "\x1b[32m" };
        println!("{color}{summary}\x1b[0m");
    } else {
        println!("{summary}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_code_depends_only_on_fail() {
        let all_ok = vec![
            Check::new("a", Level::Ok, ""),
            Check::new("b", Level::Ok, ""),
        ];
        assert_eq!(exit_code(&all_ok), 0);

        let warn_only = vec![Check::new("a", Level::Warn, "")];
        assert_eq!(exit_code(&warn_only), 0);

        let with_fail = vec![
            Check::new("a", Level::Ok, ""),
            Check::new("b", Level::Fail, ""),
        ];
        assert_eq!(exit_code(&with_fail), 1);

        assert_eq!(exit_code(&[]), 0);
    }

    #[test]
    fn check_rss_never_fails() {
        let check = check_rss();
        assert_eq!(check.level, Level::Ok);
    }
}
