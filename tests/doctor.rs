//! doctor 集成测试：检查项结论与退出码约定。

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use sluice::config::{ForwardConfig, LimitsConfig, ListenConfig, ServerConfig, TlsConfig, TlsMode};
use sluice::doctor::{self, Level};

fn tmp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sluice-doctor-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_config(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("server.toml");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[cfg(not(unix))]
    std::fs::write(&path, body).unwrap();
    path
}

fn free_addr() -> SocketAddr {
    // 借用一个临时监听器拿到空闲端口，立即释放
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

fn test_config(dir: &Path) -> ServerConfig {
    ServerConfig {
        base_domain: "doctor-test.invalid".into(),
        token: "0123456789abcdef".into(),
        dns_token: None,
        public_ip: None,
        listen: ListenConfig {
            control: free_addr(),
            http: free_addr(),
            https: None,
        },
        tls: TlsConfig {
            mode: TlsMode::SelfSigned,
            email: None,
            dns: sluice::config::DnsKind::Duckdns,
            cert_dir: dir.join("certs"),
        },
        forward: ForwardConfig::default(),
        limits: LimitsConfig::default(),
    }
}

async fn run_checks(cfg: &ServerConfig, cfg_path: &Path) -> Vec<doctor::Check> {
    doctor::run(cfg, cfg_path).await.unwrap()
}

#[tokio::test]
async fn healthy_config_reports_no_fail() {
    let dir = tmp_dir("healthy");
    let cfg_path = write_config(
        &dir,
        "base_domain = \"doctor-test.invalid\"\ntoken = \"0123456789abcdef\"\n",
    );
    let cfg = test_config(&dir);

    let checks = run_checks(&cfg, &cfg_path).await;
    doctor::print(&checks, false);

    let fails: Vec<_> = checks
        .iter()
        .filter(|c| c.level == Level::Fail)
        .map(|c| format!("{}: {}", c.name, c.detail))
        .collect();
    assert!(fails.is_empty(), "不应有 Fail：{fails:?}");
    assert_eq!(doctor::exit_code(&checks), 0);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn loose_permissions_trigger_warning() {
    let dir = tmp_dir("perm");
    let cfg_path = dir.join("server.toml");
    std::fs::write(&cfg_path, "x").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    let cfg = test_config(&dir);
    let checks = run_checks(&cfg, &cfg_path).await;

    let perm = checks
        .iter()
        .find(|c| c.name == "配置权限")
        .expect("应有权限检查项");
    #[cfg(unix)]
    assert_eq!(perm.level, Level::Warn, "{}", perm.detail);
    assert_eq!(doctor::exit_code(&checks), 0, "Warn 不影响退出码");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn occupied_port_warns_but_does_not_fail() {
    let dir = tmp_dir("port");
    let cfg_path = write_config(&dir, "x");

    // 先占住一个端口，再让配置指向它
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let occupied: SocketAddr = listener.local_addr().unwrap();

    let cfg = ServerConfig {
        listen: ListenConfig {
            control: occupied,
            http: "127.0.0.1:0".parse().unwrap(),
            https: None,
        },
        ..test_config(&dir)
    };

    let checks = run_checks(&cfg, &cfg_path).await;
    let port = checks
        .iter()
        .find(|c| c.name.contains("7835"))
        .expect("应有控制面端口检查项");
    assert_eq!(port.level, Level::Warn, "{}", port.detail);

    drop(listener);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn missing_cert_warns_in_acme_and_selfsigned() {
    for mode in [TlsMode::Acme, TlsMode::SelfSigned] {
        let dir = tmp_dir("cert");
        let cfg_path = write_config(&dir, "x");
        let cfg = ServerConfig {
            tls: TlsConfig {
                mode,
                cert_dir: dir.join("certs"),
                ..TlsConfig::default()
            },
            dns_token: Some("dns-token-value-long-enough".into()),
            ..test_config(&dir)
        };

        let checks = run_checks(&cfg, &cfg_path).await;
        let cert = checks
            .iter()
            .find(|c| c.name == "证书有效期")
            .expect("应有证书检查项");
        assert_eq!(cert.level, Level::Warn, "mode={mode:?}: {}", cert.detail);

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[tokio::test]
async fn missing_cert_fails_in_files_mode() {
    let dir = tmp_dir("cert-files");
    let cfg_path = write_config(&dir, "x");
    let cfg = ServerConfig {
        tls: TlsConfig {
            mode: TlsMode::Files,
            cert_dir: dir.join("certs"),
            ..TlsConfig::default()
        },
        ..test_config(&dir)
    };

    let checks = run_checks(&cfg, &cfg_path).await;
    let cert = checks
        .iter()
        .find(|c| c.name == "证书有效期")
        .expect("应有证书检查项");
    assert_eq!(cert.level, Level::Fail, "{}", cert.detail);
    assert_eq!(doctor::exit_code(&checks), 1);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn dns_mismatch_with_public_ip_fails() {
    let dir = tmp_dir("dns");
    let cfg_path = write_config(&dir, "x");
    let cfg = ServerConfig {
        // doctor-test.invalid 不存在解析，但 public_ip 断言必定失败路径：
        // 用一个不可能匹配的 IP，即使解析成功也比对失败
        public_ip: Some("203.0.113.1".parse().unwrap()),
        dns_token: Some("dns-token-value-long-enough".into()),
        ..test_config(&dir)
    };

    let checks = run_checks(&cfg, &cfg_path).await;
    let dns = checks.iter().find(|c| c.name == "DNS 解析").unwrap();
    // 要么解析失败（Warn），要么解析成功但与 public_ip 不符（Fail），二者都不该是 Ok
    assert_ne!(dns.level, Level::Ok, "{}", dns.detail);

    let _ = std::fs::remove_dir_all(&dir);
}
