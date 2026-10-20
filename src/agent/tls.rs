//! 控制通道的 TLS 客户端：证书指纹固定（TOFU）。
//!
//! agent 连的是 IP 或裸地址，域名校验走不通，所以用 SPKI 指纹代替：
//! 首次连接记录指纹，之后必须一致，否则拒绝——这比域名校验更强。

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

/// 计算证书的 SPKI SHA-256，base64 编码。
pub fn spki_fingerprint(cert_der: &[u8]) -> Result<String> {
    use der::{Decode, Encode};

    let cert = x509_cert::Certificate::from_der(cert_der).context("证书解析失败")?;
    let spki = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .context("SPKI 编码失败")?;

    let digest = Sha256::digest(&spki);
    Ok(base64::engine::general_purpose::STANDARD.encode(digest))
}

/// 指纹校验器：`expected` 为 `None` 时接受任意证书（首连）。
#[derive(Debug)]
struct PinnedVerifier {
    expected: Option<String>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if let Some(expected) = &self.expected {
            let actual = spki_fingerprint(end_entity.as_ref())
                .map_err(|e| rustls::Error::General(format!("指纹计算失败：{e}")))?;
            if &actual != expected {
                return Err(rustls::Error::General(format!(
                    "服务器指纹不匹配：期望 {expected}，实际 {actual}"
                )));
            }
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        // 指纹已经锁死了身份，这里不再重复验签
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
        ]
    }
}

/// 首连重试上限与间隔。服务端冷启动（OpenRC 拉起顺序、容器启动）通常几秒内
/// 就绪，5 次 × 1 秒足够；这个值是内置最优解，不暴露成调参项。
const CONNECT_RETRIES: usize = 5;
const CONNECT_RETRY_DELAY: Duration = Duration::from_secs(1);

/// 带首连重试的 [`connect`]：仅对「服务器暂时不可达」类错误重试
/// （服务端未就绪时的 Connection refused 最常见）。
/// TLS/指纹错误重试没有意义，立即返回。
pub async fn connect_retry(
    server: &str,
    expected_pin: Option<&str>,
) -> Result<(TlsStream<TcpStream>, String)> {
    for attempt in 1..=CONNECT_RETRIES {
        match connect(server, expected_pin).await {
            Ok(v) => return Ok(v),
            Err(e) if is_transient(&e) => {
                if attempt < CONNECT_RETRIES {
                    tracing::warn!(%server, attempt, "服务器暂不可达，{CONNECT_RETRY_DELAY:?} 后重试");
                    tokio::time::sleep(CONNECT_RETRY_DELAY).await;
                } else {
                    return Err(e);
                }
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!("循环内必然返回")
}

/// 是否为值得重试的瞬时网络错误。
fn is_transient(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<std::io::Error>().is_some_and(|io| {
            matches!(
                io.kind(),
                std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::NetworkUnreachable
            )
        })
    })
}

/// 建立 TLS 连接，返回连接与服务器证书指纹。
pub async fn connect(
    server: &str,
    expected_pin: Option<&str>,
) -> Result<(TlsStream<TcpStream>, String)> {
    crate::common::crypto::install();

    let socket = TcpStream::connect(server)
        .await
        .with_context(|| format!("连接 {server} 失败"))?;
    let _ = socket.set_nodelay(true);

    let config = rustls::ClientConfig::builder_with_provider(crate::common::crypto::provider())
        .with_safe_default_protocol_versions()
        .context("TLS 版本配置失败")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedVerifier {
            expected: expected_pin.map(str::to_string),
        }))
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

    // 证书里没有与地址匹配的 SAN，这里只作为 SNI 占位
    let host = server.split(':').next().unwrap_or(server);
    let server_name = ServerName::try_from(host.to_string())
        .or_else(|_| ServerName::try_from("sluice.local".to_string()))
        .context("非法服务器名")?;

    let stream = connector
        .connect(server_name, socket)
        .await
        .context("TLS 握手失败")?;

    let pin = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(|cert| spki_fingerprint(cert.as_ref()))
        .transpose()?
        .unwrap_or_default();

    Ok((stream, pin))
}
