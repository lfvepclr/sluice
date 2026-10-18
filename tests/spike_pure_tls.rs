//! P0 门禁：纯 Rust TLS 栈（rustls + rustls-rustcrypto + p256）能否真的握手。
//!
//! 这个测试不过，就不该继续往 TLS 入口上投入——先证明地基存在。

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{DigitallySignedStruct, SignatureScheme};
use sluice::common::crypto;
use sluice::server::certgen;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug)]
struct FixedCert(Arc<CertifiedKey>);

impl ResolvesServerCert for FixedCert {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// 仅测试用：信任任何证书。生产路径不会用这个。
#[derive(Debug)]
struct TrustAnything;

impl ServerCertVerifier for TrustAnything {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
        ]
    }
}

fn server_config() -> Arc<rustls::ServerConfig> {
    let generated =
        certgen::self_signed(&["localhost", "*.bench.local"], 30).expect("生成自签证书");
    let chain = vec![CertificateDer::from(generated.cert_der)];
    let key = PrivateKeyDer::Pkcs8(generated.key_der.into());

    let certified = CertifiedKey::from_der(chain, key, &crypto::provider()).expect("装载证书");

    let cfg = rustls::ServerConfig::builder_with_provider(crypto::provider())
        .with_safe_default_protocol_versions()
        .expect("默认协议版本")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(FixedCert(Arc::new(certified))));

    Arc::new(cfg)
}

fn client_config() -> Arc<rustls::ClientConfig> {
    let cfg = rustls::ClientConfig::builder_with_provider(crypto::provider())
        .with_safe_default_protocol_versions()
        .expect("默认协议版本")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TrustAnything))
        .with_no_client_auth();

    Arc::new(cfg)
}

#[tokio::test]
async fn tls13_handshake_and_data() {
    crypto::install();

    let acceptor = tokio_rustls::TlsAcceptor::from(server_config());
    let connector = tokio_rustls::TlsConnector::from(client_config());

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let server = tokio::spawn(async move {
        let mut tls = acceptor.accept(server_io).await.expect("服务端握手失败");
        let mut buf = [0u8; 5];
        tls.read_exact(&mut buf).await.expect("服务端读失败");
        tls.write_all(b"world").await.expect("服务端写失败");
        tls.flush().await.unwrap();
        buf
    });

    let name = ServerName::try_from("localhost").unwrap();
    let mut tls = connector
        .connect(name, client_io)
        .await
        .expect("客户端握手失败");

    let version = tls.get_ref().1.protocol_version();
    assert_eq!(
        version,
        Some(rustls::ProtocolVersion::TLSv1_3),
        "应协商到 TLS 1.3，实际 {version:?}"
    );

    tls.write_all(b"hello").await.unwrap();
    tls.flush().await.unwrap();

    let mut buf = [0u8; 5];
    tls.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"world");

    let received = server.await.unwrap();
    assert_eq!(&received, b"hello");
}

#[test]
fn provider_reports_tls13_suites() {
    let provider = crypto::provider();
    let has_tls13 = provider
        .cipher_suites
        .iter()
        .any(|cs| matches!(cs, rustls::SupportedCipherSuite::Tls13(_)));
    assert!(has_tls13, "provider 必须至少支持一个 TLS 1.3 套件");

    let has_p256 = provider
        .signature_verification_algorithms
        .supported_schemes()
        .contains(&SignatureScheme::ECDSA_NISTP256_SHA256);
    assert!(has_p256, "必须支持 ECDSA P-256 验签，否则自签证书用不了");
}
