//! 证书存储与 TLS 接入。
//!
//! 证书放在 `ArcSwap` 里，`ResolvesServerCert` 每次握手读一次当前值——
//! 换证不需要重建 `ServerConfig`，也不需要重绑监听端口。

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio_rustls::TlsAcceptor;

use super::certgen;

/// 当前生效的证书。
pub struct CertStore {
    current: ArcSwap<CertifiedKey>,
}

impl std::fmt::Debug for CertStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CertStore")
    }
}

impl CertStore {
    /// 从 DER 编码的证书链（[叶子, 中间, ...]）与 PKCS#8 私钥构造。
    ///
    /// 必须传入完整链：只发叶子证书时客户端无法验证到根，浏览器/ curl
    /// 会报证书链不完整。
    pub fn from_der_chain(chain_der: Vec<Vec<u8>>, key_der: Vec<u8>) -> Result<Arc<Self>> {
        if chain_der.is_empty() {
            anyhow::bail!("证书链为空");
        }
        let certified = build_certified(&chain_der, &key_der)?;
        Ok(Arc::new(Self {
            current: ArcSwap::from_pointee(certified),
        }))
    }

    /// 热替换证书链。失败时旧证书保持生效。
    pub fn replace(&self, chain_der: Vec<Vec<u8>>, key_der: Vec<u8>) -> Result<()> {
        if chain_der.is_empty() {
            anyhow::bail!("证书链为空");
        }
        let certified = build_certified(&chain_der, &key_der)?;
        self.current.store(Arc::new(certified));
        Ok(())
    }

    /// 生成自签证书并装入（单证书链）。
    pub fn self_signed(domains: &[&str], days: u32) -> Result<Arc<Self>> {
        let generated = certgen::self_signed(domains, days)?;
        Self::from_der_chain(vec![generated.cert_der], generated.key_der)
    }

    /// 当前叶子证书的剩余有效天数。解析失败按 -1 处理由调用方决定是否重签。
    pub fn days_left(&self) -> Result<i64> {
        let current = self.current.load();
        let leaf = current
            .end_entity_cert()
            .map_err(|_| anyhow::anyhow!("证书链为空"))?;
        super::acme::days_left(leaf.as_ref())
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current.load_full())
    }
}

fn build_certified(chain_der: &[Vec<u8>], key_der: &[u8]) -> Result<CertifiedKey> {
    // rustls 的 from_der 不校验公私钥是否配对，配错了要到握手时才炸。
    // 这里显式比对叶子证书 SPKI 与私钥导出的公钥，把问题挡在启动阶段。
    validate_pair(&chain_der[0], key_der)?;

    let chain: Vec<CertificateDer<'static>> = chain_der
        .iter()
        .map(|c| CertificateDer::from(c.clone()))
        .collect();
    let key = PrivateKeyDer::Pkcs8(key_der.to_vec().into());
    CertifiedKey::from_der(chain, key, &crate::common::crypto::provider())
        .context("证书或私钥格式非法")
}

/// 校验证书里的公钥与私钥是否匹配（当前只支持 ECDSA P-256）。
fn validate_pair(cert_der: &[u8], key_der: &[u8]) -> Result<()> {
    use der::{Decode, Encode};
    use p256::pkcs8::{DecodePrivateKey, EncodePublicKey};

    let cert = x509_cert::Certificate::from_der(cert_der).context("证书 DER 解析失败")?;
    let cert_spki = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .context("证书 SPKI 编码失败")?;

    let secret = p256::SecretKey::from_pkcs8_der(key_der).context("私钥不是 PKCS#8 P-256")?;
    let key_spki = secret
        .public_key()
        .to_public_key_der()
        .context("私钥导出公钥失败")?;

    if cert_spki != key_spki.as_bytes() {
        anyhow::bail!("证书与私钥不匹配");
    }
    Ok(())
}

/// 构造 TLS acceptor，证书解析走 `CertStore`。
pub fn acceptor(store: Arc<CertStore>) -> Result<TlsAcceptor> {
    let config = ServerConfig::builder_with_provider(crate::common::crypto::provider())
        .with_safe_default_protocol_versions()
        .context("TLS 协议版本配置失败")?
        .with_no_client_auth()
        .with_cert_resolver(store);

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// 从目录读取 `fullchain.pem` 与 `privkey.pem`，返回完整证书链与私钥 DER。
pub fn load_files(dir: &Path) -> Result<(Vec<Vec<u8>>, Vec<u8>)> {
    let cert_path = dir.join("fullchain.pem");
    let key_path = dir.join("privkey.pem");

    let cert_pem = std::fs::read(&cert_path)
        .with_context(|| format!("读取证书失败：{}", cert_path.display()))?;
    let key_pem = std::fs::read(&key_path)
        .with_context(|| format!("读取私钥失败：{}", key_path.display()))?;

    let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("证书 PEM 解析失败")?;
    if certs.is_empty() {
        anyhow::bail!("{} 里没有证书", cert_path.display());
    }

    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .context("私钥 PEM 解析失败")?
        .ok_or_else(|| anyhow::anyhow!("{} 里没有私钥", key_path.display()))?;

    Ok((
        certs.into_iter().map(|c| c.to_vec()).collect(),
        key.secret_der().to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_self_signed_and_replaces() {
        let store = CertStore::self_signed(&["localhost"], 30).unwrap();

        // 换一张新证书（含中间证书的多级链）应当成功
        let another = certgen::self_signed(&["localhost"], 10).unwrap();
        let chain = vec![another.cert_der.clone(), another.cert_der.clone()];
        store.replace(chain, another.key_der).unwrap();
    }

    #[test]
    fn mismatched_key_is_rejected() {
        let a = certgen::self_signed(&["a.local"], 30).unwrap();
        let b = certgen::self_signed(&["b.local"], 30).unwrap();
        // 用 a 的证书配 b 的私钥，必须失败
        assert!(CertStore::from_der_chain(vec![a.cert_der], b.key_der).is_err());
    }

    #[test]
    fn empty_chain_is_rejected() {
        let g = certgen::self_signed(&["a.local"], 30).unwrap();
        assert!(CertStore::from_der_chain(Vec::new(), g.key_der).is_err());
    }
}
