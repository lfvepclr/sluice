//! 纯 Rust 自签证书生成。
//!
//! 不用 `rcgen`：它只有 ring / aws-lc-rs 两个后端，会把 C 依赖拉回来。
//! 这里用 `x509-cert` 的 builder + `p256` 的 ECDSA 签名，全程 RustCrypto。

use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result};
use der::Encode;
use p256::ecdsa::{DerSignature, SigningKey};
use p256::pkcs8::EncodePrivateKey;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;

/// 生成结果：DER 编码的证书与 PKCS#8 私钥。
pub struct GeneratedCert {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

/// 生成自签证书（ECDSA P-256）。
///
/// `domains` 全部写进 SAN；`localhost` 之类的名字也走 DNS 类型即可。
pub fn self_signed(domains: &[&str], days: u32) -> Result<GeneratedCert> {
    if domains.is_empty() {
        anyhow::bail!("至少需要一个 SAN 域名");
    }

    let signer = SigningKey::random(&mut rand_core::OsRng);
    let spki = SubjectPublicKeyInfoOwned::from_key(*signer.verifying_key())
        .context("构造 SubjectPublicKeyInfo 失败")?;

    let validity = Validity::from_now(Duration::from_secs(u64::from(days) * 86_400))
        .context("构造有效期失败")?;

    let mut builder = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u32),
        validity,
        Name::from_str("CN=sluice").context("构造主体名失败")?,
        spki,
        &signer,
    )
    .context("创建证书构造器失败")?;

    let mut sans = Vec::with_capacity(domains.len());
    for d in domains {
        let ia5 = der::asn1::Ia5String::new(d).with_context(|| format!("非法 SAN：{d}"))?;
        sans.push(GeneralName::DnsName(ia5));
    }

    builder
        .add_extension(&SubjectAltName(sans))
        .context("添加 SAN 扩展失败")?;

    let cert = builder.build::<DerSignature>().context("签发证书失败")?;
    let cert_der = cert.to_der().context("证书 DER 编码失败")?;
    let key_der = signer
        .to_pkcs8_der()
        .context("私钥 PKCS#8 编码失败")?
        .as_bytes()
        .to_vec();

    Ok(GeneratedCert { cert_der, key_der })
}

/// 把 DER 包成 PEM，便于落盘与人工检查。
pub fn der_to_pem(label: &str, der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::with_capacity(b64.len() + 64);
    out.push_str(&format!("-----BEGIN {label}-----\n"));
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 一定是 ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Decode;

    #[test]
    fn generates_loadable_der() {
        let cert = self_signed(&["localhost", "*.bench.local"], 30).unwrap();
        assert!(cert.cert_der.len() > 200, "证书 DER 太短");
        assert!(!cert.key_der.is_empty());

        // DER 结构应能被 x509-cert 自己解析回来
        let parsed = x509_cert::Certificate::from_der(&cert.cert_der).expect("证书应能被解析");
        let san = parsed
            .tbs_certificate
            .extensions
            .as_ref()
            .and_then(|exts| {
                exts.iter()
                    .find(|e| e.extn_id == const_oid::db::rfc5280::ID_CE_SUBJECT_ALT_NAME)
            })
            .expect("应包含 SAN 扩展");
        assert!(!san.extn_value.is_empty());
    }

    #[test]
    fn pem_wrapping_is_well_formed() {
        let pem = der_to_pem("CERTIFICATE", &[1, 2, 3, 4]);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.trim_end().ends_with("-----END CERTIFICATE-----"));
    }

    #[test]
    fn rejects_empty_domains() {
        assert!(self_signed(&[], 30).is_err());
    }
}
