//! ACME 纯逻辑单元测试（不触网）：CSR、DuckDNS URL、DoH 解析、剩余天数。

use std::time::{Duration, SystemTime};

use der::Decode;
use x509_cert::Certificate;

use sluice::server::acme;
use sluice::server::certgen;

fn der_days(cert_der: &[u8]) -> i64 {
    let cert = Certificate::from_der(cert_der).expect("证书 DER 合法");
    let not_after = cert.tbs_certificate.validity.not_after.to_unix_duration();
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    (not_after.as_secs() as i64 - now.as_secs() as i64) / 86_400
}

#[test]
fn csr_carries_wildcard_san() {
    let (csr_der, key_der) = acme::build_csr("*.demo.invalid").expect("CSR 生成");
    assert!(!key_der.is_empty());

    let csr = x509_cert::request::CertReq::from_der(&csr_der).expect("CSR DER 合法");
    let extensions = csr
        .info
        .attributes
        .iter()
        .find_map(|attr| {
            attr.values
                .iter()
                .find_map(|v| v.decode_as::<x509_cert::ext::Extensions>().ok())
        })
        .expect("CSR 应带扩展属性");

    assert!(
        extensions
            .iter()
            .any(|e| e.extn_id == const_oid::db::rfc5280::ID_CE_SUBJECT_ALT_NAME),
        "CSR 缺少 SAN"
    );
}

#[test]
fn duckdns_urls_are_wellformed() {
    assert_eq!(
        acme::duckdns_update_url("demo", "tok", Some("v1")),
        "https://www.duckdns.org/update?domains=demo&token=tok&txt=v1"
    );
    assert!(acme::duckdns_update_url("demo", "tok", None).contains("clear=true"));
}

#[test]
fn doh_answer_parsing() {
    let hit = serde_json::json!({
        "Status": 0,
        "Answer": [{ "name": "_acme-challenge.demo.", "type": 16, "data": "\"AAAB\"" }]
    });
    assert!(acme::txt_propagated(&hit, "AAAB"));
    assert!(!acme::txt_propagated(&hit, "BBBB"));
    assert!(!acme::txt_propagated(
        &serde_json::json!({ "Status": 3 }),
        "AAAB"
    ));
}

#[test]
fn days_left_parses_not_after() {
    // 30 天自签证书：剩余天数应在 29..=30
    let cert = certgen::self_signed(&["demo.invalid"], 30).expect("自签成功");
    let left = acme::days_left(&cert.cert_der).expect("剩余天数可解析");
    assert!((29..=30).contains(&left), "剩余 {left} 天不在预期区间");

    // 直接核对 not_after：30 天 ± 1 天误差
    let raw = der_days(&cert.cert_der);
    assert!((29..=30).contains(&raw));

    // 非法 DER 必须报错而不是 panic
    assert!(acme::days_left(b"not a certificate").is_err());
}

#[test]
fn days_left_boundary_values() {
    let cert = certgen::self_signed(&["demo.invalid"], 1).expect("自签成功");
    let left = acme::days_left(&cert.cert_der).expect("可解析");
    // 1 天证书可能已经显示 0（向下取整）
    assert!((0..=1).contains(&left));
}

#[test]
fn cert_store_days_left_roundtrip() {
    let store = sluice::server::tls::CertStore::self_signed(&["demo.invalid"], 45).unwrap();
    let left = store.days_left().expect("可解析");
    assert!((44..=45).contains(&left), "剩余 {left} 天");

    // 换一张只剩 1 天的证书，剩余天数应跟着变
    let short = certgen::self_signed(&["demo.invalid"], 1).unwrap();
    store.replace(vec![short.cert_der], short.key_der).unwrap();
    let left = store.days_left().unwrap();
    assert!((0..=1).contains(&left));
}

#[test]
fn timeout_budget_math() {
    // 等待预算参数整理：总预算 120s、单请求 8s、间隔 5s → 至少 (120/13)+1 次机会
    let budget = Duration::from_secs(120);
    let per_request = Duration::from_secs(8);
    let interval = Duration::from_secs(5);
    let attempts = budget.as_secs() / (per_request + interval).as_secs() + 1;
    assert!((7..=16).contains(&attempts), "attempts = {attempts}");
}
