//! 自写的最小 ACME 客户端（RFC 8555，DNS-01）。
//!
//! 为什么不用 `instant-acme`：它在 `default-features = false` 下无法编译
//! （内部 `ring_like` 别名只在 ring / aws-lc-rs feature 下定义），而引入
//! 任何一个都会破坏纯 Rust 约束。这里只实现我们真正需要的四个动作：
//! 建账号、下单、过 DNS-01、取证书。

use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use der::Encode;
use http::Method;
use p256::ecdsa::{DerSignature, Signature, SigningKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use signature::Signer;

use super::tls::CertStore;
use crate::common::http_client;
use crate::config::ServerConfig;

const LETSENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
const LETSENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// 签发结果。
pub struct Issued {
    /// 完整证书链（叶子在前，中间证书随后）。
    pub chain_der: Vec<Vec<u8>>,
    pub key_der: Vec<u8>,
}

// ───────────────────────── JWS ─────────────────────────

fn b64u(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// 错误日志里附带的响应体截断，防止刷屏。
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let head: String = s.chars().take(max).collect();
        format!("{head}…")
    }
}

fn jwk(key: &SigningKey) -> Value {
    let point = key.verifying_key().to_encoded_point(false);
    let x = point.x().map(|v| b64u(v)).unwrap_or_default();
    let y = point.y().map(|v| b64u(v)).unwrap_or_default();
    // 键序必须是 crv / kty / x / y —— serde_json 默认 BTreeMap 正好按字典序输出
    json!({ "crv": "P-256", "kty": "EC", "x": x, "y": y })
}

/// RFC 7638 指纹：对规范化 JWK 做 SHA-256。
fn thumbprint(key: &SigningKey) -> String {
    let canonical = jwk(key).to_string();
    b64u(&Sha256::digest(canonical.as_bytes()))
}

fn sign_jws(
    key: &SigningKey,
    url: &str,
    nonce: &str,
    kid: Option<&str>,
    payload: Option<&Value>,
) -> Value {
    let mut protected = json!({ "alg": "ES256", "nonce": nonce, "url": url });
    match kid {
        Some(kid) => protected["kid"] = json!(kid),
        None => protected["jwk"] = jwk(key),
    }

    let protected64 = b64u(protected.to_string().as_bytes());
    let payload64 = match payload {
        Some(v) => b64u(v.to_string().as_bytes()),
        // POST-as-GET：payload 必须是空串而不是 "{}"
        None => String::new(),
    };

    let signing_input = format!("{protected64}.{payload64}");
    let signature: Signature = key.sign(signing_input.as_bytes());

    json!({
        "protected": protected64,
        "payload": payload64,
        "signature": b64u(&signature.to_bytes()),
    })
}

// ───────────────────────── 账号与目录 ─────────────────────────

struct Directory {
    new_nonce: String,
    new_account: String,
    new_order: String,
}

struct Account {
    key: SigningKey,
    url: String,
    nonce: String,
}

async fn fetch_directory(directory_url: &str) -> Result<Directory> {
    let response = http_client::request(
        Method::GET,
        directory_url,
        &[],
        None,
        Duration::from_secs(20),
    )
    .await?;

    let value: Value = serde_json::from_slice(&response.body).context("目录不是合法 JSON")?;
    let pick = |key: &str| -> Result<String> {
        value
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("目录缺少字段 {key}"))
    };

    Ok(Directory {
        new_nonce: pick("newNonce")?,
        new_account: pick("newAccount")?,
        new_order: pick("newOrder")?,
    })
}

async fn fetch_nonce(directory: &Directory) -> Result<String> {
    let response = http_client::request(
        Method::HEAD,
        &directory.new_nonce,
        &[],
        None,
        Duration::from_secs(20),
    )
    .await?;

    response
        .headers
        .get("replay-nonce")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("响应缺少 Replay-Nonce"))
}

/// 发一个已签名的 POST。nonce 失效（badNonce）时自动重试一次。
async fn post(
    account: &mut Account,
    url: &str,
    payload: Option<&Value>,
) -> Result<http_client::Response> {
    let mut response = post_once(account, url, payload).await?;

    // RFC 8555 §6.5：服务器可能判定 nonce 失效，换新 nonce 重试一次
    let is_bad_nonce = response.status.as_u16() == 400
        && serde_json::from_slice::<Value>(&response.body)
            .ok()
            .and_then(|v| v.get("type").and_then(Value::as_str).map(|t| t.to_string()))
            .is_some_and(|t| t.ends_with("badNonce"));

    if is_bad_nonce {
        tracing::debug!("nonce 失效，已换新重试");
        response = post_once(account, url, payload).await?;
    }

    Ok(response)
}

async fn post_once(
    account: &mut Account,
    url: &str,
    payload: Option<&Value>,
) -> Result<http_client::Response> {
    let jws = sign_jws(
        &account.key,
        url,
        &account.nonce,
        Some(&account.url),
        payload,
    );

    // 排障开关：SLUICE_ACME_DEBUG=1 时打印实际发送的 JWS
    if std::env::var("SLUICE_ACME_DEBUG").as_deref() == Ok("1") {
        let payload_len = jws.get("payload").and_then(Value::as_str).map(str::len);
        tracing::debug!(url = %url, ?payload_len, "ACME POST");
    }

    let response = http_client::request(
        Method::POST,
        url,
        &[
            ("content-type", "application/jose+json".to_string()),
            ("accept", "application/json".to_string()),
        ],
        Some(Bytes::from(jws.to_string())),
        Duration::from_secs(30),
    )
    .await?;

    // 每次响应都带新 nonce，省掉一次往返
    if let Some(nonce) = response
        .headers
        .get("replay-nonce")
        .and_then(|v| v.to_str().ok())
    {
        account.nonce = nonce.to_string();
    }

    Ok(response)
}

fn account_path(cert_dir: &Path) -> PathBuf {
    cert_dir.join("account.json")
}

/// 载入或创建账号。账号凭据必须持久化，否则每次签发都会新建账号撞限速。
async fn load_or_create_account(cfg: &ServerConfig, directory_url: &str) -> Result<Account> {
    let directory = fetch_directory(directory_url).await?;
    let path = account_path(&cfg.tls.cert_dir);

    // 坏掉的账号文件不致命：直接走下面重建流程，新账号覆盖旧文件
    if let Ok(text) = std::fs::read_to_string(&path)
        && let Ok(saved) = serde_json::from_str::<Value>(&text)
        && saved.get("directory").and_then(Value::as_str) == Some(directory_url)
        && let Some(url) = saved.get("url").and_then(Value::as_str).map(str::to_string)
        && let Some(key_b64) = saved.get("key").and_then(Value::as_str)
        && let Ok(der) = URL_SAFE_NO_PAD.decode(key_b64)
        && let Ok(key) = SigningKey::from_pkcs8_der(&der)
    {
        let nonce = fetch_nonce(&directory).await?;
        return Ok(Account { key, url, nonce });
    }

    // 新建账号
    let key = SigningKey::random(&mut rand_core::OsRng);
    let nonce = fetch_nonce(&directory).await?;
    let jws = sign_jws(
        &key,
        &directory.new_account,
        &nonce,
        None,
        Some(&json!({ "termsOfServiceAgreed": true })),
    );

    let response = http_client::request(
        Method::POST,
        &directory.new_account,
        &[
            ("content-type", "application/jose+json".to_string()),
            ("accept", "application/json".to_string()),
        ],
        Some(Bytes::from(jws.to_string())),
        Duration::from_secs(30),
    )
    .await?;

    if !response.status.is_success() {
        anyhow::bail!("注册账号失败：{} {}", response.status, response.text());
    }

    let url = response
        .headers
        .get("location")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| anyhow::anyhow!("注册账号未返回 Location"))?
        .to_string();

    let key_der = key.to_pkcs8_der()?.as_bytes().to_vec();
    let record = json!({
        "directory": directory_url,
        "url": url,
        "key": b64u(&key_der),
    });
    write_secure(&path, record.to_string().as_bytes())?;

    let nonce = fetch_nonce(&directory).await?;
    Ok(Account { key, url, nonce })
}

fn write_secure(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(path, bytes).with_context(|| format!("写入 {} 失败", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

// ───────────────────────── DNS-01 ─────────────────────────

/// DuckDNS 只接受裸标签（不含 `.duckdns.org`）。
fn duckdns_label(base_domain: &str) -> &str {
    base_domain.split('.').next().unwrap_or(base_domain)
}

/// 构造 DuckDNS 更新 URL。`txt` 为 `None` 表示清除记录。
pub fn duckdns_update_url(label: &str, token: &str, txt: Option<&str>) -> String {
    match txt {
        Some(value) => {
            format!("https://www.duckdns.org/update?domains={label}&token={token}&txt={value}")
        }
        None => {
            format!("https://www.duckdns.org/update?domains={label}&token={token}&txt=&clear=true")
        }
    }
}

async fn duckdns_set(label: &str, token: &str, txt: Option<&str>) -> Result<()> {
    let url = duckdns_update_url(label, token, txt);

    let response =
        http_client::request(Method::GET, &url, &[], None, Duration::from_secs(20)).await?;
    let body = response.text();
    if body.trim() != "OK" {
        anyhow::bail!("DuckDNS 更新失败：{}", body.trim());
    }
    Ok(())
}

/// 判断 DoH 响应里的 TXT 记录是否已包含期望值。
pub fn txt_propagated(doh: &Value, expect: &str) -> bool {
    doh.get("Answer")
        .and_then(Value::as_array)
        .map(|answers| {
            answers.iter().any(|a| {
                a.get("data")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim_matches('"')
                    == expect
            })
        })
        .unwrap_or(false)
}

/// 等待 TXT 生效。优先直查权威 NS 全副本一致性（无缓存问题），DoH 兜底。
async fn wait_txt(fqdn: &str, zone_hint: &str, expect: &str, budget: Duration) -> Result<()> {
    let deadline = Instant::now() + budget;

    loop {
        // 权威校验：多副本全部一致才算传播完成（LE 随机询问任意一台）
        if super::dnstxt::verify_propagated(fqdn, zone_hint, expect).await {
            return Ok(());
        }

        // DoH 兜底（权威探测因网络等原因失败时）
        let url = format!("https://dns.google/resolve?name={fqdn}&type=TXT");
        if let Ok(response) =
            http_client::request(Method::GET, &url, &[], None, Duration::from_secs(8)).await
            && let Ok(value) = serde_json::from_slice::<Value>(&response.body)
            && txt_propagated(&value, expect)
        {
            return Ok(());
        }

        if Instant::now() >= deadline {
            anyhow::bail!("TXT 传播超时（{fqdn}），请检查 DuckDNS token 与 DNS 解析");
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

// ───────────────────────── CSR ─────────────────────────

/// 生成通配域名 CSR，返回 (CSR DER, 私钥 PKCS#8 DER)。
pub fn build_csr(wildcard: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    use x509_cert::builder::{Builder, RequestBuilder};
    use x509_cert::ext::pkix::SubjectAltName;
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::name::Name;

    let signer = SigningKey::random(&mut rand_core::OsRng);
    let subject = Name::from_str(&format!("CN={wildcard}")).context("构造 CSR 主体失败")?;

    let mut builder = RequestBuilder::new(subject, &signer).context("创建 CSR 构造器失败")?;
    let san = SubjectAltName(vec![GeneralName::DnsName(
        der::asn1::Ia5String::new(wildcard).context("非法 SAN")?,
    )]);
    builder.add_extension(&san).context("添加 SAN 失败")?;

    let csr = builder.build::<DerSignature>().context("CSR 签名失败")?;
    let csr_der = csr.to_der().context("CSR DER 编码失败")?;
    let key_der = signer
        .to_pkcs8_der()
        .context("私钥编码失败")?
        .as_bytes()
        .to_vec();

    Ok((csr_der, key_der))
}

// ───────────────────────── 签发主流程 ─────────────────────────

fn directory_url() -> String {
    if let Ok(url) = std::env::var("SLUICE_ACME_DIRECTORY") {
        return url;
    }
    if std::env::var("SLUICE_ACME_STAGING").as_deref() == Ok("1") {
        LETSENCRYPT_STAGING.to_string()
    } else {
        LETSENCRYPT.to_string()
    }
}

/// 完整签发一次通配证书。
pub async fn issue(cfg: &ServerConfig) -> Result<Issued> {
    // instant-acme 时代的教训：任何 HTTPS 客户端都依赖已安装的 crypto provider
    crate::common::crypto::install();

    let dns_token = cfg
        .dns_token
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("tls.mode = acme 需要 dns_token"))?;

    let wildcard = format!("*.{}", cfg.base_domain);
    let directory_url = directory_url();
    let mut account = load_or_create_account(cfg, &directory_url).await?;
    let directory = fetch_directory(&directory_url).await?;

    // 下单
    let order_payload = json!({
        "identifiers": [{ "type": "dns", "value": wildcard }]
    });
    let order_response = post(&mut account, &directory.new_order, Some(&order_payload)).await?;
    if !order_response.status.is_success() {
        anyhow::bail!(
            "下单失败：{} {}",
            order_response.status,
            order_response.text()
        );
    }

    let order_url = order_response
        .headers
        .get("location")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| anyhow::anyhow!("下单未返回 Location"))?
        .to_string();

    let order: Value = serde_json::from_slice(&order_response.body).map_err(|e| {
        anyhow::anyhow!(
            "订单响应不是 JSON：{} {}（{e}）",
            order_response.status,
            truncate(&order_response.text(), 300)
        )
    })?;
    // finalize URL 必须从订单对象读取：它与订单 URL 不同路径（/acme/finalize/...），
    // 拼接 `{order_url}/finalize` 会落进 order 端点（只允许 POST-as-GET）
    let finalize_url = order
        .get("finalize")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "订单缺少 finalize 字段：{}",
                truncate(&order.to_string(), 300)
            )
        })?
        .to_string();
    let authz_url = order
        .get("authorizations")
        .and_then(Value::as_array)
        .and_then(|v| v.first())
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("订单没有 authorization"))?
        .to_string();

    // 取 DNS-01 challenge
    let authz_response = post(&mut account, &authz_url, None).await?;
    let authz: Value = serde_json::from_slice(&authz_response.body).map_err(|e| {
        anyhow::anyhow!(
            "authorization 响应不是 JSON：{} {}（{e}）",
            authz_response.status,
            truncate(&authz_response.text(), 300)
        )
    })?;
    let challenge = authz
        .get("challenges")
        .and_then(Value::as_array)
        .and_then(|list| {
            list.iter()
                .find(|c| c.get("type").and_then(Value::as_str) == Some("dns-01"))
        })
        .ok_or_else(|| {
            // 响应可能是 problem+json（如 badNonce / userActionRequired），
            // 把原文体带出来才能定位
            anyhow::anyhow!(
                "authorization 里没有 dns-01：HTTP {} {}",
                authz_response.status,
                truncate(&authz_response.text(), 300)
            )
        })?;

    let token = challenge
        .get("token")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("challenge 缺少 token"))?;
    let challenge_url = challenge
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("challenge 缺少 url"))?;

    // key authorization → TXT 值
    let key_auth = format!("{token}.{}", thumbprint(&account.key));
    let txt_value = b64u(&Sha256::digest(key_auth.as_bytes()));

    let label = duckdns_label(&cfg.base_domain);
    tracing::info!(%wildcard, "写入 DNS-01 TXT");
    duckdns_set(label, dns_token, Some(&txt_value)).await?;

    let fqdn = format!("_acme-challenge.{}", cfg.base_domain);
    // DuckDNS 多副本同步需要 1–2 分钟，给足预算
    let wait = wait_txt(
        &fqdn,
        &cfg.base_domain,
        &txt_value,
        Duration::from_secs(300),
    );

    if let Err(e) = wait.await {
        let _ = duckdns_set(label, dns_token, None).await;
        return Err(e);
    }

    // 触发校验并轮询
    let trigger = post(&mut account, challenge_url, Some(&json!({}))).await?;
    if !trigger.status.is_success() {
        let _ = duckdns_set(label, dns_token, None).await;
        anyhow::bail!("触发校验失败：{} {}", trigger.status, trigger.text());
    }

    let mut valid = false;
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let poll = post(&mut account, &authz_url, None).await?;
        let state: Value = serde_json::from_slice(&poll.body)?;
        match state.get("status").and_then(Value::as_str) {
            Some("valid") => {
                valid = true;
                break;
            }
            Some("invalid") => {
                let _ = duckdns_set(label, dns_token, None).await;
                anyhow::bail!("DNS-01 校验失败：{}", poll.text());
            }
            _ => {}
        }
    }
    if !valid {
        let _ = duckdns_set(label, dns_token, None).await;
        anyhow::bail!("DNS-01 校验超时");
    }

    // 清理 TXT（DuckDNS 每个域名只能存一条，必须清掉）
    let _ = duckdns_set(label, dns_token, None).await;

    // finalize
    let (csr_der, key_der) = build_csr(&wildcard)?;
    let finalize_payload = json!({ "csr": b64u(&csr_der) });
    let finalize = post(&mut account, &finalize_url, Some(&finalize_payload)).await?;
    if !finalize.status.is_success() {
        anyhow::bail!("finalize 失败：{} {}", finalize.status, finalize.text());
    }

    // 轮询订单直到拿到证书
    let mut cert_url: Option<String> = None;
    for _ in 0..30 {
        let poll = post(&mut account, &order_url, None).await?;
        let state: Value = serde_json::from_slice(&poll.body)?;
        match state.get("status").and_then(Value::as_str) {
            Some("valid") => {
                cert_url = state
                    .get("certificate")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                break;
            }
            Some("invalid") => anyhow::bail!("订单进入 invalid：{}", poll.text()),
            _ => tokio::time::sleep(Duration::from_secs(2)).await,
        }
    }

    let cert_url = cert_url.ok_or_else(|| anyhow::anyhow!("订单有效但没有证书 URL"))?;
    let cert_response = post(&mut account, &cert_url, None).await?;
    if !cert_response.status.is_success() {
        anyhow::bail!("下载证书失败：{}", cert_response.status);
    }

    // 响应是 PEM 链：落盘全链，叶子+中间证书一起热替换给 rustls
    let chain_pem = cert_response.text();
    let chain = rustls_pemfile::certs(&mut chain_pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("证书链解析失败")?;
    if chain.is_empty() {
        anyhow::bail!("证书链为空");
    }
    let chain_der: Vec<Vec<u8>> = chain.into_iter().map(|c| c.to_vec()).collect();

    std::fs::create_dir_all(&cfg.tls.cert_dir).ok();
    write_secure(
        &cfg.tls.cert_dir.join("fullchain.pem"),
        chain_pem.as_bytes(),
    )?;
    write_secure(
        &cfg.tls.cert_dir.join("privkey.pem"),
        super::certgen::der_to_pem("PRIVATE KEY", &key_der).as_bytes(),
    )?;

    tracing::info!(%wildcard, "证书签发成功");
    Ok(Issued { chain_der, key_der })
}

/// 证书剩余天数。
pub fn days_left(cert_der: &[u8]) -> Result<i64> {
    use der::Decode;

    let cert = x509_cert::Certificate::from_der(cert_der).context("证书解析失败")?;
    let not_after = cert.tbs_certificate.validity.not_after.to_unix_duration();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    Ok((not_after.as_secs() as i64 - now.as_secs() as i64) / 86_400)
}

/// 后台续期：剩余不足 30 天就重签，失败退避 60s·2ⁿ（上限 6h，±20% 抖动）。
pub fn spawn(
    cfg: Arc<ServerConfig>,
    store: Arc<CertStore>,
    bootstrap: bool,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut bootstrap = bootstrap;
        let mut backoff = Duration::from_secs(60);
        if bootstrap {
            tracing::info!("尚无可用证书，启动即签发");
        }

        loop {
            // 解析不出剩余天数（证书损坏/缺失）按「急需签发」处理
            let days = store.days_left().unwrap_or(-1);
            let need = bootstrap || days < RENEW_BEFORE_DAYS;

            if need {
                match issue(&cfg).await {
                    Ok(issued) => {
                        match store.replace(issued.chain_der, issued.key_der) {
                            Ok(()) => tracing::info!("证书已热替换"),
                            Err(e) => tracing::error!(error = %e, "装载新证书失败"),
                        }
                        bootstrap = false;
                        backoff = Duration::from_secs(60);
                        // 刚签的新证书有 90 天，巡检周期内不必再签
                        tokio::time::sleep(CHECK_INTERVAL).await;
                    }
                    Err(e) => {
                        tracing::error!(error = %e, backoff = ?backoff, "签发失败，稍后重试");
                        tokio::time::sleep(jitter(backoff)).await;
                        backoff = (backoff * 2).min(Duration::from_secs(6 * 3600));
                    }
                }
            } else {
                tracing::debug!(days, "证书有效期充足，跳过签发");
                tokio::time::sleep(CHECK_INTERVAL).await;
            }
        }
    })
}

/// 每 6 小时巡检一次证书有效期。
const CHECK_INTERVAL: Duration = Duration::from_secs(6 * 3600);
/// 剩余有效期低于该天数就触发续期。Let's Encrypt 证书 90 天。
const RENEW_BEFORE_DAYS: i64 = 30;

/// 给退避时间加 ±20% 抖动，避免多实例同时重试。
fn jitter(d: Duration) -> Duration {
    let base = d.as_millis() as u64;
    if base == 0 {
        return d;
    }
    let spread = base / 5;
    let offset = rand::Rng::gen_range(&mut rand::thread_rng(), 0..=spread.max(1));
    Duration::from_millis(base - spread / 2 + offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwk_has_canonical_order() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let text = jwk(&key).to_string();
        // RFC 7638 要求字典序：crv < kty < x < y
        let crv = text.find("\"crv\"").unwrap();
        let kty = text.find("\"kty\"").unwrap();
        let x = text.find("\"x\"").unwrap();
        let y = text.find("\"y\"").unwrap();
        assert!(crv < kty && kty < x && x < y, "键序错误：{text}");
    }

    #[test]
    fn thumbprint_is_stable() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        assert_eq!(thumbprint(&key), thumbprint(&key));
        assert!(!thumbprint(&key).contains('='), "base64url 不应有 padding");
    }

    #[test]
    fn post_as_get_uses_empty_payload() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let jws = sign_jws(&key, "https://example.com/x", "nonce", Some("kid"), None);
        assert_eq!(jws["payload"].as_str(), Some(""));
        assert!(jws["protected"].as_str().is_some());
    }

    #[test]
    fn csr_contains_wildcard_san() {
        use der::Decode;
        let (csr_der, key_der) = build_csr("*.example.com").unwrap();
        assert!(!key_der.is_empty());

        let csr = x509_cert::request::CertReq::from_der(&csr_der).unwrap();
        let extensions = csr
            .info
            .attributes
            .iter()
            .find_map(|attr| {
                attr.values
                    .iter()
                    .find_map(|v| v.decode_as::<x509_cert::ext::Extensions>().ok())
            })
            .expect("CSR 应带扩展");
        assert!(
            extensions
                .iter()
                .any(|e| e.extn_id == const_oid::db::rfc5280::ID_CE_SUBJECT_ALT_NAME),
            "CSR 缺少 SAN"
        );
    }

    #[test]
    fn duckdns_label_strips_suffix() {
        assert_eq!(duckdns_label("foo.duckdns.org"), "foo");
        assert_eq!(duckdns_label("bar"), "bar");
    }

    #[test]
    fn duckdns_url_builds_set_and_clear() {
        assert_eq!(
            duckdns_update_url("foo", "tok", Some("abc123")),
            "https://www.duckdns.org/update?domains=foo&token=tok&txt=abc123"
        );
        assert_eq!(
            duckdns_update_url("foo", "tok", None),
            "https://www.duckdns.org/update?domains=foo&token=tok&txt=&clear=true"
        );
    }

    #[test]
    fn txt_propagated_matches_unquoted_value() {
        let doh = serde_json::json!({
            "Answer": [
                { "name": "_acme-challenge.x.", "type": 16, "data": "\"abc\"" },
                { "name": "_acme-challenge.x.", "type": 16, "data": "\"def\"" }
            ]
        });
        assert!(txt_propagated(&doh, "abc"));
        assert!(txt_propagated(&doh, "def"));
        assert!(!txt_propagated(&doh, "xyz"));

        // 无 Answer 字段或为空：视为未生效
        assert!(!txt_propagated(&serde_json::json!({}), "abc"));
        assert!(!txt_propagated(&serde_json::json!({ "Answer": [] }), "abc"));
    }

    #[test]
    fn jitter_stays_within_20_percent() {
        let base = Duration::from_secs(60);
        for _ in 0..50 {
            let j = jitter(base);
            assert!(j >= Duration::from_secs(48) && j <= Duration::from_secs(72));
        }
    }
}
