//! 直查权威 NS 的 TXT 探测。
//!
//! `wait_txt` 不能只靠公共解析器：写入/清除 TXT 后，8.8.8.8 之类的缓存可能
//! 在整个等待窗口内都返回陈旧的空记录。权威服务器永远反映当前真实数据，
//! 证书校验本身也只看权威，所以这里直接发 UDP DNS 查询。
//!
//! 零 unsafe，DNS 报文手工构造（只支持我们需要的极小子集）。

use std::net::IpAddr;
use std::time::Duration;

use serde_json::Value;

use crate::common::http_client;

const QTYPE_TXT: u16 = 16;
const QCLASS_IN: u16 = 1;
const UDP_TIMEOUT: Duration = Duration::from_secs(3);

/// 校验 `fqdn` 的 TXT 是否已在**所有**可达权威副本上生效。
///
/// DuckDNS 之类服务商的权威 NS 是最终一致的多副本：某台先有值、其他台落后
/// 几十秒很常见。而 LE 校验时随机询问任意一台，所以必须等全部副本一致，
/// 只查一台会间歇性误报「已传播」。
///
/// `zone_hint` 是探测 NS 的起点（通常是基础域名）；沿父域逐级向上找第一个
/// 有 NS 记录的层级。查询失败的副本跳过（不可达不该永远阻塞判定）。
pub async fn verify_propagated(fqdn: &str, zone_hint: &str, expect: &str) -> bool {
    let Some(nameservers) = find_nameservers(zone_hint).await else {
        return false;
    };

    let mut checked = 0;
    let mut matched = 0;
    for ns in nameservers.iter().take(3) {
        let Some(ip) = resolve_a(ns).await else {
            continue;
        };
        match udp_txt_query(fqdn, ip).await {
            Ok(Some(txt)) => {
                checked += 1;
                if txt.trim_matches('"') == expect {
                    matched += 1;
                }
            }
            Ok(None) => checked += 1, // 权威确认无记录 = 未传播
            Err(e) => tracing::debug!(%ns, error = %e, "权威 TXT 查询失败，跳过该副本"),
        }
    }

    checked > 0 && checked == matched
}

/// 沿父域向上找第一个有 NS 记录的层级，返回 NS 主机名列表。
async fn find_nameservers(zone_hint: &str) -> Option<Vec<String>> {
    let labels: Vec<&str> = zone_hint.trim_end_matches('.').split('.').collect();
    // 保留 TLD 本身，从倒数第二级开始向上试
    for i in (1..labels.len().saturating_sub(1)).rev() {
        let candidate = labels[i..].join(".");
        let names = doh_strings(&candidate, "NS").await?;
        if !names.is_empty() {
            return Some(names);
        }
    }
    None
}

/// 解析 NS 主机名的 A 记录（优先 IPv4）。
async fn resolve_a(ns: &str) -> Option<IpAddr> {
    let name = ns.trim_end_matches('.');
    doh_strings(name, "A")
        .await?
        .into_iter()
        .find_map(|s| s.parse().ok())
}

/// DoH 提供商列表：依次尝试，全部失败才放弃。
const DOH_PROVIDERS: &[(&str, &str)] = &[
    ("https://dns.google/resolve", ""),
    (
        "https://cloudflare-dns.com/dns-query",
        "application/dns-json",
    ),
    (
        "https://dns.quad9.net:5053/dns-query",
        "application/dns-json",
    ),
];

/// DoH JSON 查询，返回 Answer[].data 列表。
async fn doh_strings(name: &str, qtype: &str) -> Option<Vec<String>> {
    for (base, accept) in DOH_PROVIDERS {
        let url = format!("{base}?name={name}&type={qtype}");
        let mut headers: Vec<(&str, String)> = Vec::new();
        if !accept.is_empty() {
            headers.push(("accept", accept.to_string()));
        }
        let Ok(response) = http_client::request(
            http::Method::GET,
            &url,
            &headers,
            None,
            Duration::from_secs(8),
        )
        .await
        else {
            tracing::debug!(provider = base, "DoH 提供商不可达，换下一个");
            continue;
        };
        let Ok(value) = serde_json::from_slice::<Value>(&response.body) else {
            continue;
        };
        let Some(answers) = value.get("Answer").and_then(Value::as_array) else {
            continue;
        };
        let data: Vec<String> = answers
            .iter()
            .filter_map(|a| a.get("data").and_then(Value::as_str).map(str::to_string))
            .collect();
        if !data.is_empty() {
            return Some(data);
        }
        // 应答正常但没有记录：可能是权威层面的空结果，这里继续试下一个
        // 提供商以防单家数据不全
    }
    None
}

/// 构造 TXT 查询报文（无 RD 标志，单问题）。
fn build_query(fqdn: &str, id: u16) -> Vec<u8> {
    let mut msg = Vec::with_capacity(64);
    msg.extend_from_slice(&id.to_be_bytes());
    // flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT（header 共 12 字节）
    msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in fqdn.trim_end_matches('.').split('.') {
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0);
    msg.extend_from_slice(&QTYPE_TXT.to_be_bytes());
    msg.extend_from_slice(&QCLASS_IN.to_be_bytes());
    msg
}

/// 向权威 NS 发 UDP 查询并解析 TXT 应答。
async fn udp_txt_query(fqdn: &str, ip: IpAddr) -> anyhow::Result<Option<String>> {
    use tokio::net::UdpSocket;

    let socket = UdpSocket::bind(if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await?;
    socket.connect((ip, 53)).await?;
    socket.send(&build_query(fqdn, rand_id())).await?;

    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(UDP_TIMEOUT, socket.recv(&mut buf)).await??;
    parse_txt_response(&buf[..n])
}

fn rand_id() -> u16 {
    rand::Rng::gen_range(&mut rand::thread_rng(), 0..u16::MAX)
}

/// 解析 DNS 应答，提取第一条 TXT 记录。
///
/// 返回：
/// - `Some(txt)`：有 TXT 记录
/// - `None`：应答正常（rcode 0）但没有 TXT——权威确认「无记录」
/// - `Err`：报文异常或 rcode 非零
fn parse_txt_response(msg: &[u8]) -> anyhow::Result<Option<String>> {
    if msg.len() < 12 {
        anyhow::bail!("DNS 应答过短：{n} 字节", n = msg.len());
    }
    let rcode = msg[3] & 0x0F;
    if rcode != 0 {
        anyhow::bail!("DNS rcode = {rcode}");
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    let ancount = u16::from_be_bytes([msg[6], msg[7]]);

    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(msg, pos)?;
        pos += 4; // qtype + qclass
    }

    for _ in 0..ancount {
        pos = skip_name(msg, pos)?;
        if pos + 10 > msg.len() {
            anyhow::bail!("应答记录截断");
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let rdlength = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos += 10;
        if rtype == QTYPE_TXT {
            let end = (pos + rdlength).min(msg.len());
            return Ok(Some(parse_txt_rdata(&msg[pos..end])));
        }
        pos += rdlength;
    }
    Ok(None)
}

/// 解析 TXT rdata：一串 `<len><bytes>` character-string，拼接。
fn parse_txt_rdata(rdata: &[u8]) -> String {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < rdata.len() {
        let len = rdata[pos] as usize;
        let start = pos + 1;
        let end = (start + len).min(rdata.len());
        out.extend_from_slice(&rdata[start..end]);
        pos = end;
    }
    String::from_utf8_lossy(&out).to_string()
}

/// 跳过报文里的域名（处理压缩指针），返回下一位置。
fn skip_name(msg: &[u8], mut pos: usize) -> anyhow::Result<usize> {
    loop {
        let Some(&len) = msg.get(pos) else {
            anyhow::bail!("域名越界");
        };
        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    return Ok(pos + 1);
                }
                pos += 1 + len as usize;
            }
            0xC0 => return Ok(pos + 2),
            _ => anyhow::bail!("不支持的标签类型：{len:#04x}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_build_has_expected_layout() {
        let msg = build_query("_acme-challenge.demo.invalid", 0x1234);
        assert_eq!(&msg[0..2], &[0x12, 0x34]);
        // 标志位：QR=0 RD=0；QDCOUNT=1；AN/NS/AR 均为 0
        assert_eq!(&msg[2..4], &[0x00, 0x00]);
        assert_eq!(&msg[4..6], &[0x00, 0x01]);
        assert_eq!(&msg[6..12], &[0x00; 6]);
        // 问题末尾：0 终止符 + QTYPE(16) + QCLASS(1)
        let tail = &msg[msg.len() - 5..];
        assert_eq!(tail[0], 0);
        assert_eq!(&tail[1..3], &16u16.to_be_bytes());
        assert_eq!(&tail[3..5], &1u16.to_be_bytes());
    }

    #[test]
    fn parse_txt_response_reads_rdata() {
        // 构造一个最小应答：header + 问题 + 一条 TXT 记录
        let mut msg = Vec::new();
        msg.extend_from_slice(&[
            0x00, 0x01, 0x80, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ]);
        // 问题：a.b（压缩不了，直接写）
        for label in ["a", "b"] {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0);
        msg.extend_from_slice(&QTYPE_TXT.to_be_bytes());
        msg.extend_from_slice(&QCLASS_IN.to_be_bytes());
        // 回答：名字用压缩指针指向问题里的 "a"（0xC00C）
        msg.extend_from_slice(&[0xC0, 0x0C]);
        msg.extend_from_slice(&QTYPE_TXT.to_be_bytes());
        msg.extend_from_slice(&QCLASS_IN.to_be_bytes());
        msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL 60
        msg.extend_from_slice(&[0x00, 0x06]); // rdlength
        msg.extend_from_slice(&[0x05, b'h', b'e', b'l', b'l', b'o']); // "hello"

        assert_eq!(parse_txt_response(&msg).unwrap().as_deref(), Some("hello"));
    }

    #[test]
    fn parse_txt_response_none_when_no_answer() {
        let mut msg = Vec::new();
        msg.extend_from_slice(&[
            0x00, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        assert!(matches!(parse_txt_response(&msg), Ok(None)));
    }

    #[test]
    fn parse_txt_response_err_on_bad_rcode() {
        let msg = [0u8; 12 + 3];
        // rcode = 3（NXDOMAIN）在 msg[3] 低 4 位
        let mut msg = msg.to_vec();
        msg[3] = 0x83;
        assert!(parse_txt_response(&msg).is_err());
    }

    #[test]
    fn skip_name_handles_pointer() {
        let msg = [0x03, b'a', b'b', b'c', 0x00, 0xC0, 0x0C, 0xFF];
        // 名字 a.b.c 到 0x00 结束 → 5
        assert_eq!(skip_name(&msg, 0).unwrap(), 5);
        // 指针占 2 字节 → 7
        assert_eq!(skip_name(&msg, 5).unwrap(), 7);
    }
}
