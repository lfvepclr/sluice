//! SSRF 防护：判定目标地址是否落在不可访问的网段。
//!
//! 转发模式的出口在服务器上，如果不做这层过滤，任何人都能借它探测内网、
//! 读云元数据（`169.254.169.254`）。默认拒绝，需要时用白名单开口子。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// 该地址是否禁止作为转发目标。
pub fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_forbidden_v4(v4),
        IpAddr::V6(v6) => is_forbidden_v6(v6),
    }
}

fn is_forbidden_v4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();

    // 0.0.0.0/8 本网络
    a == 0
        // 10/8 私有
        || a == 10
        // 100.64/10 运营商级 NAT
        || (a == 100 && (b & 0xc0) == 64)
        // 127/8 回环
        || a == 127
        // 169.254/16 链路本地（含云元数据 169.254.169.254）
        || (a == 169 && b == 254)
        // 172.16/12 私有
        || (a == 172 && (b & 0xf0) == 16)
        // 192.0.0/24 IETF 协议分配
        || (a == 192 && b == 0 && ip.octets()[2] == 0)
        // 192.0.2/24 文档示例
        || (a == 192 && b == 0 && ip.octets()[2] == 2)
        // 192.168/16 私有
        || (a == 192 && b == 168)
        // 198.18/15 基准测试
        || (a == 198 && (b & 0xfe) == 18)
        // 198.51.100/24 文档示例
        || (a == 198 && b == 51 && ip.octets()[2] == 100)
        // 203.0.113/24 文档示例
        || (a == 203 && b == 0 && ip.octets()[2] == 113)
        // 224/4 组播
        || (a & 0xf0) == 224
        // 240/4 保留
        || (a & 0xf0) == 240
}

fn is_forbidden_v6(ip: Ipv6Addr) -> bool {
    // IPv4-mapped 必须先归一化，否则 ::ffff:127.0.0.1 会绕过检查
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_forbidden_v4(v4);
    }

    let seg = ip.segments();
    ip.is_loopback()
        || ip.is_unspecified()
        // fc00::/7 唯一本地地址
        || (seg[0] & 0xfe00) == 0xfc00
        // fe80::/10 链路本地
        || (seg[0] & 0xffc0) == 0xfe80
        // ff00::/8 组播
        || (seg[0] & 0xff00) == 0xff00
}

/// 是否为云元数据地址（单独判定，便于给出更明确的报错）。
pub fn is_metadata_ip(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v4) if v4.octets() == [169, 254, 169, 254])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn private_v4_is_forbidden() {
        for s in [
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.1",
            "127.0.0.1",
            "0.0.0.0",
            "100.64.0.1",
            "100.127.255.255",
        ] {
            assert!(is_forbidden_ip(ip(s)), "{s} 应被拒绝");
        }
    }

    #[test]
    fn link_local_and_metadata_are_forbidden() {
        assert!(is_forbidden_ip(ip("169.254.1.1")));
        assert!(is_metadata_ip(ip("169.254.169.254")));
        assert!(is_forbidden_ip(ip("169.254.169.254")));
    }

    #[test]
    fn multicast_and_reserved_are_forbidden() {
        for s in ["224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255"] {
            assert!(is_forbidden_ip(ip(s)), "{s} 应被拒绝");
        }
    }

    #[test]
    fn public_v4_is_allowed() {
        for s in ["1.1.1.1", "8.8.8.8", "93.184.216.34", "203.0.114.1"] {
            assert!(!is_forbidden_ip(ip(s)), "{s} 应被放行");
        }
    }

    #[test]
    fn v6_loopback_and_ula_are_forbidden() {
        for s in ["::1", "::", "fc00::1", "fd12:3456::1", "fe80::1", "ff02::1"] {
            assert!(is_forbidden_ip(ip(s)), "{s} 应被拒绝");
        }
    }

    #[test]
    fn ipv4_mapped_v6_cannot_bypass() {
        for s in [
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            assert!(is_forbidden_ip(ip(s)), "{s} 是 IPv4-mapped，应被拒绝");
        }
        assert!(!is_forbidden_ip(ip("::ffff:1.1.1.1")));
    }

    #[test]
    fn public_v6_is_allowed() {
        assert!(!is_forbidden_ip(ip("2606:4700:4700::1111")));
    }
}
