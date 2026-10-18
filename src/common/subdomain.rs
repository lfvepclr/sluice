//! 子域名生成与校验。
//!
//! 字母表去掉了 `0/o/1/l/i`：这些字符在电话、截图、手抄场景下极易混淆。
//! 6 位 31 字符表 ≈ 8.9 亿组合，冲突概率可以忽略，撞上了就重试。

use rand::Rng;

/// 无歧义字母表（31 字符）。
pub const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
/// 随机子域名长度。
pub const LEN: usize = 6;

/// 保留词：这些名字要么有协议语义，要么容易被误认为官方入口。
const RESERVED: &[&str] = &[
    "www",
    "api",
    "admin",
    "root",
    "mail",
    "smtp",
    "imap",
    "pop",
    "mx",
    "ns",
    "ns1",
    "ns2",
    "ftp",
    "cdn",
    "static",
    "assets",
    "status",
    "health",
    "metrics",
    "grafana",
    "adminer",
    "test",
    "dev",
    "staging",
    "demo",
    "docs",
    "blog",
    "app",
    "dashboard",
    "console",
    "panel",
    "acme",
    "sluice",
];

/// 生成一个随机子域名。
pub fn generate() -> String {
    let mut rng = rand::thread_rng();
    (0..LEN)
        .map(|_| {
            let idx = rng.gen_range(0..ALPHABET.len());
            ALPHABET[idx] as char
        })
        .collect()
}

/// 是否为保留词。
pub fn is_reserved(name: &str) -> bool {
    RESERVED.iter().any(|r| r.eq_ignore_ascii_case(name))
}

/// 校验自定义子域名。
///
/// 规则：长度 3..=32，只含 `a-z0-9-`，首尾必须是字母或数字，不含连续连字符。
pub fn validate(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.len() < 3 || bytes.len() > 32 {
        return false;
    }
    if is_reserved(name) {
        return false;
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    {
        return false;
    }
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];
    if !(first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric()) {
        return false;
    }
    !name.contains("--")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_names_are_valid_and_unique_ish() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let name = generate();
            assert_eq!(name.len(), LEN);
            assert!(validate(&name), "生成的 `{name}` 应通过校验");
            assert!(
                name.bytes().all(|b| ALPHABET.contains(&b)),
                "`{name}` 含字母表外字符"
            );
            seen.insert(name);
        }
        // 200 次里不应出现大量碰撞
        assert!(seen.len() > 190, "随机性异常：{} 个唯一值", seen.len());
    }

    #[test]
    fn alphabet_has_no_confusable_chars() {
        for bad in b"0o1li" {
            assert!(!ALPHABET.contains(bad), "字母表不应包含 {}", *bad as char);
        }
        assert_eq!(ALPHABET.len(), 31);
    }

    #[test]
    fn accepts_normal_names() {
        for name in ["myapp", "my-app", "app2", "a1b"] {
            assert!(validate(name), "`{name}` 应合法");
        }
    }

    #[test]
    fn rejects_reserved_names() {
        for name in ["www", "api", "admin", "sluice", "ACME"] {
            assert!(!validate(name), "`{name}` 是保留词");
        }
    }

    #[test]
    fn rejects_bad_shapes() {
        for name in [
            "ab",                                // 太短
            "-abc",                              // 首字符是连字符
            "abc-",                              // 尾字符是连字符
            "a--b",                              // 连续连字符
            "abc_def",                           // 下划线
            "ABC",                               // 大写
            "abc.def",                           // 点
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 太长
        ] {
            assert!(!validate(name), "`{name}` 应被拒绝");
        }
    }

    #[test]
    fn reserved_check_is_case_insensitive() {
        assert!(is_reserved("WWW"));
        assert!(!is_reserved("myapp"));
    }
}
