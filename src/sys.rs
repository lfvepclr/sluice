//! 进程资源信息采集。零 unsafe，优先读 `/proc`，macOS 回退到 `ps`。

/// 当前进程 RSS（KiB）。取不到返回 `None`，调用方降级为「未知」。
pub fn rss_kib() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                let kib = rest.trim().trim_end_matches(" kB").trim().parse().ok()?;
                return Some(kib);
            }
        }
        None
    }

    #[cfg(target_os = "macos")]
    {
        let pid = std::process::id();
        let out = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &pid.to_string()])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        text.trim().parse().ok()
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rss_is_positive_on_this_platform() {
        let rss = rss_kib();
        // 本平台必须能取到（macOS / Linux 均支持）；取不到说明采集逻辑坏了
        let rss = rss.expect("RSS 应可采集");
        assert!(rss > 0);
    }
}
