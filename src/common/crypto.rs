//! 加密后端：整条依赖树只用纯 Rust 实现（RustCrypto），不引入 ring / aws-lc-rs。
//!
//! `rustls` 需要一个全局 `CryptoProvider`，这里统一在进程启动时安装一次。

use std::sync::{Arc, Once};

use rustls::crypto::CryptoProvider;

/// 安装全局 provider。重复调用安全。
pub fn install() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        if let Err(_existing) = rustls_rustcrypto::provider().install_default() {
            // 已经装过了，忽略
        }
    });
}

/// 取一个新的 provider 实例，供需要显式传 provider 的 API 使用。
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls_rustcrypto::provider())
}
