//! sluice —— 隧道与路径转发二合一代理。
//!
//! 本 crate 是二进制与库的统一入口：`src/main.rs` 只负责解析命令行，
//! 真正的逻辑分布在下列模块中，依赖方向严格自上而下（见 ARCHITECTURE.md）。

#![forbid(unsafe_code)]

pub mod agent;
pub mod bench;
pub mod common;
pub mod config;
pub mod doctor;
pub mod proto;
pub mod server;
pub mod transport;

/// 版本号，取自 Cargo.toml。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
