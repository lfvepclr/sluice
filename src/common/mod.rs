//! 纯逻辑工具：路径解析、头部处理、SSRF 判定、子域名生成。
//!
//! 这一层不做任何 IO，全部可单测。M2 实现。

pub mod body;
pub mod headers;
pub mod ssrf;
pub mod subdomain;
pub mod upstream;
pub mod urlpath;
