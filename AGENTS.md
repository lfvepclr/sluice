# sluice — Agent 入口

本文件是跨 Agent 的统一入口（Claude Code / Codex / CodeBuddy / Cursor 等都会自动读取）。

## 动手前先读文档

| 文档 | 回答什么问题 |
| --- | --- |
| [README.md](README.md) | 这是什么、怎么装、怎么配、怎么排障 |
| [ARCHITECTURE.md](ARCHITECTURE.md) | 分层、协议、数据流、关键决策、性能约束 |
| `.agent/` | 历史计划，命名 `YYYYMMDDHHMM-<标题>.md` |

改哪个目录，先读对应模块的文档注释（`src/**/mod.rs` 顶部）。

## 硬约定

1. **`#![forbid(unsafe_code)]`**：`src/lib.rs` 与 `src/main.rs` 两处，任何情况下不得移除。
2. **构建只走 `scripts/build-musl.sh`**，不要手写交叉编译命令。
3. **不暴露调参项**：缓冲区、流控窗口、超时、连接池都是内置最优值，不要加 CLI 开关。
4. **响应体禁止 `collect()`**：全程流式，否则 SSE 与 WebSocket 会坏。
5. **配置字段改动必须同步** `src/config.rs` + `ARCHITECTURE.md` §5 + `README.md` 配置说明。
6. **密钥、真实服务器地址禁止入库**：文档与示例统一用 `$SLUICE_HOST` / 占位域名。
7. **不监听 443**：该端口被部署环境中的既有服务占用。
8. **测试先行**：纯逻辑模块（`common/`）必须有单测覆盖边界。

## 常用命令

```sh
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
./scripts/build-musl.sh          # 交叉编译到 Alpine 可用的静态二进制
```

## 提交规范

中文 + conventional 前缀：`feat(scope)` / `fix(scope)` / `test(scope)` / `docs` / `chore`。

示例：`feat(server): 子域名分配与 60s 保留期`

## 目录职责

| 目录 | 职责 | 禁止 |
| --- | --- | --- |
| `src/server/` | 控制面、入口、隧道、出口、TLS/ACME | 不做纯函数解析 |
| `src/agent/` | 隧道承接、本地转发代理 | 不碰服务器端状态 |
| `src/common/` | 纯函数：path 解析、头部、SSRF、子域名 | **不做 IO** |
| `src/proto/` | 帧编解码与错误码 | 不依赖 hyper |
| `src/transport.rs` | TLS + yamux 建连与驱动 | 不感知 HTTP 语义 |
