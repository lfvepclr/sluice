#!/usr/bin/env bash
# sluice 唯一的构建入口：交叉编译到 x86_64-unknown-linux-musl 静态二进制。
#
# 为什么需要 zig：TLS 后端用 ring，含 C 与汇编，rust-lld 单独无法完成 musl 链接。
# 若将来换成纯 Rust 加密后端，可以去掉 zig，改回 linker = "rust-lld"。

set -euo pipefail

TARGET="x86_64-unknown-linux-musl"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

need() {
	command -v "$1" >/dev/null 2>&1 || {
		printf '缺少 %s：%s\n' "$1" "$2" >&2
		exit 1
	}
}

need cargo "https://rustup.rs"
need zig "brew install zig"
need cargo-zigbuild "cargo install cargo-zigbuild"

printf '==> 构建 %s\n' "$TARGET"
CC_x86_64_unknown_linux_musl="zig cc" \
	cargo zigbuild --release --target "$TARGET"

BIN="target/$TARGET/release/sluice"
[ -f "$BIN" ] || {
	printf '构建产物不存在：%s\n' "$BIN" >&2
	exit 1
}

printf '==> 校验产物\n'
file "$BIN"

if ! file "$BIN" | grep -q "statically linked"; then
	printf '错误：产物不是静态链接，无法在 Alpine 上可靠运行\n' >&2
	exit 1
fi

printf '==> 完成\n'
ls -lh "$BIN"
