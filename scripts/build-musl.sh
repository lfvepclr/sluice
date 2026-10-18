#!/usr/bin/env bash
# sluice 唯一的构建入口：交叉编译到 x86_64-unknown-linux-musl 静态二进制。
#
# 依赖树是纯 Rust（rustls-rustcrypto），链接器 rust-lld 即可完成 musl 交叉链接，
# 不需要 zig、C 工具链或目标平台 sysroot。

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

# 目标未安装时自动补装（rustup 管理，无需 root）
if ! rustup target list --installed | grep -q "^$TARGET$"; then
	printf '==> 安装 target %s\n' "$TARGET"
	rustup target add "$TARGET"
fi

printf '==> 构建 %s\n' "$TARGET"
cargo build --release --target "$TARGET"

BIN="target/$TARGET/release/sluice"
[ -f "$BIN" ] || {
	printf '构建产物不存在：%s\n' "$BIN" >&2
	exit 1
}

printf '==> 校验产物\n'
file "$BIN"

if ! file "$BIN" | grep -Eq "statically linked|static-pie linked"; then
	printf '错误：产物不是静态链接，无法在 Alpine 上可靠运行\n' >&2
	exit 1
fi

printf '==> 完成\n'
ls -lh "$BIN"
