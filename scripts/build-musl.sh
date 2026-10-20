#!/usr/bin/env bash
# sluice 唯一的构建入口：交叉编译到 Linux musl 静态二进制。
#
# 产物覆盖两类部署面：
#   - x86_64：Alpine 服务器
#   - aarch64：ARM64 Linux 客户端（树莓派 / ARM 云主机 / 安卓 Termux 之外的常规 ARM 盒子）
#
# 依赖树是纯 Rust（rustls-rustcrypto），链接器 rust-lld 即可完成 musl 交叉链接，
# 不需要 zig、C 工具链或目标平台 sysroot。

set -euo pipefail

TARGETS="x86_64-unknown-linux-musl aarch64-unknown-linux-musl"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

need() {
	command -v "$1" >/dev/null 2>&1 || {
		printf '缺少 %s：%s\n' "$1" "$2" >&2
		exit 1
	}
}

need cargo "https://rustup.rs"

for TARGET in $TARGETS; do
	# 目标未安装时自动补装（rustup 管理，无需 root）
	if ! rustup target list --installed | grep -q "^$TARGET$"; then
		printf '==> 安装 target %s\n' "$TARGET"
		rustup target add "$TARGET"
	fi

	# x86_64-musl 默认走 rust-lld 自含式链接；aarch64-musl 默认调 cc，
	# 在 macOS 上会撞上系统 clang。统一强制 rust-lld，保持零 C 工具链。
	case "$TARGET" in
	x86_64-unknown-linux-musl) ;;
	aarch64-unknown-linux-musl)
		export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld
		export RUSTFLAGS="-C link-self-contained=yes"
		;;
	esac

	printf '==> 构建 %s\n' "$TARGET"
	cargo build --release --target "$TARGET"

	BIN="target/$TARGET/release/sluice"
	[ -f "$BIN" ] || {
		printf '构建产物不存在：%s\n' "$BIN" >&2
		exit 1
	}

	printf '==> 校验产物 %s\n' "$TARGET"
	file "$BIN"

	if ! file "$BIN" | grep -Eq "statically linked|static-pie linked"; then
		printf '错误：%s 产物不是静态链接，无法在 Alpine 上可靠运行\n' "$TARGET" >&2
		exit 1
	fi

	ls -lh "$BIN"
done

printf '==> 完成\n'
