#!/bin/sh
# sluice 安装器（Alpine / OpenRC）
#
# 用法（在解包后的目录里，以 root 执行）：
#   sh install.sh
#
# 幂等：已存在的 /etc/sluice/server.toml 不会被覆盖，token 不会丢。

set -eu

PKG_BIN="sluice"
PKG_INITD="sluice.initd"
PKG_CONFD="sluice.confd"

PREFIX="/usr/local/bin"
STATE_DIR="/var/lib/sluice"
CONF_DIR="/etc/sluice"
CONF_FILE="$CONF_DIR/server.toml"
LOG_FILE="/var/log/sluice.log"
SERVICE="sluice"
SERVICE_USER="sluice"

log() { printf '==> %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "必须以 root 运行"
[ -f "./$PKG_BIN" ] || die "./$PKG_BIN 不存在——请在解包目录内执行"
[ -f "./$PKG_INITD" ] || die "./$PKG_INITD 不存在"
[ -f "./$PKG_CONFD" ] || die "./$PKG_CONFD 不存在"
command -v rc-service >/dev/null 2>&1 || die "未找到 rc-service——本安装器只支持 Alpine/OpenRC"

ARCH="$(uname -m)"
case "$ARCH" in
	x86_64 | aarch64) ;;
	*) die "不支持的架构：$ARCH" ;;
esac

# 静态链接是 Alpine 上唯一可靠的形式
if command -v ldd >/dev/null 2>&1; then
	if ldd "./$PKG_BIN" 2>/dev/null | grep -q "=>"; then
		die "./$PKG_BIN 看起来是动态链接，需要静态 musl 构建"
	fi
fi

log "安装 sluice（$ARCH）"

if ! getent group "$SERVICE_USER" >/dev/null 2>&1; then
	log "创建用户组 $SERVICE_USER"
	addgroup -S "$SERVICE_USER" || die "addgroup 失败"
fi
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
	log "创建用户 $SERVICE_USER"
	adduser -S -D -H -s /sbin/nologin -G "$SERVICE_USER" "$SERVICE_USER" || die "adduser 失败"
fi

install -d -m 755 "$CONF_DIR"
install -d -m 700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$STATE_DIR"

install -m 755 "./$PKG_BIN" "$PREFIX/$PKG_BIN"
install -m 755 "./$PKG_INITD" "/etc/init.d/$SERVICE"
install -m 644 "./$PKG_CONFD" "/etc/conf.d/$SERVICE"
touch "$LOG_FILE"
chown "$SERVICE_USER:$SERVICE_USER" "$LOG_FILE"
chmod 640 "$LOG_FILE"

if [ -f "$CONF_FILE" ]; then
	log "保留已有配置 $CONF_FILE（不覆盖）"
	chown root:"$SERVICE_USER" "$CONF_FILE"
	chmod 640 "$CONF_FILE"
else
	log "生成配置模板 $CONF_FILE"
	cat > "$CONF_FILE" <<'EOF'
# sluice 服务端配置——最少三个字段，其余全部有默认值
base_domain = "xxx.duckdns.org"
token       = "CHANGE_ME"
dns_token   = "CHANGE_ME"

[listen]
control = "0.0.0.0:7835"
http    = "0.0.0.0:80"
https   = "0.0.0.0:8443"

[tls]
mode = "acme"
EOF
	chown root:"$SERVICE_USER" "$CONF_FILE"
	chmod 640 "$CONF_FILE"
	warn "请先编辑 $CONF_FILE 填入 base_domain / token / dns_token"
fi

rc-update add "$SERVICE" default >/dev/null 2>&1 || true

log "完成。下一步："
printf '  1. 编辑 %s\n' "$CONF_FILE"
printf '  2. rc-service %s start\n' "$SERVICE"
printf '  3. rc-status 确认状态，日志在 %s\n' "$LOG_FILE"
