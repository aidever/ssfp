#!/usr/bin/env bash
# ssfp 安装 / 升级 / 卸载脚本
#
#   curl -fsSL https://raw.githubusercontent.com/aidever/ssfp/main/install.sh | sudo bash -s -- [选项]
#
# 选项：
#   --port N           新装时的监听端口（默认 8388；已有配置时忽略）
#   --host H           新装时写进链接的公网 IP 或域名（默认自动取出口网卡地址）
#   --version vX.Y.Z   安装指定版本（默认最新版）
#   --file PATH        用本地的 ssfp-<arch>-linux-musl.tar.gz，不下载
#   --open-firewall    在 ufw / firewalld 中放行端口（TCP + UDP）；不加只提示
#   --no-start         只安装，不启动 / 重启服务
#   --uninstall        卸载（保留配置和数据）；加 --purge 一并删除 /etc/ssfp /var/lib/ssfp /var/log/ssfp
#
# 重复运行即升级：保留配置与数据，旧程序备份为 /usr/local/bin/ssfp.bak。
set -euo pipefail

REPO="aidever/ssfp"
PORT=8388
HOST=""
VERSION="latest"
FILE=""
OPEN_FW=0
START=1
UNINSTALL=0
PURGE=0

BIN=/usr/local/bin/ssfp
CONF=/etc/ssfp/config.toml
UNIT=/etc/systemd/system/ssfp.service
SYSCTL=/etc/sysctl.d/99-ssfp.conf

say() { printf '==> %s\n' "$*"; }
warn() { printf 'WARN %s\n' "$*" >&2; }
die() { printf 'FAIL %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --host) HOST="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --file) FILE="$2"; shift 2 ;;
    --open-firewall) OPEN_FW=1; shift ;;
    --no-start) START=0; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge) PURGE=1; shift ;;
    -h|--help) sed -n '2,16p' "$0" 2>/dev/null || true; exit 0 ;;
    *) die "未知参数 $1" ;;
  esac
done

[ "$(id -u)" = 0 ] || die "需要 root（sudo bash install.sh ...）"
[ "$(uname -s)" = Linux ] || die "只支持 Linux"
command -v systemctl >/dev/null && [ -d /run/systemd/system ] || die "需要以 systemd 为 init 的系统"

if [ "$UNINSTALL" = 1 ]; then
  say "卸载 ssfp"
  systemctl disable --now ssfp 2>/dev/null || true
  rm -f "$UNIT" "$UNIT.bak" "$BIN" "$BIN.bak" "$SYSCTL"
  systemctl daemon-reload || true
  if [ "$PURGE" = 1 ]; then
    rm -rf /etc/ssfp /var/lib/ssfp /var/log/ssfp
    say "已删除配置与数据"
  else
    say "保留了 /etc/ssfp /var/lib/ssfp /var/log/ssfp（加 --purge 删除）"
  fi
  warn "net.ipv4.tcp_rmem 不会自动恢复，重启后生效或手动 sysctl -w"
  exit 0
fi

case "$(uname -m)" in
  x86_64|amd64) ARCH=x86_64 ;;
  aarch64|arm64) ARCH=aarch64 ;;
  *) die "不支持的架构 $(uname -m)（只有 x86_64 / aarch64）" ;;
esac

if command -v systemd-detect-virt >/dev/null; then
  VIRT=$(systemd-detect-virt -c 2>/dev/null || true)
  if [ -n "$VIRT" ] && [ "$VIRT" != none ]; then
    warn "运行在容器（$VIRT）里：多半无法加载 eBPF，SYN 选项布局不会改写（TTL / wscale 仍生效）"
  fi
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
NAME="ssfp-$ARCH-linux-musl"

if [ -n "$FILE" ]; then
  cp "$FILE" "$TMP/$NAME.tar.gz"
else
  command -v curl >/dev/null || die "需要 curl"
  if [ "$VERSION" = latest ]; then
    BASE="https://github.com/$REPO/releases/latest/download"
  else
    BASE="https://github.com/$REPO/releases/download/$VERSION"
  fi
  say "下载 $BASE/$NAME.tar.gz"
  curl -fsSL --retry 3 -o "$TMP/$NAME.tar.gz" "$BASE/$NAME.tar.gz" || die "下载失败（服务器访问 GitHub 不通？可以本地下载后用 --file）"
  curl -fsSL --retry 3 -o "$TMP/SHA256SUMS" "$BASE/SHA256SUMS" || die "下载 SHA256SUMS 失败"
  (cd "$TMP" && grep " $NAME.tar.gz\$" SHA256SUMS | sha256sum -c --quiet -) || die "校验和不匹配"
fi
tar xzf "$TMP/$NAME.tar.gz" -C "$TMP"
SRC="$TMP/$NAME"
[ -x "$SRC/ssfp" ] || die "压缩包里没有 ssfp"
NEW_VER=$("$SRC/ssfp" version)
say "安装 $NEW_VER"

if [ -x "$BIN" ]; then
  cp -p "$BIN" "$BIN.bak"
  say "旧版本 $("$BIN" version 2>/dev/null || echo '?') 备份为 $BIN.bak"
fi
install -m 755 "$SRC/ssfp" "$BIN.new" && mv -f "$BIN.new" "$BIN"

if [ -f "$UNIT" ] && ! cmp -s "$SRC/ssfp.service" "$UNIT"; then
  cp -p "$UNIT" "$UNIT.bak"
  say "systemd 单元有改动，旧文件备份为 $UNIT.bak"
fi
install -m 644 "$SRC/ssfp.service" "$UNIT"
install -m 644 "$SRC/99-ssfp.conf" "$SYSCTL"
sysctl -q -p "$SYSCTL" || warn "sysctl 设置失败（容器里常见）：Windows / Android 模板的 wscale 会偏小"
install -d -m 700 /etc/ssfp
install -m 644 "$SRC/config.example.toml" /etc/ssfp/config.example.toml

if [ -f "$CONF" ]; then
  say "保留现有配置 $CONF"
else
  args=(-c "$CONF" --port "$PORT")
  [ -n "$HOST" ] && args+=(--host "$HOST")
  "$BIN" init "${args[@]}"
fi

systemctl daemon-reload
systemctl enable ssfp >/dev/null 2>&1
if [ "$START" = 1 ]; then
  systemctl restart ssfp
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    sleep 1
    systemctl is-active --quiet ssfp && "$BIN" check -c "$CONF" >/dev/null 2>&1 && break
  done
  systemctl is-active --quiet ssfp || { journalctl -u ssfp -n 30 --no-pager >&2 || true; die "服务没有起来"; }
fi

# 防火墙
LPORT=$(sed -n 's/^listen *= *"[^"]*:\([0-9]*\)".*/\1/p' "$CONF" | head -1)
LPORT=${LPORT:-$PORT}
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
  if [ "$OPEN_FW" = 1 ]; then
    ufw allow "$LPORT/tcp" >/dev/null && ufw allow "$LPORT/udp" >/dev/null && say "ufw 已放行 $LPORT/tcp+udp"
  else
    warn "ufw 已启用：需要放行端口 → ufw allow $LPORT/tcp && ufw allow $LPORT/udp（或加 --open-firewall）"
  fi
elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
  if [ "$OPEN_FW" = 1 ]; then
    firewall-cmd -q --permanent --add-port="$LPORT/tcp" --add-port="$LPORT/udp" && firewall-cmd -q --reload && say "firewalld 已放行 $LPORT/tcp+udp"
  else
    warn "firewalld 已启用：需要放行端口 → firewall-cmd --permanent --add-port=$LPORT/tcp --add-port=$LPORT/udp && firewall-cmd --reload（或加 --open-firewall）"
  fi
fi

echo
if [ "$START" = 1 ]; then
  "$BIN" check -c "$CONF" || true
fi
cat <<EOF

完成。云主机还需要在控制台的安全组里放行 TCP + UDP $LPORT。
下一步：
  ssfp ctl user add 我
  ssfp ctl dev add 我 电脑 windows        # 模板：windows apple android linux auto
  ssfp ctl dev test 我/电脑               # 自测链路与 SYN 改写
  ssfp ctl sub 我                         # Clash 订阅内容；单台设备链接：ssfp ctl dev link 我/电脑
看板：ssh -L 43480:127.0.0.1:43480 <服务器>，然后打开 ssfp ctl url 输出的地址
EOF
