#!/bin/sh
# fsgw Linux 安装/升级脚本。用法：sudo sh install.sh
# 需要与本脚本同目录的 fsgw（linux/amd64 二进制）、config.yaml、fsgw.service
#
# SMB 由进程内的纯 Go SMB2/3 服务端提供，不安装 samba，也不需要系统账户。
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
BIN=/usr/local/bin/fsgw
ETC=/etc/fsgw
LIB=/var/lib/fsgw

if [ "$(id -u)" != "0" ]; then
    echo "请用 root 运行：sudo sh $0" >&2
    exit 1
fi

echo "== 1/5 检查 445 是否被占用 =="
# 只提示，不替用户停别人的服务。samba 若在跑必须停掉，否则 Go 服务端绑不上 445。
if ss -lntp 2>/dev/null | grep -q ':445 '; then
    echo "  [警告] 445 已被占用："
    ss -lntp 2>/dev/null | grep ':445 ' | sed 's/^/    /'
    echo "  若占用者是 smbd/samba，请先执行：systemctl disable --now smbd nmbd"
else
    echo "  445 空闲"
fi

echo "== 2/5 安装二进制 =="
install -m 0755 "$HERE/fsgw" "$BIN"
echo "  $BIN ($(stat -c %s "$BIN") 字节)"

echo "== 3/5 目录与配置 =="
mkdir -p "$ETC" "$LIB" /var/log/fsgw
if [ -f "$ETC/config.yaml" ]; then
    cp -f "$ETC/config.yaml" "$ETC/config.yaml.bak"
    echo "  已有配置，备份为 config.yaml.bak"
fi
install -m 0644 "$HERE/config.yaml" "$ETC/config.yaml"
echo "  $ETC/config.yaml"

echo "== 4/5 systemd 单元 =="
install -m 0644 "$HERE/fsgw.service" /etc/systemd/system/fsgw.service
systemctl daemon-reload
systemctl enable fsgw >/dev/null 2>&1 || true
systemctl restart fsgw
sleep 2
systemctl is-active fsgw >/dev/null 2>&1 && echo "  fsgw.service 已运行" || {
    echo "启动失败，最近日志：" >&2
    journalctl -u fsgw -n 30 --no-pager >&2 || true
    exit 1
}

echo "== 5/5 SMB1 通道（内置，给只支持 SMB1 的老设备）=="
# 小米电视这类客户端的 SMB 客户端只列得到 NT LM 0.12，纯 SMB2/3 服务端没法服务它。
# 网关内置一条最小的 SMB1 通道（internal/smbgo/smb1srv.go），认出这类客户端就把
# 那条 TCP 连接交给它，Linux / Windows 共用同一份代码，不需要装 samba。
echo "  内置通道已随 fsgw 一起安装（config.yaml 里 smb1_backend 留空即生效）"

# 旧版本用一份只监听 127.0.0.1:4450 的 samba 兜底，现在不再需要：装了内置通道后
# 把它停掉，免得白占内存、也免得"改的配置到底生效在哪"说不清。
if systemctl list-unit-files 2>/dev/null | grep -q '^fsgw-smb1\.service'; then
    systemctl disable --now fsgw-smb1 >/dev/null 2>&1 || true
    echo "  已停用旧的 fsgw-smb1（samba 兜底）"
fi

echo "== 自检 =="
"$BIN" status -config "$ETC/config.yaml" | head -12 || true

cat <<'EOF'

安装完成。常用命令：
  sudo fsgw on -state ALL -confirm     # 开启 SMB + DLNA + WebDAV
  sudo fsgw off                        # 全关（445 / 8200 / 8443 立即停止监听）
  sudo fsgw status
  sudo fsgw smb check                  # SMB 逐项诊断
  sudo fsgw ui                         # 打印带 token 的控制台地址
EOF
