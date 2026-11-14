#!/bin/sh
# 本机 SMB 客户端验收（**不需要管理员权限**）。
#
# 为什么要有这个脚本：Windows 自带的重定向器不支持 "\\host@port\share"，
# 没提权就抢不到 445，也就没法用资源管理器验证自研服务端。这里用第三方
# 纯 Go 客户端（go-smb2）当"外部考官"，把服务端起在任意端口上验收。
#
# 用法：
#   ./tools/smbping.sh                       # 连 127.0.0.1:4450，账号 admin/changeme
#   ./tools/smbping.sh -addr 127.0.0.1:4450 -guest
#   ./tools/smbping.sh -addr 192.0.2.10:4450 -user admin -pass changeme -mb 200 -bulk 500
#
# 前置：先在另一个窗口把服务端起起来，例如
#   ./tools/go.sh build -o .tmp/smbserve.exe ./tools/smbserve
#   ./.tmp/smbserve.exe -root D:\share -share share -addr :4450 -user admin -pass changeme
set -e

GO_ROOT_DIR="/c/Users/yanji/.workbuddy/binaries/go/go"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

export PATH="$GO_ROOT_DIR/bin:$PATH"
export GOPATH="$PROJECT_DIR/.gopath"
export GOMODCACHE="$PROJECT_DIR/.gopath/pkg/mod"
export GOCACHE="$PROJECT_DIR/.gocache2"
export GOPROXY="https://goproxy.cn"
export GOSUMDB="sum.golang.org"
export GOTOOLCHAIN="go1.26.10"
export GOFLAGS="-mod=mod"

cd "$PROJECT_DIR/tools/smbping"
exec go run . "$@"
