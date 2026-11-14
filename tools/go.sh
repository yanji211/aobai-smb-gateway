#!/bin/sh
# 本机 Go 构建环境封装：本机 Go 是便携安装，且默认代理不通，所以统一在这里设。
# 用法：./tools/go.sh build ./...    ./tools/go.sh test ./...    ./tools/go.sh vet ./...
set -e

GO_ROOT_DIR="/c/Users/yanji/.workbuddy/binaries/go/go"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

export PATH="$GO_ROOT_DIR/bin:$PATH"
export GOPATH="D:/fsgw/.gopath"
export GOMODCACHE="D:/fsgw/.gopath/pkg/mod"
export GOCACHE="D:/fsgw/.gocache"
# 不要写 ",direct"：直连会卡十几分钟才超时。
export GOPROXY="https://goproxy.cn"
# 走代理校验：GOSUMDB=off 会让 toolchain 模块下载被拒（"checksum database disabled"）。
export GOSUMDB="sum.golang.org"
# SMB 服务端依赖要求 go1.26，允许按 go.mod 自动切换工具链。
# 钉死具体版本，避免每次构建都去探测/重新下载 toolchain。
export GOTOOLCHAIN="go1.26.10"
export GOFLAGS="-mod=mod"

cd "$PROJECT_DIR"
exec go "$@"
