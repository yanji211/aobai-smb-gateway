package smbhost

// 接入端类型的人工指定项（见 smbgo/client.go）。
//
// 用类型别名而不是新结构，是为了让 app 层不必直接依赖 smbgo——
// 配置解析、app 装配、平台分发三层之间只传一个名字，不用来回转换。

import "fsgw/internal/smbgo"

// ClientHint 是"这台机器是什么客户端"的人工指定项。
type ClientHint = smbgo.ClientHint

// ClientKind 是接入端大类（windows / macos / linux-cifs / linux-samba / other）。
type ClientKind = smbgo.ClientKind
