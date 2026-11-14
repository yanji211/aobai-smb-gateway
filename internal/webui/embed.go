// Package webui 存放控制台前端资源。全部通过 embed 打进二进制：
// 无 npm、无构建步骤、无 CDN，断网也能用（见 docs/01 第 11.1 节）。
package webui

import "embed"

//go:embed index.html style.css app.js
var FS embed.FS
