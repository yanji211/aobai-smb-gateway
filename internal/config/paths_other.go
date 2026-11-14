//go:build !linux

package config

// extraDefaultPaths 在非 Linux 上为空：Windows/macOS 版一直是"配置跟着 exe 走"。
func extraDefaultPaths() []string { return nil }
