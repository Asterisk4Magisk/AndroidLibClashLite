// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

// Package capabilities describes the compiled Android binding, not an uploaded core.
package capabilities

import "github.com/metacubex/mihomo/constant"

func Snapshot() map[string]any {
	return map[string]any{
		"schemaVersion": 1, "core": "mihomo", "version": constant.Version,
		"jni": true, "cli": true, "tunFd": true, "clashApi": true,
		"mixed": true, "socks5": true, "http": true, "rootTproxy": true, "rootTun": true,
		"age": true, "subscriptionHwid": true, "autoSwitch": true, "systemDns": true,
		"libclashFacade": true, "isolatedValidation": false, "dnsOutbound": true,
		"tunDnsTcp": true, "tunDnsUdp": true,
		"ageIdentities":                  []string{"X25519", "Hybrid"},
		"tunStacks":                      []string{"system", "gvisor", "mixed", "mips"},
		"selectableCongestionController": true,
		"congestionControllers":          []string{"cubic", "reno", "bbr", "bbr3"},
		"congestionControllerStacks":     []string{"mips"},
		"listenerHotReload":              true, "connectionTracking": []string{"tcp", "udp"},
		"memoryMetric": "goHeap", "configDiagnostics": true, "uiSubtitlePattern": true,
		"dnsOptions": map[string]bool{"direct-nameserver": true, "respect-rules": true, "prefer-h3": true},
	}
}
