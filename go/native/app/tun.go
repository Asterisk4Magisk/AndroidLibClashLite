// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package app

import (
	"cfa/native/flowmeta"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"

	"cfa/native/platform"
)

type tunContext struct {
	markSocket     func(fd int)
	querySocketUid func(protocol int, source, target string) int
}

var currentTunContext atomic.Pointer[tunContext]

func MarkSocket(fd int) {
	currentTunContext.Load().markSocket(fd)
}

func QuerySocketUid(source, target net.Addr) int {
	_, bridged := source.(interface{ FlowUID() uint32 })
	if owner, ok := source.(interface{ FlowUID() uint32 }); ok && owner.FlowUID() != ^uint32(0) {
		return int(owner.FlowUID())
	}
	if raw, ok := source.(interface{ RawAddr() net.Addr }); ok {
		source = raw.RawAddr()
	}
	var protocol int

	switch source.Network() {
	case "udp", "udp4", "udp6":
		protocol = syscall.IPPROTO_UDP
	case "tcp", "tcp4", "tcp6":
		protocol = syscall.IPPROTO_TCP
	default:
		return -1
	}

	if PlatformVersion() < 29 {
		if bridged {
			src, e := netip.ParseAddrPort(source.String())
			if e != nil {
				return -1
			}
			dst, e := netip.ParseAddrPort(target.String())
			if e != nil {
				return -1
			}
			network := "tcp"
			if protocol == syscall.IPPROTO_UDP {
				network = "udp"
			}
			uid, e := flowmeta.FindUID(network, src.Addr().String(), src.Port(), dst.Addr().String(), dst.Port())
			if e != nil {
				return -1
			}
			return uid
		}
		return platform.QuerySocketUidFromProcFs(source, target)
	}

	return currentTunContext.Load().querySocketUid(protocol, source.String(), target.String())
}

func ApplyTunContext(markSocket func(fd int), querySocketUid func(int, string, string) int) {
	if markSocket == nil {
		markSocket = func(fd int) {}
	}

	if querySocketUid == nil {
		querySocketUid = func(int, string, string) int { return -1 }
	}

	currentTunContext.Store(&tunContext{markSocket: markSocket, querySocketUid: querySocketUid})
}

func init() {
	ApplyTunContext(nil, nil)
}
