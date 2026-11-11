// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package delegate

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/metacubex/mihomo/component/process"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/log"

	"cfa/native/app"
	"cfa/native/platform"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/constant"
)

var errBlocked = errors.New("blocked")

// ownerLookupTimeout bounds the name lookup that rebuilds a destination tuple.
// The answer is normally cached already, because the app resolved the same name
// through this core moments earlier.
const ownerLookupTimeout = 2 * time.Second

func Init(home, versionName string, platformVersion int) {
	log.Infoln("Init core, home: %s, versionName: %s, core: %s, platformVersion: %d", home, versionName, constant.Version, platformVersion)
	constant.SetHomeDir(home)
	app.ApplyVersionName(versionName)
	app.ApplyPlatformVersion(platformVersion)

	process.DefaultPackageNameResolver = resolvePackageName

	dialer.DefaultSocketHook = func(network, address string, conn syscall.RawConn) error {
		if platform.ShouldBlockConnection() {
			return errBlocked
		}

		return conn.Control(func(fd uintptr) {
			app.MarkSocket(int(fd))
		})
	}
}

// resolvePackageName maps a connection back to the app that owns its socket.
//
// A native TUN inbound hands over the real socket addresses in RawSrcAddr and
// RawDstAddr. A SOCKS inbound does not: the tunnel terminates the app flow and
// dials the core again from loopback, so the tuple has to be rebuilt from the
// metadata instead.
func resolvePackageName(metadata *constant.Metadata) (string, error) {
	if metadata.RawSrcAddr != nil && metadata.RawDstAddr != nil {
		uid := app.QuerySocketUid(metadata.RawSrcAddr, metadata.RawDstAddr)
		pkg := app.QueryAppByUid(uid)
		log.Debugln("[PKG] %s --> %s by %d[%s]", metadata.SourceAddress(), metadata.RemoteAddress(), uid, pkg)
		return pkg, nil
	}

	srcAddrPort := metadata.SourceAddrPort()
	if !metadata.SourceValid() || !srcAddrPort.IsValid() || srcAddrPort.Port() == 0 {
		return "", process.ErrInvalidNetwork
	}

	candidates := destinationCandidates(metadata)
	if len(candidates) == 0 {
		return "", process.ErrInvalidNetwork
	}

	for _, dstAddrPort := range candidates {
		src := metadataAddr(metadata.NetWork, srcAddrPort)
		dst := metadataAddr(metadata.NetWork, dstAddrPort)
		pkg := app.QueryAppByUid(app.QuerySocketUid(src, dst))
		if pkg != "" {
			log.Debugln("[PKG] %s --> %s by %s", metadata.SourceAddress(), dstAddrPort, pkg)
			return pkg, nil
		}
	}

	log.Debugln("[PKG] %s --> %s: no owner among %d candidates (host %q, dstIP %v, dstPort %d)",
		metadata.SourceAddress(), metadata.RemoteAddress(), len(candidates), metadata.Host, metadata.DstIP, metadata.DstPort)
	return "", nil
}

// destinationCandidates lists every destination tuple the app socket may hold.
// With sniffer override-destination the core clears DstIP and keeps only the
// domain, so the name is resolved back to the addresses the app dialed.
func destinationCandidates(metadata *constant.Metadata) []netip.AddrPort {
	candidates := make([]netip.AddrPort, 0, 4)
	if metadata.DstIP.IsValid() && metadata.DstPort != 0 {
		candidates = append(candidates, netip.AddrPortFrom(metadata.DstIP.Unmap(), metadata.DstPort))
	}

	if metadata.Host == "" || metadata.DstPort == 0 {
		return candidates
	}

	ctx, cancel := context.WithTimeout(context.Background(), ownerLookupTimeout)
	defer cancel()

	ips, err := resolver.LookupIP(ctx, metadata.Host)
	if err != nil {
		log.Debugln("[PKG] resolve %s for owner lookup failed: %s", metadata.Host, err.Error())
		return candidates
	}

	for _, ip := range ips {
		addrPort := netip.AddrPortFrom(ip.Unmap(), metadata.DstPort)
		dup := false
		for _, candidate := range candidates {
			if candidate == addrPort {
				dup = true
				break
			}
		}
		if !dup {
			candidates = append(candidates, addrPort)
		}
	}

	return candidates
}

func metadataAddr(netWork constant.NetWork, addrPort netip.AddrPort) net.Addr {
	if netWork == constant.UDP {
		return net.UDPAddrFromAddrPort(addrPort)
	}
	return net.TCPAddrFromAddrPort(addrPort)
}
