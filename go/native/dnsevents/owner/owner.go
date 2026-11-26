// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package owner

import (
	"context"
	"net"
	"net/netip"

	"cfa/environment"
	"cfa/native/app"
	"cfa/native/dnsevents"
	"cfa/native/flowmeta"
	C "github.com/metacubex/mihomo/constant"
)

func ForFlow(ctx context.Context, network string, source, destination netip.AddrPort) context.Context {
	if !dnsevents.Enabled() || !source.IsValid() || !destination.IsValid() {
		return ctx
	}
	return dnsevents.WithUIDLookup(ctx, func() (uint32, bool) {
		var uid int
		if environment.IsCLI {
			var err error
			uid, err = flowmeta.FindUID(network, source.Addr().String(), source.Port(),
				destination.Addr().String(), destination.Port())
			if err != nil {
				return 0, false
			}
		} else if network == "tcp" {
			uid = app.QuerySocketUid(net.TCPAddrFromAddrPort(source), net.TCPAddrFromAddrPort(destination))
		} else {
			uid = app.QuerySocketUid(net.UDPAddrFromAddrPort(source), net.UDPAddrFromAddrPort(destination))
		}
		return uint32(uid), uid >= 0
	})
}

// PrepareMetadata snapshots the known UID of a DNS outbound.
// A receiver uses the snapshot only when it starts observing a message.
func PrepareMetadata(metadata *C.Metadata) func(context.Context) context.Context {
	uid, known := metadata.Uid, metadata.Uid != 0 && metadata.Uid != flowmeta.UnknownUID
	if owner, ok := metadata.RawSrcAddr.(interface{ FlowUID() uint32 }); ok {
		if original := owner.FlowUID(); original != flowmeta.UnknownUID {
			// A relay can identify netd's socket as root without knowing the app.
			uid, known = original, original != 0
		}
	}
	return func(ctx context.Context) context.Context {
		if known {
			ctx = dnsevents.WithUID(ctx, uid)
		}
		return ctx
	}
}
