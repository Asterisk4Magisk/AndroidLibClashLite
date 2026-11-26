// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package owner

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"cfa/environment"
	"cfa/native/app"
	"cfa/native/dnsevents"
	"cfa/native/flowmeta"
	"github.com/metacubex/mihomo/component/process"
	C "github.com/metacubex/mihomo/constant"
)

var processMode = func() process.FindProcessMode { return process.FindProcessStrict }

func SetProcessModeReader(reader func() process.FindProcessMode) {
	processMode = reader
}

func ForUDP(ctx context.Context, source, destination netip.AddrPort) context.Context {
	if !canLookupUID(source, destination) {
		return ctx
	}
	return dnsevents.WithUIDLookup(ctx, func() (uint32, bool) {
		return lookupUID("udp", source, destination)
	})
}

// PrepareTCPUID keeps a successful lookup for the lifetime of the DNS connection.
func PrepareTCPUID(source, destination netip.AddrPort) func(context.Context) context.Context {
	var known atomic.Pointer[uint32]
	var inFlight sync.Mutex
	lookup := func() (uint32, bool) {
		if processMode() != process.FindProcessAlways {
			return 0, false
		}
		if uid := known.Load(); uid != nil {
			return *uid, true
		}
		if !inFlight.TryLock() {
			return 0, false
		}
		defer inFlight.Unlock()
		if uid := known.Load(); uid != nil {
			return *uid, true
		}
		uid, ok := lookupUID("tcp", source, destination)
		if ok {
			known.Store(&uid)
		}
		return uid, ok
	}
	return func(ctx context.Context) context.Context {
		if processMode() == process.FindProcessOff {
			return ctx
		}
		if uid := known.Load(); uid != nil {
			return dnsevents.WithUID(ctx, *uid)
		}
		if canLookupUID(source, destination) {
			return dnsevents.WithUIDLookup(ctx, lookup)
		}
		return ctx
	}
}

func canLookupUID(source, destination netip.AddrPort) bool {
	return dnsevents.HasSubscribers() && processMode() == process.FindProcessAlways &&
		source.IsValid() && destination.IsValid()
}

func lookupUID(network string, source, destination netip.AddrPort) (uint32, bool) {
	if processMode() != process.FindProcessAlways {
		return 0, false
	}
	var uid int
	if environment.IsCLI {
		var err error
		uid, err = flowmeta.FindUID(network, source, destination)
		if err != nil {
			return 0, false
		}
	} else if network == "tcp" {
		uid = app.QuerySocketUid(net.TCPAddrFromAddrPort(source), net.TCPAddrFromAddrPort(destination))
	} else {
		uid = app.QuerySocketUid(net.UDPAddrFromAddrPort(source), net.UDPAddrFromAddrPort(destination))
	}
	return uint32(uid), uid >= 0 && processMode() == process.FindProcessAlways
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
		if known && processMode() != process.FindProcessOff {
			ctx = dnsevents.WithUID(ctx, uid)
		}
		return ctx
	}
}
