// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package flowmeta

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

var errAmbiguousOwner = errors.New("ambiguous socket owner")

// FindUID uses the original tuple. Android 8/9 permit this read; newer VPNs use
// the platform callback, and the standalone ROOT launcher uses this fallback.
func FindUID(network, source string, sourcePort uint16, destination string, destinationPort uint16) (int, error) {
	if network != "tcp" && network != "udp" {
		return -1, errors.New("invalid network")
	}
	src, e := netip.ParseAddr(source)
	if e != nil {
		return -1, e
	}
	dst, e := netip.ParseAddr(destination)
	if e != nil {
		return -1, e
	}
	// A wildcard UDP socket can only own traffic originating on this device.
	// Forwarded hotspot clients may use the same port as a local application.
	if !localSource(src) {
		return -1, errors.New("source is not local")
	}
	return findUIDInTables(network, netip.AddrPortFrom(src.Unmap(), sourcePort), netip.AddrPortFrom(dst.Unmap(), destinationPort), func(path string) (io.ReadCloser, error) {
		return os.Open(path)
	})
}

func findUIDInTables(network string, source, destination netip.AddrPort, open func(string) (io.ReadCloser, error)) (int, error) {
	found := -1
	for _, suffix := range []string{"", "6"} {
		f, e := open("/proc/net/" + network + suffix)
		if e != nil {
			continue
		}
		uid, e := readUID(f, network, source, destination)
		f.Close()
		if errors.Is(e, errAmbiguousOwner) {
			return -1, e
		}
		if e == nil {
			if found >= 0 && found != uid {
				return -1, errAmbiguousOwner
			}
			found = uid
		}
	}
	if found >= 0 {
		return found, nil
	}
	return -1, errors.New("original socket owner unavailable")
}

func procAddress(text string) (netip.AddrPort, error) {
	ipText, portText, ok := strings.Cut(text, ":")
	if !ok {
		return netip.AddrPort{}, errors.New("invalid proc address")
	}
	b, e := hex.DecodeString(ipText)
	if e != nil {
		return netip.AddrPort{}, e
	}
	if len(b) != 4 && len(b) != 16 {
		return netip.AddrPort{}, errors.New("invalid proc IP")
	}
	for i := 0; i < len(b); i += 4 {
		v := binary.NativeEndian.Uint32(b[i : i+4])
		binary.BigEndian.PutUint32(b[i:i+4], v)
	}
	ip, _ := netip.AddrFromSlice(b)
	port, e := strconv.ParseUint(portText, 16, 16)
	return netip.AddrPortFrom(ip.Unmap(), uint16(port)), e
}

func readUID(reader io.Reader, network string, source, destination netip.AddrPort) (int, error) {
	scan := bufio.NewScanner(reader)
	found := -1
	for scan.Scan() {
		f := strings.Fields(scan.Text())
		if len(f) < 8 {
			continue
		}
		local, e := procAddress(f[1])
		if e != nil || local.Port() != source.Port() {
			continue
		}
		remote, e := procAddress(f[2])
		if e != nil {
			continue
		}
		if local.Addr() != source.Addr() && !(network == "udp" && local.Addr().IsUnspecified()) {
			continue
		}
		if remote != destination && !(network == "udp" && remote.Addr().IsUnspecified() && remote.Port() == 0) {
			continue
		}
		uid, e := strconv.Atoi(f[7])
		if e != nil || uid < 0 {
			continue
		}
		// Ambiguous shared UDP sockets must not inherit an arbitrary app's identity.
		if found >= 0 && found != uid {
			return -1, errAmbiguousOwner
		}
		found = uid
	}
	if found >= 0 {
		return found, nil
	}
	return -1, errors.New("socket not found")
}

func localSource(source netip.Addr) bool {
	if source.IsLoopback() {
		return true
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && prefix.Addr().Unmap() == source.Unmap() {
			return true
		}
	}
	return false
}
