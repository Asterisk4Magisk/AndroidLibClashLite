// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package flowmeta

import (
	"io"
	"net/netip"
	"strings"
	"testing"
)

func TestOriginalSocketOwner(t *testing.T) {
	source := netip.MustParseAddrPort("172.19.0.1:35000")
	destination := netip.MustParseAddrPort("198.18.0.9:443")
	// Same source port on the relay and an unrelated socket must never match.
	text := "0: 0100007F:88B8 0100007F:FFFA 01 0:0 0:0 0 99999\n1: 010013AC:88B8 01010101:01BB 01 0:0 0:0 0 12345\n2: 010013AC:88B8 090012C6:01BB 01 0:0 0:0 0 1012345\n"
	uid, err := readUID(strings.NewReader(text), "tcp", source, destination)
	if err != nil || uid != 1012345 {
		t.Fatalf("owner=%d err=%v", uid, err)
	}
	if _, err = readUID(strings.NewReader(text), "tcp", source, netip.MustParseAddrPort("198.18.0.8:443")); err == nil {
		t.Fatal("unrelated socket matched")
	}
}

func TestWildcardUDPOwner(t *testing.T) {
	text := "0: 00000000:88B8 00000000:0000 07 0:0 0:0 0 1012345\n"
	uid, err := readUID(strings.NewReader(text), "udp", netip.MustParseAddrPort("172.19.0.1:35000"), netip.MustParseAddrPort("198.18.0.9:443"))
	if err != nil || uid != 1012345 {
		t.Fatalf("owner=%d err=%v", uid, err)
	}
	if _, err = readUID(strings.NewReader(text+strings.ReplaceAll(text, "1012345", "1012346")), "udp", netip.MustParseAddrPort("172.19.0.1:35000"), netip.MustParseAddrPort("198.18.0.9:443")); err == nil {
		t.Fatal("ambiguous owner accepted")
	}
}

func TestAmbiguousIPv4CannotFallBackToIPv6(t *testing.T) {
	first := "0: 00000000:88B8 00000000:0000 07 0:0 0:0 0 1012345\n"
	tables := map[string]string{
		"/proc/net/udp":  first + strings.ReplaceAll(first, "1012345", "1012346"),
		"/proc/net/udp6": "0: 00000000000000000000000000000000:88B8 00000000000000000000000000000000:0000 07 0:0 0:0 0 1012345\n",
	}
	uid, err := findUIDInTables("udp", netip.MustParseAddrPort("172.19.0.1:35000"), netip.MustParseAddrPort("198.18.0.9:443"), func(path string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(tables[path])), nil
	})
	if uid >= 0 || err == nil {
		t.Fatal("ambiguous IPv4 socket inherited an IPv6 socket owner", uid, err)
	}
}
