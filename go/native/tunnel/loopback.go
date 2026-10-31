// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package tunnel

import (
	"net/netip"
)

var loopback = netip.MustParseAddr("127.0.0.1")
