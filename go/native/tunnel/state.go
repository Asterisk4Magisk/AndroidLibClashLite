// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package tunnel

import (
	"github.com/metacubex/mihomo/tunnel"
)

func QueryMode() string {
	return tunnel.Mode().String()
}
