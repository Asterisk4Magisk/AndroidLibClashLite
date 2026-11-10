// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package profilecache

import "github.com/metacubex/mihomo/component/profile/cachefile"

// Reset relies on cachefile_reset.go.txt, which source preparation adds to
// the upstream package.
func Reset() {
	cachefile.AsteriskReset()
}
