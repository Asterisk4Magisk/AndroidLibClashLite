// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

//go:build !linux

package flowmeta

import "errors"

func watchPackageFile(string, func(), func()) (func(), error) {
	return nil, errors.New("package watcher unavailable")
}
