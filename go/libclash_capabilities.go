// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package libclash

import (
	"cfa/native/capabilities"
	_ "cfa/native/capabilities/api"
	profile "cfa/native/config"
	"github.com/metacubex/mihomo/config"
)

// Capabilities uses the same schema as the Rust AAR and GET /asterisk/capabilities.
func Capabilities() string { return marshalJSON(capabilities.Snapshot()) }

// DiagnoseConfig reports binding compatibility warnings, without building or
// changing the running configuration. It does not replace full validation.
func DiagnoseConfig(content []byte) (string, error) {
	content, err := profile.DecryptBytes(content)
	if err != nil {
		return "", err
	}
	_, err = config.UnmarshalRawConfig(content)
	if err != nil {
		return "", err
	}
	return "[]", nil
}
