// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package libclash

import (
	"encoding/json"

	"cfa/native/autoswitch"
	_ "cfa/native/autoswitch/api"
	"cfa/native/autoswitch/option"
)

// QueryAutoSwitch returns the same JSON state as GET /asterisk/auto-switch.
func QueryAutoSwitch() string { return marshalJSON(autoswitch.Snapshot()) }

// PatchAutoSwitch accepts the same JSON settings as PATCH /asterisk/auto-switch.
// They replace the configured asterisk-auto-switch value, across hot profile
// reloads, until Reset.
func PatchAutoSwitch(settingsJSON string) error {
	var settings option.Settings
	if err := json.Unmarshal([]byte(settingsJSON), &settings); err != nil {
		return err
	}
	return autoswitch.Patch(settings)
}
