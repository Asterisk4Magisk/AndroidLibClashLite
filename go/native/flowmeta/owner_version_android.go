// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

//go:build android && cgo

package flowmeta

/*
#include <android/api-level.h>
*/
import "C"

var androidAPILevel = int(C.android_get_device_api_level())
