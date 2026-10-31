// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package libclash;

import android.content.Context;

final class CorePlatform {
  private CorePlatform() {}

  static void initialize(Context context) {
    // Rust receives DNS, UID and protection through its existing callbacks.
  }
}
