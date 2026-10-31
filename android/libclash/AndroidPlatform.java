// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package libclash;

import android.content.Context;

/** Shared Android setup for either core. Call before Libclash.init. */
public final class AndroidPlatform {
  private AndroidPlatform() {}

  public static void initialize(Context context) {
    if (context == null) throw new IllegalArgumentException("context is required");
    Context application = context.getApplicationContext();
    CorePlatform.initialize(application == null ? context : application);
  }
}
