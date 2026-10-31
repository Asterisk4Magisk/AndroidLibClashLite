// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package libclash;

public interface FetchCallback {
  void report(String statusJSON);

  void complete(String errorText);
}
