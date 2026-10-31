// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package libclash;

public interface TunInterface {
  void markSocket(int fd);

  int querySocketUid(int protocol, String source, String target);
}
