// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package libclash;

/** Callbacks run on native worker threads. Do not call Libclash methods from a callback. */
interface Platform {
  /** Protect before connect/bind. A false result rejects the socket. */
  boolean protectSocket(int fd);

  /** Return the full Android UID, or -1 when unknown. */
  int querySocketUid(int protocol, String source, String destination);

  /** Return the package name for this UID, or null/empty when unknown. */
  String packageForUid(int uid);
}
