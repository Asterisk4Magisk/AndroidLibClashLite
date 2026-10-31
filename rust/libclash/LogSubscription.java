// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package libclash;

public final class LogSubscription implements AutoCloseable {
  private final LogcatInterface callback;
  private volatile boolean closed;

  LogSubscription(LogcatInterface callback) {
    this.callback = callback;
  }

  boolean deliver(String message) {
    if (closed) return false;
    try {
      if (!callback.received(message)) close();
    } catch (RuntimeException e) {
      close();
    }
    return !closed;
  }

  @Override
  public void close() {
    closed = true;
    Libclash.removeLog(this);
  }
}
