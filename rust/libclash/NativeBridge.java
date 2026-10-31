// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package libclash;

/**
 * One embedded meow session per process. Blocking operations belong on a worker thread. No Android
 * Context, gomobile, Kotlin or coroutine dependency is required. Native failures become Java
 * exceptions. Call stop before starting another session.
 */
final class NativeBridge {
  static {
    System.loadLibrary("rsjni");
  }

  private NativeBridge() {}

  static native String command(String operation, String args);

  /**
   * Replace physical-network DNS endpoints (CSV IP:port). Call before start and on changes; empty
   * clears.
   */
  static native void notifyDnsChanged(String dnsList);

  static native String coreVersion();

  /** JSON describing the capabilities of this binding, not a claim of Mihomo parity. */
  static native String capabilities();

  /** Start an in-memory profile; baseDirectory resolves relative provider paths. */
  static native void startFromBytes(
      String home, String baseDirectory, byte[] config, Platform platform);

  /**
   * Load/reload including listener changes; retains an active TUN fd and restores the previous
   * config on failure.
   */
  static native void loadFromBytes(
      String home, String baseDirectory, byte[] config, Platform platform);

  /** Stop TUN, listeners, connections and worker tasks before releasing callbacks. */
  static native void stop();

  static native boolean isRunning();

  /** DNS IP CSV; empty disables hijacking, 0.0.0.0 hijacks every destination. */
  static native void startTunWithDns(int fd, String dns);

  /** Install VPN protection and discard transports created in standby. */
  static native void setPlatform(Platform platform);

  static native void stopTun();

  /**
   * Dispatch a finite Clash API request in-process, without opening a control port. Returns JSON
   * {"status": HTTP_STATUS, "body": "RESPONSE_BODY"}. Streaming /logs, /traffic and /memory are not
   * accepted here.
   */
  static native String request(String method, String path, String body);

  /** JSON counters: uploadTotal, downloadTotal. */
  static native String traffic();

  /** Nonblocking drain of log messages as a JSON array, oldest first. */
  static native String readLogs();

  /** Same state JSON as GET /asterisk/auto-switch. */
  static native String queryAutoSwitch();

  /** Replace auto-switch settings until stop; survives PUT /configs reloads. */
  static native void patchAutoSwitch(String settingsJSON);

  /** Parse and build with meow in offline validation mode. No listeners are started. */
  static native void validate(String home, String baseDirectory, byte[] config);
}
