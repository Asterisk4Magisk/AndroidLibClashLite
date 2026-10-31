// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package libclash;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;

/** Source-compatible Android facade. Use either the Go AAR or the Rust AAR. */
public final class Libclash {
  private Libclash() {}

  static final Object LIFECYCLE = new Object();
  static final ExecutorService WORK =
      Executors.newSingleThreadExecutor(r -> daemon(r, "meow-config"));
  private static final ScheduledExecutorService EVENTS =
      Executors.newSingleThreadScheduledExecutor(r -> daemon(r, "meow-events"));
  private static final CopyOnWriteArrayList<LogSubscription> LOGS = new CopyOnWriteArrayList<>();
  private static volatile TunInterface tun;
  private static volatile Map<Integer, String> packages = Collections.emptyMap();
  private static volatile String home, sessionOverride = "{}", physicalDns = "";
  static volatile ContentResolver contentResolver;
  private static volatile Traffic rates = new Traffic();
  private static long lastUp, lastDown, lastSample;
  private static String profileMode = "rule", profileLogLevel = "info";
  private static volatile String subtitlePattern = "";
  private static final Platform PLATFORM =
      new Platform() {
        public boolean protectSocket(int fd) {
          TunInterface callback = tun;
          if (callback != null) callback.markSocket(fd);
          return true;
        }

        public int querySocketUid(int protocol, String source, String target) {
          TunInterface callback = tun;
          return callback == null ? -1 : callback.querySocketUid(protocol, source, target);
        }

        public String packageForUid(int uid) {
          String value = packages.get(uid);
          return value == null ? "" : value;
        }
      };

  static {
    EVENTS.scheduleAtFixedRate(Libclash::sample, 1, 1, TimeUnit.SECONDS);
  }

  static Thread daemon(Runnable runnable, String name) {
    Thread thread = new Thread(runnable, name);
    thread.setDaemon(true);
    return thread;
  }

  public static void touch() {
    NativeBridge.coreVersion();
  }

  public static void init(
      String directory, String appVersion, int sdkVersion, ContentResolver resolver)
      throws Exception {
    synchronized (LIFECYCLE) {
      if (home != null) return;
      File path = new File(directory);
      if (!path.isAbsolute()) throw new IllegalArgumentException("home must be absolute");
      Files.createDirectories(path.toPath());
      home = path.getCanonicalPath();
      contentResolver = resolver;
      reset();
    }
  }

  static String home() {
    if (home == null) throw new IllegalStateException("Libclash.init is required");
    return home;
  }

  static JSONObject object(Object... values) {
    try {
      JSONObject result = new JSONObject();
      for (int i = 0; i < values.length; i += 2) result.put((String) values[i], values[i + 1]);
      return result;
    } catch (Exception e) {
      throw failure(e);
    }
  }

  static IllegalStateException failure(Exception e) {
    return e instanceof IllegalStateException
        ? (IllegalStateException) e
        : new IllegalStateException(e.getMessage(), e);
  }

  static Object nativeCall(String method, JSONObject args) {
    try {
      return new JSONTokener(NativeBridge.command(method, args.toString())).nextValue();
    } catch (Exception e) {
      throw failure(e);
    }
  }

  static JSONObject prepare(String base, byte[] bytes) {
    return (JSONObject)
        nativeCall(
            "prepare",
            object(
                "home",
                home(),
                "base",
                base,
                "content",
                java.util.Base64.getEncoder().encodeToString(bytes),
                "persist",
                readOverride(0),
                "session",
                readOverride(1)));
  }

  static String call(String method, String path, String body) {
    try {
      JSONObject response = new JSONObject(NativeBridge.request(method, path, body));
      String content = response.getString("body");
      if (response.getInt("status") >= 400) {
        JSONObject error = new JSONObject(content);
        throw new IllegalStateException(error.optString("message", content));
      }
      return content;
    } catch (Exception e) {
      throw failure(e);
    }
  }

  static String encoded(String value) {
    try {
      return java.net.URLEncoder.encode(value, "UTF-8").replace("+", "%20");
    } catch (Exception e) {
      throw failure(e);
    }
  }

  static String error(Exception error) {
    return object("error", error.getMessage() == null ? error.toString() : error.getMessage())
        .toString();
  }

  static String get(String path) {
    try {
      return call("GET", path, "");
    } catch (Exception e) {
      return error(e);
    }
  }

  public static String coreVersion() {
    return NativeBridge.coreVersion();
  }

  public static String capabilities() {
    return NativeBridge.capabilities();
  }

  /** Compatibility warnings only; this does not validate or load the core configuration. */
  public static String diagnoseConfig(byte[] content) throws Exception {
    return nativeCall(
            "diagnostics", object("content", java.util.Base64.getEncoder().encodeToString(content)))
        .toString();
  }

  public static void reset() {
    synchronized (LIFECYCLE) {
      NativeBridge.stop();
      NativeBridge.notifyDnsChanged(physicalDns);
      NativeBridge.startFromBytes(
          home(),
          home(),
          "mode: rule\ndns: {enable: true, nameserver: [system://]}\nrules: ['MATCH,DIRECT']\n"
              .getBytes(StandardCharsets.UTF_8),
          PLATFORM);
      profileMode = "rule";
      profileLogLevel = "info";
      subtitlePattern = "";
      lastUp = lastDown = lastSample = 0;
      rates = new Traffic();
    }
  }

  private interface Operation {
    void run() throws Exception;
  }

  private static void complete(Completion callback, Operation operation) {
    if (callback == null) throw new IllegalArgumentException("completion callback is required");
    WORK.execute(
        () -> {
          String error = "";
          try {
            operation.run();
          } catch (Exception e) {
            error = e.getMessage();
            if (error == null) error = e.toString();
          }
          callback.complete(error);
        });
  }

  public static void load(Completion callback, String path) throws Exception {
    complete(
        callback, () -> loadNow(path, Files.readAllBytes(new File(path, "config.yaml").toPath())));
  }

  public static void loadFromBytes(Completion callback, String path, byte[] content)
      throws Exception {
    byte[] owned = content.clone();
    complete(callback, () -> loadNow(path, owned));
  }

  private static void loadNow(String path, byte[] bytes) throws Exception {
    synchronized (LIFECYCLE) {
      JSONObject prepared = prepare(path, bytes);
      String yaml = prepared.getString("yaml");
      NativeBridge.loadFromBytes(home(), path, yaml.getBytes(StandardCharsets.UTF_8), PLATFORM);
      profileMode = prepared.getString("profileMode");
      profileLogLevel = prepared.getString("profileLogLevel");
      subtitlePattern = prepared.getString("subtitlePattern");
    }
  }

  public static void startTunContext(TunInterface callback) throws Exception {
    if (callback == null) throw new IllegalArgumentException("TUN callback is required");
    synchronized (LIFECYCLE) {
      tun = callback;
      NativeBridge.setPlatform(PLATFORM);
    }
  }

  public static void stopTunContext() {
    synchronized (LIFECYCLE) {
      NativeBridge.stopTun();
      tun = null;
      NativeBridge.setPlatform(PLATFORM);
    }
  }

  public static void startTun(
      int fd, String stack, String gateway, String portal, String dns, TunInterface callback)
      throws Exception {
    startTunWithCongestionController(fd, stack, gateway, portal, dns, "", callback);
  }

  public static void startTunWithCongestionController(
      int fd,
      String stack,
      String gateway,
      String portal,
      String dns,
      String controller,
      TunInterface callback)
      throws Exception {
    nativeCall("tunOptions", object("stack", stack, "controller", controller));
    synchronized (LIFECYCLE) {
      startTunContext(callback);
      NativeBridge.startTunWithDns(fd, dns);
    }
  }

  public static void stopTun() {
    NativeBridge.stopTun();
  }

  public static void notifyDnsChanged(String servers) {
    physicalDns = servers;
    NativeBridge.notifyDnsChanged(servers);
  }

  public static void notifyInstalledAppsChanged(String csv) {
    Map<Integer, String> next = new HashMap<>();
    for (String entry : csv.split(",")) {
      int colon = entry.indexOf(':');
      if (colon <= 0) continue;
      try {
        int uid = Integer.parseInt(entry.substring(0, colon));
        if (uid >= 0 && colon + 1 < entry.length()) next.put(uid, entry.substring(colon + 1));
      } catch (NumberFormatException ignored) {
      }
    }
    packages = Collections.unmodifiableMap(next);
  }

  public static String readOverride(int slot) {
    if (slot == 1) return sessionOverride;
    if (slot != 0) throw new IllegalArgumentException("invalid override slot");
    try {
      return new String(
          Files.readAllBytes(new File(home(), "override.json").toPath()), StandardCharsets.UTF_8);
    } catch (java.io.IOException e) {
      return "{}";
    }
  }

  public static void writeOverride(int slot, String content) {
    synchronized (LIFECYCLE) {
      try {
        JSONObject value = new JSONObject(content);
        JSONObject previous = new JSONObject(readOverride(slot));
        if (slot == 1) sessionOverride = content;
        else if (slot == 0)
          atomicWrite(new File(home(), "override.json"), content.getBytes(StandardCharsets.UTF_8));
        else throw new IllegalArgumentException("invalid override slot");
        JSONObject patch = new JSONObject();
        JSONObject persist = new JSONObject(readOverride(0)),
            session = new JSONObject(readOverride(1));
        for (String key : new String[] {"mode", "log-level"}) {
          if (!value.has(key) && !previous.has(key)) continue;
          Object selected = key.equals("mode") ? profileMode : profileLogLevel;
          if (persist.has(key) && !persist.isNull(key)) selected = persist.get(key);
          if (session.has(key) && !session.isNull(key)) selected = session.get(key);
          patch.put(key, selected);
        }
        if (patch.length() > 0 && NativeBridge.isRunning())
          call("PATCH", "/configs", patch.toString());
      } catch (Exception e) {
        throw failure(e);
      }
    }
  }

  public static void clearOverride(int slot) {
    writeOverride(slot, "{}");
  }

  static void atomicWrite(File file, byte[] bytes) throws Exception {
    Files.createDirectories(file.getParentFile().toPath());
    File scratch = File.createTempFile("meow-", ".tmp", file.getParentFile());
    try {
      Files.write(scratch.toPath(), bytes);
      Files.move(
          scratch.toPath(),
          file.toPath(),
          StandardCopyOption.REPLACE_EXISTING,
          StandardCopyOption.ATOMIC_MOVE);
    } finally {
      Files.deleteIfExists(scratch.toPath());
    }
  }

  public static String queryTunnelState() {
    try {
      return object("mode", new JSONObject(call("GET", "/configs", "")).getString("mode"))
          .toString();
    } catch (Exception e) {
      return error(e);
    }
  }

  public static String queryProxies() {
    return get("/proxies");
  }

  public static String queryConnections() {
    return get("/connections");
  }

  public static int queryConnectionCount() {
    try {
      return new JSONObject(queryConnections()).getJSONArray("connections").length();
    } catch (Exception e) {
      return 0;
    }
  }

  public static void closeAllConnections() {
    call("DELETE", "/connections", "");
  }

  public static boolean closeConnection(String id) {
    try {
      JSONArray connections = new JSONObject(queryConnections()).getJSONArray("connections");
      for (int i = 0; i < connections.length(); i++)
        if (id.equals(connections.getJSONObject(i).getString("id"))) {
          call("DELETE", "/connections/" + encoded(id), "");
          return true;
        }
    } catch (Exception ignored) {
    }
    return false;
  }

  public static boolean patchSelector(String selector, String name) {
    try {
      call("PUT", "/proxies/" + encoded(selector), object("name", name).toString());
      return true;
    } catch (Exception e) {
      return false;
    }
  }

  private static String delay(String path, String url, int timeout, String status) {
    return get(
        path + "?url=" + encoded(url) + "&timeout=" + timeout + "&expected=" + encoded(status));
  }

  public static String queryProxyDelay(String name, String url, int timeout, String status) {
    return delay("/proxies/" + encoded(name) + "/delay", url, timeout, status);
  }

  public static String queryGroupDelay(String name, String url, int timeout, String status) {
    return delay("/group/" + encoded(name) + "/delay", url, timeout, status);
  }

  public static String queryProviderProxyDelay(
      String provider, String name, String url, int timeout, String status) {
    return delay(
        "/providers/proxies/" + encoded(provider) + "/" + encoded(name) + "/healthcheck",
        url,
        timeout,
        status);
  }

  private static String providerPath(String kind) {
    if (kind.equals("Proxy")) return "/providers/proxies";
    if (kind.equals("Rule")) return "/providers/rules";
    throw new IllegalArgumentException("invalid provider type");
  }

  private static JSONObject provider(JSONObject value, String name, String kind) throws Exception {
    value.put("name", name);
    value.put("type", kind);
    Object stamp = value.opt("updatedAt");
    value.put(
        "updatedAt",
        stamp instanceof Number ? stamp : timestamp(stamp instanceof String ? (String) stamp : ""));
    if (!value.has("vehicleType")) value.put("vehicleType", "HTTP");
    JSONArray proxies = value.optJSONArray("proxies");
    if (proxies != null) {
      proxies =
          (JSONArray)
              nativeCall("formatProxies", object("pattern", subtitlePattern, "proxies", proxies));
      value.put("proxies", proxies);
      for (int i = 0; i < proxies.length(); i++) {
        JSONObject p = proxies.getJSONObject(i);
        p.put("isGroup", p.has("all"));
        JSONArray history = p.optJSONArray("history");
        p.put(
            "delay",
            history == null || history.length() == 0
                ? 0
                : history.getJSONObject(history.length() - 1).optInt("delay"));
      }
    }
    if (!value.has("testUrl")) value.put("testUrl", value.optString("healthCheckUrl"));
    return value;
  }

  public static String queryProviders() {
    try {
      JSONArray result = new JSONArray();
      for (String kind : new String[] {"Proxy", "Rule"}) {
        JSONObject map =
            new JSONObject(call("GET", providerPath(kind), "")).getJSONObject("providers");
        Iterator<String> keys = map.keys();
        while (keys.hasNext()) {
          String name = keys.next();
          JSONObject p = provider(map.getJSONObject(name), name, kind);
          if (!p.optString("vehicleType").equals("Compatible"))
            result.put(
                object(
                    "name",
                    name,
                    "type",
                    kind,
                    "vehicleType",
                    p.getString("vehicleType"),
                    "updatedAt",
                    p.getLong("updatedAt")));
        }
      }
      return result.toString();
    } catch (Exception e) {
      throw failure(e);
    }
  }

  public static String queryProvider(String kind, String name) {
    try {
      return provider(
              new JSONObject(call("GET", providerPath(kind) + "/" + encoded(name), "")), name, kind)
          .toString();
    } catch (Exception e) {
      return error(e);
    }
  }

  public static void updateProvider(Completion callback, String kind, String name)
      throws Exception {
    complete(callback, () -> call("PUT", providerPath(kind) + "/" + encoded(name), ""));
  }

  public static String queryAutoSwitch() {
    return NativeBridge.queryAutoSwitch();
  }

  public static void patchAutoSwitch(String settings) throws Exception {
    NativeBridge.patchAutoSwitch(settings);
  }

  public static Traffic queryTrafficTotal() {
    try {
      JSONObject value = new JSONObject(NativeBridge.traffic());
      return new Traffic(value.getLong("uploadTotal"), value.getLong("downloadTotal"));
    } catch (Exception e) {
      return new Traffic();
    }
  }

  public static Traffic queryTrafficNow() {
    Traffic now = rates;
    return new Traffic(now.getUpload(), now.getDownload());
  }

  /** Resident process bytes; Rust has no Go managed-heap counter. */
  public static long queryMemory() {
    return ((Number) nativeCall("memory", object())).longValue();
  }

  static long timestamp(String time) {
    try {
      return Math.max(0, Instant.parse(time).toEpochMilli());
    } catch (Exception e) {
      return 0;
    }
  }

  private static void sample() {
    try {
      Traffic total = queryTrafficTotal();
      long now = System.nanoTime();
      synchronized (LIFECYCLE) {
        if (lastSample != 0) {
          double seconds = (now - lastSample) / 1e9;
          rates =
              new Traffic(
                  (long) (Math.max(0, total.getUpload() - lastUp) / seconds),
                  (long) (Math.max(0, total.getDownload() - lastDown) / seconds));
        }
        lastUp = total.getUpload();
        lastDown = total.getDownload();
        lastSample = now;
      }
      JSONArray logs = new JSONArray(NativeBridge.readLogs());
      for (int i = 0; i < logs.length(); i++) {
        JSONObject log = logs.getJSONObject(i);
        String level = log.getString("type");
        if (level.equals("warn")) level = "warning";
        String message =
            object(
                    "level",
                    level,
                    "message",
                    log.getString("payload"),
                    "time",
                    timestamp(log.optString("time")))
                .toString();
        for (LogSubscription subscription : LOGS) subscription.deliver(message);
      }
    } catch (Exception ignored) {
      /* A reset can replace the session between samples. */
    }
  }

  public static LogSubscription subscribeLogcat(LogcatInterface callback) throws Exception {
    if (callback == null) throw new IllegalArgumentException("log callback is required");
    LogSubscription subscription = new LogSubscription(callback);
    LOGS.add(subscription);
    return subscription;
  }

  static void removeLog(LogSubscription subscription) {
    LOGS.remove(subscription);
  }

  public static boolean supportsSubscriptionHwid() {
    return true;
  }

  public static void setAgeSecretKey(String key) {
    nativeCall("setKeys", object("keys", key));
  }

  public static boolean veritySecretKeys(String keys) {
    return (Boolean) nativeCall("validKeys", object("keys", keys));
  }

  public static String decryptAge(String content, String keys) throws Exception {
    return (String) nativeCall("decrypt", object("content", content, "keys", keys));
  }

  public static void fetchAndValid(
      FetchCallback callback, long taskID, String path, String url, String optionsJSON)
      throws Exception {
    Subscription.fetch(callback, taskID, path, url, optionsJSON);
  }

  public static void cancelFetch(long taskID) {
    Subscription.cancel(taskID);
  }
}
