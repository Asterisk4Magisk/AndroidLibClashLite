// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

// Run via app_process with the AAR classes and extracted native libraries.
package libclash;

import android.os.ParcelFileDescriptor;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.json.*;

public final class CompatSmoke {
  static void check(boolean condition, String reason) {
    if (!condition) throw new AssertionError(reason);
  }

  static final byte[] PROFILE =
      "mode: rule\nlog-level: info\ndns: {enable: true, nameserver: [system://]}\nproxies: [{name: dns-out, type: dns}]\nrules: ['DST-PORT,53,dns-out', 'MATCH,DIRECT']\n"
          .getBytes(StandardCharsets.UTF_8);

  static final class Done implements Completion, FetchCallback {
    final CountDownLatch latch = new CountDownLatch(1);
    final AtomicInteger completions = new AtomicInteger();
    final List<JSONObject> status = new CopyOnWriteArrayList<>();
    String error;

    public void report(String value) {
      try {
        status.add(new JSONObject(value));
      } catch (Exception e) {
        throw new AssertionError(e);
      }
    }

    public void complete(String error) {
      this.error = error;
      completions.incrementAndGet();
      latch.countDown();
    }

    void await(boolean success) throws Exception {
      check(latch.await(45, TimeUnit.SECONDS), "callback timed out");
      check(completions.get() == 1, "callback exactly once");
      check(success == error.isEmpty(), "completion: " + error);
    }
  }

  interface Reply {
    String response(String request) throws Exception;
  }

  static final class Http implements AutoCloseable {
    final ServerSocket socket = new ServerSocket(0, 10, InetAddress.getByName("127.0.0.1"));
    final ExecutorService workers = Executors.newCachedThreadPool();
    final List<String> requests = new CopyOnWriteArrayList<>();
    volatile boolean closed;

    Http(Reply reply) throws Exception {
      workers.submit(
          () -> {
            while (!closed)
              try {
                Socket client = socket.accept();
                workers.submit(
                    () -> {
                      try (Socket owned = client) {
                        owned.setSoTimeout(10000);
                        BufferedReader reader =
                            new BufferedReader(
                                new InputStreamReader(
                                    owned.getInputStream(), StandardCharsets.UTF_8));
                        StringBuilder request = new StringBuilder();
                        String line;
                        while ((line = reader.readLine()) != null && !line.isEmpty())
                          request.append(line).append('\n');
                        requests.add(request.toString());
                        String response = reply.response(request.toString());
                        owned.getOutputStream().write(response.getBytes(StandardCharsets.UTF_8));
                      } catch (Exception e) {
                        if (!closed) e.printStackTrace();
                      }
                    });
              } catch (Exception e) {
                if (!closed) e.printStackTrace();
              }
          });
    }

    String url() {
      return "http://127.0.0.1:" + socket.getLocalPort() + "/profile";
    }

    public void close() throws Exception {
      closed = true;
      socket.close();
      workers.shutdownNow();
    }
  }

  static String response(String headers, String body) {
    return "HTTP/1.1 200 OK\r\nConnection: close\r\n"
        + headers
        + "Content-Length: "
        + body.getBytes(StandardCharsets.UTF_8).length
        + "\r\n\r\n"
        + body;
  }

  static Done fetch(long id, File path, String url, String options) throws Exception {
    Done done = new Done();
    Libclash.fetchAndValid(done, id, path.getAbsolutePath(), url, options);
    return done;
  }

  public static void main(String[] args) throws Exception {
    File home = new File(args[0]);
    Files.createDirectories(home.toPath());
    File content = new File(home, "input.yaml");
    Files.write(content.toPath(), PROFILE);
    Libclash.init(
        home.getAbsolutePath(),
        "smoke",
        36,
        uri -> ParcelFileDescriptor.open(content, ParcelFileDescriptor.MODE_READ_ONLY).detachFd());
    AtomicInteger protects = new AtomicInteger();
    Libclash.notifyDnsChanged("10.0.2.3:53");
    Libclash.notifyInstalledAppsChanged("10123:test.package");
    Libclash.startTunContext(
        new TunInterface() {
          public void markSocket(int fd) {
            protects.incrementAndGet();
          }

          public int querySocketUid(int protocol, String source, String target) {
            return 10123;
          }
        });
    Libclash.writeOverride(0, "{\"mode\":\"direct\"}");
    Libclash.writeOverride(1, "{\"mode\":\"global\"}");
    File profile = new File(home, "live");
    Files.createDirectories(profile.toPath());
    int mixed;
    try (ServerSocket free = new ServerSocket(0)) {
      mixed = free.getLocalPort();
    }
    byte[] bytes =
        (new String(PROFILE, StandardCharsets.UTF_8)
                + "mixed-port: "
                + mixed
                + "\n"
                + "bind-address: 127.0.0.1\n"
                + "geodata-mode: true\ngeodata-loader: memconservative\n"
                + "clash-for-android: {ui-subtitle-pattern: '(?<=local)-NODE'}\n"
                + "proxy-providers: {local: {type: file, path: nodes.yaml}}\n")
            .getBytes(StandardCharsets.UTF_8);
    Files.createDirectories(new File(profile, "providers").toPath());
    Files.write(
        new File(profile, "providers/nodes.yaml").toPath(),
        "proxies: [{name: local-node, type: socks5, server: 127.0.0.1, port: 9}]\n"
            .getBytes(StandardCharsets.UTF_8));
    Done load = new Done();
    Libclash.loadFromBytes(load, profile.getAbsolutePath(), bytes);
    load.await(true);
    check(
        new JSONArray(Libclash.diagnoseConfig(bytes)).length() == 2,
        "ignored geodata options reported");
    check(
        !new JSONObject(Libclash.capabilities()).getBoolean("listenerHotReload"),
        "capability boundary");
    check(
        new JSONObject(Libclash.queryTunnelState()).getString("mode").equals("global"),
        "override precedence");
    check(!new File(profile, "config.yaml").exists(), "loadFromBytes must preserve profile file");
    try (Socket client = new Socket("127.0.0.1", mixed)) {
      check(client.isConnected(), "listener created by load");
    }
    JSONArray providers = new JSONArray(Libclash.queryProviders());
    check(providers.length() == 1, "provider list");
    JSONObject provider = new JSONObject(Libclash.queryProvider("Proxy", "local"));
    check(provider.get("updatedAt") instanceof Number, "provider millisecond timestamp");
    check(provider.getJSONArray("proxies").getJSONObject(0).has("title"), "provider proxy DTO");
    check(
        provider.getJSONArray("proxies").getJSONObject(0).getString("title").equals("local"),
        "subtitle title");
    check(
        provider.getJSONArray("proxies").getJSONObject(0).getString("subtitle").equals("-node"),
        "subtitle match");
    Done badLoad = new Done();
    Libclash.loadFromBytes(
        badLoad, profile.getAbsolutePath(), "dns: [".getBytes(StandardCharsets.UTF_8));
    badLoad.await(false);
    check(
        new JSONObject(Libclash.queryProvider("Proxy", "local"))
            .getJSONArray("proxies")
            .getJSONObject(0)
            .getString("title")
            .equals("local"),
        "failed load keeps subtitle");
    ParcelFileDescriptor[] pair = ParcelFileDescriptor.createSocketPair();
    try {
      Libclash.startTunWithCongestionController(
          pair[0].getFd(),
          "mips",
          "",
          "",
          "",
          "bbr3",
          new TunInterface() {
            public void markSocket(int fd) {
              protects.incrementAndGet();
            }

            public int querySocketUid(int protocol, String source, String target) {
              return 10123;
            }
          });
      Libclash.stopTun();
    } finally {
      pair[0].close();
      pair[1].close();
    }
    Done update = new Done();
    Libclash.updateProvider(update, "Proxy", "local");
    update.await(true);
    Libclash.writeOverride(0, "{\"mode\":\"direct\"}");
    check(
        new JSONObject(Libclash.queryTunnelState()).getString("mode").equals("global"),
        "persist must not override session mode");
    Libclash.clearOverride(1);
    check(
        new JSONObject(Libclash.queryTunnelState()).getString("mode").equals("direct"),
        "clearing session restores persist mode");
    Libclash.clearOverride(0);
    check(
        new JSONObject(Libclash.queryTunnelState()).getString("mode").equals("rule"),
        "clearing overrides restores profile mode");
    NativeBridge.validate(home.getAbsolutePath(), profile.getAbsolutePath(), PROFILE);
    check(NativeBridge.isRunning(), "validation preserved running core");
    try (Socket client = new Socket("127.0.0.1", mixed)) {
      check(client.isConnected(), "validation preserved listener");
    }
    check(Libclash.queryMemory() > 0, "RSS memory");
    check(Libclash.queryTrafficTotal().getUpload() >= 0, "traffic DTO");
    check(Libclash.veritySecretKeys(""), "empty AGE key list");
    check(!Libclash.veritySecretKeys("bad"), "AGE key validation");
    check(Libclash.decryptAge("plain", "").equals("plain"), "plain AGE pass-through");
    check(new JSONObject(Libclash.queryAutoSwitch()).has("settings"), "auto-switch preserved");
    Done local = fetch(1, new File(home, "local"), content.toURI().toString(), "{}");
    local.await(true);
    Done uri = fetch(2, new File(home, "content"), "content://smoke/profile", "{}");
    uri.await(true);
    try (Http server =
        new Http(
            request ->
                response(
                    "subscription-userinfo: upload=10; download=20; total=30; expire=40\r\n"
                        + "profile-update-interval: 2\r\n"
                        + "content-disposition: attachment; filename=test.yaml\r\n",
                    new String(PROFILE, StandardCharsets.UTF_8)))) {
      Done fetch =
          fetch(
              3,
              new File(home, "http"),
              server.url(),
              "{\"hwid\":\"0123456789-test\",\"userAgent\":\"meta-smoke\"}");
      fetch.await(true);
      check(server.requests.get(0).contains("X-Hwid: 0123456789-test"), "HWID sent");
      JSONObject info =
          fetch.status.stream()
              .filter(v -> v.optString("action").equals("SubscriptionInfo"))
              .findFirst()
              .get();
      check(
          info.getLong("subExpire") == 40000 && info.getLong("subUpdateInterval") == 7200000,
          "subscription metadata units");
    }
    try (Http target =
            new Http(request -> response("", new String(PROFILE, StandardCharsets.UTF_8)));
        Http redirect =
            new Http(
                request ->
                    "HTTP/1.1 302 Found\r\nLocation: "
                        + target.url()
                        + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")) {
      Done fetch =
          fetch(
              4,
              new File(home, "redirect"),
              redirect.url().replace("http://", "http://user:pass@"),
              "{\"hwid\":\"0123456789-test\"}");
      fetch.await(true);
      check(
          !target.requests.get(0).toLowerCase().contains("x-hwid:")
              && !target.requests.get(0).toLowerCase().contains("authorization:"),
          "cross-origin credential stripping");
    }
    try (Http denied = new Http(request -> response("x-hwid-limit: true\r\n", "denied"))) {
      Done fetch = fetch(5, new File(home, "denied"), denied.url(), "{}");
      fetch.await(false);
      check(fetch.error.equals("HWID_LIMIT_REACHED"), "exact HWID error: " + fetch.error);
    }
    CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
    Done invalidHwid =
        fetch(
            9,
            new File(home, "invalid-hwid"),
            "http://subscription.invalid/profile",
            "{\"hwid\":\"bad hwid\"}");
    invalidHwid.await(false);
    check(invalidHwid.error.equals("HWID_INVALID"), "invalid HWID error: " + invalidHwid.error);
    try (Http slow =
        new Http(
            request -> {
              entered.countDown();
              release.await(15, TimeUnit.SECONDS);
              return response("", "late");
            })) {
      Done fetch = fetch(6, new File(home, "cancel"), slow.url(), "{}");
      check(entered.await(10, TimeUnit.SECONDS), "slow request started");
      Libclash.cancelFetch(6);
      fetch.await(false);
      check(fetch.error.equals("context canceled"), "cancel callback");
      release.countDown();
    }

    try (ServerSocket proxy = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
      CompletableFuture<Void> handshake =
          CompletableFuture.runAsync(
              () -> {
                try (Socket client = proxy.accept()) {
                  client.setSoTimeout(10000);
                  DataInputStream in = new DataInputStream(client.getInputStream());
                  OutputStream out = client.getOutputStream();
                  check(in.readUnsignedByte() == 5, "SOCKS version");
                  int count = in.readUnsignedByte();
                  byte[] methods = new byte[count];
                  in.readFully(methods);
                  out.write(new byte[] {5, 2});
                  check(in.readUnsignedByte() == 1, "SOCKS auth version");
                  byte[] user = new byte[in.readUnsignedByte()];
                  in.readFully(user);
                  byte[] pass = new byte[in.readUnsignedByte()];
                  in.readFully(pass);
                  check(
                      new String(user, StandardCharsets.UTF_8).equals("user")
                          && new String(pass, StandardCharsets.UTF_8).equals("pass"),
                      "SOCKS credentials");
                  out.write(new byte[] {1, 0});
                  check(in.readUnsignedByte() == 5 && in.readUnsignedByte() == 1, "SOCKS CONNECT");
                  in.readUnsignedByte();
                  int atyp = in.readUnsignedByte();
                  byte[] address = new byte[atyp == 3 ? in.readUnsignedByte() : atyp == 1 ? 4 : 16];
                  in.readFully(address);
                  in.readUnsignedShort();
                  out.write(new byte[] {5, 0, 0, 1, 127, 0, 0, 1, 0, 0});
                  BufferedReader reader =
                      new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
                  String line;
                  while ((line = reader.readLine()) != null && !line.isEmpty()) {}
                  out.write(
                      response("", new String(PROFILE, StandardCharsets.UTF_8))
                          .getBytes(StandardCharsets.UTF_8));
                } catch (Exception e) {
                  throw new RuntimeException(e);
                }
              });
      String options =
          new JSONObject()
              .put(
                  "proxy",
                  new JSONObject()
                      .put("host", "127.0.0.1")
                      .put("port", proxy.getLocalPort())
                      .put("username", "user")
                      .put("password", "pass"))
              .toString();
      fetch(7, new File(home, "socks"), "http://subscription.invalid/profile", options).await(true);
      handshake.get(10, TimeUnit.SECONDS);
    }
    final AtomicReference<String> providerURL = new AtomicReference<>();
    try (Http server =
        new Http(
            request -> {
              if (request.startsWith("GET /nodes ")) {
                check(!request.toLowerCase().contains("x-hwid:"), "provider HWID must be absent");
                return response(
                    "subscription-userinfo: upload=1; download=2; total=3\r\n",
                    "proxies: [{name: provider-node, type: socks5, server: 127.0.0.1, port: 9}]\n");
              }
              return response(
                  "",
                  new String(PROFILE, StandardCharsets.UTF_8)
                      + "proxy-providers: {remote: {type: http, url: '"
                      + providerURL.get()
                      + "', path: nodes.yaml}}\n");
            })) {
      providerURL.set(server.url().replace("/profile", "/nodes"));
      File fetched = new File(home, "prefetch");
      fetch(8, fetched, server.url(), "{\"hwid\":\"0123456789-test\"}").await(true);
      check(new File(fetched, "providers/nodes.yaml").isFile(), "provider prefetched");
      check(
          new File(fetched, "providers/nodes.yaml.subscription-userinfo").isFile(),
          "provider userinfo persisted");
    }
    CountDownLatch logged = new CountDownLatch(1);
    LogSubscription subscription =
        Libclash.subscribeLogcat(
            payload -> {
              try {
                JSONObject log = new JSONObject(payload);
                check(
                    log.has("level") && log.has("message") && log.get("time") instanceof Number,
                    "log DTO");
                logged.countDown();
                return false;
              } catch (Exception e) {
                throw new AssertionError(e);
              }
            });
    Libclash.writeOverride(1, "{\"mode\":\"direct\"}");
    check(logged.await(5, TimeUnit.SECONDS), "log subscription");
    subscription.close();
    check(protects.get() > 0, "subscription sockets use VPN protection");
    check(!new File(home, "system-dns-helper.dex").exists(), "JNI never starts ROOT helper");
    Libclash.stopTunContext();
    NativeBridge.stop();
    System.out.println("COMPAT_SMOKE_OK protects=" + protects.get());
  }
}
