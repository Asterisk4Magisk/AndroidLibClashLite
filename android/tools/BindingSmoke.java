// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package libclash;

import android.content.Context;
import android.content.ContextWrapper;
import java.nio.charset.StandardCharsets;
import org.json.JSONArray;
import org.json.JSONObject;

/** The exact same client compiled and run against either AAR. */
public final class BindingSmoke {
  public static void main(String[] args) throws Exception {
    AndroidPlatform.initialize(
        new ContextWrapper(null) {
          @Override
          public Context getApplicationContext() {
            return this;
          }
        });
    JSONObject capabilities = new JSONObject(Libclash.capabilities());
    if (capabilities.getInt("schemaVersion") != 1 || !capabilities.getBoolean("configDiagnostics"))
      throw new AssertionError("capabilities schema");
    if (!new JSONArray(
            Libclash.diagnoseConfig("rules: ['MATCH,DIRECT']\n".getBytes(StandardCharsets.UTF_8)))
        .toString()
        .equals("[]")) throw new AssertionError("valid common config");
    try {
      Libclash.diagnoseConfig("dns: [".getBytes(StandardCharsets.UTF_8));
      throw new AssertionError("broken YAML must fail");
    } catch (Exception expected) {
    }
    Libclash.init(
        args[0],
        "binding-smoke",
        36,
        uri -> {
          throw new java.io.IOException("unused");
        });
    Libclash.reset();
    int port;
    try (java.net.ServerSocket free = new java.net.ServerSocket(0)) {
      port = free.getLocalPort();
    }
    Libclash.writeOverride(
        1,
        new JSONObject()
            .put("external-controller", "127.0.0.1:" + port)
            .put("secret", "binding-test")
            .toString());
    java.util.concurrent.CountDownLatch loaded = new java.util.concurrent.CountDownLatch(1);
    java.util.concurrent.atomic.AtomicReference<String> failure =
        new java.util.concurrent.atomic.AtomicReference<>();
    Libclash.loadFromBytes(
        error -> {
          failure.set(error);
          loaded.countDown();
        },
        args[0],
        "rules: ['MATCH,DIRECT']\n".getBytes(StandardCharsets.UTF_8));
    if (!loaded.await(30, java.util.concurrent.TimeUnit.SECONDS) || !"".equals(failure.get()))
      throw new AssertionError("load: " + failure.get());
    for (boolean authenticated : new boolean[] {false, true}) {
      java.net.HttpURLConnection request =
          (java.net.HttpURLConnection)
              new java.net.URL("http://127.0.0.1:" + port + "/asterisk/capabilities")
                  .openConnection();
      request.setConnectTimeout(5000);
      request.setReadTimeout(5000);
      if (authenticated) request.setRequestProperty("Authorization", "Bearer binding-test");
      try {
        if (request.getResponseCode() != (authenticated ? 200 : 401))
          throw new AssertionError("capability authentication");
        if (authenticated) {
          java.io.ByteArrayOutputStream body = new java.io.ByteArrayOutputStream();
          try (java.io.InputStream input = request.getInputStream()) {
            byte[] buffer = new byte[4096];
            for (int n; (n = input.read(buffer)) != -1; ) body.write(buffer, 0, n);
          }
          if (!new JSONObject(body.toString("UTF-8"))
              .getString("core")
              .equals(capabilities.getString("core")))
            throw new AssertionError("HTTP capability core");
        }
      } finally {
        request.disconnect();
      }
    }
    System.out.println(
        "BINDING_SMOKE_OK " + capabilities.getString("core") + " " + Libclash.coreVersion());
    System.exit(0);
  }
}
