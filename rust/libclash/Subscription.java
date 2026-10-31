// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package libclash;

import android.os.ParcelFileDescriptor;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.JSONArray;
import org.json.JSONObject;

/** A task owns its HTTP cancellation token, content descriptor and validation child. */
final class Subscription {
  private Subscription() {}

  private static final ExecutorService WORK =
      Executors.newCachedThreadPool(r -> Libclash.daemon(r, "meow-fetch"));
  private static final ConcurrentHashMap<Long, Task> TASKS = new ConcurrentHashMap<>();

  static void fetch(FetchCallback callback, long id, String path, String url, String options)
      throws Exception {
    if (callback == null) throw new IllegalArgumentException("fetch callback is required");
    Task task = new Task(callback, id, new File(path), url, new JSONObject(options));
    if (!task.directory.isAbsolute())
      throw new IllegalArgumentException("profile path must be absolute");
    if (TASKS.putIfAbsent(id, task) != null)
      throw new IllegalArgumentException("duplicate fetch task ID");
    try {
      Libclash.nativeCall("beginFetch", Libclash.object("id", id));
      task.future = WORK.submit(task);
    } catch (Exception e) {
      TASKS.remove(id, task);
      throw e;
    }
  }

  static void cancel(long id) {
    Task task = TASKS.get(id);
    if (task != null) task.cancel();
  }

  private static final class Task implements Runnable {
    final FetchCallback callback;
    final long id;
    final File directory;
    final String url;
    final JSONObject options;
    final AtomicBoolean completed = new AtomicBoolean();
    volatile boolean cancelled;
    boolean started;
    volatile Future<?> future;
    volatile InputStream stream;
    volatile Process process;
    JSONObject downloadHeaders = new JSONObject();

    Task(FetchCallback callback, long id, File directory, String url, JSONObject options) {
      this.callback = callback;
      this.id = id;
      this.directory = directory;
      this.url = url;
      this.options = options;
    }

    synchronized void cancel() {
      if (completed.get()) return;
      cancelled = true;
      Libclash.nativeCall("cancelFetch", Libclash.object("id", id));
      closeStream();
      Process child = process;
      if (child != null) child.destroy();
      Future<?> worker = future;
      if (worker != null) worker.cancel(true);
      // A running worker completes only after releasing its resources. This also
      // prevents an old worker from using a newly registered task with the same ID.
      if (!started) finish("context canceled");
    }

    void check() throws Exception {
      if (cancelled || Thread.currentThread().isInterrupted())
        throw new InterruptedException("context canceled");
    }

    void report(JSONObject value) throws Exception {
      check();
      callback.report(value.toString());
    }

    void status(String action, int progress, int max, String... args) throws Exception {
      report(
          Libclash.object(
              "action", action, "args", new JSONArray(args), "progress", progress, "max", max));
    }

    synchronized void finish(String error) {
      if (!completed.compareAndSet(false, true)) return;
      TASKS.remove(id, this);
      Libclash.nativeCall("endFetch", Libclash.object("id", id));
      callback.complete(error);
    }

    public void run() {
      synchronized (this) {
        if (completed.get()) return;
        started = true;
      }
      String error = "";
      try {
        check();
        Files.createDirectories(directory.toPath());
        File config = new File(directory, "config.yaml");
        byte[] bytes;
        if (!options.optBoolean("force") && config.isFile())
          bytes = Files.readAllBytes(config.toPath());
        else {
          status(
              "FetchConfiguration",
              -1,
              -1,
              new URI(url).getHost() == null ? url : new URI(url).getHost());
          bytes = download(url, true);
        }
        check();
        if (new String(bytes, 0, Math.min(40, bytes.length), StandardCharsets.US_ASCII)
            .startsWith("-----BEGIN AGE")) status("Decrypting", -1, -1);
        status("Verifying", -1, -1);
        JSONObject prepared = Libclash.prepare(directory.getAbsolutePath(), bytes);
        JSONArray providers = prepared.getJSONArray("providers");
        for (int i = 0; i < providers.length(); i++) {
          check();
          JSONObject provider = providers.getJSONObject(i);
          File file = new File(provider.getString("path"));
          String source = provider.getString("url");
          if (file.isFile() || source.isEmpty()) continue;
          status("FetchProviders", i, providers.length(), provider.getString("name"));
          try {
            byte[] content = download(source, false);
            synchronized (this) {
              check();
              Libclash.atomicWrite(file, content);
              if (provider.optString("kind").equals("proxies")
                  && downloadHeaders.has("subscription-userinfo"))
                Libclash.atomicWrite(
                    new File(file.getPath() + ".subscription-userinfo"),
                    downloadHeaders
                        .getString("subscription-userinfo")
                        .getBytes(StandardCharsets.UTF_8));
            }
          } catch (Exception e) {
            check();
            android.util.Log.w(
                "libclash-rs", "Provider prefetch failed: " + provider.getString("name"), e);
          }
        }
        check();
        validate(prepared.getString("yaml"));
        check();
        // Retain the original encrypted profile, matching Go's fetch contract.
        synchronized (this) {
          check();
          Libclash.atomicWrite(config, bytes);
        }
        status("Verifying", 65535, 65535);
      } catch (Exception e) {
        error = cancelled ? "context canceled" : e.getMessage();
        if (error == null) error = e.toString();
      } finally {
        closeStream();
        Process child = process;
        if (child != null) child.destroy();
        finish(error);
      }
    }

    byte[] download(String source, boolean primary) throws Exception {
      check();
      downloadHeaders = new JSONObject();
      URI uri = new URI(source);
      String scheme = uri.getScheme();
      if ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme)) {
        JSONObject request =
            Libclash.object("id", id, "url", source, "proxy", options.opt("proxy"));
        if (primary) {
          request.put("hwid", options.optString("hwid"));
          request.put("userAgent", options.optString("userAgent"));
        }
        JSONObject response = (JSONObject) Libclash.nativeCall("http", request);
        check();
        downloadHeaders = response.getJSONObject("headers");
        if (primary) reportHeaders(downloadHeaders);
        return java.util.Base64.getDecoder().decode(response.getString("body"));
      }
      InputStream input;
      if ("content".equalsIgnoreCase(scheme)) {
        ContentResolver resolver = Libclash.contentResolver;
        if (resolver == null) throw new IllegalStateException("content resolver is required");
        int fd = resolver.openContent(source);
        if (fd < 0)
          throw new IllegalStateException("content resolver returned an invalid descriptor");
        input = new ParcelFileDescriptor.AutoCloseInputStream(ParcelFileDescriptor.adoptFd(fd));
      } else if (scheme == null || "file".equalsIgnoreCase(scheme))
        input = Files.newInputStream((scheme == null ? new File(source) : new File(uri)).toPath());
      else throw new IllegalArgumentException("unsupported subscription scheme: " + scheme);
      stream = input;
      try {
        check();
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        byte[] buffer = new byte[16384];
        int count;
        while ((count = input.read(buffer)) != -1) {
          check();
          if (bytes.size() + count > 256 * 1024 * 1024)
            throw new IllegalStateException("subscription exceeds 256 MiB");
          bytes.write(buffer, 0, count);
        }
        return bytes.toByteArray();
      } finally {
        input.close();
        stream = null;
      }
    }

    void closeStream() {
      InputStream input = stream;
      if (input != null)
        try {
          input.close();
        } catch (Exception ignored) {
        }
    }

    void reportHeaders(JSONObject headers) throws Exception {
      JSONObject status =
          Libclash.object(
              "action", "SubscriptionInfo", "args", new JSONArray(), "progress", -1, "max", -1);
      String info = headers.optString("subscription-userinfo");
      for (String entry : info.split(";")) {
        String[] pair = entry.trim().split("=", 2);
        if (pair.length != 2) continue;
        try {
          long number = Long.parseLong(pair[1].trim());
          switch (pair[0].trim()) {
            case "upload":
              status.put("subUpload", number);
              break;
            case "download":
              status.put("subDownload", number);
              break;
            case "total":
              status.put("subTotal", number);
              break;
            case "expire":
              status.put("subExpire", Math.multiplyExact(number, 1000));
              break;
            default:
              break;
          }
        } catch (NumberFormatException | ArithmeticException ignored) {
        }
      }
      if (headers.has("profile-update-interval"))
        try {
          long hours = Long.parseLong(headers.getString("profile-update-interval").trim());
          status.put(
              "subUpdateInterval",
              hours <= 0 ? 0 : Math.max(900000, Math.multiplyExact(hours, 3600000)));
        } catch (NumberFormatException | ArithmeticException ignored) {
        }
      if (headers.has("content-disposition"))
        status.put("subContentDisposition", headers.getString("content-disposition"));
      if (status.length() > 4) report(status);
    }

    void validate(String yaml) throws Exception {
      File scratch = File.createTempFile("meow-validate-", ".yaml", directory);
      try {
        Files.write(scratch.toPath(), yaml.getBytes(StandardCharsets.UTF_8));
        check();
        String launcher = (String) Libclash.nativeCall("launcher", Libclash.object());
        Process child =
            new ProcessBuilder(
                    launcher,
                    "-t",
                    "-d",
                    Libclash.home(),
                    "-b",
                    directory.getAbsolutePath(),
                    "-f",
                    scratch.getAbsolutePath())
                .redirectErrorStream(true)
                .start();
        process = child;
        stream = child.getInputStream();
        check();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int count;
        while ((count = stream.read(buffer)) != -1) {
          check();
          output.write(buffer, 0, count);
        }
        if (child.waitFor() != 0)
          throw new IllegalStateException(
              new String(output.toByteArray(), StandardCharsets.UTF_8).trim());
      } finally {
        closeStream();
        stream = null;
        Process child = process;
        if (child != null) child.destroy();
        process = null;
        Files.deleteIfExists(scratch.toPath());
      }
    }
  }
}
