# AndroidLibClashLite

Go-first Android bindings for Mihomo, built with gomobile. ROOT CLI and VPN JNI
share one Go runtime and Core. The stable core version is pinned in `go.mod`.

## Build

Requirements: Go (version from `go.mod`), JDK 21+, Python 3.10+, Android SDK
platform 37 and NDK 28.2.13676358. Set `ANDROID_HOME`, `ANDROID_NDK_HOME` and
`JAVA_HOME`. No Gradle or separate Kotlin compiler is required.

```sh
python scripts/build_shared.py
```

Outputs: `libclash.aar` and `libclash-sources.jar`. The default build includes
armeabi-v7a, arm64-v8a, x86 and x86_64 at API 26 with 16 KB ELF alignment. Use
`--arch amd64` for one ABI, `--output <file.aar>` to select an output, or
`--work-dir <directory>` to retain generated sources and logs. On Windows,
temporary files use `C:\Temp`. Set `SOURCE_DATE_EPOCH` for a fixed build timestamp.
Builds do not require an application checkout or modify the Go module cache.

Each ABI contains only:

| File | Role |
| --- | --- |
| `libgojni.so` | Mihomo Core, gomobile JNI bindings and CLI entry point |
| `libmihomo.so` | Small executable that loads the sibling `libgojni.so` |

## Android API

```kotlin
implementation(files("libs/libclash.aar"))
```

The entry point is `libclash.Libclash`. Initialize `go.Seq.setContext(application)`
before calling `Libclash.init(home, appVersion, sdkVersion, contentResolver)`.
The AAR includes generated Java sources and JNI keep rules, with no Kotlin,
coroutines or serialization dependencies. Consumers provide their own models
and coroutine adapters. The old CMFA `Clash`/`Bridge` classes are not included.

- Go errors become Java exceptions. Asynchronous `Completion.complete` and
  `FetchCallback.complete` receive an empty string on success, otherwise an error.
  Callbacks run on worker threads; dispatch UI work as needed.
- Fetch task IDs must be unique while active. `cancelFetch` requests cancellation;
  completion still fires and must be awaited before reusing task resources.
- `startTun` borrows the caller's descriptor and retains a duplicate. Pass
  `ParcelFileDescriptor.fd`, then close the original after the call on both
  success and failure. `stopTun` closes the core's duplicate. Socket protection
  and UID callbacks must return promptly and must not call TUN stop methods.
- `ContentResolver.openContent` transfers an opened descriptor to the core;
  use `detachFd()` here. The core closes it after reading.
- `subscribeLogcat` returns an idempotent, closable subscription. Close it when
  the consumer stops, including when no logs are arriving.
- Traffic queries return separate 64-bit upload/download counters. Config,
  proxy, provider and connection queries retain JSON payloads. AGE decryption
  returns plaintext or throws an exception.

The exported surface covers META's current configuration, subscription, TUN,
logging, traffic, proxy/provider and AGE operations. Unused legacy notification,
HTTP-forwarder, health-check and key-generation entry points are omitted.

## Standalone CLI

Enable native extraction in the app (`packaging.jniLibs.useLegacyPackaging = true`).
Run the launcher directly from `applicationInfo.nativeLibraryDir`:

```sh
/absolute/native/library/dir/libmihomo.so -v
/absolute/native/library/dir/libmihomo.so -d /absolute/home -f /absolute/config.yaml
```

The app supplies geodata and provider files. No launcher copying is needed.
`ANDROID_MIHOMO_LIBRARY` optionally selects an absolute shared-library path:
relative paths return 64, load failures return 70 and missing CLI ABI v1 returns
71. Use launcher and library from the same release. `AndroidMihomoCLI_v1` is for
standalone processes only; upstream commands may exit the process.

Arguments, standard streams, exit codes, signals and Clash API behavior follow
upstream Mihomo. An internal `ANDROID_MIHOMO_CLI` marker selects CLI behavior
before package initialization; applications must not set it. The bootstrap
restores environment settings, including `XDG_CONFIG_HOME`, `SAFE_PATHS`,
`GOGC`, `GOMEMLIMIT` and `GOMAXPROCS`. JNI retains Android embedding and socket
protection callbacks. Checked source overlays adapt the pinned upstream module;
they fail when expected source patterns change.

## Stable tracking and releases

Workflows follow AndroidLibXrayLite's `main.yml` / `tidy.yml` split:

- `main.yml` (**Build**) builds all four ABIs on pushes and pull requests to
  `main`, or on manual runs. Without `release_tag`, it uploads build artifacts.
  With a tag, it creates that tag if needed and publishes the AAR and sources
  after a successful build. Use `v1.19.31-android.1` for a wrapper-only revision.
- `tidy.yml` (**Check and Update mihomo**) checks upstream daily at 00:00 UTC
  (08:00 China time), or manually. It operates on the default branch, selects
  the highest numeric published `vMAJOR.MINOR.PATCH`, and excludes drafts,
  prereleases and Alpha/RC tags. It never downgrades `go.mod`.

The update workflow commits changed `go.mod`/`go.sum`, creates the tag, then
explicitly dispatches `main.yml` **at that tag**. It uses `contents: write` and
`actions: write`; no personal access token is required. Tag pushes alone do not
trigger builds. A concurrent default-branch change aborts the update push.

Automatic updates create the commit/tag before building, as in XrayLite. A
failed build leaves them available for retry: rerun **Build** with the same tag
as both its ref and `release_tag`. The daily check also retries an unpublished
matching tag when the default branch still points to it. The first release is
handled even when `go.mod` already matches upstream. Existing tags must match
the build commit; interrupted draft releases can resume, and published assets
are not overwritten.

To inspect or apply an update locally:

```sh
python scripts/check_upstream.py
python scripts/check_upstream.py --apply
```

Review upstream changes and verify CLI/API and JNI/VPN lifecycle behavior when
updating. CI builds do not substitute for Android device regression testing.

## License

GPL-3.0. See `LICENSE` and `NOTICE` for source provenance and attribution.
