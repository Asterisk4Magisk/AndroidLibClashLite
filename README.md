# AndroidLibClashLite

Go-first Android bindings for Mihomo, built with gomobile. ROOT CLI and VPN JNI
share one Go runtime and Core. The stable core version is pinned in `go.mod`.

## Build

Requirements: Go (version from `go.mod`), JDK 21+, Python 3.10+, Android SDK
platform 37.0, Build Tools 37.0.0 and NDK 28.2.13676358. Set `ANDROID_HOME`,
`ANDROID_NDK_HOME` and `JAVA_HOME`. No Gradle or separate Kotlin compiler is required.

```sh
python scripts/build_shared.py
```

Outputs: `libclash.aar` and `libclash-sources.jar`. The default build includes
armeabi-v7a, arm64-v8a, x86 and x86_64 at API 26 with 16 KB ELF alignment. Use
`--arch amd64` for one ABI, `--output <file.aar>` to select an output, or
`--work-dir <directory>` to retain generated sources and logs.
Set `SOURCE_DATE_EPOCH` for a fixed build timestamp.
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
  Cancellation of `content://` interrupts reads after descriptor acquisition;
  the synchronous resolver open itself cannot currently be interrupted.
- `supportsSubscriptionHwid()` identifies bindings with HWID support. The fetch
  options JSON accepts `hwid` (empty means omitted). Nonempty values must match
  `[a-zA-Z0-9=-]{10,64}` and apply only to the primary HTTP subscription, never
  automatically to providers. Same-origin redirects retain identity; crossing
  origins strips it for the rest of the chain. HTTPS downgrades are rejected.
  HWID refusal headers are checked before consuming the response body, including
  HTTP 200 denials. Completion errors use `HWID_INVALID`, `HWID_NOT_SUPPORTED`,
  or `HWID_LIMIT_REACHED`; clients should localize these stable codes. The library
  does not generate or persist device identifiers.
- The primary HTTP subscription reports a `SubscriptionInfo` status when it
  returns `subscription-userinfo`, `profile-update-interval` or
  `content-disposition`. `subContentDisposition` carries the raw
  `Content-Disposition` value; clients decode the filename (for example to name
  a new profile). Providers never report it, and older bindings omit the field.
- Group delay calls return partial successes, matching the Clash HTTP API;
  an error is returned when no member succeeds.
- `startTun` borrows the caller's descriptor and retains a duplicate. Pass
  `ParcelFileDescriptor.fd`, then close the original after the call on both
  success and failure. `stopTun` closes the core's duplicate. Socket protection
  and UID callbacks must return promptly and must not call TUN stop methods.
- `startTunWithCongestionController(fd, stack, gateway, portal, dns,
  congestionController, callback)` follows the same ownership and callback
  contract as `startTun`. The extra string accepts `cubic`, `reno`, `bbr`,
  `bbr3`, or an empty string for the core default. It only takes effect with
  `stack = "mips"`; other stacks ignore it. Invalid values throw an exception.
  The existing `startTun` entry point remains available and uses the core default.
- `ContentResolver.openContent` transfers an opened descriptor to the core;
  use `detachFd()` here. The core closes it after reading.
- `subscribeLogcat` returns an idempotent, closable subscription. Close it when
  the consumer stops, including when no logs are arriving.
- `notifyInstalledAppsChanged` replaces the complete `uid:package` CSV snapshot
  used by Android PROCESS-NAME rules. Send it after initialization and package
  changes. `notifyDnsChanged` replaces the underlying non-VPN network's DNS
  servers as comma-separated `IP:port` endpoints (bracket IPv6 addresses).
  Send an empty string when no underlying DNS servers remain; never feed the
  VPN's own DNS endpoint back into this API. Both notifications are thread-safe.
- Traffic queries return separate 64-bit upload/download counters. Config,
  proxy, provider and connection queries retain JSON payloads. AGE decryption
  returns plaintext or throws an exception.

- `queryAutoSwitch()` and `patchAutoSwitch(settingsJSON)` mirror the
  [auto-switch](#auto-switch) Clash API endpoint for the embedded runtime.

The exported surface covers META's current configuration, subscription, TUN,
logging, traffic, proxy/provider, Android platform notifications and AGE
operations. Unused HTTP-forwarder, health-check and key-generation entry points
are omitted.

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

## Auto-switch

The core can replace a failed node selected in a manual `select` group with a
healthy member of that group. It runs in the core for both JNI and CLI, so ROOT
operation needs no application process or Android service. Like `url-test` and
`fallback`, it changes only in-core selection: no ROOT, system or DNS resource
is touched. Configure it with the top-level key (upstream Mihomo ignores it):

```yaml
asterisk-auto-switch:
  enable: true
  groups: [Proxy]              # select groups only
  preferred-filter: "(?i)HK"   # regexp2, like a group filter; optional
  failure-threshold: 1         # 1-10 consecutive failures
  expected-delay: 0            # ms; stop a scan at the first delay below it, 0 tests all
  interval: 30                 # 10-3600 seconds between rounds
  url: https://www.gstatic.com/generate_204
  timeout: 5000                # 1000-30000 ms per test
  expected-status: ""
  concurrency: 5               # 1-32 candidate tests at once
```

Each round checks the selected node of every listed group. Only leaf nodes are
monitored; DIRECT/REJECT/PASS selections and nested groups are skipped. A
connection opened through that node and group since the previous check that has
received data counts as healthy without a probe (`inUse` in the group status),
so an actively used device sends no extra test traffic; otherwise the node is
probed with `url`. After
the threshold, healthy members matching `preferred-filter` are preferred,
otherwise any healthy member; the lowest delay wins within a tier. With a
nonzero `expected-delay`, the first member answering strictly below it wins
instead: members are probed fastest-last-result first, queued probes are
skipped and probes already in flight finish in the background. The selection
changes only if it is still the node that failed, so a manual choice made during
the scan wins. A switch updates the store-selected cache and closes connections
through the group. A scan that finds no healthy member is retried after 1, 2, 4
and then at most 8 failing rounds, so an offline device does not probe every node
each interval.

`GET /asterisk/auto-switch` (authenticated like other Clash API routes) returns
the active settings, their source (`config` or `control`), phase, next check
time, progress, per-group status and up to 100 newest-first events (`failed`,
`switched`, `no-replacement`, `selection-changed`). Events stay in memory only.
`PATCH /asterisk/auto-switch` with the same JSON settings applies immediately.
The value survives hot profile reloads (`PUT /configs` or JNI load) and lasts
until the process exits or JNI `reset()`; the YAML value applies again only in a
new session. Each apply restarts failure counting. Invalid filters, status
ranges, or an enabled value without groups return 400.

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

Original contributions in this repository are licensed under [LGPL-3.0](LICENSE). Upstream and third-party code retain their respective licenses.

## ROOT system DNS integration

A running standalone CLI with effective UID 0 starts its own Java network
observer; JNI and CLI tool commands (`-v`, `-h`, `-t`) do not. The observer uses
ConnectivityManager / LinkProperties to supply physical-network DNS addresses.
Mihomo performs the DNS exchanges for `system`, including `direct-nameserver`
and `nameserver-policy`. The app and asteriskd do not relay DNS snapshots.

The build compiles `native/systemdns/java` with javac and SDK D8, then embeds
the single dex in `libgojni.so`. At startup the core verifies and reuses
`<core-home>/system-dns-helper.dex`, or atomically replaces it from the embedded
bytes. The file is root-owned, mode 0400, and retained at exit with any ART
cache. No APK path or Gradle build is needed for the helper.

An anonymous socketpair carries version 1 address snapshots directly to the
core. Go's stdio/ExtraFiles mapping passes the child endpoint as fd 0 and fd 3;
no named DNS socket is created. Helper failure clears DNS and exits the core
with status 70. JNI continues to use `notifyDnsChanged` from its host app.

See [implementation and validation](docs/root-system-dns.md).
Build with `scripts/build_shared.py`; local AsteriskMETA builds can consume the
AAR via `-PandroidLibClashLiteAar=/path/libclash.aar`. Host tests:
`go test ./native/systemdns`.
