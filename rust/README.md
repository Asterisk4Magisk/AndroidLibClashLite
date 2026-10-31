# meow / Rust

[Project overview](../README.md) · [Mihomo / Go](../go/README.md)

The meow revision is pinned in [upstream.json](upstream.json), dependencies in
[Cargo.lock](Cargo.lock), and the toolchain in [rust-toolchain.toml](rust-toolchain.toml).
This directory contains the JNI/CLI adapters, native launcher and
[Android patches](patches/README.md). Java builds use `android/libclash` and
`rust/libclash`, with the public package `libclash`.

Unless a command explicitly changes directory, run it from the repository root.

## Build

Requirements: Python 3.12+, Git, JDK 21+, Rust/rustup, CMake 3.x, Ninja, Android
SDK platform 37.0, Build Tools 37.0.0 and NDK 28.2.13676358.
Set `ANDROID_HOME`, `JAVA_HOME` and `ANDROID_NDK_HOME`; put Cargo, CMake and
Ninja on PATH. Windows also needs a host Rust linker/toolchain (MSVC or MinGW).
Install a host libclang shared library for bindgen (for example, `libclang-dev`
on Ubuntu). On Windows, set `LIBCLANG_PATH` to the directory containing
`libclang.dll`; the NDK's `clang.exe` alone is not sufficient.

```sh
cd rust
rustup target add armv7-linux-androideabi aarch64-linux-android i686-linux-android x86_64-linux-android
cd ..
python scripts/build_rust.py
```

Outputs: `libclash-rs.aar` and `libclash-rs-sources.jar`. Defaults are all four
ABIs, API 26, release optimization and 16 KB ELF alignment. `--arch amd64`,
`--profile debug`, `--check`, `--work-dir` and `--output` are available. Set
`SOURCE_DATE_EPOCH` for an explicit archive timestamp. The build verifies the
ELF alignment, required exports and native runtime dependencies before packaging.

The build materializes the pinned sources in ignored `rust/.upstream/` and
applies the checked patches from `rust/patches/`. Before running Cargo directly,
run `python scripts/prepare_rust.py`. Its `--source <upstream-checkout>` option
supports offline preparation. Do not edit Cargo's shared dependency cache.

| Native file per ABI | Role |
| --- | --- |
| `librsjni.so` | meow core and JNI bindings |
| `libmeow.so` | Standalone launcher that loads the sibling `librsjni.so` |

## Standalone CLI

The executable loads its sibling library. `libmeow.so` exports no Java API;
it calls `AndroidMeowCLI_v1` in `librsjni.so`. The CLI entry is for standalone
processes only. JNI and ROOT are separate processes with separate runtime state.

```sh
/absolute/native/library/dir/libmeow.so -v
/absolute/native/library/dir/libmeow.so -d /absolute/home -f config.yaml -t
/absolute/native/library/dir/libmeow.so -d /absolute/home -f config.yaml
```

## Android API

```kotlin
implementation(files("libs/libclash-rs.aar"))
```

Call `libclash.AndroidPlatform.initialize(application)` before
`Libclash.init(home, appVersion, sdkVersion, contentResolver)`.

Both AARs expose the same `libclash.Libclash` entry point and callback types.
Select one core AAR at build time; they must not be packaged together.
The Rust JNI implementation is package-private inside `libclash`; there is no
second public Java API. No gomobile, Kotlin, coroutines or serialization
library dependency is required.

Engine JNI operations are blocking and serialized; use worker threads and do
not call engine operations from platform callbacks. Subscription downloads and
isolated validation do not hold the engine operation lock. Validation executes
`libmeow.so -t` in a separate process without stopping the running core or
starting the ROOT system-DNS observer.

The facade dispatches finite Clash API requests in-process; no loopback
controller is required. Explicit `external-controller` overrides can still
serve the upstream API. Resource loading, providers, probes and routing reuse
meow implementations.

## Compatibility facade

The Rust AAR preserves META's existing `Completion`, `FetchCallback`,
`ContentResolver`, `TunInterface`, `LogcatInterface`, `LogSubscription` and
64-bit `Traffic` method signatures. Replace the Go-specific `Seq.setContext`
call with `AndroidPlatform.initialize` once; the same code works with both AARs.
Keep `android:extractNativeLibs="true"` (or Gradle legacy JNI packaging), because
isolated validation executes the sibling `libmeow.so`.

- `init`, `load`, `loadFromBytes`, `reset` and persist/session override slots
  retain the existing contract. In-memory loads preserve `config.yaml`.
  Loads rebuild startup-only listeners while retaining the TUN descriptor;
  failed loads restore the previous configuration. Active connections are
  closed by a full load. Mode/log-level override writes also PATCH the live API.
- Call `startTunContext` before establishing a VPN or loading a profile that
  can open sockets under that VPN. Protection is installed first, and existing
  transport/DNS pools are discarded. `startTunWithCongestionController` keeps
  META's signature: empty/`system`/`lwip` selects lwIP, empty/default `cubic`
  keeps its built-in TCP behavior. This does not provide Linux's system stack
  or selectable congestion algorithms. Other stack/controller choices are
  accepted with a warning and keep the same lwIP implementation and behavior.
- The DNS argument is an IP CSV. Empty disables hijacking; `0.0.0.0` selects all
  port-53 targets; explicit addresses select only those targets. Both TCP and
  UDP, IPv4 and IPv6 are supported. Disabled/unselected DNS follows routing.
  Profiles without enabled DNS receive the same Android defaults as the Go
  binding, including the `28.0.0.0/8` FakeIP range and default exclusion list.
- UID and package snapshots feed UID/PROCESS-NAME rules before dispatch.
  Standalone ROOT uses `/proc/net` and `/data/system/packages.list`; ordinary
  JNI VPN sessions use Android callbacks and never start the ROOT DNS helper.
- `fetchAndValid` handles HTTP(S), authenticated SOCKS5 download proxies, local
  files and owned `content://` descriptors. It reports existing status JSON,
  subscription usage/expiry/update interval/content-disposition, prefetches
  provider files, and preserves provider usage sidecars. Cancellation interrupts
  HTTP/content reads and the validator child, completing the task once.
  HWID is sent only on the primary subscription request, removed permanently
  on cross-origin redirects, and rejected on HTTPS downgrade. Denial headers
  yield `HWID_LIMIT_REACHED` or `HWID_NOT_SUPPORTED` without reading the body;
  malformed identities yield `HWID_INVALID`.
- `setAgeSecretKey`, `decryptAge` and `veritySecretKeys` support multiline X25519
  identity files with comments. CLI also reads `CLASH_AGE_SECRET_KEY`.
- Logs use `{level,message,time}` with millisecond timestamps. Traffic exposes
  sampled bytes/second and cumulative counters. Provider timestamps/DTOs match
  META; connection queries reuse the core API. `closeAllConnections` and
  `DELETE /connections` close tracked TCP and flush UDP NAT/listener sessions.
  UDP remains absent from the connection list. Memory is process
  RSS bytes, rather than Go's managed-heap metric.
  `clash-for-android.ui-subtitle-pattern` splits provider node titles/subtitles
  case-insensitively, excluding groups, using the existing fancy-regex engine.
  Invalid/unsupported patterns warn and leave names/types unchanged. This does
  not implement all .NET/regexp2 syntax. Failed loads preserve the active pattern.
- Library normalization applies persist then session overrides, maps
  `profile.store-fake-ip` and `geox-url`/geo update settings, uses existing
  compatible geodata files in the home directory, and resolves profile provider
  caches under `providers/` with the same URL MD5 filenames as Go. The embedded
  facade applies Android DNS defaults and `append-system-dns`, enables Fake-IP
  persistence, and disables profile-owned TUN/ROOT listeners like the Go library.

`android/tools/test_compat.py --serial DEVICE --aar libclash-rs.aar` runs the
Android facade smoke. Native tests cover packet-level TUN DNS, DNS-out reloads,
ROOT identity lookup, listener rollback and FD ownership; use the separate
`test_tproxy.sh` in a disposable network namespace for real TPROXY sockets.

## Capability boundary

The Rust binding provides an embedded VPN FD path (lwIP), mixed/HTTP/
SOCKS listeners, Clash control and a standalone CLI suitable for external SOCKS
helpers. It preserves the profile's DNS, Fake-IP and sniffer settings rather
than copying meow-android's app-specific overrides. It does not install ROOT
firewall rules or routing.

Both AARs expose `Libclash.capabilities()` and authenticated
`GET /asterisk/capabilities` with the same JSON schema (`schemaVersion: 1`).
The response describes the compiled binding, including `core`, `version`,
`tunStacks`, `selectableCongestionController`, `congestionControllers`,
`congestionControllerStacks`, `ageIdentities`, `rootTproxy`, `rootTun`,
`systemDns`, `listenerHotReload`, `connectionTracking`, `memoryMetric` and
`dnsOptions`. Capabilities describe implemented behavior, even when an unsupported
configuration option is tolerated. Unknown keys can be ignored by callers.

`Libclash.diagnoseConfig(byte[])` returns a JSON array of compatibility warnings
(`code`, `field`, `message`), without changing the live configuration. It decrypts
using the configured AGE identities. This is not full configuration validation;
the Go implementation returns `[]` for a parseable Go profile. Rust reports and
ignores known unsupported DNS options (`direct-nameserver`,
`direct-nameserver-follow-policy`, `respect-rules`, `prefer-h3`), geodata selection
options, `unified-delay`, `tcp-concurrent` and unsupported TUN tuning fields.
These options cannot block startup and do not change existing meow behavior.
Diagnostics omit option values, subscription URLs and credentials. Startup/load
also logs these warnings, so existing callers need no diagnostic integration.
Unsupported nodes/rules follow upstream's policy, including unavailable proxy
placeholders; `strict: true` enables upstream's stricter validation. Malformed YAML, failed
decryption, unavailable resources and port binding failures remain real errors.

For Rust ROOT `PUT /configs`, changes to named/shorthand listeners, controller,
secret, external UI, inbound authentication or sniffer settings return HTTP 409:
`{"code":"RESTART_REQUIRED","message":"...","fields":["listeners"]}`.
This happens before any config change, including with `force=true`; the running
configuration stays intact. Routing/DNS/provider changes keep the upstream hot
reload path. Restart the CLI for startup-only settings. JNI `load`/`loadFromBytes`
already perform the required full rebuild within the library. `PATCH /configs`
retains the upstream mode/log-level/TUN contract.

ROOT-owned TUN and selectable TUN stacks/congestion controllers remain unsupported.
AGE X25519 identities (armored or binary profiles), subscription HWID, and the
`type: dns` TCP/UDP outbound are supported. AGE hybrid/PQ identities are not yet
supported; `capabilities().ageIdentities` explicitly lists the accepted key types.
Startup, validation and reload reject enabled ROOT
TUN configurations; there are no placeholder methods for missing
features. Configurations requiring those capabilities must stay on the Go AAR.
GeoIP uses MMDB; GeoSite supports DAT and MRS. GeoIP DAT/METADB files
cannot be substituted for MMDB.

## ROOT TPROXY

On Android, `tproxy-port: 9898` binds IPv4 and IPv6 TCP/UDP transparent sockets.
The supervisor supplies TPROXY rules, policy routes and outbound exemptions;
the core does not change firewall rules. JNI sessions reject TPROXY and use
`startTun` for VPN traffic. Explicit listeners can select the address and timeout:

```yaml
listeners:
  - name: transparent
    type: tproxy
    listen: '::'
    port: 9898
    firewall: false
    udp: true
    udp-timeout: 300
```

`listen: '::'` creates separate IPv4/IPv6 sockets. Startup binds TCP and UDP
before reporting success; stop releases both. Linux/macOS upstream defaults
remain unchanged. Android TCP uses the original destination on the accepted
transparent socket; it requires TPROXY rules, not TCP REDIRECT rules.
UDP routing and session handling reuse meow. Existing META rules can route
port 53 to `{name: dns-out, type: dns}`; TCP and UDP queries use the tunnel's
live resolver, including Fake-IP and resolver changes after config reload.
For Android named TPROXY listeners, omitted `firewall` defaults to `false`;
explicit `true` is rejected because the supervisor owns rules.
The upstream UDP path excludes destinations whose port equals the listener port.

## System DNS

Use `system` or `system://` wherever meow accepts DNS upstreams, including
`nameserver`, `default-nameserver`, `proxy-server-nameserver` and
`nameserver-policy`. `direct-nameserver` is not implemented by pinned meow;
DIRECT continues to use its normal resolver.

For JNI, call `notifyDnsChanged` with the underlying physical network's complete
comma-separated `IP:port` list before startup and whenever it changes. Bracket
IPv6 addresses; scope IDs and interface names are accepted. An empty string
clears the list. `stop` clears it too, so publish it again before restarting.
DNS sockets use the installed protection callback. Never publish the VPN's own
DNS endpoint. No Java observer is launched by JNI, including in a root process.

For the ROOT CLI, the shared Java observer supplies these snapshots directly.
Network changes invalidate DNS caches and pooled DNS connections. An empty
snapshot fails system resolution without falling back to public DNS servers.
Helper failure stops the CLI with status 70; CLI exit also stops its helper.

## Auto-switch

`asterisk-auto-switch` is implemented for both embedded JNI and standalone CLI.
It uses the [same settings and state schema](../go/README.md#auto-switch), including preferred
tiers, consecutive failures, 1/2/4/8-round scan backoff, expected-delay early
acceptance, manual-selection precedence and three-success restoration. It reuses
meow's probes, live provider members, Selector API and selection persistence.

Use `Libclash.queryAutoSwitch()` / `patchAutoSwitch(settingsJSON)`, or the
authenticated `GET/PATCH /asterisk/auto-switch` routes. Control overrides survive
`PUT /configs` reloads and are cleared by `stop` followed by a new session.
Reloads preserve pending restores and restart failure counting. Explicit
`POST /api/config/save` preserves the YAML extension and saves the configured
value, rather than persisting the temporary control override.

The Rust preferred filter uses `fancy-regex`, including lookahead/lookbehind,
with bounded backtracking; it is not the full .NET/regexp2 engine. Invalid API
patterns return 400. Status ranges accept Mihomo's slash/comma separators and
`*`; an empty range accepts any status, matching the Go binding.

The `inUse` optimization uses meow's tracked TCP connections and upstream's
second-resolution start timestamps. UDP-only activity
still uses a health probe because meow exposes no per-flow UDP receive history.
Switches close affected TCP connections and UDP NAT sessions; a load-balance
ancestor's UDP sessions are refreshed together because their exact member chains
are not exposed by meow.

## Tests

Linux host tests cover lifecycle, DNS, control, SOCKS relay, TUN FD ownership
and repeated netstack teardown:

```sh
python scripts/prepare_rust.py
cd rust
cargo test --locked
```

From the repository root, run Java facade, subscription, SOCKS5 auth, provider
prefetch, cancellation and isolated validation tests on an x86_64 Android
device/emulator (no root required):

```sh
python android/tools/test_compat.py --serial DEVICE --aar libclash-rs.aar
```

Set `--abi` when testing a different device architecture.
Use `--bindings-only` to run the shared initializer/capabilities/diagnostics
client against this AAR. See the [Go tests](../go/README.md#tests) for Mihomo.

Use a rootable AVD and the helper DEX retained by `--work-dir` to test the real
ROOT DNS observer, network loss/recovery and process lifecycle:

```sh
python android/tools/test_root_system_dns_core.py --core meow --serial AVD --aar libclash-rs.aar --dex WORK_DIR/system-dns-dex/classes.dex
```

Build the Rust test executable for Android and run `rust/tools/test_tproxy.sh`
through `unshare -n` on a rootable AVD to test actual dual-stack TCP/UDP forwarding
and repeated shutdown. Its routes and rules exist only in that network namespace.
These tests do not establish compatibility with a particular handset's ROOT policy.

## Upstream updates

The shared updater resolves each stable meow tag to its commit, updates
`rust/upstream.json`, applies the existing Android patches, and synchronizes the
crate version, MSRV and pinned Rust toolchain. Runtime version reporting and
build metadata read `upstream.json` directly.

After applying a meow update, refresh the lockfile and validate it:

```sh
cd rust
cargo check
cargo fmt --all -- --check
cargo test --locked
```

The update workflow runs these checks before committing. Patch or validation
failures stop the update without committing or dispatching a release; patches
are never auto-rewritten. Review upstream changes and verify CLI/API and JNI/VPN
lifecycle behavior when upgrading. CI checks do not replace Android device tests.
See the [project release workflow](../README.md#builds-and-releases).
