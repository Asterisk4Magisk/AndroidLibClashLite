# Android integration patches

`../upstream.json` pins the source revision. Run `python scripts/prepare_rust.py`
from the repository root before invoking Cargo directly. The AAR build does this
automatically. `--source PATH` accepts an existing upstream Git checkout for
offline preparation. Generated sources live in `rust/.upstream/`, outside Cargo's
shared dependency cache; do not edit them as project source.

Patch filenames use four-digit prefixes and are applied in filename order.
Keep this ordering when adding or renumbering patches.

- `0001-android-lwip-errno.patch`: selects LwIP's direct system errno include on
  Android, preventing an existing `errno` macro from expanding inside the
  indirect header name with newer NDK headers.
- `0002-android-system-dns.patch`: adds a dynamic `system` nameserver transport,
  shares physical-network snapshots with bootstrap/ECH DNS, and invalidates DNS
  caches and pooled connections after updates. The upstream DNS client selects
  the UDP socket family and handles DNS wire encoding, validation and fallback.
- `0003-android-tproxy.patch`: enables Android's use of the upstream transparent
  TCP listener, extends UDP address and ancillary handling to IPv6, and maps
  Android `tproxy-port` to an externally managed TCP+UDP listener. It adds ROOT
  UID/package lookup, externally managed named-listener firewall defaults,
  and the Android subscription redirect and HWID policies to the upstream HTTP
  client.
- `0004-global-proxy-order.patch`: preserves Mihomo's GLOBAL member order (DIRECT,
  REJECT, declared proxies, declared groups) independently of dependency build
  order. The primary outbound remains the default without moving it in the list;
  saved selections take precedence and removed selections fall back to the primary.
- `0005-inbound-process-authority.patch`: lets an inbound finish owner lookup with
  an unknown result or disable it by policy. Rule enrichment and the traffic
  ledger respect that result instead of scanning the original socket again.
- `0006-http-process-lookup.patch`: lets the Android embedder attribute plain HTTP
  and CONNECT connections using the accepted socket's original endpoints. The
  existing lookup policy and authoritative unknown results also apply here.
- `0007-proxy-ip-read-only.patch` lets exit-IP probes use the existing group
  selection logic without updating group usage, selection, or health state.
- `0008-dns-events.patch` observes completed DNS responses, preserves the
  source of the selected reply and carries flow UIDs into the upstream DNS
  outbound.
- `0009-dns-event-delivery.patch` queues event formatting and UID lookups
  separately from DNS replies. In-flight UID lookups use a bounded wait
  outside the formatting worker.
- `0010-dns-event-history.patch` retains the latest 1,000 events in memory
  during the core session and replays them before live events. It reuses
  parsed questions for simple address queries and publishes deferred UID
  results directly to the same history and live feed.

Preparation checks every patch against the pinned sources before applying it.
When updating the pin, review and regenerate these patches, then run the Android
network tests; a clean compilation alone does not verify TPROXY behavior.
