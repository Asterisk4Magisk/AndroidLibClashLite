# Android integration patches

`../upstream.json` pins the source revision. Run `python scripts/prepare_rust.py`
from the repository root before invoking Cargo directly. The AAR build does this
automatically. `--source PATH` accepts an existing upstream Git checkout for
offline preparation. Generated sources live in `rust/.upstream/`, outside Cargo's
shared dependency cache; do not edit them as project source.

- `android-tproxy.patch`: enables the Android listener path, obtains the original
  TCP destination from the accepted transparent socket, extends UDP address and
  ancillary handling to IPv6, and maps Android `tproxy-port` to an externally
  managed TCP+UDP listener. Relay, sniffing, flow control and UDP sessions remain
  upstream implementations. The same Android integration patch adds a `dns`
  outbound backed by the live resolver, ROOT UID/package lookup, externally
  managed named-listener firewall defaults, and subscription redirect/HWID
  handling through the existing HTTP transport.
- `android-system-dns.patch`: adds a dynamic `system` nameserver transport, shares
  physical-network snapshots with bootstrap/ECH DNS, invalidates DNS caches and
  pooled connections after updates, and selects the proper UDP socket family.
  DNS wire encoding, validation, TCP truncation fallback and routing stay upstream.

Preparation checks every patch against the pinned sources before applying it.
When updating the pin, review and regenerate these patches, then run the Android
network tests; a clean compilation alone does not verify TPROXY behavior.
