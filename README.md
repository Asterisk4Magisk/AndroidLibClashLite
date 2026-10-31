# AndroidLibClashLite

Android library bindings for Mihomo (Go/gomobile) and meow (Rust/JNI).
Each variant provides a VPN JNI library and a standalone CLI for ROOT use.
Both expose the `libclash.Libclash` Java API; select one AAR per application.

| Core | AAR | Documentation |
| --- | --- | --- |
| Mihomo / Go | `libclash.aar` | [Go build and integration](go/README.md) |
| meow / Rust | `libclash-rs.aar` | [Rust build and integration](rust/README.md) |

Each AAR has a matching `-sources.jar`. Build requirements, native library names,
API contracts, configuration behavior and tests are documented with each core.

## Project layout

```text
go/                 Mihomo implementation, Java bindings and source overlays
rust/               meow implementation, Java bindings and Android patches
android/            Shared Android integration
  libclash/         Shared Java interface
  systemdns/        System DNS helper
  tools/            Android integration tests
scripts/            Build, source preparation and upstream update entry points
.github/workflows/  Core builds and unified release automation
```

Build scripts run from the repository root. Go module commands run in `go/`;
Cargo commands run in `rust/`.

## Builds and releases

- `main.yml` calls `go.yml` and `rust.yml` in parallel on relevant pushes, pull
  requests or manual runs. A manual run with `release_tag` waits for both builds
  and publishes both AARs and their sources JARs in one Release. Without a tag,
  it only produces build artifacts.
- `go.yml` and `rust.yml` are reusable workflows that build all four ABIs and
  upload artifacts. Publishing belongs to `main.yml`.
- `tidy.yml` checks both upstreams daily at 00:00 UTC (08:00 UTC+8), or manually.
  It selects stable releases, applies and validates updates, then creates one
  commit/tag and dispatches `main.yml` at that tag. It excludes prereleases and
  never downgrades a core.

Release tags follow the pinned Mihomo version. A meow-only update increments
`-android.N` (for example, `v1.19.33-android.1`); the base tag is used if that
Mihomo version has no tags yet. A Mihomo update uses its new version tag.
Both cores updating together produce one release.

Automatic updates create the commit/tag before the AAR builds. If a build or
publication fails, rerun `main.yml` with the same tag as both its ref and
`release_tag`. The daily updater also retries unpublished tags when the fixed
versions and default-branch commit still match. Published releases are skipped;
interrupted draft releases can resume without changing the tag.

To inspect or apply an upstream update locally (Python 3.12+):

```sh
python scripts/check_upstream.py
python scripts/check_upstream.py --apply
```

After applying a meow update, complete the [Rust validation steps](rust/README.md#upstream-updates).

## License

Original contributions are licensed under [LGPL-3.0](LICENSE).
Upstream and third-party code retain their respective licenses.
