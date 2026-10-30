# Development

## Prerequisites

- macOS 13+ and Apple Command Line Tools or Xcode with the macOS SDK.
- Python 3.
- rustup, with the toolchain and components pinned in `rust-toolchain.toml`.
- Network access for initial Rust dependencies and the checksummed sing-box archive.

The scripts prefer rustup's Cargo under `$HOME/.cargo/bin` and set `MACOSX_DEPLOYMENT_TARGET=13.0`. The build targets the current architecture; it does not produce a universal binary. XcodeGen and Go are optional tools, not normal build requirements.

## Build

```sh
./scripts/build.sh
```

`build.sh` delegates to `build-preview.sh`, which builds the Rust library/controller, compiles the Swift app, packages the backend and verifies ad-hoc signatures. Output is `build/RouteBar.app`; the previous local build is kept at `build/RouteBar.previous.app`.

`package-backend.sh` downloads only the pinned sing-box archive from the upstream release, verifies the architecture-specific SHA-256, and caches it in `.tools/downloads/`. It does not need another checkout. Version changes must update the archive URL/checksums, controller version checks and compatibility tests together.

The generated Xcode project is available for source navigation. `project.yml` is its source; after project structure changes, run `xcodegen generate` with the minimum version declared there. The shell build is the verified certificate-free packaging path. Existing extension targets describe a separate legacy design.

## Tests

```sh
./scripts/test.sh
python3 scripts/test-whitelist-integration.py
```

`test.sh` runs Rust workspace tests, clippy with warnings denied, formatting checks and the Swift test executables. The whitelist integration script defaults to the controller and sing-box inside this repository's built app; use `--rust` and `--engine` to override those paths.

The integration fixture compiles the actual Swift importer/converter, validates six configurations with sing-box and checks 23 routing decisions. Test profiles are synthetic and generated in temporary directories. These tests do not change routes, install a launchd service or connect to a VPN.

### Optional reference comparison

If you have the separately built original Go `vpnctl` reference implementation:

```sh
python3 scripts/test-v2-parity.py --reference /path/to/vpnctl
```

The reference executable is not included or downloaded by this repository. This optional test compares 11 generated configurations and 12 routing decisions, then exercises three DNS address-family policies through a loopback-only sing-box listener. A normal clone can build and run the main test suite without it.

## Working with secrets

Keep real profiles outside source control. `.conf` files, `conf/`, local configuration, private-key/certificate files, `.env` files, logs, build output and dependency caches are ignored. Use synthetic keys and documentation IP ranges in tests. `.gitignore` does not remove a secret already committed or protect against `git add -f`.

Before a commit, inspect `git diff --cached --stat`, `git diff --cached` and `git diff --cached --check`. A source-only commit should not contain `.app` bundles, downloaded archives, `target/`, `.tools/` or real profile contents.

## Running and system acceptance

Opening the app requests administrator authorization. Stop other VPNs before starting RouteBar. Service operations can interrupt connectivity; test with an environment where losing the connection is acceptable. Follow [VALIDATION.md](VALIDATION.md) for the distinction between local tests and live system checks.

App status reports process/service state, not a proven WireGuard handshake or verified exit address. Fully quitting the app ends only the authorization helper. Use Disconnect to stop the background VPN.

## Source and binary releases

Source changes are versioned in Git. The current app is a local ad-hoc build; no notarized release or automatic publishing pipeline is supplied. Before distributing binaries, review dependency notices, collect the required licenses and corresponding source, and test the target architecture/macOS combinations. See [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).
