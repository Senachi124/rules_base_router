# Rules Base Router

A native macOS app for sending selected applications and websites through WireGuard VPNs while keeping other traffic direct.

The application is called **RouteBar**. It combines a SwiftUI interface, a Rust routing controller, and a bundled sing-box engine. The current app can be built and used locally without an Apple Developer certificate or Network Extension entitlement. System routing still requires macOS administrator authorization.

[繁體中文](README.zh-Hant.md) · [Architecture](docs/ARCHITECTURE.md) · [Configuration](docs/CONFIGURATION.md) · [Development](docs/DEVELOPMENT.md)

## Features

- One whitelist interface for apps, domains, domain suffixes, process names and IP ranges.
- Ordered, first-match routing rules with multiple WireGuard exits.
- Combined conditions: send only a selected app's connections to selected websites through a VPN.
- Independent DNS server, exit and address-family settings.
- Administrator authorization when opening the app; connection, reload, disconnect and log operations reuse that app session.
- Validation before applying changes, with rollback attempted if a replacement service fails to start.
- A menu bar interface, service status and on-demand logs.

## Build and run

Requirements: macOS 13 or later, Apple Command Line Tools or Xcode, Python 3, and [rustup](https://rustup.rs/). Rust is pinned in [rust-toolchain.toml](rust-toolchain.toml). Local validation has been performed on Apple Silicon; Intel and older macOS versions need separate acceptance testing.

```sh
git clone https://github.com/chanyan999/rules_base_router.git
cd rules_base_router
./scripts/build.sh
open build/RouteBar.app
```

The build downloads the pinned sing-box release over HTTPS, verifies its SHA-256, bundles the Rust controller and engine, and signs the app locally with an ad-hoc signature. Go and XcodeGen are not required. Build output and downloaded dependencies are ignored by Git. This is a local build, not a Developer ID notarized distribution.

## Use the app

1. Open RouteBar and complete the macOS administrator authorization. Authorization alone does not start a VPN.
2. Import a WireGuard `.conf` file in **VPN exits**. Newly imported profiles are stored in the login Keychain.
3. Add applications or websites to the **Whitelist**, choose an exit, and arrange rules in priority order.
4. Stop any other VPN before connecting RouteBar.
5. Edit rules as needed and select **Apply changes** to update an active connection. Applying changes restarts the service and interrupts existing connections.
6. Select **Disconnect** to stop the service and remove its generated private-key configuration.

Canceling authorization still allows whitelist editing; an explicit authorization button lets you retry. Closing the window leaves the menu bar app running. Fully quitting the app ends its authorization session, while an already running VPN continues independently. The VPN service also loads at system startup until disconnected. macOS may reuse recent OS authentication when a new app session requests authorization; RouteBar does not store your password.

## Routing behavior

Rules are evaluated from top to bottom; the first match wins. Applications/process names form one OR group, and domains/suffixes/IP ranges form another OR group. If both groups are present, both must match. Unmatched traffic defaults to direct routing.

DNS routing is a separate global policy. Selecting a VPN for an app does not automatically send every DNS query through that VPN. Shared networking processes, encrypted DNS, ECH and cached connections can limit domain or app attribution. There is no whole-system kill switch; traffic can use the normal system route while the VPN is stopped, restarting or unavailable.

See [configuration examples and CLI commands](docs/CONFIGURATION.md) and [security boundaries](SECURITY.md).

## Tests

```sh
./scripts/test.sh
python3 scripts/test-whitelist-integration.py
```

Run the build first so the integration test can use this repository's bundled controller and engine. These tests use synthetic profiles and local fixtures; they do not require administrator privileges or start a system VPN. An optional comparison against a separately built Go reference is documented in [Development](docs/DEVELOPMENT.md).

[Validation](docs/VALIDATION.md) distinguishes automated coverage from system acceptance checks.

## Source layout

| Path | Purpose |
| --- | --- |
| `controller/` | Current Rust routing schema, sing-box configuration, service lifecycle and authorization helper |
| `macos/App/` | SwiftUI app, whitelist editor and menu bar |
| `macos/Shared/` | Shared models, Keychain access, session socket client and legacy bridges |
| `core/` | Original Rust WireGuard library, validation ABI and diagnostic tools |
| `macos/Tests/` | Swift model, bridge, socket and regression tests |
| `scripts/` | Build, packaging and verification commands |
| `docs/` | Architecture, configuration, development and validation |

The current VPN data path uses `controller/` and sing-box. The original Network Extension sources remain for reference and regression tests; the current app build does not embed those extensions. See [legacy notes](docs/LEGACY_NETWORK_EXTENSION.md).

## Contributing and license

Read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting changes. Never commit real WireGuard profiles, private keys, local configuration or service logs; use [config.example.yaml](config.example.yaml) as a template.

Project source is licensed under [MIT](LICENSE). Dependencies retain their respective licenses. sing-box is a separate executable distributed under GPL-3.0-or-later; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) before redistributing binaries.
