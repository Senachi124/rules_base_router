# Legacy Network Extension and diagnostic code

This document describes retained source that is separate from the current app's sing-box data path. Use the root [README](../README.md) and [Development](DEVELOPMENT.md) for the supported local build workflow.

## Original integration

The original design used Swift Network Extensions with the Rust `core/` library:

- Transparent Proxy for selected application/domain flows.
- Packet Tunnel for full-device packet forwarding.
- A Rust userspace WireGuard and TCP/UDP stack exposed through `include/RouteBarCore.h`.
- Signed application identity and DNS-derived metadata for policy matching.

Sources remain in `macos/ProxyExtension/`, `macos/PacketExtension/`, `macos/Shared/TunnelEngine.swift` and `core/`. The generated Xcode project retains those targets for reference. The current build scripts compile the RouteBar host with its Rust controller and sing-box; they do not embed either extension.

Reviving the Network Extension design would require its Apple signing, entitlement, provisioning, app-group and activation work. Ad-hoc signatures alone do not authorize that design. Those requirements do not apply to the current local sing-box app.

## Original Rust tools

`routebar-check` can inspect a profile or exercise an actual WireGuard/DNS/HTTP connection using an ordinary UDP socket. It does not install system routes. The active diagnostic command does contact the configured VPN endpoint; it is not part of the offline test suite.

```sh
source scripts/toolchain.sh
"$ROUTEBAR_CARGO" run --bin routebar-check -- /path/to/profile.conf --inspect
```

The original `routebar-vpn` tool manages a full-device utun path and a recovery journal. It is a separate privileged implementation and is not the GUI's whitelist backend. Its live system integration still needs dedicated acceptance testing. Do not run it concurrently with the current RouteBar service or another VPN.

See [core/README.md](../core/README.md) for the library API, synthetic transport tests and diagnostic behavior.
