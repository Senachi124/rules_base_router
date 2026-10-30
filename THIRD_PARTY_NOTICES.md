# Third-party components

RouteBar code is licensed under the MIT License; see `LICENSE`. Dependencies retain their own licenses; see their source distributions and `Cargo.lock` for exact pinned versions and transitive dependencies.

| Component | Purpose | Upstream | License |
|---|---|---|---|
| BoringTun | WireGuard userspace protocol | https://github.com/cloudflare/boringtun | BSD-3-Clause |
| smoltcp | Userspace TCP/IP stack | https://github.com/smoltcp-rs/smoltcp | BSD-0-Clause |
| serde / serde_json | Structured data | https://github.com/serde-rs/serde | MIT OR Apache-2.0 |
| zeroize | Clear sensitive Rust memory | https://github.com/RustCrypto/utils | MIT OR Apache-2.0 |
| base64 | WireGuard key decoding | https://github.com/marshallpierce/rust-base64 | MIT OR Apache-2.0 |
| idna | Domain normalization | https://github.com/servo/rust-url | MIT OR Apache-2.0 |
| ipnet | CIDR validation | https://github.com/krisprice/ipnet | MIT OR Apache-2.0 |
| libc | macOS utun, signals and descriptor APIs | https://github.com/rust-lang/libc | MIT OR Apache-2.0 |
| rand | Nonces and identifiers | https://github.com/rust-random/rand | MIT OR Apache-2.0 |
| serde_yaml | v2 YAML configuration | https://github.com/dtolnay/serde-yaml | MIT OR Apache-2.0 |
| sing-box 1.14.4 | Separate TUN / process-routing / WireGuard executable | https://github.com/SagerNet/sing-box/tree/v1.14.4 | GPL-3.0-or-later |
| windows-sys 0.52 | Windows ACL, console, process and Job Object APIs | https://github.com/microsoft/windows-rs | MIT OR Apache-2.0 |

The Windows portable build bundles the upstream Windows amd64 sing-box archive,
including its `libcronet.dll`, alongside the controller. It includes the upstream
license and these notices in `Licenses/`. Chromium/Cronet and any bundled driver
components retain their upstream third-party licenses. The Windows UI uses the
system .NET Framework and does not redistribute a .NET runtime. Local ZIPs and
CI artifacts are development previews; this build script does not assemble a
complete corresponding-source distribution for public binary releases.

The certificate-free app bundles sing-box as a separate executable, invoked by the Rust controller. Its unmodified upstream release archive is verified against a pinned SHA-256. The bundle includes its LICENSE in Contents/Resources/Licenses. Corresponding upstream source: https://github.com/SagerNet/sing-box/tree/v1.14.4 (including go.mod and go.sum). Public redistribution must meet the upstream license's corresponding-source requirements.

This list describes direct dependencies and is not a complete redistribution notice for a public binary. Before public release, collect and ship the licenses for all transitive dependencies, including ring and its bundled code, from the locked dependency sources. WireGuard is a registered trademark of Jason A. Donenfeld. RouteBar is not affiliated with or endorsed by Surfshark, WireGuard, Tailscale, Cloudflare, or Apple.
