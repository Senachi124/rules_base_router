# RouteBar Rust core

The certificate-free v2 app now uses the separate `controller/` Rust crate and bundled sing-box for system traffic. This crate remains the original WireGuard library, validation ABI and standalone diagnostic implementation. The Network Extension notes below describe the legacy path.

This crate provides the WireGuard transport, a userspace TCP/UDP stack, strict
profile validation, and App/Domain policy matching. It does not create host
sockets, modify routes, or change DNS settings. The Swift Network Extension owns
the encrypted UDP transport and passes buffers through the C ABI in
`include/RouteBarCore.h`.

## Build and check

From the repository root:

```sh
MACOSX_DEPLOYMENT_TARGET=13.0 cargo build --lib
MACOSX_DEPLOYMENT_TARGET=13.0 cargo test --all-targets
MACOSX_DEPLOYMENT_TARGET=13.0 cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

The synthetic tests exchange actual encrypted WireGuard messages between two
peers. A smoltcp server echoes TCP and UDP inside the encrypted tunnel. Coverage
includes IPv4/IPv6 UDP, 150 KB TCP with backpressure and half-close, authentication
and replay rejection, destination/source AllowedIPs, resource bounds, profile
validation/redaction, domain suffix boundaries, and signed application identity.
These tests do not require credentials, system extensions, or changes to host
network settings.

## Live diagnostic

```sh
MACOSX_DEPLOYMENT_TARGET=13.0 cargo run --bin routebar-check -- /path/to/wireguard.conf --inspect
MACOSX_DEPLOYMENT_TARGET=13.0 cargo run --bin routebar-check -- /path/to/wireguard.conf
```

The first command only validates the local file. The second opens a regular UDP
socket to the VPN endpoint, completes an authenticated WireGuard handshake,
queries `example.com` through the profile's DNS server inside the VPN, and makes
an HTTP request to Cloudflare's `1.1.1.1/cdn-cgi/trace` inside the VPN. Endpoint
bootstrap name resolution uses the current system resolver. The diagnostic never
falls back to direct traffic for the DNS or HTTP checks, never changes system
routes, and never prints private keys, profile contents, or the full HTTP body.
The HTTP check reports the numeric status separately from the optional exit-country
lookup. A complete, valid HTTP redirect or error response proves the tunneled TCP/HTTP
roundtrip and passes that check; it does not prove an exit location. Exit-country
lookup requires HTTP 200 with a valid IP and country in the decoded trace body,
and otherwise reports `unavailable`. The exit IP and response body are never printed.
The diagnostic validates HTTP/1.0 and HTTP/1.1 responses with Content-Length,
plain chunked encoding (including trailers), or an orderly close-delimited body.
Malformed, truncated, ambiguous, and unsupported framing fails explicitly;
compressed bodies are not interpreted as trace text. No redirects are followed.
The diagnostic tries up to four resolved endpoint addresses, allowing 20 seconds
for each handshake. A failed candidate reports encrypted packet counts only.

Treat `.conf` files as credentials. They are ignored by the repository. Only use
an exported profile with its actual WireGuard private key; provider templates may
contain a placeholder instead.

## Runtime contract and current limits

- Call one engine from one serial queue. C callbacks may not re-enter it.
- The caller drives timers in milliseconds and drains output events after calls.
- After a TCP or UDP receive event, call `rb_engine_resume` only when the native
  application flow has accepted the data. TCP send returns the consumed byte count.
- Limit: 256 concurrent flows, 64 KB send/receive buffers per flow, and a bounded
  event queue (4 MB or 4,096 events). Exceeding the event queue stops the engine and
  emits a fatal event instead of growing memory indefinitely.
- UDP fragmentation/reassembly is not enabled. Oversized UDP datagrams are
  rejected explicitly using the profile MTU (1,280–1,420 bytes).
- App rules match both signing identifier and Team ID. Domain rules match the
  apex and label-delimited subdomains. The core cannot discover hidden hostnames:
  the macOS integration must supply available hostname/DNS metadata.
- Packet mode checks peer AllowedIPs both before encapsulation and after
  decryption. It does not invent an IPv6 tunnel when a profile only has IPv4.
- `authenticated_rx_count` advances only for accepted authenticated WireGuard
  traffic; malformed packets and replayed packets cannot keep a dead peer alive.
- Secret configuration temporaries use `Zeroizing`; owned key fields zeroize on
  drop. The caller must separately protect its original input buffer and storage.

The dependencies are pinned in the workspace `Cargo.lock`. BoringTun implements
WireGuard; smoltcp provides the userspace IP/TCP/UDP stack. This is an early
implementation and has not undergone an independent security audit.
