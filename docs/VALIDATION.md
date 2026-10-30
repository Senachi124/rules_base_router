# Validation

Last local verification: **2026-10-30 (Asia/Hong_Kong)**, on Apple Silicon macOS. These results describe development verification, not an independent security audit or a guarantee for every macOS release.

## Repository build and automated checks

The source was built from the `rules_base_router` checkout with a fresh local build/cache directory. The normal build downloaded and verified its own sing-box archive; it did not depend on a sibling project.

| Check | Result |
| --- | --- |
| `./scripts/build.sh` | Passed; standalone app built and ad-hoc bundle signatures verified |
| `./scripts/test.sh` | Passed; 82 Rust tests, clippy with warnings denied, rustfmt and all Swift suites |
| `python3 scripts/test-whitelist-integration.py` | Passed; 6 sing-box schema checks and 23 routing decisions |
| Optional Go reference comparison | Passed; 11 exact configuration comparisons and 12 routing decisions |
| Loopback DNS checks | Passed; IPv4-only, IPv6-only and dual-stack behavior, including relevant HTTPS/SVCB suppression |

The optional comparison used an explicitly supplied, separately built Go reference executable. That implementation is not required for building the app or running the main suite.

Rust coverage includes schema and WireGuard validation, ordered rule semantics, key redaction, operation locks, candidate validation before stop, rollback, runtime file protections, bounded subprocess handling and secret cleanup. The 13 session-helper tests cover exact kernel peer credentials/process start time, command restrictions, duplicate keys, framing, initial handshake expiry and protected parent directories.

Swift suites cover the C ABI, DNS parsing/cache, packet settings regressions, command escaping, private file handling, whitelist migration/persistence, socket peer checks before secret transmission, fragmented/oversized responses and deadlines. The integration test compiles the actual Swift whitelist converter and checks preserved compound selectors, disabled rules, selected exits, DNS settings and rule reordering.

Automated tests use synthetic keys and local fixtures. No system TUN, real VPN session or privileged service was started by these tests.

## Previously observed native behavior

During development, native UI checks confirmed imported rules, compound-condition editing, unchanged-rule save, invalid-domain rejection and persistence after quitting/reopening.

The final authorization implementation also established a real root helper session, displayed the authorized state, polled service status and read logs through its socket. Quitting the app removed the helper process and its session directory while an already running VPN retained the same process ID. These checks did not start, reload or stop that VPN. Source relocation changed packaging defaults and documentation; it did not change that app/helper implementation.

## Remaining system acceptance

The following are not established by the automated suite:

- Starting, reloading and stopping a real system VPN through the new app-session socket, including route/DNS restoration.
- Actual selected-app egress and unmatched direct traffic across all app/network combinations.
- The native authorization cancellation dialog; its error handling and editable UI path are implemented, but cancellation was not manually exercised in the recorded native run.
- Sleep/wake, Wi-Fi/uplink changes, reboot, engine/helper crashes and coexistence with other network software.
- Intel, older macOS releases and a notarized public binary distribution.
- The legacy Network Extension activation path and the original pure-Rust utun CLI's full privileged lifecycle.

For a live acceptance run, stop other VPNs, authorize the app, connect, verify intended egress and direct traffic, apply a controlled rule change, disconnect, and verify ordinary network/DNS behavior. Repeat appropriate recovery and platform checks in a disposable test environment. Service status alone does not prove a WireGuard handshake or verified exit. There is no whole-system kill switch.
