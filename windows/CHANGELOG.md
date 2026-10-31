# Windows changelog

## 0.2.2 — 2026-10-31

- Fix IPv6 direct fallback when a dual-stack WireGuard exit exists but the
  monitored physical interface has no usable IPv6 address. Each direct rule and
  the direct default now have their own runtime interface guard.
- Process/IP-only routing no longer waits for protocol sniffing. The default
  Codex preset can reject unavailable direct IPv6 during TUN pre-match, before
  accepting a TCP handshake, allowing clients to try IPv4.
- Keep ordered VPN exceptions, Codex's dual-stack vm1 route, and DNS through
  vm1 with prefer_ipv4. No global IPv6 disable or DNS-profile migration.
- Preserve domain-rule priority; sniffing starts at the first domain-dependent
  rule. Such rules still need connection data and may defer a rejection.
- Add 32 isolated real-engine loopback probes covering the three Codex process
  names, IPv4/IPv6, direct exceptions/defaults, and simulated interface states.
  These tests do not restart a system TUN or disconnect another VPN.

## 0.2.1 — 2026-10-31

- First-run preset: ChatGPT.exe, codex.exe and codex-code-mode-host.exe use vm1;
  unmatched traffic uses direct; DNS uses 1.1.1.1 through vm1 (prefer_ipv4).
- Existing saved configurations are preserved. First profile import fills the
  unresolved vm1 preset and keeps a managed copy; existing profiles are not replaced.
- Version is visible in the app title. Bundles include build provenance, English
  and Traditional Chinese instructions, dependencies and storage guidance.
- Packaging uses an explicit file list so personal profiles/settings placed next
  to the executable are excluded from distribution archives.
- Includes the preceding fixes for rollback, single-instance ownership, elevation,
  visible DNS drafts, rule validation, warning display, accessibility and layout.
- Windows WireGuard transport handles IPv6-disabled physical adapters.

## 0.2.0 Windows preview — 2026-10-30

- Native Windows x64 desktop UI, Rust controller and pinned sing-box engine.
- Ordered application/process/domain/IP rules, DNS routing and multiple exits.
- Windows ACL-protected storage, process supervision and portable build workflow.
- Original macOS implementation retained.
