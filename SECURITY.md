# Security scope

RouteBar is a local macOS and Windows routing application. The source has automated security-boundary tests and development review, but has not undergone an independent security audit.

## Windows preview

The Windows client elevates the complete desktop application through UAC to
connect. It does not use the macOS session helper described below. Its trusted
code includes the desktop app, bundled controller and engine. Store the portable
package in a trusted location; elevation does not protect modified binaries.

Imported profiles and runtime snapshots are plaintext in ACL-protected storage,
restricted to the owner, SYSTEM and administrators. They are not stored in
Keychain or an encrypted Windows vault. Normal disconnect/exit removes runtime
snapshots, while imported profiles remain. Forced termination or power loss can
leave protected temporary files. The controller owns a kill-on-close Windows
Job Object, and the desktop app closes its stdin to request shutdown.

Windows has no persistent service or auto-connect. The preview requires live
acceptance testing for VPN egress and OS route cleanup; offline tests do not
prove these behaviors. See [Windows details](docs/WINDOWS.md).

## macOS privilege boundary

Administrator authorization starts a helper for one exact app process. It is not a stored password, a sudoers exception or a permanently reusable authorization token. The app checks the helper's root socket identity before sending configuration; the helper checks the client's UID, PID and start time. Requests use a fixed command set and a bounded schema.

Helper/controller/engine snapshots reside in protected storage under `/private/var/db`. The helper receives profile contents, creates its own private temporary files, and does not read client-selected profile paths as root. Closing the app removes the session after any in-flight operation completes; the independent launchd VPN service can remain active.

These checks do not protect a user who authorizes an already modified application, against a compromised root account, or against arbitrary code already executing inside the authorized app process.

## Credentials and logs

- Newly imported WireGuard profiles use the login Keychain; imported configuration can retain local file references.
- Active generated engine configuration contains private keys and is stored in the root-only runtime directory.
- Disconnect removes generated private-key configuration. Quitting the app alone does not disconnect or remove the active service configuration.
- Service logs can contain process names and destinations. They are private local files, but should still be reviewed and sanitized before sharing.
- Git excludes real profiles, local configuration, keys, logs and generated files. Test key material is synthetic and cannot authenticate to a real VPN service.

## Network limits

There is no whole-system kill switch. Ordinary routing may resume when the VPN is stopped, fails or restarts. DNS has a separate global exit policy. Shared processes, encrypted DNS, ECH, cached connections, local routes and other VPN software can affect attribution and reachability. A running process is not evidence that every flow uses the intended exit.

Sleep/wake, network changes, crash recovery and platform-specific behavior require real system testing. See [VALIDATION.md](docs/VALIDATION.md).

## Reporting a vulnerability

Do not put credentials, private logs or sensitive exploitation details in a public issue. If this repository has GitHub private vulnerability reporting enabled, use the Security tab's private reporting flow. Otherwise, request a private contact channel from the maintainer without publishing the sensitive details. This repository does not currently promise a response SLA or a separate long-term support branch.
