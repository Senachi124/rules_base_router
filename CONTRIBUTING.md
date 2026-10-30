# Contributing

Changes to the SwiftUI app, Rust controller, tests and documentation are welcome. Keep changes focused and describe the concrete behavior they address.

## Local workflow

1. Follow [Development](docs/DEVELOPMENT.md) to build the app.
2. Make the change and update related documentation.
3. Run `./scripts/test.sh`. For changes to whitelist conversion, routing or packaging, also build the app and run `python3 scripts/test-whitelist-integration.py`.
4. Inspect the staged diff, including `git diff --cached --check`.
5. Open a pull request with the behavior change, relevant verification and any remaining system acceptance work.

## Design boundaries

- Keep one editable whitelist model and preserve first-match order, compound selectors, DNS settings and disabled rules.
- Keep privileged operations behind the narrow session protocol. Do not add arbitrary shell execution, caller-selected engine binaries or privileged reads of user-provided paths.
- Validate candidate configurations before stopping the running service. Preserve operation locking and rollback behavior.
- Keep blocking process and socket work off the UI thread.
- Maintain the distinction between current sing-box routing and legacy Network Extension/diagnostic code.

## Tests and privacy

Use synthetic profiles, local fixtures and reserved documentation addresses. Never include live VPN keys, tokens, personal configuration, browsing logs or a contributor's absolute home-directory path. Do not start a system VPN from automated tests.

For bug reports, provide the app/controller version, architecture, macOS version, reproduction steps and sanitized errors. Remove credentials and private destinations before attaching logs or configuration. Security-sensitive reports should follow [SECURITY.md](SECURITY.md).
