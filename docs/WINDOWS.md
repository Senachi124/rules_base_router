# RouteBar for Windows

Native Windows 10/11 **x64** preview, using the shared Rust routing compiler and
the pinned sing-box 1.14.4 Windows engine. The desktop app uses .NET Framework
4.8 (included in current Windows 10/11 installations). No WSL, Go or .NET SDK is
needed. ARM64 and 32-bit Windows are not supported by this package.

## Build

Install Rust through rustup and Visual Studio 2022 Build Tools with **Desktop
development with C++**, including the Windows SDK. The repository's
`rust-toolchain.toml` selects the compiler automatically.

From PowerShell in the repository:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-windows.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test-windows.ps1
```

The build verifies the upstream Windows archive against a pinned SHA-256 and
produces `build/RouteBar-windows-x64/RouteBar.exe` and
`build/RouteBar-windows-x64.zip`. Keep all extracted files together. These local
binaries are unsigned. Source retains the original macOS implementation.

## Use

1. Open `RouteBar.exe`. Editing and validation do not require administrator rights.
2. Under **VPN exits**, import an exported WireGuard `.conf`. Imports are copied
   into an ACL-protected local folder and assigned names `vpn`, `vpn2`, etc.
3. Under **Routing rules**, add applications, process names (include `.exe`),
   domains, domain suffixes or IP ranges; select the exit. Semicolons separate
   multiple selectors. Move rules up/down to set first-match priority.
4. Set the DNS server/exit and default route under **DNS & default route**, then
   press **Save DNS & default**. DNS is an independent global policy.
5. **Validate** checks profiles and the real bundled engine without starting it.
6. Stop other VPNs. Press **Connect**. If not elevated, Windows asks for UAC
   authorization and opens a new elevated window. Press **Connect** again there.
   Use the same Windows account for editing and elevation; another administrator
   account has its own settings and profiles.
7. After edits, **Apply changes** validates a private snapshot before stopping the
   current engine. Failed startup attempts to restore the previous snapshot.
8. **Disconnect** stops routing and removes its snapshot. Minimizing hides the
   window in the notification area. Closing or choosing **Exit and disconnect**
   stops the VPN and exits. There is no boot service or auto-connect.

The status means the engine process is running; it does not confirm a WireGuard
handshake, egress IP, or real application attribution. There is no kill switch;
traffic can go direct while disconnected or restarting. Encrypted DNS, ECH and
shared processes can limit domain/application matching. Windows strict TUN
routing is enabled to restrict ordinary multihomed DNS leakage; this can affect
software such as VirtualBox. See the upstream
[TUN documentation](https://sing-box.sagernet.org/configuration/inbound/tun/).

## Configuration and storage

Settings and imported profiles are under `%LOCALAPPDATA%\RouteBarWindows`.
Profiles are plaintext protected by a DACL limited to their owner, SYSTEM and
administrators; this is not encrypted vault storage. Removing an exit removes
the configuration reference, but retains the imported profile on disk.
Exported configuration contains profile paths, not private keys. Keep referenced
profiles available; YAML/JSON imports may reference files outside this folder.

Application rules use absolute Windows executable paths, with case-insensitive
path matching. macOS `.app` bundle paths must be replaced with Windows `.exe`
paths. Ordered AND/OR semantics, multiple exits, CIDRs and address-family guards
use the shared compiler. Windows example: `windows/config.example.yaml` in the
source tree, or `config.example.yaml` in the built package.

Generated engine JSON and validation files have explicit Windows ACLs. A Windows
Job Object terminates the engine if its controller exits unexpectedly. Normal
stop attempts graceful console shutdown before terminating the job. A forced
process kill or power loss can leave ACL-protected snapshots in `session-*`
folders or `routebar-*` temporary folders. Delete stale folders only when no
RouteBar process is running. Do not publish logs or profiles containing secrets.

The elevated app and bundled executables form one trust boundary. Store the
portable package somewhere you trust and do not replace binaries while running.
The macOS PID-bound privileged helper protocol is not implemented on Windows.

## CLI

```powershell
cd build/RouteBar-windows-x64
.\routebar-v2.exe validate -c C:\path\config.yaml
.\routebar-v2.exe explain -c C:\path\config.yaml --process curl.exe --domain example.org
.\routebar-v2.exe render -c C:\path\config.yaml
# In an administrator terminal; Ctrl+C or a line containing stop disconnects:
.\routebar-v2.exe run -c C:\path\config.yaml
```

`render` redacts keys on stdout. `render --output PATH` creates an ACL-protected
file containing private keys. Windows deliberately exposes foreground `run`;
macOS `up`, `down`, `reload`, `status` and session commands are not available.
The desktop app owns connect/disconnect, live process status and rollback.

## Validation scope

`scripts/test-windows.ps1` runs Rust controller tests, clippy, formatting,
desktop smoke tests and real-engine schema checks with synthetic profiles.
It never opens a TUN adapter or starts a system VPN. A real WireGuard profile
and administrator-led acceptance checks are still required for handshake,
per-application/domain egress, IPv4/IPv6, DNS, restart/rollback and route cleanup
on the target Windows machine. macOS UI tests must run separately on a Mac.

Local validation on Windows passed the 13 Rust tests, clippy, the real-engine
integration suite, the native UI construction smoke test, and the x64 build.
The macOS controller also passed cross-target compilation checks; its existing
CLI source is unchanged.
The window and its controls were detected by UI automation, but the automation
host could not activate the window, so visual/interactive acceptance remains
outstanding. No real VPN connection was started during development validation.

The bundled engine and its DLL retain upstream licenses. See
`Licenses/THIRD_PARTY_NOTICES.md` in the package (or `THIRD_PARTY_NOTICES.md` in
the source). Public binary redistribution needs the corresponding source and
complete dependency notices described there.
