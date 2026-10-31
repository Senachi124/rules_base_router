# RouteBar for Windows 0.2.1

Native Windows 10/11 **x64** preview, using the shared Rust routing compiler and
the pinned sing-box 1.14.4 Windows engine. The desktop app uses .NET Framework
4.8 (included in current Windows 10/11 installations). No WSL, Go or .NET SDK is
needed. ARM64 and 32-bit Windows are not supported by this package.
The current controller also requires the Microsoft Visual C++ v14 **x64** Runtime
(`VCRUNTIME140.dll`). Install it from the
[official Microsoft downloads](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist)
if missing. Traditional Chinese instructions are in `README.zh-Hant.md` in the
package, or [docs/WINDOWS.zh-Hant.md](https://github.com/Senachi124/rules_base_router/blob/main/docs/WINDOWS.zh-Hant.md)
in the source repository.

## Default Codex routing

On first launch without a saved configuration, the app prepares one `codex` rule:
`ChatGPT.exe`, `codex.exe` and `codex-code-mode-host.exe` use `vm1`; unmatched
traffic uses `direct`. DNS uses `1.1.1.1` through `vm1`, with `prefer_ipv4`.
Child tools such as `python.exe`, `git.exe` and separate browsers do not inherit
the Codex rule. Existing saved settings are never replaced by this preset.

No private WireGuard profile or personal server address ships with the app.
Import your profile under **VPN exits** to fill the initial unresolved `vm1`
exit. The app copies it into managed storage; later imports get unique exit names
and do not overwrite a working profile. The package's `config.example.yaml`
contains the same rules; importing that file requires a `vm1.conf` beside it.

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
Keep `RouteBar.exe`, `routebar-v2.exe`, `sing-box.exe`, `libcronet.dll` and the
included documentation/licenses together. Copy the whole folder to your desktop
or create a shortcut; copying only the UI executable is insufficient. Exit the
old app before upgrading (this disconnects its VPN). The title shows `0.2.1`,
and `BUILD-INFO.json` records the build version, source commit and timestamp.
The archive is assembled from an explicit file list, excluding personal profiles
and settings even if they were placed beside the executable.
To build beside a currently running version, use
`scripts/test-windows.ps1 -AppDirectory build/RouteBar-windows-x64-0.2.1`, then
`scripts/build-windows.ps1 -SkipRustBuild -OutputDirectory build/RouteBar-windows-x64-0.2.1`.
This produces a separate versioned folder and ZIP without replacing running files.

## Use

1. Open `RouteBar.exe`. Editing and validation do not require administrator rights.
2. Under **VPN exits**, import an exported WireGuard `.conf`. Imports are copied
   into an ACL-protected local folder and receive unique exit names derived from
   the source filename.
3. Under **Routing rules**, add applications, process names (include `.exe`),
   domains, domain suffixes or IP ranges; select the exit. Semicolons separate
   multiple selectors. Move rules up/down to set first-match priority.
4. Set the DNS server/exit and default route under **DNS and default route**, then
   press **Save DNS and default**. DNS is an independent global policy. The
   configuration state distinguishes unsaved settings and changes awaiting Apply.
5. **Validate visible settings** checks the displayed draft, profiles and bundled
   engine without starting it. Warnings appear above the tabs and in Logs. Invalid
   rules remain in their editor so they can be corrected.
6. Stop other VPNs. Press **Connect**. If not elevated, Windows asks for UAC
   authorization and hands off to one elevated window, which connects after
   loading the validated settings. Cancelling UAC leaves the editor available.
   Use the same Windows account for editing and elevation; another administrator
   account has its own settings and profiles.
7. After edits, **Apply changes** validates a private snapshot before stopping the
   current engine. Failed startup attempts to restore the previous snapshot,
   even if deletion of a temporary snapshot fails. Cleanup warnings appear in Logs.
8. **Disconnect** stops routing and removes its snapshot. Minimizing hides the
   window in the notification area. Closing or choosing **Exit and disconnect**
   stops the VPN and exits. There is no boot service or auto-connect.

Opening the app again activates its owning window. If Windows prevents activation
across privilege levels, use the existing administrator window; a second window
does not claim that its connection is disconnected. Unsaved edits survive Validate
and Disconnect, and closing prompts to save or discard them.
`RouteBar.exe --connect` explicitly requests a connection on launch; normal
launches only edit.

## Use your own VM as the default exit

RouteBar connects directly to a standard WireGuard server and does **not** require
NordVPN, its account, service, or adapters. On the server, configure a dedicated
WireGuard peer, enable IP forwarding, permit its UDP listen port, and allow/NAT
only the peer's assigned IPv4 and (if supported) IPv6 addresses to the Internet.
Keep management SSH access and existing firewall rules. The server's peer
AllowedIPs identify the client's tunnel addresses; the client profile normally
uses `AllowedIPs = 0.0.0.0/0, ::/0` for a dual-stack exit.

Import that client profile, select its exit for **Unmatched traffic** and **DNS
exit**, and choose a reachable DNS server such as `1.1.1.1`. With no exception
rules, all traffic captured by the TUN uses that exit. The tunnel endpoint itself
uses a separate direct transport, including on Windows adapters with IPv6
disabled; endpoint hostname resolution uses the bootstrap resolver so it cannot
depend on a tunnel that has not connected yet.

For acceptance testing, disconnect other system VPNs yourself, connect RouteBar,
and compare the public IPv4/IPv6 addresses with your VM. Check DNS, browser traffic,
Disconnect, and reconnect. Other VPNs' kill switches may block this independent
transport; RouteBar does not change their settings. Local-network routes and other
VPN-specific routes are not a guarantee that every packet is captured. No kill
switch is provided.

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
desktop smoke tests, isolated UI/lifecycle regression tests and real-engine schema
checks with synthetic profiles.
It never opens a TUN adapter or starts a system VPN. A real WireGuard profile
and administrator-led acceptance checks are still required for handshake,
per-application/domain egress, IPv4/IPv6, DNS, restart/rollback and route cleanup
on the target Windows machine. macOS UI tests must run separately on a Mac.

The UI regression suite uses private temporary settings and fake connection
lifecycles; it does not access personal profiles or start a system VPN. Its layout
checks are control-bound/offscreen checks, not a real monitor-DPI or screen-reader
acceptance test. Live WireGuard handshake, IPv4/IPv6 egress and UDP DNS have been
checked separately with localhost-only proxy inbounds. A subsequent live system
TUN check observed the VM's IPv4/IPv6 egress and working DNS; a split-routing check
observed non-Codex traffic using the direct public address. Codex process rule
matching was checked, but each subprocess's egress was not individually captured.
These observations do not replace full UAC, rollback, route-cleanup and monitor-DPI
acceptance testing. The original macOS CLI is unchanged; macOS UI acceptance needs
a Mac.

The bundled engine and its DLL retain upstream licenses. See
`Licenses/THIRD_PARTY_NOTICES.md` in the package (or `THIRD_PARTY_NOTICES.md` in
the source). Public binary redistribution needs the corresponding source and
complete dependency notices described there.
