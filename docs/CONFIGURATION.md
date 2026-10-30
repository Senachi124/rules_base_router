# Configuration and CLI

The app's whitelist editor is the normal configuration interface. YAML or JSON can also be imported, or passed to the Rust CLI. Start from [config.example.yaml](../config.example.yaml). Real `.conf` files and root-level `config.yaml`, `config.yml` and `config.json` are ignored by Git.

## Minimal routing example

```yaml
version: 1
vpns:
  work_vpn:
    wireguard_config: ./conf/work-vpn.conf
dns:
  server: 1.1.1.1
  via: direct
  strategy: auto
routing:
  default: direct
  rules:
    - name: Browser work sites
      match:
        apps: [/Applications/Google Chrome.app]
        domain_suffixes: [example.org]
      via: work_vpn
```

This rule sends only Chrome connections to `example.org` and its subdomains through `work_vpn`. Other traffic stays direct. The profile path resolves relative to the configuration file. Replace the example with a real exported WireGuard profile stored locally; the repository contains no usable VPN credentials.

The schema version `1` describes the configuration format, not a selectable UI mode. Unknown fields, invalid selectors and unsupported profile directives are rejected.

## Rule matching

| Selector | Meaning |
| --- | --- |
| `apps` | Absolute application paths; `.app` paths include bundled helpers |
| `process_names` | Process-name matches, OR with `apps` |
| `domains` | Exact domain matches |
| `domain_suffixes` | Apex domain and label-delimited subdomains |
| `ip_cidrs` | Destination IPv4 or IPv6 networks |
| `via` | `direct` or a configured VPN tag |

The program selectors form one OR group. Destination selectors form another OR group. When both groups exist, they are combined with AND. Rules are evaluated in order, and the first match wins. Place direct exceptions before broader VPN rules.

A helper outside an app bundle does not automatically inherit its parent application's rule. A shared WebKit networking process can serve multiple apps, so a rule for that process can affect all of them. Domain matching depends on available DNS/connection metadata and can be limited by encrypted DNS, ECH and caches.

## WireGuard profiles

Profiles must contain one `[Interface]` and one `[Peer]`, valid keys, addresses, an endpoint and supported AllowedIPs. wg-quick shell hooks are not executed. Address-family settings must agree with the profile; the controller does not invent IPv6 tunnel support for an IPv4-only exit.

New profiles imported through the UI are saved in the login Keychain. Imported YAML/JSON may reference an external file instead; keep that file available or reimport the profile into the app.

## DNS

DNS has an independent global policy because macOS can resolve names in a shared system process.

- `server`: resolver address. If omitted when `via` names a VPN, the profile's DNS server is used when available.
- `via`: `direct` or a VPN tag.
- `strategy`: `auto`, `prefer_ipv4`, `prefer_ipv6`, `ipv4_only` or `ipv6_only`.

`auto` resolves an address-family policy from the configured exits. Unknown strategy names are rejected. An explicit strategy overrides auto selection; verify reachability for every exit when combining profiles with different address families. DNS filtering and unavailable-family routing guards are generated consistently with that policy. An application's own encrypted DNS can bypass ordinary system DNS behavior.

## CLI examples

After building:

```sh
CLI=build/RouteBar.app/Contents/MacOS/routebar-v2
"$CLI" validate -c /path/to/config.yaml
"$CLI" explain -c /path/to/config.yaml --app /Applications/Google\ Chrome.app --domain example.org
"$CLI" render -c /path/to/config.yaml
"$CLI" status --json
```

`render` redacts private keys on stdout. `render --output PATH` writes a private `0600` file containing keys; do not commit or share it. `config-inspect --json` outputs normalized routing configuration and profile paths, without profile key contents.

Explicit system operations require administrator privileges:

```sh
sudo "$CLI" up -c /path/to/config.yaml
sudo "$CLI" reload -c /path/to/config.yaml
sudo "$CLI" logs --lines 100
sudo "$CLI" down
# Foreground operation; Ctrl+C requests cleanup:
sudo "$CLI" run -c /path/to/config.yaml
```

Stop other VPNs before starting. The CLI does not reuse the app's PID-bound authorization socket. `probe --via NAME` tests a selected exit through loopback SOCKS without changing system routes; it does not prove real application attribution. Read `"$CLI" --help` for options.

To import a configuration when opening the app, fully quit any running instance first:

```sh
open build/RouteBar.app --args --config /absolute/path/config.yaml
```

Importing or authorizing does not automatically connect the VPN.
