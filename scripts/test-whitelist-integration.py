#!/usr/bin/env python3
"""Exercise the actual Swift whitelist model -> Rust -> sing-box schema path.

Only synthetic profiles and offline CLI commands are used. This test never
starts a TUN, installs a service, contacts a VPN, or changes network settings.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CHROME = "/Applications/Google Chrome.app"


def run(arguments, *, timeout=45):
    result = subprocess.run([str(value) for value in arguments], capture_output=True,
                            text=True, timeout=timeout)
    if result.returncode:
        raise AssertionError(f"{Path(arguments[0]).name} failed:\n{result.stderr or result.stdout}")
    return result.stdout


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2))
    path.chmod(0o600)


def profile(path, endpoint):
    private = base64.b64encode(bytes(range(1, 33))).decode()
    public = base64.b64encode(bytes(range(32))).decode()
    path.write_text(f"[Interface]\nPrivateKey = {private}\nAddress = 10.14.0.2/16\n"
                    "DNS = 9.9.9.9\n[Peer]\n"
                    f"PublicKey = {public}\nEndpoint = {endpoint}:51820\nAllowedIPs = 0.0.0.0/0\n")
    path.chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    bundled = ROOT / "build/RouteBar.app/Contents/MacOS"
    parser.add_argument("--rust", type=Path, default=bundled / "routebar-v2")
    parser.add_argument("--engine", type=Path, default=bundled / "sing-box")
    parser.add_argument("--swiftc", default="swiftc")
    args = parser.parse_args()
    for binary in [args.rust, args.engine]:
        if not os.access(binary, os.X_OK):
            parser.error(f"Executable missing: {binary}; build it or supply its path")
    with tempfile.TemporaryDirectory(prefix="routebar-whitelist-test-") as temporary:
        directory = Path(temporary)
        profile(directory / "japan.conf", "192.0.2.1")
        profile(directory / "usa.conf", "192.0.2.2")
        imported = {
            "version": 1,
            "vpns": {name: {"wireguard_config": str(directory / f"{name}.conf")}
                     for name in ["japan", "usa"]},
            "dns": {"via": "japan", "strategy": "ipv4_only", "server": "9.9.9.9"},
            "routing": {"default": "direct", "rules": [
                {"name": "Company exception", "match": {"domain_suffixes": ["company.example"]}, "via": "direct"},
                {"name": "Chrome selected websites", "match": {
                    "apps": [CHROME], "process_names": ["ChromeShared"],
                    "domains": ["api.example.com"], "domain_suffixes": ["example.org"],
                    "ip_cidrs": ["203.0.113.0/24"]}, "via": "japan"},
                {"name": "Other Chrome traffic", "match": {"apps": [CHROME]}, "via": "usa"},
            ]},
        }
        source = directory / "source.json"
        write_json(source, imported)
        normalized = directory / "normalized.json"
        normalized.write_text(run([args.rust, "config-inspect", "-c", source, "--json"]))
        normalized.chmod(0o600)
        fixture = directory / "whitelist-fixture"
        run([args.swiftc, "-swift-version", "5", "-parse-as-library",
             ROOT / "macos/Shared/Models.swift", ROOT / "macos/Shared/V2Backend.swift",
             ROOT / "macos/Shared/WhitelistModels.swift",
             ROOT / "macos/Tests/WhitelistIntegrationFixture.swift",
             "-framework", "Foundation", "-o", fixture], timeout=90)
        cases = json.loads(run([fixture, normalized]))
        expected_cases = {"baseline", "disabled_compound", "disabled_fallback", "selected_exit", "reordered", "staged_profiles"}
        assert set(cases) == expected_cases, f"Missing fixture scenarios: {set(cases)}"
        paths = {}
        generated = {}
        for name, config in cases.items():
            assert config["routing"]["default"] == "direct", f"{name}: unmatched traffic must remain direct"
            assert set(config["vpns"]) == {"japan", "usa"}, f"{name}: profiles lost"
            assert config["dns"] == imported["dns"], f"{name}: independent DNS policy changed"
            for tag in ["japan", "usa"]:
                assert Path(config["vpns"][tag]["wireguard_config"]) == directory / f"{tag}.conf"
            path = directory / f"{name}.json"
            paths[name] = path
            write_json(path, config)
            validation = json.loads(run([args.rust, "validate", "-c", path,
                                         "--engine", args.engine, "--json"]))
            assert validation["valid"] and validation["dns_strategy"] == "ipv4_only"
            generated[name] = json.loads(run([args.rust, "render", "-c", path]))
        baseline = cases["baseline"]
        assert len(baseline["routing"]["rules"]) == 3, "Importer split or dropped a compound rule"
        assert baseline["routing"]["rules"][1]["match"] == imported["routing"]["rules"][1]["match"], "Compound selectors changed during Swift import/export"
        for name in ["disabled_compound", "disabled_fallback"]:
            assert len(cases[name]["routing"]["rules"]) == 2, f"{name}: disabled rule reached engine"
        # An unchanged imported document must compile identically after passing
        # through the real Swift model used by the settings UI.
        original = json.loads(run([args.rust, "render", "-c", source]))
        assert generated["baseline"] == original, "Swift model altered imported engine semantics"
        assert generated["staged_profiles"] == original, "Explicit profile staging changed engine semantics"
        flows = [
            ("baseline", ["--app", CHROME, "--domain", "api.example.com"], "japan"),
            ("baseline", ["--app", CHROME + "/Contents/Helpers/worker", "--domain", "api.example.com"], "japan"),
            ("baseline", ["--app", "/Applications/Safari.app", "--domain", "api.example.com"], "direct"),
            ("baseline", ["--app", CHROME, "--domain", "company.example"], "direct"),
            ("baseline", ["--app", CHROME, "--domain", "sub.company.example"], "direct"),
            ("baseline", ["--app", CHROME, "--domain", "elsewhere.invalid"], "usa"),
            ("baseline", ["--app", CHROME, "--domain", "sub.api.example.com"], "usa"),
            ("baseline", ["--app", CHROME, "--domain", "example.org"], "japan"),
            ("baseline", ["--app", CHROME, "--domain", "sub.example.org"], "japan"),
            ("baseline", ["--app", CHROME, "--domain", "notexample.org"], "usa"),
            ("baseline", ["--app", CHROME, "--ip", "203.0.113.17"], "japan"),
            ("baseline", ["--app", CHROME, "--ip", "203.0.114.17"], "usa"),
            ("baseline", ["--process", "ChromeShared", "--domain", "api.example.com"], "japan"),
            ("baseline", ["--process", "OtherProcess", "--domain", "api.example.com"], "direct"),
            ("baseline", ["--app", CHROME + ".unrelated/Contents/MacOS/worker", "--domain", "api.example.com"], "direct"),
            ("disabled_compound", ["--app", CHROME, "--domain", "api.example.com"], "usa"),
            ("disabled_compound", ["--process", "ChromeShared", "--domain", "api.example.com"], "direct"),
            ("disabled_fallback", ["--app", CHROME, "--domain", "elsewhere.invalid"], "direct"),
            ("disabled_fallback", ["--app", CHROME, "--domain", "api.example.com"], "japan"),
            ("selected_exit", ["--app", CHROME, "--domain", "api.example.com"], "usa"),
            ("selected_exit", ["--process", "ChromeShared", "--domain", "api.example.com"], "usa"),
            ("reordered", ["--app", CHROME, "--domain", "api.example.com"], "usa"),
            ("reordered", ["--app", CHROME, "--domain", "company.example"], "direct"),
        ]
        for name, flow, expected in flows:
            result = json.loads(run([args.rust, "explain", "-c", paths[name], "--json", *flow]))
            assert result["via"] == expected, f"{name}: {flow} expected {expected}, received {result}"
        first = json.loads(run([args.rust, "explain", "-c", paths["baseline"], "--json",
                                "--app", CHROME, "--domain", "api.example.com"]))
        reordered = json.loads(run([args.rust, "explain", "-c", paths["reordered"], "--json",
                                    "--app", CHROME, "--domain", "api.example.com"]))
        assert first["index"] == reordered["index"] == 2
    print(f"PASS: actual Swift whitelist conversion, {len(cases)} sing-box schema checks, "
          f"{len(flows)} routing decisions, compound import parity, disabled rules, "
          "selected exits, DNS and reorder. No TUN or network changes.")


if __name__ == "__main__":
    main()
