"""Offline Windows CLI -> actual sing-box checks; never starts a TUN/VPN."""
import base64
import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--app-directory", type=Path, default=ROOT / "build/RouteBar-windows-x64")
CLI = parser.parse_args().app_directory.resolve() / "routebar-v2.exe"
ENGINE = CLI.with_name("sing-box.exe")


def call(*args, ok=True):
    result = subprocess.run([str(CLI), *map(str, args)], capture_output=True,
                            text=True, encoding="utf-8", timeout=30)
    if ok:
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)
    assert result.returncode != 0, "invalid input was accepted"
    return result.stderr


def main():
    private = base64.b64encode(bytes(range(1, 33))).decode()
    public = base64.b64encode(bytes(range(32))).decode()
    shared = base64.b64encode(bytes(range(2, 34))).decode()
    with tempfile.TemporaryDirectory(prefix="RouteBar spaces 測試 ") as directory:
        folder = Path(directory)
        profile = folder / "synthetic profile.conf"
        profile.write_text(f"[Interface]\nPrivateKey = {private}\nAddress = 10.14.0.2/16\n"
                           f"[Peer]\nPublicKey = {public}\nPresharedKey = {shared}\n"
                           "Endpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0\n", encoding="utf-8")
        app = r"C:\Program Files\Example Browser\browser.exe"
        config = {
            "version": 1, "vpns": {"work": {"wireguard_config": profile.name}},
            "dns": {"server": "9.9.9.9", "via": "work", "strategy": "ipv4_only"},
            "routing": {"default": "direct", "rules": [
                {"name": "Exception", "match": {"domain_suffixes": ["company.example"]}, "via": "direct"},
                {"name": "Compound", "match": {"apps": [app], "process_names": ["curl.exe"],
                    "domain_suffixes": ["example.org"], "ip_cidrs": ["203.0.113.0/24"]}, "via": "work"},
            ]},
        }
        source = folder / "source.json"
        source.write_text(json.dumps(config), encoding="utf-8")
        inspected = call("config-inspect", "-c", source)
        assert Path(inspected["vpns"]["work"]["wireguard_config"]) == profile
        # The distributable default template contains rules only, never real keys.
        preset = folder / "config.example.yaml"
        preset.write_bytes((ROOT / "windows/config.example.yaml").read_bytes())
        (folder / "vm1.conf").write_bytes(profile.read_bytes())
        defaults = call("config-inspect", "-c", preset)
        assert defaults["routing"]["default"] == "direct" and defaults["dns"]["via"] == "vm1"
        assert len(defaults["routing"]["rules"]) == 1
        assert call("validate", "-c", preset)["valid"]
        for process in ("ChatGPT.exe", "codex.exe", "codex-code-mode-host.exe"):
            assert call("explain", "-c", preset, "--process", process, "--domain", "example.org")["via"] == "vm1"
        for process in ("chrome.exe", "msedge.exe", "curl.exe", "python.exe", "git.exe"):
            assert call("explain", "-c", preset, "--process", process, "--domain", "example.org")["via"] == "direct"
        assert call("validate", "-c", source, "--engine", ENGINE)["valid"]
        for flow, expected in [
            (["--app", app.lower(), "--domain", "sub.example.org"], "work"),
            (["--app", app.replace("\\", "/"), "--domain", "example.org"], "work"),
            (["--app", app, "--domain", "company.example"], "direct"),
            (["--app", app + ".evil", "--domain", "example.org"], "direct"),
            (["--process", "curl.exe", "--ip", "203.0.113.17"], "work"),
            (["--process", "curl.exe", "--domain", "notexample.org"], "direct"),
            (["--process", "other.exe", "--domain", "example.org"], "direct"),
        ]:
            assert call("explain", "-c", source, *flow)["via"] == expected
        generated = call("render", "-c", source)
        serialized = json.dumps(generated)
        assert private not in serialized and shared not in serialized
        assert generated["inbounds"][0]["strict_route"] is True
        assert generated["dns"]["servers"][1]["detour"] == "work"
        assert generated["endpoints"][0]["detour"] == "vpnctl-transport"
        transport = next(o for o in generated["outbounds"] if o["tag"] == "vpnctl-transport")
        assert transport["type"] == "direct" and transport["domain_resolver"] == "vpnctl-bootstrap"
        route = next(r for r in generated["route"]["rules"] if r.get("outbound") == "work")
        pattern = route["rules"][0]["rules"][0]["process_path_regex"][0]
        assert re.fullmatch(pattern, app.lower())
        assert not re.fullmatch(pattern, app + ".evil")
        output = folder / "private engine.json"
        call("render", "-c", source, "--output", output)
        unredacted = output.read_text(encoding="utf-8")
        assert private in unredacted and shared in unredacted
        subprocess.run([str(ENGINE), "check", "-c", str(output)], check=True, capture_output=True, timeout=20)
        assert "overwrite" in call("render", "-c", source, "--output", profile, ok=False)
        assert "overwrite" in call("render", "-c", source, "--output", source, ok=False)
        assert call("render", "-c", source, "--output", output)["contains_private_keys"]  # atomic replacement
        acl = subprocess.run(["icacls.exe", str(output)], capture_output=True, timeout=10)
        assert acl.returncode == 0 and b"(I)" not in acl.stdout
        before = source.read_bytes()
        for args in [("up",), ("validate", "-c", source, "--config", source),
                     ("explain", "-c", source, "--app", "relative.exe"),
                     ("explain", "-c", source, "--domain", "https://example.org")]:
            call(*args, ok=False)
        assert source.read_bytes() == before
        profile.write_text(profile.read_text(encoding="utf-8") + "PostUp = whoami\n", encoding="utf-8")
        error = call("validate", "-c", source, ok=False)
        assert private not in error and shared not in error
    print("Windows integration passed: paths, rules, DNS, secrets, ACLs, engine schema, rejected inputs.")


if __name__ == "__main__":
    main()
