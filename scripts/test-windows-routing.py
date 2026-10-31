"""Real engine loopback routing regression; no TUN, VPN, or external traffic.

The generated Codex preset is exercised with real client process names. Replace
only the remote VPN endpoint with a loopback-capable direct test outbound and
simulate interface availability in the guard. This verifies ordered routing and
IPv6 preservation, not Windows TUN pre-match or a real WireGuard handshake.
"""
import argparse
import base64
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]

CLIENT = r'''
using System;
using System.Net;
using System.Net.Sockets;
class Probe {
    static byte[] Read(NetworkStream s, int n) {
        byte[] b = new byte[n]; int p = 0;
        while (p < n) { int k = s.Read(b, p, n-p); if (k == 0) throw new Exception("EOF"); p += k; }
        return b;
    }
    static int Main(string[] a) {
        try {
            using (TcpClient c = new TcpClient()) {
                c.Connect("127.0.0.1", int.Parse(a[0]));
                NetworkStream s = c.GetStream(); s.ReadTimeout = 3000; s.WriteTimeout = 3000;
                s.Write(new byte[] {5,1,0}, 0, 3);
                byte[] greeting = Read(s,2);
                if (greeting[0] != 5 || greeting[1] != 0) throw new Exception("SOCKS greeting");
                byte[] ip = IPAddress.Parse(a[1]).GetAddressBytes();
                byte[] request = new byte[6+ip.Length]; request[0]=5; request[1]=1;
                request[3]=(byte)(ip.Length == 16 ? 4 : 1); Array.Copy(ip,0,request,4,ip.Length);
                int port = int.Parse(a[2]); request[4+ip.Length]=(byte)(port >> 8); request[5+ip.Length]=(byte)port;
                s.Write(request,0,request.Length);
                byte[] reply = Read(s,4);
                if (reply[1] != 0) return 2;
                if (reply[3] == 1) Read(s,6);
                else if (reply[3] == 4) Read(s,18);
                else { int size=Read(s,1)[0]; Read(s,size+2); }
                s.WriteByte(42);
                return s.ReadByte() == 42 ? 0 : 3;
            }
        } catch { return 2; }
    }
}
'''


class Echo:
    def __init__(self, family, address):
        self.socket = socket.socket(family)
        self.socket.bind((address, 0))
        self.socket.listen()
        self.socket.settimeout(0.2)
        self.port = self.socket.getsockname()[1]
        self.stopped = threading.Event()
        self.worker = threading.Thread(target=self.run, daemon=True)
        self.worker.start()

    def run(self):
        while not self.stopped.is_set():
            try:
                client, _ = self.socket.accept()
                with client:
                    client.settimeout(3)
                    data = client.recv(1)
                    if data:
                        client.sendall(data)
            except (TimeoutError, OSError):
                pass

    def close(self):
        self.stopped.set()
        self.socket.close()
        self.worker.join(timeout=4)


def simulate_interface(rule, available):
    if isinstance(rule, dict):
        if "default_interface_address" in rule:
            # The existing NOT/OR logic stays intact. Match the loopback client
            # source for available, an impossible test source for unavailable.
            del rule["default_interface_address"]
            rule["source_ip_cidr"] = ["127.0.0.0/8" if available else "192.0.2.0/24"]
        for value in rule.values():
            simulate_interface(value, available)
    elif isinstance(rule, list):
        for item in rule:
            simulate_interface(item, available)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-directory", type=Path, required=True)
    parser.add_argument("--check-current-ipv6-unavailable", action="store_true",
                        help="Also check the actual monitored interface; only use on a host known to lack direct IPv6")
    args = parser.parse_args()
    cli = args.app_directory.resolve() / "routebar-v2.exe"
    engine = cli.with_name("sing-box.exe")
    compiler = Path(os.environ["WINDIR"]) / "Microsoft.NET/Framework64/v4.0.30319/csc.exe"
    with tempfile.TemporaryDirectory(prefix="RouteBar-routing-") as directory:
        folder = Path(directory)
        key = base64.b64encode(bytes(range(1, 33))).decode()
        (folder / "vm1.conf").write_text(
            f"[Interface]\nPrivateKey = {key}\nAddress = 10.77.10.2/32, fd42:77:10::2/128\n"
            f"[Peer]\nPublicKey = {key}\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n",
            encoding="utf-8")
        config_path = folder / "config.yaml"
        config_path.write_bytes((ROOT / "windows/config.example.yaml").read_bytes())
        result = subprocess.run([str(cli), "render", "-c", str(config_path)],
                                capture_output=True, text=True, check=True, timeout=20)
        generated = json.loads(result.stdout)
        assert not any(r.get("action") == "sniff" for r in generated["route"]["rules"])
        assert generated["dns"]["strategy"] == "prefer_ipv4"
        assert generated["dns"]["servers"][1]["detour"] == "vm1"
        inspected = subprocess.run([str(cli), "config-inspect", "-c", str(config_path)],
                                   capture_output=True, text=True, check=True, timeout=20)
        exception = json.loads(inspected.stdout)
        exception["routing"] = {"default": "vm1", "rules": [
            {"name": "browser-direct", "match": {"process_names": ["chrome.exe"]}, "via": "direct"}]}
        exception_path = folder / "exception.json"
        exception_path.write_text(json.dumps(exception), encoding="utf-8")
        result = subprocess.run([str(cli), "render", "-c", str(exception_path)],
                                capture_output=True, text=True, check=True, timeout=20)
        explicit_generated = json.loads(result.stdout)
        # No generated private key is written or remote peer contacted.
        for config in (generated, explicit_generated):
            del config["endpoints"]
            config["outbounds"].append({"type": "direct", "tag": "vm1",
                "inet4_bind_address": "127.0.0.1", "inet6_bind_address": "::1"})
            config["route"]["auto_detect_interface"] = False
        source = folder / "Probe.cs"
        source.write_text(CLIENT, encoding="utf-8")
        subprocess.run([str(compiler), "/nologo", "/target:exe", "/platform:x64",
                        f"/out:{folder / 'chrome.exe'}", str(source)], check=True, capture_output=True)
        clients = ("chrome.exe", "ChatGPT.exe", "codex.exe", "codex-code-mode-host.exe")
        for name in clients[1:]:
            (folder / name).write_bytes((folder / clients[0]).read_bytes())
        v4 = Echo(socket.AF_INET, "127.0.0.1")
        v6 = Echo(socket.AF_INET6, "::1")
        checks = 0
        try:
            for available in ((False, True, None) if args.check_current_ipv6_unavailable else (False, True)):
                for explicit_direct in (False, True):
                    config = copy.deepcopy(explicit_generated if explicit_direct else generated)
                    # Test both direct fallback after VPN exceptions and an
                    # explicit direct exception ahead of a default VPN.
                    if available is not None:
                        simulate_interface(config["route"]["rules"], available)
                    with socket.socket() as port_socket:
                        port_socket.bind(("127.0.0.1", 0))
                        port = port_socket.getsockname()[1]
                    config["inbounds"] = [{"type": "mixed", "tag": "test-only",
                                            "listen": "127.0.0.1", "listen_port": port}]
                    path = folder / "engine.json"
                    path.write_text(json.dumps(config), encoding="utf-8")
                    with (folder / "engine.log").open("w", encoding="utf-8") as log:
                        process = subprocess.Popen([str(engine), "run", "-c", str(path)],
                                                   stdout=log, stderr=log,
                                                   creationflags=subprocess.CREATE_NO_WINDOW)
                        try:
                            deadline = time.monotonic() + 8
                            while True:
                                if process.poll() is not None:
                                    raise AssertionError((folder / "engine.log").read_text(encoding="utf-8"))
                                try:
                                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                                        break
                                except OSError:
                                    if time.monotonic() > deadline:
                                        raise AssertionError("test engine startup timeout")
                                    time.sleep(0.05)
                            for name in clients:
                                for address, echo in (("127.0.0.1", v4), ("::1", v6)):
                                    expected = 2 if name == "chrome.exe" and address == "::1" and not available else 0
                                    previous_log = (folder / "engine.log").stat().st_size
                                    probe = subprocess.run([str(folder / name), str(port), address, str(echo.port)],
                                                           capture_output=True, timeout=8)
                                    assert probe.returncode == expected, (
                                        name, address, available, explicit_direct, probe.returncode,
                                        (folder / "engine.log").read_text(encoding="utf-8"))
                                    if expected == 0:
                                        destination = "direct" if name == "chrome.exe" else "vm1"
                                        new_log = (folder / "engine.log").read_bytes()[previous_log:].decode("utf-8")
                                        assert f"outbound/direct[{destination}]" in new_log, (name, new_log)
                                    checks += 1
                        finally:
                            process.terminate()
                            process.wait(timeout=8)
        finally:
            v4.close()
            v6.close()
    print(f"Loopback routing passed: {checks} real-engine probes; IPv4, IPv6, Codex processes, direct guards.")


if __name__ == "__main__":
    main()
