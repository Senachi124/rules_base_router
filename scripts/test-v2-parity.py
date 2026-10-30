#!/usr/bin/env python3
"""Compare Rust v2 against the reference CLI and exercise DNS on loopback only."""
import argparse
import base64
import copy
import json
import os
import pathlib
import signal
import socket
import struct
import subprocess
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run(args):
    p = subprocess.run([str(x) for x in args], capture_output=True, text=True, timeout=25)
    if p.returncode:
        raise AssertionError(f"{args[1]} failed: {p.stderr}")
    return p.stdout


def query(port, kind):
    request = struct.pack('!6H', 0x1234, 0x100, 1, 0, 0, 0)
    request += b'\x04test\x07invalid\x00' + struct.pack('!HH', kind, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(.3)
        s.sendto(request, ('127.0.0.1', port))
        return s.recv(4096)


def check_dns(engine, generated, strategy, directory):
    dns = copy.deepcopy(generated['dns'])
    dns['servers'] = [{'type': 'hosts', 'tag': 'test-hosts', 'predefined': {
        'test.invalid': ['192.0.2.7', '2001:db8::7']}}]
    dns['final'] = 'test-hosts'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
        reserve.bind(('127.0.0.1', 0))
        port = reserve.getsockname()[1]
    doc = {'log': {'disabled': True}, 'dns': dns,
           'inbounds': [{'type': 'direct', 'tag': 'dns-test', 'listen': '127.0.0.1',
                         'listen_port': port, 'network': 'udp'}],
           'outbounds': [{'type': 'direct', 'tag': 'direct'}],
           'route': {'rules': [{'inbound': ['dns-test'], 'action': 'hijack-dns'}]}}
    path = directory / 'dns.json'
    path.write_text(json.dumps(doc))
    process = subprocess.Popen([str(engine), 'run', '-c', str(path)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 5
        while True:
            try:
                query(port, 1)
                break
            except (TimeoutError, OSError):
                if time.monotonic() > deadline:
                    raise AssertionError('DNS loopback listener did not become ready')
        expected = [(1, int(strategy != 'ipv6_only')), (28, int(strategy != 'ipv4_only'))]
        if strategy in ('ipv4_only', 'ipv6_only'):
            expected += [(64, 0), (65, 0)]
        for kind, count in expected:
            response = query(port, kind)
            assert response[3] & 15 == 0, f'DNS {strategy} {kind}: rcode'
            assert struct.unpack('!H', response[6:8])[0] == count, f'DNS {strategy} {kind}: answers'
    finally:
        process.send_signal(signal.SIGINT)
        try:
            process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()


def main():
    parser = argparse.ArgumentParser()
    bundled = ROOT / 'build/RouteBar.app/Contents/MacOS'
    parser.add_argument('--rust', type=pathlib.Path, default=bundled / 'routebar-v2')
    parser.add_argument('--reference', type=pathlib.Path, required=True,
                        help='Path to the separately built Go vpnctl reference executable')
    parser.add_argument('--engine', type=pathlib.Path, default=bundled / 'sing-box')
    args = parser.parse_args()
    for binary in [args.rust, args.reference, args.engine]:
        if not os.access(binary, os.X_OK):
            parser.error(f'Executable missing: {binary}; build it or supply its path')
    with tempfile.TemporaryDirectory(prefix='routebar-parity-') as tmp:
        directory = pathlib.Path(tmp)
        for name, address, allowed in [('v4', '10.14.0.2/16', '0.0.0.0/0'),
                                       ('v6', 'fd00::2/128', '::/0'),
                                       ('dual', '10.14.0.2/16, fd00::2/128', '0.0.0.0/0, ::/0')]:
            private = base64.b64encode(bytes(range(1, 33))).decode()
            public = base64.b64encode(bytes(range(32))).decode()
            profile = directory / f'{name}.conf'
            profile.write_text(f'[Interface]\nPrivateKey = {private}\nAddress = {address}\nDNS = 1.1.1.1\n'
                               f'[Peer]\nPublicKey = {public}\nEndpoint = 192.0.2.1:51820\nAllowedIPs = {allowed}\n')
            profile.chmod(0o600)
        rules = [
            {'name': 'exception', 'match': {'domain_suffixes': ['company.example']}, 'via': 'direct'},
            {'name': 'app', 'match': {'apps': ['/Applications/Browser.app']}, 'via': 'japan'},
            {'name': 'dest', 'match': {'domains': ['api.example.com'], 'domain_suffixes': ['example.org'],
                                     'ip_cidrs': ['203.0.113.73/24']}, 'via': 'japan'},
            {'name': 'combined', 'match': {'apps': ['/usr/bin/curl'], 'process_names': ['wget'],
                                         'domains': ['conditional.example']}, 'via': 'japan'}]
        cases = []
        for family in ('v4', 'v6', 'dual'):
            for default in ('direct', 'japan'):
                cases.append({'version': 1, 'vpns': {'japan': {'wireguard_config': f'{family}.conf'}},
                              'dns': {'via': 'japan'}, 'routing': {'default': default, 'rules': rules}})
        for strategy in ('ipv4_only', 'ipv6_only', 'prefer_ipv4', 'prefer_ipv6'):
            cases.append({'version': 1, 'vpns': {'japan': {'wireguard_config': 'v4.conf'},
                                                'other': {'wireguard_config': 'v6.conf'}},
                          'dns': {'strategy': strategy}, 'routing': {'rules': rules}})
        cases.append({'version': 1})
        for index, config in enumerate(cases):
            path = directory / 'config.yaml'
            path.write_text(json.dumps(config))
            rust = json.loads(run([args.rust, 'render', '-c', path]))
            reference = json.loads(run([args.reference, 'render', '-c', path]))
            assert rust == reference, f'Generated configuration differs in case {index}'
            run([args.rust, 'validate', '-c', path, '--engine', args.engine])
            if index in (0, 2, 4):
                check_dns(args.engine, rust, rust['dns']['strategy'], directory)
        path.write_text(json.dumps(cases[0]))
        flows = [
            ['--app', '/Applications/Browser.app', '--domain', 'company.example'],
            ['--app', '/Applications/Browser.app/Contents/Helpers/worker'],
            ['--app', '/Applications/Browser.app.evil/Contents/worker'],
            ['--app', '/usr/bin/curl', '--domain', 'conditional.example'],
            ['--process', 'wget', '--domain', 'conditional.example'],
            ['--process', 'other', '--domain', 'conditional.example'],
            ['--domain', 'EXAMPLE.ORG.'], ['--domain', 'notexample.org'],
            ['--domain', 'api.example.com'], ['--domain', 'sub.api.example.com'],
            ['--ip', '203.0.113.90'], ['--ip', '203.0.114.90']]
        for flow in flows:
            rust = json.loads(run([args.rust, 'explain', '-c', path, '--json', *flow]))
            reference = run([args.reference, 'explain', '-c', path, *flow])
            assert f"via: {rust['via']}\nrule: {rust['rule']}\n" in reference, f'Explain differs: {flow}'
    print(f'PASS: {len(cases)} exact generated-config comparisons + engine schema checks; '
          f'{len(flows)} routing decisions; three live loopback DNS family policies. No TUN or external VPN started.')


if __name__ == '__main__':
    main()
