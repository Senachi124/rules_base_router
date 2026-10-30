//! Diagnostic client using only an ordinary encrypted UDP socket. It never installs
//! a TUN device, modifies routes/DNS, or uses a direct fallback for test traffic.
use routebar_core::{
    config::Profile,
    engine::{
        Engine, Event, HANDSHAKE, NETWORK, TCP_CLOSED, TCP_CONNECTED, TCP_DATA, TCP_EOF, UDP_DATA,
    },
};
use std::{
    net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

struct Session {
    engine: Engine,
    socket: UdpSocket,
    started: Instant,
    sent_packets: u64,
    received_packets: u64,
}
impl Session {
    fn pump(&mut self) -> Result<Vec<Event>, String> {
        self.engine.tick(self.started.elapsed().as_millis() as i64);
        let mut events = vec![];
        while let Some(event) = self.engine.pop_event() {
            if event.kind == NETWORK {
                self.socket
                    .send(&event.data)
                    .map_err(|_| "Unable to send encrypted UDP packet")?;
                self.sent_packets += 1;
            } else {
                events.push(event);
            }
        }
        if !events.is_empty() {
            return Ok(events);
        }
        let mut buffer = [0u8; 65536];
        match self.socket.recv(&mut buffer) {
            Ok(n) => {
                self.received_packets += 1;
                self.engine.receive(&buffer[..n]);
            }
            Err(e)
                if [std::io::ErrorKind::WouldBlock, std::io::ErrorKind::TimedOut]
                    .contains(&e.kind()) => {}
            Err(_) => return Err("VPN transport receive failed".into()),
        }
        Ok(events)
    }
    fn until(
        &mut self,
        seconds: u64,
        mut accept: impl FnMut(&mut Engine, Event) -> Result<bool, String>,
    ) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        while Instant::now() < deadline {
            for event in self.pump()? {
                if accept(&mut self.engine, event)? {
                    return Ok(());
                }
            }
        }
        Err(format!("Operation timed out (encrypted UDP packets sent: {}, received: {}, authenticated: {}); no direct fallback was attempted", self.sent_packets, self.received_packets, self.engine.authenticated_rx_count()))
    }
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
    trace_text: bool,
}

fn header(line: &str) -> Result<(&str, &str), &'static str> {
    let (name, value) = line.split_once(':').ok_or("Malformed HTTP header")?;
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        || value.bytes().any(|b| b.is_ascii_control() && b != b'\t')
    {
        return Err("Malformed HTTP header");
    }
    Ok((name, value.trim_matches([' ', '\t'])))
}

fn decode_chunks(mut input: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut body = Vec::new();
    loop {
        let end = input
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or("Truncated HTTP chunk header")?;
        let size = std::str::from_utf8(&input[..end]).map_err(|_| "Malformed HTTP chunk header")?;
        // This diagnostic deliberately supports plain chunk sizes only. Do not
        // interpret an unfamiliar extension as a successful trace response.
        if size.is_empty() || !size.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("Unsupported or malformed HTTP chunk header");
        }
        let size = usize::from_str_radix(size, 16).map_err(|_| "Invalid HTTP chunk size")?;
        input = &input[end + 2..];
        if size == 0 {
            // Validate (but never use or print) any trailer fields.
            loop {
                let end = input
                    .windows(2)
                    .position(|w| w == b"\r\n")
                    .ok_or("Truncated HTTP trailers")?;
                if end == 0 {
                    return if input.len() == 2 {
                        Ok(body)
                    } else {
                        Err("Unexpected bytes after HTTP body")
                    };
                }
                let line =
                    std::str::from_utf8(&input[..end]).map_err(|_| "Malformed HTTP trailer")?;
                let (name, _) = header(line)?;
                if name.eq_ignore_ascii_case("content-length")
                    || name.eq_ignore_ascii_case("transfer-encoding")
                {
                    return Err("Invalid HTTP framing trailer");
                }
                input = &input[end + 2..];
            }
        }
        if size > input.len().saturating_sub(2) || &input[size..size + 2] != b"\r\n" {
            return Err("Truncated or malformed HTTP chunk body");
        }
        body.extend_from_slice(&input[..size]);
        input = &input[size + 2..];
    }
}

fn parse_http_response(input: &[u8], orderly_eof: bool) -> Result<HttpResponse, &'static str> {
    if input.len() > 65536 {
        return Err("Diagnostic HTTP response too large");
    }
    let boundary = input
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("Incomplete HTTP response headers")?;
    let head =
        std::str::from_utf8(&input[..boundary]).map_err(|_| "Malformed HTTP response headers")?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or("Missing HTTP status")?;
    let bytes = status_line.as_bytes();
    if bytes.len() < 13
        || ![b"HTTP/1.0 ".as_slice(), b"HTTP/1.1 ".as_slice()].contains(&&bytes[..9])
        || !bytes[9..12].iter().all(u8::is_ascii_digit)
        || bytes[12] != b' '
        || bytes[13..].iter().any(|b| b.is_ascii_control())
    {
        return Err("Malformed or unsupported HTTP status");
    }
    let status = status_line[9..12].parse::<u16>().unwrap();
    if !(200..=599).contains(&status) {
        return Err("Expected a final HTTP response");
    }
    let mut length = None;
    let mut chunked = false;
    let mut trace_text = true;
    for line in lines {
        let (name, value) = header(line)?;
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err("Invalid or repeated HTTP Content-Length");
            }
            length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| "Invalid HTTP Content-Length")?,
            );
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !value.eq_ignore_ascii_case("chunked") {
                return Err("Unsupported or repeated HTTP Transfer-Encoding");
            }
            chunked = true;
        } else if name.eq_ignore_ascii_case("content-encoding")
            && !value.eq_ignore_ascii_case("identity")
        {
            trace_text = false;
        }
    }
    if chunked && length.is_some() {
        return Err("Ambiguous HTTP body framing");
    }
    if status == 204 && length.is_some() {
        return Err("Unexpected Content-Length for HTTP status");
    }
    let payload = &input[boundary + 4..];
    let body = if status == 204 || status == 304 {
        if !payload.is_empty() || chunked {
            return Err("Unexpected body for HTTP status");
        }
        Vec::new()
    } else if chunked {
        decode_chunks(payload)?
    } else if let Some(length) = length {
        if payload.len() != length {
            return Err("Incomplete or oversized HTTP body");
        }
        payload.to_vec()
    } else if orderly_eof {
        payload.to_vec()
    } else {
        return Err("HTTP connection closed before response completion");
    };
    Ok(HttpResponse {
        status,
        body,
        trace_text,
    })
}

fn egress_country(response: &HttpResponse) -> Option<&str> {
    if response.status != 200 || !response.trace_text {
        return None;
    }
    let body = std::str::from_utf8(&response.body).ok()?;
    let mut ips = body.lines().filter_map(|line| line.strip_prefix("ip="));
    ips.next()?.parse::<IpAddr>().ok()?;
    if ips.next().is_some() {
        return None;
    }
    let mut countries = body.lines().filter_map(|line| line.strip_prefix("loc="));
    let country = countries.next()?;
    if countries.next().is_some()
        || country.len() != 2
        || !country.bytes().all(|b| b.is_ascii_uppercase())
    {
        return None;
    }
    Some(country)
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .ok_or("Usage: routebar-check <WireGuard.conf> [--inspect]")?;
    let inspect = args.next().as_deref() == Some("--inspect");
    let text = Zeroizing::new(
        std::fs::read_to_string(path).map_err(|_| "Unable to read configuration file")?,
    );
    let profile = Profile::parse(&text)?;
    println!(
        "Configuration: PASS ({} address family/families, MTU {})",
        profile.addresses.len(),
        profile.mtu
    );
    if inspect {
        return Ok(());
    }
    let mut endpoints: Vec<SocketAddr> = (profile.endpoint_host.as_str(), profile.endpoint_port)
        .to_socket_addrs()
        .map_err(|_| "Unable to resolve VPN endpoint")?
        .collect();
    endpoints.sort_unstable();
    endpoints.dedup();
    endpoints.truncate(4);
    if endpoints.is_empty() {
        return Err("No address for VPN endpoint".into());
    }
    let dns = profile
        .dns
        .iter()
        .find(|ip| {
            profile
                .addresses
                .iter()
                .any(|a| a.addr().is_ipv4() == ip.is_ipv4())
        })
        .copied()
        .ok_or("Profile requires a DNS server for the UDP check")?;
    let mut selected = None;
    for (index, endpoint) in endpoints.iter().enumerate() {
        let bind = if endpoint.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind).map_err(|_| "Unable to create VPN transport socket")?;
        socket
            .connect(endpoint)
            .map_err(|_| "Unable to connect VPN transport")?;
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .map_err(|_| "Unable to set transport timeout")?;
        let mut session = Session {
            engine: Engine::new(Profile::parse(&text)?, false),
            socket,
            started: Instant::now(),
            sent_packets: 0,
            received_packets: 0,
        };
        session.engine.start();
        match session.until(20, |_, e| Ok(e.kind == HANDSHAKE)) {
            Ok(()) => {
                selected = Some(session);
                break;
            }
            Err(error) => eprintln!(
                "VPN endpoint candidate {}/{}: {error}",
                index + 1,
                endpoints.len()
            ),
        }
    }
    let mut session=selected.ok_or("No VPN endpoint completed an authenticated handshake. Verify the private key belongs to the registered WireGuard public key and UDP is reachable")?;
    println!("WireGuard authenticated handshake: PASS");

    let query: [u8; 29] = [
        0x52, 0x42, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3,
        b'c', b'o', b'm', 0, 0, 1, 0, 1,
    ];
    session.engine.open_udp(1)?;
    session.engine.udp_send(1, dns, 53, &query)?;
    session.until(10, |engine, e| {
        if e.kind != UDP_DATA || e.flow != 1 {
            return Ok(false);
        }
        let response = &e.data;
        if response.len() < 12
            || response[..2] != query[..2]
            || response[2] & 0x80 == 0
            || response[3] & 0x0f != 0
            || u16::from_be_bytes([response[6], response[7]]) == 0
        {
            return Err("DNS server returned an invalid/unsuccessful response".into());
        }
        engine.close(1);
        Ok(true)
    })?;
    println!("UDP DNS query through WireGuard: PASS");

    let target: SocketAddr = "1.1.1.1:80".parse().unwrap();
    session.engine.open_tcp(2, target.ip(), target.port())?;
    session.until(10, |_, e| {
        if e.kind == TCP_CLOSED && e.flow == 2 {
            Err("TCP connection closed before establishment".into())
        } else {
            Ok(e.kind == TCP_CONNECTED && e.flow == 2)
        }
    })?;
    let request=b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\nUser-Agent: RouteBar-Diagnostic/0.1\r\n\r\n";
    if session.engine.tcp_write(2, request)? != request.len() {
        return Err("Unexpected TCP backpressure for diagnostic request".into());
    }
    let mut response = vec![];
    let mut orderly_eof = false;
    session.until(15, |engine, e| {
        if e.flow != 2 {
            return Ok(false);
        }
        if e.kind == TCP_DATA {
            if response.len() + e.data.len() > 65536 {
                return Err("Diagnostic HTTP response too large".into());
            }
            response.extend(&e.data);
            engine.resume(2);
        }
        orderly_eof |= e.kind == TCP_EOF;
        Ok(orderly_eof || e.kind == TCP_CLOSED)
    })?;
    let response = parse_http_response(&response, orderly_eof)?;
    println!(
        "TCP HTTP request through WireGuard: PASS (HTTP {})",
        response.status
    );
    if let Some(country) = egress_country(&response) {
        println!("Exit-country lookup: PASS (egress country: {country})");
    } else {
        println!("Exit-country lookup: unavailable (HTTP response did not contain a usable trace)");
    }
    println!("System routes and DNS: unchanged; private keys: never logged");
    session.engine.close(2);
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("Check failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use boringtun::x25519::{PublicKey, StaticSecret};

    fn http(version: &str, status: u16, body: &str) -> Vec<u8> {
        format!(
            "{version} {status} Test\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    #[test]
    fn http_trace_accepts_both_versions_and_valid_ip_families() {
        for version in ["HTTP/1.0", "HTTP/1.1"] {
            for ip in ["192.0.2.1", "2001:db8::1"] {
                let bytes = http(version, 200, &format!("ip={ip}\nloc=JP\n"));
                let response = parse_http_response(&bytes, false).unwrap();
                assert_eq!(response.status, 200);
                assert_eq!(egress_country(&response), Some("JP"));
            }
        }
    }

    #[test]
    fn http_redirects_and_errors_prove_roundtrip_but_not_exit_country() {
        for status in [301, 403, 503] {
            let bytes = http("HTTP/1.1", status, "ip=192.0.2.1\nloc=JP\n");
            let response = parse_http_response(&bytes, false).unwrap();
            assert_eq!(response.status, status);
            assert_eq!(egress_country(&response), None);
        }
    }

    #[test]
    fn http_trace_uses_only_unencoded_body_and_valid_unambiguous_fields() {
        for body in [
            "loc=JP\n",
            "ip=invalid\nloc=JP\n",
            "ip=192.0.2.1\nloc=Japan\n",
            "ip=192.0.2.1\nip=192.0.2.2\nloc=JP\n",
            "ip=192.0.2.1\nloc=JP\nloc=US\n",
        ] {
            let response = parse_http_response(&http("HTTP/1.1", 200, body), true).unwrap();
            assert_eq!(egress_country(&response), None);
        }
        let header_only = b"HTTP/1.1 200 OK\r\nX-Trace: ip=192.0.2.1\r\n\r\nloc=JP\n";
        assert_eq!(
            egress_country(&parse_http_response(header_only, true).unwrap()),
            None
        );
        let encoded = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\nip=192.0.2.1\nloc=JP\n";
        assert_eq!(
            egress_country(&parse_http_response(encoded, true).unwrap()),
            None
        );
    }

    #[test]
    fn http_chunked_trace_is_reassembled_before_parsing() {
        // Split the ip= field across chunks, so searching raw bytes cannot pass.
        let bytes = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\ni\r\n13\r\np=192.0.2.1\nloc=JP\n\r\n0\r\nX-Note: complete\r\n\r\n";
        let response = parse_http_response(bytes, false).unwrap();
        assert_eq!(egress_country(&response), Some("JP"));
    }

    #[test]
    fn http_close_delimited_body_requires_orderly_eof() {
        let bytes = b"HTTP/1.0 200 OK\r\n\r\nip=192.0.2.1\nloc=JP\n";
        assert!(parse_http_response(bytes, false).is_err());
        assert_eq!(
            egress_country(&parse_http_response(bytes, true).unwrap()),
            Some("JP")
        );
    }

    #[test]
    fn http_rejects_malformed_truncated_and_ambiguous_responses() {
        for bytes in [
            b"not an HTTP response".as_slice(),
            b"HTTP/1.1 2000 Bad\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX-Bad\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabc",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nabc",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabc\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nextra",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFFF\r\n",
        ] {
            assert!(parse_http_response(bytes, true).is_err());
        }
    }

    fn profile(secret: u8, peer: u8, ip: &str) -> Profile {
        let public = PublicKey::from(&StaticSecret::from([peer; 32]));
        Profile::parse(&format!("[Interface]\nPrivateKey={}\nAddress={ip}/24\n[Peer]\nPublicKey={}\nEndpoint=127.0.0.1:51820\nAllowedIPs=10.0.0.0/24",STANDARD.encode([secret;32]),STANDARD.encode(public.as_bytes()))).unwrap()
    }
    #[test]
    fn cli_transport_authenticates_against_loopback_udp_peer() {
        let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_address = server_socket.local_addr().unwrap();
        server_socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let server = std::thread::spawn(move || {
            let mut engine = Engine::new(profile(2, 1, "10.0.0.1"), true);
            let started = Instant::now();
            let mut buffer = [0u8; 65536];
            while started.elapsed() < Duration::from_secs(3) {
                if let Ok((length, remote)) = server_socket.recv_from(&mut buffer) {
                    engine.receive(&buffer[..length]);
                    while let Some(event) = engine.pop_event() {
                        if event.kind == NETWORK {
                            server_socket.send_to(&event.data, remote).unwrap();
                        }
                    }
                    if engine.is_ready() && buffer[0] == 4 {
                        return;
                    }
                }
            }
            panic!("synthetic server handshake timed out");
        });
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.connect(server_address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let mut session = Session {
            engine: Engine::new(profile(1, 2, "10.0.0.2"), false),
            socket,
            started: Instant::now(),
            sent_packets: 0,
            received_packets: 0,
        };
        session.engine.start();
        session.until(3, |_, e| Ok(e.kind == HANDSHAKE)).unwrap();
        assert!(
            session.sent_packets > 0
                && session.received_packets > 0
                && session.engine.authenticated_rx_count() > 0
        );
        server.join().unwrap();
    }
}
