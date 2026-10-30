use super::{
    network::{NetworkPlan, NetworkState},
    state::{self, Store},
    utun::Utun,
};
use routebar_core::{
    config::Profile,
    engine::{Engine, ERROR, NETWORK, RAW_IP},
};
use serde::Serialize;
use std::{
    collections::VecDeque,
    fs::File,
    io::{self, Read, Write},
    net::{SocketAddr, ToSocketAddrs, UdpSocket},
    os::unix::{
        io::AsRawFd,
        net::{UnixListener, UnixStream},
    },
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn stop_signal(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

fn signals() -> Result<(), String> {
    STOP.store(false, Ordering::Relaxed);
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGTSTP] {
        // SAFETY: handler only sets a lock-free atomic; no pointers are retained.
        let result =
            unsafe { libc::signal(signal, stop_signal as *const () as libc::sighandler_t) };
        if result == libc::SIG_ERR {
            return Err("Cannot install shutdown signal handler".into());
        }
    }
    // SAFETY: ignore SIGPIPE so a disconnected control client cannot kill the VPN.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    Ok(())
}

fn read_profile(path: &str) -> Result<Zeroizing<String>, String> {
    let file = File::open(path).map_err(|_| "Cannot read configuration file")?;
    if !file
        .metadata()
        .map_err(|_| "Cannot inspect configuration file")?
        .is_file()
    {
        return Err("Configuration must be a regular file".into());
    }
    let mut text = Zeroizing::new(String::new());
    file.take(65537)
        .read_to_string(&mut text)
        .map_err(|_| "Cannot read configuration text")?;
    if text.len() > 65536 {
        return Err("Configuration is too large".into());
    }
    Ok(text)
}

fn endpoints(profile: &Profile) -> Result<Vec<SocketAddr>, String> {
    let mut addresses: Vec<_> = (profile.endpoint_host.as_str(), profile.endpoint_port)
        .to_socket_addrs()
        .map_err(|_| "Cannot resolve VPN endpoint")?
        .collect();
    addresses.sort_unstable();
    addresses.dedup();
    addresses.truncate(4);
    if addresses.is_empty() {
        return Err("VPN endpoint resolved to no addresses".into());
    }
    Ok(addresses)
}

struct Transport {
    engine: Engine,
    socket: UdpSocket,
    started: Instant,
    last_auth: Instant,
    authenticated: u64,
    sent: u64,
    received: u64,
    raw_sent: u64,
    raw_received: u64,
    dropped: u64,
    // Datagram writes can temporarily block. Never allow unbounded producer queues.
    encrypted: VecDeque<Vec<u8>>,
    decrypted: VecDeque<Vec<u8>>,
}

impl Transport {
    fn new(profile: Profile, endpoint: SocketAddr) -> Result<Self, String> {
        let socket = UdpSocket::bind(if endpoint.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .map_err(|_| "Cannot create encrypted UDP transport")?;
        socket
            .connect(endpoint)
            .map_err(|_| "Cannot connect encrypted UDP transport")?;
        socket
            .set_nonblocking(true)
            .map_err(|_| "Cannot configure UDP transport")?;
        let now = Instant::now();
        Ok(Self {
            engine: Engine::new(profile, true),
            socket,
            started: now,
            last_auth: now,
            authenticated: 0,
            sent: 0,
            received: 0,
            raw_sent: 0,
            raw_received: 0,
            dropped: 0,
            encrypted: VecDeque::new(),
            decrypted: VecDeque::new(),
        })
    }

    fn events(&mut self) -> Result<(), String> {
        while let Some(event) = self.engine.pop_event() {
            let queue = match event.kind {
                NETWORK => &mut self.encrypted,
                RAW_IP => &mut self.decrypted,
                ERROR => return Err("WireGuard core stopped; restoring network settings".into()),
                _ => continue,
            };
            if queue.len() >= 256 {
                return Err("Tunnel packet queue exhausted".into());
            }
            queue.push_back(event.data);
        }
        let authenticated = self.engine.authenticated_rx_count();
        if authenticated != self.authenticated {
            self.authenticated = authenticated;
            self.last_auth = Instant::now();
        }
        Ok(())
    }

    fn pump(&mut self, tun: Option<&Utun>) -> Result<(), String> {
        self.engine.tick(self.started.elapsed().as_millis() as i64);
        let mut packet = [0u8; 65536];
        // Bound work in each direction so shutdown and control requests remain responsive.
        for _ in 0..128 {
            match self.socket.recv(&mut packet) {
                Ok(n) => {
                    self.received += 1;
                    self.engine.receive(&packet[..n]);
                    self.events()?;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err("Encrypted UDP receive failed".into()),
            }
        }
        if let Some(tun) = tun {
            for _ in 0..128 {
                match tun.read_packet(&mut packet) {
                    Ok(n) => {
                        // Missing IP families and destinations outside AllowedIPs are dropped.
                        // No packet ever has a direct fallback path.
                        if self.engine.feed_ip(&packet[..n]).is_ok() {
                            self.raw_sent += 1;
                        } else {
                            self.dropped += 1;
                        }
                        self.events()?;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                        self.dropped += 1;
                    }
                    Err(_) => return Err("Cannot read utun packets".into()),
                }
            }
            while let Some(packet) = self.decrypted.front() {
                match tun.write_packet(packet) {
                    Ok(()) => {
                        self.decrypted.pop_front();
                        self.raw_received += 1;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => return Err("Cannot write utun packets".into()),
                }
            }
        }
        self.events()?;
        while let Some(packet) = self.encrypted.front() {
            match self.socket.send(packet) {
                Ok(n) if n == packet.len() => {
                    self.encrypted.pop_front();
                    self.sent += 1;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                _ => return Err("Encrypted UDP send failed".into()),
            }
        }
        Ok(())
    }

    fn handshake(&mut self) -> Result<(), String> {
        self.engine.start();
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline && !STOP.load(Ordering::Relaxed) {
            self.pump(None)?;
            if self.engine.is_ready() {
                return Ok(());
            }
            wait(self.socket.as_raw_fd(), None);
        }
        Err(if STOP.load(Ordering::Relaxed) {
            "Stopped before routing changed"
        } else {
            "WireGuard handshake timed out; system routes and DNS unchanged"
        }
        .into())
    }
}

fn wait(udp: i32, tun: Option<i32>) {
    let mut fds = [
        libc::pollfd {
            fd: udp,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: tun.unwrap_or(-1),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    // SAFETY: fds points to two initialized pollfd entries valid for this call.
    unsafe {
        libc::poll(fds.as_mut_ptr(), 2, 20);
    }
}

#[derive(Serialize)]
struct Status<'a> {
    state: &'a str,
    interface: &'a str,
    uptime_seconds: u64,
    handshake_age_seconds: Option<u64>,
    last_authenticated_packet_seconds: u64,
    encrypted_packets_sent: u64,
    encrypted_packets_received: u64,
    tunneled_packets_sent: u64,
    tunneled_packets_received: u64,
    dropped_packets: u64,
}

fn read_control_request(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_millis(100);
    stream.set_nonblocking(true)?;
    let result = (|| {
        let mut request = Vec::new();
        while request.len() < 16 && Instant::now() < deadline {
            let mut byte = [0u8; 1];
            match stream.read(&mut byte) {
                Ok(0) => break,
                Ok(_) => {
                    request.push(byte[0]);
                    if byte[0] == b'\n' {
                        return Ok(request);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    let mut fd = libc::pollfd {
                        fd: stream.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let ms = deadline
                        .saturating_duration_since(Instant::now())
                        .as_millis()
                        .max(1) as i32;
                    // SAFETY: fd is one live pollfd, and timeout is at most 100 ms.
                    if unsafe { libc::poll(&mut fd, 1, ms) } < 0 {
                        let error = io::Error::last_os_error();
                        if error.kind() != io::ErrorKind::Interrupted {
                            return Err(error);
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Incomplete or oversized control command",
        ))
    })();
    stream.set_nonblocking(false)?;
    result
}

fn serve(listener: &UnixListener, transport: &Transport, tun: &Utun) -> Option<UnixStream> {
    for _ in 0..8 {
        let Ok((mut stream, _)) = listener.accept() else {
            break;
        };
        let _ = stream.set_write_timeout(Some(Duration::from_millis(100)));
        let Ok(request) = read_control_request(&mut stream) else {
            continue;
        };
        match request.as_slice() {
            b"stop\n" => {
                STOP.store(true, Ordering::Relaxed);
                return Some(stream);
            }
            b"status\n" => {
                let value = Status {
                    state: "running",
                    interface: tun.name(),
                    uptime_seconds: transport.started.elapsed().as_secs(),
                    handshake_age_seconds: transport.engine.handshake_age(),
                    last_authenticated_packet_seconds: transport.last_auth.elapsed().as_secs(),
                    encrypted_packets_sent: transport.sent,
                    encrypted_packets_received: transport.received,
                    tunneled_packets_sent: transport.raw_sent,
                    tunneled_packets_received: transport.raw_received,
                    dropped_packets: transport.dropped,
                };
                if let Ok(bytes) = serde_json::to_vec_pretty(&value) {
                    let _ = stream.write_all(&bytes);
                }
            }
            _ => {
                let _ = stream.write_all(b"Invalid command\n");
            }
        }
    }
    None
}

fn control(command: &str) -> Result<(), String> {
    state::require_root()?;
    state::check_runtime_directory()?;
    let mut stream = UnixStream::connect(state::SOCKET).map_err(|_| {
        "No running RouteBar VPN control socket; use `recover` after an unclean exit"
    })?;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|_| "Cannot configure control socket")?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| "Cannot configure control socket")?;
    stream
        .write_all(if command == "down" {
            b"stop\n"
        } else {
            b"status\n"
        })
        .map_err(|_| "Cannot send control request")?;
    let mut response = String::new();
    stream
        .take(8192)
        .read_to_string(&mut response)
        .map_err(|_| "Control request timed out; inspect the foreground process")?;
    if response.is_empty() {
        return Err("No control response; inspect `recover` status".into());
    }
    println!("{response}");
    if response.starts_with("Recovery required") {
        return Err("Network restoration incomplete; run `recover`".into());
    }
    Ok(())
}

fn recover() -> Result<(), String> {
    let store = Store::acquire()?;
    if !store.has_journal() {
        store.clear_socket()?;
        println!("No pending network recovery");
        return Ok(());
    }
    let mut network = store.load()?;
    let name =
        std::ffi::CString::new(network.interface_name()).map_err(|_| "Invalid saved interface")?;
    // SAFETY: name is a valid NUL-terminated C string.
    if unsafe { libc::if_nametoindex(name.as_ptr()) } != 0 {
        return Err(
            "Saved utun interface still exists; refusing recovery to avoid altering another tunnel"
                .into(),
        );
    }
    network.rollback(&mut |s| store.save(s))?;
    if !network.is_clean() {
        return Err("Network recovery remains incomplete".into());
    }
    store.clear_journal()?;
    store.clear_socket()?;
    println!("Network settings restored");
    Ok(())
}

fn up(text: &str, profile: &Profile, candidates: &[SocketAddr]) -> Result<(), String> {
    let store = Store::acquire()?;
    if store.has_journal() {
        return Err("Pending recovery journal; run `sudo routebar-vpn recover` first".into());
    }
    signals()?;
    let mut selected = None;
    for (index, endpoint) in candidates.iter().enumerate() {
        if STOP.load(Ordering::Relaxed) {
            return Err("Stopped before routing changed".into());
        }
        let plan = NetworkPlan::discover(profile, *endpoint)?;
        let mut transport = Transport::new(Profile::parse(text)?, *endpoint)?;
        println!(
            "Authenticating WireGuard endpoint {}/{} before changing routes...",
            index + 1,
            candidates.len()
        );
        match transport.handshake() {
            Ok(()) => {
                selected = Some((plan, transport));
                break;
            }
            Err(error) => eprintln!("{error}"),
        }
    }
    let (plan, mut transport) =
        selected.ok_or("No authenticated endpoint; system routes and DNS unchanged")?;
    if STOP.load(Ordering::Relaxed) {
        return Err("Stopped before routing changed".into());
    }
    let tun = Utun::create().map_err(|_| "Cannot create macOS utun; run this CLI with sudo")?;
    let mut network = NetworkState::new(tun.name())?;
    store.clear_socket()?;
    let listener = UnixListener::bind(state::SOCKET).map_err(|_| "Cannot create control socket")?;
    listener
        .set_nonblocking(true)
        .map_err(|_| "Cannot configure control socket")?;
    let mut stop_client = None;
    // Always attempt rollback, including during a Rust unwind. SIGKILL/power loss
    // still requires the durable recovery journal; this is not a crash kill switch.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<(), String> {
        store.save(&network)?;
        if STOP.load(Ordering::Relaxed) { return Err("Stopped before routing changed".into()); }
        plan.apply(&mut network, &mut |s| {
            store.save(s)?;
            if STOP.load(Ordering::Relaxed) { Err("Startup cancelled; restoring network settings".into()) }
            else { Ok(()) }
        })?;
        println!("RouteBar VPN running on {}. Keep this terminal open; Ctrl-C stops and restores network settings.", tun.name());
        let mut checked = Instant::now();
        while !STOP.load(Ordering::Relaxed) {
            transport.pump(Some(&tun))?;
            if let Some(client) = serve(&listener, &transport, &tun) { stop_client = Some(client); }
            if checked.elapsed() >= Duration::from_secs(2) {
                if !plan.underlay_unchanged()? { return Err("Underlying network changed; stopping and restoring settings. Restart on the new network.".into()); }
                checked = Instant::now();
            }
            wait(transport.socket.as_raw_fd(), Some(tun.as_raw_fd()));
        }
        Ok(())
    })).unwrap_or_else(|_| Err("Tunnel stopped unexpectedly; attempting network restoration".into()));
    let restored = network.rollback(&mut |s| store.save(s));
    drop(tun);
    drop(listener);
    let cleared = store.clear_socket();
    let cleanup = restored.and_then(|_| {
        if !network.is_clean() {
            return Err("Network recovery remains incomplete".into());
        }
        if store.has_journal() {
            store.clear_journal()?;
        }
        Ok(())
    });
    if let Some(mut stream) = stop_client {
        let reply = if cleanup.is_ok() {
            b"Stopped; network settings restored\n".as_slice()
        } else {
            b"Recovery required; run sudo routebar-vpn recover\n".as_slice()
        };
        let _ = stream.write_all(reply);
    }
    cleanup
        .map_err(|e| format!("{e}; recovery journal preserved. Run `sudo routebar-vpn recover`"))?;
    cleared.map_err(|e| {
        format!(
            "Network restored, but {e}. Run `sudo routebar-vpn recover` to clear the stale socket"
        )
    })?;
    println!("RouteBar stopped; network settings restored");
    result
}

pub fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [command] if command == "status" || command == "down" => control(command),
        [command] if command == "recover" => recover(),
        [command, path] if command == "plan" || command == "up" => {
            if command == "up" {
                state::require_root()?;
            }
            let text = read_profile(path)?;
            let profile = Profile::parse(&text)?;
            let addresses = endpoints(&profile)?;
            if command == "plan" {
                let plan = NetworkPlan::discover(&profile, addresses[0])?;
                println!(
                    "Read-only plan; no routes or DNS changed:\n{}",
                    serde_json::to_string_pretty(&plan).map_err(|_| "Cannot encode plan")?
                );
                Ok(())
            } else {
                up(&text, &profile, &addresses)
            }
        }
        _ => {
            println!("Usage:\n  routebar-vpn plan <WireGuard.conf>\n  sudo routebar-vpn up <WireGuard.conf>\n  sudo routebar-vpn status\n  sudo routebar-vpn down\n  sudo routebar-vpn recover\n\nmacOS only. `up` runs in the foreground. Stop other VPNs first. No WireGuard app or Apple Developer signing required. Local/more-specific routes may remain outside the tunnel; no process-crash kill switch.");
            if args.is_empty() || args == ["--help"] || args == ["-h"] {
                Ok(())
            } else {
                Err("Invalid arguments".into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use boringtun::x25519::{PublicKey, StaticSecret};

    #[test]
    fn control_handles_fragmented_and_rejects_unterminated_requests() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let sender = std::thread::spawn(move || {
            client.write_all(b"sta").unwrap();
            std::thread::sleep(Duration::from_millis(5));
            client.write_all(b"tus\n").unwrap();
        });
        assert_eq!(read_control_request(&mut server).unwrap(), b"status\n");
        sender.join().unwrap();
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client.write_all(b"status").unwrap();
        drop(client);
        assert!(read_control_request(&mut server).is_err());
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client.write_all(b"01234567890123456\n").unwrap();
        assert!(read_control_request(&mut server).is_err());
    }

    fn profile(secret: u8, peer: u8, address: &str) -> Profile {
        let public = PublicKey::from(&StaticSecret::from([peer; 32]));
        Profile::parse(&format!("[Interface]\nPrivateKey={}\nAddress={address}/32\n[Peer]\nPublicKey={}\nEndpoint=127.0.0.1:51820\nAllowedIPs=0.0.0.0/0", STANDARD.encode([secret; 32]), STANDARD.encode(public.as_bytes()))).unwrap()
    }

    #[test]
    fn raw_transport_roundtrip_uses_authenticated_udp_without_system_routes() {
        let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        server_socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let endpoint = server_socket.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut engine = Engine::new(profile(2, 1, "10.0.0.1"), true);
            let started = Instant::now();
            let mut packet = [0u8; 65536];
            while started.elapsed() < Duration::from_secs(3) {
                if let Ok((n, remote)) = server_socket.recv_from(&mut packet) {
                    engine.receive(&packet[..n]);
                    let mut replied = false;
                    while let Some(event) = engine.pop_event() {
                        if event.kind == NETWORK {
                            server_socket.send_to(&event.data, remote).unwrap();
                        }
                        if event.kind == RAW_IP {
                            let mut reply = event.data;
                            assert_eq!(&reply[20..], &[1, 2, 3, 4]);
                            reply[12..16].copy_from_slice(&[10, 0, 0, 1]);
                            reply[16..20].copy_from_slice(&[10, 0, 0, 2]);
                            engine.feed_ip(&reply).unwrap();
                            replied = true;
                        }
                    }
                    if replied {
                        return;
                    }
                }
            }
            panic!("Raw packet server timed out");
        });
        let mut client = Transport::new(profile(1, 2, "10.0.0.2"), endpoint).unwrap();
        client.handshake().unwrap();
        let mut packet = vec![
            0x45, 0, 0, 24, 0, 1, 0, 0, 64, 253, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1, 1, 2, 3, 4,
        ];
        let mut checksum: u32 = packet[..20]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u16::from_be_bytes([p[0], p[1]]) as u32)
            .sum();
        while checksum > 0xffff {
            checksum = (checksum & 0xffff) + (checksum >> 16);
        }
        packet[10..12].copy_from_slice(&(!(checksum as u16)).to_be_bytes());
        client.engine.feed_ip(&packet).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while client.decrypted.is_empty() && Instant::now() < deadline {
            client.pump(None).unwrap();
            wait(client.socket.as_raw_fd(), None);
        }
        let response = client
            .decrypted
            .pop_front()
            .expect("authenticated raw IP reply");
        assert_eq!(&response[12..20], &[10, 0, 0, 1, 10, 0, 0, 2]);
        assert_eq!(&response[20..], &[1, 2, 3, 4]);
        assert!(client.authenticated > 0 && client.sent > 0 && client.received > 0);
        server.join().unwrap();
    }
}
