use crate::{config::Profile, device::MemoryDevice};
use boringtun::{
    noise::{Tunn, TunnResult},
    x25519::{PublicKey, StaticSecret},
};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    socket::{tcp, udp},
    time::{Duration, Instant},
    wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint},
};
use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
};

pub const NETWORK: u32 = 1;
pub const TCP_CONNECTED: u32 = 2;
pub const TCP_DATA: u32 = 3;
pub const TCP_CLOSED: u32 = 4;
pub const UDP_DATA: u32 = 5;
pub const RAW_IP: u32 = 6;
pub const HANDSHAKE: u32 = 7;
pub const ERROR: u32 = 8;
pub const TCP_EOF: u32 = 9;
const MAX_FLOWS: usize = 256;
const MAX_PENDING_EVENTS: usize = 4096;
const MAX_PENDING_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug)]
pub struct Event {
    pub kind: u32,
    pub flow: u64,
    pub address: String,
    pub port: u16,
    pub data: Vec<u8>,
}
impl Event {
    fn bytes(kind: u32, flow: u64, data: Vec<u8>) -> Self {
        Self {
            kind,
            flow,
            address: String::new(),
            port: 0,
            data,
        }
    }
}
/// The host must regularly drain events. An unresponsive host fails closed rather
/// than allowing network input or a full tunnel producer to grow memory forever.
struct EventBuffer {
    queue: VecDeque<Event>,
    bytes: usize,
    overflowed: bool,
}
impl EventBuffer {
    fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            bytes: 0,
            overflowed: false,
        }
    }
    fn push_back(&mut self, event: Event) {
        if self.overflowed {
            return;
        }
        if self.queue.len() >= MAX_PENDING_EVENTS
            || self.bytes.saturating_add(event.data.len()) > MAX_PENDING_BYTES
        {
            self.queue.clear();
            self.bytes = 0;
            self.overflowed = true;
            self.queue.push_back(Event::bytes(
                ERROR,
                0,
                b"Core event queue exhausted; tunnel stopped".to_vec(),
            ));
            return;
        }
        self.bytes += event.data.len();
        self.queue.push_back(event);
    }
    fn pop_front(&mut self) -> Option<Event> {
        self.queue.pop_front().inspect(|e| {
            self.bytes = self.bytes.saturating_sub(e.data.len());
        })
    }
}
struct Flow {
    handle: SocketHandle,
    tcp: bool,
    connected: bool,
    readable: bool,
    eof_sent: bool,
    last_active: i64,
}

/// Single-threaded engine. The host serializes calls and owns the encrypted UDP socket.
/// No platform routing changes, host sockets, logging of keys, or direct fallback happen here.
pub struct Engine {
    profile: Profile,
    tunnel: Tunn,
    device: MemoryDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    flows: HashMap<u64, Flow>,
    events: EventBuffer,
    now: i64,
    next_port: u16,
    raw: bool,
    handshaken: bool,
    authenticated_rx: u64,
}

impl Engine {
    pub fn new(profile: Profile, raw: bool) -> Self {
        let tunnel = Tunn::new(
            StaticSecret::from(profile.private_key),
            PublicKey::from(profile.peer_key),
            profile.preshared_key,
            Some(profile.keepalive),
            rand::random::<u32>() >> 8,
            None,
        );
        let mut device = MemoryDevice {
            received: VecDeque::new(),
            sent: VecDeque::new(),
            mtu: profile.mtu as usize,
        };
        let mut cfg = Config::new(HardwareAddress::Ip);
        cfg.random_seed = rand::random();
        let mut iface = Interface::new(cfg, &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|list| {
            for addr in &profile.addresses {
                list.push(IpCidr::new(IpAddress::from(addr.addr()), addr.prefix_len()))
                    .expect("two interface addresses fit");
            }
        });
        // Medium::Ip has no ARP: use our local address as the default-route next hop.
        for addr in &profile.addresses {
            match addr.addr() {
                IpAddr::V4(a) => {
                    let _ = iface.routes_mut().add_default_ipv4_route(a);
                }
                IpAddr::V6(a) => {
                    let _ = iface.routes_mut().add_default_ipv6_route(a);
                }
            }
        }
        Self {
            profile,
            tunnel,
            device,
            iface,
            sockets: SocketSet::new(vec![]),
            flows: HashMap::new(),
            events: EventBuffer::new(),
            now: 0,
            next_port: 49152,
            raw,
            handshaken: false,
            authenticated_rx: 0,
        }
    }

    pub fn pop_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }
    pub fn is_ready(&self) -> bool {
        self.handshaken
            && !self.events.overflowed
            && self.tunnel.time_since_last_handshake().is_some()
    }
    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }
    pub fn authenticated_rx_count(&self) -> u64 {
        self.authenticated_rx
    }
    pub fn handshake_age(&self) -> Option<u64> {
        self.tunnel.time_since_last_handshake().map(|d| d.as_secs())
    }
    pub fn start(&mut self) {
        if self.events.overflowed {
            return;
        }
        let mut buf = vec![0u8; 65536];
        if let TunnResult::WriteToNetwork(data) =
            self.tunnel.format_handshake_initiation(&mut buf, false)
        {
            self.events
                .push_back(Event::bytes(NETWORK, 0, data.to_vec()));
        }
    }
    pub fn receive(&mut self, encrypted: &[u8]) {
        if encrypted.is_empty() || encrypted.len() > 65535 || self.events.overflowed {
            return;
        }
        let mut buf = vec![0u8; 65536];
        let mut input = encrypted;
        for _ in 0..256 {
            match self.tunnel.decapsulate(None, input, &mut buf) {
                TunnResult::WriteToNetwork(data) => {
                    // A cookie response is not proof of peer authentication. Only a
                    // successful handshake response/init, or authenticated transport, counts.
                    if input.first() == Some(&2) || (input.first() == Some(&1) && data.len() == 92)
                    {
                        self.authenticated_rx = self.authenticated_rx.saturating_add(1);
                    }
                    self.events
                        .push_back(Event::bytes(NETWORK, 0, data.to_vec()));
                }
                TunnResult::WriteToTunnelV4(data, source) => {
                    self.authenticated_rx = self.authenticated_rx.saturating_add(1);
                    if self
                        .profile
                        .allowed_ips
                        .iter()
                        .any(|net| net.contains(&IpAddr::V4(source)))
                    {
                        self.accept_packet(data.to_vec());
                    }
                    break;
                }
                TunnResult::WriteToTunnelV6(data, source) => {
                    self.authenticated_rx = self.authenticated_rx.saturating_add(1);
                    if self
                        .profile
                        .allowed_ips
                        .iter()
                        .any(|net| net.contains(&IpAddr::V6(source)))
                    {
                        self.accept_packet(data.to_vec());
                    }
                    break;
                }
                TunnResult::Done => {
                    if input.first() == Some(&4) {
                        self.authenticated_rx = self.authenticated_rx.saturating_add(1);
                    }
                    break;
                }
                _ => break,
            }
            input = &[];
        }
        if !self.handshaken && self.tunnel.time_since_last_handshake().is_some() {
            self.handshaken = true;
            self.events.push_back(Event::bytes(HANDSHAKE, 0, vec![]));
        }
        self.poll();
    }
    fn accept_packet(&mut self, data: Vec<u8>) {
        if self.raw {
            self.events.push_back(Event::bytes(RAW_IP, 0, data));
        } else if self.device.received.len() < 512 {
            self.device.received.push_back(data);
        }
    }
    fn encapsulate(&mut self, packet: &[u8]) {
        let mut buffer = vec![0u8; packet.len().saturating_add(256).max(65536)];
        if let TunnResult::WriteToNetwork(data) = self.tunnel.encapsulate(packet, &mut buffer) {
            self.events
                .push_back(Event::bytes(NETWORK, 0, data.to_vec()));
        }
    }
    pub fn feed_ip(&mut self, packet: &[u8]) -> Result<(), String> {
        self.ensure_running()?;
        if !self.raw || packet.len() > self.profile.mtu as usize {
            return Err("Invalid packet for tunnel".into());
        }
        let dest = Tunn::dst_address(packet).ok_or("Invalid IP packet")?;
        self.check_destination(dest)?;
        self.encapsulate(packet);
        Ok(())
    }
    fn check_destination(&self, ip: IpAddr) -> Result<(), String> {
        self.ensure_running()?;
        if !self
            .profile
            .addresses
            .iter()
            .any(|a| a.addr().is_ipv4() == ip.is_ipv4())
        {
            return Err("This profile has no address for the requested IP family".into());
        }
        if !self.profile.allowed_ips.iter().any(|a| a.contains(&ip)) {
            return Err("Destination is outside the peer AllowedIPs".into());
        }
        Ok(())
    }
    fn ensure_running(&self) -> Result<(), String> {
        if self.events.overflowed {
            Err("Core event queue exhausted; recreate the tunnel".into())
        } else {
            Ok(())
        }
    }
    fn allocate_port(&mut self) -> Result<u16, String> {
        for _ in 0..16384 {
            let port = self.next_port;
            self.next_port = if port == 65535 { 49152 } else { port + 1 };
            let used = self.flows.values().any(|f| {
                if f.tcp {
                    self.sockets
                        .get::<tcp::Socket>(f.handle)
                        .local_endpoint()
                        .map(|e| e.port)
                        == Some(port)
                } else {
                    self.sockets.get::<udp::Socket>(f.handle).endpoint().port == port
                }
            });
            if !used {
                return Ok(port);
            }
        }
        Err("No free source ports".into())
    }
    pub fn open_tcp(&mut self, id: u64, ip: IpAddr, port: u16) -> Result<(), String> {
        self.check_destination(ip)?;
        if self.raw || port == 0 || self.flows.contains_key(&id) || self.flows.len() >= MAX_FLOWS {
            return Err("Cannot open flow".into());
        }
        let local_port = self.allocate_port()?;
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 65536]),
            tcp::SocketBuffer::new(vec![0; 65536]),
        );
        socket.set_timeout(Some(Duration::from_secs(60)));
        socket.set_keep_alive(Some(Duration::from_secs(30)));
        socket
            .connect(
                self.iface.context(),
                IpEndpoint::new(ip.into(), port),
                local_port,
            )
            .map_err(|_| "TCP connect failed")?;
        let handle = self.sockets.add(socket);
        self.flows.insert(
            id,
            Flow {
                handle,
                tcp: true,
                connected: false,
                readable: true,
                eof_sent: false,
                last_active: self.now,
            },
        );
        self.poll();
        Ok(())
    }
    pub fn tcp_write(&mut self, id: u64, data: &[u8]) -> Result<usize, String> {
        self.ensure_running()?;
        let flow = self
            .flows
            .get_mut(&id)
            .filter(|f| f.tcp)
            .ok_or("Unknown TCP flow")?;
        let socket = self.sockets.get_mut::<tcp::Socket>(flow.handle);
        if !flow.connected {
            return Ok(0);
        }
        let n = socket.send_slice(data).map_err(|_| "TCP send closed")?;
        flow.last_active = self.now;
        self.poll();
        Ok(n)
    }
    pub fn tcp_eof(&mut self, id: u64) {
        if let Some(f) = self.flows.get(&id).filter(|f| f.tcp) {
            self.sockets.get_mut::<tcp::Socket>(f.handle).close();
        }
        self.poll();
    }
    pub fn resume(&mut self, id: u64) {
        if let Some(f) = self.flows.get_mut(&id) {
            f.readable = true;
        }
        self.poll();
    }
    pub fn open_udp(&mut self, id: u64) -> Result<(), String> {
        self.ensure_running()?;
        if self.raw || self.flows.contains_key(&id) || self.flows.len() >= MAX_FLOWS {
            return Err("Cannot open UDP flow".into());
        }
        let port = self.allocate_port()?;
        let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0; 65536]);
        let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0; 65536]);
        let mut socket = udp::Socket::new(rx, tx);
        socket.bind(port).map_err(|_| "UDP bind failed")?;
        let handle = self.sockets.add(socket);
        self.flows.insert(
            id,
            Flow {
                handle,
                tcp: false,
                connected: true,
                readable: true,
                eof_sent: false,
                last_active: self.now,
            },
        );
        Ok(())
    }
    pub fn udp_send(
        &mut self,
        id: u64,
        ip: IpAddr,
        port: u16,
        data: &[u8],
    ) -> Result<usize, String> {
        self.check_destination(ip)?;
        // No IP fragmentation in v0.1. Fail explicitly instead of silently dropping large datagrams.
        let header = if ip.is_ipv4() { 28 } else { 48 };
        if data.len() + header > self.profile.mtu as usize || port == 0 {
            return Err("UDP datagram exceeds tunnel MTU".into());
        }
        let f = self
            .flows
            .get_mut(&id)
            .filter(|f| !f.tcp)
            .ok_or("Unknown UDP flow")?;
        let socket = self.sockets.get_mut::<udp::Socket>(f.handle);
        if !socket.can_send() {
            return Ok(0);
        }
        socket
            .send_slice(data, IpEndpoint::new(ip.into(), port))
            .map_err(|_| "UDP buffer full")?;
        f.last_active = self.now;
        self.poll();
        Ok(data.len())
    }
    pub fn close(&mut self, id: u64) {
        if let Some(f) = self.flows.remove(&id) {
            if f.tcp {
                self.sockets.get_mut::<tcp::Socket>(f.handle).abort();
                self.iface.poll(
                    Instant::from_millis(self.now),
                    &mut self.device,
                    &mut self.sockets,
                );
            }
            self.sockets.remove(f.handle);
        }
        self.flush_packets();
    }
    pub fn tick(&mut self, now: i64) {
        if self.events.overflowed {
            return;
        }
        self.now = self.now.max(now);
        let mut buffer = vec![0u8; 65536];
        if let TunnResult::WriteToNetwork(data) = self.tunnel.update_timers(&mut buffer) {
            self.events
                .push_back(Event::bytes(NETWORK, 0, data.to_vec()));
        }
        self.poll();
    }
    fn poll(&mut self) {
        if self.raw || self.events.overflowed {
            return;
        }
        self.iface.poll(
            Instant::from_millis(self.now),
            &mut self.device,
            &mut self.sockets,
        );
        let mut closed = vec![];
        for (&id, f) in &mut self.flows {
            if f.tcp {
                let socket = self.sockets.get_mut::<tcp::Socket>(f.handle);
                if !f.connected && socket.may_send() {
                    f.connected = true;
                    f.last_active = self.now;
                    self.events
                        .push_back(Event::bytes(TCP_CONNECTED, id, vec![]));
                }
                if f.readable && socket.can_recv() {
                    let mut bytes = vec![0; 16384];
                    if let Ok(n) = socket.recv_slice(&mut bytes) {
                        bytes.truncate(n);
                        f.readable = false;
                        f.last_active = self.now;
                        self.events.push_back(Event::bytes(TCP_DATA, id, bytes));
                    }
                }
                if f.connected && f.readable && !socket.may_recv() && !f.eof_sent {
                    f.eof_sent = true;
                    self.events.push_back(Event::bytes(TCP_EOF, id, vec![]));
                }
                if socket.state() == tcp::State::Closed
                    || (!f.connected && self.now - f.last_active > 30000)
                {
                    closed.push(id);
                }
            } else {
                let socket = self.sockets.get_mut::<udp::Socket>(f.handle);
                if f.readable && socket.can_recv() {
                    if let Ok((bytes, metadata)) = socket.recv() {
                        self.events.push_back(Event {
                            kind: UDP_DATA,
                            flow: id,
                            address: metadata.endpoint.addr.to_string(),
                            port: metadata.endpoint.port,
                            data: bytes.to_vec(),
                        });
                        f.readable = false;
                        f.last_active = self.now;
                    }
                }
                if self.now - f.last_active > 120000 {
                    closed.push(id);
                }
            }
        }
        self.flush_packets();
        for id in closed {
            self.close(id);
            self.events.push_back(Event::bytes(TCP_CLOSED, id, vec![]));
        }
    }
    fn flush_packets(&mut self) {
        while let Some(packet) = self.device.sent.pop_front() {
            self.encapsulate(&packet);
        }
    }
}
