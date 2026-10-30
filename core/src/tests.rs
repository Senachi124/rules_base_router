use crate::{config::Profile, device::MemoryDevice, engine::*, policy::*};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use boringtun::x25519::{PublicKey, StaticSecret};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    socket::{tcp, udp},
    time::Instant,
    wire::{HardwareAddress, IpCidr},
};
use std::{
    collections::VecDeque,
    ffi::{CStr, CString},
};

fn config(secret: u8, other: u8, address: &str) -> String {
    let peer = PublicKey::from(&StaticSecret::from([other; 32]));
    format!("[Interface]\nPrivateKey = {}\nAddress = {address}\nDNS = 1.1.1.1\n[Peer]\nPublicKey = {}\nEndpoint = 127.0.0.1:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n", STANDARD.encode([secret; 32]), STANDARD.encode(peer.as_bytes()))
}

#[test]
fn config_rejects_malformed_and_never_exposes_private_key() {
    let text = config(1, 2, "10.0.0.2/24");
    let private = STANDARD.encode([1; 32]);
    let profile = Profile::parse(&text).unwrap();
    let summary = serde_json::to_string(&profile.summary()).unwrap();
    assert!(!summary.contains(&private));
    assert!(!summary.contains("private"));
    for bad in [
        text.replace(&private, "bad-key"),
        text.replace("51820", "0"),
        text.replace("10.0.0.2/24", "nonsense"),
        format!("{text}\n[Peer]\n"),
        text.replace("DNS =", "PreUp ="),
        text.replace("DNS =", "PrivateKey ="),
        text.replace("DNS = 1.1.1.1", "MTU = 9000"),
    ] {
        let error = Profile::parse(&bad).err().expect("must reject");
        assert!(!error.contains(&private));
    }
    assert!(Profile::parse(&"x".repeat(65537)).is_err());
    for endpoint in [
        "https://vpn.example.com:51820",
        "vpn.example.com/path:51820",
        "[::1:51820",
        "::1:51820",
        "vpn example.com:51820",
    ] {
        assert!(Profile::parse(&text.replace("127.0.0.1:51820", endpoint)).is_err());
    }
    assert_eq!(
        Profile::parse(&text.replace("127.0.0.1:51820", "[::1]:51820"))
            .unwrap()
            .endpoint_host,
        "::1"
    );
    let secret_field = format!("[Interface]\n{private}=value");
    assert!(!Profile::parse(&secret_field)
        .err()
        .unwrap()
        .contains(&private));
}

fn policy() -> Policy {
    Policy {
        mode: "whitelist".into(),
        apps: vec![AppRule {
            id: "a".into(),
            name: "Browser".into(),
            path: "/Applications/Browser.app".into(),
            enabled: true,
            identities: vec![AppIdentity {
                signing_id: "org.browser".into(),
                team_id: "TEAM1".into(),
            }],
        }],
        domains: vec![DomainRule {
            id: "d".into(),
            domain: "example.com".into(),
            enabled: true,
        }],
    }
}
#[test]
fn policy_domain_boundaries_and_team_identity() {
    let mut p = policy();
    p.validate().unwrap();
    for host in ["example.com", "WWW.Example.COM.", "a.b.example.com"] {
        assert_eq!(
            p.evaluate(&FlowIdentity {
                hostname: Some(host.into()),
                ..Default::default()
            })
            .route,
            "vpn"
        );
    }
    for host in [
        "evil-example.com",
        "example.com.evil.org",
        "notexample.com",
        "example.com:443",
        "https://example.com",
    ] {
        assert_eq!(
            p.evaluate(&FlowIdentity {
                hostname: Some(host.into()),
                ..Default::default()
            })
            .route,
            "direct"
        );
    }
    assert_eq!(
        p.evaluate(&FlowIdentity {
            signing_id: "org.browser".into(),
            team_id: "TEAM1".into(),
            hostname: None
        })
        .route,
        "vpn"
    );
    assert_eq!(
        p.evaluate(&FlowIdentity {
            signing_id: "org.browser".into(),
            team_id: "SPOOF".into(),
            hostname: None
        })
        .route,
        "direct"
    );
    p.apps[0].enabled = false;
    p.domains[0].enabled = false;
    assert_eq!(
        p.evaluate(&FlowIdentity {
            signing_id: "org.browser".into(),
            team_id: "TEAM1".into(),
            hostname: Some("example.com".into())
        })
        .route,
        "direct"
    );
    p.mode = "full".into();
    assert_eq!(p.evaluate(&FlowIdentity::default()).route, "vpn");
}
#[test]
fn domain_normalization_validates_syntax() {
    assert_eq!(normalize_domain(" *.EXAMPLE.com. ").unwrap(), "example.com");
    assert_eq!(
        normalize_domain("例子.香港").unwrap(),
        "xn--fsqu00a.xn--j6w193g"
    );
    for s in [
        "",
        "com",
        "127.0.0.1",
        "a..com",
        "-a.com",
        "a-.com",
        "https://a.com",
        "a.com/path",
        "a.com:443",
    ] {
        assert!(normalize_domain(s).is_err(), "{s}");
    }
}
#[test]
fn ffi_null_inputs_and_allocations_are_safe() {
    unsafe {
        let output = crate::ffi::rb_profile_inspect(std::ptr::null());
        assert!(CStr::from_ptr(output)
            .to_str()
            .unwrap()
            .contains("Missing input"));
        crate::ffi::rb_string_free(output);
        crate::ffi::rb_string_free(std::ptr::null_mut());
        assert_eq!(crate::ffi::rb_engine_start(std::ptr::null_mut()), -1);
        let profile = CString::new(config(1, 2, "10.0.0.2/24")).unwrap();
        let engine = crate::ffi::rb_engine_new(profile.as_ptr(), false);
        assert!(!engine.is_null());
        assert_eq!(
            crate::ffi::rb_engine_receive(engine, std::ptr::null(), 1),
            -1
        );
        assert_eq!(
            crate::ffi::rb_engine_receive(engine, std::ptr::null(), 0),
            0
        );
        crate::ffi::rb_engine_free(engine);
    }
}

struct Pair {
    client: Engine,
    server: Engine,
    device: MemoryDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    tcp: SocketHandle,
    udp: SocketHandle,
    now: i64,
    events: Vec<Event>,
    echoed: Vec<u8>,
    close_after_eof: bool,
}
impl Pair {
    fn new() -> Self {
        let client = Engine::new(
            Profile::parse(&config(1, 2, "10.0.0.2/24, fd00::2/64")).unwrap(),
            false,
        );
        let server = Engine::new(
            Profile::parse(&config(2, 1, "10.0.0.1/24, fd00::1/64")).unwrap(),
            true,
        );
        let mut device = MemoryDevice {
            received: VecDeque::new(),
            sent: VecDeque::new(),
            mtu: 1280,
        };
        let mut cfg = Config::new(HardwareAddress::Ip);
        cfg.random_seed = 7;
        let mut iface = Interface::new(cfg, &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|a| {
            a.push("10.0.0.1/24".parse::<IpCidr>().unwrap()).unwrap();
            a.push("fd00::1/64".parse().unwrap()).unwrap();
        });
        let mut sockets = SocketSet::new(vec![]);
        let mut tcp = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 65536]),
            tcp::SocketBuffer::new(vec![0; 65536]),
        );
        tcp.listen(8080).unwrap();
        let tcp = sockets.add(tcp);
        let mut udp = udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0; 65536]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0; 65536]),
        );
        udp.bind(5353).unwrap();
        let udp = sockets.add(udp);
        Self {
            client,
            server,
            device,
            iface,
            sockets,
            tcp,
            udp,
            now: 0,
            events: vec![],
            echoed: vec![],
            close_after_eof: false,
        }
    }
    fn step(&mut self) {
        self.now += 10;
        self.client.tick(self.now);
        self.server.tick(self.now);
        for _ in 0..8 {
            while let Some(event) = self.client.pop_event() {
                if event.kind == NETWORK {
                    self.server.receive(&event.data);
                } else {
                    self.events.push(event);
                }
            }
            while let Some(event) = self.server.pop_event() {
                match event.kind {
                    NETWORK => self.client.receive(&event.data),
                    RAW_IP => self.device.received.push_back(event.data),
                    _ => {}
                }
            }
            self.iface.poll(
                Instant::from_millis(self.now),
                &mut self.device,
                &mut self.sockets,
            );
            let udp = self.sockets.get_mut::<udp::Socket>(self.udp);
            if let Ok((data, meta)) = udp.recv() {
                let data = data.to_vec();
                udp.send_slice(&data, meta).unwrap();
            }
            let tcp = self.sockets.get_mut::<tcp::Socket>(self.tcp);
            if tcp.can_recv() && tcp.can_send() {
                let mut bytes = vec![0; 4096];
                let n = tcp.recv_slice(&mut bytes).unwrap();
                bytes.truncate(n);
                self.echoed.extend(&bytes);
                assert_eq!(tcp.send_slice(&bytes).unwrap(), n);
            }
            if self.close_after_eof && tcp.state() == tcp::State::CloseWait && !tcp.can_recv() {
                tcp.close();
            }
            self.iface.poll(
                Instant::from_millis(self.now),
                &mut self.device,
                &mut self.sockets,
            );
            while let Some(packet) = self.device.sent.pop_front() {
                self.server.feed_ip(&packet).unwrap();
            }
        }
    }
    fn handshake(&mut self) {
        self.client.start();
        for _ in 0..10 {
            self.step();
        }
        assert!(self.client.is_ready());
        assert!(self.server.is_ready());
    }
}

#[test]
fn encrypted_tcp_roundtrip_backpressure_and_halfclose() {
    let mut p = Pair::new();
    p.handshake();
    p.client
        .open_tcp(1, "10.0.0.1".parse().unwrap(), 8080)
        .unwrap();
    for _ in 0..10 {
        p.step();
    }
    assert!(p.events.iter().any(|e| e.kind == TCP_CONNECTED));
    p.events.clear();
    let payload: Vec<u8> = (0..150000).map(|i| (i % 251) as u8).collect();
    let mut sent = 0;
    let mut received = vec![];
    let mut saw_backpressure = false;
    for _ in 0..3000 {
        if sent < payload.len() {
            let n = p.client.tcp_write(1, &payload[sent..]).unwrap();
            if n < payload.len() - sent {
                saw_backpressure = true;
            }
            sent += n;
        }
        p.step();
        for event in std::mem::take(&mut p.events) {
            if event.kind == TCP_DATA {
                received.extend(event.data);
                p.client.resume(1);
            }
        }
        if received.len() == payload.len() {
            break;
        }
    }
    assert!(saw_backpressure);
    assert_eq!(received, payload);
    assert_eq!(p.echoed, payload);
    p.close_after_eof = true;
    p.client.tcp_eof(1);
    for _ in 0..100 {
        p.step();
    }
    assert!(p.events.iter().any(|e| e.kind == TCP_EOF));
}
#[test]
fn encrypted_udp_ipv4_and_ipv6_and_read_backpressure() {
    let mut p = Pair::new();
    p.handshake();
    p.client.open_udp(7).unwrap();
    for ip in ["10.0.0.1", "fd00::1"] {
        p.client
            .udp_send(7, ip.parse().unwrap(), 5353, b"encrypted echo")
            .unwrap();
        for _ in 0..20 {
            p.step();
        }
        let event = p.events.iter().find(|e| e.kind == UDP_DATA).unwrap();
        assert_eq!(event.data, b"encrypted echo");
        assert_eq!(event.address, ip);
        p.events.clear();
        p.client.resume(7);
    }
    p.client
        .udp_send(7, "10.0.0.1".parse().unwrap(), 5353, b"one")
        .unwrap();
    p.client
        .udp_send(7, "10.0.0.1".parse().unwrap(), 5353, b"two")
        .unwrap();
    for _ in 0..20 {
        p.step();
    }
    assert_eq!(p.events.iter().filter(|e| e.kind == UDP_DATA).count(), 1);
    p.events.clear();
    p.client.resume(7);
    p.step();
    assert_eq!(p.events.iter().filter(|e| e.kind == UDP_DATA).count(), 1);
}
#[test]
fn malformed_and_replayed_wireguard_do_not_count_as_liveness() {
    let mut p = Pair::new();
    p.handshake();
    let before = p.client.authenticated_rx_count();
    for length in 0..256 {
        p.client.receive(&vec![0x42; length]);
    }
    assert_eq!(p.client.authenticated_rx_count(), before);
    p.client.open_udp(1).unwrap();
    p.client
        .udp_send(1, "10.0.0.1".parse().unwrap(), 5353, b"test")
        .unwrap();
    while let Some(event) = p.client.pop_event() {
        if event.kind == NETWORK {
            p.server.receive(&event.data);
            let n = p.server.authenticated_rx_count();
            p.server.receive(&event.data);
            assert_eq!(p.server.authenticated_rx_count(), n);
        }
    }
}
#[test]
fn destination_policy_mtu_and_flow_limits_fail_closed() {
    let text = config(1, 2, "10.0.0.2/24").replace("0.0.0.0/0, ::/0", "10.0.0.0/24");
    let mut e = Engine::new(Profile::parse(&text).unwrap(), false);
    assert!(e.open_tcp(1, "1.1.1.1".parse().unwrap(), 80).is_err());
    assert!(e.open_tcp(1, "fd00::1".parse().unwrap(), 80).is_err());
    e.open_udp(1).unwrap();
    assert!(e
        .udp_send(1, "10.0.0.1".parse().unwrap(), 1, &vec![0; 1253])
        .is_err());
    for id in 2..=256 {
        e.open_udp(id).unwrap();
    }
    assert!(e.open_udp(257).is_err());
    e.close(1);
    assert!(e.open_udp(257).is_ok());
    assert_eq!(e.flow_count(), 256);
}

fn handshake_raw(client: &mut Engine, server: &mut Engine) {
    client.start();
    for _ in 0..10 {
        while let Some(event) = client.pop_event() {
            if event.kind == NETWORK {
                server.receive(&event.data);
            }
        }
        while let Some(event) = server.pop_event() {
            if event.kind == NETWORK {
                client.receive(&event.data);
            }
        }
    }
    assert!(client.is_ready() && server.is_ready());
}

fn ipv4_packet(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
    let mut packet = vec![0u8; 28];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&28u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    packet[20..22].copy_from_slice(&1234u16.to_be_bytes());
    packet[22..24].copy_from_slice(&1234u16.to_be_bytes());
    packet[24..26].copy_from_slice(&8u16.to_be_bytes());
    let sum: u32 = packet[..20]
        .chunks(2)
        .map(|x| u16::from_be_bytes([x[0], x[1]]) as u32)
        .sum();
    let sum = (sum & 0xffff) + (sum >> 16);
    let checksum = !(sum as u16);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet
}

#[test]
fn raw_tunnel_rejects_authenticated_source_outside_allowed_ips() {
    let config_client = config(1, 2, "10.0.0.2/24").replace("0.0.0.0/0, ::/0", "10.0.0.0/24");
    let mut client = Engine::new(Profile::parse(&config_client).unwrap(), true);
    let mut server = Engine::new(Profile::parse(&config(2, 1, "10.0.0.1/24")).unwrap(), true);
    handshake_raw(&mut client, &mut server);
    for source in [[192, 168, 0, 1], [10, 0, 0, 1]] {
        let packet = ipv4_packet(source, [10, 0, 0, 2]);
        server.feed_ip(&packet).unwrap();
        while let Some(event) = server.pop_event() {
            if event.kind == NETWORK {
                client.receive(&event.data);
            }
        }
        let mut received = vec![];
        while let Some(event) = client.pop_event() {
            if event.kind == RAW_IP {
                received.push(event);
            }
        }
        assert_eq!(received.len(), usize::from(source == [10, 0, 0, 1]));
    }
}

#[test]
fn undrained_event_queue_has_a_hard_limit_and_stops_tunnel() {
    let mut client = Engine::new(Profile::parse(&config(1, 2, "10.0.0.2/24")).unwrap(), true);
    let mut server = Engine::new(Profile::parse(&config(2, 1, "10.0.0.1/24")).unwrap(), true);
    handshake_raw(&mut client, &mut server);
    let packet = ipv4_packet([10, 0, 0, 2], [10, 0, 0, 1]);
    for _ in 0..5000 {
        let _ = client.feed_ip(&packet);
    }
    assert!(!client.is_ready());
    assert!(client.feed_ip(&packet).is_err());
    let event = client.pop_event().unwrap();
    assert_eq!(event.kind, ERROR);
    assert!(client.pop_event().is_none());
}

#[test]
fn malformed_config_and_policy_inputs_do_not_panic_or_echo_values() {
    let samples = [
        "\0",
        "[Interface]",
        "[Peer]",
        "PrivateKey=",
        "☃=秘密",
        "[Interface]\n秘密=value",
        "[Interface]\nPrivateKey=秘密\n[Peer]",
    ];
    for sample in samples {
        let result = std::panic::catch_unwind(|| Profile::parse(sample));
        assert!(result.is_ok());
        if let Err(error) = result.unwrap() {
            assert!(!error.contains("秘密"));
        }
    }
    let mut p = policy();
    p.apps[0].identities[0].team_id.clear();
    assert!(p.validate().is_err());
    let mut p = policy();
    p.mode = "typo".into();
    assert!(p.validate().is_err());
}
