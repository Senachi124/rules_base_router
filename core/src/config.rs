use base64::{engine::general_purpose::STANDARD, Engine};
use ipnet::IpNet;
use serde::Serialize;
use std::net::IpAddr;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Never derive Debug or Serialize: this object owns private key material.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Profile {
    pub private_key: [u8; 32],
    pub peer_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub endpoint_host: String,
    pub endpoint_port: u16,
    #[zeroize(skip)]
    pub addresses: Vec<IpNet>,
    #[zeroize(skip)]
    pub allowed_ips: Vec<IpNet>,
    #[zeroize(skip)]
    pub dns: Vec<IpAddr>,
    pub mtu: u16,
    pub keepalive: u16,
}

#[derive(Serialize)]
pub struct ProfileSummary {
    pub endpoint_host: String,
    pub endpoint_port: u16,
    pub addresses: Vec<String>,
    pub dns: Vec<String>,
    pub mtu: u16,
    pub has_ipv6: bool,
}

impl Profile {
    pub fn parse(input: &str) -> Result<Self, String> {
        if input.len() > 64 * 1024 {
            return Err("Configuration is too large".into());
        }
        let mut interface = std::collections::HashMap::<String, Zeroizing<String>>::new();
        let mut peer = std::collections::HashMap::<String, Zeroizing<String>>::new();
        let mut section = "";
        let mut peer_count = 0;
        for raw in input.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('[') {
                section = match line {
                    "[Interface]" if section.is_empty() => "interface",
                    "[Peer]" if section == "interface" => {
                        peer_count += 1;
                        "peer"
                    }
                    _ => return Err("Expected one [Interface] and one [Peer] section".into()),
                };
                continue;
            }
            let (key, value) = line.split_once('=').ok_or("Invalid configuration line")?;
            let key = key.trim().to_ascii_lowercase();
            let value = Zeroizing::new(value.trim().to_string());
            let supported = match section {
                "interface" => ["privatekey", "address", "dns", "mtu"].contains(&key.as_str()),
                "peer" => [
                    "publickey",
                    "presharedkey",
                    "endpoint",
                    "allowedips",
                    "persistentkeepalive",
                ]
                .contains(&key.as_str()),
                _ => false,
            };
            if !supported {
                return Err("Unsupported configuration field. Shell hooks and arbitrary routing commands are not supported.".into());
            }
            let fields = if section == "interface" {
                &mut interface
            } else {
                &mut peer
            };
            if fields.insert(key.clone(), value).is_some() {
                return Err(format!("Duplicate field: {key}"));
            }
        }
        let get = |map: &std::collections::HashMap<String, Zeroizing<String>>, key: &str| {
            map.get(key)
                .cloned()
                .ok_or_else(|| format!("Missing {key}"))
        };
        let key = |value: &str| -> Result<[u8; 32], String> {
            let mut decoded = STANDARD
                .decode(value)
                .map_err(|_| "Invalid WireGuard key encoding")?;
            let result = decoded
                .as_slice()
                .try_into()
                .map_err(|_| "WireGuard keys must be 32 bytes".into());
            decoded.zeroize();
            result
        };
        let result = (|| {
            if peer_count != 1 {
                return Err("Exactly one peer is required".into());
            }
            let addresses = get(&interface, "address")?
                .split(',')
                .map(|x| {
                    x.trim()
                        .parse::<IpNet>()
                        .map_err(|_| "Invalid interface address".to_string())
                })
                .collect::<Result<Vec<_>, _>>()?;
            if addresses.is_empty() || addresses.len() > 2 {
                return Err("Use one address per IP family (maximum two)".into());
            }
            if addresses.iter().filter(|a| a.addr().is_ipv4()).count() > 1
                || addresses.iter().filter(|a| a.addr().is_ipv6()).count() > 1
            {
                return Err("Use one address per IP family".into());
            }
            let allowed_ips = get(&peer, "allowedips")?
                .split(',')
                .map(|x| {
                    x.trim()
                        .parse::<IpNet>()
                        .map_err(|_| "Invalid AllowedIPs".to_string())
                })
                .collect::<Result<Vec<_>, _>>()?;
            let dns = interface
                .get("dns")
                .map(|v| {
                    v.split(',')
                        .map(|x| {
                            x.trim()
                                .parse::<IpAddr>()
                                .map_err(|_| "DNS must contain IP addresses".to_string())
                        })
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()?
                .unwrap_or_default();
            let endpoint = get(&peer, "endpoint")?;
            let (host, port) = endpoint
                .rsplit_once(':')
                .ok_or("Endpoint must include a port")?;
            let host = if host.starts_with('[') && host.ends_with(']') {
                let ip = &host[1..host.len() - 1];
                if ip.parse::<std::net::Ipv6Addr>().is_err() {
                    return Err("Invalid IPv6 endpoint".into());
                }
                ip.to_string()
            } else {
                let host = idna::domain_to_ascii(host)
                    .map_err(|_| "Invalid endpoint host")?
                    .to_ascii_lowercase();
                if host.is_empty()
                    || host.len() > 253
                    || host.split('.').any(|label| {
                        label.is_empty()
                            || label.len() > 63
                            || label.starts_with('-')
                            || label.ends_with('-')
                            || !label
                                .bytes()
                                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
                    })
                {
                    return Err("Invalid endpoint host".into());
                }
                host
            };
            let endpoint_port: u16 = port.parse().map_err(|_| "Invalid endpoint port")?;
            if endpoint_port == 0 {
                return Err("Endpoint port must be nonzero".into());
            }
            let mtu = interface
                .get("mtu")
                .map(|v| v.parse::<u16>())
                .transpose()
                .map_err(|_| "Invalid MTU")?
                .unwrap_or(1280);
            if !(1280..=1420).contains(&mtu) {
                return Err("MTU must be between 1280 and 1420".into());
            }
            Ok(Self {
                private_key: key(&get(&interface, "privatekey")?)?,
                peer_key: key(&get(&peer, "publickey")?)?,
                preshared_key: peer.get("presharedkey").map(|v| key(v)).transpose()?,
                endpoint_host: host,
                endpoint_port,
                addresses,
                allowed_ips,
                dns,
                mtu,
                keepalive: peer
                    .get("persistentkeepalive")
                    .map(|v| v.parse::<u16>())
                    .transpose()
                    .map_err(|_| "Invalid keepalive")?
                    .unwrap_or(25),
            })
        })();
        for value in interface.values_mut().chain(peer.values_mut()) {
            value.zeroize();
        }
        result
    }

    pub fn summary(&self) -> ProfileSummary {
        ProfileSummary {
            endpoint_host: self.endpoint_host.clone(),
            endpoint_port: self.endpoint_port,
            addresses: self.addresses.iter().map(ToString::to_string).collect(),
            dns: self.dns.iter().map(ToString::to_string).collect(),
            mtu: self.mtu,
            has_ipv6: self.addresses.iter().any(|a| a.addr().is_ipv6()),
        }
    }
}
