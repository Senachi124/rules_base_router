//! Single-peer WireGuard profiles. No wg-quick hooks are ever executed.
use base64::{engine::general_purpose::STANDARD, Engine};
use ipnet::IpNet;
use std::{collections::BTreeSet, io::Read, net::IpAddr, path::Path};

#[derive(Clone)]
pub struct Config {
    pub address: Vec<String>,
    pub private_key: String,
    pub dns: Vec<String>,
    pub mtu: u16,
    pub peer: Peer,
}
#[derive(Clone, Default)]
pub struct Peer {
    pub host: String,
    pub port: u16,
    pub public_key: String,
    pub preshared_key: String,
    pub allowed_ips: Vec<String>,
    pub keepalive: u16,
}
impl Config {
    pub fn supports_ip_version(&self, version: u8) -> bool {
        let has = |values: &[String]| {
            values.iter().any(|s| {
                s.parse::<IpNet>()
                    .is_ok_and(|p| p.addr().is_ipv6() == (version == 6))
            })
        };
        has(&self.address) && has(&self.peer.allowed_ips)
    }
    pub fn load(path: &Path) -> Result<Self, String> {
        let file = std::fs::File::open(path).map_err(|_| "cannot read WireGuard profile")?;
        let mut text = String::new();
        file.take(128 * 1024 + 1)
            .read_to_string(&mut text)
            .map_err(|_| "cannot read UTF-8 WireGuard profile")?;
        Self::parse(&text)
    }
    pub fn parse(text: &str) -> Result<Self, String> {
        if text.len() > 128 * 1024 {
            return Err("WireGuard profile exceeds 128 KiB".into());
        }
        let mut c = Config {
            address: vec![],
            private_key: String::new(),
            dns: vec![],
            mtu: 1408,
            peer: Peer::default(),
        };
        let mut section = "";
        let mut seen = BTreeSet::new();
        for (i, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or_default().trim();
            if line.is_empty() || line.starts_with(';') {
                continue;
            }
            if line.starts_with('[') {
                if line != "[Interface]" && line != "[Peer]" {
                    return Err(format!("line {}: unsupported section", i + 1));
                }
                if !seen.insert(line.to_owned()) {
                    return Err(format!(
                        "line {}: exactly one Interface and one Peer are supported",
                        i + 1
                    ));
                }
                section = line;
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| format!("line {}: expected a field inside a section", i + 1))?;
            if section.is_empty() {
                return Err(format!("line {}: expected a field inside a section", i + 1));
            }
            let key = key.trim();
            let value = value.trim();
            let field = format!("{section}{key}");
            if !seen.insert(field.clone()) {
                return Err(format!("line {}: duplicate field", i + 1));
            }
            // Error text never includes unknown field names or input values.
            let invalid = || format!("line {}: invalid WireGuard field", i + 1);
            match field.as_str() {
                "[Interface]PrivateKey" => { check_key(value).map_err(|_| invalid())?; c.private_key = value.into(); },
                "[Interface]Address" => { c.address = prefixes(value).map_err(|_| invalid())?; },
                "[Interface]DNS" => {
                    c.dns = split(value).map(|v| v.parse::<IpAddr>().map(|a| a.to_string())).collect::<Result<_, _>>().map_err(|_| invalid())?;
                },
                "[Interface]MTU" => { c.mtu = number(value, 1280, 9000).map_err(|_| invalid())?; },
                "[Interface]ListenPort" => { number(value, 0, 65535).map_err(|_| invalid())?; },
                "[Peer]PublicKey" => { check_key(value).map_err(|_| invalid())?; c.peer.public_key = value.into(); },
                "[Peer]PresharedKey" => { check_key(value).map_err(|_| invalid())?; c.peer.preshared_key = value.into(); },
                "[Peer]AllowedIPs" => { c.peer.allowed_ips = prefixes(value).map_err(|_| invalid())?; },
                "[Peer]PersistentKeepalive" => { c.peer.keepalive = number(value, 0, 65535).map_err(|_| invalid())?; },
                "[Peer]Endpoint" => { let (host, port) = endpoint(value).map_err(|_| invalid())?; c.peer.host = host; c.peer.port = port; },
                _ => return Err(format!("line {}: unsupported WireGuard field (hooks and routing directives are not executed)", i + 1)),
            }
        }
        if c.private_key.is_empty()
            || c.address.is_empty()
            || c.peer.public_key.is_empty()
            || c.peer.host.is_empty()
            || c.peer.port == 0
            || c.peer.allowed_ips.is_empty()
        {
            return Err("WireGuard config requires Interface Address/PrivateKey and Peer PublicKey/Endpoint/AllowedIPs".into());
        }
        Ok(c)
    }
}
fn check_key(value: &str) -> Result<(), ()> {
    if STANDARD.decode(value).is_ok_and(|k| k.len() == 32) {
        Ok(())
    } else {
        Err(())
    }
}
fn split(value: &str) -> impl Iterator<Item = &str> {
    value.split(',').map(str::trim)
}
fn prefixes(value: &str) -> Result<Vec<String>, ()> {
    split(value)
        .map(|v| v.parse::<IpNet>().map(|p| p.to_string()).map_err(|_| ()))
        .collect()
}
fn number(value: &str, min: u16, max: u16) -> Result<u16, ()> {
    value
        .parse::<u16>()
        .ok()
        .filter(|n| *n >= min && *n <= max)
        .ok_or(())
}
fn endpoint(value: &str) -> Result<(String, u16), ()> {
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (host, port) = rest.split_once("]:").ok_or(())?;
        if !host.parse::<IpAddr>().is_ok_and(|a| a.is_ipv6()) {
            return Err(());
        }
        (host, port)
    } else {
        let (host, port) = value.rsplit_once(':').ok_or(())?;
        if host.contains(':')
            || (host.parse::<IpAddr>().is_err()
                && !crate::config::valid_domain(&crate::config::normalize_domain(host)))
        {
            return Err(());
        }
        (host, port)
    };
    if host.is_empty() {
        return Err(());
    }
    Ok((host.into(), number(port, 1, 65535)?))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub const KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    pub fn profile() -> String {
        format!("[Interface]\nPrivateKey = {KEY}\nAddress = 10.14.0.2/16, fd00::2/128\nDNS = 1.1.1.1, 1.0.0.1\nMTU = 1380\n[Peer]\nPublicKey = {KEY}\nPresharedKey = {KEY}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = [2001:db8::1]:51820\nPersistentKeepalive = 25\n")
    }
    #[test]
    fn fields_and_families() {
        let p = Config::parse(&profile()).unwrap();
        assert_eq!(p.address, ["10.14.0.2/16", "fd00::2/128"]);
        assert_eq!(p.dns, ["1.1.1.1", "1.0.0.1"]);
        assert_eq!(p.mtu, 1380);
        assert_eq!(p.peer.host, "2001:db8::1");
        assert_eq!(p.peer.port, 51820);
        assert_eq!(p.peer.keepalive, 25);
        assert_eq!(p.peer.preshared_key, KEY);
        assert!(p.supports_ip_version(4));
        assert!(p.supports_ip_version(6));
        for profile in [
            profile().replace(", fd00::2/128", ""),
            profile().replace(", ::/0", ""),
        ] {
            let p = Config::parse(&profile).unwrap();
            assert!(p.supports_ip_version(4));
            assert!(!p.supports_ip_version(6));
        }
        let p = Config::parse(
            &profile()
                .replace("10.14.0.2/16, ", "")
                .replace("0.0.0.0/0, ", ""),
        )
        .unwrap();
        assert!(!p.supports_ip_version(4));
        assert!(p.supports_ip_version(6));
        let p = Config::parse(&profile().replace("[2001:db8::1]", "wg.example.org")).unwrap();
        assert_eq!(p.peer.host, "wg.example.org");
    }
    #[test]
    fn rejects_hooks_duplicates_malformed_fields_without_leaking() {
        let secret = "DO_NOT_PRINT_THIS_PRIVATE_KEY";
        for text in [
            profile().replacen(KEY, secret, 1),
            profile().replace("MTU = 1380", "PostUp = arbitrary shell code"),
            profile().replace("MTU = 1380", "SaveConfig = true"),
            profile().replace("MTU = 1380", "MTU = -1"),
            profile().replace(":51820", ":70000"),
            format!("{}\n[Peer]\n", profile()),
            profile().replace("[Interface]", "[Unexpected]"),
            format!("[Interface]\nPrivateKey = {KEY}"),
            profile().replace(
                "PrivateKey = ",
                &format!("PrivateKey = {KEY}\nPrivateKey = "),
            ),
            profile().replace("MTU = 1380", &format!("{secret} = bad")),
            profile().replace("[2001:db8::1]:51820", "a/b:51820"),
        ] {
            let error = match Config::parse(&text) {
                Err(e) => e,
                Ok(_) => panic!("accepted invalid profile"),
            };
            assert!(!error.contains(secret));
            assert!(!error.contains(KEY));
        }
    }
}
