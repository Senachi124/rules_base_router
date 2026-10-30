//! Compile vpn-v2 routing to the supported sing-box 1.14 schema.
use crate::{
    config::{self, Config, Match, Rule},
    wireguard,
};
use serde_json::{json, Value};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{collections::BTreeMap, path::Path};

pub struct Generated {
    pub json: Value,
    pub warnings: Vec<String>,
    pub dns_strategy: String,
}

pub fn generate(config: &Config) -> Result<Generated, String> {
    let mut profiles = BTreeMap::new();
    let mut endpoints = vec![];
    #[allow(unused_mut)]
    let mut warnings = vec![];
    for (name, vpn) in &config.vpns {
        let wg = wireguard::Config::load(Path::new(&vpn.wireguard_config))
            .map_err(|e| format!("VPN {name}: {e}"))?;
        #[cfg(unix)]
        if std::fs::metadata(&vpn.wireguard_config)
            .is_ok_and(|m| m.permissions().mode() & 0o077 != 0)
        {
            warnings.push(format!(
                "{} contains a private key; set its permissions to 0600",
                vpn.wireguard_config
            ));
        }
        let mut peer = json!({"address": wg.peer.host, "port": wg.peer.port, "public_key": wg.peer.public_key, "allowed_ips": wg.peer.allowed_ips});
        if !wg.peer.preshared_key.is_empty() {
            peer["pre_shared_key"] = json!(wg.peer.preshared_key);
        }
        if wg.peer.keepalive != 0 {
            peer["persistent_keepalive_interval"] = json!(wg.peer.keepalive);
        }
        endpoints.push(json!({"type": "wireguard", "tag": name, "system": false, "mtu": wg.mtu,
            "address": wg.address, "private_key": wg.private_key, "peers": [peer], "domain_resolver": "vpnctl-bootstrap"}));
        profiles.insert(name.clone(), wg);
    }
    generate_with_profiles(config, profiles, endpoints, warnings)
}

fn generate_with_profiles(
    config: &Config,
    profiles: BTreeMap<String, wireguard::Config>,
    endpoints: Vec<Value>,
    mut warnings: Vec<String>,
) -> Result<Generated, String> {
    let strategy = dns_strategy(config, &profiles)?;
    let server = if !config.dns.server.is_empty() {
        config.dns.server.clone()
    } else {
        profiles
            .get(&config.dns.via)
            .and_then(|wg| wg.dns.first())
            .cloned()
            .unwrap_or_else(|| "1.1.1.1".into())
    };
    let mut dns = json!({"servers": [
        {"type": "udp", "tag": "vpnctl-bootstrap", "server": "1.1.1.1", "detour": "direct"},
        {"type": "udp", "tag": "vpnctl-dns", "server": server, "detour": config.dns.via}],
        "final": "vpnctl-dns", "reverse_mapping": true, "strategy": strategy});
    if strategy == "ipv4_only" {
        dns["rules"] = json!([{"query_type": ["AAAA", "HTTPS", "SVCB"], "action": "predefined", "rcode": "NOERROR"}]);
    }
    if strategy == "ipv6_only" {
        dns["rules"] = json!([{"query_type": ["A", "HTTPS", "SVCB"], "action": "predefined", "rcode": "NOERROR"}]);
    }
    let mut rules = vec![json!({"port": [53], "action": "hijack-dns"})];
    // Reject unavailable IPv6 before sniff accepts a TCP handshake. The engine
    // evaluates its monitored physical interface rather than our synthetic TUN.
    if !profiles.values().any(|p| p.supports_ip_version(6)) {
        rules.push(json!({"type": "logical", "mode": "and", "rules": [
            {"ip_version": 6}, {"type": "logical", "mode": "or", "invert": true, "rules": [
                {"default_interface_address": ["2000::/3"]}, {"default_interface_address": ["fc00::/7"]}
            ]}], "action": "reject", "method": "default", "no_drop": true}));
    }
    rules.push(json!({"action": "sniff", "timeout": "300ms"}));
    for rule in &config.routing.rules {
        rules.extend(family_guards(
            profiles.get(&rule.via),
            Some(compile_match(&rule.r#match)),
        ));
        rules.push(compile_rule(rule));
        for app in &rule.r#match.apps {
            if !Path::new(app).exists() {
                warnings.push(format!(
                    "rule {:?}: app path does not currently exist: {app}",
                    rule.name
                ));
            }
        }
    }
    rules.extend(family_guards(profiles.get(&config.routing.default), None));
    let mut root = json!({
        "log": {"level": "info", "timestamp": true}, "dns": dns,
        "inbounds": [{"type": "tun", "tag": "vpnctl-tun", "address": ["172.31.255.1/30", "fd7a:7650:6e63::1/126"],
            "mtu": 1400, "auto_route": true, "dns_mode": "hijack"}],
        "outbounds": [{"type": "direct", "tag": "direct", "domain_resolver": "vpnctl-dns"}],
        "route": {"auto_detect_interface": true, "find_process": true, "default_domain_resolver": "vpnctl-bootstrap", "rules": rules, "final": config.routing.default}
    });
    #[cfg(windows)]
    {
        root["inbounds"][0]["interface_name"] = json!("RouteBar");
        root["inbounds"][0]["strict_route"] = json!(true);
        if !endpoints.is_empty() {
            // A detour uses the peer's address family rather than the engine's
            // dual-stack listener. On Windows an IPv6-disabled physical adapter
            // otherwise makes the WireGuard bind fail even for an IPv4 peer.
            // Keep endpoint DNS independent of DNS routed inside the tunnel.
            root["outbounds"].as_array_mut().unwrap().push(json!({
                "type": "direct", "tag": "vpnctl-transport",
                "domain_resolver": "vpnctl-bootstrap"
            }));
        }
    }
    #[cfg(windows)]
    let endpoints: Vec<Value> = endpoints
        .into_iter()
        .map(|mut endpoint| {
            endpoint["detour"] = json!("vpnctl-transport");
            endpoint
        })
        .collect();
    if !endpoints.is_empty() {
        root["endpoints"] = json!(endpoints);
    }
    Ok(Generated {
        json: root,
        warnings,
        dns_strategy: strategy,
    })
}
pub fn dns_strategy(
    config: &Config,
    profiles: &BTreeMap<String, wireguard::Config>,
) -> Result<String, String> {
    if config.dns.strategy != "auto" && !config.dns.strategy.is_empty() {
        return Ok(config.dns.strategy.clone());
    }
    match (profiles.values().all(|p| p.supports_ip_version(4)), profiles.values().all(|p| p.supports_ip_version(6))) {
        (true, true) => Ok("prefer_ipv4".into()), (true, false) => Ok("ipv4_only".into()), (false, true) => Ok("ipv6_only".into()),
        (false, false) => Err("VPN profiles have no common IP address family; set an explicit dns.strategy and review per-VPN reachability".into()),
    }
}
fn family_guards(profile: Option<&wireguard::Config>, selector: Option<Value>) -> Vec<Value> {
    let Some(profile) = profile else {
        return vec![];
    };
    [4, 6].into_iter().filter(|version| !profile.supports_ip_version(*version)).map(|version| {
        if let Some(ref selector) = selector {
            json!({"type": "logical", "mode": "and", "rules": [selector, {"ip_version": version}], "action": "reject", "method": "default", "no_drop": true})
        } else { json!({"ip_version": version, "action": "reject", "method": "default", "no_drop": true}) }
    }).collect()
}
pub fn compile_match(selector: &Match) -> Value {
    let mut groups = vec![];
    let mut apps = vec![];
    #[cfg(windows)]
    if !selector.apps.is_empty() {
        let paths: Vec<_> = selector
            .apps
            .iter()
            .map(|p| config::windows_app_regex(p))
            .collect();
        apps.push(json!({"process_path_regex": paths}));
    }
    #[cfg(not(windows))]
    {
        let paths: Vec<_> = selector
            .apps
            .iter()
            .filter(|s| !s.ends_with(".app"))
            .collect();
        let bundles: Vec<_> = selector
            .apps
            .iter()
            .filter(|s| s.ends_with(".app"))
            .map(|s| config::app_regex(s))
            .collect();
        if !paths.is_empty() {
            apps.push(json!({"process_path": paths}));
        }
        if !bundles.is_empty() {
            apps.push(json!({"process_path_regex": bundles}));
        }
    }
    if !selector.process_names.is_empty() {
        apps.push(json!({"process_name": selector.process_names}));
    }
    if !apps.is_empty() {
        groups.push(json!({"type": "logical", "mode": "or", "rules": apps}));
    }
    // sing-box's domain, domain_suffix, and ip_cidr are one destination OR group.
    let mut destination = json!({});
    if !selector.domains.is_empty() {
        destination["domain"] = json!(selector.domains);
    }
    if !selector.domain_suffixes.is_empty() {
        destination["domain_suffix"] = json!(selector.domain_suffixes);
    }
    if !selector.ip_cidrs.is_empty() {
        destination["ip_cidr"] = json!(selector.ip_cidrs);
    }
    if !destination.as_object().unwrap().is_empty() {
        groups.push(destination);
    }
    json!({"type": "logical", "mode": "and", "rules": groups})
}
pub fn compile_rule(rule: &Rule) -> Value {
    let mut value = compile_match(&rule.r#match);
    value["action"] = json!("route");
    value["outbound"] = json!(rule.via);
    value
}
pub fn redacted(value: &Value) -> Value {
    let mut value = value.clone();
    visit_secrets(&mut value, &mut |secret| *secret = json!("<redacted>"));
    value
}
pub fn sanitize(message: &str, config: &Value) -> String {
    let mut result = message.to_string();
    visit_secrets(&mut config.clone(), &mut |secret| {
        if let Some(s) = secret.as_str().filter(|s| !s.is_empty()) {
            result = result.replace(s, "<redacted>");
        }
    });
    result.trim().to_string()
}
fn visit_secrets(value: &mut Value, visit: &mut impl FnMut(&mut Value)) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if key == "private_key" || key == "pre_shared_key" {
                    visit(value);
                } else {
                    visit_secrets(value, visit);
                }
            }
        }
        Value::Array(array) => {
            for value in array {
                visit_secrets(value, visit);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> Config {
        #[cfg(windows)]
        return Config::from_text("version: 1\nvpns: {jp: {wireguard_config: C:/tmp/test.conf}}\nrouting:\n  rules:\n    - {name: exception, match: {domain_suffixes: [company.example]}, via: direct}\n    - {name: browser, match: {apps: ['C:/Program Files/A+B/app.exe'], process_names: [curl.exe], domains: [example.org]}, via: jp}\n", Path::new("C:/config.yaml")).unwrap();
        #[cfg(not(windows))]
        Config::from_text("version: 1\nvpns: {jp: {wireguard_config: /tmp/test.conf}}\nrouting:\n  rules:\n    - {name: exception, match: {domain_suffixes: [company.example]}, via: direct}\n    - {name: browser, match: {apps: [/Applications/A+B.app], process_names: [curl], domains: [example.org]}, via: jp}\n", Path::new("/config.yaml")).unwrap()
    }
    fn profiles() -> BTreeMap<String, wireguard::Config> {
        BTreeMap::from([(
            "jp".into(),
            wireguard::Config::parse(&wireguard::tests::profile().replace(", fd00::2/128", ""))
                .unwrap(),
        )])
    }
    #[test]
    fn generation_preserves_v2_rules_dns_and_family_guards() {
        let c = config();
        let generated = generate_with_profiles(&c, profiles(), vec![], vec![]).unwrap();
        assert_eq!(generated.dns_strategy, "ipv4_only");
        assert_eq!(
            generated.json["dns"]["rules"][0]["query_type"],
            json!(["AAAA", "HTTPS", "SVCB"])
        );
        let rules = generated.json["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["action"], "hijack-dns");
        assert_eq!(rules[1]["action"], "reject");
        assert_eq!(rules[2]["action"], "sniff");
        assert_eq!(rules[3]["outbound"], "direct");
        assert_eq!(rules[4]["action"], "reject");
        assert_eq!(rules[5]["outbound"], "jp");
        assert_eq!(
            rules[4]["rules"][0],
            compile_match(&c.routing.rules[1].r#match)
        );
        assert_eq!(rules[4]["rules"][1]["ip_version"], 6);
        #[cfg(not(windows))]
        assert_eq!(
            rules[5]["rules"][0]["rules"][0]["process_path_regex"],
            json!(["^/Applications/A\\+B\\.app/"])
        );
        #[cfg(windows)]
        {
            assert_eq!(
                rules[5]["rules"][0]["rules"][0]["process_path_regex"],
                json!([r"(?i)^C:\\Program Files\\A\+B\\app\.exe$"])
            );
            assert_eq!(generated.json["inbounds"][0]["strict_route"], true);
        }
        assert_eq!(rules[5]["rules"][0]["mode"], "or");
        assert_eq!(rules[5]["mode"], "and");
        assert_eq!(generated.json["route"]["final"], "direct");
        assert_eq!(generated.json["dns"]["servers"][1]["detour"], "direct");
    }
    #[test]
    fn family_auto_uses_intersection_and_profile_dns() {
        let mut c = config();
        let mut p = profiles();
        c.dns.via = "jp".into();
        p.get_mut("jp").unwrap().dns = vec!["10.0.0.1".into()];
        let generated = generate_with_profiles(&c, p.clone(), vec![], vec![]).unwrap();
        assert_eq!(generated.json["dns"]["servers"][1]["server"], "10.0.0.1");
        let v6 = wireguard::Config::parse(
            &wireguard::tests::profile()
                .replace("10.14.0.2/16, ", "")
                .replace("0.0.0.0/0, ", ""),
        )
        .unwrap();
        p.insert("v6".into(), v6);
        assert!(dns_strategy(&c, &p).is_err());
        c.dns.strategy = "prefer_ipv6".into();
        assert_eq!(dns_strategy(&c, &p).unwrap(), "prefer_ipv6");
        c.dns.strategy = "auto".into();
        p.remove("jp");
        let generated = generate_with_profiles(&c, p, vec![], vec![]).unwrap();
        assert_eq!(generated.dns_strategy, "ipv6_only");
        assert_eq!(
            generated.json["dns"]["rules"][0]["query_type"],
            json!(["A", "HTTPS", "SVCB"])
        );
        assert_eq!(generated.json["route"]["rules"][1]["action"], "sniff");
    }
    #[test]
    fn default_vpn_guard_follows_direct_exceptions() {
        let mut c = config();
        c.routing.default = "jp".into();
        c.routing.rules.truncate(1);
        let generated = generate_with_profiles(&c, profiles(), vec![], vec![]).unwrap();
        let rules = generated.json["route"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 5);
        assert_eq!(rules[3]["outbound"], "direct");
        assert_eq!(
            rules[4],
            json!({"ip_version": 6, "action": "reject", "method": "default", "no_drop": true})
        );
    }

    #[test]
    fn generated_profiles_pass_real_engine_schema_when_available() {
        use crate::runtime::{atomic_write, check_engine, locate_engine, PrivateDir};
        let binary = match std::env::var("ROUTEBAR_TEST_ENGINE") {
            Ok(binary) => std::path::PathBuf::from(binary),
            Err(_) => match locate_engine(None) {
                Ok(binary) => binary,
                Err(_) => return,
            },
        };
        let temp = PrivateDir::new(&std::env::temp_dir(), "routebar-profile-test").unwrap();
        let profile_path = temp.0.join("synthetic.conf");
        let source = temp.0.join("config.yaml");
        for (profile, strategy) in [
            (wireguard::tests::profile(), "prefer_ipv4"),
            (
                wireguard::tests::profile().replace(", fd00::2/128", ""),
                "ipv4_only",
            ),
            (
                wireguard::tests::profile()
                    .replace("10.14.0.2/16, ", "")
                    .replace("0.0.0.0/0, ", ""),
                "ipv6_only",
            ),
        ] {
            atomic_write(&profile_path, profile.as_bytes(), 0o600).unwrap();
            let mut c = config();
            c.source = source.clone();
            c.vpns.get_mut("jp").unwrap().wireguard_config = profile_path.to_string_lossy().into();
            let generated = generate(&c).unwrap();
            assert_eq!(generated.dns_strategy, strategy);
            #[cfg(windows)]
            {
                assert_eq!(generated.json["endpoints"][0]["detour"], "vpnctl-transport");
                let transport = generated.json["outbounds"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|outbound| outbound["tag"] == "vpnctl-transport")
                    .unwrap();
                assert_eq!(transport["type"], "direct");
                assert_eq!(transport["domain_resolver"], "vpnctl-bootstrap");
            }
            assert_eq!(
                generated.json["endpoints"][0]["peers"][0]["persistent_keepalive_interval"],
                25
            );
            let safe = redacted(&generated.json);
            assert_eq!(safe["endpoints"][0]["private_key"], "<redacted>");
            assert_eq!(
                safe["endpoints"][0]["peers"][0]["pre_shared_key"],
                "<redacted>"
            );
            check_engine(&binary, &generated.json).unwrap();
        }
    }

    #[test]
    fn redacts_nested_secrets_and_engine_errors() {
        let value = json!({"endpoints": [{"private_key": "secret1", "peers": [{"pre_shared_key": "secret2", "public_key": "public"}]}]});
        let rendered = redacted(&value).to_string();
        assert!(!rendered.contains("secret1"));
        assert!(!rendered.contains("secret2"));
        assert!(rendered.contains("public"));
        assert_eq!(
            sanitize("bad secret1 and secret2", &value),
            "bad <redacted> and <redacted>"
        );
    }
}
