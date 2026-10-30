//! The vpn-v2 version-1 schema and its ordered routing semantics.
use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    #[serde(default, deserialize_with = "unique_vpns")]
    pub vpns: BTreeMap<String, VPN>,
    #[serde(default)]
    pub routing: Routing,
    #[serde(default)]
    pub dns: DNS,
    #[serde(skip)]
    pub source: PathBuf,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VPN {
    pub wireguard_config: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DNS {
    pub server: String,
    pub via: String,
    pub strategy: String,
}
impl Default for DNS {
    fn default() -> Self {
        Self {
            server: String::new(),
            via: "direct".into(),
            strategy: "auto".into(),
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Routing {
    pub default: String,
    pub rules: Vec<Rule>,
}
impl Default for Routing {
    fn default() -> Self {
        Self {
            default: "direct".into(),
            rules: Vec::new(),
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    #[serde(default)]
    pub name: String,
    pub r#match: Match,
    pub via: String,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Match {
    pub apps: Vec<String>,
    pub process_names: Vec<String>,
    pub domains: Vec<String>,
    pub domain_suffixes: Vec<String>,
    pub ip_cidrs: Vec<String>,
}
#[derive(Clone, Default)]
pub struct Flow {
    pub app: String,
    pub process_name: String,
    pub domain: String,
    pub ip: Option<IpAddr>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Decision {
    pub via: String,
    pub rule: String,
    pub index: usize,
}

fn unique_vpns<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, VPN>, D::Error> {
    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = BTreeMap<String, VPN>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a map of unique VPN names")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut map: M,
        ) -> Result<Self::Value, M::Error> {
            let mut values = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, VPN>()? {
                if values.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom("duplicate VPN name"));
                }
            }
            Ok(values)
        }
    }
    deserializer.deserialize_map(Visitor)
}

pub(crate) fn clean_path(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            other => result.push(other.as_os_str()),
        }
    }
    result
}
fn absolute(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        Ok(clean_path(path))
    } else {
        Ok(clean_path(
            &std::env::current_dir()
                .map_err(|_| "cannot find current directory")?
                .join(path),
        ))
    }
}
pub fn normalize_domain(value: &str) -> String {
    value
        .trim()
        .strip_suffix('.')
        .unwrap_or(value.trim())
        .to_ascii_lowercase()
}
pub fn valid_domain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.parse::<IpAddr>().is_err()
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}
pub fn app_regex(path: &str) -> String {
    // Match Go regexp.QuoteMeta exactly: Rust regex::escape also escapes
    // punctuation such as hyphens that is literal in the engine's RE2 syntax.
    let mut escaped = String::from("^");
    for ch in path.chars() {
        if r"\.+*?()|[]{}^$".contains(ch) {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped.push('/');
    escaped
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        use std::io::Read;
        let file = std::fs::File::open(path)
            .map_err(|e| format!("cannot read YAML configuration: {e}"))?;
        let mut text = String::new();
        file.take(1024 * 1024 + 1)
            .read_to_string(&mut text)
            .map_err(|_| "cannot read UTF-8 YAML configuration")?;
        Self::from_text(&text, path)
    }
    pub fn from_text(text: &str, source: &Path) -> Result<Self, String> {
        if text.len() > 1024 * 1024 {
            return Err("YAML configuration exceeds 1 MiB".into());
        }
        // Direct deserialization rejects duplicate struct fields and extra documents.
        // Never echo YAML values: an accidental paste may contain private material.
        let mut c: Self = serde_yaml::from_str(text).map_err(|e| {
            e.location().map(|p| format!("invalid YAML schema at line {}, column {} (unknown/duplicate fields and multiple documents are not accepted)", p.line(), p.column()))
                .unwrap_or_else(|| "invalid YAML schema (unknown/duplicate fields and multiple documents are not accepted)".into())
        })?;
        c.source = absolute(source)?;
        c.validate()?;
        Ok(c)
    }
    pub fn validate(&mut self) -> Result<(), String> {
        if self.version != 1 {
            return Err("version must be 1".into());
        }
        if self.routing.default.is_empty() {
            self.routing.default = "direct".into();
        }
        if self.dns.via.is_empty() {
            self.dns.via = "direct".into();
        }
        if self.dns.strategy.is_empty() {
            self.dns.strategy = "auto".into();
        }
        if ![
            "auto",
            "ipv4_only",
            "ipv6_only",
            "prefer_ipv4",
            "prefer_ipv6",
        ]
        .contains(&self.dns.strategy.as_str())
        {
            return Err(
                "dns.strategy must be auto, ipv4_only, ipv6_only, prefer_ipv4, or prefer_ipv6"
                    .into(),
            );
        }
        if !self.dns.server.is_empty() && self.dns.server.parse::<IpAddr>().is_err() {
            return Err("dns.server must be an IP address".into());
        }
        for (name, vpn) in &mut self.vpns {
            if name.is_empty()
                || name.len() > 64
                || !name.as_bytes()[0].is_ascii_alphabetic()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                || name == "direct"
                || name.starts_with("vpnctl-")
            {
                return Err("invalid or reserved VPN name".into());
            }
            if vpn.wireguard_config.trim().is_empty() || vpn.wireguard_config.contains('\0') {
                return Err("wireguard_config is required and must be a valid path".into());
            }
            let mut path = PathBuf::from(&vpn.wireguard_config);
            if !path.is_absolute() {
                path = self.source.parent().unwrap_or(Path::new("/")).join(path);
            }
            vpn.wireguard_config = clean_path(&path).to_string_lossy().into_owned();
        }
        let known_via = |via: &str| via == "direct" || self.vpns.contains_key(via);
        if !known_via(&self.routing.default) {
            return Err("routing.default references an unknown VPN".into());
        }
        if !known_via(&self.dns.via) {
            return Err("dns.via references an unknown VPN".into());
        }
        let mut names = BTreeSet::new();
        for (index, rule) in self.routing.rules.iter_mut().enumerate() {
            if rule.name.is_empty() {
                rule.name = format!("rule-{}", index + 1);
            }
            if !names.insert(rule.name.clone()) {
                return Err(format!("rule {} has a duplicate name", index + 1));
            }
            if !known_via(&rule.via) {
                return Err(format!("rule {} references an unknown VPN", index + 1));
            }
            let m = &mut rule.r#match;
            if m.apps.len()
                + m.process_names.len()
                + m.domains.len()
                + m.domain_suffixes.len()
                + m.ip_cidrs.len()
                == 0
            {
                return Err(format!(
                    "rule {} has an empty match; use routing.default for fallback",
                    index + 1
                ));
            }
            for app in &mut m.apps {
                if !Path::new(app).is_absolute() || app.contains('\0') {
                    return Err(format!("rule {} app paths must be absolute", index + 1));
                }
                let path = clean_path(Path::new(app));
                if path == Path::new("/") {
                    return Err(format!("rule {} app path cannot be /", index + 1));
                }
                *app = path
                    .canonicalize()
                    .unwrap_or(path)
                    .to_string_lossy()
                    .into_owned();
            }
            if m.process_names
                .iter()
                .any(|name| name.is_empty() || name.contains(['/', '\0', '\n', '\r']))
            {
                return Err(format!("rule {} has an invalid process name", index + 1));
            }
            for domain in m.domains.iter_mut().chain(m.domain_suffixes.iter_mut()) {
                *domain = normalize_domain(domain);
                if !valid_domain(domain) {
                    return Err(format!(
                        "rule {} domains must be hostnames without schemes, ports, or wildcards",
                        index + 1
                    ));
                }
            }
            for cidr in &mut m.ip_cidrs {
                let parsed: IpNet = cidr.parse().map_err(|_| {
                    format!("rule {} has an invalid destination IP CIDR", index + 1)
                })?;
                *cidr = parsed.trunc().to_string();
            }
        }
        Ok(())
    }
    pub fn explain(&self, flow: &Flow) -> Decision {
        let mut flow = flow.clone();
        flow.domain = normalize_domain(&flow.domain);
        if !flow.app.is_empty() {
            let path = clean_path(Path::new(&flow.app));
            flow.app = path
                .canonicalize()
                .unwrap_or(path)
                .to_string_lossy()
                .into_owned();
            if flow.process_name.is_empty() {
                flow.process_name = Path::new(&flow.app)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned();
            }
        }
        for (i, rule) in self.routing.rules.iter().enumerate() {
            if rule.r#match.matches(&flow) {
                return Decision {
                    via: rule.via.clone(),
                    rule: rule.name.clone(),
                    index: i + 1,
                };
            }
        }
        Decision {
            via: self.routing.default.clone(),
            rule: "default".into(),
            index: 0,
        }
    }
}
impl Match {
    pub fn matches(&self, flow: &Flow) -> bool {
        let app = (self.apps.is_empty() && self.process_names.is_empty())
            || self.apps.iter().any(|app| {
                flow.app == *app
                    || app.ends_with(".app") && flow.app.starts_with(&format!("{app}/"))
            })
            || self.process_names.contains(&flow.process_name);
        let destination = (self.domains.is_empty()
            && self.domain_suffixes.is_empty()
            && self.ip_cidrs.is_empty())
            || self.domains.contains(&flow.domain)
            || self.domain_suffixes.iter().any(|domain| {
                flow.domain == *domain || flow.domain.ends_with(&format!(".{domain}"))
            })
            || self.ip_cidrs.iter().any(|cidr| {
                flow.ip
                    .is_some_and(|ip| cidr.parse::<IpNet>().is_ok_and(|net| net.contains(&ip)))
            });
        app && destination
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const EXAMPLE: &str = "version: 1\nvpns: {japan: {wireguard_config: ./conf/japan.conf}}\nrouting:\n  rules:\n    - {name: company, match: {domain_suffixes: [company.example]}, via: direct}\n    - {name: browser, match: {apps: [/Applications/Browser.app]}, via: japan}\n    - {name: destinations, match: {domains: [api.example.com], domain_suffixes: [example.org], ip_cidrs: [203.0.113.0/24]}, via: japan}\n    - {name: combined, match: {apps: [/usr/bin/curl], process_names: [wget], domains: [conditional.example]}, via: japan}\n";
    #[test]
    fn routing_priority_boundaries_and_groups() {
        let mut c = Config::from_text(EXAMPLE, Path::new("/settings/config.yaml")).unwrap();
        assert_eq!(
            c.vpns["japan"].wireguard_config,
            "/settings/conf/japan.conf"
        );
        for (app, process, domain, ip, rule) in [
            (
                "/Applications/Browser.app",
                "",
                "x.company.example",
                "",
                "company",
            ),
            (
                "/Applications/Browser.app",
                "",
                "other.example",
                "",
                "browser",
            ),
            (
                "/Applications/Browser.app/Contents/Helpers/h",
                "",
                "",
                "",
                "browser",
            ),
            (
                "/Applications/Browser.app.evil/Contents/h",
                "",
                "",
                "",
                "default",
            ),
            ("", "", "api.example.com", "", "destinations"),
            ("", "", "sub.api.example.com", "", "default"),
            ("", "", "EXAMPLE.ORG.", "", "destinations"),
            ("", "", "deep.sub.example.org", "", "destinations"),
            ("", "", "notexample.org", "", "default"),
            ("", "", "", "203.0.113.70", "destinations"),
            ("/usr/bin/curl", "", "conditional.example", "", "combined"),
            ("", "wget", "conditional.example", "", "combined"),
            ("/usr/bin/other", "", "conditional.example", "", "default"),
            ("/usr/bin/curl", "", "other.example", "", "default"),
        ] {
            let f = Flow {
                app: app.into(),
                process_name: process.into(),
                domain: domain.into(),
                ip: ip.parse().ok(),
            };
            assert_eq!(c.explain(&f).rule, rule);
        }
        c.routing.rules.swap(0, 1);
        assert_eq!(
            c.explain(&Flow {
                app: "/Applications/Browser.app".into(),
                domain: "company.example".into(),
                ..Flow::default()
            })
            .via,
            "japan"
        );
    }
    #[test]
    fn rejects_ambiguous_or_invalid_schema() {
        for input in [
            "version: 2", "version: 1\nunknown: true", "version: 1\n---\nversion: 1", "version: 1\nversion: 1",
            "version: 1\nvpns: {jp: {wireguard_config: a}, jp: {wireguard_config: b}}",
            "version: 1\nvpns: {jp: {wireguard_config: a, wireguard_config: b}}",
            "version: 1\nrouting: {default: missing}", "version: 1\ndns: {via: missing}", "version: 1\ndns: {server: dns.example}",
            "version: 1\ndns: {strategy: ipv4}", "version: 1\nvpns: {direct: {wireguard_config: a}}", "version: 1\nvpns: {vpnctl-x: {wireguard_config: a}}",
            "version: 1\nrouting: {rules: [{match: {}, via: direct}]}",
            "version: 1\nrouting: {rules: [{match: {domains: [https://example.org]}, via: direct}]}",
            "version: 1\nrouting: {rules: [{match: {domain_suffixes: ['*.example.org']}, via: direct}]}",
            "version: 1\nrouting: {rules: [{match: {domains: ['1.1.1.1']}, via: direct}]}",
            "version: 1\nrouting: {rules: [{match: {apps: [relative.app]}, via: direct}]}",
            "version: 1\nrouting: {rules: [{match: {apps: ['/']}, via: direct}]}",
            "version: 1\nrouting: {rules: [{match: {ip_cidrs: [bad]}, via: direct}]}",
            "version: 1\nrouting: {rules: [{match: {domains: [example.org]}, via: typo}]}",
        ] { assert!(Config::from_text(input, Path::new("/config.yaml")).is_err(), "accepted {input}"); }
    }
    #[test]
    fn defaults_and_normalization() {
        let c = Config::from_text("version: 1", Path::new("/config.yaml")).unwrap();
        assert_eq!(c.routing.default, "direct");
        assert_eq!(c.dns.via, "direct");
        assert_eq!(c.dns.strategy, "auto");
        assert_eq!(normalize_domain(" EXAMPLE.org. "), "example.org");
        assert_eq!(
            app_regex("/Applications/A+B.app"),
            "^/Applications/A\\+B\\.app/"
        );
    }
}
