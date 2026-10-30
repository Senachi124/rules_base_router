use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, Eq)]
pub struct AppIdentity {
    pub signing_id: String,
    pub team_id: String,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct AppRule {
    pub id: String,
    pub name: String,
    pub path: String,
    pub enabled: bool,
    pub identities: Vec<AppIdentity>,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct DomainRule {
    pub id: String,
    pub domain: String,
    pub enabled: bool,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct Policy {
    pub mode: String,
    pub apps: Vec<AppRule>,
    pub domains: Vec<DomainRule>,
}

#[derive(Default, Deserialize)]
pub struct FlowIdentity {
    #[serde(default)]
    pub signing_id: String,
    #[serde(default)]
    pub team_id: String,
    pub hostname: Option<String>,
}

#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct Decision {
    pub route: &'static str,
    pub reason: String,
}

pub fn normalize_domain(input: &str) -> Result<String, String> {
    let input = input
        .trim()
        .trim_end_matches('.')
        .strip_prefix("*.")
        .unwrap_or(input.trim().trim_end_matches('.'));
    let name = idna::domain_to_ascii(input)
        .map_err(|_| "Invalid domain name")?
        .to_ascii_lowercase();
    if name.len() > 253
        || name.parse::<std::net::IpAddr>().is_ok()
        || !name.contains('.')
        || name.split('.').any(|l| {
            l.is_empty()
                || l.len() > 63
                || l.starts_with('-')
                || l.ends_with('-')
                || !l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
    {
        return Err("Enter a domain such as example.com, without a URL, path or port".into());
    }
    Ok(name)
}

impl Policy {
    pub fn validate(&mut self) -> Result<(), String> {
        if !["whitelist", "full"].contains(&self.mode.as_str()) {
            return Err("Unknown routing mode".into());
        }
        if self.apps.len() > 256 || self.domains.len() > 1024 {
            return Err("Too many rules".into());
        }
        for domain in &mut self.domains {
            domain.domain = normalize_domain(&domain.domain)?;
        }
        for app in &self.apps {
            if app.identities.is_empty()
                || app
                    .identities
                    .iter()
                    .any(|i| i.signing_id.is_empty() || i.team_id.is_empty())
            {
                return Err(
                    "Application rules require signed application identities and a Team ID".into(),
                );
            }
        }
        Ok(())
    }
    pub fn evaluate(&self, flow: &FlowIdentity) -> Decision {
        if self.mode == "full" {
            return Decision {
                route: "vpn",
                reason: "Full-device mode".into(),
            };
        }
        for rule in self.apps.iter().filter(|r| r.enabled) {
            if rule
                .identities
                .iter()
                .any(|i| i.signing_id == flow.signing_id && i.team_id == flow.team_id)
            {
                return Decision {
                    route: "vpn",
                    reason: format!("Application: {}", rule.name),
                };
            }
        }
        if let Some(host) = flow
            .hostname
            .as_deref()
            .and_then(|h| normalize_domain(h).ok())
        {
            for rule in self.domains.iter().filter(|r| r.enabled) {
                if host == rule.domain || host.ends_with(&format!(".{}", rule.domain)) {
                    return Decision {
                        route: "vpn",
                        reason: format!("Domain: {}", rule.domain),
                    };
                }
            }
        }
        Decision {
            route: "direct",
            reason: if flow.hostname.is_none() {
                "No app match; hostname unavailable".into()
            } else {
                "No matching rule".into()
            },
        }
    }
}
