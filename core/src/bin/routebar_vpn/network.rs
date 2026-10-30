//! macOS route/DNS transactions. All child programs are fixed system paths;
//! configuration and journal contents are never interpreted as shell commands.
use ipnet::IpNet;
use routebar_core::config::Profile;
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const ROUTE: &str = "/sbin/route";
const IFCONFIG: &str = "/sbin/ifconfig";
const NETWORKSETUP: &str = "/usr/sbin/networksetup";
const SCUTIL: &str = "/usr/sbin/scutil";
const NETSTAT: &str = "/usr/sbin/netstat";
const SPLIT_ROUTES: [&str; 4] = ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"];

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPlan {
    pub endpoint: SocketAddr,
    pub underlay_interface: String,
    pub gateway: Ipv4Addr,
    pub addresses: Vec<IpNet>,
    pub dns: Vec<IpAddr>,
    pub mtu: u16,
    pub carries_ipv4: bool,
    pub carries_ipv6: bool,
    dns_before: Vec<DnsSnapshot>,
    default_before: RouteView,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DnsSnapshot {
    service: String,
    servers: Vec<IpAddr>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteView {
    network: IpNet,
    interface: String,
    gateway: Option<IpAddr>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedRoute {
    network: IpNet,
    interface: String,
    gateway: Option<Ipv4Addr>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Change {
    Route {
        route: OwnedRoute,
        confirmed: bool,
    },
    Dns {
        service: String,
        before: Vec<IpAddr>,
        installed: Vec<IpAddr>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkState {
    version: u32,
    tun: String,
    changes: Vec<Change>,
}

struct Output {
    success: bool,
    stdout: String,
    stderr: String,
}

trait Runner {
    fn run(&mut self, program: &str, args: &[String]) -> Result<Output, String>;
}

struct SystemRunner;
impl Runner for SystemRunner {
    fn run(&mut self, program: &str, args: &[String]) -> Result<Output, String> {
        let mut child = Command::new(program)
            .args(args)
            .env_clear()
            .env("LC_ALL", "C")
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| format!("Unable to start {program}"))?;
        let start = Instant::now();
        loop {
            if child
                .try_wait()
                .map_err(|_| "Unable to wait for system command")?
                .is_some()
            {
                break;
            }
            if start.elapsed() > Duration::from_secs(10) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("System command timed out: {program}"));
            }
            thread::sleep(Duration::from_millis(10));
        }
        let result = child
            .wait_with_output()
            .map_err(|_| "Unable to read system command result")?;
        if result.stdout.len() > 256 * 1024 || result.stderr.len() > 256 * 1024 {
            return Err("System command output exceeded limit".into());
        }
        Ok(Output {
            success: result.status.success(),
            stdout: String::from_utf8(result.stdout).map_err(|_| "Non-UTF8 system output")?,
            stderr: String::from_utf8(result.stderr).map_err(|_| "Non-UTF8 system error")?,
        })
    }
}

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| (*s).to_owned()).collect()
}

fn success(
    runner: &mut impl Runner,
    program: &str,
    arguments: &[String],
) -> Result<String, String> {
    let result = runner.run(program, arguments)?;
    // Darwin's route utility can print an operational error yet exit with 0.
    // None of our successful mutation commands require stderr output.
    if !result.success || result.stdout.starts_with("Error") || !result.stderr.trim().is_empty() {
        return Err(format!("System command failed: {program}"));
    }
    Ok(result.stdout)
}

fn valid_interface(name: &str) -> bool {
    !name.is_empty() && name.len() <= 15 && name.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn valid_tun(name: &str) -> bool {
    name.strip_prefix("utun")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        && valid_interface(name)
}

fn physical_interface(name: &str) -> bool {
    valid_interface(name)
        && ["en", "bridge", "bond"].iter().any(|prefix| {
            name.strip_prefix(prefix).is_some_and(|suffix| {
                !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit())
            })
        })
}

fn valid_service(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.starts_with('-')
        && !name.chars().any(char::is_control)
}

fn parse_services(output: &str) -> Result<Vec<String>, String> {
    let mut result = Vec::new();
    let mut pending: Option<String> = None;
    for line in output.lines().map(str::trim).filter(|s| !s.is_empty()) {
        if line.starts_with("An asterisk") {
            continue;
        }
        if line.starts_with("(Hardware Port:") {
            let service = pending.take();
            let (_, device) = line
                .rsplit_once(", Device: ")
                .ok_or("Malformed network service device")?;
            let device = device
                .strip_suffix(')')
                .ok_or("Malformed network service device")?;
            if let Some(service) = service {
                if physical_interface(device) {
                    result.push(service);
                }
            }
        } else if let Some((position, name)) =
            line.strip_prefix('(').and_then(|s| s.split_once(") "))
        {
            if pending.is_some() || !valid_service(name) {
                return Err("Malformed network service list".into());
            }
            if position == "*" || name.starts_with('*') {
                pending = None;
            } else if position.bytes().all(|b| b.is_ascii_digit()) && !position.is_empty() {
                pending = Some(name.to_string());
            } else {
                return Err("Malformed network service index".into());
            }
        } else {
            return Err("Unrecognized network service list".into());
        }
    }
    if pending.is_some() || result.is_empty() || result.len() > 32 {
        return Err("No supported hardware network services, or incomplete service list".into());
    }
    result.sort();
    result.dedup();
    Ok(result)
}

fn read_dns(runner: &mut impl Runner, service: &str) -> Result<Vec<IpAddr>, String> {
    let output = success(runner, NETWORKSETUP, &args(&["-getdnsservers", service]))?;
    if output.trim() == format!("There aren't any DNS Servers set on {service}.") {
        return Ok(Vec::new());
    }
    let values = output
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<IpAddr>()
                .map_err(|_| "Unrecognized DNS configuration".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if values.is_empty() || values.len() > 16 {
        return Err("Unsupported DNS configuration".into());
    }
    Ok(values)
}

fn set_dns(runner: &mut impl Runner, service: &str, servers: &[IpAddr]) -> Result<(), String> {
    let mut arguments = args(&["-setdnsservers", service]);
    if servers.is_empty() {
        arguments.push("Empty".into());
    } else {
        arguments.extend(servers.iter().map(ToString::to_string));
    }
    success(runner, NETWORKSETUP, &arguments)?;
    if read_dns(runner, service)? != servers {
        return Err("DNS setting did not match requested values".into());
    }
    Ok(())
}

fn parse_address(value: &str, v6: bool) -> Result<IpAddr, String> {
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok(ip);
    }
    // Darwin shortens IPv4 destination/mask fields (for example "128").
    if !v6 {
        let mut parts = value
            .split('.')
            .map(|part| part.parse::<u8>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "Unrecognized route address")?;
        if parts.is_empty() || parts.len() > 4 {
            return Err("Unrecognized route address".into());
        }
        parts.resize(4, 0);
        return Ok(Ipv4Addr::new(parts[0], parts[1], parts[2], parts[3]).into());
    }
    Err("Unrecognized route address".into())
}

fn parse_route(output: &str, v6: bool) -> Result<RouteView, String> {
    let field = |key: &str| {
        output
            .lines()
            .find_map(|line| line.trim().strip_prefix(key).map(str::trim))
    };
    let interface = field("interface:")
        .filter(|s| valid_interface(s))
        .ok_or("Missing route interface")?;
    let destination = field("destination:").ok_or("Missing route destination")?;
    let gateway = field("gateway:").and_then(|s| s.parse::<IpAddr>().ok());
    let network = if destination.contains('/') {
        destination
            .parse::<IpNet>()
            .map_err(|_| "Invalid route prefix")?
            .trunc()
    } else {
        // Darwin can label the zero destination "default" even for a /1;
        // the returned mask determines the actual route prefix.
        let address = parse_address(
            if destination == "default" {
                if v6 {
                    "::"
                } else {
                    "0.0.0.0"
                }
            } else {
                destination
            },
            v6,
        )?;
        let is_host =
            field("flags:").is_some_and(|s| s.split([',', '<', '>']).any(|flag| flag == "HOST"));
        let prefix = if is_host {
            if v6 {
                128
            } else {
                32
            }
        } else {
            let mask = field("mask:")
                .or(if destination == "default" {
                    Some("default")
                } else {
                    None
                })
                .ok_or("Missing route netmask")?;
            if mask == "default" {
                0
            } else {
                let mask = parse_address(mask, v6)?;
                match mask {
                    IpAddr::V4(mask) => {
                        let bits = u32::from(mask);
                        if bits != u32::MAX.checked_shl(bits.trailing_zeros()).unwrap_or(0) {
                            return Err("Non-contiguous route netmask".into());
                        }
                        bits.count_ones() as u8
                    }
                    IpAddr::V6(mask) => {
                        let bits = u128::from(mask);
                        if bits != u128::MAX.checked_shl(bits.trailing_zeros()).unwrap_or(0) {
                            return Err("Non-contiguous route netmask".into());
                        }
                        bits.count_ones() as u8
                    }
                }
            }
        };
        IpNet::new(address, prefix)
            .map_err(|_| "Invalid route prefix")?
            .trunc()
    };
    if network.addr().is_ipv6() != v6 {
        return Err("Unexpected route address family".into());
    }
    Ok(RouteView {
        network,
        interface: interface.into(),
        gateway,
    })
}

fn route_get(runner: &mut impl Runner, network: IpNet) -> Result<Option<RouteView>, String> {
    let family = if network.addr().is_ipv6() {
        "-inet6"
    } else {
        "-inet"
    };
    let query = if network.prefix_len() == 0 {
        "default".to_string()
    } else {
        network.to_string()
    };
    let output = runner.run(ROUTE, &args(&["-n", "get", family, &query]))?;
    // An absent route is normal (especially IPv6 on IPv4-only networks).
    // Actual Darwin output has an empty stdout and may still have exit code 0.
    if output.stdout.trim().is_empty()
        && matches!(
            output.stderr.trim(),
            "route: writing to routing socket: not in table" | "route: route has not been found"
        )
    {
        return Ok(None);
    }
    if !output.success || !output.stderr.trim().is_empty() {
        return Err(format!("Unable to inspect {family} route for {query}"));
    }
    parse_route(&output.stdout, network.addr().is_ipv6())
        .map(Some)
        .map_err(|error| format!("Unable to parse {family} route for {query}: {error}"))
}

fn host_network(ip: IpAddr) -> IpNet {
    IpNet::new(ip, if ip.is_ipv4() { 32 } else { 128 }).unwrap()
}

fn default_route_get(runner: &mut impl Runner) -> Result<Option<RouteView>, String> {
    // Inspect the actual /0 entry. A destination lookup of 0.0.0.0 can instead
    // select our more-specific /1 after startup and falsely report a change.
    let output = success(runner, NETSTAT, &args(&["-nr", "-f", "inet"]))?;
    let mut routes = Vec::new();
    for line in output.lines() {
        let columns = line.split_whitespace().collect::<Vec<_>>();
        if columns.first().copied() != Some("default") {
            continue;
        }
        if columns.len() < 4 || !valid_interface(columns[3]) {
            return Err("Unrecognized default routing table entry".into());
        }
        // I is RTF_IFSCOPE; ignore scoped fallbacks on secondary services.
        if columns[2].contains('I') {
            continue;
        }
        let gateway = columns[1].parse::<Ipv4Addr>().ok().map(IpAddr::V4);
        if gateway.is_none() && !columns[1].starts_with("link#") {
            return Err("Unrecognized default route gateway".into());
        }
        routes.push(RouteView {
            network: "0.0.0.0/0".parse().unwrap(),
            interface: columns[3].into(),
            gateway,
        });
    }
    if routes.len() > 1 {
        return Err("Multiple unscoped IPv4 default routes are unsupported".into());
    }
    Ok(routes.pop())
}

fn no_other_vpn(runner: &mut impl Runner) -> Result<(), String> {
    let state = success(runner, SCUTIL, &args(&["--nc", "list"]))?;
    if state.lines().any(|line| {
        [
            "(Connected)",
            "(Connecting)",
            "(Reasserting)",
            "(Disconnecting)",
        ]
        .iter()
        .any(|s| line.contains(s))
    }) {
        return Err("Another VPN is active; disconnect it before starting RouteBar".into());
    }
    Ok(())
}

impl NetworkPlan {
    pub fn discover(profile: &Profile, endpoint: SocketAddr) -> Result<Self, String> {
        Self::discover_with(profile, endpoint, &mut SystemRunner)
    }

    fn discover_with(
        profile: &Profile,
        endpoint: SocketAddr,
        runner: &mut impl Runner,
    ) -> Result<Self, String> {
        if !endpoint.is_ipv4() {
            return Err("This CLI currently requires an IPv4 VPN endpoint".into());
        }
        let carries_ipv4 = profile.addresses.iter().any(|ip| ip.addr().is_ipv4());
        let carries_ipv6 = profile.addresses.iter().any(|ip| ip.addr().is_ipv6());
        for (enabled, default) in [(carries_ipv4, "0.0.0.0/0"), (carries_ipv6, "::/0")] {
            if enabled
                && !profile
                    .allowed_ips
                    .iter()
                    .any(|prefix| *prefix == default.parse::<IpNet>().unwrap())
            {
                return Err("Full-device mode requires a default AllowedIPs route for each configured address family".into());
            }
        }
        let dns = profile
            .dns
            .iter()
            .copied()
            .filter(|ip| {
                if ip.is_ipv4() {
                    carries_ipv4
                } else {
                    carries_ipv6
                }
            })
            .collect::<Vec<_>>();
        if dns.is_empty() || dns.len() > 16 {
            return Err("Full-device mode requires DNS servers reachable through the configured address families".into());
        }
        no_other_vpn(runner)?;
        let underlay =
            route_get(runner, host_network(endpoint.ip()))?.ok_or("No route to VPN endpoint")?;
        if !physical_interface(&underlay.interface) {
            return Err(
                "VPN endpoint must use a physical en/bridge/bond interface, not another tunnel"
                    .into(),
            );
        }
        let gateway = match underlay.gateway {
            Some(IpAddr::V4(ip)) if !ip.is_unspecified() && !ip.is_multicast() => ip,
            _ => return Err("VPN endpoint requires a physical IPv4 gateway".into()),
        };
        let default_before = default_route_get(runner)?.ok_or("No IPv4 default route")?;
        if default_before.interface != underlay.interface
            || default_before.gateway != underlay.gateway
        {
            return Err("VPN endpoint and default route use different underlays; custom routing is unsupported".into());
        }
        for prefix in SPLIT_ROUTES {
            let network = prefix.parse::<IpNet>().unwrap();
            if route_get(runner, network)?.is_some_and(|route| route.network == network) {
                return Err("A split-default route already exists; refusing to replace it".into());
            }
        }
        let services = parse_services(&success(
            runner,
            NETWORKSETUP,
            &args(&["-listnetworkserviceorder"]),
        )?)?;
        let mut dns_before = Vec::new();
        for service in services {
            dns_before.push(DnsSnapshot {
                servers: read_dns(runner, &service)?,
                service,
            });
        }
        Ok(Self {
            endpoint,
            underlay_interface: underlay.interface,
            gateway,
            addresses: profile.addresses.clone(),
            dns,
            mtu: profile.mtu,
            carries_ipv4,
            carries_ipv6,
            dns_before,
            default_before,
        })
    }

    pub fn underlay_unchanged(&self) -> Result<bool, String> {
        self.underlay_unchanged_with(&mut SystemRunner)
    }

    fn underlay_unchanged_with(&self, runner: &mut impl Runner) -> Result<bool, String> {
        Ok(default_route_get(runner)?.as_ref() == Some(&self.default_before))
    }

    pub fn apply(
        &self,
        state: &mut NetworkState,
        persist: &mut impl FnMut(&NetworkState) -> Result<(), String>,
    ) -> Result<(), String> {
        self.apply_with(state, persist, &mut SystemRunner)
    }

    fn apply_with(
        &self,
        state: &mut NetworkState,
        persist: &mut impl FnMut(&NetworkState) -> Result<(), String>,
        runner: &mut impl Runner,
    ) -> Result<(), String> {
        state.validate()?;
        if !state.is_clean() {
            return Err("Network journal is not empty".into());
        }
        no_other_vpn(runner)?;
        if !self.underlay_unchanged_with(runner)? {
            return Err("Underlay changed after preflight; run the command again".into());
        }
        for before in &self.dns_before {
            if read_dns(runner, &before.service)? != before.servers {
                return Err("DNS changed after preflight; refusing to overwrite it".into());
            }
        }
        let tun = state.tun.clone();
        success(
            runner,
            IFCONFIG,
            &args(&[&tun, "mtu", &self.mtu.to_string()]),
        )?;
        let mut addresses = self.addresses.clone();
        if !self.carries_ipv4 {
            addresses.push("192.0.0.8/32".parse().unwrap());
        }
        if !self.carries_ipv6 {
            addresses.push("fd00:726f:7574:6562::1/128".parse().unwrap());
        }
        for address in addresses {
            if address.addr().is_ipv4() {
                success(
                    runner,
                    IFCONFIG,
                    &args(&[
                        &tun,
                        "inet",
                        &address.to_string(),
                        &address.addr().to_string(),
                        "alias",
                    ]),
                )?;
            } else {
                success(
                    runner,
                    IFCONFIG,
                    &args(&[&tun, "inet6", &address.to_string(), "alias"]),
                )?;
            }
        }
        success(runner, IFCONFIG, &args(&[&tun, "up"]))?;
        let endpoint_route = OwnedRoute {
            network: host_network(self.endpoint.ip()),
            interface: self.underlay_interface.clone(),
            gateway: Some(self.gateway),
        };
        // A pre-existing matching host route needs no modification or ownership.
        let existing = route_get(runner, endpoint_route.network)?;
        if existing
            .as_ref()
            .is_some_and(|route| route.network == endpoint_route.network)
        {
            if !endpoint_route.matches(existing.as_ref().unwrap()) {
                return Err("Endpoint host route changed after preflight".into());
            }
        } else {
            state.add_route(endpoint_route, persist, runner)?;
        }
        for prefix in SPLIT_ROUTES {
            state.add_route(
                OwnedRoute {
                    network: prefix.parse().unwrap(),
                    interface: tun.clone(),
                    gateway: None,
                },
                persist,
                runner,
            )?;
        }
        for before in &self.dns_before {
            if before.servers == self.dns {
                continue;
            }
            if read_dns(runner, &before.service)? != before.servers {
                return Err("DNS changed while starting; refusing to overwrite it".into());
            }
            state.changes.push(Change::Dns {
                service: before.service.clone(),
                before: before.servers.clone(),
                installed: self.dns.clone(),
            });
            persist(state)?;
            set_dns(runner, &before.service, &self.dns)?;
        }
        Ok(())
    }
}

impl OwnedRoute {
    fn matches(&self, view: &RouteView) -> bool {
        view.network == self.network
            && view.interface == self.interface
            && self
                .gateway
                .is_none_or(|gateway| view.gateway == Some(gateway.into()))
    }

    fn command(&self, action: &str) -> Vec<String> {
        let family = if self.network.addr().is_ipv4() {
            "-inet"
        } else {
            "-inet6"
        };
        if let Some(gateway) = self.gateway {
            args(&[
                "-n",
                action,
                family,
                "-host",
                &self.network.addr().to_string(),
                &gateway.to_string(),
            ])
        } else {
            args(&[
                "-n",
                action,
                family,
                "-net",
                &self.network.to_string(),
                "-interface",
                &self.interface,
            ])
        }
    }
}

impl NetworkState {
    pub fn new(tun: &str) -> Result<Self, String> {
        let state = Self {
            version: 1,
            tun: tun.into(),
            changes: Vec::new(),
        };
        state.validate()?;
        Ok(state)
    }

    pub fn interface_name(&self) -> &str {
        &self.tun
    }
    pub fn is_clean(&self) -> bool {
        self.changes.is_empty()
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1 || !valid_tun(&self.tun) || self.changes.len() > 40 {
            return Err("Invalid network recovery journal".into());
        }
        for change in &self.changes {
            match change {
                Change::Route { route, .. } => {
                    let valid = if let Some(gateway) = route.gateway {
                        route.network.addr().is_ipv4()
                            && route.network.prefix_len() == 32
                            && physical_interface(&route.interface)
                            && !gateway.is_unspecified()
                            && !gateway.is_multicast()
                    } else {
                        route.interface == self.tun
                            && SPLIT_ROUTES
                                .iter()
                                .any(|s| s.parse::<IpNet>().unwrap() == route.network)
                    };
                    if !valid {
                        return Err("Invalid route in recovery journal".into());
                    }
                }
                Change::Dns {
                    service,
                    before,
                    installed,
                } => {
                    if !valid_service(service)
                        || before.len() > 16
                        || installed.is_empty()
                        || installed.len() > 16
                    {
                        return Err("Invalid DNS in recovery journal".into());
                    }
                }
            }
        }
        Ok(())
    }

    fn add_route(
        &mut self,
        route: OwnedRoute,
        persist: &mut impl FnMut(&NetworkState) -> Result<(), String>,
        runner: &mut impl Runner,
    ) -> Result<(), String> {
        if route_get(runner, route.network)?.is_some_and(|r| r.network == route.network) {
            return Err("Route already exists; refusing to replace it".into());
        }
        self.changes.push(Change::Route {
            route: route.clone(),
            confirmed: false,
        });
        persist(self)?;
        // A timeout or failed result does not prove the kernel rejected the
        // write. Retain unconfirmed intent; cleanup can discard it if absent,
        // but must preserve a matching route whose ownership is ambiguous.
        success(runner, ROUTE, &route.command("add"))?;
        if let Some(Change::Route { confirmed, .. }) = self.changes.last_mut() {
            *confirmed = true;
        }
        persist(self)?;
        Ok(())
    }

    pub fn rollback(
        &mut self,
        persist: &mut impl FnMut(&NetworkState) -> Result<(), String>,
    ) -> Result<(), String> {
        self.rollback_with(persist, &mut SystemRunner)
    }

    fn rollback_with(
        &mut self,
        persist: &mut impl FnMut(&NetworkState) -> Result<(), String>,
        runner: &mut impl Runner,
    ) -> Result<(), String> {
        self.validate()?;
        let mut errors = Vec::new();
        for index in (0..self.changes.len()).rev() {
            let change = self.changes[index].clone();
            let result = (|| {
                match &change {
                    Change::Route { route, confirmed } => {
                        if let Some(current) = route_get(runner, route.network)? {
                            if current.network != route.network {
                                return Ok(());
                            }
                            if !route.matches(&current) {
                                return Err("Route changed externally; preserved it".into());
                            }
                            if !confirmed {
                                return Err(
                                    "Unconfirmed route ownership; manual recovery required".into(),
                                );
                            }
                            persist(self)?;
                            success(runner, ROUTE, &route.command("delete"))?;
                        }
                    }
                    Change::Dns {
                        service,
                        before,
                        installed,
                    } => {
                        let current = read_dns(runner, service)?;
                        if current == *before {
                            return Ok(());
                        }
                        if current != *installed {
                            return Err("DNS changed externally; preserved it".into());
                        }
                        persist(self)?;
                        set_dns(runner, service, before)?;
                    }
                }
                Ok(())
            })();
            if let Err(error) = result {
                errors.push(error);
                continue;
            }
            self.changes.remove(index);
            if let Err(error) = persist(self) {
                self.changes.insert(index, change);
                errors.push(error);
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::HashMap, rc::Rc};

    struct FixedOutput {
        success: bool,
        stdout: &'static str,
        stderr: &'static str,
    }

    impl Runner for FixedOutput {
        fn run(&mut self, _: &str, _: &[String]) -> Result<Output, String> {
            Ok(Output {
                success: self.success,
                stdout: self.stdout.into(),
                stderr: self.stderr.into(),
            })
        }
    }

    #[test]
    fn darwin_missing_ipv6_route_is_absent_even_with_zero_exit_status() {
        for exited_successfully in [true, false] {
            let mut runner = FixedOutput {
                success: exited_successfully,
                stdout: "",
                stderr: "route: writing to routing socket: not in table\n",
            };
            for prefix in ["::/1", "8000::/1"] {
                assert!(route_get(&mut runner, prefix.parse().unwrap())
                    .unwrap()
                    .is_none());
            }
        }
    }

    #[test]
    fn route_query_and_mutation_errors_are_not_success_or_missing_routes() {
        for stderr in [
            "route: writing to routing socket: Permission denied\n",
            "unexpected diagnostic\n",
            "",
        ] {
            let mut runner = FixedOutput {
                success: true,
                stdout: "",
                stderr,
            };
            assert!(route_get(&mut runner, "::/1".parse().unwrap()).is_err());
        }
        let mut runner = FixedOutput {
            success: true,
            stdout: "add net 0.0.0.0: gateway utun42\n",
            stderr: "route: writing to routing socket: File exists\n",
        };
        assert!(success(&mut runner, ROUTE, &args(&["-n", "add"])).is_err());
        let mut runner = FixedOutput {
            success: true,
            stdout: "destination: default\nmask: default\ngateway: 192.0.2.1\ninterface: en7\nflags: <UP,GATEWAY,DONE,STATIC>\n",
            stderr: "",
        };
        let route = route_get(&mut runner, "203.0.113.10/32".parse().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(route.interface, "en7");
        assert_eq!(route.network, "0.0.0.0/0".parse::<IpNet>().unwrap());
    }

    struct MockRunner {
        routes: Vec<RouteView>,
        dns: HashMap<String, Vec<IpAddr>>,
        journal: Rc<RefCell<Vec<NetworkState>>>,
        writes: usize,
        fail_at: Option<usize>,
        fail_dns_after_apply: bool,
        fail_route_after_apply: bool,
        active_vpn: bool,
    }

    fn default_route() -> RouteView {
        RouteView {
            network: "0.0.0.0/0".parse().unwrap(),
            interface: "en0".into(),
            gateway: Some("192.0.2.1".parse().unwrap()),
        }
    }

    fn plan() -> NetworkPlan {
        NetworkPlan {
            endpoint: "198.51.100.2:51820".parse().unwrap(),
            underlay_interface: "en0".into(),
            gateway: "192.0.2.1".parse().unwrap(),
            addresses: vec!["10.14.0.2/16".parse().unwrap()],
            dns: vec!["1.1.1.1".parse().unwrap()],
            mtu: 1280,
            carries_ipv4: true,
            carries_ipv6: false,
            dns_before: vec![DnsSnapshot {
                service: "Wi-Fi".into(),
                servers: vec!["8.8.8.8".parse().unwrap()],
            }],
            default_before: default_route(),
        }
    }

    fn mock() -> MockRunner {
        MockRunner {
            routes: vec![default_route()],
            dns: HashMap::from([("Wi-Fi".into(), vec!["8.8.8.8".parse().unwrap()])]),
            journal: Rc::new(RefCell::new(Vec::new())),
            writes: 0,
            fail_at: None,
            fail_dns_after_apply: false,
            fail_route_after_apply: false,
            active_vpn: false,
        }
    }

    fn ok(stdout: String) -> Result<Output, String> {
        Ok(Output {
            success: true,
            stdout,
            stderr: String::new(),
        })
    }

    impl Runner for MockRunner {
        fn run(&mut self, program: &str, arguments: &[String]) -> Result<Output, String> {
            if program == NETSTAT {
                return ok(self
                    .routes
                    .iter()
                    .filter(|route| {
                        route.network.prefix_len() == 0 && route.network.addr().is_ipv4()
                    })
                    .map(|route| {
                        format!(
                            "default {} UGSc {}\n",
                            route
                                .gateway
                                .map(|ip| ip.to_string())
                                .unwrap_or_else(|| "link#42".into()),
                            route.interface
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(""));
            }
            if program == SCUTIL {
                return ok(if self.active_vpn {
                    "* (Connected) VPN"
                } else {
                    "* (Disconnected) VPN"
                }
                .into());
            }
            if program == NETWORKSETUP {
                if arguments[0] == "-listnetworkserviceorder" {
                    return ok("An asterisk (*) denotes that a network service is disabled.\n(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n".into());
                }
                if arguments[0] == "-getdnsservers" {
                    let dns = self.dns.get(&arguments[1]).ok_or("Unknown service")?;
                    return ok(if dns.is_empty() {
                        format!("There aren't any DNS Servers set on {}.\n", arguments[1])
                    } else {
                        dns.iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join("\n")
                    });
                }
            }
            if program == ROUTE && arguments[1] == "get" {
                let network = if arguments[3] == "default" {
                    if arguments[2] == "-inet6" {
                        "::/0"
                    } else {
                        "0.0.0.0/0"
                    }
                    .parse::<IpNet>()
                    .unwrap()
                } else {
                    arguments[3].parse::<IpNet>().unwrap()
                };
                let route = self
                    .routes
                    .iter()
                    .filter(|route| route.network.contains(&network.addr()))
                    .max_by_key(|route| route.network.prefix_len());
                return match route {
                    Some(route) => ok(format!(
                        "destination: {}\nmask: {}\ninterface: {}\n{}flags: <UP,STATIC{}>\n",
                        if route.network.prefix_len() == 0 {
                            "default".to_string()
                        } else {
                            route.network.addr().to_string()
                        },
                        route.network.netmask(),
                        route.interface,
                        route
                            .gateway
                            .map(|ip| format!("gateway: {ip}\n"))
                            .unwrap_or_default(),
                        if route.network.prefix_len()
                            == if network.addr().is_ipv4() { 32 } else { 128 }
                        {
                            ",HOST"
                        } else {
                            ""
                        }
                    )),
                    None => Ok(Output {
                        success: true,
                        stdout: String::new(),
                        stderr: "route: writing to routing socket: not in table\n".into(),
                    }),
                };
            }
            self.writes += 1;
            let should_fail = self.fail_at == Some(self.writes);
            if program == IFCONFIG {
                return if should_fail {
                    Err("Injected ifconfig failure".into())
                } else {
                    ok(String::new())
                };
            }
            // Every persistent routing or DNS write must already be journaled.
            assert!(!self.journal.borrow().last().unwrap().changes.is_empty());
            if program == ROUTE {
                if should_fail && !self.fail_route_after_apply {
                    return Err("Injected route failure".into());
                }
                let network = if arguments[3] == "-host" {
                    host_network(arguments[4].parse().unwrap())
                } else {
                    arguments[4].parse().unwrap()
                };
                if arguments[1] == "add" {
                    assert!(!self.routes.iter().any(|route| route.network == network));
                    self.routes.push(RouteView {
                        network,
                        interface: if arguments[3] == "-host" {
                            "en0".into()
                        } else {
                            arguments[6].clone()
                        },
                        gateway: if arguments[3] == "-host" {
                            Some(arguments[5].parse().unwrap())
                        } else {
                            None
                        },
                    });
                } else {
                    self.routes.retain(|route| route.network != network);
                }
                if should_fail {
                    return Err("Injected ambiguous route failure".into());
                }
            } else if program == NETWORKSETUP && arguments[0] == "-setdnsservers" {
                if should_fail && !self.fail_dns_after_apply {
                    return Err("Injected DNS failure".into());
                }
                let servers = if arguments[2] == "Empty" {
                    vec![]
                } else {
                    arguments[2..].iter().map(|s| s.parse().unwrap()).collect()
                };
                self.dns.insert(arguments[1].clone(), servers);
                if should_fail {
                    return Err("Injected partial DNS failure".into());
                }
            } else {
                panic!("Unexpected mocked command {program}");
            }
            ok(String::new())
        }
    }

    #[test]
    fn network_rollback_restores_after_each_start_failure_including_partial_dns() {
        // Four interface operations, endpoint + four split routes, then DNS.
        for fail_at in 1..=10 {
            for partial_dns in [false, true] {
                let mut runner = mock();
                runner.fail_at = Some(fail_at);
                runner.fail_dns_after_apply = partial_dns;
                let journal = runner.journal.clone();
                let mut persist = |state: &NetworkState| {
                    journal.borrow_mut().push(state.clone());
                    Ok(())
                };
                let mut state = NetworkState::new("utun42").unwrap();
                assert!(plan()
                    .apply_with(&mut state, &mut persist, &mut runner)
                    .is_err());
                runner.fail_at = None;
                state.rollback_with(&mut persist, &mut runner).unwrap();
                assert!(state.is_clean(), "failure step {fail_at}");
                assert_eq!(runner.routes, vec![default_route()]);
                assert_eq!(
                    runner.dns["Wi-Fi"],
                    vec!["8.8.8.8".parse::<IpAddr>().unwrap()]
                );
            }
        }
    }

    #[test]
    fn network_success_installs_both_families_and_preserves_existing_endpoint_route() {
        let mut runner = mock();
        let endpoint = RouteView {
            network: "198.51.100.2/32".parse().unwrap(),
            interface: "en0".into(),
            gateway: Some("192.0.2.1".parse().unwrap()),
        };
        runner.routes.push(endpoint.clone());
        let journal = runner.journal.clone();
        let mut persist = |state: &NetworkState| {
            journal.borrow_mut().push(state.clone());
            Ok(())
        };
        let mut state = NetworkState::new("utun42").unwrap();
        plan()
            .apply_with(&mut state, &mut persist, &mut runner)
            .unwrap();
        assert_eq!(
            runner
                .routes
                .iter()
                .filter(|route| route.interface == "utun42")
                .count(),
            4
        );
        state.rollback_with(&mut persist, &mut runner).unwrap();
        assert!(state.is_clean());
        assert_eq!(runner.routes, vec![default_route(), endpoint]);
    }

    #[test]
    fn network_cleanup_preserves_external_changes_and_can_retry() {
        let mut runner = mock();
        let journal = runner.journal.clone();
        let mut persist = |state: &NetworkState| {
            journal.borrow_mut().push(state.clone());
            Ok(())
        };
        let mut state = NetworkState::new("utun42").unwrap();
        plan()
            .apply_with(&mut state, &mut persist, &mut runner)
            .unwrap();
        runner
            .dns
            .insert("Wi-Fi".into(), vec!["9.9.9.9".parse().unwrap()]);
        runner
            .routes
            .iter_mut()
            .find(|r| r.network == "0.0.0.0/1".parse::<IpNet>().unwrap())
            .unwrap()
            .interface = "utun99".into();
        assert!(state.rollback_with(&mut persist, &mut runner).is_err());
        assert_eq!(state.changes.len(), 2);
        assert_eq!(
            runner.dns["Wi-Fi"],
            vec!["9.9.9.9".parse::<IpAddr>().unwrap()]
        );
        assert!(runner.routes.iter().any(|r| r.interface == "utun99"));
        runner.dns.insert("Wi-Fi".into(), plan().dns);
        runner.routes.retain(|r| r.interface != "utun99");
        state.rollback_with(&mut persist, &mut runner).unwrap();
        assert!(state.is_clean());
        assert_eq!(runner.routes, vec![default_route()]);
    }

    #[test]
    fn network_journal_failure_prevents_persistent_mutation() {
        let mut runner = mock();
        let mut state = NetworkState::new("utun42").unwrap();
        assert!(plan()
            .apply_with(&mut state, &mut |_| Err("disk failure".into()), &mut runner)
            .is_err());
        assert_eq!(runner.routes, vec![default_route()]);
        assert_eq!(
            runner.dns["Wi-Fi"],
            vec!["8.8.8.8".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn network_preflight_rejects_tunnels_dns_changes_and_existing_split_routes() {
        let mut runner = mock();
        runner.active_vpn = true;
        let mut state = NetworkState::new("utun42").unwrap();
        assert!(plan()
            .apply_with(&mut state, &mut |_| Ok(()), &mut runner)
            .is_err());
        assert_eq!(runner.writes, 0);
        runner.active_vpn = false;
        runner.routes[0].interface = "utun19".into();
        assert!(!plan().underlay_unchanged_with(&mut runner).unwrap());
        runner.routes[0] = default_route();
        runner.dns.insert("Wi-Fi".into(), vec![]);
        assert!(plan()
            .apply_with(&mut state, &mut |_| Ok(()), &mut runner)
            .is_err());
        assert_eq!(runner.writes, 0);
    }

    #[test]
    fn network_discovery_checks_full_profile_and_route_conflicts_without_writes() {
        let mut profile = Profile {
            private_key: [1; 32],
            peer_key: [2; 32],
            preshared_key: None,
            endpoint_host: "example.com".into(),
            endpoint_port: 51820,
            addresses: vec!["10.14.0.2/16".parse().unwrap()],
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            dns: vec![
                "1.1.1.1".parse().unwrap(),
                "2606:4700:4700::1111".parse().unwrap(),
            ],
            mtu: 1280,
            keepalive: 25,
        };
        let mut runner = mock();
        let endpoint = "198.51.100.2:51820".parse().unwrap();
        let discovered = NetworkPlan::discover_with(&profile, endpoint, &mut runner).unwrap();
        assert_eq!(discovered.dns, vec!["1.1.1.1".parse::<IpAddr>().unwrap()]);
        assert!(discovered.carries_ipv4 && !discovered.carries_ipv6);
        profile.allowed_ips = vec!["10.0.0.0/8".parse().unwrap()];
        assert!(NetworkPlan::discover_with(&profile, endpoint, &mut runner).is_err());
        profile.allowed_ips = vec!["0.0.0.0/0".parse().unwrap()];
        runner.routes.push(RouteView {
            network: "0.0.0.0/1".parse().unwrap(),
            interface: "en0".into(),
            gateway: Some("192.0.2.1".parse().unwrap()),
        });
        assert!(NetworkPlan::discover_with(&profile, endpoint, &mut runner).is_err());
        assert_eq!(runner.writes, 0);
    }

    #[test]
    fn network_recovery_does_not_delete_unconfirmed_endpoint_route() {
        let mut runner = mock();
        let route = OwnedRoute {
            network: "198.51.100.2/32".parse().unwrap(),
            interface: "en0".into(),
            gateway: Some("192.0.2.1".parse().unwrap()),
        };
        runner.routes.push(RouteView {
            network: route.network,
            interface: route.interface.clone(),
            gateway: route.gateway.map(IpAddr::V4),
        });
        let mut state = NetworkState::new("utun42").unwrap();
        state.changes.push(Change::Route {
            route,
            confirmed: false,
        });
        assert!(state.rollback_with(&mut |_| Ok(()), &mut runner).is_err());
        assert!(!state.is_clean());
        assert_eq!(runner.writes, 0);
    }

    #[test]
    fn network_ambiguous_add_failure_keeps_durable_recovery_intent() {
        let mut runner = mock();
        runner.fail_at = Some(5); // Endpoint route, after the four utun settings.
        runner.fail_route_after_apply = true;
        let journal = runner.journal.clone();
        let mut persist = |state: &NetworkState| {
            journal.borrow_mut().push(state.clone());
            Ok(())
        };
        let mut state = NetworkState::new("utun42").unwrap();
        assert!(plan()
            .apply_with(&mut state, &mut persist, &mut runner)
            .is_err());
        assert_eq!(state.changes.len(), 1);
        assert_eq!(journal.borrow().last().unwrap().changes.len(), 1);
        runner.fail_at = None;
        assert!(state.rollback_with(&mut persist, &mut runner).is_err());
        assert!(!state.is_clean());
        assert!(runner
            .routes
            .iter()
            .any(|r| r.network == host_network(plan().endpoint.ip())));
    }

    #[test]
    fn network_parsers_and_recovery_validation_fail_closed() {
        assert_eq!(
            parse_route(
                "destination: default\nmask: 128.0.0.0\ninterface: utun42\n",
                false
            )
            .unwrap()
            .network,
            "0.0.0.0/1".parse::<IpNet>().unwrap()
        );
        assert_eq!(
            parse_route(
                "destination: default\nmask: 8000::\ninterface: utun42\n",
                true
            )
            .unwrap()
            .network,
            "::/1".parse::<IpNet>().unwrap()
        );
        assert_eq!(parse_services("An asterisk (*) denotes that a network service is disabled.\n(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n(2) VPN\n(Hardware Port: VPN, Device: )\n(*) Disabled\n(Hardware Port: Ethernet, Device: en3)\n").unwrap(), vec!["Wi-Fi"]);
        assert!(parse_services("(1) Wi-Fi\ninvalid").is_err());
        assert!(
            parse_route("destination: 128\nmask: 128\ninterface: utun42\n", false)
                .unwrap()
                .network
                == "128.0.0.0/1".parse::<IpNet>().unwrap()
        );
        assert!(parse_route(
            "destination: 0.0.0.0\nmask: 255.0.255.0\ninterface: utun42\n",
            false
        )
        .is_err());
        assert!(parse_route("destination: default\ninterface: en0;bad\n", false).is_err());
        assert!(NetworkState::new("en0").is_err());
        let mut state = NetworkState::new("utun42").unwrap();
        state.changes.push(Change::Route {
            route: OwnedRoute {
                network: "10.0.0.0/8".parse().unwrap(),
                interface: "utun42".into(),
                gateway: None,
            },
            confirmed: true,
        });
        assert!(state.validate().is_err());
        assert!(!physical_interface("utun42"));
        assert!(!physical_interface("ppp0"));
        assert!(!physical_interface("lo0"));
    }
}
