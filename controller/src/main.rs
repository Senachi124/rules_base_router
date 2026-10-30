use routebar_v2::{
    config::{Config, Flow},
    engine, runtime, service, session,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        if std::env::args().any(|a| a == "--json") {
            println!("{}", json!({"error":error}));
        } else {
            eprintln!("routebar-v2: {error}");
        }
        std::process::exit(1);
    }
}
struct Options {
    command: String,
    values: BTreeMap<String, String>,
    json: bool,
}
impl Options {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let command = args.first().cloned().unwrap_or_else(|| "help".into());
        let mut values = BTreeMap::new();
        let mut json = false;
        let mut i = 1;
        let permitted: &[&str] = match command.as_str() {
            "validate" | "config-inspect" | "up" | "reload" | "run" => &["config", "engine"],
            "render" => &["config", "engine", "output"],
            "explain" => &["config", "app", "process", "domain", "ip"],
            "probe" => &["config", "engine", "via"],
            "logs" => &["lines"],
            "session-start" => &["owner-pid", "owner-uid", "session-id"],
            "session-serve" => &["state"],
            "status" | "down" | "help" | "--help" | "-h" | "version" | "--version" => &[],
            _ => return Err(format!("unknown command {command}; use routebar-v2 help")),
        };
        while i < args.len() {
            if args[i] == "--json" {
                if json {
                    return Err("duplicate --json".into());
                }
                json = true;
                i += 1;
                continue;
            }
            if args[i] == "--help" || args[i] == "-h" {
                return Ok(Self {
                    command: "help".into(),
                    values,
                    json,
                });
            }
            let key = match args[i].as_str() {
                "-c" | "--config" => "config",
                s => s
                    .strip_prefix("--")
                    .ok_or("unexpected positional argument")?,
            };
            if !permitted.contains(&key) {
                return Err(format!("unsupported option --{key} for {command}"));
            }
            i += 1;
            let value = args
                .get(i)
                .ok_or_else(|| format!("--{key} requires a value"))?;
            if values.insert(key.into(), value.clone()).is_some() {
                return Err(format!("duplicate option --{key}"));
            }
            i += 1;
        }
        Ok(Self {
            command,
            values,
            json,
        })
    }
    fn value(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }
    fn config(&self) -> &Path {
        Path::new(self.value("config").unwrap_or("config.yaml"))
    }
}
fn emit(value: Value, json_mode: bool, message: &str) {
    if json_mode {
        println!("{value}");
    } else {
        println!("{message}");
    }
}
fn run(args: Vec<String>) -> Result<(), String> {
    let options = Options::parse(args)?;
    let command = options.command.as_str();
    if ["help", "--help", "-h"].contains(&command) {
        println!("{}", HELP);
        return Ok(());
    }
    if ["version", "--version"].contains(&command) {
        emit(
            json!({"version":env!("CARGO_PKG_VERSION")}),
            options.json,
            &format!("routebar-v2 {}", env!("CARGO_PKG_VERSION")),
        );
        return Ok(());
    }
    if command == "session-start" {
        let pid = options
            .value("owner-pid")
            .ok_or("missing --owner-pid")?
            .parse::<u32>()
            .map_err(|_| "invalid owner PID")?;
        let uid = options
            .value("owner-uid")
            .ok_or("missing --owner-uid")?
            .parse::<u32>()
            .map_err(|_| "invalid owner UID")?;
        let id = options.value("session-id").ok_or("missing --session-id")?;
        println!("{}", session::start(pid, uid, id)?);
        return Ok(());
    }
    if command == "session-serve" {
        let state = options
            .value("state")
            .ok_or("missing internal session state")?;
        return session::serve(Path::new(state));
    }
    let manager = service::Manager::new();
    if ["up", "reload", "down", "run"].contains(&command) {
        service::require_root()?;
    }
    match command {
        "status" => {
            let state = manager.status()?;
            emit(serde_json::to_value(&state).map_err(|e|e.to_string())?,options.json,&format!("{} (pid={})\nProcess status does not confirm WireGuard handshake or VPN egress.",state.detail,state.pid));
            return Ok(());
        }
        "down" => {
            manager.down()?;
            emit(
                json!({"stopped":true}),
                options.json,
                "Stopped; launchd registration and generated secret configuration removed.",
            );
            return Ok(());
        }
        "logs" => {
            let lines = options
                .value("lines")
                .unwrap_or("50")
                .parse::<usize>()
                .map_err(|_| "--lines must be between 1 and 10000")?;
            if !(1..=10000).contains(&lines) {
                return Err("--lines must be between 1 and 10000".into());
            }
            let mut logs = runtime::read_tail(&manager.directory.join("service.log"), lines)?;
            // Defensive redaction of any engine output that happens to include keys.
            if let Ok(bytes) = std::fs::read(manager.directory.join("config.json")) {
                if let Ok(config) = serde_json::from_slice::<Value>(&bytes) {
                    logs = runtime::sanitize(&logs, &config);
                }
            }
            emit(json!({"logs":logs}), options.json, &logs);
            return Ok(());
        }
        _ => {}
    }
    let config = Config::load(options.config())?;
    if command == "config-inspect" {
        let normalized = serde_json::to_value(&config).map_err(|e| e.to_string())?;
        println!(
            "{}",
            serde_json::to_string_pretty(&normalized).map_err(|e| e.to_string())?
        );
        return Ok(());
    }
    if command == "explain" {
        let app = options.value("app").unwrap_or("").to_owned();
        if !app.is_empty() && !Path::new(&app).is_absolute() {
            return Err("--app must be an absolute path".into());
        }
        let process_name = options.value("process").unwrap_or("").to_owned();
        let domain = options.value("domain").unwrap_or("").to_owned();
        let ip = options
            .value("ip")
            .map(|s| {
                s.parse()
                    .map_err(|_| "--ip must be an IP address".to_owned())
            })
            .transpose()?;
        if app.is_empty() && process_name.is_empty() && domain.is_empty() && ip.is_none() {
            return Err("provide --app, --process, --domain, or --ip".into());
        }
        if !domain.is_empty() && !valid_domain(&domain) {
            return Err("--domain must be a hostname without wildcard, scheme or port".into());
        }
        let decision = config.explain(&Flow {
            app,
            process_name,
            domain,
            ip,
        });
        emit(
            serde_json::to_value(&decision).map_err(|e| e.to_string())?,
            options.json,
            &format!(
                "via: {}\nrule: {}\npriority: {} (first match wins; preview only)",
                decision.via, decision.rule, decision.index
            ),
        );
        return Ok(());
    }
    let generated = engine::generate(&config)?;
    if command == "render" && options.value("output").is_none() {
        println!(
            "{}",
            serde_json::to_string_pretty(&engine::redacted(&generated.json))
                .map_err(|e| e.to_string())?
        );
        return Ok(());
    }
    let binary = runtime::locate_engine(options.value("engine"))?;
    runtime::check_engine(&binary, &generated.json)?;
    match command {
        "validate" => emit(
            json!({"valid":true,"vpns":config.vpns.len(),"rules":config.routing.rules.len(),"default":config.routing.default,"dns_strategy":generated.dns_strategy,"warnings":generated.warnings}),
            options.json,
            &format!(
                "Valid: {} VPN(s), {} ordered rule(s), default={}, DNS={} via {}",
                config.vpns.len(),
                config.routing.rules.len(),
                config.routing.default,
                generated.dns_strategy,
                config.dns.via
            ),
        ),
        "render" => {
            let output = absolute(Path::new(options.value("output").ok_or("missing output")?))?;
            if same_file(&output, options.config())
                || config
                    .vpns
                    .values()
                    .any(|vpn| same_file(&output, Path::new(&vpn.wireguard_config)))
            {
                return Err(
                    "output must not overwrite the source configuration or a WireGuard profile"
                        .into(),
                );
            }
            runtime::atomic_write(
                &output,
                &serde_json::to_vec_pretty(&generated.json).map_err(|e| e.to_string())?,
                0o600,
            )?;
            emit(
                json!({"output":output,"contains_private_keys":true}),
                options.json,
                &format!(
                    "Wrote {} (contains private keys; mode 0600)",
                    output.display()
                ),
            );
        }
        "up" | "reload" => {
            let state = manager.apply(
                &binary,
                &absolute(options.config())?,
                &generated.json,
                command == "reload",
            )?;
            emit(serde_json::to_value(&state).map_err(|e|e.to_string())?,options.json,&format!("{} (pid={}); process status does not verify VPN egress. Reload may reset existing connections.",state.detail,state.pid));
        }
        "run" => {
            if options.json {
                return Err("run streams engine logs and does not support --json; use up for the application".into());
            }
            manager.run_foreground(&binary, &generated.json)?;
            println!("Stopped; foreground configuration removed.");
        }
        "probe" => {
            let via = options.value("via").unwrap_or(&config.routing.default);
            if via != "direct" && !config.vpns.contains_key(via) {
                return Err("unknown probe VPN".into());
            }
            let state = manager.status()?;
            if state.loaded || state.foreground_unknown {
                return Err("stop background/foreground routing before probe (sudo status can inspect foreground mode)".into());
            }
            if via != "direct" {
                service::check_network()?;
            }
            let result = probe(&binary, &generated.json, via)?;
            emit(result.clone(),options.json,&format!("via={} egress_ip={} country={}\nProbe checks only this exit; system routes and per-app rules were not changed or tested.",via,result["egress_ip"].as_str().unwrap_or(""),result["country"].as_str().unwrap_or("")));
        }
        _ => return Err("unsupported command".into()),
    }
    if !options.json {
        for warning in generated.warnings {
            eprintln!("warning: {warning}");
        }
    }
    Ok(())
}
fn absolute(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        Ok(path.to_owned())
    } else {
        Ok(std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(path))
    }
}
fn same_file(a: &Path, b: &Path) -> bool {
    let normalize =
        |p: &Path| std::fs::canonicalize(p).or_else(|_| absolute(p).map_err(std::io::Error::other));
    match (normalize(a), normalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}
fn valid_domain(domain: &str) -> bool {
    routebar_v2::config::valid_domain(&routebar_v2::config::normalize_domain(domain))
}

fn probe(binary: &Path, config: &Value, via: &str) -> Result<Value, String> {
    use std::net::{TcpListener, TcpStream};
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    drop(listener);
    let mut candidate = config.clone();
    candidate["inbounds"] = json!([{"type":"mixed","tag":"routebar-probe","listen":"127.0.0.1","listen_port":addr.port()}]);
    candidate["route"]["rules"] = json!([]);
    candidate["route"]["final"] = json!(via);
    candidate["route"]["find_process"] = json!(false);
    candidate["route"]["auto_detect_interface"] = json!(false);
    runtime::check_engine(binary, &candidate)?;
    let directory = runtime::PrivateDir::new(&std::env::temp_dir(), "routebar-probe")?;
    let path = directory.0.join("config.json");
    runtime::atomic_write(
        &path,
        &serde_json::to_vec(&candidate).map_err(|e| e.to_string())?,
        0o600,
    )?;
    let mut child = Command::new(binary)
        .arg("run")
        .arg("-c")
        .arg(&path)
        .arg("-D")
        .arg(&directory.0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let result = (|| {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if child.try_wait().map_err(|e| e.to_string())?.is_some() {
                return Err("probe engine stopped before listening".into());
            }
            if TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
                break;
            }
            if Instant::now() > deadline {
                return Err("probe listener startup timed out".into());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let output = runtime::capture(
            Command::new("/usr/bin/curl").args([
                "--disable",
                "--silent",
                "--show-error",
                "--fail",
                "--connect-timeout",
                "10",
                "--max-time",
                "25",
                "--noproxy",
                "",
                "--socks5-hostname",
                &addr.to_string(),
                "https://www.cloudflare.com/cdn-cgi/trace",
            ]),
            Duration::from_secs(30),
        )?;
        if !output.status.success() {
            return Err(format!(
                "probe connection failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let ip = text
            .lines()
            .find_map(|l| l.strip_prefix("ip="))
            .ok_or("probe returned no egress address")?;
        let _: std::net::IpAddr = ip
            .parse()
            .map_err(|_| "probe returned an invalid egress address")?;
        let country = text
            .lines()
            .find_map(|l| l.strip_prefix("loc="))
            .unwrap_or("");
        Ok(json!({"via":via,"egress_ip":ip,"country":country}))
    })();
    let stopped = service::stop_child(&mut child);
    match result {
        Ok(value) => {
            stopped?;
            Ok(value)
        }
        Err(e) => Err(e),
    }
}
const HELP: &str = "RouteBar v2 — Rust-controlled macOS per-app/domain WireGuard routing
Usage: routebar-v2 COMMAND [options]
  config-inspect -c config.yaml --json  Read normalized rules (no profile secrets)
  validate -c config.yaml              Check configuration and bundled engine
  explain -c config.yaml --app PATH --domain HOST [--process NAME] [--ip IP]
  render -c config.yaml                Print redacted engine JSON
  render -c config.yaml --output PATH  Write secret engine JSON (0600)
  up -c config.yaml                    Start launchd routing (administrator)
  reload -c config.yaml                Validate, restart, rollback on failure
  down                                Stop and remove generated secrets
  status [--json]                      Process status, not handshake verification
  logs --lines 100                     Read recent logs (administrator)
  run -c config.yaml                   Foreground routing, Ctrl+C to stop
  probe -c config.yaml --via NAME      Check egress without modifying routes
  version                             Version
Configuration uses vpn-v2 version 1 YAML or JSON. First matching rule wins.
Engine must be sing-box 1.14.x; override bundled executable with --engine PATH.
No Apple Developer certificate required. System TUN routing requires administrator permission.";

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn options_reject_duplicates_unknowns_and_positionals() {
        for args in [
            vec!["up", "--nonsense", "1"],
            vec!["down", "-c", "file"],
            vec!["status", "junk"],
            vec!["validate", "-c", "a", "--config", "b"],
            vec!["status", "--json", "--json"],
        ] {
            assert!(Options::parse(args.into_iter().map(str::to_owned).collect()).is_err());
        }
    }
    #[test]
    fn domain_input_validation() {
        assert!(valid_domain("EXAMPLE.com."));
        for s in [
            "*.example.com",
            "https://example.com",
            "1.2.3.4",
            "a..b",
            "foo:42",
            "example.org..",
        ] {
            assert!(!valid_domain(s));
        }
    }
}
