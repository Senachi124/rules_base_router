use routebar_v2::{
    config::{Config, Flow},
    engine, runtime,
};
use serde_json::json;
use std::io::{BufRead, Write};
use std::os::windows::process::CommandExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    collections::BTreeMap,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS},
    Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY},
    System::{
        Console::{GenerateConsoleCtrlEvent, SetConsoleCtrlHandler, CTRL_BREAK_EVENT},
        Threading::{CreateMutexW, GetCurrentProcess, OpenProcessToken, CREATE_NEW_PROCESS_GROUP},
    },
};

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("{}", json!({"error":error}));
        std::process::exit(1);
    }
}
struct Options {
    command: String,
    values: BTreeMap<String, String>,
}
impl Options {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let command = args.first().map(String::as_str).unwrap_or("help");
        let allowed: &[&str] = match command {
            "validate" | "run" => &["config", "engine"],
            "render" => &["config", "engine", "output"],
            "config-inspect" => &["config"],
            "explain" => &["config", "app", "process", "domain", "ip"],
            "help" | "--help" | "-h" | "version" | "--version" => &[],
            _ => return Err("unknown Windows command; use routebar-v2 help".into()),
        };
        let mut values = BTreeMap::new();
        let mut i = 1;
        let mut json_seen = false;
        while i < args.len() {
            if args[i] == "--json" && !json_seen {
                json_seen = true;
                i += 1;
                continue;
            }
            let key = if args[i] == "-c" {
                "config"
            } else {
                args[i].strip_prefix("--").unwrap_or("")
            };
            if !allowed.contains(&key) {
                return Err(format!("unsupported option {}", args[i]));
            }
            i += 1;
            let value = args.get(i).ok_or("option requires a value")?;
            if values.insert(key.to_owned(), value.clone()).is_some() {
                return Err(format!("duplicate option --{key}"));
            }
            i += 1;
        }
        Ok(Self {
            command: command.to_owned(),
            values,
        })
    }
    fn value(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }
}
fn run(args: Vec<String>) -> Result<(), String> {
    let options = Options::parse(args)?;
    match options.command.as_str() {
        "help" | "--help" | "-h" => {
            println!(
                "RouteBar for Windows\n\
            validate -c CONFIG [--engine PATH]  Validate rules, profiles and engine\n\
            config-inspect -c CONFIG           Normalized JSON, no keys\n\
            explain -c CONFIG --app PATH --domain HOST [--process NAME] [--ip IP]\n\
            render -c CONFIG                   Redacted engine configuration\n\
            render -c CONFIG --output PATH     ACL-protected configuration with keys\n\
            run -c CONFIG                      Administrator; Ctrl+C or stdin stop to disconnect\n\
            version                            Controller version\n\
            The Windows app owns the VPN lifetime. No boot service is installed."
            );
            return Ok(());
        }
        "version" | "--version" => {
            println!(
                "{}",
                json!({"version":env!("CARGO_PKG_VERSION"),"platform":"windows"})
            );
            return Ok(());
        }
        _ => {}
    }
    if options.command == "run" {
        require_admin()?;
    }
    let source = Path::new(options.value("config").unwrap_or("config.yaml"));
    let config = Config::load(source)?;
    if options.command == "config-inspect" {
        println!(
            "{}",
            serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?
        );
        return Ok(());
    }
    if options.command == "explain" {
        let app = options.value("app").unwrap_or("");
        let process = options.value("process").unwrap_or("");
        let domain = options.value("domain").unwrap_or("");
        let ip = options
            .value("ip")
            .map(str::parse)
            .transpose()
            .map_err(|_| "invalid IP address")?;
        if !app.is_empty() && !Path::new(app).is_absolute() {
            return Err("--app requires an absolute Windows path".into());
        }
        if !domain.is_empty()
            && !routebar_v2::config::valid_domain(&routebar_v2::config::normalize_domain(domain))
        {
            return Err("invalid domain".into());
        }
        if app.is_empty() && process.is_empty() && domain.is_empty() && ip.is_none() {
            return Err("provide a flow selector".into());
        }
        println!(
            "{}",
            serde_json::to_string(&config.explain(&Flow {
                app: app.into(),
                process_name: process.into(),
                domain: domain.into(),
                ip
            }))
            .map_err(|e| e.to_string())?
        );
        return Ok(());
    }
    let generated = engine::generate(&config)?;
    if options.command == "render" && options.value("output").is_none() {
        println!(
            "{}",
            serde_json::to_string_pretty(&engine::redacted(&generated.json))
                .map_err(|e| e.to_string())?
        );
        return Ok(());
    }
    let binary = runtime::locate_engine(options.value("engine"))?;
    runtime::check_engine(&binary, &generated.json)?;
    match options.command.as_str() {
        "validate" => println!(
            "{}",
            json!({"valid":true,"vpns":config.vpns.len(),"rules":config.routing.rules.len(),"warnings":generated.warnings})
        ),
        "render" => {
            let output =
                std::path::absolute(options.value("output").unwrap()).map_err(|e| e.to_string())?;
            let same = |path: &Path| {
                std::fs::canonicalize(path)
                    .unwrap_or_else(|_| path.to_owned())
                    .to_string_lossy()
                    .eq_ignore_ascii_case(
                        &std::fs::canonicalize(&output)
                            .unwrap_or(output.clone())
                            .to_string_lossy(),
                    )
            };
            if same(&config.source)
                || config
                    .vpns
                    .values()
                    .any(|v| same(Path::new(&v.wireguard_config)))
            {
                return Err("output must not overwrite the source or a profile".into());
            }
            runtime::atomic_write(
                &output,
                &serde_json::to_vec_pretty(&generated.json).map_err(|e| e.to_string())?,
                0o600,
            )?;
            println!("{}", json!({"output":output,"contains_private_keys":true}));
        }
        "run" => run_engine(&binary, &generated.json)?,
        _ => unreachable!(),
    }
    Ok(())
}
fn require_admin() -> Result<(), String> {
    let mut token = 0;
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err("cannot inspect Windows access token".into());
    }
    let mut elevation: TOKEN_ELEVATION = unsafe { std::mem::zeroed() };
    let mut length = 0;
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as _,
            std::mem::size_of_val(&elevation) as u32,
            &mut length,
        )
    };
    unsafe {
        CloseHandle(token);
    }
    if ok == 0 || elevation.TokenIsElevated == 0 {
        return Err("Run RouteBar as administrator to connect the VPN".into());
    }
    Ok(())
}
static STOP: AtomicBool = AtomicBool::new(false);
unsafe extern "system" fn stop_handler(_: u32) -> i32 {
    STOP.store(true, Ordering::Relaxed);
    1
}
fn run_engine(binary: &Path, config: &serde_json::Value) -> Result<(), String> {
    struct Handle(isize);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    let name: Vec<u16> = "Global\\RouteBarWindowsVPN"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mutex = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
    if mutex == 0 {
        return Err("cannot acquire system VPN lock".into());
    }
    let existing = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
    let _lock = Handle(mutex);
    if existing {
        return Err("another RouteBar connection is running".into());
    }
    let dir = runtime::PrivateDir::new(&std::env::temp_dir(), "routebar-run")?;
    let path = dir.0.join("config.json");
    runtime::atomic_write(
        &path,
        &serde_json::to_vec(config).map_err(|e| e.to_string())?,
        0o600,
    )?;
    // Config goes away after process exit; job termination also covers crashes.
    let job = runtime::Job::new()?;
    let mut child = Command::new(binary)
        .arg("run")
        .arg("-c")
        .arg(&path)
        .arg("-D")
        .arg(&dir.0)
        .creation_flags(CREATE_NEW_PROCESS_GROUP)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    if let Err(error) = job.assign(&child) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    let stderr = child.stderr.take().unwrap();
    let secrets = config.clone();
    let reader = std::thread::spawn(move || {
        for line in std::io::BufReader::new(stderr)
            .lines()
            .map_while(Result::ok)
        {
            println!(
                "{}",
                json!({"event":"log","message":runtime::sanitize(&line, &secrets)})
            );
        }
    });
    STOP.store(false, Ordering::Relaxed);
    unsafe {
        SetConsoleCtrlHandler(Some(stop_handler), 1);
    }
    std::thread::spawn(|| {
        for line in std::io::stdin().lock().lines() {
            if line.map_or(true, |s| s.trim() == "stop") {
                break;
            }
        }
        STOP.store(true, Ordering::Relaxed);
    });
    let start = Instant::now();
    let mut announced = false;
    let result = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Err(format!("engine exited ({status}); inspect logs")),
            Err(e) => break Err(e.to_string()),
            Ok(None) => {}
        }
        if STOP.load(Ordering::Relaxed) {
            break Ok(());
        }
        if !announced && start.elapsed() > Duration::from_secs(2) {
            println!(
                "{}",
                json!({"event":"running","pid":child.id(),"detail":"Process running; VPN handshake and egress are not verified"})
            );
            let _ = std::io::stdout().flush();
            announced = true;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    unsafe {
        GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, child.id());
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while matches!(child.try_wait(), Ok(None)) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(job);
    let _ = child.wait();
    let _ = reader.join();
    unsafe {
        SetConsoleCtrlHandler(Some(stop_handler), 0);
    }
    println!("{}", json!({"event":"stopped"}));
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unknown_duplicate_and_service_options() {
        for args in [
            vec!["up"],
            vec!["run", "--config", "a", "-c", "b"],
            vec!["render", "--raw"],
            vec!["validate", "--json", "--json"],
        ] {
            assert!(Options::parse(args.into_iter().map(str::to_owned).collect()).is_err());
        }
    }
}
