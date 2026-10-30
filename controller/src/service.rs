//! macOS launchd lifecycle. No network extensions or developer entitlements.
use crate::runtime::{atomic_write, capture, check_engine, unique_name};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

pub const LABEL: &str = "local.routebar.v2";
pub const DIRECTORY: &str = "/Library/Application Support/RouteBarV2";
pub const PLIST: &str = "/Library/LaunchDaemons/local.routebar.v2.plist";
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Status {
    pub loaded: bool,
    pub running: bool,
    pub pid: u32,
    pub detail: String,
    #[serde(default)]
    pub foreground_unknown: bool,
}

pub trait Backend {
    fn start(&self, plist: &Path) -> Result<(), String>;
    fn stop(&self) -> Result<(), String>;
    fn status(&self) -> Result<Status, String>;
}
pub struct Launchd;
impl Backend for Launchd {
    fn start(&self, plist: &Path) -> Result<(), String> {
        let out = capture(
            Command::new("/bin/launchctl")
                .args(["bootstrap", "system"])
                .arg(plist),
            Duration::from_secs(20),
        )?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "launchctl bootstrap failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }
    fn stop(&self) -> Result<(), String> {
        let out = capture(
            Command::new("/bin/launchctl").args(["bootout", &format!("system/{LABEL}")]),
            Duration::from_secs(25),
        )?;
        if !out.status.success() {
            return Err(format!(
                "launchctl bootout failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if !self.status()?.loaded {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(100));
        }
        Err("service did not unregister; configuration retained for recovery".into())
    }
    fn status(&self) -> Result<Status, String> {
        launchd_status(LABEL)
    }
}
fn launchd_status(label: &str) -> Result<Status, String> {
    let out = capture(
        Command::new("/bin/launchctl").args(["print", &format!("system/{label}")]),
        Duration::from_secs(5),
    )?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        if err.to_lowercase().contains("could not find service") {
            return Ok(Status {
                detail: "stopped".into(),
                ..Status::default()
            });
        }
        return Err(format!("cannot inspect service: {}", err.trim()));
    }
    Ok(parse_status(&String::from_utf8_lossy(&out.stdout)))
}
fn parse_status(output: &str) -> Status {
    let pid = output
        .lines()
        .filter_map(|line| line.trim().strip_prefix("pid = "))
        .find_map(|p| p.trim().parse::<u32>().ok())
        .unwrap_or(0);
    Status {
        loaded: true,
        running: pid > 0,
        pid,
        detail: if pid > 0 {
            "running"
        } else {
            "loaded, not running"
        }
        .into(),
        foreground_unknown: false,
    }
}

pub struct OperationLock(File);
impl OperationLock {
    fn fd(&self) -> i32 {
        self.0.as_raw_fd()
    }
}

pub struct Manager<B: Backend = Launchd> {
    pub directory: PathBuf,
    pub plist: PathBuf,
    pub backend: B,
    pub network_check: fn() -> Result<(), String>,
    pub health_interval: Duration,
}
impl Default for Manager<Launchd> {
    fn default() -> Self {
        Self::new()
    }
}
impl Manager<Launchd> {
    pub fn new() -> Self {
        Self {
            directory: DIRECTORY.into(),
            plist: PLIST.into(),
            backend: Launchd,
            network_check: check_network,
            health_interval: Duration::from_millis(400),
        }
    }
}
impl<B: Backend> Manager<B> {
    pub fn operation_lock(&self) -> Result<OperationLock, String> {
        use std::os::unix::fs::DirBuilderExt;
        match fs::DirBuilder::new().mode(0o700).create(&self.directory) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.to_string()),
        }
        let metadata = fs::symlink_metadata(&self.directory).map_err(|e| e.to_string())?;
        if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(
                "runtime directory must be a real directory owned by the current administrator"
                    .into(),
            );
        }
        fs::set_permissions(&self.directory, fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.directory.join("lock"))
            .map_err(|e| e.to_string())?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("another operation or foreground run is active; stop foreground routing in its terminal".into());
        }
        Ok(OperationLock(file))
    }
    pub fn status(&self) -> Result<Status, String> {
        let status = self.backend.status()?;
        if status.loaded {
            return Ok(status);
        }
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.directory.join("foreground.lock"))
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(status),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return Ok(Status {
                detail:
                    "background stopped; administrator access required to inspect foreground mode"
                        .into(),
                foreground_unknown: true,
                ..status
            }),
            Err(e) => return Err(e.to_string()),
        };
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } == 0 {
            return Ok(status);
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(error.to_string());
        }
        let mut text = String::new();
        (&mut file)
            .take(4096)
            .read_to_string(&mut text)
            .map_err(|e| e.to_string())?;
        Ok(serde_json::from_str(&text).unwrap_or(Status {
            loaded: true,
            detail: "foreground starting or stopping".into(),
            ..Status::default()
        }))
    }
    fn healthy(&self) -> Result<(), String> {
        let mut last = 0;
        let mut stable = 0;
        for _ in 0..13 {
            let state = self.backend.status()?;
            if state.running && state.pid == last {
                stable += 1;
            } else {
                stable = 0;
            }
            if stable >= 6 {
                return Ok(());
            }
            last = state.pid;
            thread::sleep(self.health_interval);
        }
        Err("engine did not remain running; inspect service logs".into())
    }
    /// The caller validates before invoking. This method stages and checks an
    /// administrator-owned engine before stopping a currently running service.
    pub fn apply(
        &self,
        binary: &Path,
        source: &Path,
        data: &Value,
        reload: bool,
    ) -> Result<Status, String> {
        let _lock = self.operation_lock()?;
        let current = self.backend.status()?;
        if !reload && current.loaded {
            if current.running {
                return Ok(Status {
                    detail: "already running; use reload to apply changes".into(),
                    ..current
                });
            }
            return Err("service loaded but not running; inspect logs then reload or down".into());
        }
        if reload && !current.loaded {
            return Err("service is not loaded; use up first".into());
        }
        if !reload {
            (self.network_check)()?;
        }
        let config_path = self.directory.join("config.json");
        let meta_path = self.directory.join("state.json");
        let previous_config = fs::read(&config_path).ok();
        let previous_plist = fs::read(&self.plist).ok();
        let previous_meta = fs::read(&meta_path).ok();
        if reload
            && (previous_config.is_none() || previous_plist.is_none() || previous_meta.is_none())
        {
            return Err("service snapshot incomplete; use down before up".into());
        }
        let installed = self.directory.join(unique_name("sing-box"));
        // Unique root-owned copies prevent an app update/user-writable source
        // from replacing a program that launchd will execute at the next boot.
        atomic_write(
            &installed,
            &fs::read(binary).map_err(|e| e.to_string())?,
            0o700,
        )?;
        if let Err(e) = check_engine(&installed, data) {
            let _ = fs::remove_file(&installed);
            return Err(e);
        }
        if current.loaded {
            if let Err(e) = self.backend.stop() {
                let _ = fs::remove_file(&installed);
                return Err(e);
            }
        }
        let candidate = (|| {
            atomic_write(
                &config_path,
                &serde_json::to_vec_pretty(data).map_err(|e| e.to_string())?,
                0o600,
            )?;
            atomic_write(
                &self.plist,
                plist(&installed, &config_path, &self.directory).as_bytes(),
                0o644,
            )?;
            atomic_write(
                &meta_path,
                &serde_json::to_vec(&serde_json::json!({"config":source,"engine":installed}))
                    .map_err(|e| e.to_string())?,
                0o600,
            )?;
            let log = self.directory.join("service.log");
            let file = OpenOptions::new()
                .append(true)
                .create(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(log)
                .map_err(|e| e.to_string())?;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
            self.backend.start(&self.plist)?;
            self.healthy()
        })();
        if let Err(cause) = candidate {
            let failed = self
                .backend
                .status()
                .map_err(|e| format!("{cause}; cannot inspect failed service: {e}"))?;
            if failed.loaded {
                self.backend
                    .stop()
                    .map_err(|e| format!("{cause}; cannot stop failed service: {e}"))?;
            }
            let _ = fs::remove_file(&installed);
            if reload {
                atomic_write(
                    &config_path,
                    previous_config.as_deref().unwrap_or_default(),
                    0o600,
                )?;
                atomic_write(
                    &self.plist,
                    previous_plist.as_deref().unwrap_or_default(),
                    0o644,
                )?;
                if let Some(meta) = previous_meta {
                    atomic_write(&meta_path, &meta, 0o600)?;
                }
                self.backend
                    .start(&self.plist)
                    .and_then(|_| self.healthy())
                    .map_err(|e| {
                        format!("{cause}; old configuration restored but restart failed: {e}")
                    })?;
                return Err(format!(
                    "{cause}; previous configuration restored and running"
                ));
            }
            remove_if_exists(&config_path)?;
            remove_if_exists(&meta_path)?;
            remove_if_exists(&self.plist)?;
            return Err(cause);
        }
        // Only remove an old engine after the candidate has survived startup.
        if let Some(meta) = previous_meta {
            if let Ok(value) = serde_json::from_slice::<Value>(&meta) {
                if let Some(old) = value["engine"].as_str() {
                    let old = Path::new(old);
                    if old.parent() == Some(self.directory.as_path()) && old != installed {
                        let _ = fs::remove_file(old);
                    }
                }
            }
        }
        self.backend.status()
    }
    pub fn down(&self) -> Result<(), String> {
        let _lock = self.operation_lock()?;
        if self.backend.status()?.loaded {
            self.backend.stop()?;
        }
        for path in [
            &self.plist,
            &self.directory.join("config.json"),
            &self.directory.join("state.json"),
        ] {
            remove_if_exists(path)?;
        }
        for entry in fs::read_dir(&self.directory).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            if entry.file_name().to_string_lossy().starts_with("sing-box-") {
                remove_if_exists(&entry.path())?;
            }
        }
        Ok(())
    }
    pub fn run_foreground(&self, binary: &Path, data: &Value) -> Result<(), String> {
        let operation = self.operation_lock()?;
        if self.backend.status()?.loaded {
            return Err("background service is loaded; use down before run".into());
        }
        (self.network_check)()?;
        let mut lease = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.directory.join("foreground.lock"))
            .map_err(|e| e.to_string())?;
        if unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("foreground engine is still running".into());
        }
        lease.set_len(0).map_err(|e| e.to_string())?;
        let temp = crate::runtime::PrivateDir::new(&self.directory, "foreground")?;
        let config = temp.0.join("config.json");
        atomic_write(
            &config,
            &serde_json::to_vec(data).map_err(|e| e.to_string())?,
            0o600,
        )?;
        STOP.store(false, Ordering::SeqCst);
        let handlers = SignalHandlers::install();
        let mut command = Command::new(binary);
        command
            .arg("run")
            .arg("-c")
            .arg(&config)
            .arg("-D")
            .arg(&temp.0)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let fds = [operation.fd(), lease.as_raw_fd()];
        unsafe {
            command.pre_exec(move || {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                for fd in fds {
                    if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let mut child = command.spawn().map_err(|e| e.to_string())?;
        let state = Status {
            loaded: true,
            running: true,
            pid: child.id(),
            detail: "running (foreground)".into(),
            foreground_unknown: false,
        };
        if let Err(e) = lease.write_all(&serde_json::to_vec(&state).map_err(|e| e.to_string())?) {
            let _ = stop_child(&mut child);
            return Err(e.to_string());
        }
        println!("Foreground engine running (pid={}); Ctrl+C stops routing. Process status does not verify VPN egress.", child.id());
        let result = loop {
            if STOP.load(Ordering::SeqCst) {
                break stop_child(&mut child);
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    break if status.success() {
                        Ok(())
                    } else {
                        Err(format!("foreground engine exited: {status}"))
                    }
                }
                Ok(None) => thread::sleep(Duration::from_millis(100)),
                Err(e) => {
                    let _ = stop_child(&mut child);
                    break Err(e.to_string());
                }
            }
        };
        let _ = lease.set_len(0);
        drop(handlers);
        result
    }
}

static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}
struct SignalHandlers(Vec<(i32, libc::sighandler_t)>);
impl SignalHandlers {
    fn install() -> Self {
        Self(
            [libc::SIGINT, libc::SIGTERM, libc::SIGHUP]
                .iter()
                .map(|signal| {
                    (*signal, unsafe {
                        libc::signal(*signal, on_signal as *const () as libc::sighandler_t)
                    })
                })
                .collect(),
        )
    }
}
impl Drop for SignalHandlers {
    fn drop(&mut self) {
        for (signal, handler) in &self.0 {
            unsafe {
                libc::signal(*signal, *handler);
            }
        }
    }
}
pub fn stop_child(child: &mut Child) -> Result<(), String> {
    stop_child_with_signal(child, |pid| {
        if unsafe { libc::kill(pid, libc::SIGINT) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(error.to_string())
        }
    })
}
fn stop_child_with_signal(
    child: &mut Child,
    signal: impl FnOnce(i32) -> Result<(), String>,
) -> Result<(), String> {
    let completed = |status: std::process::ExitStatus| {
        if status.success() {
            Ok(())
        } else {
            Err(format!(
                "engine shutdown did not complete cleanly: {status}"
            ))
        }
    };
    // try_wait may already have reaped a failed probe. Never signal that stale
    // numeric PID; the OS is allowed to assign it to an unrelated process.
    if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
        return completed(status);
    }
    signal(child.id() as i32)?;
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            return completed(status);
        }
        thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
    Err("engine stop timed out and was forced; verify system DNS and routes".into())
}

fn remove_if_exists(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}
fn escape_xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
pub fn plist(binary: &Path, config: &Path, directory: &Path) -> String {
    let binary = escape_xml(&binary.to_string_lossy());
    let config = escape_xml(&config.to_string_lossy());
    let dir = escape_xml(&directory.to_string_lossy());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{LABEL}</string>
<key>ProgramArguments</key><array><string>{binary}</string><string>run</string><string>-c</string><string>{config}</string><string>-D</string><string>{dir}</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
<key>ThrottleInterval</key><integer>10</integer><key>ExitTimeOut</key><integer>15</integer><key>Umask</key><integer>63</integer>
<key>StandardOutPath</key><string>{dir}/service.log</string><key>StandardErrorPath</key><string>{dir}/service.log</string>
</dict></plist>
"#
    )
}

pub fn check_network() -> Result<(), String> {
    #[cfg(not(target_os = "macos"))]
    return Err("system routing requires macOS".into());
    #[cfg(target_os = "macos")]
    {
        if launchd_status("local.vpnctl")?.loaded {
            return Err(
                "vpn-v2's vpnctl service is loaded; stop it before starting RouteBar".into(),
            );
        }
        for destination in ["1.1.1.1", "200.1.1.1"] {
            let out = capture(
                Command::new("/sbin/route").args(["-n", "get", destination]),
                Duration::from_secs(3),
            )?;
            if !out.status.success() {
                return Err(
                    "cannot inspect default network route; connect a network before starting"
                        .into(),
                );
            }
            let output = String::from_utf8_lossy(&out.stdout);
            let interface = output
                .lines()
                .find_map(|l| l.trim().strip_prefix("interface:"))
                .map(str::trim)
                .ok_or("cannot identify default network interface")?;
            if ["utun", "tun", "ppp"]
                .iter()
                .any(|prefix| interface.starts_with(prefix))
            {
                return Err(format!(
                    "an existing VPN uses {interface}; disconnect it before starting RouteBar"
                ));
            }
        }
        Ok(())
    }
}

pub fn require_root() -> Result<(), String> {
    if !cfg!(target_os = "macos") {
        return Err("service management requires macOS".into());
    }
    if unsafe { libc::geteuid() } != 0 {
        return Err("administrator permission required; use the application's Connect button or sudo routebar-v2".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    struct Mock {
        state: RefCell<Status>,
        calls: RefCell<Vec<&'static str>>,
        fail_start: Cell<bool>,
    }
    impl Backend for Mock {
        fn start(&self, _: &Path) -> Result<(), String> {
            self.calls.borrow_mut().push("start");
            if self.fail_start.replace(false) {
                return Err("simulated launchd failure".into());
            }
            *self.state.borrow_mut() = Status {
                loaded: true,
                running: true,
                pid: 99,
                detail: "running".into(),
                foreground_unknown: false,
            };
            Ok(())
        }
        fn stop(&self) -> Result<(), String> {
            self.calls.borrow_mut().push("stop");
            *self.state.borrow_mut() = Status::default();
            Ok(())
        }
        fn status(&self) -> Result<Status, String> {
            Ok(self.state.borrow().clone())
        }
    }
    fn manager(dir: &Path, loaded: bool) -> Manager<Mock> {
        Manager {
            directory: dir.join("runtime"),
            plist: dir.join("service.plist"),
            backend: Mock {
                state: RefCell::new(Status {
                    loaded,
                    running: loaded,
                    pid: 42,
                    ..Status::default()
                }),
                calls: RefCell::new(vec![]),
                fail_start: Cell::new(false),
            },
            network_check: || Ok(()),
            health_interval: Duration::ZERO,
        }
    }
    #[test]
    fn status_parse() {
        let s = parse_status("service = {\n state = running\n pid = 1234\n}");
        assert!(s.loaded && s.running);
        assert_eq!(s.pid, 1234);
        assert!(!parse_status("state = waiting").running);
    }
    #[test]
    fn repeated_up_leaves_configuration_untouched() {
        let dir = crate::runtime::PrivateDir::new(&std::env::temp_dir(), "service-test").unwrap();
        let m = manager(&dir.0, true);
        let result = m
            .apply(
                Path::new("/nonexistent"),
                Path::new("config"),
                &serde_json::json!({}),
                false,
            )
            .unwrap();
        assert_eq!(result.pid, 42);
        assert!(m.backend.calls.borrow().is_empty());
    }
    #[test]
    fn lock_excludes_down_and_second_run() {
        let dir = crate::runtime::PrivateDir::new(&std::env::temp_dir(), "service-test").unwrap();
        let m = manager(&dir.0, false);
        let lock = m.operation_lock().unwrap();
        assert!(m.operation_lock().is_err());
        assert!(m.down().is_err());
        drop(lock);
        assert!(m.operation_lock().is_ok());
    }
    #[test]
    fn stop_unregisters_and_removes_secrets() {
        let dir = crate::runtime::PrivateDir::new(&std::env::temp_dir(), "service-test").unwrap();
        let m = manager(&dir.0, true);
        drop(m.operation_lock().unwrap());
        atomic_write(&m.directory.join("config.json"), b"secret", 0o600).unwrap();
        atomic_write(&m.plist, b"plist", 0o644).unwrap();
        m.down().unwrap();
        assert!(!m.directory.join("config.json").exists());
        assert!(!m.plist.exists());
        assert_eq!(*m.backend.calls.borrow(), vec!["stop"]);
    }
    #[test]
    fn xml_escapes_paths() {
        let p = plist(Path::new("/a<&'\""), Path::new("/c"), Path::new("/d"));
        assert!(p.contains("/a&lt;&amp;&apos;&quot;"));
        assert!(p.contains("<integer>63</integer>"));
    }
    fn fake_engine(directory: &Path, valid: bool) -> PathBuf {
        let path = directory.join("engine");
        let script = if valid {
            "#!/bin/sh\nif [ \"$1\" = version ]; then echo 'sing-box version 1.14.4'; fi\nexit 0\n"
        } else {
            "#!/bin/sh\necho 'unsupported version'\nexit 1\n"
        };
        atomic_write(&path, script.as_bytes(), 0o700).unwrap();
        path
    }
    #[test]
    fn failed_candidate_restores_previous_config_plist_metadata_and_service() {
        let dir = crate::runtime::PrivateDir::new(&std::env::temp_dir(), "service-test").unwrap();
        let m = manager(&dir.0, true);
        drop(m.operation_lock().unwrap());
        let old_engine = m.directory.join("sing-box-old");
        atomic_write(&old_engine, b"old engine", 0o700).unwrap();
        let old_meta = serde_json::to_vec(&serde_json::json!({"engine":old_engine})).unwrap();
        atomic_write(
            &m.directory.join("config.json"),
            b"previous secret config",
            0o600,
        )
        .unwrap();
        atomic_write(&m.directory.join("state.json"), &old_meta, 0o600).unwrap();
        atomic_write(&m.plist, b"previous plist", 0o644).unwrap();
        m.backend.fail_start.set(true);
        let result = m.apply(
            &fake_engine(&dir.0, true),
            Path::new("new source"),
            &serde_json::json!({"new":true}),
            true,
        );
        assert!(result
            .unwrap_err()
            .contains("previous configuration restored and running"));
        assert_eq!(
            fs::read(m.directory.join("config.json")).unwrap(),
            b"previous secret config"
        );
        assert_eq!(fs::read(m.directory.join("state.json")).unwrap(), old_meta);
        assert_eq!(fs::read(&m.plist).unwrap(), b"previous plist");
        assert!(old_engine.exists());
        assert_eq!(*m.backend.calls.borrow(), vec!["stop", "start", "start"]);
    }
    #[test]
    fn invalid_candidate_preserves_running_service_and_secrets() {
        let dir = crate::runtime::PrivateDir::new(&std::env::temp_dir(), "service-test").unwrap();
        let m = manager(&dir.0, true);
        drop(m.operation_lock().unwrap());
        for path in [
            m.directory.join("config.json"),
            m.directory.join("state.json"),
            m.plist.clone(),
        ] {
            atomic_write(&path, b"old", 0o600).unwrap();
        }
        assert!(m
            .apply(
                &fake_engine(&dir.0, false),
                Path::new("source"),
                &serde_json::json!({}),
                true
            )
            .is_err());
        assert!(m.backend.calls.borrow().is_empty());
        assert_eq!(fs::read(m.directory.join("config.json")).unwrap(), b"old");
    }
    #[test]
    fn engine_is_copied_to_private_runtime_and_plist_never_points_at_user_source() {
        let dir = crate::runtime::PrivateDir::new(&std::env::temp_dir(), "service-test").unwrap();
        let m = manager(&dir.0, false);
        let engine = fake_engine(&dir.0, true);
        m.apply(&engine, Path::new("source"), &serde_json::json!({}), false)
            .unwrap();
        let plist = fs::read_to_string(&m.plist).unwrap();
        assert!(!plist.contains(&format!("<string>{}</string>", engine.display())));
        let metadata: Value =
            serde_json::from_slice(&fs::read(m.directory.join("state.json")).unwrap()).unwrap();
        let installed = Path::new(metadata["engine"].as_str().unwrap());
        assert_eq!(installed.parent(), Some(m.directory.as_path()));
        assert_eq!(
            fs::metadata(installed).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(m.directory.join("config.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    #[test]
    fn runtime_symlink_is_rejected() {
        let dir = crate::runtime::PrivateDir::new(&std::env::temp_dir(), "service-test").unwrap();
        let m = manager(&dir.0, false);
        std::os::unix::fs::symlink(&dir.0, &m.directory).unwrap();
        assert!(m.operation_lock().is_err());
    }
    #[test]
    fn stop_already_reaped_child_never_signals_pid() {
        for status in ["0", "7"] {
            let mut child = Command::new("/bin/sh")
                .args(["-c", &format!("exit {status}")])
                .spawn()
                .unwrap();
            let exit = child.wait().unwrap();
            let called = Cell::new(false);
            let result = stop_child_with_signal(&mut child, |_| {
                called.set(true);
                Ok(())
            });
            assert!(!called.get());
            assert_eq!(result.is_ok(), exit.success());
        }
    }
}
