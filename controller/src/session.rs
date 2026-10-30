//! Ephemeral administrator session, scoped to one exact GUI process.
//!
//! The wire protocol accepts our v2 routing schema and profile *contents*. It
//! never accepts sing-box configuration, an engine path, or a file to read.
use crate::{config::Config, engine, runtime, service, wireguard};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const PROTOCOL: u32 = 1;
const MAX_FRAME: usize = 4 * 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Owner {
    pid: u32,
    uid: u32,
    start_seconds: u64,
    start_microseconds: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionState {
    session_id: String,
    owner: Owner,
}

#[cfg(target_os = "macos")]
fn process_owner(pid: u32) -> Result<Owner, String> {
    let pid = i32::try_from(pid).map_err(|_| "invalid owner process")?;
    if pid <= 1 {
        return Err("invalid owner process".into());
    }
    let mut information = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
    let actual = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            information.as_mut_ptr().cast(),
            size,
        )
    };
    if actual != size {
        return Err("application process is no longer available".into());
    }
    let information = unsafe { information.assume_init() };
    // Zombies have exited, even though proc_pidinfo can still report their PID.
    if information.pbi_pid != pid as u32 || information.pbi_status == libc::SZOMB {
        return Err("application process has exited".into());
    }
    Ok(Owner {
        pid: information.pbi_pid,
        uid: information.pbi_uid,
        start_seconds: information.pbi_start_tvsec,
        start_microseconds: information.pbi_start_tvusec,
    })
}
#[cfg(not(target_os = "macos"))]
fn process_owner(_: u32) -> Result<Owner, String> {
    Err("administrator sessions require macOS".into())
}
impl Owner {
    fn alive(&self) -> bool {
        process_owner(self.pid).as_ref() == Ok(self)
    }
}
fn valid_session_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn session_path(uid: u32, id: &str) -> Result<PathBuf, String> {
    if uid == 0 || !valid_session_id(id) {
        return Err("invalid application UID or session identifier".into());
    }
    let base = fs::canonicalize("/var/db").map_err(|_| "cannot resolve session directory")?;
    #[cfg(target_os = "macos")]
    if base != Path::new("/private/var/db") {
        return Err("unexpected /var/db directory".into());
    }
    // Every ancestor must be root-owned and non-writable by other users.
    // /var/run is intentionally not used: standard macOS makes it group-writable,
    // allowing another group member to rename a supposedly pinned session path.
    for ancestor in base.ancestors() {
        require_owned_directory(ancestor, 0, false)?;
    }
    Ok(base.join(format!("routebar-s-{uid}-{id}")))
}
fn require_owned_directory(path: &Path, uid: u32, private: bool) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "protected directory is unavailable")?;
    let forbidden = if private { 0o077 } else { 0o022 };
    if !metadata.is_dir() || metadata.uid() != uid || metadata.permissions().mode() & forbidden != 0
    {
        return Err("session directory ownership or permissions are unsafe".into());
    }
    Ok(())
}
fn protected_read(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "protected session file is unavailable")?;
    let metadata = file.metadata().map_err(|_| "cannot inspect session file")?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > maximum
    {
        return Err("invalid protected session file".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read session file")?;
    if bytes.len() as u64 > maximum {
        return Err("session file exceeds limit".into());
    }
    Ok(bytes)
}
fn copy_executable(source: &Path, destination: &Path) -> Result<(), String> {
    let mut file = File::open(source).map_err(|_| "bundled session executable is unavailable")?;
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect bundled executable")?;
    if !metadata.is_file() || metadata.len() > 256 * 1024 * 1024 {
        return Err("invalid bundled executable".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(256 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot snapshot bundled executable")?;
    if bytes.len() > 256 * 1024 * 1024 {
        return Err("bundled executable exceeds limit".into());
    }
    runtime::atomic_write(destination, &bytes, 0o700)
}

/// Called once through the macOS administrator authorization dialog.
pub fn start(owner_pid: u32, owner_uid: u32, session_id: &str) -> Result<Value, String> {
    service::require_root()?;
    let owner = process_owner(owner_pid)?;
    if owner.uid != owner_uid || owner_uid == 0 {
        return Err("session owner does not match the application process".into());
    }
    let directory = session_path(owner_uid, session_id)?;
    fs::DirBuilder::new()
        .mode(0o711)
        .create(&directory)
        .map_err(|_| "cannot create a new administrator session")?;
    let mut cleanup = Cleanup::new(directory.clone())?;
    let result = (|| {
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o711))
            .map_err(|_| "cannot protect session directory")?;
        let private = directory.join("private");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&private)
            .map_err(|_| "cannot create private session directory")?;
        let original = std::env::current_exe().map_err(|_| "cannot locate bundled controller")?;
        let engine_source = original
            .parent()
            .ok_or("controller directory is unavailable")?
            .join("sing-box");
        let helper = private.join("routebar-v2");
        let engine = private.join("sing-box");
        copy_executable(&original, &helper)?;
        copy_executable(&engine_source, &engine)?;
        runtime::check_version(&engine)?;
        let state_path = private.join("session.json");
        let state = SessionState {
            session_id: session_id.to_owned(),
            owner: owner.clone(),
        };
        runtime::atomic_write(
            &state_path,
            &serde_json::to_vec(&state).map_err(|_| "cannot encode session state")?,
            0o600,
        )?;
        if !owner.alive() {
            return Err("application exited before authorization completed".into());
        }
        let mut command = Command::new(&helper);
        command
            .args(["session-serve", "--state"])
            .arg(&state_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        let mut child = command
            .spawn()
            .map_err(|_| "cannot start administrator session")?;
        let deadline = Instant::now() + Duration::from_secs(10);
        let ready = private.join("ready");
        loop {
            if child
                .try_wait()
                .map_err(|_| "cannot inspect administrator session")?
                .is_some()
            {
                return Err("administrator session exited during startup".into());
            }
            if ready.exists() {
                if !owner.alive() {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("application exited during authorization".into());
                }
                let path = directory.join("control.sock");
                return Ok(json!({"socket_path":path,"session_id":session_id,"protocol":PROTOCOL}));
            }
            if !owner.alive() || Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err("administrator session startup timed out or application exited".into());
            }
            thread::sleep(Duration::from_millis(50));
        }
    })();
    if result.is_ok() {
        cleanup.armed = false;
    }
    result
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    session_id: String,
    command: String,
    config: Option<Config>,
    #[serde(default, deserialize_with = "unique_profiles")]
    profiles: Option<BTreeMap<String, String>>,
    lines: Option<usize>,
}
fn unique_profiles<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<BTreeMap<String, String>>, D::Error> {
    struct UniqueProfiles(BTreeMap<String, String>);
    impl<'de> Deserialize<'de> for UniqueProfiles {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct Visitor;
            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = UniqueProfiles;
                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("a map of unique VPN tags to profile contents")
                }
                fn visit_map<A: serde::de::MapAccess<'de>>(
                    self,
                    mut map: A,
                ) -> Result<Self::Value, A::Error> {
                    let mut profiles = BTreeMap::new();
                    while let Some((tag, content)) = map.next_entry::<String, String>()? {
                        if profiles.len() >= 32 || content.len() > 128 * 1024 {
                            return Err(serde::de::Error::custom("profile limits exceeded"));
                        }
                        if profiles.insert(tag, content).is_some() {
                            return Err(serde::de::Error::custom("duplicate profile tag"));
                        }
                    }
                    Ok(UniqueProfiles(profiles))
                }
            }
            deserializer.deserialize_map(Visitor)
        }
    }
    Option::<UniqueProfiles>::deserialize(deserializer)
        .map(|value| value.map(|UniqueProfiles(profiles)| profiles))
}

fn decode_request(bytes: &[u8]) -> Result<Request, String> {
    if bytes.len() > MAX_FRAME {
        return Err("request exceeds 4 MiB".into());
    }
    serde_json::from_slice(bytes).map_err(|_| "invalid administrator request schema".into())
}
fn validate_request(request: &Request, session_id: &str) -> Result<(), String> {
    if request.session_id != session_id {
        return Err("administrator session does not match".into());
    }
    match request.command.as_str() {
        "up" | "reload" => {
            if request.config.is_none() || request.profiles.is_none() || request.lines.is_some() {
                return Err(
                    "routing operation requires only configuration and profile contents".into(),
                );
            }
        }
        "logs" => {
            if request.config.is_some()
                || request.profiles.is_some()
                || request.lines.is_some_and(|n| !(1..=10000).contains(&n))
            {
                return Err("logs accepts only a line count from 1 to 10000".into());
            }
        }
        "ping" | "status" | "down" | "close" => {
            if request.config.is_some() || request.profiles.is_some() || request.lines.is_some() {
                return Err("unexpected fields for administrator command".into());
            }
        }
        _ => return Err("unsupported administrator command".into()),
    }
    Ok(())
}
struct Candidate {
    _directory: runtime::PrivateDir,
    config: Config,
    generated: engine::Generated,
}
fn prepare_candidate(
    value: &Config,
    profiles: &BTreeMap<String, String>,
    private_root: &Path,
) -> Result<Candidate, String> {
    if profiles.len() > 32 {
        return Err("at most 32 VPN profiles are supported per session request".into());
    }
    let text = serde_json::to_string(value).map_err(|_| "invalid routing configuration")?;
    // from_text only validates schema and paths. It does not read profile files.
    let mut config = Config::from_text(&text, &private_root.join("request.json"))?;
    if config.vpns.len() != profiles.len() || !config.vpns.keys().eq(profiles.keys()) {
        return Err("profile contents must match the configured VPN tags exactly".into());
    }
    for content in profiles.values() {
        wireguard::Config::parse(content)?;
    }
    let directory = runtime::PrivateDir::new(private_root, "request")?;
    for (index, (tag, vpn)) in config.vpns.iter_mut().enumerate() {
        let path = directory.0.join(format!("profile-{index}.conf"));
        runtime::atomic_write(&path, profiles[tag].as_bytes(), 0o600)?;
        // Ignore every client supplied wireguard_config path. Numeric filenames
        // are generated here, entirely inside the helper's private directory.
        vpn.wireguard_config = path.to_string_lossy().into_owned();
    }
    config.source = directory.0.join("request.json");
    let generated = engine::generate(&config)?;
    Ok(Candidate {
        _directory: directory,
        config,
        generated,
    })
}
trait Operations {
    fn status(&mut self) -> Result<Value, String>;
    fn apply(&mut self, candidate: &Candidate, reload: bool) -> Result<Value, String>;
    fn down(&mut self) -> Result<Value, String>;
    fn logs(&mut self, lines: usize) -> Result<Value, String>;
}
struct SystemOperations {
    engine: PathBuf,
    manager: service::Manager,
}
impl Operations for SystemOperations {
    fn status(&mut self) -> Result<Value, String> {
        serde_json::to_value(self.manager.status()?)
            .map_err(|_| "cannot encode service status".into())
    }
    fn apply(&mut self, candidate: &Candidate, reload: bool) -> Result<Value, String> {
        runtime::check_engine(&self.engine, &candidate.generated.json)?;
        serde_json::to_value(self.manager.apply(
            &self.engine,
            &candidate.config.source,
            &candidate.generated.json,
            reload,
        )?)
        .map_err(|_| "cannot encode service status".into())
    }
    fn down(&mut self) -> Result<Value, String> {
        self.manager.down()?;
        Ok(json!({"stopped":true}))
    }
    fn logs(&mut self, lines: usize) -> Result<Value, String> {
        let mut logs = runtime::read_tail(&self.manager.directory.join("service.log"), lines)?;
        if let Ok(bytes) = fs::read(self.manager.directory.join("config.json")) {
            if let Ok(config) = serde_json::from_slice::<Value>(&bytes) {
                logs = runtime::sanitize(&logs, &config);
            }
        }
        Ok(json!({"logs":logs}))
    }
}
fn execute(
    request: Request,
    session_id: &str,
    private_root: &Path,
    operations: &mut impl Operations,
) -> Result<(Value, bool), String> {
    validate_request(&request, session_id)?;
    let result = match request.command.as_str() {
        "ping" => json!({"session_id":session_id,"protocol":PROTOCOL}),
        "status" => operations.status()?,
        "down" => operations.down()?,
        "logs" => operations.logs(request.lines.unwrap_or(100))?,
        "close" => return Ok((json!({"closed":true}), true)),
        "up" | "reload" => {
            let candidate = prepare_candidate(
                request.config.as_ref().ok_or("missing configuration")?,
                request.profiles.as_ref().ok_or("missing profiles")?,
                private_root,
            )?;
            operations.apply(&candidate, request.command == "reload")?
        }
        _ => unreachable!("validate_request rejects other commands"),
    };
    Ok((result, false))
}

#[cfg(target_os = "macos")]
fn peer_identity(stream: &UnixStream) -> Result<(u32, u32), String> {
    let mut uid = 0;
    let mut gid = 0;
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err("cannot verify client credentials".into());
    }
    let mut pid: libc::pid_t = 0;
    let mut length = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut length,
        )
    } != 0
        || length as usize != std::mem::size_of::<libc::pid_t>()
        || pid <= 1
    {
        return Err("cannot verify client process".into());
    }
    Ok((uid, pid as u32))
}
#[cfg(not(target_os = "macos"))]
fn peer_identity(_: &UnixStream) -> Result<(u32, u32), String> {
    Err("administrator sessions require macOS".into())
}
fn authorize_peer(stream: &UnixStream, owner: &Owner) -> Result<(), String> {
    if peer_identity(stream)? != (owner.uid, owner.pid) || !owner.alive() {
        return Err("request is not from the authorized application session".into());
    }
    Ok(())
}
fn read_frame(stream: &mut UnixStream, owner: &Owner) -> Result<Vec<u8>, String> {
    stream
        .set_nonblocking(true)
        .map_err(|_| "cannot configure session socket")?;
    let deadline = Instant::now() + IO_TIMEOUT;
    let mut bytes = Vec::new();
    let mut buffer = [0; 8192];
    loop {
        if Instant::now() >= deadline || !owner.alive() {
            return Err("administrator request timed out or application exited".into());
        }
        match stream.read(&mut buffer) {
            Ok(0) => return Err("administrator request ended before its newline".into()),
            Ok(size) => {
                if bytes.len() + size > MAX_FRAME {
                    return Err("request exceeds 4 MiB".into());
                }
                if let Some(end) = buffer[..size].iter().position(|b| *b == b'\n') {
                    if buffer[end + 1..size]
                        .iter()
                        .any(|b| !b.is_ascii_whitespace())
                    {
                        return Err("one request is permitted per connection".into());
                    }
                    bytes.extend_from_slice(&buffer[..end]);
                    return Ok(bytes);
                }
                bytes.extend_from_slice(&buffer[..size]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10))
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err("cannot read administrator request".into()),
        }
    }
}
fn write_frame(stream: &mut UnixStream, response: &Value) -> Result<(), String> {
    stream
        .set_nonblocking(true)
        .map_err(|_| "cannot configure session socket")?;
    let mut bytes =
        serde_json::to_vec(response).map_err(|_| "cannot encode administrator response")?;
    if bytes.len() >= MAX_FRAME {
        bytes = br#"{"ok":false,"error":"administrator response exceeds 4 MiB"}"#.to_vec();
    }
    bytes.push(b'\n');
    let deadline = Instant::now() + IO_TIMEOUT;
    let mut offset = 0;
    while offset < bytes.len() {
        if Instant::now() >= deadline {
            return Err("administrator response timed out".into());
        }
        match stream.write(&bytes[offset..]) {
            Ok(0) => return Err("administrator client disconnected".into()),
            Ok(size) => offset += size,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10))
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err("cannot write administrator response".into()),
        }
    }
    Ok(())
}
struct Cleanup {
    path: PathBuf,
    device: u64,
    inode: u64,
    armed: bool,
}
impl Cleanup {
    fn new(path: PathBuf) -> Result<Self, String> {
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| "cannot identify session directory")?;
        if !metadata.is_dir() {
            return Err("session cleanup path must be a directory".into());
        }
        Ok(Self {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
            armed: true,
        })
    }
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(metadata) = fs::symlink_metadata(&self.path) {
            if metadata.is_dir() && metadata.dev() == self.device && metadata.ino() == self.inode {
                let _ = fs::remove_dir_all(&self.path);
            }
        }
    }
}
struct Handshake {
    deadline: Instant,
    initialized: bool,
}
impl Handshake {
    fn new() -> Self {
        Self {
            deadline: Instant::now() + Duration::from_secs(15),
            initialized: false,
        }
    }
    fn active(&self) -> bool {
        self.initialized || Instant::now() < self.deadline
    }
    fn permit(&self, command: &str) -> Result<(), String> {
        if !self.active() {
            return Err("administrator session initialization expired".into());
        }
        if !self.initialized && command != "ping" && command != "close" {
            return Err("administrator session requires an initial ping".into());
        }
        Ok(())
    }
}

/// Internal command: invoked only from the pinned, protected helper snapshot.
pub fn serve(state_path: &Path) -> Result<(), String> {
    service::require_root()?;
    let state: SessionState = serde_json::from_slice(&protected_read(state_path, 4096)?)
        .map_err(|_| "invalid protected session state")?;
    let directory = session_path(state.owner.uid, &state.session_id)?;
    let private = directory.join("private");
    if state_path != private.join("session.json")
        || std::env::current_exe().map_err(|_| "cannot inspect helper path")?
            != private.join("routebar-v2")
    {
        return Err("session helper must run from its protected snapshot".into());
    }
    require_owned_directory(&directory, 0, false)?;
    require_owned_directory(&private, 0, true)?;
    let _cleanup = Cleanup::new(directory.clone())?;
    if !state.owner.alive() {
        return Err("application exited before session startup".into());
    }
    let engine = private.join("sing-box");
    protected_read(&engine, 256 * 1024 * 1024)?;
    let socket = directory.join("control.sock");
    let listener =
        UnixListener::bind(&socket).map_err(|_| "cannot create administrator session socket")?;
    let socket_path = std::ffi::CString::new(socket.as_os_str().as_encoded_bytes())
        .map_err(|_| "invalid socket path")?;
    if unsafe { libc::chown(socket_path.as_ptr(), state.owner.uid, !0) } != 0 {
        return Err("cannot assign administrator socket owner".into());
    }
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))
        .map_err(|_| "cannot protect administrator socket")?;
    listener
        .set_nonblocking(true)
        .map_err(|_| "cannot configure administrator listener")?;
    let mut operations = SystemOperations {
        engine,
        manager: service::Manager::new(),
    };
    runtime::atomic_write(&private.join("ready"), b"1", 0o600)?;
    let mut handshake = Handshake::new();
    while state.owner.alive() && handshake.active() {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let mut ping = false;
                let result = authorize_peer(&stream, &state.owner)
                    .and_then(|_| read_frame(&mut stream, &state.owner))
                    .and_then(|bytes| decode_request(&bytes))
                    .and_then(|request| {
                        authorize_peer(&stream, &state.owner)?;
                        handshake.permit(&request.command)?;
                        ping = request.command == "ping";
                        execute(request, &state.session_id, &private, &mut operations)
                    });
                let (response, close) = match result {
                    Ok((value, close)) => (json!({"ok":true,"result":value}), close),
                    Err(error) => (json!({"ok":false,"error":error}), false),
                };
                if write_frame(&mut stream, &response).is_ok() && ping && response["ok"] == true {
                    handshake.initialized = true;
                }
                // Finish any in-flight transactional operation before dropping
                // the session. The separate launchd VPN service is untouched.
                if close {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100))
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err("administrator session listener failed".into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "0123456789abcdef0123456789abcdef";
    #[derive(Default)]
    struct MockOperations {
        calls: Vec<String>,
        generated: Option<Value>,
    }
    impl Operations for MockOperations {
        fn status(&mut self) -> Result<Value, String> {
            self.calls.push("status".into());
            Ok(json!({"running":false}))
        }
        fn apply(&mut self, candidate: &Candidate, reload: bool) -> Result<Value, String> {
            self.calls.push(if reload { "reload" } else { "up" }.into());
            self.generated = Some(candidate.generated.json.clone());
            Ok(json!({"running":true}))
        }
        fn down(&mut self) -> Result<Value, String> {
            self.calls.push("down".into());
            Ok(json!({"stopped":true}))
        }
        fn logs(&mut self, lines: usize) -> Result<Value, String> {
            self.calls.push(format!("logs:{lines}"));
            Ok(json!({"logs":"test"}))
        }
    }
    fn request(command: &str) -> Request {
        Request {
            session_id: ID.into(),
            command: command.into(),
            config: None,
            profiles: None,
            lines: None,
        }
    }
    fn profile() -> String {
        use base64::Engine;
        let key = base64::engine::general_purpose::STANDARD.encode([1; 32]);
        format!("[Interface]\nPrivateKey = {key}\nAddress = 10.14.0.2/16\n[Peer]\nPublicKey = {key}\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0\n")
    }
    fn routing_request() -> Request {
        let mut r = request("up");
        r.config = Some(serde_json::from_value(json!({"version":1,"vpns":{"japan":{"wireguard_config":"/this/file/must/never/be/read"}},"routing":{"rules":[{"name":"app","match":{"apps":["/Applications/Test.app"]},"via":"japan"}]}})).unwrap());
        r.profiles = Some(BTreeMap::from([("japan".into(), profile())]));
        r
    }
    #[test]
    fn protocol_rejects_unknown_fields_commands_and_wrong_session() {
        assert!(
            decode_request(br#"{"session_id":"x","command":"up","engine":"/bin/sh"}"#).is_err()
        );
        let mut r = request("run");
        assert!(validate_request(&r, ID).is_err());
        r.command = "ping".into();
        r.session_id = "wrong".into();
        assert!(validate_request(&r, ID).is_err());
        let mut r = request("down");
        r.config = Some(serde_json::from_value(json!({"version":1})).unwrap());
        assert!(validate_request(&r, ID).is_err());
    }
    #[test]
    fn routing_uses_supplied_profile_contents_and_removes_temporary_secrets() {
        let private = runtime::PrivateDir::new(&std::env::temp_dir(), "session-test").unwrap();
        let mut operations = MockOperations::default();
        execute(routing_request(), ID, &private.0, &mut operations).unwrap();
        assert_eq!(operations.calls, ["up"]);
        assert_eq!(
            operations.generated.unwrap()["endpoints"][0]["tag"],
            "japan"
        );
        assert_eq!(fs::read_dir(&private.0).unwrap().count(), 0);
    }
    #[test]
    fn exact_profiles_only_and_no_raw_engine_json() {
        let private = runtime::PrivateDir::new(&std::env::temp_dir(), "session-test").unwrap();
        let mut operations = MockOperations::default();
        let mut r = routing_request();
        r.profiles
            .as_mut()
            .unwrap()
            .insert("extra".into(), profile());
        assert!(execute(r, ID, &private.0, &mut operations).is_err());
        assert!(decode_request(br#"{"session_id":"x","command":"up","config":{"inbounds":[{"type":"tun"}]},"profiles":{}}"#).is_err());
        assert!(operations.calls.is_empty());
    }
    #[test]
    fn close_never_stops_vpn_and_log_limits_are_enforced() {
        let private = runtime::PrivateDir::new(&std::env::temp_dir(), "session-test").unwrap();
        let mut operations = MockOperations::default();
        assert!(
            execute(request("close"), ID, &private.0, &mut operations)
                .unwrap()
                .1
        );
        assert!(operations.calls.is_empty());
        let mut r = request("logs");
        r.lines = Some(10001);
        assert!(execute(r, ID, &private.0, &mut operations).is_err());
        execute(request("logs"), ID, &private.0, &mut operations).unwrap();
        assert_eq!(operations.calls, ["logs:100"]);
    }
    #[test]
    fn malformed_profile_errors_do_not_echo_secrets() {
        let private = runtime::PrivateDir::new(&std::env::temp_dir(), "session-test").unwrap();
        let mut operations = MockOperations::default();
        let mut r = routing_request();
        r.profiles.as_mut().unwrap().insert(
            "japan".into(),
            "[Interface]\nPrivateKey = TOP_SECRET_INVALID_KEY".into(),
        );
        let error = execute(r, ID, &private.0, &mut operations).unwrap_err();
        assert!(!error.contains("TOP_SECRET"));
        assert!(operations.calls.is_empty());
    }
    #[test]
    fn session_id_and_size_limits() {
        assert!(valid_session_id(ID));
        for invalid in ["../test", "0123456789ABCDEF0123456789ABCDEF", ""] {
            assert!(!valid_session_id(invalid));
        }
        assert!(decode_request(&vec![b' '; MAX_FRAME + 1]).is_err());
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn kernel_peer_credentials_and_start_time_bind_exact_process() {
        let owner = process_owner(std::process::id()).unwrap();
        assert!(owner.alive());
        let directory = runtime::PrivateDir::new(&std::env::temp_dir(), "peer-test").unwrap();
        let listener = UnixListener::bind(directory.0.join("s")).unwrap();
        let _client = UnixStream::connect(directory.0.join("s")).unwrap();
        let (stream, _) = listener.accept().unwrap();
        assert_eq!(peer_identity(&stream).unwrap(), (owner.uid, owner.pid));
        authorize_peer(&stream, &owner).unwrap();
        let mut wrong = owner.clone();
        wrong.start_microseconds += 1;
        assert!(!wrong.alive());
        assert!(authorize_peer(&stream, &wrong).is_err());
        wrong = owner;
        wrong.uid += 1;
        assert!(authorize_peer(&stream, &wrong).is_err());
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn framing_roundtrip_and_trailing_command_rejected() {
        let owner = process_owner(std::process::id()).unwrap();
        let (mut server, mut client) = UnixStream::pair().unwrap();
        client.write_all(b"{\"a\":1}\n").unwrap();
        assert_eq!(read_frame(&mut server, &owner).unwrap(), b"{\"a\":1}");
        write_frame(&mut server, &json!({"ok":true})).unwrap();
        let mut reply = [0; 64];
        let count = client.read(&mut reply).unwrap();
        assert_eq!(&reply[..count], b"{\"ok\":true}\n");
        client.write_all(b"{}\n{}\n").unwrap();
        assert!(read_frame(&mut server, &owner).is_err());
    }
    #[test]
    fn initial_ping_is_required_and_expires_without_initialization() {
        let mut handshake = Handshake::new();
        assert!(handshake.permit("ping").is_ok());
        assert!(handshake.permit("close").is_ok());
        assert!(handshake.permit("up").is_err());
        handshake.deadline = Instant::now() - Duration::from_secs(1);
        assert!(!handshake.active());
        assert!(handshake.permit("ping").is_err());
        handshake.initialized = true;
        assert!(handshake.active());
        assert!(handshake.permit("up").is_ok());
    }
    #[test]
    fn duplicate_config_keys_are_rejected_before_value_normalization() {
        for bytes in [
            br#"{"session_id":"x","command":"up","config":{"version":1,"version":1},"profiles":{}}"#.as_slice(),
            br#"{"session_id":"x","command":"up","config":{"version":1},"profiles":{"japan":"one","japan":"two"}}"#.as_slice(),
            br#"{"session_id":"x","command":"up","config":{"version":1,"vpns":{"japan":{"wireguard_config":"a"},"japan":{"wireguard_config":"b"}}},"profiles":{}}"#.as_slice(),
        ] { assert!(decode_request(bytes).is_err()); }
    }
    #[test]
    fn cleanup_does_not_follow_replaced_directory() {
        let directory = runtime::PrivateDir::new(&std::env::temp_dir(), "cleanup-test").unwrap();
        let path = directory.0.join("session");
        fs::create_dir(&path).unwrap();
        let cleanup = Cleanup::new(path.clone()).unwrap();
        fs::rename(&path, directory.0.join("original")).unwrap();
        fs::create_dir(&path).unwrap();
        fs::write(path.join("keep"), b"new directory").unwrap();
        drop(cleanup);
        assert!(path.join("keep").exists());
    }
    #[test]
    fn group_writable_session_parent_is_rejected() {
        let directory =
            runtime::PrivateDir::new(&std::env::temp_dir(), "session-parent-test").unwrap();
        let uid = unsafe { libc::geteuid() };
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o755)).unwrap();
        require_owned_directory(&directory.0, uid, false).unwrap();
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(require_owned_directory(&directory.0, uid, false).is_err());
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn session_socket_parent_is_protected_var_db() {
        let path = session_path(501, ID).unwrap();
        assert_eq!(path.parent(), Some(Path::new("/private/var/db")));
        for ancestor in path.parent().unwrap().ancestors() {
            require_owned_directory(ancestor, 0, false).unwrap();
        }
    }
}
