//! Bounded engine execution and private, atomic configuration storage.
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
pub fn unique_name(prefix: &str) -> String {
    format!(
        "{}-{}-{}-{}",
        prefix,
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

pub struct PrivateDir(pub PathBuf);
impl PrivateDir {
    pub fn new(parent: &Path, prefix: &str) -> Result<Self, String> {
        use std::os::unix::fs::DirBuilderExt;
        for _ in 0..10 {
            let path = parent.join(unique_name(prefix));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("create private working directory: {e}")),
            }
        }
        Err("cannot allocate private working directory".into())
    }
}
impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub fn atomic_write(path: &Path, data: &[u8], mode: u32) -> Result<(), String> {
    let parent = path.parent().ok_or("output needs a parent directory")?;
    let tmp = parent.join(unique_name(".routebar"));
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)
            .map_err(|e| e.to_string())?;
        f.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|e| e.to_string())?;
        f.write_all(data)
            .and_then(|_| f.sync_all())
            .map_err(|e| e.to_string())?;
        fs::rename(&tmp, path).map_err(|e| e.to_string())?;
        Ok(())
    })();
    let _ = fs::remove_file(tmp);
    result
}

const MAX_CAPTURE_BYTES: usize = 1024 * 1024;

fn nonblocking(fd: i32) -> Result<(), String> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

// Bound each polling iteration as well as the retained output. An endlessly
// writing child must not prevent us from checking the deadline.
fn drain_pipe(pipe: &mut impl Read, bytes: &mut Vec<u8>) -> Result<bool, String> {
    let mut buffer = [0; 8192];
    for _ in 0..8 {
        match pipe.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(size) => {
                if bytes.len() + size > MAX_CAPTURE_BYTES {
                    return Err("command output exceeded 1 MiB".into());
                }
                bytes.extend_from_slice(&buffer[..size]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(false)
}

pub fn capture(command: &mut Command, timeout: Duration) -> Result<Output, String> {
    // A separate process group lets cancellation include descendants which
    // might otherwise keep inherited pipes open after the parent is killed.
    let mut child = command
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot start command: {e}"))?;
    let group = child.id() as i32;
    let result = (|| {
        let mut stdout = child.stdout.take().ok_or("missing command stdout")?;
        let mut stderr = child.stderr.take().ok_or("missing command stderr")?;
        nonblocking(stdout.as_raw_fd())?;
        nonblocking(stderr.as_raw_fd())?;
        let mut out = Vec::new();
        let mut err = Vec::new();
        let deadline = Instant::now() + timeout;
        loop {
            let out_closed = drain_pipe(&mut stdout, &mut out)?;
            let err_closed = drain_pipe(&mut stderr, &mut err)?;
            if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                if out_closed && err_closed {
                    return Ok(Output {
                        status,
                        stdout: out,
                        stderr: err,
                    });
                }
            }
            if Instant::now() >= deadline {
                return Err("command timed out".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    })();
    if result.is_err() {
        unsafe {
            libc::kill(-group, libc::SIGKILL);
        }
        // No blocking read or join remains. Even descendants which create a
        // new process group cannot hold this call open through inherited pipes.
        let cleanup_deadline = Instant::now() + Duration::from_millis(500);
        while Instant::now() < cleanup_deadline {
            match child.try_wait() {
                Ok(Some(_)) | Err(_) => break,
                Ok(None) => {
                    let _ = child.kill();
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }
    result
}

pub fn locate_engine(explicit: Option<&str>) -> Result<PathBuf, String> {
    if let Some(path) = explicit {
        return fs::canonicalize(path)
            .map_err(|_| "selected sing-box executable does not exist".into());
    }
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.join("sing-box"));
        }
    }
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            candidates.push(dir.join("sing-box"));
        }
    }
    candidates.extend([
        PathBuf::from("/opt/homebrew/bin/sing-box"),
        PathBuf::from("/usr/local/bin/sing-box"),
    ]);
    candidates
        .into_iter()
        .find(|p| p.is_file())
        .map(|p| fs::canonicalize(p).map_err(|e| e.to_string()))
        .unwrap_or_else(|| {
            Err(
                "sing-box is missing; rebuild the RouteBar application with its bundled engine"
                    .into(),
            )
        })
}

pub fn check_version(binary: &Path) -> Result<(), String> {
    let output = capture(Command::new(binary).arg("version"), Duration::from_secs(5))?;
    let text = String::from_utf8_lossy(&output.stdout);
    let version = text
        .lines()
        .find_map(|line| line.strip_prefix("sing-box version "));
    if !output.status.success()
        || !version.is_some_and(|v| {
            v.starts_with("1.14.")
                && v[5..]
                    .split('-')
                    .next()
                    .is_some_and(|p| p.parse::<u32>().is_ok())
        })
    {
        return Err("this application requires sing-box 1.14.x".into());
    }
    Ok(())
}

pub fn sanitize(message: &str, config: &Value) -> String {
    fn secrets(value: &Value, out: &mut Vec<String>) {
        match value {
            Value::Object(fields) => {
                for (key, value) in fields {
                    if key == "private_key" || key == "pre_shared_key" {
                        if let Some(s) = value.as_str() {
                            if !s.is_empty() {
                                out.push(s.to_owned());
                            }
                        }
                    } else {
                        secrets(value, out);
                    }
                }
            }
            Value::Array(values) => {
                for value in values {
                    secrets(value, out);
                }
            }
            _ => {}
        }
    }
    let mut values = Vec::new();
    secrets(config, &mut values);
    let mut result = message.to_owned();
    for value in values {
        result = result.replace(&value, "[REDACTED]");
    }
    result
}

pub fn check_engine(binary: &Path, config: &Value) -> Result<(), String> {
    check_version(binary)?;
    let temp = PrivateDir::new(&std::env::temp_dir(), "routebar-check")?;
    let path = temp.0.join("config.json");
    atomic_write(
        &path,
        &serde_json::to_vec(config).map_err(|e| e.to_string())?,
        0o600,
    )?;
    let output = capture(
        Command::new(binary).arg("check").arg("-c").arg(&path),
        Duration::from_secs(15),
    )?;
    if !output.status.success() {
        return Err(format!(
            "sing-box rejected configuration: {}",
            sanitize(&String::from_utf8_lossy(&output.stderr), config).trim()
        ));
    }
    Ok(())
}

pub fn read_tail(path: &Path, lines: usize) -> Result<String, String> {
    use std::io::{Seek, SeekFrom};
    let mut file = File::open(path)
        .map_err(|e| format!("read service log (administrator permission may be needed): {e}"))?;
    let length = file.metadata().map_err(|e| e.to_string())?.len();
    file.seek(SeekFrom::Start(length.saturating_sub(1024 * 1024)))
        .map_err(|e| e.to_string())?;
    let mut data = Vec::new();
    file.read_to_end(&mut data).map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&data);
    let rows: Vec<_> = text.lines().collect();
    Ok(rows[rows.len().saturating_sub(lines)..].join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_atomic_file_and_replacement() {
        let dir = PrivateDir::new(&std::env::temp_dir(), "routebar-test").unwrap();
        let path = dir.0.join("config");
        atomic_write(&path, b"secret", 0o600).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        atomic_write(&path, b"new", 0o600).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");
    }
    #[test]
    fn errors_redact_both_keys() {
        let cfg = serde_json::json!({"endpoints":[{"private_key":"private", "peers":[{"pre_shared_key":"shared"}]}]});
        assert_eq!(sanitize("private shared", &cfg), "[REDACTED] [REDACTED]");
    }
    #[test]
    fn command_timeout() {
        let start = Instant::now();
        assert!(capture(
            Command::new("/bin/sleep").arg("10"),
            Duration::from_millis(50)
        )
        .is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
    }
    #[test]
    fn timeout_cancels_descendants_holding_output_pipes() {
        let start = Instant::now();
        let result = capture(
            Command::new("/bin/sh").args(["-c", "/bin/sleep 30 & wait"]),
            Duration::from_millis(100),
        );
        assert_eq!(result.unwrap_err(), "command timed out");
        assert!(start.elapsed() < Duration::from_secs(2));
    }
    #[test]
    fn exited_parent_with_live_descendant_cannot_hold_capture_open() {
        let start = Instant::now();
        let result = capture(
            Command::new("/bin/sh").args(["-c", "/bin/sleep 30 & exit 0"]),
            Duration::from_millis(100),
        );
        assert_eq!(result.unwrap_err(), "command timed out");
        assert!(start.elapsed() < Duration::from_secs(2));
    }
    #[test]
    fn command_output_is_bounded() {
        let start = Instant::now();
        let result = capture(&mut Command::new("/usr/bin/yes"), Duration::from_secs(5));
        assert_eq!(result.unwrap_err(), "command output exceeded 1 MiB");
        assert!(start.elapsed() < Duration::from_secs(3));
    }
    #[test]
    fn capture_preserves_stdout_stderr_and_exit_status() {
        let output = capture(
            Command::new("/bin/sh").args(["-c", "printf 'out'; printf 'err' >&2; exit 7"]),
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(output.stdout, b"out");
        assert_eq!(output.stderr, b"err");
        assert_eq!(output.status.code(), Some(7));
    }
}
