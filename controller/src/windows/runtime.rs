//! Windows ACL-protected files and bounded child-process execution.
use serde_json::Value;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    mpsc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use windows_sys::Win32::{
    Foundation::{CloseHandle, LocalFree, HANDLE, INVALID_HANDLE_VALUE},
    Security::{
        Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW, SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::{
        CreateDirectoryW, CreateFileW, MoveFileExW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    },
    System::{
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        },
        Threading::CREATE_NO_WINDOW,
    },
};

fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}
fn error() -> String {
    std::io::Error::last_os_error().to_string()
}
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
pub fn unique_name(prefix: &str) -> String {
    format!(
        "{prefix}-{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

// Explicit protected DACL: owner, SYSTEM and administrators only. Applied at
// creation, before any secret is written; numeric SIDs work on localized Windows.
struct Security(SECURITY_ATTRIBUTES);
impl Security {
    fn new() -> Result<Self, String> {
        let sddl = wide(std::ffi::OsStr::new(
            "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
        ));
        let mut descriptor = std::ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(error());
        }
        Ok(Self(SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        }))
    }
}
impl Drop for Security {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0.lpSecurityDescriptor);
        }
    }
}
pub struct PrivateDir(pub PathBuf);
impl PrivateDir {
    pub fn new(parent: &Path, prefix: &str) -> Result<Self, String> {
        let security = Security::new()?;
        let path = parent.join(unique_name(prefix));
        if unsafe { CreateDirectoryW(wide(path.as_os_str()).as_ptr(), &security.0) } == 0 {
            return Err(error());
        }
        Ok(Self(path))
    }
}
impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
pub fn atomic_write(path: &Path, data: &[u8], _mode: u32) -> Result<(), String> {
    let parent = path.parent().ok_or("output needs a parent directory")?;
    let tmp = parent.join(unique_name(".routebar"));
    let security = Security::new()?;
    let result = (|| {
        let handle = unsafe {
            CreateFileW(
                wide(tmp.as_os_str()).as_ptr(),
                0x40000000,
                0,
                &security.0,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                0,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(error());
        }
        let mut file = unsafe { File::from_raw_handle(handle as _) };
        file.write_all(data)
            .and_then(|_| file.sync_all())
            .map_err(|e| e.to_string())?;
        drop(file);
        if unsafe {
            MoveFileExW(
                wide(tmp.as_os_str()).as_ptr(),
                wide(path.as_os_str()).as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(error());
        }
        Ok(())
    })();
    let _ = fs::remove_file(tmp);
    result
}

/// Kernel closes the job and terminates its processes even if the controller crashes.
pub struct Job(HANDLE);
impl Job {
    pub fn new() -> Result<Self, String> {
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle == 0 {
            return Err(error());
        }
        let job = Self(handle);
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &limits as *const _ as _,
                std::mem::size_of_val(&limits) as u32,
            )
        } == 0
        {
            return Err(error());
        }
        Ok(job)
    }
    pub fn assign(&self, child: &std::process::Child) -> Result<(), String> {
        if unsafe { AssignProcessToJobObject(self.0, child.as_raw_handle() as isize) } == 0 {
            return Err(error());
        }
        Ok(())
    }
}
impl Drop for Job {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

pub fn capture(command: &mut Command, timeout: Duration) -> Result<Output, String> {
    let job = Job::new()?;
    let mut child = command
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    if let Err(e) = job.assign(&child) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e);
    }
    let (tx, rx) = mpsc::channel();
    fn reader(
        pipe: impl Read + Send + 'static,
        tx: mpsc::Sender<(bool, Result<Vec<u8>, String>)>,
        stderr: bool,
    ) {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = pipe
                .take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())
                .and_then(|_| {
                    if bytes.len() > 1024 * 1024 {
                        Err("command output exceeded 1 MiB".into())
                    } else {
                        Ok(bytes)
                    }
                });
            let _ = tx.send((stderr, result));
        });
    }
    reader(child.stdout.take().unwrap(), tx.clone(), false);
    reader(child.stderr.take().unwrap(), tx, true);
    let deadline = Instant::now() + timeout;
    let mut stdout = None;
    let mut stderr = None;
    let result = (|| loop {
        while let Ok((is_error, bytes)) = rx.try_recv() {
            if is_error {
                stderr = Some(bytes?);
            } else {
                stdout = Some(bytes?);
            }
        }
        if stdout.is_some() && stderr.is_some() {
            if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                return Ok(Output {
                    status,
                    stdout: stdout.take().unwrap(),
                    stderr: stderr.take().unwrap(),
                });
            }
        }
        if Instant::now() >= deadline {
            return Err("command timed out".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    })();
    drop(job);
    let _ = child.wait();
    result
}
pub fn locate_engine(explicit: Option<&str>) -> Result<PathBuf, String> {
    let path = match explicit {
        Some(path) => PathBuf::from(path),
        None => std::env::current_exe()
            .map_err(|e| e.to_string())?
            .with_file_name("sing-box.exe"),
    };
    fs::canonicalize(path)
        .map_err(|_| "sing-box.exe is missing; run scripts/build-windows.ps1".into())
}
pub fn check_engine(binary: &Path, config: &Value) -> Result<(), String> {
    let version = capture(Command::new(binary).arg("version"), Duration::from_secs(5))?;
    if !version.status.success()
        || !String::from_utf8_lossy(&version.stdout)
            .lines()
            .any(|s| s.trim() == "sing-box version 1.14.4")
    {
        return Err("Windows requires the bundled sing-box 1.14.4".into());
    }
    let dir = PrivateDir::new(&std::env::temp_dir(), "routebar-check")?;
    let path = dir.0.join("config.json");
    atomic_write(
        &path,
        &serde_json::to_vec(config).map_err(|e| e.to_string())?,
        0o600,
    )?;
    let output = capture(
        Command::new(binary).arg("check").arg("-c").arg(path),
        Duration::from_secs(15),
    )?;
    if !output.status.success() {
        return Err(format!(
            "sing-box rejected configuration: {}",
            sanitize(&String::from_utf8_lossy(&output.stderr), config)
        ));
    }
    Ok(())
}
pub fn sanitize(message: &str, config: &Value) -> String {
    crate::engine::sanitize(message, config)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_atomic_replacement() {
        let dir = PrivateDir::new(&std::env::temp_dir(), "routebar-test").unwrap();
        let path = dir.0.join("secret.json");
        atomic_write(&path, b"secret", 0o600).unwrap();
        atomic_write(&path, b"replacement", 0o600).unwrap();
        assert_eq!(fs::read(path).unwrap(), b"replacement");
        let output = capture(
            Command::new("icacls.exe").arg(&dir.0),
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(output.status.success());
        assert!(!String::from_utf8_lossy(&output.stdout).contains("(I)"));
    }
    #[test]
    fn capture_exit_and_timeout() {
        let output = capture(
            Command::new("cmd.exe").args(["/d", "/c", "echo out & echo err >&2 & exit /b 7"]),
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(output.status.code(), Some(7));
        assert!(String::from_utf8_lossy(&output.stdout).contains("out"));
        assert!(String::from_utf8_lossy(&output.stderr).contains("err"));
        let start = Instant::now();
        assert_eq!(
            capture(
                Command::new("ping.exe").args(["-n", "30", "127.0.0.1"]),
                Duration::from_millis(100)
            )
            .unwrap_err(),
            "command timed out"
        );
        assert!(start.elapsed() < Duration::from_secs(3));
    }
}
