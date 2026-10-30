//! Root-owned lock and nonsecret recovery journal. No key material is persisted.
use super::network::NetworkState;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
        io::AsRawFd,
    },
    path::{Path, PathBuf},
};

// DNS preferences survive reboot, so their recovery journal must survive too.
pub const DIRECTORY: &str = "/var/db/routebar-vpn";
pub const SOCKET: &str = "/var/db/routebar-vpn/control.sock";
const LIMIT: u64 = 256 * 1024;

pub fn require_root() -> Result<(), String> {
    // SAFETY: geteuid has no pointer arguments or side effects.
    if unsafe { libc::geteuid() } != 0 {
        return Err("this command needs sudo; use `plan <config>` for a read-only preview".into());
    }
    Ok(())
}

fn check_directory(path: &Path, owner: u32) -> Result<(), String> {
    let m = fs::symlink_metadata(path).map_err(|_| "Cannot inspect runtime directory")?;
    if !m.is_dir() || m.uid() != owner || m.mode() & 0o077 != 0 {
        return Err("Runtime directory must be a real owner-only directory".into());
    }
    Ok(())
}

pub fn check_runtime_directory() -> Result<(), String> {
    check_directory(Path::new(DIRECTORY), 0)
}

fn secure_file(path: &Path, owner: u32) -> Result<File, String> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "Cannot open recovery journal")?;
    let m = f
        .metadata()
        .map_err(|_| "Cannot inspect recovery journal")?;
    if !m.is_file()
        || m.uid() != owner
        || m.mode() & 0o077 != 0
        || m.nlink() != 1
        || m.len() > LIMIT
    {
        return Err("Recovery journal has unsafe ownership, permissions, links, or size".into());
    }
    Ok(f)
}

pub struct Store {
    directory: PathBuf,
    _lock: File,
}

impl Store {
    pub fn acquire() -> Result<Self, String> {
        require_root()?;
        Self::acquire_at(Path::new(DIRECTORY), 0)
    }

    fn acquire_at(path: &Path, owner: u32) -> Result<Self, String> {
        match fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(_) => return Err("Cannot create runtime directory".into()),
        }
        check_directory(path, owner)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path.join("lock"))
            .map_err(|_| "Cannot open runtime lock")?;
        let m = lock.metadata().map_err(|_| "Cannot inspect runtime lock")?;
        if !m.is_file() || m.uid() != owner || m.mode() & 0o077 != 0 || m.nlink() != 1 {
            return Err("Unsafe runtime lock".into());
        }
        // SAFETY: lock owns a valid descriptor for the lifetime of Store.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(
                "RouteBar VPN is already running; use `sudo routebar-vpn status` or `down`".into(),
            );
        }
        Ok(Self {
            directory: path.to_path_buf(),
            _lock: lock,
        })
    }

    pub fn has_journal(&self) -> bool {
        fs::symlink_metadata(self.directory.join("journal.json")).is_ok()
    }

    pub fn load(&self) -> Result<NetworkState, String> {
        self.load_as(0)
    }

    fn load_as(&self, owner: u32) -> Result<NetworkState, String> {
        let mut f = secure_file(&self.directory.join("journal.json"), owner)?;
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes)
            .map_err(|_| "Cannot read recovery journal")?;
        serde_json::from_slice(&bytes)
            .map_err(|_| "Invalid recovery journal; preserved for inspection".into())
    }

    pub fn save(&self, state: &NetworkState) -> Result<(), String> {
        let bytes =
            serde_json::to_vec_pretty(state).map_err(|_| "Cannot encode recovery journal")?;
        let temporary = self.directory.join("journal.new");
        // A leftover temporary belongs to a stopped process under this exclusive lock.
        match fs::remove_file(&temporary) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err("Cannot clear stale journal temporary".into()),
        }
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)
            .map_err(|_| "Cannot create recovery journal")?;
        f.write_all(&bytes)
            .and_then(|_| f.sync_all())
            .map_err(|_| "Cannot persist recovery journal")?;
        fs::rename(temporary, self.directory.join("journal.json"))
            .map_err(|_| "Cannot install recovery journal")?;
        self.sync_directory()
    }

    fn sync_directory(&self) -> Result<(), String> {
        File::open(&self.directory)
            .and_then(|f| f.sync_all())
            .map_err(|_| "Cannot sync runtime directory".into())
    }

    pub fn clear_journal(&self) -> Result<(), String> {
        fs::remove_file(self.directory.join("journal.json"))
            .map_err(|_| "Cannot remove restored recovery journal")?;
        self.sync_directory()
    }

    pub fn clear_socket(&self) -> Result<(), String> {
        use std::os::unix::fs::FileTypeExt;
        let path = self.directory.join("control.sock");
        match fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_socket() && m.uid() == 0 => {
                fs::remove_file(path).map_err(|_| "Cannot clear stale control socket".into())
            }
            Ok(_) => Err("Unexpected file at control socket path".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err("Cannot inspect control socket".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    struct TemporaryDirectory(PathBuf);

    impl TemporaryDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "routebar-state-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }

        fn owner(&self) -> u32 {
            fs::metadata(&self.0).unwrap().uid()
        }
    }

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn journal_survives_store_reopen_and_atomic_replacement() {
        let temporary = TemporaryDirectory::new();
        let path = temporary.0.join("store");
        let owner = temporary.owner();
        let store = Store::acquire_at(&path, owner).unwrap();
        assert!(!store.has_journal());
        store.save(&NetworkState::new("utun123").unwrap()).unwrap();
        let metadata = fs::symlink_metadata(path.join("journal.json")).unwrap();
        assert_eq!(metadata.uid(), owner);
        assert_eq!(metadata.mode() & 0o077, 0);
        assert_eq!(metadata.nlink(), 1);
        assert!(metadata.is_file());
        assert!(!path.join("journal.new").exists());
        drop(store);

        let reopened = Store::acquire_at(&path, owner).unwrap();
        let saved = reopened.load_as(owner).unwrap();
        assert_eq!(saved.interface_name(), "utun123");
        assert!(saved.is_clean());
        saved.validate().unwrap();
        // An incomplete temporary from a stopped writer is never read as state.
        fs::write(path.join("journal.new"), b"incomplete JSON").unwrap();
        assert_eq!(reopened.load_as(owner).unwrap().interface_name(), "utun123");
        reopened
            .save(&NetworkState::new("utun124").unwrap())
            .unwrap();
        drop(reopened);

        let reopened = Store::acquire_at(&path, owner).unwrap();
        assert_eq!(reopened.load_as(owner).unwrap().interface_name(), "utun124");
        assert!(!path.join("journal.new").exists());
        reopened.clear_journal().unwrap();
        assert!(!reopened.has_journal());
        drop(reopened);
        assert!(!Store::acquire_at(&path, owner).unwrap().has_journal());
    }

    #[test]
    fn failed_journal_replacement_preserves_previous_snapshot() {
        let temporary = TemporaryDirectory::new();
        let path = temporary.0.join("store");
        let owner = temporary.owner();
        let store = Store::acquire_at(&path, owner).unwrap();
        store.save(&NetworkState::new("utun123").unwrap()).unwrap();
        // A filesystem obstacle prevents installing the next journal version.
        fs::create_dir(path.join("journal.new")).unwrap();
        assert!(store.save(&NetworkState::new("utun124").unwrap()).is_err());
        drop(store);
        let reopened = Store::acquire_at(&path, owner).unwrap();
        assert_eq!(reopened.load_as(owner).unwrap().interface_name(), "utun123");
    }

    #[test]
    fn journal_rejects_symlinks_and_hardlinks_without_changing_targets() {
        let temporary = TemporaryDirectory::new();
        let path = temporary.0.join("store");
        let owner = temporary.owner();
        let store = Store::acquire_at(&path, owner).unwrap();
        let bytes = serde_json::to_vec(&NetworkState::new("utun123").unwrap()).unwrap();
        let target = temporary.0.join("original.json");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&target)
            .unwrap();
        file.write_all(&bytes).unwrap();
        drop(file);

        let journal = path.join("journal.json");
        symlink(&target, &journal).unwrap();
        assert!(store.load_as(owner).is_err());
        assert!(fs::symlink_metadata(&journal)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read(&target).unwrap(), bytes);
        fs::remove_file(&journal).unwrap();

        fs::hard_link(&target, &journal).unwrap();
        assert_eq!(fs::metadata(&journal).unwrap().nlink(), 2);
        assert!(store.load_as(owner).is_err());
        assert_eq!(fs::read(&target).unwrap(), bytes);
        assert_eq!(fs::read(&journal).unwrap(), bytes);
    }

    #[test]
    fn journal_rejects_oversized_permissions_owner_and_corrupt_data() {
        let temporary = TemporaryDirectory::new();
        let path = temporary.0.join("store");
        let owner = temporary.owner();
        let store = Store::acquire_at(&path, owner).unwrap();
        let journal = path.join("journal.json");
        store.save(&NetworkState::new("utun123").unwrap()).unwrap();
        let original = fs::read(&journal).unwrap();
        assert!(store.load_as(owner.wrapping_add(1)).is_err());
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(store.load_as(owner).is_err());
        assert_eq!(fs::read(&journal).unwrap(), original);
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();

        let file = OpenOptions::new().write(true).open(&journal).unwrap();
        file.set_len(LIMIT + 1).unwrap();
        drop(file);
        assert!(store.load_as(owner).is_err());
        assert_eq!(fs::metadata(&journal).unwrap().len(), LIMIT + 1);
        fs::write(&journal, b"incomplete JSON").unwrap();
        assert!(store.load_as(owner).is_err());
        assert_eq!(fs::read(&journal).unwrap(), b"incomplete JSON");
    }

    #[test]
    fn lock_is_exclusive_and_rejects_symlink_and_world_readable_directory() {
        let root = std::env::temp_dir().join(format!(
            "routebar-state-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("state");
        // SAFETY: getuid is a side-effect-free libc query.
        let owner = unsafe { libc::getuid() };
        let first = Store::acquire_at(&path, owner).unwrap();
        assert!(Store::acquire_at(&path, owner).is_err());
        drop(first);
        assert!(Store::acquire_at(&path, owner).is_ok());
        let alias = root.join("alias");
        symlink(&path, &alias).unwrap();
        assert!(Store::acquire_at(&alias, owner).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Store::acquire_at(&path, owner).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
