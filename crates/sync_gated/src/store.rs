//! Persistence in the per-user data directory: the learned cost model and the paused set.
//! Every write is atomic (temp file, fsync, rename), so a crash never leaves a torn file.

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use sync_gate_core::CostModel;
pub use sync_gate_probe::write_atomic;
use sync_gate_probe::{LOCK_FILE, create_private_dir, try_lock};

/// How long a starting daemon waits for a recovery pass that holds its lock.
pub const LOCK_WAIT: Duration = Duration::from_secs(2);

/// The per-user data directory, or `None` when the platform has no home directory.
pub fn default_dir() -> Option<PathBuf> {
    sync_gate_probe::data_dir()
}

/// `<name>` with `suffix` appended to the file name (e.g. `cost.json.tmp`).
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_owned();
    name.push(suffix);
    path.with_file_name(name)
}

#[cfg(test)]
thread_local! {
    /// Files `read` opened on this thread: a test proves a refused one never was.
    pub(crate) static READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Reads `path` from the handle `open_private_file` judged; `None` when missing, refused or
/// unreadable (the last two are reported, a refusal with its `consequence`). A refused file is
/// left as it is: the daemon rebuilds these records whole, and the next save replaces it.
fn read(path: &Path, consequence: &str) -> Option<String> {
    use std::io::Read;
    let mut f = match sync_gate_core::open_private_file(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
        Err(e) => {
            eprintln!(
                "sync_gated: ignoring {}: {e}; {consequence} (delete it; sync_gate writes a new one)",
                path.display()
            );
            return None;
        }
    };
    #[cfg(test)]
    READS.with(|n| n.set(n.get() + 1));
    let mut text = String::new();
    match f.read_to_string(&mut text) {
        Ok(_) => Some(text),
        Err(e) => {
            eprintln!("sync_gated: cannot read {}: {e}", path.display());
            None
        }
    }
}

/// Moves a corrupt file to `<name>.bad` and says so.
pub(crate) fn quarantine(path: &Path, why: &dyn std::fmt::Display) {
    let bad = sibling(path, ".bad");
    let moved = std::fs::rename(path, &bad);
    eprintln!(
        "sync_gated: corrupt {} ({why}); moved to {} ({moved:?}); starting fresh",
        path.display(),
        bad.display()
    );
}

/// A missing file gives the default model; a corrupt one is moved to `cost.json.bad` first.
pub fn load(path: &Path) -> CostModel {
    let Some(text) = read(path, "using the default cost model") else {
        return CostModel::default();
    };
    // The key format changed (only subcommand-shaped words now): an older file's keys may hold
    // credentials and would lend their estimates to other commands. Start fresh and overwrite it.
    if let Ok(serde_json::Value::Object(o)) = serde_json::from_str(&text)
        && !o.contains_key("history_v2")
    {
        eprintln!(
            "sync_gated: {}: cost model from an older key format; starting fresh",
            path.display()
        );
        let fresh = CostModel::default();
        if let Err(e) = save(path, &fresh) {
            // The old keys must not stay on disk until the next save: remove the file instead.
            let removed = std::fs::remove_file(path);
            eprintln!(
                "sync_gated: cannot rewrite {}: {e}; removing it: {removed:?}",
                path.display()
            );
        }
        return fresh;
    }
    serde_json::from_str(&text).unwrap_or_else(|e| {
        quarantine(path, &e);
        CostModel::default()
    })
}

pub fn save(path: &Path, model: &CostModel) -> io::Result<()> {
    write_atomic(path, &serde_json::to_vec(model).map_err(io::Error::other)?)
}

/// Own-process registry rows as `(name, pid, start_time, exe)`; missing or corrupt reads as empty.
/// A file another user could have written is never read (it names what gets terminated): it
/// reads as empty and is left in place, and the next save replaces it.
pub fn load_services(path: &Path) -> Vec<(String, u32, u64, String)> {
    let Some(text) = read(path, "leftovers it names are not stopped") else {
        return Vec::new();
    };
    serde_json::from_str(&text).unwrap_or_else(|e| {
        quarantine(path, &e);
        Vec::new()
    })
}

pub fn save_services(path: &Path, rows: &[(String, u32, u64, String)]) -> io::Result<()> {
    write_atomic(path, &serde_json::to_vec(rows).map_err(io::Error::other)?)
}

/// One daemon per data dir: an exclusive OS lock on `<dir>/sync_gated.lock`, released when
/// dropped or when the process dies (even by a hard kill). Whoever holds it owns the paused
/// record: a CLI recovers (`sync_gate_probe::recover_as_owner`) only while holding it.
pub struct InstanceLock {
    _lock: sync_gate_probe::FileLock,
}

/// Takes the instance lock, waiting up to [`LOCK_WAIT`]; `AddrInUse` when it stays held.
pub fn lock_instance(dir: &Path) -> io::Result<InstanceLock> {
    lock_instance_within(dir, LOCK_WAIT)
}

/// [`lock_instance`] with its wait: retries in 50 ms steps, so a recovery pass in progress
/// cannot make a legitimate start fail.
pub fn lock_instance_within(dir: &Path, wait: Duration) -> io::Result<InstanceLock> {
    create_private_dir(dir)?;
    let deadline = Instant::now() + wait;
    loop {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(dir.join(LOCK_FILE))?;
        if let Some(_lock) = try_lock(file, true)? {
            return Ok(InstanceLock { _lock });
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::AddrInUse.into());
        }
        std::thread::sleep(left.min(Duration::from_millis(50)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_to_others(p: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o666)).unwrap();
        }
        #[cfg(windows)]
        {
            let out = std::process::Command::new("icacls")
                .arg(p)
                .args(["/grant", "*S-1-1-0:(W)"])
                .output()
                .unwrap();
            assert!(out.status.success(), "icacls: {out:?}");
        }
    }

    /// C6: `services.json` and `cost.json` that others can change are never read: empty and
    /// the default model, the files left as they were (the next save replaces them).
    #[test]
    fn a_record_others_can_change_is_ignored_and_kept() {
        let dir = std::env::temp_dir().join(format!("fg-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        create_private_dir(&dir).unwrap();
        let reads = || READS.with(std::cell::Cell::get);
        let services = dir.join("services.json");
        let row = r#"[["srv",4242,1,"/bin/victim"]]"#;
        std::fs::write(&services, row).unwrap();
        let before = reads();
        assert_eq!(load_services(&services).len(), 1, "control");
        assert_eq!(reads(), before + 1);
        open_to_others(&services);
        assert!(load_services(&services).is_empty());
        assert_eq!(reads(), before + 1, "the refused file was read");
        assert_eq!(std::fs::read_to_string(&services).unwrap(), row);

        let cost = dir.join("cost.json");
        let mut m = CostModel::default();
        let sig =
            sync_gate_core::signature(&["cargo".into(), "build".into()], Path::new("/r")).unwrap();
        m.record(&sig, 900 * sync_gate_core::MIB);
        save(&cost, &m).unwrap();
        let text = std::fs::read(&cost).unwrap();
        assert_eq!(
            load(&cost).estimate(&sig, true).peak_bytes,
            900 * sync_gate_core::MIB
        );
        open_to_others(&cost);
        let before = reads();
        assert_eq!(
            load(&cost).estimate(&sig, true).peak_bytes,
            sync_gate_core::PRIOR_HEAVY
        );
        assert_eq!(reads(), before);
        assert_eq!(std::fs::read(&cost).unwrap(), text);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
