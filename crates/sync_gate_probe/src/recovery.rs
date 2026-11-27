//! Crash recovery shared by the daemon (at start) and the CLI watchdog: one pass over
//! `paused.json` and one over `paused-guests.json`, run only by whoever holds the daemon's
//! exclusive instance lock.
use crate::{FrozenUnit, GuestUnit, LOCK_FILE, Suspension, try_lock};
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// File name of the paused record inside the data dir.
pub const PAUSED_FILE: &str = "paused.json";

pub use sync_gate_core::data_dir;

/// What `paused.json` holds: exact frozen units `(pid, tid, start_time)` and pause intents
/// `(root_pid, root_start_time)` written before a tree is suspended.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PausedRecord {
    #[serde(default)]
    pub units: Vec<(u32, u32, u64)>,
    #[serde(default)]
    pub intents: Vec<(u32, u64)>,
}

/// The old format (a bare array of units) is still read.
#[derive(Deserialize)]
#[serde(untagged)]
enum OnDisk {
    Units(Vec<(u32, u32, u64)>),
    Record(PausedRecord),
}

fn parse_record(bytes: &[u8]) -> io::Result<PausedRecord> {
    Ok(
        match serde_json::from_slice(bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        {
            OnDisk::Units(units) => PausedRecord {
                units,
                intents: Vec::new(),
            },
            OnDisk::Record(r) => r,
        },
    )
}

/// Reads the record. Unix: a file another user could have written is refused before it is read
/// (`PermissionDenied`, the same path as any unreadable record).
fn read_record(path: &Path) -> io::Result<Vec<u8>> {
    #[cfg(unix)]
    sync_gate_core::check_private_file(path)?;
    #[cfg(test)]
    RECORD_READS.with(|n| n.set(n.get() + 1));
    std::fs::read(path)
}

#[cfg(test)]
thread_local! {
    /// Records `read_record` opened on this thread: a test proves a refused one never was.
    static RECORD_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// `Ok(None)` when there is no record; read or format failures are errors. Never changes the file.
pub fn load_record(path: &Path) -> io::Result<Option<PausedRecord>> {
    match read_record(path) {
        Ok(bytes) => parse_record(&bytes).map(Some),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Missing is empty; other read/format failures are returned for retry. Never changes the file.
pub fn load_paused(path: &Path) -> io::Result<Vec<FrozenUnit>> {
    Ok(load_record(path)?
        .unwrap_or_default()
        .units
        .into_iter()
        .map(unit)
        .collect())
}

pub fn save_record(path: &Path, record: &PausedRecord) -> io::Result<()> {
    write_atomic(path, &serde_json::to_vec(record).map_err(io::Error::other)?)
}

/// Pause records of guest jobs. A separate file that no binary older than 3-S opens, rewrites or
/// deletes (F38): an old CLI or daemon can never erase a guest's pause (D3).
pub const GUEST_PAUSED_FILE: &str = "paused-guests.json";

/// What `paused-guests.json` holds.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestRecord {
    pub units: Vec<GuestUnit>,
}

/// Writes `<dir>/paused-guests.json` atomically; an empty record removes the file (a missing
/// one is fine).
pub fn save_guest_record(dir: &Path, r: &GuestRecord) -> io::Result<()> {
    let path = dir.join(GUEST_PAUSED_FILE);
    if r.units.is_empty() {
        return match std::fs::remove_file(&path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        };
    }
    write_atomic(&path, &serde_json::to_vec(r).map_err(io::Error::other)?)
}

fn unit((pid, tid, start_time): (u32, u32, u64)) -> FrozenUnit {
    FrozenUnit {
        pid,
        tid,
        start_time,
    }
}

/// `<name>` with `suffix` appended to the file name (e.g. `paused.json.tmp`).
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_owned();
    name.push(suffix);
    path.with_file_name(name)
}

/// Creates `dir` and missing parents that only the user can change. An existing folder is
/// checked first: one others can write (or a link, or another owner's) is an error and is left as
/// found. Unix: 0700, and a folder others can only read is tightened to 0700. Windows: what
/// others may only read is kept, inherited or not; a new folder loses any write access for others.
pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        use sync_gate_core::{DirState, check_private_dir};
        match check_private_dir(dir)? {
            DirState::Private => return Ok(()),
            DirState::OthersCanRead => {
                return std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
            }
            DirState::Missing => {}
        }
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        check_private_dir(dir).map(|_| ())
    }
    #[cfg(windows)]
    sync_gate_core::private_dir::create_private_dir(dir)
}

/// Writes a new temporary file beside `path`, fsyncs it, then renames it over `path`, so a crash
/// never leaves a torn file. The temporary file is always created here, exclusively, and on Unix
/// as 0600 whatever the umask: an existing one (left by a crash, maybe looser, maybe held open by
/// someone) is never reused, so the record passes `check_private_file`. Removed on failure.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        create_private_dir(dir)?;
    }
    let (tmp, mut f) = new_tmp(path)?;
    let done = f.write_all(bytes).and_then(|()| f.sync_all());
    drop(f);
    let done = done.and_then(|()| std::fs::rename(&tmp, path));
    if done.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    done
}

/// A fresh `<name>.tmp-<pid>-<n>` beside `path`, opened for writing.
fn new_tmp(path: &Path) -> io::Result<(PathBuf, std::fs::File)> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    for _ in 0..16 {
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp = sibling(path, &format!(".tmp-{}-{n}", std::process::id()));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        match opts.open(&tmp) {
            Ok(f) => return Ok((tmp, f)),
            // Left by an earlier process with the same pid: take the next name.
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("no free temporary name beside {}", path.display()),
    ))
}

/// What a recovery pass acts on; faked in tests.
pub trait Recover {
    /// Start time of a live process; `None` when gone.
    fn start_time(&mut self, pid: u32) -> Option<u64>;
    /// Resumes exactly these units; returns the ones that failed for real.
    fn units(&mut self, units: Vec<FrozenUnit>) -> Vec<FrozenUnit>;
    /// Resumes the current tree of `root`; `NotFound` when it is gone.
    fn tree(&mut self, root: u32) -> io::Result<()>;
    /// Resumes these guest units by identity ([`crate::resume_guest_units`]); returns the
    /// failed ones.
    fn guest_units(&mut self, units: Vec<GuestUnit>) -> Vec<GuestUnit>;
}

/// The real resumer: exact units through [`Suspension::resume`] (which checks each thread's
/// owning process on Windows), intents through [`crate::resume_tree`], guest units through
/// [`crate::resume_guest_units`].
pub struct OsRecover;

impl Recover for OsRecover {
    fn start_time(&mut self, pid: u32) -> Option<u64> {
        crate::start_time(pid)
    }
    fn units(&mut self, units: Vec<FrozenUnit>) -> Vec<FrozenUnit> {
        Suspension::from_units(units)
            .resume()
            .err()
            .map(|(rest, _)| rest.units().to_vec())
            .unwrap_or_default()
    }
    fn tree(&mut self, root: u32) -> io::Result<()> {
        crate::resume_tree(root)
    }
    fn guest_units(&mut self, units: Vec<GuestUnit>) -> Vec<GuestUnit> {
        crate::resume_guest_units(units)
    }
}

/// What one pass did; `kept` (what failed) is also what the file holds afterwards.
#[derive(Debug, Default)]
pub struct Pass {
    pub resumed: usize,
    pub gone: usize,
    pub failed: usize,
    pub kept: PausedRecord,
}

/// Reads the record: bytes, or a read error (not "not found", which is an empty record).
type Reader<'a> = &'a mut dyn FnMut(&Path) -> io::Result<Vec<u8>>;

/// Extra reads of an unreadable record, and the pause between them.
const READ_RETRIES: u32 = 3;
const READ_BACKOFF: Duration = Duration::from_millis(50);

/// `paused.json.bad-<unix seconds>`, with `-1`, `-2`, ... appended while that name is taken:
/// a quarantined file is never replaced.
fn quarantine_name(path: &Path) -> PathBuf {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let base = sibling(path, &format!(".bad-{secs}"));
    let mut name = base.clone();
    let mut n = 0;
    while name.exists() {
        n += 1;
        name = sibling(&base, &format!("-{n}"));
    }
    name
}

/// The recovery pass. The caller MUST hold the exclusive instance lock of `dir`: a live daemon
/// holds it, so nothing it paused on purpose is ever touched. A record that is gone, has start
/// time 0 or a different start time (a reused pid) is dropped; a matching one is resumed; a real
/// failure is kept. The file is rewritten atomically only when it changed. Only a record that
/// cannot be PARSED is quarantined (renamed to `paused.json.bad-<secs>`, treated as empty); one
/// that cannot be READ (after 3 retries) fails the pass with its error and nothing is touched.
pub fn recovery_pass(dir: &Path, r: &mut impl Recover) -> io::Result<Pass> {
    recovery_pass_with(dir, r, &mut read_record, READ_BACKOFF)
}

/// [`recovery_pass`] with an injectable reader and retry pause.
pub fn recovery_pass_with(
    dir: &Path,
    r: &mut impl Recover,
    read: Reader<'_>,
    backoff: Duration,
) -> io::Result<Pass> {
    let path = dir.join(PAUSED_FILE);
    let Some(bytes) = read_retrying(&path, read, backoff)? else {
        return Ok(Pass::default());
    };
    let record = match parse_record(&bytes) {
        Ok(record) => record,
        Err(e) => {
            quarantine(&path, &e);
            return Ok(Pass::default());
        }
    };
    let mut pass = Pass::default();
    let units = record.units.iter().copied().map(unit).collect();
    let live = still_ours(units, |pid| r.start_time(pid));
    let live_intents: Vec<(u32, u64)> = record
        .intents
        .iter()
        .copied()
        .filter(|&(root, start)| start != 0 && r.start_time(root) == Some(start))
        .collect();
    pass.gone = record.units.len() - live.len() + record.intents.len() - live_intents.len();
    if !live.is_empty() {
        let n = live.len();
        let failed = r.units(live);
        pass.resumed += n - failed.len();
        pass.failed += failed.len();
        pass.kept.units = failed
            .iter()
            .map(|u| (u.pid, u.tid, u.start_time))
            .collect();
    }
    for (root, start) in live_intents {
        match r.tree(root) {
            Ok(()) => pass.resumed += 1,
            Err(e) if e.kind() == io::ErrorKind::NotFound => pass.gone += 1,
            Err(_) => {
                pass.failed += 1;
                pass.kept.intents.push((root, start));
            }
        }
    }
    if pass.kept != record {
        // On failure the old (larger) record stays: the next pass retries it.
        if let Err(e) = save_record(&path, &pass.kept) {
            eprintln!("sync_gate: cannot rewrite {}: {e}", path.display());
        }
    }
    Ok(pass)
}

/// The bytes at `path`, None when it does not exist; any other read error is retried
/// `READ_RETRIES` times, then returned.
fn read_retrying(path: &Path, read: Reader<'_>, backoff: Duration) -> io::Result<Option<Vec<u8>>> {
    let mut tries = 0;
    loop {
        match read(path) {
            Ok(bytes) => return Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) if tries >= READ_RETRIES => return Err(e),
            Err(_) => {
                tries += 1;
                std::thread::sleep(backoff);
            }
        }
    }
}

/// Moves a record that cannot be parsed aside, under a name never reused, and says so.
fn quarantine(path: &Path, e: &io::Error) {
    let bad = quarantine_name(path);
    let moved = std::fs::rename(path, &bad);
    eprintln!(
        "sync_gate: corrupt {} ({e}); moved to {} ({moved:?})",
        path.display(),
        bad.display()
    );
}

/// The guest pass: a missing file is nothing to do; one that cannot be parsed is quarantined as
/// `paused-guests.json.bad-<secs>` (as `paused.json` is); every unit goes to `r.guest_units`,
/// which checks each one's identity itself; the failed ones are written back, none = the file is
/// removed. Never looks at a tree. `kept` stays empty (it is the owner's format). The caller
/// MUST hold the instance lock of `dir`.
pub fn guest_recovery_pass(dir: &Path, r: &mut impl Recover) -> io::Result<Pass> {
    guest_pass_with(dir, r, save_guest_record)
}

/// [`guest_recovery_pass`] with an injectable store. Replay is at-least-once (R-3S-T3a): when the
/// units were resumed but the record cannot be settled (rewritten or removed), the pass FAILS, so
/// the caller never sees success while a stale record stays on disk.
fn guest_pass_with(
    dir: &Path,
    r: &mut impl Recover,
    save: impl FnOnce(&Path, &GuestRecord) -> io::Result<()>,
) -> io::Result<Pass> {
    let path = dir.join(GUEST_PAUSED_FILE);
    let Some(bytes) = read_retrying(&path, &mut read_record, READ_BACKOFF)? else {
        return Ok(Pass::default());
    };
    let record: GuestRecord = match serde_json::from_slice(&bytes) {
        Ok(record) => record,
        Err(e) => {
            quarantine(&path, &e.into());
            return Ok(Pass::default());
        }
    };
    let n = record.units.len();
    let failed = r.guest_units(record.units);
    let pass = Pass {
        resumed: n.saturating_sub(failed.len()),
        failed: failed.len(),
        ..Pass::default()
    };
    // On failure the old (larger) record stays: the next pass retries it, and this one fails.
    save(dir, &GuestRecord { units: failed }).inspect_err(|e| {
        eprintln!("sync_gate: cannot rewrite {}: {e}", path.display());
    })?;
    Ok(pass)
}

/// Result of [`recover_as_owner`].
#[derive(Debug)]
pub enum RecoveryOutcome {
    /// A live daemon (or another recoverer) holds the instance lock: nothing was done.
    Busy,
    Done {
        resumed: usize,
        gone: usize,
        failed: usize,
    },
    /// The lock or the directory could not be used.
    Unavailable(io::Error),
}

/// Runs [`recovery_pass`], then [`guest_recovery_pass`], only while holding
/// `<dir>/sync_gated.lock` exclusively, taken without blocking and released at the end; the
/// outcome adds both (either one failing makes it `Unavailable`). A missing dir means nothing was
/// ever recorded there.
pub fn recover_as_owner(dir: &Path) -> RecoveryOutcome {
    recover_as_owner_with(dir, &mut OsRecover)
}

/// [`recover_as_owner`] with an injectable resumer.
pub fn recover_as_owner_with(dir: &Path, r: &mut impl Recover) -> RecoveryOutcome {
    // Records are read by path after a file check, which holds only if nobody else can change the
    // folder or its ancestors: refuse before opening the lock or reading anything.
    {
        use sync_gate_core::{DirState, check_private_dir};
        let nothing = RecoveryOutcome::Done {
            resumed: 0,
            gone: 0,
            failed: 0,
        };
        match check_private_dir(dir) {
            Ok(DirState::Missing) => return nothing,
            Err(e) => {
                eprintln!("sync_gate: not recovering from {}: {e}", dir.display());
                return nothing;
            }
            Ok(_) => {}
        }
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(dir.join(LOCK_FILE));
    let file = match file {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return RecoveryOutcome::Done {
                resumed: 0,
                gone: 0,
                failed: 0,
            };
        }
        Err(e) => return RecoveryOutcome::Unavailable(e),
    };
    let _lock = match try_lock(file, true) {
        Ok(Some(lock)) => lock,
        Ok(None) => return RecoveryOutcome::Busy,
        Err(e) => return RecoveryOutcome::Unavailable(e),
    };
    // The guest file is never hostage to the owner's: both passes run.
    let owner = recovery_pass(dir, r);
    let guests = guest_recovery_pass(dir, r);
    match (owner, guests) {
        (Ok(a), Ok(b)) => RecoveryOutcome::Done {
            resumed: a.resumed + b.resumed,
            gone: a.gone + b.gone,
            failed: a.failed + b.failed,
        },
        (Err(e), _) | (_, Err(e)) => RecoveryOutcome::Unavailable(e),
    }
}

/// Units whose process still has its recorded identity; reused PIDs are skipped. A record with
/// start time 0 (unknown when recorded) never matches: a reused pid must not pass as it.
pub fn still_ours(
    units: Vec<FrozenUnit>,
    mut start: impl FnMut(u32) -> Option<u64>,
) -> Vec<FrozenUnit> {
    units
        .into_iter()
        .filter(|u| u.start_time != 0 && start(u.pid) == Some(u.start_time))
        .collect()
}

/// Tests: lets every user change the folder `p` (`on`), or takes that back: mode 0777/0700 on
/// Unix, an inheritable Modify entry for Everyone on Windows.
#[cfg(test)]
pub(crate) fn others_write(p: &Path, on: bool) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if on { 0o777 } else { 0o700 };
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    #[cfg(windows)]
    {
        let args = if on {
            ["/grant", "*S-1-1-0:(OI)(CI)(M)"]
        } else {
            ["/remove:g", "*S-1-1-0"]
        };
        let out = std::process::Command::new("icacls")
            .arg(p)
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "icacls: {out:?}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FrozenUnit;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier, Mutex, mpsc};
    use std::time::Duration;

    #[test]
    fn paused_format_reads_exact_units_without_modifying_input() {
        let bytes = b"[[10,11,100],[20,21,200]]";
        let record = parse_record(bytes).unwrap();
        assert_eq!(record.units, vec![(10, 11, 100), (20, 21, 200)]);
        assert!(record.intents.is_empty());
        assert!(parse_record(b"broken").is_err());
    }

    #[test]
    fn a_record_with_an_unknown_start_time_never_matches() {
        let unit = FrozenUnit {
            pid: 1,
            tid: 1,
            start_time: 0,
        };
        // A reused pid whose start time cannot be read must not look like the frozen unit.
        assert!(still_ours(vec![unit], |_| Some(0)).is_empty());
    }

    // ---- fix round 3: one recovery owner at a time ----

    fn fu(pid: u32, start_time: u64) -> FrozenUnit {
        FrozenUnit {
            pid,
            tid: pid + 1,
            start_time,
        }
    }

    /// Fake resumer: `starts` are the live processes; `stuck` units, `stuck_trees` roots and
    /// `guest_stuck` guest units fail. `guest_calls` is what each `guest_units` call was given.
    #[derive(Default)]
    struct Fake {
        starts: std::collections::HashMap<u32, u64>,
        stuck: Vec<FrozenUnit>,
        stuck_trees: Vec<u32>,
        resumed: Vec<FrozenUnit>,
        trees: Vec<u32>,
        guest_stuck: Vec<GuestUnit>,
        guest_calls: Vec<Vec<GuestUnit>>,
    }

    impl Recover for Fake {
        fn start_time(&mut self, pid: u32) -> Option<u64> {
            self.starts.get(&pid).copied()
        }
        fn units(&mut self, units: Vec<FrozenUnit>) -> Vec<FrozenUnit> {
            let (failed, ok): (Vec<_>, Vec<_>) =
                units.into_iter().partition(|u| self.stuck.contains(u));
            self.resumed.extend(ok);
            failed
        }
        fn tree(&mut self, root: u32) -> io::Result<()> {
            self.trees.push(root);
            if self.stuck_trees.contains(&root) {
                Err(io::ErrorKind::PermissionDenied.into())
            } else {
                Ok(())
            }
        }
        fn guest_units(&mut self, units: Vec<GuestUnit>) -> Vec<GuestUnit> {
            self.guest_calls.push(units.clone());
            units
                .into_iter()
                .filter(|u| self.guest_stuck.contains(u))
                .collect()
        }
    }

    fn rdir(tag: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("sync_gate-recover-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn on_disk(dir: &Path) -> PausedRecord {
        load_record(&dir.join(PAUSED_FILE)).unwrap().unwrap()
    }

    fn tuple(u: &FrozenUnit) -> (u32, u32, u64) {
        (u.pid, u.tid, u.start_time)
    }

    #[test]
    fn a_held_instance_lock_means_busy_and_nothing_is_touched() {
        let dir = rdir("busy");
        let text = r#"{"units":[[10,11,100]],"intents":[[20,200]]}"#;
        std::fs::write(dir.join(PAUSED_FILE), text).unwrap();
        let held = try_lock(std::fs::File::create(dir.join(LOCK_FILE)).unwrap(), true)
            .unwrap()
            .expect("free");
        let mut fake = Fake {
            starts: [(10, 100), (20, 200)].into(),
            ..Fake::default()
        };
        let outcome = recover_as_owner_with(&dir, &mut fake);
        assert!(matches!(outcome, RecoveryOutcome::Busy), "{outcome:?}");
        assert!(fake.resumed.is_empty() && fake.trees.is_empty());
        assert_eq!(
            std::fs::read_to_string(dir.join(PAUSED_FILE)).unwrap(),
            text
        );
        drop(held);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_pass_resumes_matching_units_drops_stale_ones_and_keeps_failures() {
        let dir = rdir("units");
        let (ok, gone, reused, zero, stuck) =
            (fu(1, 100), fu(2, 200), fu(3, 300), fu(4, 0), fu(5, 500));
        let record = PausedRecord {
            units: [ok, gone, reused, zero, stuck].iter().map(tuple).collect(),
            intents: Vec::new(),
        };
        save_record(&dir.join(PAUSED_FILE), &record).unwrap();
        let mut fake = Fake {
            // 2 is gone, 3 was reused, 4 has no recorded start time (a live 0 must not match)
            starts: [(1, 100), (3, 999), (4, 0), (5, 500)].into(),
            stuck: vec![stuck],
            ..Fake::default()
        };
        let outcome = recover_as_owner_with(&dir, &mut fake);
        assert!(
            matches!(
                outcome,
                RecoveryOutcome::Done {
                    resumed: 1,
                    gone: 3,
                    failed: 1
                }
            ),
            "{outcome:?}"
        );
        assert_eq!(fake.resumed, vec![ok]);
        assert_eq!(
            on_disk(&dir),
            PausedRecord {
                units: vec![tuple(&stuck)],
                intents: Vec::new()
            }
        );
        // The failed unit is retried by the next pass; once it resumes the record is empty.
        fake.stuck.clear();
        recover_as_owner_with(&dir, &mut fake);
        assert_eq!(fake.resumed, vec![ok, stuck]);
        assert_eq!(on_disk(&dir), PausedRecord::default());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_old_array_format_is_read_as_units() {
        let dir = rdir("old");
        std::fs::write(dir.join(PAUSED_FILE), "[[1,2,100]]").unwrap();
        let mut fake = Fake {
            starts: [(1, 100)].into(),
            ..Fake::default()
        };
        recover_as_owner_with(&dir, &mut fake);
        assert_eq!(fake.resumed, vec![fu(1, 100)]);
        assert_eq!(on_disk(&dir), PausedRecord::default());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn quarantined(dir: &Path) -> Vec<PathBuf> {
        quarantined_of(dir, PAUSED_FILE)
    }

    fn quarantined_of(dir: &Path, file: &str) -> Vec<PathBuf> {
        let prefix = format!("{file}.bad-");
        let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                let name = p.file_name().unwrap().to_string_lossy().into_owned();
                name.starts_with(&prefix)
            })
            .collect();
        found.sort();
        found
    }

    #[test]
    fn a_corrupt_record_is_moved_aside_never_overwritten() {
        let dir = rdir("corrupt");
        std::fs::write(dir.join(PAUSED_FILE), "broken").unwrap();
        let outcome = recover_as_owner_with(&dir, &mut Fake::default());
        assert!(
            matches!(
                outcome,
                RecoveryOutcome::Done {
                    resumed: 0,
                    gone: 0,
                    failed: 0
                }
            ),
            "{outcome:?}"
        );
        let bad = quarantined(&dir);
        assert_eq!(bad.len(), 1, "{bad:?}");
        assert_eq!(std::fs::read_to_string(&bad[0]).unwrap(), "broken");
        assert!(!dir.join(PAUSED_FILE).exists());
        // A second corrupt file in the same second gets its own name; the first stays intact.
        std::fs::write(dir.join(PAUSED_FILE), "also broken").unwrap();
        recover_as_owner_with(&dir, &mut Fake::default());
        let bad = quarantined(&dir);
        assert_eq!(bad.len(), 2, "{bad:?}");
        let texts: Vec<_> = bad
            .iter()
            .map(|p| std::fs::read_to_string(p).unwrap())
            .collect();
        assert!(texts.contains(&"broken".to_string()), "{texts:?}");
        assert!(texts.contains(&"also broken".to_string()), "{texts:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_read_error_touches_nothing_and_fails_the_pass() {
        let dir = rdir("read-error");
        let text = r#"{"units":[[10,11,100]],"intents":[]}"#;
        std::fs::write(dir.join(PAUSED_FILE), text).unwrap();
        let mut fake = Fake {
            starts: [(10, 100)].into(),
            ..Fake::default()
        };
        let mut reads = 0;
        let err = recovery_pass_with(
            &dir,
            &mut fake,
            &mut |_| {
                reads += 1;
                Err(io::ErrorKind::PermissionDenied.into())
            },
            Duration::ZERO,
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(reads, 4, "the read and 3 retries");
        assert_eq!(
            std::fs::read_to_string(dir.join(PAUSED_FILE)).unwrap(),
            text
        );
        assert!(quarantined(&dir).is_empty());
        assert!(fake.resumed.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_transient_read_error_is_a_normal_pass() {
        let dir = rdir("read-transient");
        let text = r#"{"units":[[10,11,100]],"intents":[]}"#;
        std::fs::write(dir.join(PAUSED_FILE), text).unwrap();
        let mut fake = Fake {
            starts: [(10, 100)].into(),
            ..Fake::default()
        };
        let mut reads = 0;
        let pass = recovery_pass_with(
            &dir,
            &mut fake,
            &mut |p| {
                reads += 1;
                if reads == 1 {
                    return Err(io::ErrorKind::PermissionDenied.into());
                }
                std::fs::read(p)
            },
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!((reads, pass.resumed), (2, 1));
        assert_eq!(fake.resumed, vec![fu(10, 100)]);
        assert_eq!(on_disk(&dir), PausedRecord::default());
        assert!(quarantined(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unreadable_record_is_unavailable_through_recover_as_owner() {
        // A directory where the file should be: reading it fails, and it is not "not found".
        let dir = rdir("read-dir");
        std::fs::create_dir(dir.join(PAUSED_FILE)).unwrap();
        let outcome = recover_as_owner_with(&dir, &mut Fake::default());
        assert!(
            matches!(outcome, RecoveryOutcome::Unavailable(_)),
            "{outcome:?}"
        );
        assert!(dir.join(PAUSED_FILE).is_dir());
        assert!(quarantined(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A record another user could have written is unreadable: never parsed, never resumed.
    #[cfg(unix)]
    #[test]
    fn an_untrusted_paused_record_is_unreadable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = rdir("untrusted");
        let path = dir.join(PAUSED_FILE);
        let text = r#"{"units":[[10,11,100]],"intents":[[20,200]]}"#;
        std::fs::write(&path, text).unwrap();
        let chmod = |mode| std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode));
        let reads = || RECORD_READS.with(std::cell::Cell::get);
        chmod(0o666).unwrap();
        let before = reads();
        let e = load_record(&path).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
        // The pass the daemon and the CLI run treats it the same way, and leaves it alone.
        let mut fake = Fake {
            starts: [(10, 100), (20, 200)].into(),
            ..Fake::default()
        };
        let outcome = recover_as_owner_with(&dir, &mut fake);
        assert!(
            matches!(&outcome, RecoveryOutcome::Unavailable(e) if e.kind() == io::ErrorKind::PermissionDenied),
            "{outcome:?}"
        );
        assert!(fake.resumed.is_empty() && fake.trees.is_empty());
        assert_eq!(reads(), before, "the refused record was read");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        // Control: only we can write it.
        chmod(0o600).unwrap();
        assert!(load_record(&path).unwrap().is_some());
        recover_as_owner_with(&dir, &mut fake);
        assert_eq!(fake.resumed, vec![fu(10, 100)]);
        assert_eq!(reads(), before + 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A folder others can write is never trusted, even with a legitimate 0600 record in it:
    /// nothing is read, resumed or written. Control: the same with the folder 0700.
    #[test]
    fn cli_recovery_refuses_a_folder_others_can_write() {
        let dir = rdir("unsafe-dir");
        let path = dir.join(PAUSED_FILE);
        let text = r#"{"units":[[10,11,100]],"intents":[]}"#;
        std::fs::write(&path, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let reads = || RECORD_READS.with(std::cell::Cell::get);
        let mut fake = Fake {
            starts: [(10, 100)].into(),
            ..Fake::default()
        };
        others_write(&dir, true);
        let before = reads();
        let outcome = recover_as_owner_with(&dir, &mut fake);
        assert!(
            matches!(outcome, RecoveryOutcome::Done { resumed: 0, .. }),
            "{outcome:?}"
        );
        assert_eq!(reads(), before, "the record was read");
        assert!(fake.resumed.is_empty());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        others_write(&dir, false);
        recover_as_owner_with(&dir, &mut fake);
        assert_eq!(fake.resumed, vec![fu(10, 100)]);
        // Windows also counts the absent guest record (no file check refuses it first).
        assert!(reads() > before, "the record was not read");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// What `write_atomic` writes passes `check_private_file` whatever the umask (0002 on many
    /// Linux desktops would otherwise give 0664, and the records would be refused) and whatever
    /// a crash left behind: a stale `.tmp` (0666 here) is never reused.
    #[cfg(unix)]
    #[test]
    fn write_atomic_gives_a_file_only_we_can_read() {
        use std::os::unix::fs::PermissionsExt;
        let dir = rdir("mode");
        let path = dir.join(PAUSED_FILE);
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        write_atomic(&path, b"[]").unwrap();
        assert_eq!(mode(&path), 0o600, "{:o}", mode(&path));
        let stale = sibling(&path, ".tmp");
        std::fs::write(&stale, b"stale").unwrap();
        std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o666)).unwrap();
        write_atomic(&path, b"[[1,2,3]]").unwrap();
        assert_eq!(mode(&path), 0o600, "{:o}", mode(&path));
        assert_eq!(std::fs::read(&path).unwrap(), b"[[1,2,3]]");
        // A failed write leaves no temporary file of its own behind.
        let blocked = dir.join("blocked");
        std::fs::create_dir_all(blocked.join("inside")).unwrap();
        assert!(write_atomic(&blocked, b"x").is_err());
        let mut names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, ["blocked", "paused.json", "paused.json.tmp"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_live_intent_is_resumed_by_tree_and_a_stale_one_is_dropped() {
        let dir = rdir("intents");
        let record = PausedRecord {
            units: Vec::new(),
            intents: vec![(10, 100), (20, 200), (30, 300), (40, 0), (50, 500)],
        };
        save_record(&dir.join(PAUSED_FILE), &record).unwrap();
        let mut fake = Fake {
            // 20 was reused, 30 is gone, 40 has no start time, 50 cannot be resumed yet
            starts: [(10, 100), (20, 999), (40, 0), (50, 500)].into(),
            stuck_trees: vec![50],
            ..Fake::default()
        };
        let outcome = recover_as_owner_with(&dir, &mut fake);
        assert!(
            matches!(
                outcome,
                RecoveryOutcome::Done {
                    resumed: 1,
                    gone: 3,
                    failed: 1
                }
            ),
            "{outcome:?}"
        );
        assert_eq!(fake.trees, vec![10, 50]);
        assert_eq!(
            on_disk(&dir),
            PausedRecord {
                units: Vec::new(),
                intents: vec![(50, 500)]
            }
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_dir_or_record_is_nothing_to_recover() {
        let dir = rdir("empty");
        let missing = dir.join("never-created");
        for d in [&dir, &missing] {
            let outcome = recover_as_owner_with(d, &mut Fake::default());
            assert!(
                matches!(
                    outcome,
                    RecoveryOutcome::Done {
                        resumed: 0,
                        gone: 0,
                        failed: 0
                    }
                ),
                "{outcome:?}"
            );
            assert!(!d.join(PAUSED_FILE).exists());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Blocks inside the pass until the test says so, counting how many passes got in.
    struct Gate {
        entered: Arc<AtomicUsize>,
        release: Arc<Mutex<mpsc::Receiver<()>>>,
    }

    impl Recover for Gate {
        fn start_time(&mut self, _: u32) -> Option<u64> {
            Some(100)
        }
        fn units(&mut self, _: Vec<FrozenUnit>) -> Vec<FrozenUnit> {
            self.entered.fetch_add(1, Ordering::SeqCst);
            let _ = self
                .release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(2));
            Vec::new()
        }
        fn tree(&mut self, _: u32) -> io::Result<()> {
            Ok(())
        }
        fn guest_units(&mut self, _: Vec<GuestUnit>) -> Vec<GuestUnit> {
            Vec::new()
        }
    }

    fn gu(pid: u32) -> GuestUnit {
        GuestUnit {
            pid,
            tid: pid + 1,
            created: 133_000_000_000_000_000 + u64::from(pid),
            ident: "account:S-1-5-21-1-2-3-1004".to_string(),
        }
    }

    fn guests_on_disk(dir: &Path) -> GuestRecord {
        serde_json::from_slice(&std::fs::read(dir.join(GUEST_PAUSED_FILE)).unwrap()).unwrap()
    }

    /// Test 39: the guest file has a pass of its own, never by tree, next to the owner's.
    #[test]
    fn the_guest_file_is_its_own_pass() {
        let dir = rdir("guest-pass");
        let owner = r#"{"units":[[10,11,1000]],"intents":[]}"#;
        let (a, b) = (gu(20), gu(30));
        std::fs::write(dir.join(PAUSED_FILE), owner).unwrap();
        save_guest_record(
            &dir,
            &GuestRecord {
                units: vec![a.clone(), b.clone()],
            },
        )
        .unwrap();
        let mut fake = Fake {
            starts: [(10, 1000)].into(),
            guest_stuck: vec![b.clone()],
            ..Fake::default()
        };
        let outcome = recover_as_owner_with(&dir, &mut fake);
        assert!(
            matches!(
                outcome,
                RecoveryOutcome::Done {
                    resumed: 2,
                    gone: 0,
                    failed: 1
                }
            ),
            "{outcome:?}"
        );
        assert_eq!(fake.resumed, vec![unit((10, 11, 1000))]);
        assert_eq!(fake.guest_calls, vec![vec![a.clone(), b.clone()]]);
        assert!(fake.trees.is_empty());
        // The one that failed is all the file keeps; once nothing fails the file goes.
        assert_eq!(
            guests_on_disk(&dir),
            GuestRecord {
                units: vec![b.clone()]
            }
        );
        fake.guest_stuck.clear();
        recover_as_owner_with(&dir, &mut fake);
        assert_eq!(fake.guest_calls[1], vec![b]);
        assert!(!dir.join(GUEST_PAUSED_FILE).exists());

        // An unparsable guest file is moved aside; the owner's record is handled as always.
        std::fs::write(dir.join(PAUSED_FILE), owner).unwrap();
        std::fs::write(dir.join(GUEST_PAUSED_FILE), "broken").unwrap();
        let mut fake = Fake {
            starts: [(10, 1000)].into(),
            ..Fake::default()
        };
        recover_as_owner_with(&dir, &mut fake);
        assert_eq!(fake.resumed, vec![unit((10, 11, 1000))]);
        assert!(fake.guest_calls.is_empty());
        let bad = quarantined_of(&dir, GUEST_PAUSED_FILE);
        assert_eq!(bad.len(), 1, "{bad:?}");
        assert_eq!(std::fs::read_to_string(&bad[0]).unwrap(), "broken");
        assert!(quarantined(&dir).is_empty());

        // Without the guest file, nothing is created.
        assert!(!dir.join(GUEST_PAUSED_FILE).exists());
        recover_as_owner_with(&dir, &mut fake);
        assert!(!dir.join(GUEST_PAUSED_FILE).exists());
        assert!(fake.guest_calls.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// R-3S-T3a: a record that cannot be settled after resuming makes the pass fail.
    #[test]
    fn a_guest_record_that_cannot_be_settled_fails_the_pass() {
        let dir = rdir("settle-fails");
        let denied = |_: &Path, _: &GuestRecord| Err(io::ErrorKind::PermissionDenied.into());
        // Once with a rewrite (one unit still stuck) and once with a delete (none stuck).
        for stuck in [vec![gu(30)], vec![]] {
            save_guest_record(
                &dir,
                &GuestRecord {
                    units: vec![gu(20), gu(30)],
                },
            )
            .unwrap();
            let mut fake = Fake {
                guest_stuck: stuck,
                ..Fake::default()
            };
            let e = guest_pass_with(&dir, &mut fake, denied).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
            // The stale record is still there for the next pass.
            assert_eq!(guests_on_disk(&dir).units.len(), 2);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Test 40 (D3): an older binary rewriting `paused.json` never touches a guest's pause.
    #[test]
    fn an_old_rewrite_of_paused_json_keeps_guest_pauses() {
        /// `PausedRecord` as of f797014, copied literally (only the name differs).
        #[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub struct OldRecord {
            #[serde(default)]
            pub units: Vec<(u32, u32, u64)>,
            #[serde(default)]
            pub intents: Vec<(u32, u64)>,
        }
        let dir = rdir("old-rewrite");
        let paused = dir.join(PAUSED_FILE);
        save_record(
            &paused,
            &PausedRecord {
                units: vec![(10, 11, 1000)],
                intents: vec![(12, 1000)],
            },
        )
        .unwrap();
        let guests = vec![gu(20), gu(30)];
        save_guest_record(
            &dir,
            &GuestRecord {
                units: guests.clone(),
            },
        )
        .unwrap();
        let before = std::fs::read(dir.join(GUEST_PAUSED_FILE)).unwrap();
        // What an older binary does: read paused.json, empty its units, write it back.
        let mut old: OldRecord = serde_json::from_slice(&std::fs::read(&paused).unwrap()).unwrap();
        old.units.clear();
        write_atomic(&paused, &serde_json::to_vec(&old).unwrap()).unwrap();
        assert_eq!(std::fs::read(dir.join(GUEST_PAUSED_FILE)).unwrap(), before);
        let mut fake = Fake::default();
        guest_recovery_pass(&dir, &mut fake).unwrap();
        assert_eq!(fake.guest_calls, vec![guests]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn two_recoverers_at_once_run_exactly_one_pass() {
        let dir = rdir("race");
        for i in 0..20 {
            std::fs::write(dir.join(PAUSED_FILE), "[[1,2,100]]").unwrap();
            let entered = Arc::new(AtomicUsize::new(0));
            let (release_tx, release_rx) = mpsc::channel();
            let release = Arc::new(Mutex::new(release_rx));
            let (out_tx, out_rx) = mpsc::channel();
            let barrier = Arc::new(Barrier::new(2));
            let racers: Vec<_> = (0..2)
                .map(|_| {
                    let mut gate = Gate {
                        entered: entered.clone(),
                        release: release.clone(),
                    };
                    let (dir, out, barrier) = (dir.clone(), out_tx.clone(), barrier.clone());
                    std::thread::spawn(move || {
                        barrier.wait();
                        let _ = out.send(recover_as_owner_with(&dir, &mut gate));
                    })
                })
                .collect();
            // The first answer must come while the other racer is still inside its pass.
            let first = out_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            release_tx.send(()).unwrap();
            let second = out_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            for r in racers {
                r.join().unwrap();
            }
            assert!(matches!(first, RecoveryOutcome::Busy), "{i}: {first:?}");
            assert!(
                matches!(second, RecoveryOutcome::Done { resumed: 1, .. }),
                "{i}: {second:?}"
            );
            assert_eq!(entered.load(Ordering::SeqCst), 1, "iteration {i}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    fn mode_of(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    fn chmod(p: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn an_existing_readable_dir_is_tightened_to_0700() {
        let base = rdir("tighten");
        let d = base.join("sub");
        std::fs::create_dir(&d).unwrap();
        chmod(&d, 0o755);
        create_private_dir(&d).unwrap();
        assert_eq!(mode_of(&d), 0o700);
        // a new one is 0700 too, parents included
        create_private_dir(&d.join("a").join("b")).unwrap();
        assert_eq!(mode_of(&d.join("a").join("b")), 0o700);
        assert_eq!(mode_of(&d.join("a")), 0o700);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn a_dir_others_can_write_is_refused_not_tightened() {
        let base = rdir("others-write");
        let d = base.join("sub");
        std::fs::create_dir(&d).unwrap();
        chmod(&d, 0o777);
        assert!(create_private_dir(&d).is_err());
        assert_eq!(mode_of(&d), 0o777);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The descriptor of `p` in SDDL: owner and DACL.
    #[cfg(windows)]
    fn sddl(p: &Path) -> String {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
            SDDL_REVISION_1, SE_FILE_OBJECT,
        };
        use windows_sys::Win32::Security::{
            DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        };
        let wide: Vec<u16> = p.as_os_str().encode_wide().chain([0]).collect();
        let what = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: a NUL-terminated path; the out pointers are valid; `sd` is freed below.
        let err = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                what,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sd,
            )
        };
        assert_eq!(err, 0, "GetNamedSecurityInfoW {}", p.display());
        let (mut text, mut len) = (std::ptr::null_mut(), 0u32);
        // SAFETY: `sd` is the valid descriptor read above; `text` is freed below.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1,
                what,
                &mut text,
                &mut len,
            )
        };
        assert_ne!(ok, 0);
        // SAFETY: `text` holds `len` UTF-16 units.
        let s = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len as usize) });
        // SAFETY: both were allocated by the calls above and are freed once.
        unsafe {
            LocalFree(text.cast());
            LocalFree(sd);
        }
        s.trim_end_matches('\0').to_owned()
    }

    /// This user's SID, as `whoami` prints it.
    #[cfg(windows)]
    fn user_sid() -> String {
        let out = std::process::Command::new("whoami")
            .args(["/user", "/fo", "csv", "/nh"])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        text.trim()
            .rsplit(',')
            .next()
            .unwrap()
            .trim_matches('"')
            .to_owned()
    }

    #[cfg(windows)]
    fn icacls(p: &Path, args: &[&str]) {
        let out = std::process::Command::new("icacls")
            .arg(p)
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "icacls: {out:?}");
    }

    /// The DACL entries of an SDDL string, without the inherited flag.
    #[cfg(windows)]
    fn entries(s: &str) -> Vec<String> {
        let dacl = &s[s.find("D:").unwrap() + 2..];
        let mut v: Vec<String> = dacl
            .split('(')
            .skip(1)
            .map(|a| format!("({a}").replace("ID;", ";"))
            .collect();
        v.sort();
        v
    }

    /// A new folder and the parents it creates are owned by this user and inherit what others
    /// may read from where they are created; write access an inherited entry would give others
    /// is taken out, and their read access stays.
    #[cfg(windows)]
    #[test]
    fn a_new_dir_keeps_what_others_may_read_and_never_their_write() {
        let u = user_sid();
        let base = rdir("new-acl");
        icacls(&base, &["/grant", "*S-1-5-32-545:(OI)(CI)(RX)"]);
        let d = base.join("a").join("b");
        create_private_dir(&d).unwrap();
        for p in [base.join("a"), d.clone()] {
            let s = sddl(&p);
            assert!(!s.contains("D:P"), "{}: {s}", p.display());
            assert!(s.contains("ID;0x1200a9;;;BU)"), "{}: {s}", p.display());
        }
        assert_eq!(
            sync_gate_core::check_private_dir(&d).unwrap(),
            sync_gate_core::DirState::OthersCanRead
        );
        // An entry that gives others write only to what is created inside.
        let w = rdir("new-acl-io");
        icacls(&w, &["/grant", "*S-1-5-32-545:(OI)(CI)(RX)"]);
        icacls(&w, &["/grant", "*S-1-5-32-545:(OI)(CI)(IO)(M)"]);
        let d = w.join("a").join("b");
        create_private_dir(&d).unwrap();
        for p in [w.join("a"), d.clone()] {
            let s = sddl(&p);
            assert!(s.starts_with(&format!("O:{u}")), "{}: {s}", p.display());
            let bu: Vec<String> = entries(&s)
                .into_iter()
                .filter(|a| a.ends_with(";;;BU)"))
                .collect();
            assert_eq!(bu, ["(A;OICI;0x1200a9;;;BU)"], "{}: {s}", p.display());
        }
        std::fs::create_dir(d.join("c")).unwrap();
        assert_eq!(
            sync_gate_core::check_private_dir(&d.join("c")).unwrap(),
            sync_gate_core::DirState::OthersCanRead
        );
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&w);
    }

    /// A folder of ours others can only read is left as found; one others can change is an
    /// error and keeps its DACL as found.
    #[cfg(windows)]
    #[test]
    fn an_existing_dir_others_can_only_read_is_left_as_found() {
        let base = rdir("tighten-acl");
        let r = base.join("readable");
        std::fs::create_dir(&r).unwrap();
        icacls(&r, &["/grant", "*S-1-5-32-545:(OI)(CI)(RX)"]);
        let before = sddl(&r);
        assert!(before.contains(";;;BU)"), "{before}");
        create_private_dir(&r).unwrap();
        assert_eq!(sddl(&r), before);
        let w = base.join("writable");
        std::fs::create_dir(&w).unwrap();
        icacls(&w, &["/grant", "*S-1-5-32-545:(OI)(CI)(M)"]);
        let before = sddl(&w);
        let e = create_private_dir(&w).unwrap_err();
        assert!(e.to_string().contains("writable by other users"), "{e}");
        assert_eq!(sddl(&w), before);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_dir_is_refused() {
        let base = rdir("symlink");
        let target = base.join("target");
        std::fs::create_dir(&target).unwrap();
        chmod(&target, 0o755);
        let link = base.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(create_private_dir(&link).is_err());
        assert_eq!(mode_of(&target), 0o755);
        let _ = std::fs::remove_dir_all(&base);
    }
}
