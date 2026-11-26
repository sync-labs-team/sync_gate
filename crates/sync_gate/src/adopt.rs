//! `sync_gate mcp adopt | restore`: point chosen MCP servers of Claude Code and Codex at the hub
//! (`sync_gate mcp connect <name>`) and put their original launch back. Only the bytes of the
//! `command` and `args` values change (`sync_gate_core::agent_config`); this is the file
//! transaction around that edit.
//!
//! Per agent file: sync_gate's own lock (one adopt or restore at a time), Claude Code's lock
//! folder `<file>.lock` (taken when free and never removed; waited for when fresh; a stale one is
//! left as it is and the operation goes ahead without it), a backup beside the file, a final
//! check that the file still holds what was read, and a rename. Neither agent can be fully
//! excluded, and the output says so (plan 3, D9 and D10).
//!
//! Debug builds only (the e2e tests): `SYNC_GATE_TEST_ADOPT_PAUSE=<marker>` (in the window before
//! the rename, create `<marker>` and wait up to 30 s for `<marker>.go`),
//! `SYNC_GATE_TEST_ADOPT_WINDOW=<file>` (copy `<file>` over the agent file in that window: a writer
//! that ignores the lock), `SYNC_GATE_TEST_ADOPT_BEFORE_CHECK=<file>` (the same, once, before the
//! final check), `SYNC_GATE_TEST_LOCK_WAIT_MS` (both lock waits), `SYNC_GATE_TEST_LOCK_STALE_MS`
//! (the age at which Claude's lock counts as abandoned), `SYNC_GATE_TEST_LOCK_BUSY=<marker>`
//! (create `<marker>` while waiting for a busy Claude lock) and `SYNC_GATE_TEST_ADOPT_TRACE=<file>`
//! (append `durable <path>` / `replaced <path>` lines, in the order they happen).

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{fs, thread};
use sync_gate_core::adopted::{Adopted, AdoptedEntry, Agent, RECORD, mcp_table, read_adopted};
use sync_gate_core::agent_config::{Found, Restored, restore_launch, servers, set_launch};
use sync_gate_core::{Config, ConfigLoadError, McpServer};

#[derive(Clone, Copy, PartialEq, Eq, Debug, clap::ValueEnum)]
pub enum AgentArg {
    All,
    Claude,
    Codex,
}

impl AgentArg {
    fn has(self, a: Agent) -> bool {
        match self {
            AgentArg::All => true,
            AgentArg::Claude => a == Agent::Claude,
            AgentArg::Codex => a == Agent::Codex,
        }
    }
}

pub struct AdoptOptions {
    pub agent: AgentArg,
    pub dry_run: bool,
    pub any_folder: bool,
    pub claude_config: Option<PathBuf>,
    pub codex_config: Option<PathBuf>,
    pub servers: Vec<String>,
    /// None = SYNC_GATE_CONFIG / SYNC_GATE_DATA_DIR / the defaults; tests pass paths, never env.
    pub sync_gate_config: Option<PathBuf>,
    pub data_dir: Option<PathBuf>,
}

pub struct RestoreOptions {
    pub agent: AgentArg,
    pub claude_config: Option<PathBuf>,
    pub codex_config: Option<PathBuf>,
    /// Empty: every recorded entry.
    pub servers: Vec<String>,
    /// Exit 3 while a selected entry is still adopted after the restore.
    pub strict: bool,
    /// None = SYNC_GATE_DATA_DIR / the default.
    pub data_dir: Option<PathBuf>,
}

const FG_LOCK: &str = "mcp-adopt.lock";
const FG_WAIT: Duration = Duration::from_secs(10);
const CLAUDE_WAIT: Duration = Duration::from_secs(15);
/// Claude Code's own rule (`proper-lockfile`, `stale: 1e4`): an older lock is abandoned.
const STALE: Duration = Duration::from_secs(10);
/// Longest we keep Claude's lock before the rename: well under its 10 s.
const HELD_MAX: Duration = Duration::from_secs(4);
const RETRIES: u32 = 3;
const SKIP_ADOPTED: &str = "already adopted";

const CLAUDE_NOTE: &str = "Claude Code locks this file while it saves, but sync_gate cannot fully exclude it: Claude may write without the lock under heavy contention, and when sync_gate finds the lock stale it goes ahead without it, so a setting Claude saved in the same instant, with or without its lock, would be lost.";
const CODEX_NOTE: &str =
    "Codex does not lock this file: a setting Codex saved in this same instant would be lost.";

fn note(a: Agent) -> &'static str {
    match a {
        Agent::Claude => CLAUDE_NOTE,
        Agent::Codex => CODEX_NOTE,
    }
}

fn seam(name: &str) -> Option<PathBuf> {
    if !cfg!(debug_assertions) {
        return None;
    }
    std::env::var_os(name).map(PathBuf::from)
}

/// Appends `<what> <p>` to `SYNC_GATE_TEST_ADOPT_TRACE` (the e2e tests read the order of steps).
fn trace(what: &str, p: &Path) {
    if let Some(t) = seam("SYNC_GATE_TEST_ADOPT_TRACE")
        && let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(t)
    {
        let _ = writeln!(f, "{what} {}", p.display());
    }
}

fn seam_ms(name: &str, default: Duration) -> Duration {
    seam(name)
        .and_then(|v| v.to_str()?.parse().ok())
        .map_or(default, Duration::from_millis)
}

fn fail(msg: &str) -> i32 {
    eprintln!("sync_gate: {msg}");
    1
}

/// `<path>` with `suffix` appended to its file name.
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_owned();
    name.push(suffix);
    path.with_file_name(name)
}

fn absolute(p: &Path) -> Result<PathBuf, String> {
    std::path::absolute(p).map_err(|e| format!("{}: {e}", p.display()))
}

struct Target {
    agent: Agent,
    path: PathBuf,
}

/// What Claude Code (Node's `os.homedir`) and Codex use as the home folder.
fn home() -> Result<PathBuf, String> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| format!("{var} is not set: pass --claude-config and --codex-config"))
}

fn targets(
    agent: AgentArg,
    claude: Option<&Path>,
    codex: Option<&Path>,
) -> Result<Vec<Target>, String> {
    let mut out = Vec::new();
    if agent.has(Agent::Claude) {
        let path = match claude {
            Some(p) => p.to_path_buf(),
            None => {
                // Claude then uses another file and another lock (S11): never the default in silence.
                if let Some(dir) = std::env::var_os("CLAUDE_CONFIG_DIR").filter(|d| !d.is_empty()) {
                    let dir = PathBuf::from(dir);
                    return Err(format!(
                        "CLAUDE_CONFIG_DIR is set ({}): pass --claude-config {}, or unset it",
                        dir.display(),
                        dir.join(".claude.json").display()
                    ));
                }
                home()?.join(".claude.json")
            }
        };
        out.push(Target {
            agent: Agent::Claude,
            path: absolute(&path)?,
        });
    }
    if agent.has(Agent::Codex) {
        let path = match codex {
            Some(p) => p.to_path_buf(),
            None => match std::env::var_os("CODEX_HOME").filter(|d| !d.is_empty()) {
                Some(h) => PathBuf::from(h).join("config.toml"),
                None => home()?.join(".codex").join("config.toml"),
            },
        };
        out.push(Target {
            agent: Agent::Codex,
            path: absolute(&path)?,
        });
    }
    Ok(out)
}

/// The file's text; `None` when it does not exist.
fn read_text(path: &Path) -> Result<Option<String>, String> {
    match fs::read(path) {
        Ok(b) => String::from_utf8(b)
            .map(Some)
            .map_err(|_| format!("{} is not UTF-8 text", path.display())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
    }
}

// ---- locks ----

#[derive(Debug, PartialEq, Eq)]
enum LockProbe {
    Taken,
    Busy,
    Stale,
    NotFolder,
}

/// One try at Claude Code's lock folder, the way `proper-lockfile` takes it (`mkdir`). An
/// existing one is never touched: stale (older than `stale` by its mtime) or busy.
fn probe_lock(lock: &Path, now: SystemTime, stale: Duration) -> io::Result<LockProbe> {
    match fs::create_dir(lock) {
        Ok(()) => return Ok(LockProbe::Taken),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let m = match fs::symlink_metadata(lock) {
        Ok(m) => m,
        // Released between the two calls: try again.
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(LockProbe::Busy),
        Err(e) => return Err(e),
    };
    if !m.is_dir() {
        return Ok(LockProbe::NotFolder);
    }
    let age = now.duration_since(m.modified()?).unwrap_or_default();
    Ok(if age > stale {
        LockProbe::Stale
    } else {
        LockProbe::Busy
    })
}

/// Step 2: `Some(when it was taken)`, or `None` when a stale lock is left as it is. sync_gate
/// never removes the folder: it expires by Claude's own rule (D10).
fn claude_lock(f: &Path) -> Result<Option<Instant>, String> {
    let lock = sibling(f, ".lock");
    let wait = seam_ms("SYNC_GATE_TEST_LOCK_WAIT_MS", CLAUDE_WAIT);
    let stale = seam_ms("SYNC_GATE_TEST_LOCK_STALE_MS", STALE);
    let start = Instant::now();
    loop {
        let t0 = Instant::now();
        let probe = probe_lock(&lock, SystemTime::now(), stale)
            .map_err(|e| format!("cannot take {}: {e}", lock.display()))?;
        match probe {
            LockProbe::Taken => return Ok(Some(t0)),
            LockProbe::Stale => {
                println!(
                    "{} is older than 10 s (abandoned by Claude Code's own rule); continuing without the lock, which is left as it is",
                    lock.display()
                );
                return Ok(None);
            }
            LockProbe::NotFolder => {
                return Err(format!(
                    "{} is not a folder: Claude Code's lock protocol seems to have changed; nothing was changed",
                    lock.display()
                ));
            }
            LockProbe::Busy if start.elapsed() >= wait => {
                return Err(format!(
                    "Claude Code is writing {} (lock {}); try again",
                    f.display(),
                    lock.display()
                ));
            }
            LockProbe::Busy => {
                if let Some(m) = seam("SYNC_GATE_TEST_LOCK_BUSY") {
                    let _ = fs::write(m, b"");
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// Step 0: one `adopt` or `restore` at a time (an OS lock, gone with the process).
fn sync_gate_lock(data_dir: &Path) -> Result<sync_gate_probe::FileLock, String> {
    // Folders this run creates (data_dir and ancestors), innermost first.
    let created: Vec<&Path> = data_dir
        .ancestors()
        .take_while(|d| !d.as_os_str().is_empty() && fs::symlink_metadata(d).is_err())
        .collect();
    sync_gate_probe::create_private_dir(data_dir)
        .map_err(|e| format!("cannot use {}: {e}", data_dir.display()))?;
    // Each new folder's name lives in its parent: sync those (first pre-existing ancestor down)
    // before anything is replaced, or a crash can lose the record's folder.
    for d in created.iter().rev() {
        sync_dir(d).map_err(|e| format!("cannot sync the parent of {}: {e}", d.display()))?;
        trace("durable-dir", d.parent().unwrap_or(d));
    }
    let path = data_dir.join(FG_LOCK);
    let wait = seam_ms("SYNC_GATE_TEST_LOCK_WAIT_MS", FG_WAIT);
    let start = Instant::now();
    loop {
        let mut o = fs::OpenOptions::new();
        o.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        let file = o
            .open(&path)
            .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
        match sync_gate_probe::try_lock(file, true) {
            Ok(Some(l)) => return Ok(l),
            Ok(None) if start.elapsed() < wait => thread::sleep(Duration::from_millis(50)),
            Ok(None) => return Err("another sync_gate mcp adopt or restore is running".into()),
            Err(e) => return Err(format!("cannot lock {}: {e}", path.display())),
        }
    }
}

// ---- files ----
//
// Durability, so a power loss after the agent file is replaced still finds its backup and the
// record that undoes it (both are durable before that replace):
// - Unix: every new file is fsynced, then its folder is fsynced; a rename is followed by an
//   fsync of the folder (POSIX: a name survives a crash once its folder is synced), and so is
//   the parent of every folder this run created (the data folder and its new ancestors). On
//   macOS these use `F_FULLFSYNC` (flushes the drive's own cache). Only when the file system
//   says it is not supported (ENOTSUP, EINVAL) does it fall back to `fsync` with one stderr
//   note: a reduced guarantee, the drive's cache may still hold the data. Any other error
//   (EIO, ENOSPC...) is returned and aborts before the agent file is replaced. Elsewhere
//   `fsync` already reaches the device.
// - Windows: a new file is created with FILE_FLAG_WRITE_THROUGH and flushed; a renamed file is
//   reopened and flushed. Per Microsoft's "File Caching" page, metadata changes (a creation, a
//   rename) reach the disk once the file is flushed or opened write-through. Documented, not
//   tested by pulling the power.

/// A symlink (Windows: also a junction). Other name-surrogate reparse points are caught by
/// `surrogate_meta`; non-surrogate ones (cloud placeholders) are ordinary files.
fn is_link(m: &fs::Metadata) -> bool {
    m.file_type().is_symlink()
}

#[cfg(any(windows, test))]
/// `IsReparseTagNameSurrogate`: the tag's bit 0x20000000 (symlink, mount point/junction...).
fn is_name_surrogate(tag: u32) -> bool {
    tag & 0x2000_0000 != 0
}

#[cfg(any(windows, test))]
#[derive(Debug, PartialEq)]
enum ReadPlan {
    Refuse,
    Direct,
    Reopen,
}

/// What to do with a file opened without following: attributes and reparse tag decide.
#[cfg(any(windows, test))]
fn read_plan(attrs: u32, tag: u32) -> ReadPlan {
    if attrs & 0x400 == 0 {
        ReadPlan::Direct
    } else if is_name_surrogate(tag) {
        ReadPlan::Refuse
    } else {
        ReadPlan::Reopen
    }
}

/// Volume serial number and 128-bit file id: the same file on the same volume.
#[cfg(any(windows, test))]
fn same_identity(a: (u64, [u8; 16]), b: (u64, [u8; 16])) -> bool {
    a == b
}

/// Windows: `p` (opened without following) is a name-surrogate reparse point. Unknown counts yes.
#[cfg(windows)]
fn surrogate_at(p: &Path) -> bool {
    let mut o = fs::OpenOptions::new();
    o.read(true);
    std::os::windows::fs::OpenOptionsExt::custom_flags(
        &mut o,
        windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
    );
    o.open(p).map_or(true, |f| surrogate_of(&f))
}

/// Windows: (attributes, reparse tag) of an open handle.
#[cfg(windows)]
fn tag_info(f: &fs::File) -> Option<(u32, u32)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_TAG_INFO, FileAttributeTagInfo, GetFileInformationByHandleEx,
    };
    let mut i = FILE_ATTRIBUTE_TAG_INFO {
        FileAttributes: 0,
        ReparseTag: 0,
    };
    // SAFETY: a valid handle and a buffer of the size passed.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            f.as_raw_handle() as _,
            FileAttributeTagInfo,
            (&raw mut i).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    };
    (ok != 0).then_some((i.FileAttributes, i.ReparseTag))
}

/// Windows: (volume serial number, 128-bit file id) of an open handle.
#[cfg(windows)]
pub(crate) fn identity(f: &fs::File) -> Option<(u64, [u8; 16])> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
    };
    let mut i = FILE_ID_INFO::default();
    // SAFETY: a valid handle and a buffer of the size passed.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            f.as_raw_handle() as _,
            FileIdInfo,
            (&raw mut i).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    };
    (ok != 0).then_some((i.VolumeSerialNumber, i.FileId.Identifier))
}

#[cfg(windows)]
fn surrogate_of(f: &fs::File) -> bool {
    tag_info(f).is_none_or(|(_, tag)| is_name_surrogate(tag))
}

/// Windows: a reparse point of the name-surrogate kind. Elsewhere: never.
fn surrogate_meta(m: &fs::Metadata, p: &Path) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        m.file_attributes() & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
            && surrogate_at(p)
    }
    #[cfg(not(windows))]
    {
        let _ = (m, p);
        false
    }
}

/// Step 1: `f` itself (not what a link points to) is a regular file.
fn regular(f: &Path) -> Result<(), String> {
    match fs::symlink_metadata(f) {
        Ok(m) if is_link(&m) || surrogate_meta(&m, f) => Err(format!(
            "{} is a link; nothing was changed (pass the file it points to)",
            f.display()
        )),
        Ok(m) if !m.is_file() => Err(format!("{} is not a regular file", f.display())),
        Ok(_) => Ok(()),
        Err(e) => Err(format!("cannot read {}: {e}", f.display())),
    }
}

/// `f`'s bytes, opened without following a link (Unix `O_NOFOLLOW`, Windows
/// FILE_FLAG_OPEN_REPARSE_POINT) and checked on the open handle: a file swapped for a link
/// while we waited for a lock is refused, never read through. Windows reads only from a handle
/// whose object was checked: the first one when `f` is no reparse point, else a second, normal
/// open (a cloud placeholder must be read through its filter) whose identity equals the first's.
fn read_regular(f: &Path) -> Result<Vec<u8>, String> {
    let mut o = fs::OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(
        &mut o,
        nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK,
    );
    #[cfg(windows)]
    std::os::windows::fs::OpenOptionsExt::custom_flags(
        &mut o,
        windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
    );
    let cannot = |e: io::Error| format!("cannot read {}: {e}", f.display());
    let refused = |e: Option<io::Error>| {
        regular(f).err().unwrap_or_else(|| match e {
            Some(e) => cannot(e),
            None => format!("{} is not a regular file", f.display()),
        })
    };
    // A link makes the open fail (ELOOP): `regular` says why.
    #[allow(unused_mut)]
    let mut file = o.open(f).map_err(|e| refused(Some(e)))?;
    let m = file.metadata().map_err(cannot)?;
    if is_link(&m) || !m.is_file() {
        return Err(refused(None));
    }
    #[cfg(target_os = "linux")]
    if has_acl(&file, c"system.posix_acl_access").map_err(cannot)? {
        return Err(format!(
            "{} has an access ACL (extended permissions); the backup and the new file would keep only its mode bits, which can let others read it: nothing was changed (remove the ACL with setfacl -b first, or edit the file by hand)",
            f.display()
        ));
    }
    // The backup and the new file are created in the same folder: a default ACL there would be
    // inherited by them and can grant someone who could not read the original.
    #[cfg(target_os = "linux")]
    {
        let dir = f
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let d = fs::File::open(dir).map_err(cannot)?;
        if has_acl(&d, c"system.posix_acl_default").map_err(cannot)? {
            return Err(format!(
                "{} has a default ACL (extended permissions); the backup and the new file would inherit it and could be readable by others: nothing was changed (remove it with setfacl -k first, or edit the file by hand)",
                dir.display()
            ));
        }
    }
    #[cfg(windows)]
    {
        // An unknown tag or identity refuses: nothing is read unchecked.
        let (attrs, tag) = tag_info(&file).ok_or_else(|| refused(None))?;
        match read_plan(attrs, tag) {
            ReadPlan::Direct => {}
            ReadPlan::Refuse => return Err(refused(None)),
            ReadPlan::Reopen => {
                let first = identity(&file).ok_or_else(|| refused(None))?;
                let second = fs::File::open(f).map_err(cannot)?;
                if identity(&second).is_none_or(|id| !same_identity(first, id)) {
                    return Err(format!(
                        "{} changed while it was being opened; nothing was changed",
                        f.display()
                    ));
                }
                // `file` (the first handle) stays open until the read ends, pinning the object.
                let mut b = Vec::new();
                (&second).read_to_end(&mut b).map_err(cannot)?;
                return Ok(b);
            }
        }
    }
    let mut b = Vec::new();
    file.read_to_end(&mut b).map_err(cannot)?;
    Ok(b)
}

/// Linux: whether the open file or folder has the POSIX ACL `name` (`system.posix_acl_access`:
/// its copies would get only the mode bits, whose group bits are then the ACL mask, wider than the
/// owning group's own entry; `system.posix_acl_default` on a folder: new files there inherit it).
/// shortcut: macOS ACLs are not checked (`libc` has no ACL API there); add when macOS ships.
#[cfg(target_os = "linux")]
fn has_acl(f: &fs::File, name: &std::ffi::CStr) -> io::Result<bool> {
    use std::os::fd::AsRawFd;
    // SAFETY: a size query (null buffer, length 0) on an open descriptor and a NUL-terminated name.
    let n = unsafe { nix::libc::fgetxattr(f.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if n >= 0 {
        return Ok(true);
    }
    let e = io::Error::last_os_error();
    match e.raw_os_error() {
        // No ACL, or a file system without ACLs.
        Some(nix::libc::ENODATA | nix::libc::EOPNOTSUPP) => Ok(false),
        _ => Err(e),
    }
}

/// Unix: fsyncs the folder that holds `p`, so `p`'s name (new or renamed) is durable.
#[cfg(unix)]
fn sync_dir(p: &Path) -> io::Result<()> {
    let dir = p
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    full_sync(&fs::File::open(dir)?)
}

/// What to do with the result of `F_FULLFSYNC`.
#[cfg(all(unix, any(target_os = "macos", test)))]
#[derive(Debug, PartialEq)]
enum Flush {
    Done,
    Fallback,
    Fail(nix::errno::Errno),
}

#[cfg(all(unix, any(target_os = "macos", test)))]
fn flush_outcome(r: Result<(), nix::errno::Errno>) -> Flush {
    use nix::errno::Errno;
    match r {
        Ok(()) => Flush::Done,
        Err(e) if e == Errno::ENOTSUP || e == Errno::EINVAL => Flush::Fallback,
        Err(e) => Flush::Fail(e),
    }
}

/// fsync; on macOS `F_FULLFSYNC` first (reaches the drive itself), `fsync` if that fails.
fn full_sync(f: &fs::File) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    match flush_outcome(nix::fcntl::fcntl(f, nix::fcntl::FcntlArg::F_FULLFSYNC).map(drop)) {
        Flush::Done => return Ok(()),
        Flush::Fallback => {
            static SAID: std::sync::Once = std::sync::Once::new();
            SAID.call_once(|| {
                eprintln!(
                    "note: this file system cannot flush the device cache (F_FULLFSYNC); using fsync, a reduced durability guarantee"
                );
            });
        }
        Flush::Fail(e) => return Err(e.into()),
    }
    f.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_: &Path) -> io::Result<()> {
    Ok(())
}

/// Makes the rename that just put `p` in place durable (see the top of this section).
fn sync_renamed(p: &Path) -> io::Result<()> {
    #[cfg(windows)]
    fs::OpenOptions::new().write(true).open(p)?.sync_all()?;
    sync_dir(p)?;
    trace("durable", p);
    Ok(())
}

/// `p`, which must not exist, opened for writing and never looser than `like`: Unix 0600 (its
/// mode is copied from `like` only after it is written); Windows with `like`'s DACL from its
/// creation, write-through, shared with no one.
fn create_like(p: &Path, like: &Path) -> io::Result<fs::File> {
    #[cfg(windows)]
    return win::create_like(p, like);
    #[cfg(not(windows))]
    {
        let _ = like;
        let mut o = fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        o.open(p)
    }
}

#[cfg(windows)]
mod win {
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use std::path::Path;
    use windows_sys::Win32::Foundation::{
        ERROR_INSUFFICIENT_BUFFER, GENERIC_WRITE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetFileSecurityW, GetSecurityDescriptorControl,
        SE_DACL_AUTO_INHERIT_REQ, SE_DACL_AUTO_INHERITED, SECURITY_ATTRIBUTES,
        SetKernelObjectSecurity, SetSecurityDescriptorControl,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_WRITE_THROUGH, WRITE_DAC,
    };

    fn wide(p: &Path) -> Vec<u16> {
        p.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    /// `like`'s DACL, as the self-relative security descriptor Windows hands out (8-aligned
    /// buffer); `None` when `like` does not exist.
    fn dacl_of(like: &Path) -> io::Result<Option<Vec<u64>>> {
        let name = wide(like);
        let mut need = 0u32;
        // SAFETY: a null buffer of length 0 only asks for the size; `name` ends with NUL.
        let ok = unsafe {
            GetFileSecurityW(
                name.as_ptr(),
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                0,
                &mut need,
            )
        };
        if ok == 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::NotFound {
                return Ok(None);
            }
            if e.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
                return Err(e);
            }
        }
        let mut sd = vec![0u64; (need as usize).div_ceil(8)];
        // SAFETY: `sd` holds at least `need` bytes.
        let ok = unsafe {
            GetFileSecurityW(
                name.as_ptr(),
                DACL_SECURITY_INFORMATION,
                sd.as_mut_ptr().cast(),
                need,
                &mut need,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Some(sd))
    }

    pub(super) fn create_like(p: &Path, like: &Path) -> io::Result<std::fs::File> {
        let mut sd = dacl_of(like)?;
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd
                .as_mut()
                .map_or(std::ptr::null_mut(), |s| s.as_mut_ptr().cast()),
            bInheritHandle: 0,
        };
        let name = wide(p);
        // SAFETY: `name` ends with NUL; `sa` and the descriptor it points to outlive the call.
        let h = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_WRITE | WRITE_DAC,
                0,
                &sa,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
                std::ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a valid handle that nothing else owns.
        let file = unsafe { std::fs::File::from_raw_handle(h) };
        if let Some(sd) = sd.as_mut()
            && let Err(e) = keep_auto_inherited(h, sd.as_mut_ptr().cast())
        {
            drop(file);
            let _ = std::fs::remove_file(p);
            return Err(e);
        }
        Ok(file)
    }

    /// The creation copies `like`'s ACEs exactly but drops its "auto-inherited" flag; setting
    /// the same DACL again with SE_DACL_AUTO_INHERIT_REQ puts the flag back (the ACEs marked
    /// inherited are the ones the file already has), still before any byte is written.
    fn keep_auto_inherited(
        h: windows_sys::Win32::Foundation::HANDLE,
        sd: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
    ) -> io::Result<()> {
        let (mut control, mut revision) = (0u16, 0u32);
        // SAFETY: `sd` is the valid descriptor `dacl_of` returned; `h` is open with WRITE_DAC.
        let ok = unsafe {
            GetSecurityDescriptorControl(sd, &mut control, &mut revision) != 0
                && (control & SE_DACL_AUTO_INHERITED == 0
                    || SetSecurityDescriptorControl(
                        sd,
                        SE_DACL_AUTO_INHERIT_REQ,
                        SE_DACL_AUTO_INHERIT_REQ,
                    ) != 0
                        && SetKernelObjectSecurity(h, DACL_SECURITY_INFORMATION, sd) != 0)
        };
        if ok {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

/// A new file with `bytes`, made exclusively, never looser than `like` (when it exists; see
/// `create_like`), then given `like`'s permissions and made durable. Removed if anything after
/// its creation fails.
fn write_new(p: &Path, bytes: &[u8], like: &Path) -> io::Result<()> {
    let mut file = create_like(p, like)?;
    let done = file.write_all(bytes).and_then(|()| full_sync(&file));
    drop(file);
    let done = done
        .and_then(|()| match fs::metadata(like) {
            Ok(m) => fs::set_permissions(p, m.permissions()),
            Err(_) => Ok(()),
        })
        .and_then(|()| sync_dir(p));
    if done.is_err() {
        let _ = fs::remove_file(p);
    } else {
        trace("durable", p);
    }
    done
}

/// A fresh `<name>.sync_gate-tmp-<pid>-<n>` beside `path` holding `bytes`.
fn write_temp(path: &Path, bytes: &[u8]) -> io::Result<PathBuf> {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    for _ in 0..16 {
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp = sibling(path, &format!(".sync_gate-tmp-{}-{n}", std::process::id()));
        match write_new(&tmp, bytes, path) {
            Ok(()) => return Ok(tmp),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("no free temporary name beside {}", path.display()),
    ))
}

/// Windows: an antivirus may hold the target for a moment. `deadline` (Claude's lock budget) is
/// checked before every try: past it, `TimedOut` and nothing is renamed.
fn rename_retry(from: &Path, to: &Path, deadline: Option<Instant>) -> io::Result<()> {
    let mut tries = 0;
    loop {
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(io::ErrorKind::TimedOut.into());
        }
        match fs::rename(from, to) {
            Err(e) if cfg!(windows) && e.kind() == io::ErrorKind::PermissionDenied && tries < 5 => {
                tries += 1;
                thread::sleep(Duration::from_millis(100));
            }
            r => return r,
        }
    }
}

/// Replaces a file another program owns: temp beside it with the same permissions, fsync,
/// rename (Windows: retried 5 × 100 ms on PermissionDenied, for antivirus), made durable, never
/// changing the folder.
fn replace_foreign(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = write_temp(path, bytes)?;
    let r = rename_retry(&tmp, path, None);
    if r.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    r.and_then(|()| sync_renamed(path))
}

/// Step 4: `<F>.sync_gate-<unix_secs>-<pid>.bak` (a retry adds `-<n>`), with the permissions of `F`.
fn write_backup(f: &Path, bytes: &[u8], attempt: u32) -> io::Result<PathBuf> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let pid = std::process::id();
    let suffix = match attempt {
        0 => format!(".sync_gate-{secs}-{pid}.bak"),
        n => format!(".sync_gate-{secs}-{pid}-{n}.bak"),
    };
    let p = sibling(f, &suffix);
    write_new(&p, bytes, f)?;
    Ok(p)
}

/// Copies `src` over `dst` in place, as a writer that ignores every lock would (test seams).
fn overwrite(src: &Path, dst: &Path) {
    if let Ok(b) = fs::read(src) {
        let _ = fs::write(dst, b);
    }
}

/// How long the test held us in the window: its time, not the lock's (zero in release builds).
fn pause_seam() -> Duration {
    let Some(marker) = seam("SYNC_GATE_TEST_ADOPT_PAUSE") else {
        return Duration::ZERO;
    };
    let go = sibling(&marker, ".go");
    let _ = fs::write(&marker, b"");
    let start = Instant::now();
    while !go.exists() && start.elapsed() < Duration::from_secs(30) {
        thread::sleep(Duration::from_millis(20));
    }
    start.elapsed()
}

// ---- the transaction ----

/// What `adopt` and `restore` plug into [`transact`].
trait Job {
    /// Step 3: the new text for the text just read; `None` when nothing changes.
    fn prepare(&mut self, text: &str) -> Option<String>;
    /// Steps 5 and 6, after the backup.
    fn commit(&mut self) -> Result<(), String> {
        Ok(())
    }
    /// Takes back what `commit` recorded.
    fn undo(&mut self) {}
}

enum Outcome {
    Unchanged,
    /// `intact`: the file reread after the rename is the text we wrote.
    Replaced {
        backup: PathBuf,
        intact: bool,
    },
}

/// Drops the temporary file and what `commit` recorded; the agent file was never touched.
fn give_up(job: &mut dyn Job, tmp: Option<&Path>, why: String) -> Result<Outcome, String> {
    if let Some(tmp) = tmp {
        let _ = fs::remove_file(tmp);
    }
    job.undo();
    Err(why)
}

/// Steps 1 to 11 for one agent file. Any failure leaves the file as it was.
fn transact(t: &Target, job: &mut dyn Job) -> Result<Outcome, String> {
    let f = &t.path;
    regular(f)?;
    let held = match t.agent {
        Agent::Claude => claude_lock(f)?,
        Agent::Codex => None,
    };
    let mut before_check = seam("SYNC_GATE_TEST_ADOPT_BEFORE_CHECK");
    let mut attempt = 0;
    loop {
        // Read without following a link: the file may have been swapped while we waited.
        let a = read_regular(f)?;
        let text =
            std::str::from_utf8(&a).map_err(|_| format!("{} is not UTF-8 text", f.display()))?;
        let Some(b) = job.prepare(text) else {
            return Ok(Outcome::Unchanged);
        };
        let backup = write_backup(f, &a, attempt)
            .map_err(|e| format!("cannot write a backup of {}: {e}", f.display()))?;
        println!("backup of {}: {}", f.display(), backup.display());
        job.commit()?;
        let tmp = match write_temp(f, b.as_bytes()) {
            Ok(tmp) => tmp,
            Err(e) => {
                return give_up(
                    job,
                    None,
                    format!("cannot write beside {}: {e}", f.display()),
                );
            }
        };
        if let Some(src) = before_check.take() {
            overwrite(&src, f);
        }
        let now = match read_regular(f) {
            Ok(b) => b,
            Err(m) => return give_up(job, Some(&tmp), m),
        };
        if now != a {
            if attempt == RETRIES {
                return give_up(
                    job,
                    Some(&tmp),
                    format!("{} kept changing; nothing was changed in it", f.display()),
                );
            }
            let _ = fs::remove_file(&tmp);
            job.undo();
            attempt += 1;
            continue;
        }
        let paused = pause_seam();
        if let Some(src) = seam("SYNC_GATE_TEST_ADOPT_WINDOW") {
            overwrite(&src, f);
        }
        // No identity check: a lock retaken within 4 s is within the lesser guarantee (D10).
        let deadline = held.map(|t0| t0 + HELD_MAX + paused);
        if let Err(e) = rename_retry(&tmp, f, deadline) {
            let why = if e.kind() == io::ErrorKind::TimedOut {
                format!(
                    "lock for {} was held too long (it expires at 10 s); nothing was changed in it",
                    f.display()
                )
            } else {
                format!(
                    "cannot replace {}: {e}; nothing was changed in it",
                    f.display()
                )
            };
            return give_up(job, Some(&tmp), why);
        }
        trace("replaced", f);
        let intact = read_regular(f).ok().as_deref() == Some(b.as_bytes());
        return Ok(Outcome::Replaced { backup, intact });
    }
}

/// Step 11: the lesser guarantee, or the warning that another program wrote right after us.
fn report(t: &Target, backup: &Path, intact: bool) {
    if intact {
        println!("updated {}", t.path.display());
        println!("{} Backup: {}", note(t.agent), backup.display());
    } else {
        eprintln!(
            "sync_gate: warning: another program wrote {} right after sync_gate replaced it; check it. Backup: {}",
            t.path.display(),
            backup.display()
        );
    }
}

/// stdout for `Ok`, stderr for `Err`.
fn show(notes: &[Result<String, String>]) {
    for n in notes {
        match n {
            Ok(m) => println!("{m}"),
            Err(m) => eprintln!("sync_gate: {m}"),
        }
    }
}

fn save_record(data_dir: &Path, entries: Vec<AdoptedEntry>) -> Result<(), String> {
    let rec = Adopted {
        version: 1,
        entries,
    };
    let bytes = serde_json::to_vec_pretty(&rec).map_err(|e| e.to_string())?;
    let path = data_dir.join(RECORD);
    sync_gate_probe::write_atomic(&path, &bytes)
        .and_then(|()| sync_renamed(&path))
        .map_err(|e| format!("cannot write the adoption record: {e}"))
}

fn same_key(a: &AdoptedEntry, b: &AdoptedEntry) -> bool {
    a.agent == b.agent && a.file == b.file && a.server == b.server
}

// ---- adopt ----

/// What the sync_gate config gets for a server: its original launch.
#[derive(Clone)]
struct Launch {
    command: String,
    args: Vec<String>,
    env_from: Vec<String>,
    cwd: Option<String>,
}

fn launch_of(f: &Found, any_folder: bool) -> Launch {
    let mut env_from = f.env_keys.clone();
    env_from.sort();
    env_from.dedup();
    Launch {
        command: f.command.clone(),
        args: f.args.clone().unwrap_or_default(),
        env_from,
        cwd: f
            .cwd
            .clone()
            .or_else(|| (!any_folder).then(|| "inherit".to_string())),
    }
}

/// The same program in the same place with the same variables (mode and tuning fields aside).
/// Adopt never writes a fixed `env`, so a table with one launches something else.
fn same_launch(s: &McpServer, l: &Launch) -> bool {
    let mut env_from = s.env_from.clone();
    env_from.sort();
    env_from.dedup();
    s.command == l.command
        && s.args == l.args
        && s.cwd == l.cwd
        && env_from == l.env_from
        && s.env.is_empty()
}

/// Another agent file's entry for `name` whose original launch is not `f`'s: `find_original`
/// assumes one original per name.
fn recorded_elsewhere<'r>(rec: &'r Adopted, t: &Target, f: &Found) -> Option<&'r AdoptedEntry> {
    let args = f.args.as_deref().unwrap_or_default();
    rec.entries.iter().find(|e| {
        e.server == f.server
            && !(e.agent == t.agent && e.file == t.path)
            && (e.original_command != f.command
                || e.original_args.as_deref().unwrap_or_default() != args)
    })
}

fn conflict(name: &str, cfg_path: &Path) -> String {
    format!(
        "{name} not adopted: {} already has [mcp.{name}] with another launch (another agent's server of the same name?); rename one, or edit that table",
        cfg_path.display()
    )
}

fn load_sync_gate_config(path: &Path) -> Result<(String, Config), String> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    // The parser's text quotes the file (an `env` value): a category and a position only.
    let cfg = Config::from_toml(&text)
        .map_err(|e| format!("{}: {}", path.display(), ConfigLoadError::parse(&text, &e)))?;
    Ok((text, cfg))
}

struct Plan {
    text: String,
    entries: Vec<AdoptedEntry>,
    tables: Vec<(String, Launch)>,
    notes: Vec<Result<String, String>>,
    ok: bool,
}

/// Step 3 of `adopt` for one file: the edited text, the record entries and the config tables.
/// `cfg` gets the planned tables, so a later agent's same name is seen as a conflict.
#[allow(clippy::too_many_arguments)]
fn plan(
    t: &Target,
    text: &str,
    names: &[String],
    cfg: &mut Config,
    cfg_path: &Path,
    rec: &Adopted,
    any_folder: bool,
    exe: &str,
) -> Plan {
    let label = t.agent.label();
    let mut p = Plan {
        text: text.to_string(),
        entries: Vec::new(),
        tables: Vec::new(),
        notes: Vec::new(),
        ok: true,
    };
    let found = match servers(t.agent.format(), text) {
        Ok(f) => f,
        Err(e) => {
            p.notes.push(Err(format!("{}: {e}", t.path.display())));
            p.ok = false;
            return p;
        }
    };
    for name in names {
        let Some(f) = found.iter().find(|f| f.server == *name) else {
            p.notes.push(Err(format!(
                "{label}: {name} is no longer in {}",
                t.path.display()
            )));
            p.ok = false;
            continue;
        };
        match f.skip.as_deref() {
            Some(SKIP_ADOPTED) => {
                p.notes
                    .push(Ok(format!("{label}: {name} is already adopted")));
                continue;
            }
            Some(why) => {
                p.notes
                    .push(Err(format!("{label}: {name} not adopted: {why}")));
                p.ok = false;
                continue;
            }
            None => {}
        }
        let l = launch_of(f, any_folder);
        if cfg.mcp.get(name).is_some_and(|s| !same_launch(s, &l)) {
            p.notes
                .push(Err(format!("{label}: {}", conflict(name, cfg_path))));
            p.ok = false;
            continue;
        }
        if let Some(e) = recorded_elsewhere(rec, t, f) {
            p.notes.push(Err(format!(
                "{label}: {name} not adopted: the adoption record has {name} from {} ({}) with another launch; restore that one first, or rename one",
                e.agent.label(),
                e.file.display()
            )));
            p.ok = false;
            continue;
        }
        let args = vec!["mcp".to_string(), "connect".to_string(), name.clone()];
        match set_launch(t.agent.format(), &p.text, name, exe, &args) {
            Ok(e) => {
                p.entries.push(AdoptedEntry {
                    agent: t.agent,
                    file: t.path.clone(),
                    server: name.clone(),
                    original: e.original,
                    original_command: f.command.clone(),
                    original_args: f.args.clone(),
                    adopted_command: exe.to_string(),
                    adopted_args: args,
                    inserted_args: e.inserted_args,
                });
                p.text = e.text;
                cfg.mcp.insert(
                    name.clone(),
                    McpServer {
                        command: l.command.clone(),
                        args: l.args.clone(),
                        env_from: l.env_from.clone(),
                        cwd: l.cwd.clone(),
                        ..McpServer::default()
                    },
                );
                p.tables.push((name.clone(), l));
            }
            Err(e) => {
                p.notes
                    .push(Err(format!("{label}: {name} not adopted: {e}")));
                p.ok = false;
            }
        }
    }
    p
}

/// Step 5: appends the missing `[mcp.<name>]` tables, by `replace_foreign` (F29).
fn add_tables(cfg_path: &Path, tables: &[(String, Launch)]) -> Result<(), String> {
    let (text, cfg) = load_sync_gate_config(cfg_path)?;
    let mut add = String::new();
    for (name, l) in tables {
        match cfg.mcp.get(name) {
            Some(s) if same_launch(s, l) => {}
            Some(_) => return Err(conflict(name, cfg_path)),
            None => add.push_str(&mcp_table(
                name,
                &l.command,
                &l.args,
                &l.env_from,
                l.cwd.as_deref(),
            )),
        }
    }
    if add.is_empty() {
        return Ok(());
    }
    let mut new = text;
    if !new.is_empty() && !new.ends_with('\n') {
        new.push('\n');
    }
    new.push_str(&add);
    let check = Config::from_toml(&new).map_err(|e| {
        format!(
            "adding to {} would make it invalid ({}); nothing was changed",
            cfg_path.display(),
            ConfigLoadError::parse(&new, &e)
        )
    })?;
    if tables
        .iter()
        .any(|(n, l)| !check.mcp.get(n).is_some_and(|s| same_launch(s, l)))
    {
        return Err(format!(
            "the tables added to {} do not read back as written; nothing was changed",
            cfg_path.display()
        ));
    }
    if let Some(dir) = cfg_path.parent().filter(|d| !d.as_os_str().is_empty())
        && !dir.exists()
    {
        let mut b = fs::DirBuilder::new();
        b.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
        b.create(dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    replace_foreign(cfg_path, new.as_bytes())
        .map_err(|e| format!("cannot write {}: {e}", cfg_path.display()))
}

struct AdoptJob<'a> {
    t: &'a Target,
    names: Vec<String>,
    any_folder: bool,
    exe: &'a str,
    cfg_path: &'a Path,
    data_dir: &'a Path,
    plan: Option<Plan>,
    before: Option<Vec<AdoptedEntry>>,
}

impl Job for AdoptJob<'_> {
    fn prepare(&mut self, text: &str) -> Option<String> {
        let read = load_sync_gate_config(self.cfg_path).and_then(|(_, cfg)| {
            read_adopted(self.data_dir)
                .map(|rec| (cfg, rec))
                .map_err(|e| format!("refusing the adoption record: {e}"))
        });
        let p = match read {
            Ok((mut cfg, rec)) => plan(
                self.t,
                text,
                &self.names,
                &mut cfg,
                self.cfg_path,
                &rec,
                self.any_folder,
                self.exe,
            ),
            Err(e) => Plan {
                text: text.to_string(),
                entries: Vec::new(),
                tables: Vec::new(),
                notes: vec![Err(e)],
                ok: false,
            },
        };
        let out = (!p.entries.is_empty()).then(|| p.text.clone());
        self.plan = Some(p);
        out
    }

    fn commit(&mut self) -> Result<(), String> {
        let p = self.plan.as_ref().expect("prepared");
        add_tables(self.cfg_path, &p.tables)?;
        let rec = read_adopted(self.data_dir)
            .map_err(|e| format!("refusing the adoption record: {e}"))?;
        let before = rec.entries.clone();
        let mut entries: Vec<AdoptedEntry> = rec
            .entries
            .into_iter()
            .filter(|e| !p.entries.iter().any(|n| same_key(e, n)))
            .collect();
        entries.extend(p.entries.iter().cloned());
        save_record(self.data_dir, entries)?;
        self.before = Some(before);
        Ok(())
    }

    fn undo(&mut self) {
        if let Some(b) = self.before.take() {
            let _ = save_record(self.data_dir, b);
        }
    }
}

/// One agent file as read before any lock: what `adopt` lists and plans from.
struct Scan {
    t: Target,
    text: String,
    found: Vec<Found>,
}

fn list(scans: &[Scan]) {
    for s in scans {
        println!("{} ({}):", s.t.agent.label(), s.t.path.display());
        if s.found.is_empty() {
            println!("  no stdio servers");
        }
        for f in &s.found {
            match &f.skip {
                None => println!("  {}: can adopt ({})", f.server, f.command),
                Some(why) => println!("  {}: skipped: {why}", f.server),
            }
        }
    }
    println!("Adopt with: sync_gate mcp adopt <server>...");
}

pub fn adopt(o: &AdoptOptions) -> i32 {
    let targets = match targets(
        o.agent,
        o.claude_config.as_deref(),
        o.codex_config.as_deref(),
    ) {
        Ok(t) => t,
        Err(m) => return fail(&m),
    };
    let mut failed = false;
    let mut scans = Vec::new();
    for t in targets {
        let read = read_text(&t.path).and_then(|text| match text {
            None => Ok(None),
            Some(text) => servers(t.agent.format(), &text)
                .map(|found| Some((text, found)))
                .map_err(|e| format!("{}: {e}", t.path.display())),
        });
        match read {
            Ok(Some((text, found))) => scans.push(Scan { t, text, found }),
            Ok(None) => println!("{}: {} not found", t.agent.label(), t.path.display()),
            Err(m) => {
                fail(&m);
                failed = true;
            }
        }
    }
    if o.servers.is_empty() {
        list(&scans);
        return i32::from(failed);
    }
    let unknown: Vec<&String> = o
        .servers
        .iter()
        .filter(|n| {
            !scans
                .iter()
                .any(|s| s.found.iter().any(|f| f.server == **n))
        })
        .collect();
    if !unknown.is_empty() {
        for n in unknown {
            eprintln!("sync_gate: no agent config has a server named {n}; nothing was changed");
        }
        return 2;
    }
    let cfg_path = o
        .sync_gate_config
        .clone()
        .or_else(sync_gate_shim::config_path);
    let data_dir = o.data_dir.clone().or_else(sync_gate_core::data_dir);
    let (Some(cfg_path), Some(data_dir)) = (cfg_path, data_dir) else {
        return fail(
            "no per-user config or data folder (set SYNC_GATE_CONFIG and SYNC_GATE_DATA_DIR)",
        );
    };
    let exe = match std::env::current_exe() {
        Ok(p) => p.to_string_lossy().into_owned(),
        Err(e) => return fail(&format!("cannot find this program's path: {e}")),
    };
    let mut cfg = match load_sync_gate_config(&cfg_path) {
        Ok((_, c)) => c,
        Err(m) => return fail(&m),
    };
    let rec = match read_adopted(&data_dir) {
        Ok(r) => r,
        Err(e) => {
            return fail(&format!(
                "refusing the adoption record: {e}; nothing was changed"
            ));
        }
    };
    let mut lock = None;
    for s in &scans {
        let names: Vec<String> = o
            .servers
            .iter()
            .filter(|n| s.found.iter().any(|f| f.server == **n))
            .cloned()
            .collect();
        if names.is_empty() {
            continue;
        }
        // Planned on what was read first: a file with nothing to adopt is never locked.
        let p = plan(
            &s.t,
            &s.text,
            &names,
            &mut cfg,
            &cfg_path,
            &rec,
            o.any_folder,
            &exe,
        );
        if o.dry_run || p.entries.is_empty() {
            show(&p.notes);
            failed |= !p.ok;
            if o.dry_run {
                dry_run_report(&s.t, &p, &cfg_path);
            }
            continue;
        }
        if lock.is_none() {
            match sync_gate_lock(&data_dir) {
                Ok(l) => lock = Some(l),
                Err(m) => return fail(&m),
            }
            if let Err(e) = read_adopted(&data_dir) {
                return fail(&format!(
                    "refusing the adoption record: {e}; nothing was changed"
                ));
            }
        }
        let mut job = AdoptJob {
            t: &s.t,
            names,
            any_folder: o.any_folder,
            exe: &exe,
            cfg_path: &cfg_path,
            data_dir: &data_dir,
            plan: None,
            before: None,
        };
        let r = transact(&s.t, &mut job);
        if let Some(p) = &job.plan {
            show(&p.notes);
            failed |= !p.ok;
        }
        match r {
            Ok(Outcome::Unchanged) => {}
            Ok(Outcome::Replaced { backup, intact }) => {
                for e in job.plan.iter().flat_map(|p| &p.entries) {
                    println!("adopted {} in {}", e.server, s.t.path.display());
                }
                report(&s.t, &backup, intact);
                if intact {
                    println!(
                        "Restart your {} sessions to use the hub. sync_gated picks up new servers on their first connection.",
                        s.t.agent.label()
                    );
                }
            }
            Err(m) => {
                fail(&m);
                failed = true;
            }
        }
    }
    i32::from(failed)
}

/// Names only: an argument or env value may be a credential the D11 heuristic missed.
fn dry_run_report(t: &Target, p: &Plan, cfg_path: &Path) {
    for e in &p.entries {
        println!(
            "would adopt {} in {}: command and args would point at the hub",
            e.server,
            t.path.display()
        );
    }
    for (name, l) in &p.tables {
        let cwd = if l.cwd.is_some() { ", cwd" } else { "" };
        println!(
            "would add [mcp.{name}] to {}: command, args, env_from{cwd}, mode",
            cfg_path.display()
        );
    }
}

// ---- restore ----

struct RestoreJob {
    entries: Vec<AdoptedEntry>,
    done: Vec<AdoptedEntry>,
    dropped: Vec<AdoptedEntry>,
    notes: Vec<Result<String, String>>,
    failed: bool,
}

impl Job for RestoreJob {
    fn prepare(&mut self, text: &str) -> Option<String> {
        self.done.clear();
        self.dropped.clear();
        self.notes.clear();
        self.failed = false;
        let mut out = text.to_string();
        for e in &self.entries {
            let label = e.agent.label();
            let r = restore_launch(
                e.agent.format(),
                &out,
                &e.server,
                (&e.adopted_command, &e.adopted_args),
                &e.original,
                (&e.original_command, e.original_args.as_deref()),
                e.inserted_args,
            );
            match r {
                Ok(Restored::Done(t)) => {
                    out = t;
                    self.done.push(e.clone());
                }
                Ok(Restored::Gone) => {
                    self.notes.push(Ok(format!(
                        "{label}: {} is no longer in {}; dropped from the record",
                        e.server,
                        e.file.display()
                    )));
                    self.dropped.push(e.clone());
                }
                Ok(Restored::AlreadyOriginal) => {
                    self.notes.push(Ok(format!(
                        "{label}: {} already has its original launch; dropped from the record",
                        e.server
                    )));
                    self.dropped.push(e.clone());
                }
                Ok(Restored::Changed) => self.notes.push(Ok(format!(
                    "{label}: {}: changed since adopt; left as is",
                    e.server
                ))),
                Err(m) => {
                    self.notes
                        .push(Err(format!("{label}: {} not restored: {m}", e.server)));
                    self.failed = true;
                }
            }
        }
        (!self.done.is_empty()).then_some(out)
    }
}

pub fn restore(o: &RestoreOptions) -> i32 {
    let Some(data_dir) = o.data_dir.clone().or_else(sync_gate_core::data_dir) else {
        return fail("no per-user data folder (set SYNC_GATE_DATA_DIR)");
    };
    let explicit = |a: Agent| match a {
        Agent::Claude => o.claude_config.as_deref(),
        Agent::Codex => o.codex_config.as_deref(),
    };
    let mut paths = Vec::new();
    for a in [Agent::Claude, Agent::Codex] {
        match explicit(a).map(absolute).transpose() {
            Ok(p) => paths.push((a, p)),
            Err(m) => return fail(&m),
        }
    }
    let selected = |e: &AdoptedEntry| {
        o.agent.has(e.agent)
            && (o.servers.is_empty() || o.servers.contains(&e.server))
            && paths.iter().all(|(a, p)| {
                *a != e.agent
                    || p.as_ref()
                        .is_none_or(|p| crate::shims::same_file(p, &e.file))
            })
    };
    let refused = |e: io::Error| {
        fail(&format!(
            "refusing the adoption record: {e}; nothing was changed"
        ))
    };
    let rec = match read_adopted(&data_dir) {
        Ok(r) => r,
        Err(e) => return refused(e),
    };
    let unknown: Vec<&String> = o
        .servers
        .iter()
        .filter(|n| !rec.entries.iter().any(|e| selected(e) && e.server == **n))
        .collect();
    if !unknown.is_empty() {
        for n in unknown {
            eprintln!("sync_gate: no adoption recorded for {n}; nothing was changed");
        }
        return 2;
    }
    if !rec.entries.iter().any(selected) {
        println!("nothing to restore");
        return 0;
    }
    let _lock = match sync_gate_lock(&data_dir) {
        Ok(l) => l,
        Err(m) => return fail(&m),
    };
    // Again under the lock: what we act on is what no other adopt or restore is changing.
    let mut rec = match read_adopted(&data_dir) {
        Ok(r) => r,
        Err(e) => return refused(e),
    };
    let mut files: Vec<(Agent, PathBuf)> = Vec::new();
    for e in rec.entries.iter().filter(|e| selected(e)) {
        if !files.iter().any(|(a, f)| *a == e.agent && *f == e.file) {
            files.push((e.agent, e.file.clone()));
        }
    }
    let mut failed = false;
    for (agent, file) in files {
        let t = Target { agent, path: file };
        let mut job = RestoreJob {
            entries: rec
                .entries
                .iter()
                .filter(|e| selected(e) && e.agent == agent && e.file == t.path)
                .cloned()
                .collect(),
            done: Vec::new(),
            dropped: Vec::new(),
            notes: Vec::new(),
            failed: false,
        };
        let r = transact(&t, &mut job);
        show(&job.notes);
        failed |= job.failed;
        let mut gone = Vec::new();
        match r {
            Ok(Outcome::Unchanged) => gone = job.dropped,
            Ok(Outcome::Replaced { backup, intact }) => {
                for e in &job.done {
                    println!("restored {} in {}", e.server, t.path.display());
                }
                report(&t, &backup, intact);
                gone = job.dropped;
                // A file another program wrote right after us keeps its entries: the next
                // restore sees what it holds.
                if intact {
                    gone.extend(job.done);
                }
            }
            Err(m) => {
                fail(&m);
                failed = true;
            }
        }
        if !gone.is_empty() {
            rec.entries.retain(|e| !gone.contains(e));
            if let Err(m) = save_record(&data_dir, rec.entries.clone()) {
                {
                    fail(&m);
                    failed = true;
                };
            }
        }
    }
    if o.strict {
        let mut left = false;
        for e in rec.entries.iter().filter(|e| selected(e)) {
            println!(
                "still adopted: {} {} in {} (launches {})",
                e.agent.label(),
                e.server,
                e.file.display(),
                e.adopted_command
            );
            left = true;
        }
        if left && !failed {
            return 3;
        }
    }
    i32::from(failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_name_surrogate_tags_are_refused() {
        assert!(is_name_surrogate(0xA000_000C), "symlink");
        assert!(is_name_surrogate(0xA000_0003), "mount point");
        assert!(!is_name_surrogate(0x9000_001A), "cloud placeholder");
        assert!(!is_name_surrogate(0));
    }

    #[test]
    fn read_plan_decision_table() {
        const RP: u32 = 0x400;
        assert_eq!(read_plan(0x20, 0), ReadPlan::Direct, "plain file");
        assert_eq!(read_plan(RP, 0xA000_000C), ReadPlan::Refuse, "symlink");
        assert_eq!(read_plan(RP, 0xA000_0003), ReadPlan::Refuse, "junction");
        assert_eq!(read_plan(RP | 0x20, 0x9000_001A), ReadPlan::Reopen, "cloud");
    }

    #[test]
    fn identity_needs_volume_and_file_id() {
        let a = (7u64, [1u8; 16]);
        assert!(same_identity(a, (7, [1; 16])));
        assert!(!same_identity(a, (8, [1; 16])), "other volume");
        let mut id = [1u8; 16];
        id[15] = 2;
        assert!(!same_identity(a, (7, id)), "other file, high bytes differ");
    }

    #[cfg(unix)]
    #[test]
    fn full_fsync_only_falls_back_when_unsupported() {
        use nix::errno::Errno;
        assert_eq!(flush_outcome(Ok(())), Flush::Done);
        assert_eq!(flush_outcome(Err(Errno::ENOTSUP)), Flush::Fallback);
        assert_eq!(flush_outcome(Err(Errno::EINVAL)), Flush::Fallback);
        assert_eq!(flush_outcome(Err(Errno::EIO)), Flush::Fail(Errno::EIO));
        assert_eq!(
            flush_outcome(Err(Errno::ENOSPC)),
            Flush::Fail(Errno::ENOSPC)
        );
    }

    #[test]
    fn lock_is_stale_only_after_10_seconds_of_mtime() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("fg-adopt-lock-{}-{n}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        // Claude's lock folder, with something of its own inside.
        let lock = dir.join("f.json.lock");
        fs::create_dir(&lock).unwrap();
        fs::write(lock.join("theirs"), b"x").unwrap();
        let m = fs::metadata(&lock).unwrap().modified().unwrap();
        let at = |secs| probe_lock(&lock, m + Duration::from_secs(secs), STALE).unwrap();
        assert_eq!(at(9), LockProbe::Busy);
        assert_eq!(at(11), LockProbe::Stale);
        // Neither probe took, changed or removed it.
        assert!(lock.join("theirs").is_file());
        assert_eq!(fs::metadata(&lock).unwrap().modified().unwrap(), m);
        // A free one is taken.
        let free = dir.join("g.json.lock");
        let taken = probe_lock(&free, SystemTime::now(), STALE).unwrap();
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(taken, LockProbe::Taken);
    }

    #[test]
    fn rename_stops_at_its_deadline() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("fg-adopt-rn-{}-{n}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let (from, to) = (dir.join("new"), dir.join("old"));
        fs::write(&from, b"new").unwrap();
        fs::write(&to, b"old").unwrap();
        let r = rename_retry(&from, &to, Some(Instant::now()));
        let kept = (fs::read(&from).ok(), fs::read(&to).ok());
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(kept, (Some(b"new".to_vec()), Some(b"old".to_vec())));
    }
}
