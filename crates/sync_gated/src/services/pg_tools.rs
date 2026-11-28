//! The PostgreSQL cluster that belongs to sync_gate: create it, prove its identity, start it,
//! query it and stop it. Nothing here stops, queries or writes into a cluster before every
//! identity check passed; on any doubt the answer is an error and nothing is touched. Every
//! tool runs through the supervisor (`run_tool`, `run_starter`).

use super::pg_sql::{
    ADMIN_PREAMBLE, ADMIN_ROLE, cluster_identity_sql, hba_conf, identity_guard_sql, redact,
    server_conf,
};
use crate::supervisor::{process_exe, run_starter_to, run_tool};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use sync_gate_probe::{create_private_dir, process_alive, start_time, write_atomic};

pub const PG_MIN_MAJOR: u32 = 15;

// Limits of the plan's time-budget table ("Prazos"); `run_tool` adds its 5 s grace.
const VERSION_TIMEOUT: Duration = Duration::from_secs(10);
const INITDB_TIMEOUT: Duration = Duration::from_secs(120);
const CONTROLDATA_TIMEOUT: Duration = Duration::from_secs(10);
const START_TIMEOUT: Duration = Duration::from_secs(75);
const STOP_TIMEOUT: Duration = Duration::from_secs(40);
const PSQL_TIMEOUT: Duration = Duration::from_secs(30);

/// Tolerance between the start time in `postmaster.pid` and the operating system's; used once.
const START_SLACK_SECS: u64 = 2;
/// Longest socket file path every supported platform accepts (`sun_path` minus the NUL).
const SOCKET_PATH_MAX: usize = 103;
const LEASES_EMPTY: &str = r#"{"version":1,"unknown_before":false,"leases":[]}"#;
/// The template registry of a new cluster: known, empty.
pub const TEMPLATES_EMPTY: &str =
    r#"{"version":1,"unknown_before":false,"next_seq":1,"templates":[]}"#;
const INCLUDE_LINE: &str = "include 'sync_gate.conf'";

/// Where one cluster lives: `root` = `<canonical data_dir>/pg/<major>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterPaths {
    pub bin: PathBuf,
    pub root: PathBuf,
    pub data: PathBuf,
    pub sock: PathBuf,
    pub log: PathBuf,
    pub record: PathBuf,
    pub leases: PathBuf,
    pub templates: PathBuf,
    pub port: u16,
}

impl ClusterPaths {
    pub fn new(bin: &Path, root: &Path, port: u16) -> ClusterPaths {
        ClusterPaths {
            bin: bin.to_path_buf(),
            root: root.to_path_buf(),
            data: root.join("data"),
            sock: root.join("s"),
            log: root.join("server.log"),
            record: root.join("cluster.json"),
            leases: root.join("leases.json"),
            templates: root.join("templates.json"),
            port,
        }
    }

    /// The socket file path fits every platform's limit and has no comma (ruling PF27: the
    /// server accepts one, but `psql -h` splits the host on it). The caller fails open.
    pub fn socket_path_ok(&self) -> bool {
        self.sock
            .join(format!(".s.PGSQL.{}", self.port))
            .to_str()
            .is_some_and(|s| s.len() <= SOCKET_PATH_MAX && !s.contains(','))
    }
}

/// Written once by `init` right after `initdb`; the proof that a cluster is sync_gate's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterRecord {
    pub data: PathBuf,
    pub bin: PathBuf,
    pub system_identifier: u64,
    pub major: u32,
}

/// A running server: its pid and the operating system's start time for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerId {
    pub pid: u32,
    pub start: u64,
}

/// The major version in `pg_ctl --version` output (the first word that starts with a digit).
pub fn parse_major(version_output: &str) -> Option<u32> {
    let word = version_output
        .split_whitespace()
        .find(|w| w.starts_with(|c: char| c.is_ascii_digit()))?;
    let digits: String = word.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

pub fn parse_system_identifier(controldata: &str) -> Option<u64> {
    controldata.lines().find_map(|l| {
        l.strip_prefix("Database system identifier:")
            .and_then(|v| v.trim().parse().ok())
    })
}

/// The path resolved, without the Windows verbatim prefix (`\\?\`, `\\?\UNC\`).
pub fn canonical(p: &Path) -> io::Result<PathBuf> {
    let c = std::fs::canonicalize(p)?;
    #[cfg(windows)]
    {
        let s = c.to_string_lossy();
        if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
            return Ok(PathBuf::from(format!(r"\\{rest}")));
        }
        if let Some(rest) = s.strip_prefix(r"\\?\") {
            return Ok(PathBuf::from(rest));
        }
    }
    Ok(c)
}

/// The one comparison every identity check uses (ruling PF9): both paths resolve and are the
/// same, case-insensitively on Windows. A path that does not resolve is never the same.
pub fn same_path(a: &Path, b: &Path) -> bool {
    match (canonical(a), canonical(b)) {
        (Ok(a), Ok(b)) if cfg!(windows) => {
            a.to_string_lossy().to_lowercase() == b.to_string_lossy().to_lowercase()
        }
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

fn fail(msg: impl Into<String>) -> io::Error {
    io::Error::other(msg.into())
}

fn refused(p: &Path) -> io::Error {
    sync_gate_core::refusal(
        io::ErrorKind::Other,
        format!(
            "link or unexpected file in the cluster path: {}",
            p.display()
        ),
    )
}

/// A refusal by a rule (link, kind, owner, who can change it), never an error of the system
/// (a file in use, a failed read), which may pass on a retry. What writes a refused file is
/// disabled; what meets a system error tries again later.
pub(crate) fn is_policy_refusal(e: &io::Error) -> bool {
    sync_gate_core::is_refusal(e)
}

/// Absent, or of the expected kind and not a link (on Windows, no reparse point either:
/// junction, mount point, file link), and nothing another user could have written: a file
/// passes `check_private_file`; a folder is ours with no group or other write (Unix) or passes
/// `check_private_dir` (Windows).
fn check_entry(p: &Path, dir: bool) -> io::Result<()> {
    let m = match std::fs::symlink_metadata(p) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        r => r?,
    };
    if bad_kind(&m, dir) {
        return Err(refused(p));
    }
    if !dir {
        return match sync_gate_core::check_private_file(p) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            r => r,
        };
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if m.uid() != nix::unistd::geteuid().as_raw() || m.mode() & 0o022 != 0 {
            return Err(sync_gate_core::refusal(
                io::ErrorKind::PermissionDenied,
                format!(
                    "a folder other users can change in the cluster path: {}",
                    p.display()
                ),
            ));
        }
    }
    #[cfg(windows)]
    sync_gate_core::check_private_dir(p)?;
    Ok(())
}

/// A configuration or registry file of the cluster, judged and read from the same handle.
fn read_checked(p: &Path) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    sync_gate_core::open_private_file(p)?.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// `read_checked` as text.
fn read_text_checked(p: &Path) -> io::Result<String> {
    String::from_utf8(read_checked(p)?)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "not UTF-8"))
}

/// A registry file (`leases.json`, `templates.json`) read for loading: its bytes, or `None` when
/// absent. Any other error, a refusal by the rules or one of the system (a file in use, a failed
/// read), fails the load (the service fails with it and retries; the file is kept, never set
/// aside as unreadable): only bytes that do not parse make a registry unreadable.
pub(crate) fn read_registry(p: &Path) -> Result<Option<Vec<u8>>, String> {
    match read_checked(p) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// A file the running server writes (`postmaster.pid`): judged by owner and DACL only
/// (`check_private_file`, no probe for writers: the server has it open), then read by path.
fn read_operational(p: &Path) -> io::Result<String> {
    sync_gate_core::check_private_file(p)?;
    std::fs::read_to_string(p)
}

/// Windows: nothing holds `p` open for writing its data. Opened for DELETE only (it takes part in
/// the sharing check without reading the data, which a full read would make the virus scanner do
/// for every file of the cluster), sharing reads and deletes but not writes. Contract, pinned by
/// `check_tree_probe_refuses_what_a_read_refuses`: refuses every handle with write or append
/// access, as `open_private_file` does; also refuses a handle that does not share deletes (a
/// sharing violation: retried, never disabling); judges nothing (`check_private_file` did, just
/// before, in a folder only this user can change).
#[cfg(windows)]
fn no_writer(p: &Path) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    const DELETE: u32 = 0x1_0000;
    const SHARE_READ_DELETE: u32 = 0x1 | 0x4;
    const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    std::fs::OpenOptions::new()
        .access_mode(DELETE)
        .share_mode(SHARE_READ_DELETE)
        .custom_flags(OPEN_REPARSE_POINT)
        .open(p)
        .map(drop)
        .map_err(|e| match e.raw_os_error() {
            Some(32) => io::Error::new(
                e.kind(),
                format!(
                    "{} is in use by another program in a way that conflicts with a safe read (sharing violation); close it and retry",
                    p.display()
                ),
            ),
            _ => e,
        })
}

/// Before a start, with the server stopped: every folder under `root` passes the folder rule,
/// every file passes `check_private_file` and (Windows) nothing holds it open for writing. Not
/// `open_private_file`: reading every data file made the start 20 times slower (the scanner).
/// Links are not followed: one is refused.
pub(crate) fn check_tree(root: &Path) -> io::Result<()> {
    // shortcut: check_private_dir walks the ancestors again for each folder; 50 databases (79
    // folders, 15,892 files) took 2.2 s on Windows. Keep the parent's verdict if starts get slow.
    let mut folders = vec![root.to_path_buf()];
    while let Some(d) = folders.pop() {
        sync_gate_core::check_private_dir(&d)?;
        for e in std::fs::read_dir(&d)? {
            let e = e?;
            if e.file_type()?.is_dir() {
                folders.push(e.path());
            } else {
                sync_gate_core::check_private_file(&e.path())?;
                #[cfg(windows)]
                no_writer(&e.path())?;
            }
        }
    }
    Ok(())
}

/// A link, a reparse point (Windows: junction, mount point, file link) or not of the kind.
fn bad_kind(m: &std::fs::Metadata, dir: bool) -> bool {
    #[cfg(windows)]
    let reparse = {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    };
    #[cfg(not(windows))]
    let reparse = false;
    let kind_ok = if dir { m.is_dir() } else { m.is_file() };
    m.file_type().is_symlink() || reparse || !kind_ok
}

/// The refusal, when the file `p` or its `.tmp` sibling is a link, a reparse point, something
/// other than a file (ruling PF8) or a file another user could change: the caller disables what
/// writes it. An error of the system is not a refusal (`None`): the write meets it and is retried.
pub(crate) fn write_target_refused(p: &Path) -> Option<io::Error> {
    [p.to_path_buf(), tmp_sibling(p)]
        .iter()
        .find_map(|q| check_entry(q, false).err().filter(is_policy_refusal))
}

fn tmp_sibling(path: &Path) -> PathBuf {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    PathBuf::from(tmp)
}

/// R18/R23: every component from the canonical data folder down, and every file and folder
/// the daemon reads or writes in the cluster, is absent or of its kind and not a link; and
/// `postgresql.auto.conf` sets nothing. On error the caller reads and writes nothing.
pub fn check_paths(c: &ClusterPaths) -> io::Result<()> {
    let base = c.root.parent().and_then(Path::parent);
    let names = c
        .root
        .parent()
        .and_then(Path::file_name)
        .zip(c.root.file_name());
    let (Some(base), Some((pg_name, major))) = (base, names) else {
        return Err(refused(&c.root));
    };
    // The data folder itself may sit under a system link (`/var` on macOS); nothing below it.
    let pg = canonical(base)?.join(pg_name);
    let root = pg.join(major);
    let data = root.join("data");
    let global = data.join("global");
    let entries = [
        (pg.clone(), true),
        (root.clone(), true),
        (root.join("cluster.json"), false),
        (root.join("cluster.json.tmp"), false),
        (root.join("leases.json"), false),
        (root.join("leases.json.tmp"), false),
        (root.join("leases.json.unreadable"), false),
        (root.join("templates.json"), false),
        (root.join("templates.json.tmp"), false),
        (root.join("templates.json.unreadable"), false),
        (root.join("server.log"), false),
        (root.join("s"), true),
        (data.clone(), true),
        (data.join("PG_VERSION"), false),
        (data.join("postmaster.pid"), false),
        (data.join("pg_hba.conf"), false),
        (data.join("postgresql.conf"), false),
        (data.join("postgresql.auto.conf"), false),
        (data.join("sync_gate.conf"), false),
        (global.clone(), true),
        (global.join("pg_control"), false),
    ];
    for (p, dir) in &entries {
        check_entry(p, *dir)?;
    }
    // PostgreSQL reads this over postgresql.conf; sync_gate never writes it nor runs ALTER SYSTEM.
    let auto = data.join("postgresql.auto.conf");
    match read_text_checked(&auto) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
        Ok(text) => {
            if text
                .lines()
                .map(str::trim)
                .all(|l| l.is_empty() || l.starts_with('#'))
            {
                Ok(())
            } else {
                Err(fail(format!(
                    "postgresql.auto.conf sets parameters: {}",
                    auto.display()
                )))
            }
        }
    }
}

/// `write_atomic`, refused when the file or its `.tmp` sibling is a link, of another kind (ruling
/// PF8) or another user could change it. `write_atomic` now writes a fresh exclusive temporary
/// file instead of `.tmp`; a planted `.tmp` still disables the writer, as before.
/// `is_policy_refusal` tells a refusal from an error of the system.
pub(crate) fn write_checked(path: &Path, bytes: &[u8]) -> io::Result<()> {
    check_entry(path, false)?;
    check_entry(&tmp_sibling(path), false)?;
    write_atomic(path, bytes)
}

/// A PostgreSQL tool of `bin`, with no inherited `PG*` variable and untranslated messages.
pub(crate) fn tool_command(bin: &Path, name: &str) -> Command {
    let mut cmd = Command::new(bin.join(format!("{name}{}", std::env::consts::EXE_SUFFIX)));
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().to_ascii_uppercase().starts_with("PG") {
            cmd.env_remove(k);
        }
    }
    cmd.env("LC_ALL", "C").env_remove("LANGUAGE");
    cmd
}

/// Runs a tool that takes no secret; a failure carries the last lines of its stderr.
fn run_plain(cmd: Command, timeout: Duration, what: &str) -> io::Result<String> {
    let out = run_tool(cmd, None, timeout)?;
    if out.code == Some(0) {
        return Ok(out.stdout);
    }
    Err(fail(format!(
        "{what} failed ({:?}): {}",
        out.code,
        redact(&last_lines(&out.stderr, 5), &[])
    )))
}

fn last_lines(text: &str, n: usize) -> String {
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    lines[lines.len().saturating_sub(n)..].join(" | ")
}

/// How much of the end of `server.log` a failed start reads.
const LOG_TAIL_BYTES: u64 = 64 * 1024;

/// The last five non-blank lines of the file, from at most its last `LOG_TAIL_BYTES`. The first
/// line of a window that starts mid-file may be cut and is dropped. Unreadable reads as empty.
fn log_tail(path: &Path) -> String {
    let read = || -> io::Result<String> {
        sync_gate_core::check_private_file(path)?;
        let mut f = std::fs::File::open(path)?;
        let from = f.metadata()?.len().saturating_sub(LOG_TAIL_BYTES);
        f.seek(SeekFrom::Start(from))?;
        let mut buf = Vec::new();
        f.take(LOG_TAIL_BYTES).read_to_end(&mut buf)?;
        let text = String::from_utf8_lossy(&buf);
        Ok(match (from, text.split_once('\n')) {
            (0, _) => text.to_string(),
            (_, Some((_, rest))) => rest.to_string(),
            (_, None) => String::new(),
        })
    };
    last_lines(&read().unwrap_or_default(), 5)
}

/// What a failed `pg_ctl start` says: the tail of `server.log`, or, when pg_ctl died before it
/// opened that log, the tail of what it printed itself (`out`).
fn start_failure(code: Option<i32>, log: &Path, out: &Path) -> String {
    let mut said = log_tail(log);
    if said.is_empty() {
        said = log_tail(out);
    }
    format!("pg_ctl start failed ({code:?}): {}", redact(&said, &[]))
}

/// Runs `attempt` (a `pg_ctl start`); once more when it failed and `left_nothing()` says it
/// left neither a log nor a server, so repeating cannot start a second one. `first_failed`
/// gets the first result before the repeat.
fn start_twice(
    attempt: &mut dyn FnMut() -> io::Result<Option<i32>>,
    left_nothing: &dyn Fn() -> bool,
    first_failed: &mut dyn FnMut(Option<i32>),
) -> io::Result<Option<i32>> {
    let first = attempt()?;
    if first == Some(0) || !left_nothing() {
        return Ok(first);
    }
    first_failed(first);
    attempt()
}

fn controldata(c: &ClusterPaths) -> io::Result<u64> {
    let mut cmd = tool_command(&c.bin, "pg_controldata");
    cmd.arg("-D").arg(&c.data);
    let out = run_plain(cmd, CONTROLDATA_TIMEOUT, "pg_controldata")?;
    parse_system_identifier(&out).ok_or_else(|| fail("pg_controldata printed no system identifier"))
}

fn load_record(c: &ClusterPaths) -> io::Result<ClusterRecord> {
    let bytes = read_checked(&c.record)?;
    serde_json::from_slice(&bytes).map_err(|e| fail(format!("unreadable cluster record: {e}")))
}

/// `postgresql.conf` with exactly one include of `sync_gate.conf`, as its last line.
fn with_include(conf: &str) -> String {
    let kept: Vec<&str> = conf.lines().filter(|l| l.trim() != INCLUDE_LINE).collect();
    format!("{}\n{INCLUDE_LINE}\n", kept.join("\n").trim_end())
}

fn process_cmd(pid: u32) -> Option<Vec<OsString>> {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
    let mut sys = System::new().ok()?;
    let p = Pid::from_u32(pid);
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[p]),
        true,
        ProcessRefreshKind::nothing().with_cmd(UpdateKind::Always),
    );
    Some(sys.process(p)?.cmd().to_vec())
}

/// Items 2-4 of the identity (no SQL): `<data>/postmaster.pid` names `data`, and its pid is a
/// live `postgres` of `bin` whose start time matches (within the slack, once) and whose
/// command line, when readable, serves `data`. No pid file, or a pid that is positively gone
/// (ruling PF1), is `Ok(None)`. The start time returned is the operating system's (PF7).
pub(crate) fn running_postmaster(data: &Path, bin: &Path) -> Result<Option<ServerId>, String> {
    let file = data.join("postmaster.pid");
    let text = match read_operational(&file) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot read {}: {e}", file.display())),
        Ok(t) => t,
    };
    let bad = || format!("unreadable {}", file.display());
    let mut lines = text.lines().map(|l| l.trim_end_matches('\r'));
    let pid: u32 = lines
        .next()
        .and_then(|l| l.trim().parse().ok())
        .ok_or_else(bad)?;
    let dir = lines.next().ok_or_else(bad)?;
    let written: u64 = lines
        .next()
        .and_then(|l| l.trim().parse().ok())
        .ok_or_else(bad)?;
    if !same_path(Path::new(dir), data) {
        return Err(format!("{} names another data folder", file.display()));
    }
    match process_alive(pid) {
        Some(false) => return Ok(None),
        None => return Err(format!("cannot tell whether pid {pid} is alive")),
        Some(true) => {}
    }
    let postgres = bin.join(format!("postgres{}", std::env::consts::EXE_SUFFIX));
    if !process_exe(pid).is_some_and(|exe| same_path(&exe, &postgres)) {
        return Err(format!("pid {pid} is not {}", postgres.display()));
    }
    let start = start_time(pid).ok_or_else(|| format!("start time of pid {pid} is unreadable"))?;
    if start.abs_diff(written) > START_SLACK_SECS {
        return Err(format!("pid {pid} started at another time: a reused pid"));
    }
    if let Some(cmd) = process_cmd(pid).filter(|a| !a.is_empty()) {
        let d = cmd
            .iter()
            .position(|a| a == "-D")
            .and_then(|i| cmd.get(i + 1));
        if !d.is_some_and(|d| same_path(Path::new(d), data)) {
            return Err(format!("pid {pid} serves another data folder"));
        }
    }
    Ok(Some(ServerId { pid, start }))
}

/// The port a running server listens on: line 4 of its `postmaster.pid`. The configured port
/// may have changed since it started (final review P1).
fn pid_port(data: &Path) -> Result<u16, String> {
    let file = data.join("postmaster.pid");
    let text =
        read_operational(&file).map_err(|e| format!("cannot read {}: {e}", file.display()))?;
    text.lines()
        .nth(3)
        .and_then(|l| l.trim().parse().ok())
        .filter(|p| *p != 0)
        .ok_or_else(|| format!("no port in {}", file.display()))
}

/// The administrator's `psql` over the private socket on `port`: script on stdin after the
/// preamble, so neither it nor its errors reach the server log. An error quotes only the
/// first `ERROR:` (else `FATAL:`) line of stderr, redacted.
fn psql(c: &ClusterPaths, port: u16, script: &str, secrets: &[&str]) -> io::Result<String> {
    let mut cmd = tool_command(&c.bin, "psql");
    cmd.args(["-X", "-q", "-A", "-t", "-w", "-v", "ON_ERROR_STOP=1", "-h"]);
    cmd.arg(&c.sock).arg("-p").arg(port.to_string());
    cmd.args(["-U", ADMIN_ROLE, "-d", "postgres", "-f", "-"]);
    let input = format!("{ADMIN_PREAMBLE}{script}\n");
    let out = run_tool(cmd, Some(input.as_bytes()), PSQL_TIMEOUT)?;
    if out.code == Some(0) {
        // psql on Windows ends lines with CRLF; callers see one form.
        return Ok(out.stdout.replace("\r\n", "\n"));
    }
    let first = |tag: &str| out.stderr.lines().find(|l| l.contains(tag));
    Err(fail(match first("ERROR:").or_else(|| first("FATAL:")) {
        Some(line) => redact(line.trim(), secrets),
        None => format!("psql failed ({:?})", out.code),
    }))
}

pub trait PgTools: Send + Sync {
    fn major_version(&self, bin: &Path) -> io::Result<u32>;
    fn init(&self, c: &ClusterPaths, max_connections: u32) -> io::Result<()>;
    fn start(&self, c: &ClusterPaths) -> io::Result<ServerId>;
    fn server(&self, c: &ClusterPaths) -> Result<Option<ServerId>, String>;
    fn stop(&self, c: &ClusterPaths, id: ServerId) -> io::Result<()>;
    fn sql(&self, c: &ClusterPaths, script: &str, secrets: &[&str]) -> io::Result<String>;
    fn config_current(&self, c: &ClusterPaths, max_connections: u32) -> bool;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct OsPgTools;

impl PgTools for OsPgTools {
    fn major_version(&self, bin: &Path) -> io::Result<u32> {
        let mut cmd = tool_command(bin, "pg_ctl");
        cmd.arg("--version");
        let out = run_plain(cmd, VERSION_TIMEOUT, "pg_ctl --version")?;
        parse_major(&out).ok_or_else(|| fail("unrecognised pg_ctl --version output"))
    }

    fn init(&self, c: &ClusterPaths, max_connections: u32) -> io::Result<()> {
        check_paths(c)?;
        create_private_dir(&c.root)?;
        create_private_dir(&c.sock)?;
        let not_ours = || fail(format!("not a sync_gate cluster: {}", c.data.display()));
        if c.data.join("PG_VERSION").is_file() {
            let rec = load_record(c).map_err(|_| not_ours())?;
            if !same_path(&rec.data, &c.data)
                || !same_path(&rec.bin, &c.bin)
                || rec.system_identifier != controldata(c)?
            {
                return Err(not_ours());
            }
        } else {
            match std::fs::read_dir(&c.data) {
                Ok(mut d) => {
                    if d.next().is_some() {
                        return Err(not_ours());
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            let mut cmd = tool_command(&c.bin, "initdb");
            cmd.arg("-D").arg(&c.data);
            cmd.args(["-U", ADMIN_ROLE, "--auth-local=trust", "--auth-host=reject"]);
            cmd.args(["-E", "UTF8", "--no-locale", "--no-instructions"]);
            run_plain(cmd, INITDB_TIMEOUT, "initdb")?;
            check_paths(c)?;
            let major = read_text_checked(&c.data.join("PG_VERSION"))?
                .trim()
                .parse()
                .map_err(|_| fail("unreadable PG_VERSION"))?;
            let rec = ClusterRecord {
                data: canonical(&c.data)?,
                bin: canonical(&c.bin)?,
                system_identifier: controldata(c)?,
                major,
            };
            write_checked(&c.record, &serde_json::to_vec_pretty(&rec)?)?;
            // From here on a missing lease record means "unknown", never "empty".
            write_checked(&c.leases, LEASES_EMPTY.as_bytes())?;
            write_checked(&c.templates, TEMPLATES_EMPTY.as_bytes())?;
        }
        match self.server(c) {
            Ok(None) => {}
            // The configuration is never rewritten under a running server.
            Ok(Some(_)) => return Ok(()),
            Err(e) => return Err(fail(e)),
        }
        let conf =
            server_conf(c.port, &c.sock, max_connections).map_err(|e| fail(e.to_string()))?;
        write_checked(&c.data.join("pg_hba.conf"), hba_conf().as_bytes())?;
        write_checked(&c.data.join("sync_gate.conf"), conf.as_bytes())?;
        let main = c.data.join("postgresql.conf");
        let text = read_text_checked(&main)?;
        write_checked(&main, with_include(&text).as_bytes())
    }

    fn start(&self, c: &ClusterPaths) -> io::Result<ServerId> {
        check_paths(c)?;
        match self.server(c) {
            Ok(None) => {}
            Ok(Some(_)) => return Err(fail("the server is already running")),
            Err(e) => return Err(fail(e)),
        }
        // What pg_ctl itself prints (it dies before opening `server.log` in some failures).
        let out = c.log.with_file_name("pg_ctl.out");
        let mut attempt = || {
            // The server is stopped here (no `server` found just before, in this call or in the
            // check before the repeat): nothing of the cluster is open for writing.
            check_tree(&c.root)?;
            let mut cmd = tool_command(&c.bin, "pg_ctl");
            cmd.arg("start")
                .arg("-D")
                .arg(&c.data)
                .arg("-l")
                .arg(&c.log);
            cmd.args(["-w", "-t", "60"]);
            run_starter_to(cmd, START_TIMEOUT, &out)
        };
        // A stale log from an earlier run also blocks the repeat: the safe side.
        let left_nothing = || log_tail(&c.log).is_empty() && matches!(self.server(c), Ok(None));
        let note = &mut |code: Option<i32>| {
            eprintln!(
                "sync_gated: pg_ctl start failed ({code:?}) leaving no log and no server, trying once more: {}",
                redact(&log_tail(&out), &[])
            );
        };
        // `JOB_LOCKED` and every other starter error go up unchanged.
        match start_twice(&mut attempt, &left_nothing, note)? {
            Some(0) => match self.server(c) {
                Ok(Some(id)) => Ok(id),
                Ok(None) => Err(fail("the server started but left no live postmaster.pid")),
                Err(e) => Err(fail(format!("the started server is not proven ours: {e}"))),
            },
            code => Err(fail(start_failure(code, &c.log, &out))),
        }
    }

    /// R4: files and the process table first (items 1-4), then the only query run before the
    /// server is accepted (item 5), on the port in the server's `postmaster.pid`.
    fn server(&self, c: &ClusterPaths) -> Result<Option<ServerId>, String> {
        check_paths(c).map_err(|e| e.to_string())?;
        let rec = load_record(c).map_err(|e| format!("cluster record: {e}"))?;
        if !same_path(&rec.data, &c.data) {
            return Err("the cluster record names another data folder".into());
        }
        let Some(id) = running_postmaster(&c.data, &rec.bin)? else {
            return Ok(None);
        };
        let port = pid_port(&c.data)?;
        let out = psql(c, port, &cluster_identity_sql(), &[])
            .map_err(|e| format!("identity query failed: {e}"))?;
        let (sysid, dir) = out
            .trim_end()
            .split_once('|')
            .ok_or("unexpected identity answer")?;
        if sysid.parse::<u64>().ok() != Some(rec.system_identifier)
            || !same_path(Path::new(dir), &rec.data)
        {
            return Err(format!(
                "the server on {} is not this cluster",
                c.sock.display()
            ));
        }
        Ok(Some(id))
    }

    fn stop(&self, c: &ClusterPaths, id: ServerId) -> io::Result<()> {
        check_paths(c)?;
        match self.server(c) {
            Ok(Some(now)) if now == id => {}
            Ok(_) => return Err(fail("the server is not the one identified; not stopping")),
            Err(e) => return Err(fail(e)),
        }
        let mut cmd = tool_command(&c.bin, "pg_ctl");
        cmd.arg("stop").arg("-D").arg(&c.data);
        cmd.args(["-m", "fast", "-w", "-t", "30"]);
        run_plain(cmd, STOP_TIMEOUT, "pg_ctl stop").map(drop)
    }

    fn sql(&self, c: &ClusterPaths, script: &str, secrets: &[&str]) -> io::Result<String> {
        check_paths(c)?;
        let rec = load_record(c).map_err(|e| fail(format!("cluster record: {e}")))?;
        if !same_path(&rec.data, &c.data) {
            return Err(fail("the cluster record names another data folder"));
        }
        match running_postmaster(&c.data, &rec.bin) {
            Ok(Some(_)) => {}
            Ok(None) => return Err(fail("postgres is not running")),
            Err(reason) => return Err(fail(reason)),
        }
        let port = pid_port(&c.data).map_err(fail)?;
        // Same session as the script: nothing can change between the proof and the SQL.
        let guarded = format!("{}{script}", identity_guard_sql(rec.system_identifier));
        psql(c, port, &guarded, secrets)
    }

    fn config_current(&self, c: &ClusterPaths, max_connections: u32) -> bool {
        let Ok(conf) = server_conf(c.port, &c.sock, max_connections) else {
            return false;
        };
        let read = |name: &str| read_text_checked(&c.data.join(name)).ok();
        check_paths(c).is_ok()
            && read("pg_hba.conf").as_deref() == Some(hba_conf())
            && read("sync_gate.conf") == Some(conf)
            && read("postgresql.conf").is_some_and(|t| {
                t.lines().rev().map(str::trim).find(|l| !l.is_empty()) == Some(INCLUDE_LINE)
            })
    }
}

#[cfg(test)]
mod tests;
