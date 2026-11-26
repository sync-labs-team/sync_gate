//! The CLI's behaviour: admission, supervised execution, and fail-open fallbacks.
//!
//! Test or advanced overrides read from the environment (not part of the public interface):
//! `SYNC_GATE_SOCKET` (daemon socket name), `SYNC_GATE_DATA_DIR` (pending tickets live under it),
//! `SYNC_GATE_FORCE_HEAVY=1|true` (treat every command as heavy), `SYNC_GATE_CONFIG` (path of
//! `config.toml`, read by the daemon, the CLI and `sync_gate_mcp`). Debug builds only (the e2e tests):
//! `SYNC_GATE_TEST_INTERRUPT_AFTER_MS` (with `SYNC_GATE_TEST_HANDLER_MARK` and `SYNC_GATE_TEST_HANDLER_GO`: see
//! `handler_with_markers`) and `SYNC_GATE_TEST_STOP_FILE` (simulate Ctrl+C through the
//! same path as the handler, then create the stop file the test fixture watches; the child is
//! never killed), `SYNC_GATE_TEST_SAVE_FAILS_ON_REQUEUE` (the save of a requeued pending fails).

use crate::client::{ClientError, call_at, guest_explained};
use crate::lease::{self, HandOver, Lease};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::SeqCst};
use std::sync::{Arc, Mutex, MutexGuard, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use sync_gate_core::ipc_name::SelfKind;
use sync_gate_core::{
    Config, DaemonInfo, ERR_ADMITTED, ERR_BUSY, ERR_CLAIMED, ERR_UNKNOWN_TICKET, MAX_WAIT_SECS,
    MIB, Request, Response, StatusReport, TicketId, is_heavy, socket_name,
};
use sync_gate_probe::{
    Probe, RecoveryOutcome, Renewal, process_alive, recover_as_owner, resume_tree,
};

/// Exit code of `run` / `wait` when the queue wait ran out (EX_TEMPFAIL).
pub const EXIT_QUEUED: i32 = 75;
/// Exit code after Ctrl+C while queued or admitted but not yet started (128 + SIGINT).
const EXIT_INTERRUPTED: i32 = 130;

pub fn socket() -> String {
    socket_name()
}

/// Where pending commands live. `SYNC_GATE_DATA_DIR` wins (Disk). Windows, by `self_kind()`: an
/// account guest keeps them in its own profile; `@appcontainer` and `@restricted` keep none (a
/// sandbox cannot resume a ticket later, so nothing is written anywhere); the owner as today.
#[derive(Debug, PartialEq, Eq)]
enum Store {
    Disk(PathBuf),
    InProcess,
}

/// Pure choice of the store. `own_profile` is the folder of this process's own account when the
/// environment names another one. No shared-`/tmp` fallback: without a per-user dir (`default`
/// None) there is nowhere safe to keep tickets.
fn pick_store(
    kind: &SelfKind,
    env_dir: Option<PathBuf>,
    own_profile: Option<PathBuf>,
    default: Option<PathBuf>,
) -> Option<Store> {
    if let Some(d) = env_dir {
        return Some(Store::Disk(d));
    }
    match kind {
        // shortcut: assumes no folder redirection on the account; read its FOLDERID_RoamingAppData
        // through its own registry hive if one shows up. Unreadable profile: no file at all.
        SelfKind::Account(_) => Some(own_profile.map_or(Store::InProcess, |p| {
            Store::Disk(p.join(r"AppData\Roaming\sync_labs\sync_gate\data"))
        })),
        SelfKind::AppContainer | SelfKind::Restricted => Some(Store::InProcess),
        SelfKind::Owner => default.map(Store::Disk),
    }
}

fn store() -> Option<Store> {
    #[cfg(windows)]
    let (kind, own) = (
        sync_gate_core::ipc_name::self_kind(),
        sync_gate_core::ipc_name::own_profile_if_env_is_foreign(),
    );
    #[cfg(not(windows))]
    let (kind, own) = (SelfKind::Owner, None);
    pick_store(
        &kind,
        std::env::var_os("SYNC_GATE_DATA_DIR").map(PathBuf::from),
        own,
        sync_gate_probe::data_dir(),
    )
}

/// The folder of the Disk store, if any.
fn data_dir() -> Option<PathBuf> {
    match store() {
        Some(Store::Disk(d)) => Some(d),
        _ => None,
    }
}

fn load_config() -> Config {
    sync_gate_shim::load_config().unwrap_or_else(|e| {
        eprintln!("sync_gate: ignoring the config: {e}");
        Config::default()
    })
}

/// What `sync_gate wait N` needs to run a queued command later.
#[derive(Serialize, Deserialize)]
struct Pending {
    argv: Vec<String>,
    cwd: PathBuf,
    session: String,
}

fn pending_path(id: TicketId) -> Option<PathBuf> {
    pending_in(&store(), id)
}

fn pending_in(store: &Option<Store>, id: TicketId) -> Option<PathBuf> {
    match store {
        Some(Store::Disk(d)) => Some(d.join("pending").join(format!("{id}.json"))),
        _ => None,
    }
}

fn remove_pending(id: TicketId) {
    if let Some(p) = pending_path(id) {
        let _ = std::fs::remove_file(p);
    }
}

fn save_pending(id: TicketId, p: &Pending) -> std::io::Result<()> {
    #[cfg(windows)]
    let kind = sync_gate_core::ipc_name::self_kind();
    #[cfg(not(windows))]
    let kind = SelfKind::Owner;
    let sweeps = guest_sweeps(&kind, std::env::var_os("SYNC_GATE_DATA_DIR").is_some());
    save_and_sweep(&store(), id, p, sweeps)
}

/// Only an `elevated` sandbox account sweeps, its own store, which the owner's daemon cannot
/// read; everyone else leaves expiry to the daemon, which knows which tickets are waited on.
fn guest_sweeps(kind: &SelfKind, env_dir_set: bool) -> bool {
    cfg!(windows) && matches!(kind, SelfKind::Account(_)) && !env_dir_set
}

/// `save_in`, then (`sweeps`) the expired stored commands of the same folder go.
fn save_and_sweep(
    store: &Option<Store>,
    id: TicketId,
    p: &Pending,
    sweeps: bool,
) -> std::io::Result<()> {
    save_in(store, id, p)?;
    if let (true, Some(Store::Disk(d))) = (sweeps, store) {
        let _ = sync_gate_probe::sweep_pending(
            &d.join("pending"),
            sync_gate_probe::PENDING_TTL,
            |_| false,
        );
    }
    Ok(())
}

fn save_in(store: &Option<Store>, id: TicketId, p: &Pending) -> std::io::Result<()> {
    use std::io::Write;
    // In-process store: nothing is written anywhere; the ticket lives and dies with this process.
    if store == &Some(Store::InProcess) {
        return Ok(());
    }
    let path = pending_in(store, id).ok_or_else(|| {
        std::io::Error::other("no per-user data directory (set SYNC_GATE_DATA_DIR)")
    })?;
    sync_gate_probe::create_private_dir(path.parent().expect("has parent"))?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    opts.open(path)?
        .write_all(&serde_json::to_vec(p).map_err(std::io::Error::other)?)
}

/// Unix: only a file of ours, with one link, that nobody else can write may be run later.
#[cfg(unix)]
fn pending_is_trusted(path: &Path) -> std::io::Result<()> {
    sync_gate_core::check_private_file(path).map(|_| ())
}

#[cfg(not(unix))]
fn pending_is_trusted(_: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Where this process is, for the Ctrl+C handler (installed once, at the start of `main`).
pub(crate) enum Phase {
    Idle,
    Queued(TicketId),
    Admitted(TicketId),
    Running,
}

static PHASE: Mutex<Phase> = Mutex::new(Phase::Idle);
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// Whether Ctrl+C arrived.
pub(crate) fn interrupted() -> bool {
    INTERRUPTED.load(SeqCst)
}

pub(crate) fn lock_phase() -> MutexGuard<'static, Phase> {
    PHASE.lock().unwrap_or_else(|e| e.into_inner())
}

/// Sets the phase. A Ctrl+C that arrived while Idle (Acquire in flight) acts here, as soon as
/// there is a ticket to undo.
fn set_phase(p: Phase) {
    let mut phase = lock_phase();
    *phase = p;
    if INTERRUPTED.load(SeqCst) {
        undo_and_exit(&mut phase);
    }
}

fn on_interrupt() {
    INTERRUPTED.store(true, SeqCst);
    undo_and_exit(&mut lock_phase());
}

/// Ctrl+C in any phase. Running: nothing (the child gets the console's Ctrl+C itself; we wait
/// for it and send Finished). Queued: cancel the ticket. Admitted, not yet spawned: release it.
fn undo_and_exit(phase: &mut Phase) {
    match *phase {
        Phase::Queued(id) => {
            *phase = Phase::Idle;
            // Another waiter owns this admission: the pending file is not ours to delete.
            let reply = call_at(&socket(), &Request::Cancel { id });
            if !matches!(reply, Ok(Response::Error { message }) if message.contains(ERR_ADMITTED)) {
                remove_pending(id);
            }
            std::process::exit(EXIT_INTERRUPTED);
        }
        Phase::Admitted(id) => {
            *phase = Phase::Idle;
            release(id);
            std::process::exit(EXIT_INTERRUPTED);
        }
        Phase::Idle | Phase::Running => {}
    }
}

/// Gives an admitted, never-started ticket back to the daemon.
fn release(id: TicketId) {
    let finished = Request::Finished {
        id,
        peak_rss: 0,
        exit_code: None,
    };
    let _ = call_at(&socket(), &finished);
}

/// Installs the Ctrl+C handler; call once at the start of `main`.
pub fn install_ctrlc() {
    let _ = ctrlc::set_handler(on_interrupt);
    // The test hooks exist only in debug builds (the e2e tests); a release binary ignores them.
    if !cfg!(debug_assertions) {
        return;
    }
    if let Some(ms) = std::env::var("SYNC_GATE_TEST_INTERRUPT_AFTER_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        let stop = std::env::var_os("SYNC_GATE_TEST_STOP_FILE");
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(ms));
            match std::env::var_os("SYNC_GATE_TEST_HANDLER_MARK") {
                Some(mark) => handler_with_markers(&mark),
                None => on_interrupt(),
            }
            if let Some(stop) = stop {
                let _ = std::fs::write(stop, "");
            }
        });
    }
}

/// Debug-only handler for the tests: raises the flag, writes `mark`, waits (bounded) for the file
/// `SYNC_GATE_TEST_HANDLER_GO`, then takes the phase lock and looks at the phase. It writes
/// `<mark>.exits` if the phase makes the handler end the process (Queued, Admitted) or
/// `<mark>.deferred` if it does not (Running, Idle: the exit is left to the caller), so a test
/// can tell what the handler found at that moment.
fn handler_with_markers(mark: &std::ffi::OsStr) {
    let with = |ext: &str| {
        let mut p = mark.to_os_string();
        p.push(ext);
        let _ = std::fs::write(p, "");
    };
    INTERRUPTED.store(true, SeqCst);
    let _ = std::fs::write(mark, "");
    if let Some(go) = std::env::var_os("SYNC_GATE_TEST_HANDLER_GO") {
        let end = std::time::Instant::now() + Duration::from_secs(60);
        while !Path::new(&go).exists() && std::time::Instant::now() < end {
            thread::sleep(Duration::from_millis(10));
        }
    }
    let mut phase = lock_phase();
    let exits = matches!(*phase, Phase::Queued(_) | Phase::Admitted(_));
    with(if exits { ".exits" } else { ".deferred" });
    undo_and_exit(&mut phase);
}

/// Asks for the database of the command that is about to start; `None` runs it as it is.
fn lease_for(argv: &[String], cwd: Option<&Path>) -> Option<Lease> {
    let cfg = load_config();
    cfg.postgres.as_ref()?;
    let cwd = cwd
        .map(Path::to_path_buf)
        .or_else(|| std::env::current_dir().ok())?;
    lease::acquire(&cfg, &cwd, argv)
}

/// After the command ended (or never started): stops the registration, gives the database back,
/// and waits for a give-up still being sent.
fn end_lease(handover: Option<HandOver>, lease: Option<Lease>) {
    if let Some(h) = handover {
        h.finish();
    }
    if let Some(l) = lease {
        l.release();
    }
    lease::settle();
}

/// With a lease the command gets its variables (and loses the user's own PostgreSQL settings);
/// without one its environment is the CLI's own. Errors name only `argv[0]`.
/// `job` is the admitted ticket: the child (and every shim below it) sees `SYNC_GATE_JOB` and runs
/// inside that admission.
fn spawn(
    argv: &[String],
    cwd: Option<&Path>,
    lease: Option<&Lease>,
    job: Option<TicketId>,
) -> Result<Child, i32> {
    let program = crate::program::resolve_in_env(&argv[0]);
    let mut c = Command::new(&program);
    c.args(&argv[1..]);
    if let Some(id) = job {
        c.env("SYNC_GATE_JOB", id.to_string());
    }
    if let Some(d) = cwd {
        c.current_dir(d);
    }
    if let Some(l) = lease {
        l.apply(&mut c);
    }
    c.spawn().map_err(|e| spawn_failure(&argv[0], &program, &e))
}

/// The message and exit code for a program that did not start (127 not found, 126 otherwise).
/// Windows: a `.cmd`/`.bat` that cannot take an argument with a line break (`InvalidInput`) says
/// so, and a name that exists only as `<name>.ps1` is 127 (a `.ps1` is never forwarded).
fn spawn_failure(shown: &str, program: &Path, e: &std::io::Error) -> i32 {
    use std::io::ErrorKind;
    #[cfg(windows)]
    {
        let ext = program
            .extension()
            .map(|x| x.to_string_lossy().to_lowercase());
        if e.kind() == ErrorKind::InvalidInput && matches!(ext.as_deref(), Some("cmd" | "bat")) {
            eprintln!(
                "sync_gate: {} is a batch file and cannot receive an argument with a line break; nothing ran (run the tool's own executable)",
                program.file_name().unwrap_or_default().to_string_lossy()
            );
            return 126;
        }
        if e.kind() == ErrorKind::NotFound && program.components().count() == 1 {
            let path = std::env::var_os("PATH");
            if let Some(ps1) =
                sync_gate_core::program::find_ps1(program.as_os_str(), path.as_deref())
            {
                eprintln!("{}", ps1_only_message(shown, &ps1));
                return 127;
            }
        }
    }
    #[cfg(not(windows))]
    let _ = program;
    eprintln!("sync_gate: cannot run {shown}: {e}");
    if e.kind() == ErrorKind::NotFound {
        127
    } else {
        126
    }
}

pub(crate) fn ps1_only_message(name: &str, ps1: &Path) -> String {
    format!(
        "sync_gate: {name} exists only as a PowerShell script ({}); the shim cannot run it. Run \"sync_gate shims install\" to stop shadowing it, or call the script by its path.",
        ps1.display()
    )
}

pub(crate) fn exit_code(s: ExitStatus) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = s.signal() {
            return 128 + sig;
        }
    }
    s.code().unwrap_or(1)
}

/// Runs without the daemon (light command, or fail-open).
fn run_direct(argv: &[String], cwd: Option<&Path>) -> i32 {
    let lease = lease_for(argv, cwd);
    // A Ctrl+C during the `migrate`: the command does not start.
    if INTERRUPTED.load(SeqCst) {
        end_lease(None, lease);
        return EXIT_INTERRUPTED;
    }
    let spawned = spawn(argv, cwd, lease.as_ref(), None);
    let handover = match (&spawned, &lease) {
        (Ok(c), Some(l)) => Some(l.hand_over(c.id())),
        _ => None,
    };
    let waited = spawned.and_then(|mut c| c.wait().map_err(|_| 1));
    end_lease(handover, lease);
    match waited {
        Ok(s) => exit_code(s),
        Err(code) => code,
    }
}

/// What the watchdog acts on; a seam so tests need no processes and no daemon.
trait Recovery {
    /// One recovery pass over `dir`, only while holding the daemon's instance lock.
    fn pass(&mut self, dir: &Path) -> RecoveryOutcome;
    /// Resumes the child's current process tree; used only when no data dir is known.
    fn tree(&mut self) -> std::io::Result<()>;
}

struct OsRecovery {
    pid: u32,
}

impl Recovery for OsRecovery {
    fn pass(&mut self, dir: &Path) -> RecoveryOutcome {
        recover_as_owner(dir)
    }
    fn tree(&mut self) -> std::io::Result<()> {
        resume_tree(self.pid)
    }
}

/// Serialises the no-data-dir tree resume with reaping the child: once reaped, its pid may
/// belong to a stranger, so a tree resume must never start (or still be running) after it.
#[derive(Default)]
struct ReapGate(Mutex<bool>);

impl ReapGate {
    /// Runs `f` while holding the gate, unless the child was reaped.
    fn unless_reaped<R>(&self, f: impl FnOnce() -> R) -> Option<R> {
        let reaped = self.0.lock().unwrap_or_else(|e| e.into_inner());
        (!*reaped).then(f)
    }

    /// Runs `try_reap` while holding the gate; when it reaps (`Some`), the child is marked
    /// reaped in the same critical section.
    fn try_reap<T>(&self, try_reap: impl FnOnce() -> Option<T>) -> Option<T> {
        let mut reaped = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let done = try_reap();
        *reaped |= done.is_some();
        done
    }
}

/// Waits for the child without reaping it outside the gate.
/// shortcut: polls `try_wait` every 20 ms (nix 0.31 has no `waitid` for Apple targets, so a
/// `WNOWAIT` wait is not portable); upgrade to `waitid(WEXITED | WNOWAIT)` if exit latency matters.
fn wait_child(gate: &ReapGate, child: &mut Child) -> i32 {
    loop {
        match gate.try_reap(|| child.try_wait().transpose()) {
            Some(Ok(status)) => return exit_code(status),
            Some(Err(_)) => return 1,
            None => thread::sleep(Duration::from_millis(20)),
        }
    }
}

/// How long recorded units that fail to resume are retried before saying so.
const RETRY_WINDOW: Duration = Duration::from_secs(30);

fn could_not_resume(n: usize) -> String {
    format!("sync_gate: could not resume {n} paused unit(s) after losing the daemon")
}

/// The watchdog's view of the daemon, one `Status` poll per second.
///
/// With a data dir (the daemon's own, else the local one if no daemon ever said), every poll
/// that cannot connect runs a recovery pass; the pass only acts while holding the daemon's
/// exclusive instance lock, so a live daemon (which holds it) is never second-guessed. The
/// child's tree is never resumed blindly: the daemon records an intent before suspending.
/// Without any data dir there is no lock and no record: after 3 failed connects the child's
/// own tree is resumed, never after it was reaped.
struct Watch {
    /// Consecutive polls that could not connect.
    failures: u32,
    /// Printed "daemon lost" (3 failed connects): `Finished` is no longer sent.
    lost: bool,
    /// The last identity a daemon reported.
    daemon: Option<DaemonInfo>,
    local_dir: Option<PathBuf>,
    /// Recorded units are failing (or the lock is unusable) since then: retried every poll.
    retry_since: Option<Instant>,
    failing: usize,
    gave_up_noted: bool,
    unavailable_noted: bool,
    /// No data dir: the tree resume, retried on errors for at most the window.
    tree_since: Option<Instant>,
    tree_done: bool,
}

impl Watch {
    fn new(local_dir: Option<PathBuf>) -> Self {
        Watch {
            failures: 0,
            lost: false,
            daemon: None,
            local_dir,
            retry_since: None,
            failing: 0,
            gave_up_noted: false,
            unavailable_noted: false,
            tree_since: None,
            tree_done: false,
        }
    }

    /// The daemon's data dir once it said which (`None` = it keeps no files); else the local one.
    fn dir(&self) -> Option<&Path> {
        match &self.daemon {
            Some(d) => d.data_dir.as_deref(),
            None => self.local_dir.as_deref(),
        }
    }

    /// One poll's reply; returns the lines to print.
    fn poll(
        &mut self,
        now: Instant,
        reply: &Result<Response, ClientError>,
        r: &mut impl Recovery,
        gate: &ReapGate,
    ) -> Vec<String> {
        let mut out = Vec::new();
        if let Ok(Response::Status(s)) = reply {
            // pid 0: a daemon that predates `DaemonInfo` told nothing.
            if s.daemon.pid != 0 {
                self.daemon = Some(s.daemon.clone());
            }
        }
        // A timeout means slow, not gone: only a failed connect counts.
        let connected = !matches!(reply, Err(ClientError::DaemonDown));
        self.failures = if connected { 0 } else { self.failures + 1 };
        if self.failures >= 3 && !self.lost {
            self.lost = true;
            out.push("sync_gate: daemon lost, continuing without queue".to_string());
        }
        match self.dir().map(Path::to_owned) {
            Some(dir) if !connected || self.retry_since.is_some() => {
                self.recover(now, &dir, r, &mut out);
            }
            Some(_) => {}
            None if self.lost => self.resume_tree(now, r, gate),
            None => {}
        }
        out
    }

    fn recover(&mut self, now: Instant, dir: &Path, r: &mut impl Recovery, out: &mut Vec<String>) {
        match r.pass(dir) {
            // Busy: a live daemon (or another recoverer) owns the record now.
            RecoveryOutcome::Busy | RecoveryOutcome::Done { failed: 0, .. } => {
                self.retry_since = None;
            }
            RecoveryOutcome::Done { failed, .. } => {
                self.failing = failed;
                self.retry_since.get_or_insert(now);
            }
            RecoveryOutcome::Unavailable(e) => {
                if !std::mem::replace(&mut self.unavailable_noted, true) {
                    out.push(format!(
                        "sync_gate: cannot recover paused units in {}: {e}",
                        dir.display()
                    ));
                }
                self.retry_since.get_or_insert(now);
            }
        }
        let expired = self
            .retry_since
            .is_some_and(|t| now.saturating_duration_since(t) >= RETRY_WINDOW);
        if expired {
            self.retry_since = None;
            if self.failing > 0 && !std::mem::replace(&mut self.gave_up_noted, true) {
                out.push(could_not_resume(self.failing));
            }
        }
    }

    fn resume_tree(&mut self, now: Instant, r: &mut impl Recovery, gate: &ReapGate) {
        let since = *self.tree_since.get_or_insert(now);
        if self.tree_done || now.saturating_duration_since(since) > RETRY_WINDOW {
            return;
        }
        self.tree_done = match gate.unless_reaped(|| r.tree()) {
            Some(Err(e)) => e.kind() == std::io::ErrorKind::NotFound,
            // Resumed, or the child was reaped: never again.
            Some(Ok(())) | None => true,
        };
    }
}

/// The post-exit pass may not delay the exit by more than this.
const EXIT_PASS_LIMIT: Duration = Duration::from_secs(2);

/// After the child exited: one last recovery pass, bounded by `limit`, unless `Finished` got a
/// successful reply (the daemon resumes the job's units before it replies). Any error, or no
/// `Finished` at all, runs it: a live daemon holds the lock, so it is then a cheap `Busy`. A pass
/// still running is left behind (the record stays on disk for the next daemon or CLI).
fn post_exit_pass(
    watch: &Watch,
    finished: Option<&Result<Response, ClientError>>,
    mut r: impl Recovery + Send + 'static,
    limit: Duration,
) {
    if matches!(finished, Some(Ok(Response::Ack))) {
        return;
    }
    let Some(dir) = watch.dir().map(Path::to_owned) else {
        return;
    };
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(r.pass(&dir));
    });
    match rx.recv_timeout(limit) {
        Ok(RecoveryOutcome::Done { failed, .. }) if failed > 0 && !watch.gave_up_noted => {
            eprintln!("{}", could_not_resume(failed));
        }
        _ => {}
    }
}

/// Runs an admitted ticket: Started, watchdog, Finished. Never kills the child.
/// The caller has already set `Phase::Admitted(id)` and claimed the command.
fn run_admitted(id: TicketId, argv: &[String], cwd: Option<&Path>) -> i32 {
    let sock = socket();
    // Asked for before the phase lock (it may take its patience) and after the claim.
    let mut lease = lease_for(argv, cwd);
    // Phase held across spawn -> Running: a Ctrl+C in between cannot exit and leave the child
    // running unsupervised.
    let mut phase = lock_phase();
    // A Ctrl+C whose handler is still waiting for this lock: undo now (release + exit 130).
    if INTERRUPTED.load(SeqCst) {
        end_lease(None, lease.take());
        undo_and_exit(&mut phase);
    }
    let spawned = spawn(argv, cwd, lease.as_ref(), Some(id));
    *phase = if spawned.is_ok() {
        Phase::Running
    } else {
        Phase::Idle
    };
    drop(phase);
    let mut child = match spawned {
        Ok(c) => c,
        Err(code) => {
            end_lease(None, lease);
            let finished = Request::Finished {
                id,
                peak_rss: 0,
                exit_code: Some(code),
            };
            let _ = call_at(&sock, &finished);
            return code;
        }
    };
    let pid = child.id();
    let handover = lease.as_ref().map(|l| l.hand_over(pid));
    let done = Arc::new(AtomicBool::new(false));
    let gate = Arc::new(ReapGate::default());
    let peak = Arc::new(AtomicU64::new(0));
    match call_at(&sock, &Request::Started { id, pid }) {
        Ok(Response::Ack) => {}
        Ok(other) => {
            // try_wait caches the status in `child`, so `wait_child` still sees the exit code.
            let exited = child_exited(&gate.try_reap(|| child.try_wait().transpose()));
            if started_refusal_is_worth_saying(exited) {
                eprintln!("sync_gate: warning: unexpected reply to Started: {other:?}");
            }
        }
        // A failed connect or a timeout is not proof the daemon is gone: the watchdog decides.
        Err(e) => eprintln!("sync_gate: warning: Started failed: {e}"),
    }
    let watchdog = {
        let (sock, done, peak, gate) = (sock.clone(), done.clone(), peak.clone(), gate.clone());
        thread::spawn(move || {
            let mut probe = Probe::new();
            let (mut sampled, mut polled, mut noted) = (Instant::now(), Instant::now(), false);
            let mut watch = Watch::new(data_dir());
            let mut os = OsRecovery { pid };
            peak.fetch_max(probe.tree_rss(pid), SeqCst);
            while !done.load(SeqCst) {
                thread::sleep(Duration::from_millis(50));
                if sampled.elapsed() >= Duration::from_millis(500) {
                    sampled = Instant::now();
                    peak.fetch_max(probe.tree_rss(pid), SeqCst);
                }
                if INTERRUPTED.load(SeqCst) && !noted {
                    noted = true;
                    eprintln!("sync_gate: interrupted, waiting for the command to exit");
                }
                if polled.elapsed() >= Duration::from_secs(1) {
                    let reply = call_at(&sock, &Request::Status);
                    polled = Instant::now();
                    for line in watch.poll(polled, &reply, &mut os, &gate) {
                        eprintln!("{line}");
                    }
                }
            }
            watch
        })
    };
    let code = wait_child(&gate, &mut child);
    end_lease(handover, lease);
    done.store(true, SeqCst);
    let watch = watchdog.join().ok();
    let lost = watch.as_ref().is_some_and(|w| w.lost);
    let finished = (!lost).then(|| {
        call_at(
            &sock,
            &Request::Finished {
                id,
                peak_rss: peak.load(SeqCst),
                exit_code: Some(code),
            },
        )
    });
    if let Some(w) = &watch {
        post_exit_pass(w, finished.as_ref(), OsRecovery { pid }, EXIT_PASS_LIMIT);
    }
    code
}

/// A refused `Started` is only news while the child runs: a guest's very short command may be gone
/// before the daemon can read the pid's identity, and that run is fine.
/// Only a real exit counts; a `try_wait` error proves nothing, so the warning stays.
fn child_exited(r: &Option<std::io::Result<std::process::ExitStatus>>) -> bool {
    matches!(r, Some(Ok(_)))
}

fn started_refusal_is_worth_saying(child_exited: bool) -> bool {
    !child_exited
}

/// A guest's queue is full (`ERR_BUSY`), or its connection was dropped: the owner's daemon never
/// sends either, so the owner's paths do not change.
fn is_busy(r: &Result<Response, ClientError>) -> bool {
    match r {
        Err(ClientError::Busy) => true,
        Ok(Response::Error { message }) => message.contains(ERR_BUSY),
        _ => false,
    }
}

const BUSY_LINE: &str = "sync_gate: the queue is busy for this account, running directly";
const DOWN_LINE: &str = "sync_gate: daemon not running, running directly";

/// Whether to print `line`: an unlisted guest was already told, in one line, that the command
/// runs without the queue, so it gets no second sync_gate line. The owner always gets `line`.
fn down_line_wanted(line: &str, explained: bool) -> bool {
    !(explained && line == DOWN_LINE)
}

fn say(line: &str) {
    if down_line_wanted(line, guest_explained()) {
        eprintln!("{line}");
    }
}

enum Waited {
    Admitted,
    /// The queue is busy for this account: run directly, under the claim.
    Busy,
    TimedOut,
    /// The daemon is not there: the only case that falls back to a direct run.
    Down,
    /// The daemon handed the ticket to another client: never run it here.
    Claimed,
    /// The daemon no longer knows the ticket (restart, expiry): queue the command again.
    Unknown,
    /// Any other error: never run.
    Refused(String),
}

/// Waits for `id` until `deadline`. Each daemon-side wait is capped at the time left (rounded
/// up), so the daemon's wait never outlives the CLI and the ticket goes dormant by the time we
/// exit 75. At least one wait is always sent, even with no time left: that zero-length wait is
/// what makes the daemon put an unwaited ticket to sleep.
fn wait_admission(sock: &str, id: TicketId, deadline: Instant) -> Waited {
    let mut first = true;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() && !first {
            return Waited::TimedOut;
        }
        first = false;
        let secs = left.as_secs_f64().ceil() as u64;
        let (tx, rx) = mpsc::channel();
        let sock = sock.to_owned();
        thread::spawn(move || {
            let req = Request::Wait {
                id,
                timeout_secs: Some(secs),
            };
            let _ = tx.send(call_at(&sock, &req));
        });
        // A wedged daemon must not hold us past the deadline (plus the cap's rounding).
        match rx.recv_timeout(Duration::from_secs(secs + 2)) {
            Ok(r) if is_busy(&r) => return Waited::Busy,
            Ok(Ok(Response::Admitted { .. })) => return Waited::Admitted,
            Ok(Ok(Response::Queued { .. })) => {
                // The daemon's own wait ended; back off so a zero-length wait cannot spin.
                thread::sleep(Duration::from_millis(200));
            }
            Ok(Ok(Response::Error { message })) if message.contains(ERR_CLAIMED) => {
                return Waited::Claimed;
            }
            Ok(Ok(Response::Error { message })) if message.contains(ERR_UNKNOWN_TICKET) => {
                return Waited::Unknown;
            }
            Ok(Ok(Response::Error { message })) => return Waited::Refused(message),
            Ok(Ok(other)) => return Waited::Refused(format!("unexpected reply {other:?}")),
            // Gone mid-wait (EOF, reset): same as down; the exclusive claim keeps it to one run.
            Ok(Err(ClientError::DaemonDown | ClientError::Io(_) | ClientError::Protocol(_))) => {
                return Waited::Down;
            }
            Ok(Err(e)) => return Waited::Refused(e.to_string()),
            Err(_) => return Waited::TimedOut,
        }
    }
}

/// The claim: only the process that removes the pending file runs the command, so `run` and a
/// concurrent `wait N` (or two `wait N`) never both run it. The removal is serialised by an
/// exclusive `create_new` marker: two concurrent `remove_file` calls can both succeed on Windows.
///
/// The phase lock is held throughout, so the Ctrl+C handler cannot exit between the marker and
/// the removal and leave a stale marker. Callers must not hold it (`set_phase` takes it too).
fn claim_pending(id: TicketId) -> bool {
    if store() == Some(Store::InProcess) {
        let _phase = lock_phase();
        return claim_in_process(&CLAIMED_IN_PROCESS, id);
    }
    let Some(path) = pending_path(id) else {
        return false;
    };
    let _phase = lock_phase();
    claim_pending_retrying(&path, process_alive)
}

/// How long a claim or a renewal waits for another process's `<id>.claim` to go: a renewal
/// holds it for milliseconds, so only a stuck or slow claimant outlasts this.
const MARKED_RETRY: Duration = Duration::from_secs(2);

/// Repeats `attempt` every 20 ms, for up to `MARKED_RETRY`, while `again` says so and both the
/// stored command and its claim marker are still there.
fn while_marked<T>(path: &Path, mut attempt: impl FnMut() -> T, again: impl Fn(&T) -> bool) -> T {
    let deadline = Instant::now() + MARKED_RETRY;
    let marked = || path.with_extension("claim").exists();
    loop {
        // A marker seen before OR after the attempt: it may have gone between the attempt and
        // the check, and that is exactly when the next attempt wins.
        let before = marked();
        let r = attempt();
        if !again(&r) || Instant::now() >= deadline || !path.exists() || !(before || marked()) {
            return r;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// `claim_at`, retried while a renewal (or another claimant) holds the marker (I1): the command
/// still runs at most once, and when the holder was a renewal, it runs.
fn claim_pending_retrying(path: &Path, alive: impl Fn(u32) -> Option<bool>) -> bool {
    while_marked(path, || sync_gate_probe::claim_at(path, &alive), |won| !won)
}

static CLAIMED_IN_PROCESS: Mutex<Vec<TicketId>> = Mutex::new(Vec::new());

/// `true` once per id: the in-process counterpart of removing the pending file.
fn claim_in_process(claimed: &Mutex<Vec<TicketId>>, id: TicketId) -> bool {
    let mut c = claimed.lock().unwrap_or_else(|e| e.into_inner());
    if c.contains(&id) {
        return false;
    }
    c.push(id);
    true
}

fn claimed_elsewhere(id: TicketId) -> i32 {
    set_phase(Phase::Idle);
    eprintln!(
        "sync_gate: ticket {id} is being run by another process, or its stored command expired; nothing was run here{}",
        claim_hint(id)
    );
    1
}

/// ` (<the marker files>; delete them if no sync_gate is running)`, or nothing when none exists.
fn claim_hint(id: TicketId) -> String {
    // Only a claim by another sync_gate process leaves a marker; a daemon-side claim does not.
    let hints: Vec<String> = pending_path(id)
        .into_iter()
        .flat_map(|p| {
            [
                ("marker", p.with_extension("claim")),
                ("reclaim lock", p.with_extension("claim.reclaim")),
            ]
        })
        .filter(|(_, f)| f.exists())
        .map(|(what, f)| format!("{what}: {}", f.display()))
        .collect();
    if hints.is_empty() {
        String::new()
    } else {
        format!(
            " ({}; delete them if no sync_gate is running)",
            hints.join("; ")
        )
    }
}

/// Fail-open once the daemon is gone: run directly, if this process claims the command.
fn run_unqueued(id: TicketId, p: &Pending, cwd: Option<&Path>, why: &str) -> i32 {
    set_phase(Phase::Idle);
    if !claim_pending(id) {
        return claimed_elsewhere(id);
    }
    say(why);
    run_direct(&p.argv, cwd)
}

/// `save_pending` for a requeue; debug builds can make it fail (the e2e tests, see the header).
fn save_requeued(id: TicketId, p: &Pending) -> std::io::Result<()> {
    if cfg!(debug_assertions) && std::env::var_os("SYNC_GATE_TEST_SAVE_FAILS_ON_REQUEUE").is_some()
    {
        return Err(std::io::Error::other("test: save fails on requeue"));
    }
    save_pending(id, p)
}

/// The daemon forgot ticket `old` (restart, expiry): queue the stored command again. The old
/// pending file is claimed before the new one is written, so there is never a second copy.
/// `Continue(new id)` to keep waiting, `Break(exit code)` when done.
fn requeue(old: TicketId, p: &Pending, cwd: Option<&Path>) -> ControlFlow<i32, TicketId> {
    let req = Request::Acquire {
        argv: p.argv.clone(),
        cwd: p.cwd.clone(),
        session: p.session.clone(),
        heavy: true,
    };
    let reply = call_at(&socket(), &req);
    if is_busy(&reply) {
        return ControlFlow::Break(run_unqueued(old, p, cwd, BUSY_LINE));
    }
    match reply {
        Ok(Response::Admitted { id }) => {
            set_phase(Phase::Admitted(id));
            if !claim_pending(old) {
                set_phase(Phase::Idle);
                release(id);
                return ControlFlow::Break(claimed_elsewhere(old));
            }
            ControlFlow::Break(run_admitted(id, &p.argv, cwd))
        }
        Ok(Response::Queued { id, .. }) => {
            if !claim_pending(old) {
                let _ = call_at(&socket(), &Request::Cancel { id });
                return ControlFlow::Break(claimed_elsewhere(old));
            }
            set_phase(Phase::Queued(id));
            if let Err(e) = save_requeued(id, p) {
                set_phase(Phase::Idle);
                // The old pending is already ours: give the new ticket back and run once, here.
                let _ = call_at(&socket(), &Request::Cancel { id });
                eprintln!("sync_gate: cannot save pending command ({e}); running directly");
                return ControlFlow::Break(run_direct(&p.argv, cwd));
            }
            eprintln!(
                "sync_gate: the daemon no longer knew ticket {old}; queued again as ticket {id}"
            );
            ControlFlow::Continue(id)
        }
        Err(ClientError::DaemonDown) => ControlFlow::Break(run_unqueued(old, p, cwd, DOWN_LINE)),
        other => {
            set_phase(Phase::Idle);
            eprintln!(
                "sync_gate: cannot queue ticket {old} again ({other:?}); resume with: sync_gate wait {old}"
            );
            ControlFlow::Break(1)
        }
    }
}

const RERUN_LINE: &str = "sync_gate: still queued; this sandbox cannot resume a ticket later, so it was given back: run the command again";

/// What a spent wait does: `(give the ticket back, the line to print)`. A pending file can be
/// resumed with `wait N`; an in-process ticket cannot, so it is never left dormant.
fn timeout_decision(in_process: bool, id: TicketId) -> (bool, String) {
    if in_process {
        (true, RERUN_LINE.to_owned())
    } else {
        (
            false,
            format!("queued: ticket {id} — resume with: sync_gate wait {id}"),
        )
    }
}

fn timed_out(id: TicketId) -> i32 {
    set_phase(Phase::Idle);
    let (give_back, line) = timeout_decision(store() == Some(Store::InProcess), id);
    if give_back {
        let _ = call_at(&socket(), &Request::Cancel { id });
    }
    eprintln!("{line}");
    EXIT_QUEUED
}

/// Waits in the queue, then runs the stored command; 75 if the wait runs out.
fn queue_then_run(mut id: TicketId, p: &Pending, cwd: Option<&Path>, max_wait: Option<u64>) -> i32 {
    let secs = max_wait.unwrap_or_else(|| load_config().max_wait_secs);
    let deadline = Instant::now() + Duration::from_secs(secs.min(MAX_WAIT_SECS));
    let mut requeued = false;
    loop {
        set_phase(Phase::Queued(id));
        match wait_admission(&socket(), id, deadline) {
            Waited::Admitted => {
                // Claim the command before anything runs: `wait N` must never run it twice.
                set_phase(Phase::Admitted(id));
                if !claim_pending(id) {
                    set_phase(Phase::Idle);
                    release(id);
                    return claimed_elsewhere(id);
                }
                return run_admitted(id, &p.argv, cwd);
            }
            Waited::TimedOut => return timed_out(id),
            Waited::Down => return run_unqueued(id, p, cwd, DOWN_LINE),
            Waited::Busy => {
                // Best effort: a ghost ticket is dropped by the daemon anyway.
                let _ = call_at(&socket(), &Request::Cancel { id });
                return run_unqueued(id, p, cwd, BUSY_LINE);
            }
            Waited::Claimed => return claimed_elsewhere(id),
            Waited::Unknown if INTERRUPTED.load(SeqCst) => {
                // Our own Ctrl+C cancelled it: never queue it again. Taking the phase lock waits
                // for the handler, which cleans up and exits.
                set_phase(Phase::Idle);
                return EXIT_INTERRUPTED;
            }
            // Out of time, or a ticket we just requeued was forgotten again: stop here (exit 75,
            // pending kept) instead of re-queuing forever; `sync_gate wait` resumes it.
            Waited::Unknown if requeued || Instant::now() >= deadline => return timed_out(id),
            Waited::Unknown => match requeue(id, p, cwd) {
                ControlFlow::Continue(new) => {
                    id = new;
                    requeued = true;
                }
                ControlFlow::Break(code) => return code,
            },
            Waited::Refused(why) => {
                // The pending file stays: the command is still owed a run.
                set_phase(Phase::Idle);
                eprintln!("sync_gate: {why}; resume with: sync_gate wait {id}");
                return 1;
            }
        }
    }
}

fn force_heavy() -> bool {
    matches!(
        std::env::var("SYNC_GATE_FORCE_HEAVY").as_deref(),
        Ok("1" | "true")
    )
}

/// Shim mode with an argument that is not Unicode: no daemon, no database, the program runs as
/// it is. `argv[0]` is the resolved program.
pub fn run_os_direct(argv: Vec<OsString>) -> i32 {
    let mut c = Command::new(&argv[0]);
    c.args(&argv[1..]);
    match c.status() {
        Ok(s) => exit_code(s),
        Err(e) => spawn_failure(&argv[0].to_string_lossy(), Path::new(&argv[0]), &e),
    }
}

pub fn run(session: String, max_wait: Option<u64>, argv: Vec<String>) -> i32 {
    // Inside an admitted job (a nested command, or a lease's `migrate`): the job already holds the
    // slot and its database, which the command inherits; it asks for neither again.
    if std::env::var_os("SYNC_GATE_JOB").is_some_and(|v| !v.is_empty()) {
        return match spawn(&argv, None, None, None).and_then(|mut c| c.wait().map_err(|_| 1)) {
            Ok(s) => exit_code(s),
            Err(code) => code,
        };
    }
    let os: Vec<OsString> = argv.iter().map(OsString::from).collect();
    if !is_heavy(&os) && !force_heavy() {
        return run_direct(&argv, None);
    }
    let cwd = std::env::current_dir().unwrap_or_default();
    let req = Request::Acquire {
        argv: argv.clone(),
        cwd: cwd.clone(),
        session: session.clone(),
        heavy: true,
    };
    // `set_phase` below also acts on a Ctrl+C that came while this call was in flight.
    let reply = call_at(&socket(), &req);
    match reply {
        Ok(Response::Admitted { id }) => {
            set_phase(Phase::Admitted(id));
            run_admitted(id, &argv, None)
        }
        Ok(Response::Queued { id, .. }) => {
            set_phase(Phase::Queued(id));
            let p = Pending { argv, cwd, session };
            if let Err(e) = save_pending(id, &p) {
                // Never hand out a resume ticket we cannot honour: give it back and run once,
                // here. (If the Cancel meets ERR_ADMITTED, the daemon drops the ownerless
                // ticket in 10 s.)
                set_phase(Phase::Idle);
                let _ = call_at(&socket(), &Request::Cancel { id });
                eprintln!("sync_gate: cannot save pending command ({e}); running directly");
                return run_direct(&p.argv, None);
            }
            queue_then_run(id, &p, None, max_wait)
        }
        // Ctrl+C while the Acquire was in flight, and no ticket to undo: run nothing.
        _ if INTERRUPTED.load(SeqCst) => EXIT_INTERRUPTED,
        r if is_busy(&r) => {
            eprintln!("{BUSY_LINE}");
            run_direct(&argv, None)
        }
        Ok(Response::Error { message }) => {
            eprintln!("sync_gate: daemon refused ({message}), running directly");
            run_direct(&argv, None)
        }
        Err(ClientError::DaemonDown) => {
            say(DOWN_LINE);
            run_direct(&argv, None)
        }
        Ok(_) | Err(_) => {
            eprintln!("sync_gate: daemon not responding, running directly");
            run_direct(&argv, None)
        }
    }
}

/// What `wait` prints, with exit 2, when the stored command is not there any more. The plugin
/// skill and docs/sandbox.md quote it: keep them in step.
fn gone_message(id: TicketId) -> String {
    format!(
        "sync_gate: ticket {id} expired or is gone (a stored command is deleted 25 h after it was saved or its last wait began); nothing was run: run the original command again, unless another `sync_gate wait {id}` already ran it"
    )
}

pub fn wait(id: TicketId, max_wait: Option<u64>) -> i32 {
    // First, the folder: the file read below is the one that passed the check only if nobody
    // else could have swapped it.
    #[cfg(unix)]
    if let Some(dir) = pending_path(id).and_then(|p| p.parent().map(Path::to_path_buf)) {
        use sync_gate_core::{DirState, check_private_dir};
        match check_private_dir(&dir) {
            Ok(DirState::Missing) => {
                eprintln!("{}", gone_message(id));
                return 2;
            }
            Err(e) => {
                eprintln!(
                    "sync_gate: refusing ticket {id}: {e}; nothing was run (check the folder, then chmod 700 it)"
                );
                return 2;
            }
            Ok(DirState::OthersCanRead) => {
                if let Err(e) = sync_gate_probe::create_private_dir(&dir) {
                    eprintln!("sync_gate: refusing ticket {id}: {e}; nothing was run");
                    return 2;
                }
            }
            Ok(DirState::Private) => {}
        }
    }
    let path = pending_path(id).filter(|p| p.exists());
    let Some(path) = path else {
        eprintln!("{}", gone_message(id));
        return 2;
    };
    if let Err(e) = pending_is_trusted(&path) {
        eprintln!(
            "sync_gate: refusing ticket {id}: {e}; nothing was run (run the original command again)"
        );
        return 2;
    }
    // The retention restarts before the queue, under the claim marker, so the stored command
    // cannot expire while this wait is on it; a wait that cannot renew never queues.
    let renewed = while_marked(
        &path,
        || sync_gate_probe::renew_at(&path, process_alive),
        |r| matches!(r, Renewal::Busy),
    );
    match renewed {
        Renewal::Renewed => {}
        Renewal::Busy => {
            eprintln!(
                "sync_gate: ticket {id} is being run or expired by another process right now; nothing was run here{}",
                claim_hint(id)
            );
            return 1;
        }
        Renewal::Gone => {
            eprintln!("{}", gone_message(id));
            return 2;
        }
        Renewal::Failed(e) => {
            eprintln!(
                "sync_gate: refusing ticket {id}: cannot renew its stored command ({e}); nothing was run"
            );
            return 2;
        }
    }
    let stored = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice::<Pending>(&b).ok());
    let Some(p) = stored else {
        eprintln!("sync_gate: no pending command for ticket {id} (unreadable ticket file)");
        return 2;
    };
    if p.argv.is_empty() {
        eprintln!("sync_gate: ticket {id} holds an empty command; nothing to run");
        return 2;
    }
    let cwd = p.cwd.clone();
    queue_then_run(id, &p, Some(&cwd), max_wait)
}

pub(crate) fn render(s: &StatusReport) -> String {
    use std::fmt::Write;
    let m = &s.snapshot;
    let mut o = String::new();
    let _ = write!(
        o,
        "memory: total {} MiB, available {} MiB (+{} reclaimable), swap {}/{} MiB",
        m.total / MIB,
        m.available / MIB,
        m.reclaimable / MIB,
        m.swap_used / MIB,
        m.swap_total / MIB
    );
    if let Some(v) = m.vram {
        let _ = write!(o, ", vram {}/{} MiB", v.used / MIB, v.total / MIB);
    }
    o.push_str("\nrunning:\n");
    for (id, key, rss) in &s.running {
        let _ = writeln!(o, "  #{id} {key}  peak {} MiB", rss / MIB);
    }
    o.push_str("queued:\n");
    for (id, key, pos) in &s.queued {
        let _ = writeln!(o, "  #{id} {key}  position {pos}");
    }
    let paused: Vec<String> = s.paused.iter().map(|i| format!("#{i}")).collect();
    let _ = writeln!(o, "paused: {}", paused.join(" "));
    for v in &s.services {
        let _ = write!(
            o,
            "{}: {}, {} lease(s), rss {} MiB, restarts {}",
            v.service,
            v.state,
            v.leases,
            v.rss / MIB,
            v.restarts
        );
        if v.unknown_holders > 0 {
            let _ = write!(o, ", {} with unknown owner", v.unknown_holders);
        }
        if v.cleanup_pending > 0 {
            let _ = write!(o, ", {} cleanup pending", v.cleanup_pending);
        }
        o.push('\n');
    }
    o.push_str("decisions:\n");
    for d in &s.decisions {
        let _ = writeln!(o, "  {d}");
    }
    o
}

pub fn status() -> i32 {
    match call_at(&socket(), &Request::Status) {
        Ok(Response::Status(s)) => {
            print!("{}", render(&s));
            0
        }
        Ok(other) => {
            eprintln!("sync_gate: unexpected reply {other:?}");
            1
        }
        Err(ClientError::DaemonDown) => {
            eprintln!("sync_gate: daemon not running");
            1
        }
        Err(e) => {
            eprintln!("sync_gate: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An unlisted guest gets exactly one sync_gate line: the explanation already said it, so
    /// the generic down line is dropped; the owner's down line is unchanged.
    #[test]
    fn an_explained_guest_gets_no_second_down_line() {
        assert!(down_line_wanted(DOWN_LINE, false), "the owner's line");
        assert!(
            !down_line_wanted(DOWN_LINE, true),
            "a second line for a guest"
        );
        assert!(
            down_line_wanted(BUSY_LINE, true),
            "other lines are never dropped"
        );
    }

    #[test]
    fn a_try_wait_error_is_not_an_exit() {
        let err = Some(Err(std::io::Error::other("x")));
        assert!(!child_exited(&err));
        assert!(!child_exited(&None));
    }

    #[test]
    fn refused_started_is_silent_only_when_the_child_already_exited() {
        assert!(!started_refusal_is_worth_saying(true));
        assert!(started_refusal_is_worth_saying(false));
    }

    /// Fake `Recovery`: records every pass and tree resume; answers with `outcome`.
    struct Fake {
        passes: Vec<PathBuf>,
        outcome: Outcome,
        tree_calls: u32,
        tree_fails: bool,
    }

    #[derive(Clone, Copy)]
    enum Outcome {
        Busy,
        Failed(usize),
        Unavailable,
    }

    impl Fake {
        fn new(outcome: Outcome) -> Self {
            Fake {
                passes: Vec::new(),
                outcome,
                tree_calls: 0,
                tree_fails: false,
            }
        }
    }

    impl Recovery for Fake {
        fn pass(&mut self, dir: &Path) -> RecoveryOutcome {
            self.passes.push(dir.to_owned());
            match self.outcome {
                Outcome::Busy => RecoveryOutcome::Busy,
                Outcome::Failed(failed) => RecoveryOutcome::Done {
                    resumed: 1,
                    gone: 0,
                    failed,
                },
                Outcome::Unavailable => {
                    RecoveryOutcome::Unavailable(std::io::ErrorKind::PermissionDenied.into())
                }
            }
        }
        fn tree(&mut self) -> std::io::Result<()> {
            self.tree_calls += 1;
            if self.tree_fails {
                Err(std::io::Error::other("retry tree"))
            } else {
                Ok(())
            }
        }
    }

    fn down() -> Result<Response, ClientError> {
        Err(ClientError::DaemonDown)
    }

    fn status_from(data_dir: Option<&str>, pid: u32) -> Result<Response, ClientError> {
        Ok(Response::Status(StatusReport {
            snapshot: sync_gate_core::MachineSnapshot {
                total: 0,
                available: 0,
                reclaimable: 0,
                swap_used: 0,
                swap_total: 0,
                vram: None,
            },
            running: Vec::new(),
            queued: Vec::new(),
            paused: Vec::new(),
            decisions: Vec::new(),
            mcp: Vec::new(),
            services: Vec::new(),
            daemon: DaemonInfo {
                pid,
                start_time: 7,
                data_dir: data_dir.map(PathBuf::from),
            },
        }))
    }

    const LOST: &str = "sync_gate: daemon lost, continuing without queue";

    /// Polls once per second from `t0`, returning every printed line.
    fn polls(
        w: &mut Watch,
        t0: Instant,
        replies: impl IntoIterator<Item = Result<Response, ClientError>>,
        r: &mut Fake,
        gate: &ReapGate,
    ) -> Vec<String> {
        let mut out = Vec::new();
        for (i, reply) in replies.into_iter().enumerate() {
            out.extend(w.poll(t0 + Duration::from_secs(i as u64), &reply, r, gate));
        }
        out
    }

    #[test]
    fn a_busy_daemon_counts_as_connected_and_says_nothing() {
        let mut w = Watch::new(None);
        let mut fake = Fake::new(Outcome::Busy);
        let out = polls(
            &mut w,
            Instant::now(),
            (0..3).map(|_| Err(ClientError::Busy)),
            &mut fake,
            &ReapGate::default(),
        );
        assert_eq!(w.failures, 0);
        assert!(!w.lost);
        assert!(out.is_empty(), "{out:?}");
        assert_eq!(fake.tree_calls, 0);
    }

    #[test]
    fn only_busy_replies_are_busy() {
        let err = |m: &str| {
            Ok(Response::Error {
                message: m.to_owned(),
            })
        };
        assert!(is_busy(&Err(ClientError::Busy)));
        assert!(is_busy(&err(
            "the queue is busy for this account (8 live tickets)"
        )));
        assert!(!is_busy(&err("boom")));
        assert!(!is_busy(&err("ticket #7 was cancelled or is unknown")));
        assert!(!is_busy(&down()));
        assert!(!is_busy(&Ok(Response::Ack)));
    }

    #[test]
    fn the_in_process_store_never_leaves_a_resumable_ticket() {
        let p = Pending {
            argv: vec!["x".into()],
            cwd: PathBuf::from("."),
            session: "s".into(),
        };
        let dir = std::env::temp_dir().join(format!("sync_gate-inproc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // InProcess: save writes nothing; claim is true once per id.
        save_in(&Some(Store::InProcess), 7, &p).unwrap();
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        assert_eq!(pending_in(&Some(Store::InProcess), 7), None);
        let claimed = Mutex::new(Vec::new());
        assert!(claim_in_process(&claimed, 7));
        assert!(!claim_in_process(&claimed, 7));
        assert!(claim_in_process(&claimed, 8));
        // timed_out: InProcess cancels and says RERUN_LINE; Disk is the line of today.
        assert_eq!(timeout_decision(true, 7), (true, RERUN_LINE.to_owned()));
        assert_eq!(
            timeout_decision(false, 7),
            (
                false,
                "queued: ticket 7 — resume with: sync_gate wait 7".to_owned()
            )
        );
        // Disk still writes its file (control).
        save_in(&Some(Store::Disk(dir.clone())), 7, &p).unwrap();
        assert!(dir.join("pending").join("7.json").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_store_follows_the_kind_and_the_override() {
        let env = || Some(PathBuf::from("override"));
        let own = || Some(PathBuf::from(r"C:\Users\sandbox"));
        let default = || Some(PathBuf::from("owner-data"));
        let acc = SelfKind::Account("sandbox".into());
        let pick = |k: &SelfKind, e, o, d| pick_store(k, e, o, d);
        // SYNC_GATE_DATA_DIR always wins.
        for k in [
            SelfKind::Owner,
            SelfKind::AppContainer,
            SelfKind::Restricted,
            SelfKind::Account("sandbox".into()),
        ] {
            assert_eq!(
                pick(&k, env(), own(), default()),
                Some(Store::Disk("override".into()))
            );
        }
        assert_eq!(
            pick(&SelfKind::AppContainer, None, None, default()),
            Some(Store::InProcess)
        );
        assert_eq!(
            pick(&SelfKind::Restricted, None, own(), default()),
            Some(Store::InProcess)
        );
        // Unix `join` puts `/` after the profile; `\` is an ordinary character there.
        #[cfg(windows)]
        let account_dir = r"C:\Users\sandbox\AppData\Roaming\sync_labs\sync_gate\data";
        #[cfg(not(windows))]
        let account_dir = r"C:\Users\sandbox/AppData\Roaming\sync_labs\sync_gate\data";
        assert_eq!(
            pick(&acc, None, own(), default()),
            Some(Store::Disk(PathBuf::from(account_dir)))
        );
        // An account whose profile cannot be read never falls back to the owner's folder.
        assert_eq!(pick(&acc, None, None, default()), Some(Store::InProcess));
        assert_eq!(
            pick(&SelfKind::Owner, None, own(), default()),
            Some(Store::Disk("owner-data".into()))
        );
        assert_eq!(pick(&SelfKind::Owner, None, None, None), None);
    }

    #[test]
    fn with_a_data_dir_the_tree_is_never_resumed_and_every_failed_connect_runs_a_pass() {
        let mut w = Watch::new(Some(PathBuf::from("local")));
        let mut fake = Fake::new(Outcome::Failed(0));
        let out = polls(
            &mut w,
            Instant::now(),
            (0..10).map(|_| down()),
            &mut fake,
            &ReapGate::default(),
        );
        assert_eq!(fake.tree_calls, 0, "the intent record covers the tree");
        assert_eq!(fake.passes.len(), 10);
        assert_eq!(out, vec![LOST.to_string()]);
        assert!(w.lost);
    }

    #[test]
    fn the_lost_line_needs_three_consecutive_failed_connects() {
        let mut w = Watch::new(Some(PathBuf::from("local")));
        let mut fake = Fake::new(Outcome::Busy);
        let gate = ReapGate::default();
        let t0 = Instant::now();
        // Slow is not gone: a timeout or any reply resets the count.
        let replies = [
            down(),
            down(),
            Err(ClientError::Timeout),
            down(),
            Ok(Response::Ack),
            down(),
            down(),
        ];
        assert!(polls(&mut w, t0, replies, &mut fake, &gate).is_empty());
        assert!(!w.lost);
        assert_eq!(
            w.poll(t0 + Duration::from_secs(9), &down(), &mut fake, &gate),
            vec![LOST.to_string()]
        );
        assert!(w.lost);
    }

    #[test]
    fn busy_does_nothing_and_a_connected_poll_runs_no_pass() {
        let mut w = Watch::new(Some(PathBuf::from("local")));
        let mut fake = Fake::new(Outcome::Busy);
        let replies = [down(), Ok(Response::Ack), Ok(Response::Ack)];
        let out = polls(
            &mut w,
            Instant::now(),
            replies,
            &mut fake,
            &ReapGate::default(),
        );
        assert!(out.is_empty());
        assert_eq!(fake.passes.len(), 1, "only the failed connect ran a pass");
    }

    #[test]
    fn failures_are_retried_every_poll_and_the_give_up_line_is_printed_once() {
        let mut w = Watch::new(Some(PathBuf::from("local")));
        let mut fake = Fake::new(Outcome::Failed(2));
        let gate = ReapGate::default();
        let t0 = Instant::now();
        // One failed connect, then the daemon answers again (another daemon, not ours).
        let replies = std::iter::once(down()).chain((0..40).map(|_| Ok(Response::Ack)));
        let out = polls(&mut w, t0, replies, &mut fake, &gate);
        let give_up = "sync_gate: could not resume 2 paused unit(s) after losing the daemon";
        assert_eq!(out, vec![give_up.to_string()]);
        assert_eq!(
            fake.passes.len(),
            31,
            "retried once per poll for 30 s, then stopped"
        );
        // A later failed connect still runs a pass (never leave a process frozen), quietly.
        let later = w.poll(t0 + Duration::from_secs(90), &down(), &mut fake, &gate);
        assert!(later.is_empty());
        assert_eq!(fake.passes.len(), 32);
    }

    #[test]
    fn an_unusable_lock_is_reported_once_and_retried() {
        let mut w = Watch::new(Some(PathBuf::from("local")));
        let mut fake = Fake::new(Outcome::Unavailable);
        let out = polls(
            &mut w,
            Instant::now(),
            (0..5).map(|_| down()),
            &mut fake,
            &ReapGate::default(),
        );
        let unavailable: Vec<_> = out
            .iter()
            .filter(|l| l.starts_with("sync_gate: cannot recover paused units"))
            .collect();
        assert_eq!(unavailable.len(), 1, "{out:?}");
        assert_eq!(fake.passes.len(), 5);
    }

    #[test]
    fn the_daemons_own_data_dir_wins_over_the_local_one() {
        let gate = ReapGate::default();
        let t0 = Instant::now();
        let mut w = Watch::new(Some(PathBuf::from("local")));
        let mut fake = Fake::new(Outcome::Busy);
        polls(
            &mut w,
            t0,
            [status_from(Some("daemon"), 9), down()],
            &mut fake,
            &gate,
        );
        assert_eq!(fake.passes, vec![PathBuf::from("daemon")]);
        // A daemon that predates DaemonInfo (pid 0) tells nothing: the local dir is used.
        let mut w = Watch::new(Some(PathBuf::from("local")));
        let mut fake = Fake::new(Outcome::Busy);
        polls(&mut w, t0, [status_from(None, 0), down()], &mut fake, &gate);
        assert_eq!(fake.passes, vec![PathBuf::from("local")]);
        // A daemon that keeps no files: no record, no lock, so the tree rule applies.
        let mut w = Watch::new(Some(PathBuf::from("local")));
        let mut fake = Fake::new(Outcome::Busy);
        let replies = std::iter::once(status_from(None, 9)).chain((0..3).map(|_| down()));
        polls(&mut w, t0, replies, &mut fake, &gate);
        assert!(fake.passes.is_empty());
        assert_eq!(fake.tree_calls, 1);
    }

    /// A `Recovery` that can move into the post-exit thread and still be observed.
    struct Shared {
        passes: Arc<Mutex<Vec<PathBuf>>>,
        block: Duration,
    }

    impl Recovery for Shared {
        fn pass(&mut self, dir: &Path) -> RecoveryOutcome {
            self.passes.lock().unwrap().push(dir.to_owned());
            thread::sleep(self.block);
            RecoveryOutcome::Busy
        }
        fn tree(&mut self) -> std::io::Result<()> {
            panic!("the post-exit pass never resumes a tree")
        }
    }

    /// Runs the post-exit step and returns how many passes started and how long it took.
    fn post_exit(
        dir: Option<&str>,
        finished: Option<Result<Response, ClientError>>,
        block: Duration,
        limit: Duration,
    ) -> (usize, Duration) {
        let w = Watch::new(dir.map(PathBuf::from));
        let passes = Arc::new(Mutex::new(Vec::new()));
        let r = Shared {
            passes: passes.clone(),
            block,
        };
        let t = Instant::now();
        post_exit_pass(&w, finished.as_ref(), r, limit);
        let took = t.elapsed();
        // The pass runs on its own thread: give a started one a moment to record itself.
        thread::sleep(Duration::from_millis(20));
        let n = passes.lock().unwrap().len();
        (n, took)
    }

    #[test]
    fn the_post_exit_pass_is_skipped_only_when_finished_was_answered() {
        let none = Duration::ZERO;
        let lim = Duration::from_secs(1);
        let answered = post_exit(Some("d"), Some(Ok(Response::Ack)), none, lim);
        assert_eq!(answered.0, 0, "Finished answered: the daemon resumed");
        let protocol = Err(ClientError::Protocol(
            "connection closed before a reply".into(),
        ));
        assert_eq!(post_exit(Some("d"), Some(protocol), none, lim).0, 1);
        let io = Err(ClientError::Io(std::io::ErrorKind::BrokenPipe.into()));
        assert_eq!(post_exit(Some("d"), Some(io), none, lim).0, 1);
        let timeout = Err(ClientError::Timeout);
        assert_eq!(post_exit(Some("d"), Some(timeout), none, lim).0, 1);
        let refused = Ok(Response::Error {
            message: "no".into(),
        });
        assert_eq!(post_exit(Some("d"), Some(refused), none, lim).0, 1);
        assert_eq!(post_exit(Some("d"), None, none, lim).0, 1, "daemon lost");
        assert_eq!(post_exit(None, None, none, lim).0, 0, "no data dir");
    }

    #[test]
    fn the_post_exit_pass_respects_its_bound() {
        let (n, took) = post_exit(
            Some("d"),
            None,
            Duration::from_secs(5),
            Duration::from_millis(60),
        );
        assert_eq!(n, 1);
        assert!(
            took < Duration::from_secs(2),
            "returned at the bound: {took:?}"
        );
    }

    #[test]
    fn without_a_data_dir_the_tree_is_resumed_after_three_failures_and_never_after_reaping() {
        let t0 = Instant::now();
        let gate = ReapGate::default();
        let mut w = Watch::new(None);
        let mut fake = Fake::new(Outcome::Busy);
        fake.tree_fails = true;
        polls(&mut w, t0, [down(), down()], &mut fake, &gate);
        assert_eq!(fake.tree_calls, 0);
        polls(
            &mut w,
            t0 + Duration::from_secs(2),
            [down(), down()],
            &mut fake,
            &gate,
        );
        assert_eq!(fake.tree_calls, 2, "a failing tree resume is retried");
        assert_eq!(gate.try_reap(|| Some(())), Some(()));
        polls(
            &mut w,
            t0 + Duration::from_secs(4),
            [down(), down()],
            &mut fake,
            &gate,
        );
        assert_eq!(fake.tree_calls, 2, "a reaped pid may belong to a stranger");
        assert!(fake.passes.is_empty());
    }

    #[test]
    fn reaping_and_the_tree_resume_race_and_the_resume_never_runs_after_reaped() {
        use std::sync::atomic::AtomicUsize;
        let late = Arc::new(AtomicUsize::new(0));
        for _ in 0..200 {
            let gate = Arc::new(ReapGate::default());
            // Stands for "the pid was released to the OS": set only by the reaper.
            let released = Arc::new(AtomicBool::new(false));
            let start = Arc::new(std::sync::Barrier::new(2));
            let resumer = {
                let (gate, released, start, late) =
                    (gate.clone(), released.clone(), start.clone(), late.clone());
                thread::spawn(move || {
                    start.wait();
                    for _ in 0..50 {
                        gate.unless_reaped(|| {
                            for _ in 0..20 {
                                if released.load(SeqCst) {
                                    late.fetch_add(1, SeqCst);
                                }
                                std::hint::spin_loop();
                            }
                        });
                    }
                })
            };
            start.wait();
            gate.try_reap(|| {
                released.store(true, SeqCst);
                Some(())
            });
            resumer.join().unwrap();
        }
        assert_eq!(late.load(SeqCst), 0, "a tree resume ran after the reap");
    }

    /// T3.4
    #[test]
    fn guest_sweeps_only_in_its_own_account_store() {
        let account = SelfKind::Account("sandbox".into());
        assert!(!guest_sweeps(&SelfKind::Owner, false));
        assert_eq!(guest_sweeps(&account, false), cfg!(windows));
        assert!(!guest_sweeps(&account, true));
        assert!(!guest_sweeps(&SelfKind::AppContainer, false));
        assert!(!guest_sweeps(&SelfKind::Restricted, false));
    }

    fn pending_test_dir(tag: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("sync_gate-pending-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        sync_gate_probe::create_private_dir(&d.join("pending")).unwrap();
        d
    }

    fn put_aged(path: &Path, age: Duration) {
        std::fs::write(path, "{}").unwrap();
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(std::time::SystemTime::now() - age)
            .unwrap();
    }

    /// T3.5
    #[test]
    fn the_guest_store_sweeps_after_saving() {
        for sweeps in [true, false] {
            let d = pending_test_dir(&format!("guest-{sweeps}"));
            let old = d.join("pending").join("1.json");
            put_aged(&old, Duration::from_secs(26 * 3600));
            let p = Pending {
                argv: vec!["x".into()],
                cwd: d.clone(),
                session: "s".into(),
            };
            save_and_sweep(&Some(Store::Disk(d.clone())), 9, &p, sweeps).unwrap();
            assert_eq!(old.exists(), !sweeps, "sweeps: {sweeps}");
            assert!(
                d.join("pending").join("9.json").exists(),
                "sweeps: {sweeps}"
            );
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    /// The marker goes between a failed attempt and the check after it (the race the e2e of
    /// T3.6 met once): the claim still tries again and wins.
    #[test]
    fn a_marker_gone_right_after_a_failed_attempt_still_gets_a_retry() {
        let d = pending_test_dir("gone-after");
        let p = d.join("pending").join("7.json");
        let marker = p.with_extension("claim");
        std::fs::write(&p, "{}").unwrap();
        std::fs::write(&marker, "4242").unwrap();
        let mut calls = 0;
        let won = while_marked(
            &p,
            || {
                calls += 1;
                // The first attempt loses to the marker, which its holder removes right after.
                let _ = std::fs::remove_file(&marker);
                calls == 2
            },
            |won| !won,
        );
        assert!(won && calls == 2, "won {won}, {calls} attempt(s)");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// T3.6 (unit control of I1): the claim waits for a marker only while it and the stored
    /// command are both there, and for 2 s at most.
    #[test]
    fn a_claim_retries_only_while_a_marker_holds_the_stored_command() {
        let live = |_| Some(true);
        let d = pending_test_dir("retry");
        let p = d.join("pending").join("7.json");
        let marker = p.with_extension("claim");
        // A marker that goes after 100 ms (a renewal): the claim wins.
        std::fs::write(&p, "{}").unwrap();
        std::fs::write(&marker, "4242").unwrap();
        let (tx, rx) = mpsc::channel();
        {
            let marker = marker.clone();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(100));
                let _ = tx.send(std::fs::remove_file(&marker).is_ok());
            });
        }
        assert!(claim_pending_retrying(&p, live));
        assert!(rx.recv_timeout(Duration::from_secs(10)).unwrap());
        assert!(!p.exists() && !marker.exists());
        // A marker that never goes: false after about 2 s, the file stays.
        std::fs::write(&p, "{}").unwrap();
        std::fs::write(&marker, "4242").unwrap();
        let t = Instant::now();
        assert!(!claim_pending_retrying(&p, live));
        let took = t.elapsed();
        assert!(
            took >= Duration::from_millis(1900) && took < Duration::from_secs(5),
            "{took:?}"
        );
        assert!(p.exists() && marker.exists());
        // The stored command goes during the retry: false at once.
        let (tx, rx) = mpsc::channel();
        {
            let p = p.clone();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(100));
                let _ = tx.send(std::fs::remove_file(&p).is_ok());
            });
        }
        let t = Instant::now();
        assert!(!claim_pending_retrying(&p, live));
        assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
        assert!(rx.recv_timeout(Duration::from_secs(10)).unwrap());
        // No marker: one attempt only.
        std::fs::remove_file(&marker).unwrap();
        let t = Instant::now();
        assert!(!claim_pending_retrying(&p, live));
        assert!(
            t.elapsed() < Duration::from_millis(500),
            "{:?}",
            t.elapsed()
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
