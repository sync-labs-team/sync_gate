//! Supervisor for processes the daemon itself starts (the MCP hub's servers).
//!
//! THIS IS THE ONLY PLACE IN THE PROJECT THAT TERMINATES A PROCESS, and only processes this
//! daemon started itself (its own children, or rows left in the [`Registry`] by a previous
//! run). Anything else, an agent's or the user's process, is never touched: everywhere else
//! sync_gate only suspends and resumes. Identity (pid + process start time + executable path)
//! is verified like this. The start time is the full creation FILETIME (100 ns ticks) on
//! Windows and whole seconds on Unix; a Windows row recorded in seconds by an older version
//! never matches, so it is forgotten without touching the process (children live in a
//! kill-on-close Job Object, so a leftover is rare):
//! - own child (kept in the launcher's table with its `Child`): the unreaped zombie (Unix) or
//!   open handle (Windows) pins the pid, so it cannot belong to anyone else. That held handle
//!   (and job / process group) IS the identity: the child is stopped through it even when its
//!   start time could not be read (recorded as 0). The caller's start time must still equal
//!   the one recorded at spawn, checked while the table lock is held across the signal.
//! - leftover from disk (no handle): pid + start time + exe path must all equal the recorded
//!   row (`reap_leftovers` compares the exe; Windows also re-reads the start time and the
//!   liveness from the very handle it terminates; Unix has no pidfd, see `kill_foreign`).
//!
//! A leftover whose start time is 0 or unreadable is unverifiable and is never terminated; on
//! Unix a leftover is also signalled only if it leads its own process group and that group is
//! not the daemon's. Pids 0, 1 and the daemon's own are refused outright.
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, mpsc};
use std::time::{Duration, Instant};

/// A freshly started child: identity for the registry plus its pipes.
pub struct Spawned {
    pub pid: u32,
    /// Process start time (Windows: FILETIME ticks from the child's handle; Unix: probe
    /// seconds); 0 = unknown. A leftover row with 0 is never terminated; while the launcher
    /// still holds the child, its handle is the identity and it is stopped through it.
    pub start_time: u64,
    pub exe: PathBuf,
    pub stdin: Box<dyn Write + Send>,
    pub stdout: Box<dyn Read + Send>,
}

pub trait Launcher: Send + Sync {
    /// Starts `command` with the daemon's environment plus `env`, minus every name in
    /// `env_remove` (forwarded variables the session does not have).
    fn spawn(
        &self,
        command: &str,
        args: &[String],
        env: &BTreeMap<String, String>,
        env_remove: &[String],
        cwd: Option<&Path>,
    ) -> io::Result<Spawned>;
    /// For a foreign process (not a child of this launcher) on Windows with a recorded start
    /// time, false only when it is known to be gone or known to be another one (its start time
    /// differs). True when it is the recorded process, and also when its state or start time
    /// cannot be read (the open, the wait or the creation-time query failed), so no caller
    /// reports a stop or drops a row on a guess. True is no leave to signal: `terminate`
    /// verifies again and refuses, with an error, a process it cannot identify.
    /// Not covered by that guarantee, false without proof: a recorded start time of 0 (a
    /// foreign process is never ours then); on Unix, a probe that cannot read the start time;
    /// and a child of this launcher whose exit cannot be observed and cannot be confirmed
    /// running (its entry is dropped).
    fn is_alive(&self, pid: u32, start_time: u64) -> bool;
    /// Terminates the process (and the tree it started) if it still matches `start_time`.
    fn terminate(&self, pid: u32, start_time: u64) -> io::Result<()>;
    /// False when `pid`'s identity (state, start time) cannot be read, so it can be neither
    /// confirmed as the recorded process nor ruled out. A launcher that cannot tell says true.
    fn identity_readable(&self, _pid: u32, _start_time: u64) -> bool {
        true
    }
    /// Executable path of the live process `pid`, if the OS can tell.
    fn exe_of(&self, _pid: u32) -> Option<PathBuf> {
        None
    }
    /// The file `spawn` would run for `command` with `env`: a bare name found the way the agent
    /// finds it, a name with a folder part as is; `None` when a bare name is found nowhere (the
    /// hub then does not run it: the session does). A launcher with no lookup of its own runs
    /// the name as given.
    fn resolve(&self, command: &str, _env: &BTreeMap<String, String>) -> Option<PathBuf> {
        Some(PathBuf::from(command))
    }
    /// Drops what the launcher still holds for a stopped child (reaps it); its exit code when
    /// known.
    fn reap(&self, _pid: u32) -> Option<i32> {
        None
    }
}

/// Restart delay: 1 s, 2 s, 4 s ... capped at 30 s. The caller resets it after 60 s of uptime.
#[derive(Default)]
pub struct Backoff {
    failures: u32,
}

impl Backoff {
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Duration {
        let secs = (1u64 << self.failures.min(5)).min(30);
        self.failures = self.failures.saturating_add(1);
        Duration::from_secs(secs)
    }

    pub fn reset(&mut self) {
        self.failures = 0;
    }
}

/// Server names, pids, start times and exe paths in `<data_dir>/services.json`.
/// Never environment values or arguments: they can hold secrets.
pub struct Registry {
    path: PathBuf,
    rows: Vec<(String, u32, u64, String)>,
}

impl Registry {
    pub fn load(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            rows: crate::store::load_services(path),
        }
    }

    pub fn record(&mut self, name: &str, pid: u32, start_time: u64, exe: &Path) {
        self.rows.retain(|r| r.1 != pid);
        let exe = exe.to_string_lossy().into_owned();
        self.rows.push((name.to_string(), pid, start_time, exe));
        self.persist();
    }

    pub fn forget(&mut self, pid: u32) {
        self.rows.retain(|r| r.1 != pid);
        self.persist();
    }

    pub fn leftovers(&self) -> Vec<(String, u32, u64, PathBuf)> {
        let row = |r: &(String, u32, u64, String)| (r.0.clone(), r.1, r.2, PathBuf::from(&r.3));
        self.rows.iter().map(row).collect()
    }

    /// A failed write is reported, not fatal: the child is already running.
    fn persist(&self) {
        if let Err(e) = crate::store::save_services(&self.path, &self.rows) {
            eprintln!("sync_gated: cannot save {}: {e}", self.path.display());
        }
    }
}

static POISONINGS: AtomicU64 = AtomicU64::new(0);

/// A panic on another thread must not take the daemon down with it: a poisoned lock is
/// recovered (and cleared, so it counts once) and counted for the hub to note.
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| {
        POISONINGS.fetch_add(1, Ordering::SeqCst);
        m.clear_poison();
        e.into_inner()
    })
}

/// Locks recovered by [`lock`] since the daemon started.
pub(crate) fn poisonings() -> u64 {
    POISONINGS.load(Ordering::SeqCst)
}

/// Graceful stop of a child this daemon started: close its stdin (a well-behaved MCP server
/// exits on EOF), wait up to `grace` for it to go, then, if the identity still matches,
/// terminate it. On success the launcher releases (reaps) the child and its exit code, when
/// known, is returned.
pub fn stop_own(
    l: &dyn Launcher,
    pid: u32,
    start_time: u64,
    stdin: Option<Box<dyn Write + Send>>,
    grace: Duration,
) -> io::Result<Option<i32>> {
    drop(stdin);
    let deadline = Instant::now() + grace;
    loop {
        // This check doubles as the identity verification right before `terminate`.
        if !l.is_alive(pid, start_time) {
            return Ok(l.reap(pid));
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            l.terminate(pid, start_time)?;
            return Ok(l.reap(pid));
        }
        std::thread::sleep(left.min(Duration::from_millis(50)));
    }
}

/// Daemon start: stop what a previous run left behind. Entries that still match pid + start
/// time + exe path are terminated (their stdin pipe died with the old daemon); one that is gone
/// or is another process (start time or exe differs) is forgotten. The row is kept, for the
/// next start, when something could not be read (the exe, the identity; `terminate` checks the
/// identity again) or the stop failed. No row is begun after `LEFTOVER_DEADLINE`: the rest
/// stay for the next start. Returns how many were terminated.
pub fn reap_leftovers(l: &dyn Launcher, reg: &mut Registry) -> usize {
    reap_leftovers_until(l, reg, Instant::now() + LEFTOVER_DEADLINE)
}

/// Each of `OsLauncher::terminate`'s two rounds waits up to this long for the process to go.
const KILL_WAIT_SECS: u64 = 2;

/// The daemon start spends at most about 10 s stopping leftovers: no stop begins later than
/// 10 s minus the longest one (two terminate rounds), so one begun at the deadline still ends
/// by then, give or take the OS queries.
const LEFTOVER_DEADLINE: Duration = Duration::from_secs(10 - 2 * KILL_WAIT_SECS);

fn reap_leftovers_until(l: &dyn Launcher, reg: &mut Registry, deadline: Instant) -> usize {
    let mut stopped = 0;
    let rows = reg.leftovers();
    let total = rows.len();
    for (n, (name, pid, start_time, exe)) in rows.into_iter().enumerate() {
        if Instant::now() >= deadline {
            let kept = total - n;
            eprintln!("sync_gated: leftover cleanup out of time; {kept} kept for the next start");
            break;
        }
        if l.is_alive(pid, start_time) {
            match l.exe_of(pid) {
                // unreadable is not "another program": neither stopped nor forgotten
                None => {
                    eprintln!("sync_gated: cannot read the exe of leftover {name} (pid {pid})");
                    continue;
                }
                Some(e) if e != exe => {}
                // same exe but cannot be told apart from another process: never signalled,
                // and kept, unlike a refused target
                Some(_) if !l.identity_readable(pid, start_time) => {
                    eprintln!("sync_gated: cannot verify leftover {name} (pid {pid}); kept");
                    continue;
                }
                Some(_) => match l.terminate(pid, start_time) {
                    Ok(()) => stopped += 1,
                    // refused as a target (pid 0, 1, ours): no retry will ever work
                    Err(e) if e.kind() == io::ErrorKind::InvalidInput => {}
                    Err(e) => {
                        // keep the row: the next start tries again
                        eprintln!("sync_gated: cannot stop leftover {name} (pid {pid}): {e}");
                        continue;
                    }
                },
            }
        }
        reg.forget(pid);
    }
    stopped
}

/// A child this daemon started: its handle pins the pid until it is reaped.
struct Owned {
    child: Child,
    start_time: u64,
    /// Windows Job Object holding the whole tree (0 = none; always 0 on Unix).
    job: Job,
}

type Job = usize;

impl Drop for Owned {
    fn drop(&mut self) {
        close_job(self.job);
    }
}

/// The real launcher. Keeps each child in `children` (keyed by pid): the unreaped `Child`
/// keeps its pid from being reused while we signal it, and `try_wait` reaps it (no zombie).
#[derive(Default)]
pub struct OsLauncher {
    children: Mutex<std::collections::HashMap<u32, Owned>>,
    /// Exit codes of children `is_alive` saw exit and dropped, until `reap` takes them or a
    /// new child takes the pid.
    exits: Mutex<std::collections::HashMap<u32, i32>>,
}

impl OsLauncher {
    /// One signal round. Own children are signalled with the table lock held, so nobody can
    /// reap them (and free the pid) between the check and the signal.
    fn kill_once(&self, pid: u32, start_time: u64, hard: bool) -> io::Result<()> {
        let mut children = lock(&self.children);
        if let Some(o) = children.get_mut(&pid) {
            return if o.start_time == start_time {
                kill_own(o, hard)
            } else {
                Ok(())
            };
        }
        drop(children);
        if !self.is_alive(pid, start_time) {
            return Ok(());
        }
        kill_foreign(pid, start_time, hard)
    }
}

impl OsLauncher {
    /// Holds a new child under `pid`. A code kept for an older child on the same pid is
    /// dropped first: it is not this child's.
    fn track(&self, pid: u32, owned: Owned) {
        self.note_exit(pid, None);
        lock(&self.children).insert(pid, owned);
    }

    /// Keeps `code` as the exit of the child just dropped under `pid`; `None` (no code, as
    /// after a signal on Unix) forgets any code kept for an older child on that pid.
    fn note_exit(&self, pid: u32, code: Option<i32>) {
        let mut exits = lock(&self.exits);
        match code {
            Some(code) => exits.insert(pid, code),
            None => exits.remove(&pid),
        };
    }

    /// `is_alive`, with the exit observation (`observe`) and the group signal for a leader
    /// that has gone (`on_gone`) injectable.
    fn is_alive_with(
        &self,
        pid: u32,
        start_time: u64,
        observe: &mut dyn FnMut(&mut Child) -> io::Result<bool>,
        on_gone: &mut dyn FnMut(&mut Owned),
    ) -> bool {
        let mut children = lock(&self.children);
        if let Some(o) = children.get_mut(&pid) {
            match observe(&mut o.child) {
                // The held handle is the identity; the recorded start time (even 0) must match.
                Ok(false) => return o.start_time == start_time,
                // Leader gone but still unreaped, so its pid and group id are still ours:
                // take the rest of its tree down now. Windows: dropping the entry closes the
                // job, same effect.
                Ok(true) => on_gone(o),
                // Not observable (Unix): signal nothing. A child still running is still ours.
                Err(_) => {
                    if let Ok(None) = o.child.try_wait() {
                        return o.start_time == start_time;
                    }
                }
            }
            // Reaped last; nothing is signalled after this.
            let code = o.child.try_wait().ok().flatten().and_then(|s| s.code());
            self.note_exit(pid, code);
            children.remove(&pid);
            return false;
        }
        drop(children);
        // 0 = unverifiable: never ours.
        if start_time == 0 {
            return false;
        }
        #[cfg(windows)]
        {
            foreign_is_alive(pid, start_time)
        }
        // An unreadable probe reads as None: not ours.
        #[cfg(not(windows))]
        {
            sync_gate_probe::start_time(pid) == Some(start_time)
        }
    }
}

/// A command with no folder part (`npx`): the OS looks it up through `PATH`.
pub(crate) fn is_bare(command: &str) -> bool {
    !command
        .chars()
        .any(|c| std::path::is_separator(c) || (cfg!(windows) && c == ':'))
}

/// Unix: the `PATH` a bare command is looked up in (the server's, else the daemon's) has an empty
/// or relative entry, which means a folder of the child's, not of the daemon's. Windows never
/// searches such an entry.
pub(crate) fn path_has_relative_entry(env: &BTreeMap<String, String>) -> bool {
    #[cfg(unix)]
    {
        let path = path_of(env)
            .map(std::ffi::OsString::from)
            .or_else(|| std::env::var_os("PATH"));
        path.is_some_and(|p| std::env::split_paths(&p).any(|d| !d.is_absolute()))
    }
    #[cfg(not(unix))]
    {
        let _ = env;
        false
    }
}

/// `PATH` of a server's environment (any case on Windows, where names ignore case).
fn path_of(env: &BTreeMap<String, String>) -> Option<&str> {
    env.iter()
        .find(|(k, _)| k.as_str() == "PATH" || (cfg!(windows) && k.eq_ignore_ascii_case("PATH")))
        .map(|(_, v)| v.as_str())
}

impl Launcher for OsLauncher {
    fn spawn(
        &self,
        command: &str,
        args: &[String],
        env: &BTreeMap<String, String>,
        env_remove: &[String],
        cwd: Option<&Path>,
    ) -> io::Result<Spawned> {
        // Never a bare name to `Command`: its own search could pick a sync_gate shim that this
        // one skipped. Found nowhere safe, the caller falls back to the session.
        let program = self
            .resolve(command, env)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "program not found"))?;
        let mut cmd = Command::new(&program);
        for name in env_remove {
            cmd.env_remove(name);
        }
        cmd.args(args)
            .envs(env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let Some(cwd) = cwd {
            cmd.current_dir(cwd);
        }
        isolate(&mut cmd);
        let mut child = cmd.spawn()?;
        // First thing: the probe below is slow and a grandchild started meanwhile escapes the job.
        let job = open_job(&child);
        let pid = child.id();
        // Windows: the full creation time from the child's own handle; Unix: the probe's seconds.
        #[cfg(windows)]
        let start_time = {
            use std::os::windows::io::AsRawHandle;
            handle_start_time(child.as_raw_handle()).unwrap_or(0)
        };
        #[cfg(not(windows))]
        let start_time = sync_gate_probe::start_time(pid).unwrap_or(0);
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            // Never leave an untracked child running.
            let mut o = Owned {
                child,
                start_time,
                job,
            };
            let _ = kill_own(&mut o, true);
            let _ = o.child.wait();
            return Err(io::ErrorKind::BrokenPipe.into());
        };
        self.track(
            pid,
            Owned {
                child,
                start_time,
                job,
            },
        );
        Ok(Spawned {
            pid,
            start_time,
            exe: process_exe(pid).unwrap_or(program),
            stdin: Box::new(stdin),
            stdout: Box::new(stdout),
        })
    }

    /// A bare name through the server's own `PATH` (else the daemon's), the daemon's `PATHEXT`
    /// and folder, as the agent would find it (`npx` is `npx.cmd` on Windows).
    fn resolve(&self, command: &str, env: &BTreeMap<String, String>) -> Option<PathBuf> {
        if !is_bare(command) {
            return Some(PathBuf::from(command));
        }
        let path = path_of(env).map(std::ffi::OsString::from);
        sync_gate_core::program::find_program(
            std::ffi::OsStr::new(command),
            path.or_else(|| std::env::var_os("PATH")).as_deref(),
            std::env::var_os("PATHEXT").as_deref(),
            &std::env::current_dir().unwrap_or_default(),
        )
    }

    fn is_alive(&self, pid: u32, start_time: u64) -> bool {
        self.is_alive_with(pid, start_time, &mut exited_unreaped, &mut |o| {
            let _ = kill_own(o, true);
        })
    }

    fn terminate(&self, pid: u32, start_time: u64) -> io::Result<()> {
        check_target(pid)?;
        let wait_gone = |limit: Duration| {
            let end = Instant::now() + limit;
            while self.is_alive(pid, start_time) {
                if Instant::now() >= end {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            true
        };
        if !self.is_alive(pid, start_time) {
            return Ok(());
        }
        self.kill_once(pid, start_time, false)?;
        if wait_gone(Duration::from_secs(KILL_WAIT_SECS)) {
            return Ok(());
        }
        self.kill_once(pid, start_time, true)?;
        if wait_gone(Duration::from_secs(KILL_WAIT_SECS)) {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "pid {pid} survived the final kill"
            )))
        }
    }

    #[cfg(windows)]
    fn identity_readable(&self, pid: u32, start_time: u64) -> bool {
        foreign_seen(pid, start_time) != Seen::Unreadable
    }

    fn exe_of(&self, pid: u32) -> Option<PathBuf> {
        process_exe(pid)
    }

    fn reap(&self, pid: u32) -> Option<i32> {
        let held = lock(&self.children).remove(&pid);
        let seen = lock(&self.exits).remove(&pid);
        let code = held.and_then(|mut o| o.child.try_wait().ok().flatten()?.code());
        code.or(seen)
    }
}

/// Never signal pid 0, pid 1 or ourselves, whatever a registry row says.
fn check_target(pid: u32) -> io::Result<()> {
    if pid <= 1 || pid == std::process::id() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("refusing to signal pid {pid}"),
        ));
    }
    Ok(())
}

/// What a short tool printed, each stream capped at [`TOOL_OUTPUT_CAP`].
#[derive(Debug)]
pub struct ToolOutput {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

/// Bytes kept per output stream of a tool; the rest is read and dropped.
pub const TOOL_OUTPUT_CAP: usize = 1 << 20;

/// Time a tool gets after its deadline, with stdin closed, before its tree is ended.
pub const TOOL_GRACE: Duration = Duration::from_secs(5);

/// `run_starter` refuses to start: the server could not be kept out of every job object.
pub const JOB_LOCKED: &str = "postgres cannot be started outside the daemon's job object";

/// Runs a short tool (`initdb`, `psql`, `pg_controldata`, `pg_ctl --version|stop|status`),
/// isolated like an [`OsLauncher`] child (own process group on Unix, a kill-on-close Job
/// Object on Windows, which is required: no tool runs without it). `stdin` is delivered by a
/// helper thread; each output stream keeps at most [`TOOL_OUTPUT_CAP`] bytes. Past `timeout`
/// the input delivery is cancelled and stdin closed, the tool gets [`TOOL_GRACE`] more, then
/// its own tree is ended and the result is `ErrorKind::TimedOut`. Whatever happens, the tree
/// is signalled while the leader is still unreaped, and reaping it is the last step. No error
/// ever quotes `stdin` (it can hold a password).
pub fn run_tool(cmd: Command, stdin: Option<&[u8]>, timeout: Duration) -> io::Result<ToolOutput> {
    run_tool_with(
        cmd,
        stdin,
        timeout,
        try_open_job,
        &mut exited_unreaped,
        &mut |_| {},
    )
}

/// What `run_tool` did, in order (a seam for the tests; production ignores it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ToolEvent {
    Spawned(u32),
    StdinClosed,
    SignalTree,
    Reap,
}

fn run_tool_with(
    mut cmd: Command,
    stdin: Option<&[u8]>,
    timeout: Duration,
    open: fn(&Child) -> io::Result<Job>,
    observe: &mut dyn FnMut(&mut Child) -> io::Result<bool>,
    trace: &mut dyn FnMut(ToolEvent),
) -> io::Result<ToolOutput> {
    let deadline = Instant::now() + timeout;
    let input = if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    };
    cmd.stdin(input)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    isolate(&mut cmd);
    let mut child = cmd.spawn()?;
    trace(ToolEvent::Spawned(child.id()));
    // shortcut: on Windows the job is assigned after the tool has started, so a process the
    // tool creates in that instant is outside the job and outlives a timeout; upgrade to
    // creating the tool suspended (as run_starter does) if a tool that forks at once matters.
    let job = match open(&child) {
        Ok(job) => job,
        Err(e) => {
            // No tool runs without tree isolation: the child this call just created goes.
            let _ = child.kill();
            trace(ToolEvent::Reap);
            let _ = child.wait();
            return Err(io::Error::new(
                e.kind(),
                format!("cannot isolate the tool's process tree: {e}"),
            ));
        }
    };
    let pipes = (child.stdin.take(), child.stdout.take(), child.stderr.take());
    let mut own = Owned {
        child,
        start_time: 0,
        job,
    };
    let mut writer = None;
    let result = drive_tool(
        &mut own,
        pipes,
        stdin,
        &mut writer,
        deadline,
        timeout,
        observe,
        trace,
    );
    if let Some(w) = writer {
        // The writer never outlives this call.
        w.stop();
        trace(ToolEvent::StdinClosed);
    }
    let result = match result {
        // The leader is no longer our unreaped child: its pid and group id may be someone
        // else's, so nothing is signalled from here on. `try_wait` never blocks.
        Err(e) if is_identity_lost(&e) => {
            if let Ok(None) = own.child.try_wait() {
                // Still ours and running, but not observable without reaping. This thread
                // only waits (never signals) and may outlive the call: it ends when the tool
                // exits by itself (its stdin and output pipes are already closed).
                let reaper =
                    std::thread::Builder::new()
                        .name("tool-reap".into())
                        .spawn(move || {
                            let _ = own.child.wait();
                        });
                if let Err(t) = reaper {
                    return Err(io::Error::new(
                        e.kind(),
                        format!("{e}; no reaper thread ({t}), so it may be left a zombie"),
                    ));
                }
            }
            return Err(e);
        }
        r => r,
    };
    // The leader is still unreaped here (only observed), so its pid and group id are still
    // ours: end the tree first, reap last, and signal nothing after that.
    trace(ToolEvent::SignalTree);
    let _ = kill_own(&mut own, true);
    trace(ToolEvent::Reap);
    let status = own.child.wait();
    // Dropping `own` closes the job: on Windows nothing of the tool's tree outlives it.
    let (stdout, stderr) = result?;
    Ok(ToolOutput {
        code: status?.code(),
        stdout: capped_text(&stdout),
        stderr: capped_text(&stderr),
    })
}

type ToolPipes = (
    Option<std::process::ChildStdin>,
    Option<std::process::ChildStdout>,
    Option<std::process::ChildStderr>,
);

/// Waits for the tool and its output; never reaps the leader (the caller does, last).
#[allow(clippy::too_many_arguments)]
fn drive_tool(
    own: &mut Owned,
    (pipe_in, pipe_out, pipe_err): ToolPipes,
    input: Option<&[u8]>,
    writer: &mut Option<StdinWriter>,
    deadline: Instant,
    timeout: Duration,
    observe: &mut dyn FnMut(&mut Child) -> io::Result<bool>,
    trace: &mut dyn FnMut(ToolEvent),
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let out = spawn_reader(pipe_out)?;
    let err = spawn_reader(pipe_err)?;
    if let (Some(pipe), Some(bytes)) = (pipe_in, input) {
        *writer = Some(StdinWriter::start(pipe, bytes)?);
    }
    if !wait_exit(&mut own.child, deadline, observe)? {
        // Cancel the input and close stdin before the grace starts.
        if let Some(w) = writer.take() {
            w.stop();
            trace(ToolEvent::StdinClosed);
        }
        let _ = wait_exit(&mut own.child, Instant::now() + TOOL_GRACE, observe)?;
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("tool did not finish within {} s", timeout.as_secs()),
        ));
    }
    let collect = |r: &OutputReader| {
        r.rx.recv_timeout(TOOL_GRACE).map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "tool output stayed open after the tool exited",
            )
        })
    };
    Ok((collect(&out)?, collect(&err)?))
}

/// Delivers a tool's input on a helper thread in a way that can be cancelled. Unix: the
/// pipe is non-blocking and the thread checks the stop flag between attempts. Windows: std
/// writes a child's stdin with an alertable overlapped `WriteFileEx` (measured:
/// `CancelSynchronousIo` on the thread does not end it), so the pending write is cancelled
/// with `CancelIoEx` on the pipe handle. The thread owns the pipe and closes it as soon as
/// it is done, so the tool sees end of input then; on Windows it closes it under `open`'s
/// lock and clears the handle there, so a cancel never reaches a closed (reused) handle.
struct StdinWriter {
    stop: Arc<AtomicBool>,
    thread: std::thread::JoinHandle<()>,
    #[cfg(windows)]
    open: Arc<Mutex<Option<usize>>>,
}

impl StdinWriter {
    fn start(pipe: std::process::ChildStdin, bytes: &[u8]) -> io::Result<Self> {
        #[cfg(unix)]
        set_nonblocking(&pipe)?;
        #[cfg(windows)]
        let open = {
            use std::os::windows::io::AsRawHandle;
            Arc::new(Mutex::new(Some(pipe.as_raw_handle() as usize)))
        };
        #[cfg(windows)]
        let still_open = open.clone();
        let bytes = bytes.to_vec();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = std::thread::Builder::new()
            .name("tool-stdin".into())
            .spawn(move || {
                let pipe = write_input(pipe, &bytes, &flag);
                #[cfg(windows)]
                let mut guard = lock(&still_open);
                // The tool sees end of input here.
                drop(pipe);
                #[cfg(windows)]
                {
                    *guard = None;
                }
            })?;
        Ok(Self {
            stop,
            thread,
            #[cfg(windows)]
            open,
        })
    }

    /// Stops the delivery and returns once the thread is gone, i.e. stdin is closed.
    fn stop(self) {
        self.stop.store(true, Ordering::SeqCst);
        #[cfg(windows)]
        while !self.thread.is_finished() {
            if let Some(h) = *lock(&self.open) {
                // SAFETY: while the lock is held and the value is Some, the pipe handle is
                // open (the writer closes it only under this lock); cancelling only fails
                // its pending write.
                unsafe { windows_sys::Win32::System::IO::CancelIoEx(h as _, std::ptr::null()) };
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let _ = self.thread.join();
    }
}

/// Writes until done, the stop flag, or a failed write; hands the pipe back to be closed.
fn write_input(
    mut pipe: std::process::ChildStdin,
    bytes: &[u8],
    stop: &AtomicBool,
) -> std::process::ChildStdin {
    let mut rest = bytes;
    while !rest.is_empty() && !stop.load(Ordering::SeqCst) {
        match pipe.write(&rest[..rest.len().min(64 * 1024)]) {
            Ok(0) => break,
            Ok(n) => rest = &rest[n..],
            // Unix: the pipe is full; look at the stop flag again shortly.
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            // Broken pipe (the tool is gone) or a cancelled write (Windows).
            Err(_) => break,
        }
    }
    pipe
}

#[cfg(unix)]
fn set_nonblocking(pipe: &std::process::ChildStdin) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let fd = pipe.as_raw_fd();
    // SAFETY: `fd` is the open write end owned by `pipe`; F_GETFL/F_SETFL only change its
    // status flags (our end only: the child's read end is another open file description).
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// True once `child` has exited, `false` if `deadline` passed first; never reaps it.
fn wait_exit(
    child: &mut Child,
    deadline: Instant,
    observe: &mut dyn FnMut(&mut Child) -> io::Result<bool>,
) -> io::Result<bool> {
    loop {
        if observe(child)? {
            return Ok(true);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Ok(false);
        }
        std::thread::sleep(left.min(Duration::from_millis(20)));
    }
}

/// Unix: `waitid(P_PID, pid, WEXITED | WNOWAIT | WNOHANG)` reports the exit and leaves the
/// zombie in place, so the pid (and the group id it leads) cannot be reused yet. Any failure
/// other than `EINTR` (retried; `ECHILD` above all) means the child is no longer ours to
/// observe and comes back as [`IdentityLost`]. With `WNOHANG` and no exit yet it returns 0
/// with `si_signo` 0, which is "still running", not an exit.
#[cfg(unix)]
fn exited_unreaped(child: &mut Child) -> io::Result<bool> {
    let pid = libc::id_t::from(child.id());
    loop {
        // SAFETY: a zeroed siginfo_t is a valid out buffer; WNOWAIT leaves the child
        // unreaped, WNOHANG returns at once (si_signo stays 0 when nothing happened).
        let (r, signo) = unsafe {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            let r = libc::waitid(
                libc::P_PID,
                pid,
                &mut info,
                libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
            );
            (r, info.si_signo)
        };
        if r == 0 {
            return Ok(signo != 0);
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(identity_lost(e));
        }
    }
}

/// The OS no longer shows the leader as our unreaped child (`ECHILD`, for one: `SIGCHLD` set
/// to ignore makes the kernel reap it at once). Its pid and group id may belong to someone
/// else now, so nothing is signalled after this error.
#[cfg(unix)]
#[derive(Debug)]
struct IdentityLost(io::Error);

#[cfg(unix)]
impl std::fmt::Display for IdentityLost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the tool's exit could not be observed: {}", self.0)
    }
}

#[cfg(unix)]
impl std::error::Error for IdentityLost {}

#[cfg(unix)]
fn identity_lost(e: io::Error) -> io::Error {
    io::Error::new(e.kind(), IdentityLost(e))
}

#[cfg(unix)]
fn is_identity_lost(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|i| i.is::<IdentityLost>())
}

/// Windows: the held handle is the identity, so it is never lost.
#[cfg(not(unix))]
fn is_identity_lost(_: &io::Error) -> bool {
    false
}

/// Windows: the held process handle pins the pid until `Child` is dropped, so observing the
/// exit through it releases nothing.
#[cfg(windows)]
fn exited_unreaped(child: &mut Child) -> io::Result<bool> {
    Ok(child.try_wait()?.is_some())
}

/// One output stream of a tool, read on a helper thread; `rx` gets what was kept. Unix:
/// dropping it stops the thread and joins it, which closes our read end, so the reader never
/// outlives `run_tool` on any path. Windows: the thread stays detached (the job ends the
/// writers; a process that left the job and holds the pipe is a known leftover).
struct OutputReader {
    rx: mpsc::Receiver<Vec<u8>>,
    #[cfg(unix)]
    stop: Arc<AtomicBool>,
    #[cfg(unix)]
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(unix)]
impl Drop for OutputReader {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

#[cfg(unix)]
trait OutputPipe: Read + std::os::fd::AsRawFd + Send + 'static {}
#[cfg(unix)]
impl<T: Read + std::os::fd::AsRawFd + Send + 'static> OutputPipe for T {}
#[cfg(not(unix))]
trait OutputPipe: Read + Send + 'static {}
#[cfg(not(unix))]
impl<T: Read + Send + 'static> OutputPipe for T {}

/// Reads up to [`TOOL_OUTPUT_CAP`] bytes on a helper thread, then drains the rest so the tool
/// never blocks on a full pipe. A missing pipe reads as empty.
fn spawn_reader(pipe: Option<impl OutputPipe>) -> io::Result<OutputReader> {
    let (tx, rx) = mpsc::channel();
    #[cfg(unix)]
    let stop = Arc::new(AtomicBool::new(false));
    let Some(pipe) = pipe else {
        let _ = tx.send(Vec::new());
        return Ok(OutputReader {
            rx,
            #[cfg(unix)]
            stop,
            #[cfg(unix)]
            thread: None,
        });
    };
    #[cfg(unix)]
    let flag = stop.clone();
    let thread = std::thread::Builder::new()
        .name("tool-output".into())
        .spawn(move || {
            #[cfg(unix)]
            let kept = read_output(pipe, &flag);
            #[cfg(not(unix))]
            let kept = read_output(pipe);
            let _ = tx.send(kept);
        })?;
    #[cfg(not(unix))]
    drop(thread);
    Ok(OutputReader {
        rx,
        #[cfg(unix)]
        stop,
        #[cfg(unix)]
        thread: Some(thread),
    })
}

/// Unix: waits for data with `poll` (at most 100 ms at a time) and looks at the stop flag
/// between waits. Returns the kept bytes at end of output or on stop; the pipe closes then.
#[cfg(unix)]
fn read_output(mut pipe: impl Read + std::os::fd::AsRawFd, stop: &AtomicBool) -> Vec<u8> {
    let mut kept = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    while !stop.load(Ordering::SeqCst) {
        let mut pfd = libc::pollfd {
            fd: pipe.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd for the open read end owned by `pipe`.
        let r = unsafe { libc::poll(&mut pfd, 1, 100) };
        if r < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if r == 0 {
            continue;
        }
        // Readable or hung up: we are its only reader, so this read does not block.
        match pipe.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let room = TOOL_OUTPUT_CAP - kept.len();
                kept.extend_from_slice(&buf[..n.min(room)]);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    kept
}

/// Windows: blocking reads; the thread ends when every writer has closed the pipe.
#[cfg(not(unix))]
fn read_output(mut pipe: impl Read) -> Vec<u8> {
    let mut kept = Vec::new();
    let _ = (&mut pipe)
        .take(TOOL_OUTPUT_CAP as u64)
        .read_to_end(&mut kept);
    let _ = io::copy(&mut pipe, &mut io::sink());
    kept
}

/// Lossy UTF-8, still within the cap (a cut character becomes U+FFFD, which is longer).
fn capped_text(bytes: &[u8]) -> String {
    let mut s = String::from_utf8_lossy(bytes).into_owned();
    while s.len() > TOOL_OUTPUT_CAP {
        s.pop();
    }
    s
}

fn starter_timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "starter did not finish in time")
}

/// Only for `pg_ctl start`: the server it leaves behind must never die because this daemon
/// exits, so the starter is never in a job object sync_gate owns, and its stdio is null.
/// Returns its exit code. Past `timeout` only the starter itself is ended, never what it
/// started (`ErrorKind::TimedOut`).
///
/// Windows (ruling PF31): the starter is created suspended with `CREATE_BREAKAWAY_FROM_JOB`,
/// or, when a job in the chain refuses that (`ERROR_ACCESS_DENIED`), suspended without it.
/// Before it runs it is checked against every live job this daemon created (the launcher's
/// kill-on-close jobs): inside one, or membership unreadable, it is ended unrun and the
/// result is [`JOB_LOCKED`]. A job the daemon itself was started in (the session's, a
/// terminal's, a CI runner's) is not a reason to refuse: see [`own_job_kills_on_close`].
/// Unix: own process group (`pg_ctl` itself calls `setsid`).
pub fn run_starter(cmd: Command, timeout: Duration) -> io::Result<Option<i32>> {
    run_starter_out(cmd, timeout, None)
}

fn run_starter_out(cmd: Command, timeout: Duration, out: Option<&Path>) -> io::Result<Option<i32>> {
    let deadline = Instant::now() + timeout;
    let mut expired = || Instant::now() >= deadline;
    #[cfg(windows)]
    return start_detached(
        cmd,
        &mut expired,
        &|s| s.in_jobs(&lock(own_jobs())),
        &Suspended::end,
        out,
    );
    #[cfg(unix)]
    return start_detached(cmd, &mut expired, out);
}

/// Like [`run_starter`], but the starter's stdout and stderr go to the file `out` (created,
/// truncated), so what `pg_ctl` says before it opens its own log is not lost.
pub fn run_starter_to(cmd: Command, timeout: Duration, out: &Path) -> io::Result<Option<i32>> {
    run_starter_out(cmd, timeout, Some(out))
}

/// Whether the job object this daemon itself runs in (its immediate one) ends its processes
/// when closed: then a server started from here ends with that job too. `Some(false)` outside
/// any job and always on Unix; `None` when Windows cannot tell (never a reason to refuse).
pub fn own_job_kills_on_close() -> Option<bool> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::JobObjects::{
            IsProcessInJob, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            QueryInformationJobObject,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        let mut in_job = 0;
        // SAFETY: pseudo handle of this process, null job = any job, valid out pointer.
        if unsafe { IsProcessInJob(GetCurrentProcess(), std::ptr::null_mut(), &mut in_job) } == 0 {
            return None;
        }
        if in_job == 0 {
            return Some(false);
        }
        // SAFETY: a null job handle queries the calling process's immediate job; `info` is a
        // writable JOBOBJECT_EXTENDED_LIMIT_INFORMATION of the size passed.
        unsafe {
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            let ok = QueryInformationJobObject(
                std::ptr::null_mut(),
                JobObjectExtendedLimitInformation,
                (&raw mut info).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                std::ptr::null_mut(),
            );
            (ok != 0).then_some(
                info.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE != 0,
            )
        }
    }
    #[cfg(unix)]
    Some(false)
}

#[cfg(unix)]
fn start_detached(
    mut cmd: Command,
    expired: &mut dyn FnMut() -> bool,
    out: Option<&Path>,
) -> io::Result<Option<i32>> {
    cmd.stdin(Stdio::null());
    match out {
        Some(path) => {
            let file = std::fs::File::create(path)?;
            cmd.stdout(file.try_clone()?).stderr(file);
        }
        None => {
            cmd.stdout(Stdio::null()).stderr(Stdio::null());
        }
    }
    isolate(&mut cmd);
    let mut child = cmd.spawn()?;
    let mut wait = || -> io::Result<Option<std::process::ExitStatus>> {
        loop {
            if let Some(status) = child.try_wait()? {
                return Ok(Some(status));
            }
            if expired() {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    };
    let waited = wait();
    if let Ok(Some(status)) = waited {
        return Ok(status.code());
    }
    // The starter alone (a signal to its pid, not its group): the server is not ours to end.
    let _ = child.kill();
    let _ = child.wait();
    waited.and(Err(starter_timed_out()))
}

/// `in_owned` answers, for the still suspended starter, whether it sits in a job this daemon
/// owns (`None`: cannot tell, treated as yes). `end_unrun` ends the never-run starter
/// (`Suspended::end`; a seam so the tests can make it fail).
#[cfg(windows)]
fn start_detached(
    cmd: Command,
    expired: &mut dyn FnMut() -> bool,
    in_owned: &dyn Fn(&Suspended) -> Option<bool>,
    end_unrun: &dyn Fn(&Suspended) -> io::Result<()>,
    out: Option<&Path>,
) -> io::Result<Option<i32>> {
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, ResumeThread, WaitForSingleObject,
    };
    let s = match create_suspended(&cmd, true, out) {
        // A job in the chain forbids breakaway: the starter stays in the jobs this daemon is
        // in, which the check below accepts unless one of them is sync_gate's own.
        Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => {
            create_suspended(&cmd, false, out)?
        }
        r => r?,
    };
    if in_owned(&s) != Some(false) {
        if let Err(e) = end_unrun(&s) {
            // PF33: never leave a process this code created suspended. Resumed, it runs
            // inside the sync_gate-owned job and ends with that job; the caller fails.
            // SAFETY: `s.thread` is the live primary thread handle owned by `s`.
            let resumed = unsafe { ResumeThread(s.thread) } != u32::MAX;
            let what = if resumed {
                "it was resumed and runs inside that job"
            } else {
                "resuming it failed too"
            };
            return Err(io::Error::other(format!(
                "the postgres starter, created inside a job sync_gate owns, could not be ended ({e}); {what}"
            )));
        }
        return Err(io::Error::other(JOB_LOCKED));
    }
    // SAFETY: `s.thread` is the live primary thread handle owned by `s`.
    if unsafe { ResumeThread(s.thread) } == u32::MAX {
        let e = io::Error::last_os_error();
        s.end_or_warn();
        return Err(e);
    }
    loop {
        // SAFETY: `s.process` is a live process handle owned by `s`.
        match unsafe { WaitForSingleObject(s.process, 20) } {
            WAIT_OBJECT_0 => {
                let mut code = 0u32;
                // SAFETY: live process handle and a valid out pointer.
                if unsafe { GetExitCodeProcess(s.process, &mut code) } == 0 {
                    return Err(io::Error::last_os_error());
                }
                return Ok(Some(code as i32));
            }
            WAIT_TIMEOUT if !expired() => {}
            WAIT_TIMEOUT => {
                s.end_or_warn();
                return Err(starter_timed_out());
            }
            _ => {
                let e = io::Error::last_os_error();
                s.end_or_warn();
                return Err(e);
            }
        }
    }
}

/// Every live job object this daemon created for its own children (kill-on-close), so the
/// starter can be checked against them. `open_job` adds a handle and `close_job` removes it
/// under this lock before closing it, so the starter's check never reads a closed handle.
#[cfg(windows)]
fn own_jobs() -> &'static Mutex<Vec<Job>> {
    static OWN_JOBS: Mutex<Vec<Job>> = Mutex::new(Vec::new());
    &OWN_JOBS
}

/// A process this daemon created suspended, with its primary thread; both handles are closed
/// on drop.
#[cfg(windows)]
struct Suspended {
    process: windows_sys::Win32::Foundation::HANDLE,
    thread: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl Drop for Suspended {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;
        // SAFETY: both handles came from CreateProcessW and are closed exactly once, here.
        unsafe {
            CloseHandle(self.thread);
            CloseHandle(self.process);
        }
    }
}

#[cfg(windows)]
impl Suspended {
    /// `Some(true)` inside one of `jobs`, `Some(false)` in none, `None` when Windows cannot
    /// tell for one of them.
    fn in_jobs(&self, jobs: &[Job]) -> Option<bool> {
        use windows_sys::Win32::System::JobObjects::IsProcessInJob;
        let mut inside = false;
        for &job in jobs {
            let mut r = 0;
            // SAFETY: live process handle, a live job handle (the caller keeps it open for
            // the call), valid out pointer.
            if unsafe { IsProcessInJob(self.process, job as _, &mut r) } == 0 {
                return None;
            }
            inside |= r != 0;
        }
        Some(inside)
    }

    /// `Some(true)` in some job, `Some(false)` in none, `None` when Windows cannot tell.
    #[cfg(test)]
    fn in_any_job(&self) -> Option<bool> {
        use windows_sys::Win32::System::JobObjects::IsProcessInJob;
        let mut r = 0;
        // SAFETY: live process handle, null job = "any job", valid out pointer.
        let ok = unsafe { IsProcessInJob(self.process, std::ptr::null_mut(), &mut r) };
        (ok != 0).then_some(r != 0)
    }

    /// Ends this one process (never a tree) through its own handle and waits for it to go.
    fn end(&self) -> io::Result<()> {
        use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
        use windows_sys::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};
        // SAFETY: `self.process` is a live process handle owned by `self`.
        unsafe {
            if WaitForSingleObject(self.process, 0) == WAIT_OBJECT_0 {
                return Ok(());
            }
            if TerminateProcess(self.process, 1) == 0 {
                return Err(io::Error::last_os_error());
            }
            if WaitForSingleObject(self.process, 5_000) != WAIT_OBJECT_0 {
                return Err(io::Error::other("process survived TerminateProcess"));
            }
        }
        Ok(())
    }

    fn end_or_warn(&self) {
        if let Err(e) = self.end() {
            eprintln!("sync_gated: cannot end the postgres starter it created: {e}");
        }
    }
}

/// `CreateProcessW` with `CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP`,
/// plus `CREATE_BREAKAWAY_FROM_JOB` when `breakaway`: nothing of the program runs before
/// `ResumeThread`. Its stdin is NUL, its stdout and stderr are `out` (or NUL), each through a
/// handle of its own, and those three are the only handles it inherits. Program, arguments,
/// added or removed variables and the working directory come from `cmd`; its stdio settings
/// are ignored. The OS error of a refused creation is kept (`raw_os_error`).
#[cfg(windows)]
fn create_suspended(cmd: &Command, breakaway: bool, out: Option<&Path>) -> io::Result<Suspended> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation};
    use windows_sys::Win32::System::Threading::{
        CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, CREATE_SUSPENDED,
        CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
        EXTENDED_STARTUPINFO_PRESENT, InitializeProcThreadAttributeList,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
        STARTUPINFOEXW, UpdateProcThreadAttribute,
    };
    let mut line = command_line(cmd);
    let env = environment_block(cmd);
    let cwd: Option<Vec<u16>> = cmd
        .get_current_dir()
        .map(|d| d.as_os_str().encode_wide().chain([0]).collect());
    let output = match out {
        Some(path) => std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?,
        None => std::fs::OpenOptions::new().write(true).open("NUL")?,
    };
    // Issue 13: one handle for all three made cmd.exe (pg_ctl hands its stdio down to it) now
    // and then exit 1 before opening the server log. The stderr copy shares the file position.
    let files = [std::fs::File::open("NUL")?, output.try_clone()?, output];
    let handles: [HANDLE; 3] = files.each_ref().map(|f| f.as_raw_handle() as HANDLE);
    for &h in &handles {
        // SAFETY: `h` is a live handle owned by `files`. Inheritable only matters for a process
        // created with inheritance on, and the handle list below limits the starter to these.
        if unsafe { SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let mut size = 0usize;
    // SAFETY: a null list only asks for the size (this call "fails" by design).
    unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size) };
    // usize-aligned storage, as the opaque list holds pointers.
    let mut storage = vec![0usize; size.div_ceil(size_of::<usize>()).max(1)];
    let list = storage.as_mut_ptr().cast::<core::ffi::c_void>();
    // SAFETY: `list` points at `size` writable bytes owned by `storage`.
    if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut size) } == 0 {
        return Err(io::Error::last_os_error());
    }
    struct AttrList(*mut core::ffi::c_void);
    impl Drop for AttrList {
        fn drop(&mut self) {
            // SAFETY: initialized above, deleted once, before its storage is freed.
            unsafe { DeleteProcThreadAttributeList(self.0) };
        }
    }
    let attrs = AttrList(list);
    // SAFETY: `handles` outlives the CreateProcessW call below (the list keeps a pointer).
    let ok = unsafe {
        UpdateProcThreadAttribute(
            attrs.0,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            handles.as_ptr().cast(),
            size_of_val(&handles),
            std::ptr::null_mut(),
            std::ptr::null(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut si = STARTUPINFOEXW::default();
    si.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = handles[0];
    si.StartupInfo.hStdOutput = handles[1];
    si.StartupInfo.hStdError = handles[2];
    si.lpAttributeList = attrs.0;
    let mut flags = CREATE_SUSPENDED
        | CREATE_NO_WINDOW
        | CREATE_NEW_PROCESS_GROUP
        | EXTENDED_STARTUPINFO_PRESENT;
    if breakaway {
        flags |= CREATE_BREAKAWAY_FROM_JOB;
    }
    if env.is_some() {
        flags |= CREATE_UNICODE_ENVIRONMENT;
    }
    let mut pi = PROCESS_INFORMATION::default();
    // SAFETY: every pointer is valid for the call: `line` is a mutable NUL-terminated buffer,
    // `env` a double-NUL-terminated UTF-16 block, `cwd` NUL-terminated, `si` an initialized
    // STARTUPINFOEXW (flagged by EXTENDED_STARTUPINFO_PRESENT), `pi` writable.
    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),
            line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            flags,
            env.as_ref().map_or(std::ptr::null(), |e| e.as_ptr().cast()),
            cwd.as_ref().map_or(std::ptr::null(), |d| d.as_ptr()),
            (&raw const si).cast(),
            &mut pi,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    drop(attrs);
    drop(files);
    Ok(Suspended {
        process: pi.hProcess,
        thread: pi.hThread,
    })
}

/// The UTF-16 command line, NUL-terminated, quoted the way the C runtime (and Rust's own
/// argument parser) splits it back: the program in quotes, each argument quoted when empty or
/// holding a space, tab, newline or quote, with backslashes doubled only before a quote.
#[cfg(windows)]
fn command_line(cmd: &Command) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    const QUOTE: u16 = b'"' as u16;
    const BACKSLASH: u16 = b'\\' as u16;
    // A Windows path cannot contain a quote, so the program needs no escaping.
    let mut line = vec![QUOTE];
    line.extend(cmd.get_program().encode_wide());
    line.push(QUOTE);
    for arg in cmd.get_args() {
        line.push(u16::from(b' '));
        let wide: Vec<u16> = arg.encode_wide().collect();
        let plain = !wide.is_empty()
            && !wide
                .iter()
                .any(|&c| matches!(c, 0x20 | 0x09 | 0x0a | 0x0b | QUOTE));
        if plain {
            line.extend(wide);
            continue;
        }
        line.push(QUOTE);
        let mut backslashes = 0;
        for c in wide {
            if c == BACKSLASH {
                backslashes += 1;
            } else {
                if c == QUOTE {
                    line.extend(std::iter::repeat_n(BACKSLASH, backslashes + 1));
                }
                backslashes = 0;
            }
            line.push(c);
        }
        line.extend(std::iter::repeat_n(BACKSLASH, backslashes));
        line.push(QUOTE);
    }
    line.push(0);
    line
}

/// The daemon's environment with `cmd`'s additions and removals, as a sorted UTF-16 block;
/// `None` (inherit as is) when `cmd` changes nothing.
// shortcut: `Command::env_clear` cannot be read back and is not honoured; no caller uses it.
#[cfg(windows)]
fn environment_block(cmd: &Command) -> Option<Vec<u16>> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStrExt;
    cmd.get_envs().next()?;
    // Windows names are case-insensitive; the block is sorted by the upper-cased name.
    let key = |k: &std::ffi::OsStr| k.to_string_lossy().to_uppercase();
    let mut vars: BTreeMap<String, (OsString, OsString)> = std::env::vars_os()
        .map(|(k, v)| (key(&k), (k, v)))
        .collect();
    for (k, v) in cmd.get_envs() {
        match v {
            Some(v) => vars.insert(key(k), (k.to_owned(), v.to_owned())),
            None => vars.remove(&key(k)),
        };
    }
    let mut block = Vec::new();
    for (k, v) in vars.values() {
        block.extend(k.encode_wide());
        block.push(u16::from(b'='));
        block.extend(v.encode_wide());
        block.push(0);
    }
    if vars.is_empty() {
        block.push(0);
    }
    block.push(0);
    Some(block)
}

/// Executable path of a live process, as the OS reports it.
pub(crate) fn process_exe(pid: u32) -> Option<PathBuf> {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
    let mut sys = System::new().ok()?;
    let p = Pid::from_u32(pid);
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[p]),
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::Always),
    );
    sys.process(p)?.exe().map(Path::to_path_buf)
}

/// Own process group on Unix, so a terminal Ctrl+C aimed at the daemon does not reach it.
#[cfg(unix)]
fn isolate(cmd: &mut Command) {
    std::os::unix::process::CommandExt::process_group(cmd, 0);
}

/// No console window, own process group: the console's Ctrl+C does not reach the child.
#[cfg(windows)]
fn isolate(cmd: &mut Command) {
    use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW};
    std::os::windows::process::CommandExt::creation_flags(
        cmd,
        CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
    );
}

#[cfg(unix)]
fn open_job(_child: &Child) -> Job {
    0
}

/// Unix isolation is the process group `isolate` set at spawn: nothing more to open.
#[cfg(unix)]
fn try_open_job(_child: &Child) -> io::Result<Job> {
    Ok(0)
}

#[cfg(unix)]
fn close_job(_job: Job) {}

/// Signals the whole process group of an own child (it leads its group, see `isolate`).
#[cfg(unix)]
fn kill_own(o: &mut Owned, hard: bool) -> io::Result<()> {
    let pgid = nix::unistd::Pid::from_raw(i32::try_from(o.child.id()).map_err(io::Error::other)?);
    unix_signal(hard, |sig| nix::sys::signal::killpg(pgid, sig))
}

/// Structural guard for a leftover: the daemon only ever starts group leaders, so the target
/// must lead its own group (pgid == pid), and that group must not be the daemon's. An
/// unreadable pgid is no match.
#[cfg(any(unix, test))]
fn leftover_may_be_signalled(pid: i32, pgid: Option<i32>, own_pgid: i32) -> bool {
    pgid == Some(pid) && pgid != Some(own_pgid)
}

/// Leftover from disk: the caller has just checked pid + start time (+ exe).
// shortcut: no pidfd, so the pid could in theory be reused between that check and this
// signal (microseconds); upgrade to pidfd_open (Linux only) if that ever matters.
#[cfg(unix)]
fn kill_foreign(pid: u32, _start_time: u64, hard: bool) -> io::Result<()> {
    let p = nix::unistd::Pid::from_raw(i32::try_from(pid).map_err(io::Error::other)?);
    let pgid = nix::unistd::getpgid(Some(p))
        .ok()
        .map(nix::unistd::Pid::as_raw);
    let own = nix::unistd::getpgrp().as_raw();
    if !leftover_may_be_signalled(p.as_raw(), pgid, own) {
        return Ok(()); // not something we started: leave it alone
    }
    unix_signal(hard, |sig| nix::sys::signal::killpg(p, sig))
}

/// SIGTERM (or SIGKILL when `hard`) through `send`; ESRCH (already gone) counts as success.
#[cfg(unix)]
fn unix_signal(
    hard: bool,
    send: impl FnOnce(nix::sys::signal::Signal) -> nix::Result<()>,
) -> io::Result<()> {
    use nix::sys::signal::Signal;
    let sig = if hard {
        Signal::SIGKILL
    } else {
        Signal::SIGTERM
    };
    match send(sig) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// The MCP launcher's policy (unchanged): without a job only the leader will be stopped.
#[cfg(windows)]
fn open_job(child: &Child) -> Job {
    try_open_job(child).unwrap_or_else(|e| {
        eprintln!(
            "sync_gated: could not put pid {} in a job object ({e}); only the leader will be stopped",
            child.id()
        );
        0
    })
}

/// One Job Object per child (kill-on-close), so grandchildren die with it; registered in
/// `own_jobs` while it lives.
// shortcut: a grandchild created before the assignment is missed (std has no suspended
// spawn); upgrade to CREATE_SUSPENDED through raw CreateProcessW if that ever matters.
#[cfg(windows)]
fn try_open_job(child: &Child) -> io::Result<Job> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject,
    };
    // SAFETY: plain Win32 calls on handles we own; the job is closed on failure.
    unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let ok = SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&raw const info).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        ) != 0
            && AssignProcessToJobObject(job, child.as_raw_handle() as HANDLE) != 0;
        if !ok {
            let e = io::Error::last_os_error();
            CloseHandle(job);
            return Err(e);
        }
        let job = job as usize;
        lock(own_jobs()).push(job);
        Ok(job)
    }
}

#[cfg(windows)]
fn close_job(job: Job) {
    if job != 0 {
        let mut own = lock(own_jobs());
        own.retain(|&j| j != job);
        // SAFETY: the handle came from `open_job` and is closed exactly once (Owned::drop),
        // with the registry lock held so no starter check is reading it.
        unsafe { windows_sys::Win32::Foundation::CloseHandle(job as _) };
    }
}

/// Terminates the job (the whole tree); without a job, the child through its own handle.
/// There is no graceful signal on Windows, so `hard` changes nothing.
#[cfg(windows)]
fn kill_own(o: &mut Owned, hard: bool) -> io::Result<()> {
    let _ = hard;
    if o.job != 0 {
        // SAFETY: `o.job` is a live job handle owned by `o`.
        let ok =
            unsafe { windows_sys::Win32::System::JobObjects::TerminateJobObject(o.job as _, 1) };
        return if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        };
    }
    match o.child.kill() {
        Err(e) if e.kind() != io::ErrorKind::InvalidInput => Err(e),
        _ => Ok(()),
    }
}

/// Windows identity of a process: its creation time as the raw FILETIME, read from the process
/// handle itself. The value counts 100 ns units since 1601; that is its representation, not
/// the resolution of the clock that stamps it, which may advance in much coarser steps.
/// Keeping the full value removes the truncation to whole seconds that the probe applies
/// (`sync_gate_probe::start_time`, still what Unix records); it does not guarantee that two
/// processes reusing a pid get different values.
#[cfg(windows)]
fn handle_start_time(h: windows_sys::Win32::Foundation::HANDLE) -> Option<u64> {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::GetProcessTimes;
    let zero = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut created, mut b, mut c, mut d) = (zero, zero, zero, zero);
    // SAFETY: valid handle and out pointers.
    if unsafe { GetProcessTimes(h, &mut created, &mut b, &mut c, &mut d) } == 0 {
        return None;
    }
    Some((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}

/// What a handle opened on a leftover's pid says about the recorded identity.
#[cfg(windows)]
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    /// The process object has terminated.
    Gone,
    /// Running, but not the recorded process (a reused pid, or a row from an older version
    /// that recorded seconds): never touched.
    Other,
    /// Running and the recorded process.
    Same,
    /// The state or the creation time could not be read: neither gone nor another process.
    Unreadable,
}

/// Opens `pid` for the identity check (plus `PROCESS_TERMINATE` when `terminate`); the handle
/// closes when dropped.
#[cfg(windows)]
fn open_foreign(pid: u32, terminate: bool) -> io::Result<std::os::windows::io::OwnedHandle> {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
    };
    let mut access = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE;
    if terminate {
        access |= PROCESS_TERMINATE;
    }
    // SAFETY: plain Win32 call.
    let h = unsafe { OpenProcess(access, 0, pid) };
    if h.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh handle nobody else owns.
    Ok(unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(h) })
}

/// A failed open: error 87 (invalid parameter) means no such pid, so gone; any other failure
/// (access denied...) says nothing about the process.
#[cfg(windows)]
fn seen_on_open_error(e: &io::Error) -> Seen {
    if e.raw_os_error() == Some(87) {
        Seen::Gone
    } else {
        Seen::Unreadable
    }
}

/// Liveness comes from waiting on the handle (signalled once the process ends), not from the
/// exit code: 259 (`STILL_ACTIVE`) is also a legal exit code.
#[cfg(windows)]
fn seen_through(h: windows_sys::Win32::Foundation::HANDLE, start_time: u64) -> Seen {
    use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::WaitForSingleObject;
    // SAFETY: valid handle.
    match unsafe { WaitForSingleObject(h, 0) } {
        WAIT_TIMEOUT => {}
        WAIT_OBJECT_0 => return Seen::Gone,
        _ => return Seen::Unreadable,
    }
    match handle_start_time(h) {
        None => Seen::Unreadable,
        Some(t) if t == start_time => Seen::Same,
        Some(_) => Seen::Other,
    }
}

/// `OsLauncher::is_alive` for a process we hold no handle on, with the trait's contract:
/// unreadable counts as alive, so a row is not dropped on a guess; `kill_foreign` then
/// refuses to signal it.
#[cfg(windows)]
fn foreign_is_alive(pid: u32, start_time: u64) -> bool {
    matches!(foreign_seen(pid, start_time), Seen::Same | Seen::Unreadable)
}

/// What a query-only open of a process we hold no handle on shows.
#[cfg(windows)]
fn foreign_seen(pid: u32, start_time: u64) -> Seen {
    use std::os::windows::io::AsRawHandle;
    match open_foreign(pid, false) {
        Ok(h) => seen_through(h.as_raw_handle(), start_time),
        Err(e) => seen_on_open_error(&e),
    }
}

/// Leftover from disk: opens the process and kills through that handle (`kill_through`).
/// No such pid is `Ok`; any other open failure is an error (the row stays).
#[cfg(windows)]
fn kill_foreign(pid: u32, start_time: u64, hard: bool) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    let _ = hard;
    match open_foreign(pid, true) {
        Ok(h) => kill_through(h.as_raw_handle(), pid, start_time),
        Err(e) if seen_on_open_error(&e) == Seen::Gone => Ok(()),
        Err(e) => Err(e),
    }
}

/// Checks the recorded identity on `h` and terminates through that same handle, so the
/// process checked is the process terminated: a pid reused after the open is not hit. A
/// different process with the very same creation time would still match (see
/// `handle_start_time`). Gone or another process is `Ok`; an identity that cannot be read is
/// an error and nothing is signalled (the row stays).
#[cfg(windows)]
fn kill_through(
    h: windows_sys::Win32::Foundation::HANDLE,
    pid: u32,
    start_time: u64,
) -> io::Result<()> {
    use windows_sys::Win32::System::Threading::TerminateProcess;
    match seen_through(h, start_time) {
        Seen::Gone | Seen::Other => Ok(()),
        Seen::Unreadable => Err(io::Error::other(format!(
            "cannot verify the identity of pid {pid}; not terminated"
        ))),
        // SAFETY: valid handle.
        Seen::Same if unsafe { TerminateProcess(h, 1) } != 0 => Ok(()),
        Seen::Same => {
            let e = io::Error::last_os_error();
            if seen_through(h, start_time) == Seen::Gone {
                Ok(())
            } else {
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::sync::mpsc::{self, Receiver};
    use std::sync::{Arc, Mutex};

    type Log = Arc<Mutex<Vec<String>>>;

    /// Records every call. `alive` answers `is_alive`; `exit_on_close` flips it when stdin drops.
    struct Fake {
        log: Log,
        alive: Arc<Mutex<bool>>,
        exit_on_close: bool,
        /// Pids `is_alive` accepts; empty = use `alive`.
        only: Vec<u32>,
        /// What `exe_of` answers per pid.
        exes: BTreeMap<u32, PathBuf>,
        /// Pids `terminate` refuses to stop.
        stuck: Vec<u32>,
        /// Pids whose identity cannot be read.
        unreadable: Vec<u32>,
        /// How long each `terminate` takes.
        slow: Duration,
    }
    struct FakeStdin(Log, Arc<Mutex<bool>>, bool);
    impl Write for FakeStdin {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl Drop for FakeStdin {
        fn drop(&mut self) {
            self.0.lock().unwrap().push("close_stdin".into());
            if self.2 {
                *self.1.lock().unwrap() = false;
            }
        }
    }
    impl Fake {
        fn new(alive: bool, exit_on_close: bool) -> Self {
            Fake {
                log: Default::default(),
                alive: Arc::new(Mutex::new(alive)),
                exit_on_close,
                only: Vec::new(),
                exes: BTreeMap::new(),
                stuck: Vec::new(),
                unreadable: Vec::new(),
                slow: Duration::ZERO,
            }
        }
        fn stdin(&self) -> Option<Box<dyn Write + Send>> {
            Some(Box::new(FakeStdin(
                self.log.clone(),
                self.alive.clone(),
                self.exit_on_close,
            )))
        }
        fn calls(&self) -> Vec<String> {
            self.log.lock().unwrap().clone()
        }
    }
    impl Launcher for Fake {
        fn spawn(
            &self,
            _: &str,
            _: &[String],
            _: &BTreeMap<String, String>,
            _: &[String],
            _: Option<&Path>,
        ) -> io::Result<Spawned> {
            Err(io::ErrorKind::Unsupported.into())
        }
        fn is_alive(&self, pid: u32, _: u64) -> bool {
            self.log.lock().unwrap().push("is_alive".into());
            if self.only.is_empty() {
                *self.alive.lock().unwrap()
            } else {
                self.only.contains(&pid)
            }
        }
        fn terminate(&self, pid: u32, _: u64) -> io::Result<()> {
            self.log.lock().unwrap().push(format!("terminate {pid}"));
            std::thread::sleep(self.slow);
            if self.stuck.contains(&pid) {
                return Err(io::Error::other("access denied"));
            }
            Ok(())
        }
        fn identity_readable(&self, pid: u32, _: u64) -> bool {
            !self.unreadable.contains(&pid)
        }
        fn exe_of(&self, pid: u32) -> Option<PathBuf> {
            self.exes.get(&pid).cloned()
        }
        fn reap(&self, pid: u32) -> Option<i32> {
            self.log.lock().unwrap().push(format!("reap {pid}"));
            None
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sync_gate-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn backoff_doubles_to_a_cap_and_resets() {
        let mut b = Backoff::default();
        assert_eq!(
            [b.next(), b.next(), b.next()].map(|d| d.as_secs()),
            [1, 2, 4]
        );
        for _ in 0..10 {
            b.next();
        }
        assert_eq!(b.next().as_secs(), 30);
        b.reset();
        assert_eq!(b.next().as_secs(), 1);
    }

    #[test]
    fn stop_own_closes_stdin_first_and_terminates_only_after_grace() {
        let f = Fake::new(true, false);
        stop_own(&f, 7, 1, f.stdin(), Duration::ZERO).unwrap();
        assert_eq!(
            f.calls(),
            ["close_stdin", "is_alive", "terminate 7", "reap 7"]
        );

        let f = Fake::new(true, true);
        stop_own(&f, 7, 1, f.stdin(), Duration::from_secs(5)).unwrap();
        assert_eq!(f.calls(), ["close_stdin", "is_alive", "reap 7"]);
    }

    /// Matching exe, but `terminate` fails: the row stays on disk for the next start.
    #[test]
    fn a_leftover_that_cannot_be_stopped_keeps_its_row_on_disk() {
        let dir = temp_dir("keep");
        let path = dir.join("services.json");
        let mut reg = Registry::load(&path);
        reg.record("a", 10, 1, Path::new("/bin/a"));
        let mut f = Fake::new(false, false);
        f.only = vec![10];
        f.exes.insert(10, "/bin/a".into());
        f.stuck = vec![10];
        assert_eq!(reap_leftovers(&f, &mut reg), 0);
        assert!(f.calls().contains(&"terminate 10".to_string()));
        let kept: Vec<_> = Registry::load(&path).leftovers();
        assert_eq!(kept.iter().map(|r| r.1).collect::<Vec<_>>(), vec![10]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Matching exe, identity unreadable: never terminated, and the row stays on disk (it is
    /// not the refused-target case, which forgets it).
    #[test]
    fn a_leftover_with_an_unreadable_identity_keeps_its_row_on_disk() {
        let dir = temp_dir("unreadable");
        let path = dir.join("services.json");
        let mut reg = Registry::load(&path);
        reg.record("a", 10, 1, Path::new("/bin/a"));
        let mut f = Fake::new(false, false);
        f.only = vec![10];
        f.exes.insert(10, "/bin/a".into());
        f.unreadable = vec![10];
        assert_eq!(reap_leftovers(&f, &mut reg), 0);
        assert!(
            !f.calls().iter().any(|c| c.starts_with("terminate")),
            "{:?}",
            f.calls()
        );
        let kept: Vec<_> = Registry::load(&path).leftovers();
        assert_eq!(kept.iter().map(|r| r.1).collect::<Vec<_>>(), vec![10]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stop_own_never_terminates_a_reused_pid() {
        let f = Fake::new(false, false);
        stop_own(&f, 7, 1, f.stdin(), Duration::ZERO).unwrap();
        assert!(f.calls().iter().all(|c| !c.starts_with("terminate")));
    }

    #[test]
    fn registry_roundtrips_and_reap_needs_pid_start_time_and_exe() {
        let dir = temp_dir("reg");
        let path = dir.join("services.json");
        let mut reg = Registry::load(&path);
        reg.record("a", 10, 1, Path::new("/bin/a"));
        reg.record("b", 20, 1, Path::new("/bin/b"));
        reg.record("c", 30, 1, Path::new("/bin/c"));
        assert_eq!(Registry::load(&path).leftovers().len(), 3);

        // 10: all match. 20: alive, but another executable. 30: alive, exe unreadable: not
        // terminated, but not "another program" either, so its row stays for the next start.
        let mut f = Fake::new(false, false);
        f.only = vec![10, 20, 30];
        f.exes.insert(10, "/bin/a".into());
        f.exes.insert(20, "/somewhere/else".into());
        assert_eq!(reap_leftovers(&f, &mut reg), 1);
        let terminated: Vec<_> = f
            .calls()
            .into_iter()
            .filter(|c| c.starts_with("terminate"))
            .collect();
        assert_eq!(terminated, ["terminate 10"]);
        let pids =
            |rows: Vec<(String, u32, u64, PathBuf)>| rows.iter().map(|r| r.1).collect::<Vec<_>>();
        assert_eq!(pids(reg.leftovers()), vec![30]);
        assert_eq!(pids(Registry::load(&path).leftovers()), vec![30]);

        std::fs::write(&path, "not json").unwrap();
        assert!(Registry::load(&path).leftovers().is_empty());
        assert!(dir.join("services.json.bad").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A leftover that is the same process but cannot be stopped keeps its row, so the next
    /// daemon start tries again; one that is no longer the same process is forgotten.
    #[test]
    fn a_leftover_that_cannot_be_stopped_keeps_its_row() {
        let dir = temp_dir("stuck-reg");
        let path = dir.join("services.json");
        let mut reg = Registry::load(&path);
        reg.record("a", 10, 1, Path::new("/bin/a"));
        reg.record("b", 20, 1, Path::new("/bin/b"));
        let mut f = Fake::new(false, false);
        f.only = vec![10, 20];
        f.exes.insert(10, "/bin/a".into());
        f.exes.insert(20, "/somewhere/else".into());
        f.stuck = vec![10];
        assert_eq!(reap_leftovers(&f, &mut reg), 0);
        let left: Vec<_> = Registry::load(&path).leftovers();
        assert_eq!(left.len(), 1, "{left:?}");
        assert_eq!(left[0].1, 10);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A `services.json` another user could have written names a process that looks like a
    /// leftover in every way (live pid, same start time, same exe): it is never terminated.
    #[cfg(unix)]
    #[test]
    fn an_untrusted_services_record_terminates_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("untrusted-reg");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join("services.json");
        let forged = r#"[["srv",4242,1,"/bin/victim"]]"#;
        let reads = || crate::store::READS.with(std::cell::Cell::get);
        // (leftovers stopped, `terminate` calls, times the file was opened)
        let terminated = |mode: u32| {
            std::fs::write(&path, forged).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            let mut f = Fake::new(false, false);
            f.only = vec![4242];
            f.exes.insert(4242, "/bin/victim".into());
            let before = reads();
            let mut reg = Registry::load(&path);
            let opened = reads() - before;
            let stopped = reap_leftovers(&f, &mut reg);
            let calls = f
                .calls()
                .iter()
                .filter(|c| c.starts_with("terminate"))
                .count();
            (stopped, calls, opened)
        };
        assert_eq!(terminated(0o666), (0, 0, 0));
        // The refused file is left as it was, for the user to look at.
        assert_eq!(std::fs::read_to_string(&path).unwrap(), forged);
        // Control: the same row in a file only we can write is a real leftover.
        assert_eq!(terminated(0o600), (1, 1, 1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn real_launcher_never_signals_pid_0_1_or_itself() {
        let l = OsLauncher::default();
        let me = std::process::id();
        let st = identity_of(me).unwrap();
        for pid in [0, 1, me] {
            let e = l.terminate(pid, st).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "pid {pid}");
        }
        // A hand-written registry with those rows (our own row even has the true identity):
        // nothing is terminated and the rows are dropped.
        let dir = temp_dir("rows");
        let mut reg = Registry::load(&dir.join("services.json"));
        let exe = process_exe(me).unwrap();
        reg.record("zero", 0, st, &exe);
        reg.record("me", me, st, &exe);
        assert_eq!(reap_leftovers(&l, &mut reg), 0);
        assert!(reg.leftovers().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The identity the supervisor records for a live process (None once it has exited, like
    /// the probe): Windows reads the full FILETIME from the process handle, Unix the probe's
    /// seconds.
    #[cfg(windows)]
    fn identity_of(pid: u32) -> Option<u64> {
        use std::os::windows::io::AsRawHandle;
        let h = open_foreign(pid, false).ok()?;
        let h = h.as_raw_handle();
        (seen_through(h, 0) != Seen::Gone)
            .then(|| handle_start_time(h))
            .flatten()
    }
    #[cfg(not(windows))]
    fn identity_of(pid: u32) -> Option<u64> {
        sync_gate_probe::start_time(pid)
    }

    /// GetProcessTimes' creation FILETIME, read directly (independent of `handle_start_time`).
    #[cfg(windows)]
    fn raw_ticks(h: windows_sys::Win32::Foundation::HANDLE) -> u64 {
        use windows_sys::Win32::Foundation::FILETIME;
        use windows_sys::Win32::System::Threading::GetProcessTimes;
        let z = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let (mut c, mut b, mut e, mut d) = (z, z, z, z);
        // SAFETY: valid handle and out pointers.
        assert_ne!(
            unsafe { GetProcessTimes(h, &mut c, &mut b, &mut e, &mut d) },
            0
        );
        (u64::from(c.dwHighDateTime) << 32) | u64::from(c.dwLowDateTime)
    }

    /// A test child that is killed and reaped even when an assertion fails.
    #[cfg(windows)]
    struct Sleeper(Child);
    #[cfg(windows)]
    impl Drop for Sleeper {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    #[cfg(windows)]
    impl Sleeper {
        fn start() -> Self {
            Sleeper(
                child_command("sleep")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .spawn()
                    .unwrap(),
            )
        }
        fn pid(&self) -> u32 {
            self.0.id()
        }
        /// (full ticks, the same in whole Unix seconds as the old identity)
        fn identities(&self) -> (u64, u64) {
            use std::os::windows::io::AsRawHandle;
            let ticks = raw_ticks(self.0.as_raw_handle());
            (ticks, ticks / 10_000_000 - 11_644_473_600)
        }
        /// Waits up to `limit` on the child's own handle: true once it has ended, false if it
        /// still runs at the deadline (termination is asynchronous). A failed wait proves
        /// nothing either way, so it fails the test.
        fn ends_within(&self, limit: Duration) -> bool {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
            use windows_sys::Win32::System::Threading::WaitForSingleObject;
            let ms = u32::try_from(limit.as_millis()).unwrap();
            // SAFETY: the child's handle, open while `self` lives.
            match unsafe { WaitForSingleObject(self.0.as_raw_handle(), ms) } {
                WAIT_OBJECT_0 => true,
                WAIT_TIMEOUT => false,
                r => panic!(
                    "wait on the child failed ({r}): {}",
                    io::Error::last_os_error()
                ),
            }
        }
    }

    /// `OpenProcess` with exactly `access`; the handle closes when dropped, even when an
    /// assertion fails.
    #[cfg(windows)]
    fn open_with(pid: u32, access: u32) -> std::os::windows::io::OwnedHandle {
        use std::os::windows::io::FromRawHandle;
        // SAFETY: plain Win32 call.
        let h = unsafe { windows_sys::Win32::System::Threading::OpenProcess(access, 0, pid) };
        assert!(!h.is_null(), "{}", io::Error::last_os_error());
        // SAFETY: a fresh handle nobody else owns.
        unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(h) }
    }

    #[cfg(windows)]
    #[test]
    fn handle_start_time_keeps_100ns_resolution() {
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        // SAFETY: GetCurrentProcess returns a pseudo handle that needs no closing.
        let h = unsafe { GetCurrentProcess() };
        let ticks = raw_ticks(h);
        assert_eq!(handle_start_time(h), Some(ticks));
        // The probe (seconds) is only the coarse view of the same instant.
        let secs = sync_gate_probe::start_time(std::process::id()).unwrap();
        assert_eq!(ticks / 10_000_000 - 11_644_473_600, secs);
    }

    #[cfg(windows)]
    #[test]
    fn a_whole_second_identity_is_not_alive_for_a_foreign_process() {
        let c = Sleeper::start();
        let (ticks, secs) = c.identities();
        let l = OsLauncher::default();
        assert!(!l.is_alive(c.pid(), secs), "an identity in seconds");
        assert!(l.is_alive(c.pid(), ticks), "control: the exact identity");
    }

    #[cfg(windows)]
    #[test]
    fn a_whole_second_identity_leaves_a_foreign_process_alive() {
        let c = Sleeper::start();
        let (_, secs) = c.identities();
        kill_foreign(c.pid(), secs, true).unwrap();
        let l = OsLauncher::default();
        assert!(l.terminate(c.pid(), secs).is_ok());
        assert!(
            !c.ends_within(Duration::from_secs(1)),
            "a row in seconds must never kill"
        );
    }

    #[cfg(windows)]
    #[test]
    fn the_exact_identity_terminates_a_foreign_process() {
        let c = Sleeper::start();
        let (ticks, _) = c.identities();
        let l = OsLauncher::default();
        l.terminate(c.pid(), ticks).unwrap();
        assert!(
            c.ends_within(Duration::from_secs(10)),
            "the child must really be gone"
        );
    }

    /// A `services.json` written by an older version (start time in whole seconds), read back
    /// from disk: the row is forgotten on disk too, and the process is left running.
    #[cfg(windows)]
    #[test]
    fn reap_leftovers_forgets_an_old_row_read_back_from_disk_without_killing() {
        let c = Sleeper::start();
        let (_, secs) = c.identities();
        let dir = temp_dir("old-row");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("services.json");
        let exe = process_exe(c.pid()).unwrap();
        let old = serde_json::to_vec(&[("old", c.pid(), secs, exe.to_string_lossy())]).unwrap();
        std::fs::write(&path, old).unwrap();
        let mut reg = Registry::load(&path);
        let read_back = reg.leftovers();
        let stopped = reap_leftovers(&OsLauncher::default(), &mut reg);
        let on_disk = Registry::load(&path).leftovers();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(read_back.len(), 1, "the old row is read back");
        assert_eq!(read_back[0].2, secs);
        assert_eq!(stopped, 0);
        assert!(on_disk.is_empty(), "{on_disk:?}");
        assert!(
            !c.ends_within(Duration::from_secs(1)),
            "an old row must be forgotten, not acted on"
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_pid_that_cannot_exist_is_gone() {
        let l = OsLauncher::default();
        assert!(!l.is_alive(0xFFFF_FFF0, 123));
        kill_foreign(0xFFFF_FFF0, 123, true).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn an_exited_process_is_gone_even_when_its_exit_code_is_259() {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Threading::GetExitCodeProcess;
        let mut child = child_command("exit259")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        // `Child` keeps its own handle until dropped (after `wait` too): the pid stays ours.
        let h = child.as_raw_handle();
        let ticks = raw_ticks(h);
        let _ = child.wait();
        let mut code = 0u32;
        // SAFETY: valid handle and out pointer.
        assert_ne!(unsafe { GetExitCodeProcess(h, &mut code) }, 0);
        assert_eq!(code, 259, "the trap: an exit code equal to STILL_ACTIVE");
        assert_eq!(seen_through(h, ticks), Seen::Gone);
        assert!(!OsLauncher::default().is_alive(pid, ticks));
    }

    /// The wait on the handle fails (no SYNCHRONIZE right): unreadable.
    #[cfg(windows)]
    #[test]
    fn an_unreadable_process_is_neither_gone_nor_another_process() {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;
        let c = Sleeper::start();
        let (ticks, _) = c.identities();
        let h = open_with(c.pid(), PROCESS_QUERY_LIMITED_INFORMATION);
        assert_eq!(seen_through(h.as_raw_handle(), ticks), Seen::Unreadable);
    }

    /// The wait says running, then GetProcessTimes fails (no query right): unreadable, not
    /// "another process".
    #[cfg(windows)]
    #[test]
    fn a_creation_time_that_cannot_be_read_is_unreadable() {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Threading::PROCESS_SYNCHRONIZE;
        let c = Sleeper::start();
        let (ticks, _) = c.identities();
        let h = open_with(c.pid(), PROCESS_SYNCHRONIZE);
        assert_eq!(handle_start_time(h.as_raw_handle()), None);
        assert_eq!(seen_through(h.as_raw_handle(), ticks), Seen::Unreadable);
    }

    /// `Seen::Unreadable` reaches the kill: both ways of failing to read (the wait, the
    /// creation time) are an error, and a handle that could terminate is never used.
    #[cfg(windows)]
    #[test]
    fn an_unreadable_identity_is_never_terminated() {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Threading::{
            PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
        };
        let c = Sleeper::start();
        let (ticks, _) = c.identities();
        for access in [PROCESS_SYNCHRONIZE, PROCESS_QUERY_LIMITED_INFORMATION] {
            let h = open_with(c.pid(), access | PROCESS_TERMINATE);
            let e = kill_through(h.as_raw_handle(), c.pid(), ticks).unwrap_err();
            assert!(e.to_string().contains("cannot verify"), "{e}");
        }
        assert!(
            !c.ends_within(Duration::from_secs(1)),
            "an unverifiable process must never be terminated"
        );
    }

    /// Only "no such pid" (87) is gone; any other open failure (access denied...) is
    /// unreadable: `is_alive` keeps it alive and the kill refuses it.
    #[cfg(windows)]
    #[test]
    fn an_open_failure_other_than_no_such_pid_is_unreadable() {
        assert_eq!(
            seen_on_open_error(&io::Error::from_raw_os_error(87)),
            Seen::Gone
        );
        assert_eq!(
            seen_on_open_error(&io::Error::from_raw_os_error(5)),
            Seen::Unreadable
        );
    }
    /// Re-executed by the tests below; `echo` repeats stdin lines with a prefix, `sleep`
    /// ignores stdin, `tree` starts a `sleep` grandchild and reports both pids, `env` says
    /// whether each variable named on stdin is set.
    #[test]
    fn child_entry() {
        let Ok(spec) = std::env::var("SYNC_GATE_TEST_CHILD") else {
            return;
        };
        match spec.as_str() {
            "echo" => {
                for line in std::io::stdin().lock().lines() {
                    println!("echo:{}", line.unwrap());
                    std::io::stdout().flush().unwrap();
                }
                std::process::exit(0);
            }
            // Also the detached descendant of several fixtures: it ends by itself after 60 s,
            // so a guard that rightly refuses to act never leaves it behind for long.
            "sleep" => std::thread::sleep(Duration::from_secs(60)),
            "exit3" => std::process::exit(3),
            // Exits with 259, the value of STILL_ACTIVE.
            "exit259" => std::process::exit(259),
            // Ends by itself after about a second.
            "nap" => std::thread::sleep(Duration::from_secs(1)),
            // Writes a line every 50 ms; ends on the first failed write, or after 30 s.
            "writer" => {
                let end = Instant::now() + Duration::from_secs(30);
                let mut out = std::io::stdout();
                while Instant::now() < end {
                    if writeln!(out, "still writing")
                        .and_then(|()| out.flush())
                        .is_err()
                    {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                std::process::exit(0);
            }
            "env" => {
                for name in std::io::stdin().lock().lines() {
                    let name = name.unwrap();
                    let set = std::env::var_os(&name).map_or("absent", |_| "present");
                    println!("env:{name}={set}");
                    std::io::stdout().flush().unwrap();
                }
                std::process::exit(0);
            }
            "tree" => {
                let mut grandchild = child_command("sleep")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .spawn()
                    .unwrap();
                // The grandchild's start time is read here, while we hold it unreaped.
                let start = identity_of(grandchild.id()).unwrap_or(0);
                println!("pids:{}:{}:{start}", std::process::id(), grandchild.id());
                std::io::stdout().flush().unwrap();
                let _ = grandchild.wait();
            }
            "flood" => {
                let chunk = [b'x'; 64 * 1024];
                let mut out = std::io::stdout().lock();
                for _ in 0..32 {
                    out.write_all(&chunk).unwrap();
                }
                out.flush().unwrap();
                drop(out);
                std::process::exit(0);
            }
            // Waits for "go" (the test puts it in its job first), then reports that job.
            "job-report" => {
                let mut go = String::new();
                std::io::stdin().read_line(&mut go).unwrap();
                println!("jobreport:{:?}", own_job_kills_on_close());
                std::io::stdout().flush().unwrap();
                std::process::exit(0);
            }
            other => child_entry_with_path(other),
        }
    }

    /// Modes that carry an absolute path: `<mode>:<path>`.
    fn child_entry_with_path(spec: &str) {
        let Some((mode, path)) = spec.split_once(':') else {
            panic!("unknown child mode {spec}");
        };
        match mode {
            // A pg_ctl stand-in: starts a detached grandchild and exits.
            "spawn-detached" => {
                spawn_detached_sleep(path);
                std::process::exit(0);
            }
            // The same, but the stand-in hangs afterwards.
            "spawn-detached-then-sleep" => {
                spawn_detached_sleep(path);
                std::thread::sleep(Duration::from_secs(120));
            }
            // A tool with a grandchild in its tree; marks when its stdin reaches EOF.
            // The first stdin line is read before the grandchild starts: run_tool delivers input
            // only after the job assignment, so the grandchild is created inside the job. This
            // test therefore does NOT cover a descendant created before the job assignment.
            "tree-pidfile" => {
                let mut input = std::io::stdin().lock();
                let _ = input.read_line(&mut String::new());
                let grandchild = child_command("sleep")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap();
                write_pidfile(path, &grandchild);
                let _ = std::io::copy(&mut input, &mut std::io::sink());
                std::fs::write(format!("{path}.eof"), "eof").unwrap();
                std::thread::sleep(Duration::from_secs(120));
                drop(grandchild);
            }
            // A tool whose leader exits at once while a descendant in its tree keeps the
            // output pipe open.
            "pipe-holder" => {
                let holder = child_command("sleep")
                    .stdin(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap();
                write_pidfile(path, &holder);
                std::process::exit(0);
            }
            // The same, but the descendant keeps writing to the inherited output pipe.
            "pipe-writer" => {
                let writer = child_command("writer")
                    .stdin(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap();
                write_pidfile(path, &writer);
                std::process::exit(0);
            }
            // Reads stdin only once `<dir>/go` exists, then to EOF; writes how many bytes.
            "late-reader" => {
                let dir = Path::new(path);
                let end = Instant::now() + Duration::from_secs(60);
                while !dir.join("go").exists() && Instant::now() < end {
                    std::thread::sleep(Duration::from_millis(10));
                }
                let n = std::io::copy(&mut std::io::stdin().lock(), &mut std::io::sink()).unwrap();
                std::fs::write(dir.join("read.tmp"), n.to_string()).unwrap();
                std::fs::rename(dir.join("read.tmp"), dir.join("read.txt")).unwrap();
                std::process::exit(0);
            }
            // Says "boom" on stdout and on stderr, then fails (a `pg_ctl` that dies early).
            "say-boom" => {
                println!("out-boom");
                eprintln!("err-boom");
                std::process::exit(1);
            }
            // Writes the arguments after the harness's own, one per line.
            "write-args" => {
                let args: Vec<String> = std::env::args().skip(1 + child_args().len()).collect();
                std::fs::write(path, args.join("\n")).unwrap();
                std::process::exit(0);
            }
            // Writes the values of its stdin, stdout and stderr handles, one per line.
            #[cfg(windows)]
            "std-handles" => {
                use std::os::windows::io::AsRawHandle;
                let values = [
                    std::io::stdin().as_raw_handle(),
                    std::io::stdout().as_raw_handle(),
                    std::io::stderr().as_raw_handle(),
                ]
                .map(|h| format!("{h:?}"));
                std::fs::write(path, values.join("\n")).unwrap();
                std::process::exit(0);
            }
            // Waits for "go <owned job handles>" (the test puts it in its jobs first and
            // duplicates the handles of the jobs it declares sync_gate-owned into it), then
            // probes and starts, checking against exactly those jobs.
            #[cfg(windows)]
            "starter-in-job" => {
                let mut go = String::new();
                std::io::stdin().read_line(&mut go).unwrap();
                // "end-fails" makes ending the never-run starter fail (seam for PF33).
                let words: Vec<&str> = go.split_whitespace().skip(1).collect();
                let end_fails = words.contains(&"end-fails");
                let owned: Vec<Job> = words
                    .iter()
                    .filter(|w| **w != "end-fails")
                    .map(|h| h.parse().unwrap())
                    .collect();
                println!("probe:{}", probe_breakaway());
                let starter = child_command(&format!("spawn-detached:{path}"));
                let end = Instant::now() + Duration::from_secs(60);
                let failing = |_: &Suspended| Err(io::Error::other("injected end failure"));
                let end_unrun: &dyn Fn(&Suspended) -> io::Result<()> =
                    if end_fails { &failing } else { &Suspended::end };
                let r = start_detached(
                    starter,
                    &mut || Instant::now() >= end,
                    &|s| s.in_jobs(&owned),
                    end_unrun,
                    None,
                );
                print_starter_result(r);
            }
            // Puts itself in the job the real launcher made for a child of its own (so in the
            // registry), then calls the public `run_starter`: the production guard must fire.
            #[cfg(windows)]
            "starter-in-own-job" => {
                use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
                use windows_sys::Win32::System::Threading::GetCurrentProcess;
                let l = OsLauncher::default();
                let s = spawn_child(&l, "sleep");
                let job = l.children.lock().unwrap_or_else(|e| e.into_inner())[&s.pid].job;
                assert_ne!(job, 0);
                // SAFETY: live job handle and the pseudo handle of this process.
                let ok = unsafe { AssignProcessToJobObject(job as _, GetCurrentProcess()) };
                assert_ne!(ok, 0, "{}", io::Error::last_os_error());
                let starter = child_command(&format!("spawn-detached:{path}"));
                // Exiting closes the job, which takes this fixture and its "sleep" child along.
                print_starter_result(run_starter(starter, Duration::from_secs(60)));
            }
            _ => panic!("unknown child mode {spec}"),
        }
    }

    /// `<own pid> <own start> <grandchild pid> <grandchild start>`, renamed into place so a
    /// reader never sees half of it. Each identity is read by a process that holds it: our
    /// own, and the grandchild's while we hold it unreaped. A start time of 0 is unknown.
    fn write_pidfile(path: &str, grandchild: &Child) {
        let me = std::process::id();
        let start = |pid| identity_of(pid).unwrap_or(0);
        let line = format!(
            "{me} {} {} {}",
            start(me),
            grandchild.id(),
            start(grandchild.id())
        );
        let tmp = format!("{path}.tmp");
        std::fs::write(&tmp, line).unwrap();
        std::fs::rename(&tmp, path).unwrap();
    }

    /// `[(own pid, start), (grandchild pid, start)]`, or `None` for a line that does not parse.
    fn parse_pidfile(text: &str) -> Option<[(u32, u64); 2]> {
        let mut it = text.split(' ');
        let mut next = || Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?));
        Some([next()?, next()?])
    }

    /// Waits for the pidfile to appear and returns `(own pid, grandchild pid)`.
    fn read_pidfile(path: &Path) -> (u32, u32) {
        let end = Instant::now() + Duration::from_secs(20);
        loop {
            if let Ok(text) = std::fs::read_to_string(path) {
                let [(own, _), (grandchild, _)] = parse_pidfile(&text).unwrap();
                return (own, grandchild);
            }
            assert!(Instant::now() < end, "{} never appeared", path.display());
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// A `sleep` grandchild in its own session (Unix), owing nothing to its parent.
    #[allow(clippy::zombie_processes)] // the parent exits right after; nothing to reap
    fn spawn_detached_sleep(pidfile: &str) {
        let mut c = child_command("sleep");
        c.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(unix)]
        // SAFETY: setsid is async-signal-safe and touches no memory of the parent.
        unsafe {
            std::os::unix::process::CommandExt::pre_exec(&mut c, || {
                nix::unistd::setsid().map(drop).map_err(io::Error::from)
            });
        }
        let grandchild = c.spawn().unwrap();
        write_pidfile(pidfile, &grandchild);
    }

    /// Live (not zombie) processes whose parent is `pid` and that started after it.
    #[cfg(windows)]
    fn live_children_of(pid: u32) -> usize {
        use sysinfo::{Pid, ProcessRefreshKind, ProcessStatus, ProcessesToUpdate, System};
        let mut sys = System::new().unwrap();
        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing(),
        );
        let me = Pid::from_u32(pid);
        let born = sys.process(me).map_or(0, |p| p.start_time());
        sys.processes()
            .values()
            .filter(|p| p.parent() == Some(me) && p.start_time() >= born)
            .filter(|p| p.status() != ProcessStatus::Zombie)
            .count()
    }

    /// Gone, or a zombie nobody reaps (a container's pid 1 may not): no longer running.
    fn not_running(pid: u32) -> bool {
        use sysinfo::{Pid, ProcessRefreshKind, ProcessStatus, ProcessesToUpdate, System};
        let mut sys = System::new().unwrap();
        let p = Pid::from_u32(pid);
        sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[p]),
            true,
            ProcessRefreshKind::nothing(),
        );
        sys.process(p)
            .is_none_or(|x| x.status() == ProcessStatus::Zombie)
    }

    /// Waits up to 20 s for `pid` to stop running.
    fn wait_not_running(pid: u32) -> bool {
        let end = Instant::now() + Duration::from_secs(20);
        while !not_running(pid) {
            if Instant::now() >= end {
                return false;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        true
    }

    /// Waits up to 10 s until the process `pid` with identity `start` (recorded while it was
    /// known alive) is gone. A bare `process_alive` right after a reap is not a fact on
    /// Windows: an exited process stays listed while any handle on it is open. With no
    /// recorded start time, only `process_alive == Some(false)` counts.
    fn assert_gone(pid: u32, start: Option<u64>, what: &str) {
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            if (start.is_some() && identity_of(pid) != start)
                || sync_gate_probe::process_alive(pid) == Some(false)
            {
                return;
            }
            assert!(Instant::now() < end, "{what}: pid {pid} is still listed");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Waits up to 10 s until the launcher no longer counts `pid` with identity `start` as
    /// alive. Once the launcher has released its own entry it answers from the process table,
    /// where an exited process can linger (see `assert_gone`).
    fn assert_not_alive(l: &OsLauncher, pid: u32, start: u64) {
        let end = Instant::now() + Duration::from_secs(10);
        while l.is_alive(pid, start) {
            assert!(Instant::now() < end, "pid {pid} still counts as alive");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// What creating a suspended breakaway process from here does, without running anything.
    #[cfg(windows)]
    fn probe_breakaway() -> String {
        match create_suspended(&child_command("sleep"), true, None) {
            Err(e) => format!("create-failed:{:?}", e.raw_os_error()),
            Ok(s) => {
                let in_job = s.in_any_job();
                s.end().unwrap();
                format!("created:in_job={in_job:?}")
            }
        }
    }

    /// True when this test process itself sits in a job object (always false on Unix).
    #[cfg(windows)]
    fn current_in_job() -> bool {
        use windows_sys::Win32::System::JobObjects::IsProcessInJob;
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        let mut r = 0;
        // SAFETY: pseudo handle of this process, null job = any job, valid out pointer.
        let ok = unsafe { IsProcessInJob(GetCurrentProcess(), std::ptr::null_mut(), &mut r) };
        ok != 0 && r != 0
    }

    #[cfg(unix)]
    fn current_in_job() -> bool {
        false
    }

    /// PF31: the ambient job no longer decides anything; the tests only say where they ran.
    fn report_ambient(r: &io::Result<Option<i32>>) {
        println!(
            "ambient: in a job = {}; own job kills on close = {:?}; outcome {r:?}",
            current_in_job(),
            own_job_kills_on_close()
        );
    }

    /// `start_detached` with an injected expiry (the event a test waits for, not a clock),
    /// checked against the daemon's real registry of own jobs, as `run_starter` does.
    fn start_until(cmd: Command, expired: &mut dyn FnMut() -> bool) -> io::Result<Option<i32>> {
        #[cfg(windows)]
        return start_detached(
            cmd,
            expired,
            &|s| s.in_jobs(&own_jobs().lock().unwrap_or_else(|e| e.into_inner())),
            &Suspended::end,
            None,
        );
        #[cfg(unix)]
        return start_detached(cmd, expired, None);
    }

    /// The fixture's verdict line, then exit (its own exit ends whatever job it sits in).
    #[cfg(windows)]
    fn print_starter_result(r: io::Result<Option<i32>>) -> ! {
        // An exited child stays in the process table while any handle to it is open (seen on
        // hosted Windows runners): give the count up to 10 s to reach zero before reporting it.
        let end = Instant::now() + Duration::from_secs(10);
        let mut kids = live_children_of(std::process::id());
        while kids != 0 && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(50));
            kids = live_children_of(std::process::id());
        }
        match r {
            Ok(code) => println!("starter:ok:{code:?}:children={kids}"),
            Err(e) => println!("starter:err:{e}:children={kids}"),
        }
        std::io::stdout().flush().unwrap();
        std::process::exit(0);
    }

    /// Kills a fixture the test started (and reaps it), pass or fail.
    #[cfg(windows)]
    struct ChildGuard(Child);
    #[cfg(windows)]
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// A fresh absolute scratch folder, removed when the test ends (early returns included).
    struct PidDir(PathBuf);
    impl std::ops::Deref for PidDir {
        type Target = Path;
        fn deref(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for PidDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn pid_dir(tag: &str) -> PidDir {
        let dir = temp_dir(tag);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(dir.is_absolute());
        PidDir(dir)
    }

    #[test]
    fn run_tool_feeds_stdin_and_captures() {
        let out = run_tool(child_command("echo"), Some(b"a\n"), Duration::from_secs(60)).unwrap();
        assert_eq!(out.code, Some(0));
        // The harness prints its own header first; the tool's line ends the stream.
        assert!(out.stdout.ends_with("echo:a\n"), "{:?}", out.stdout);
    }

    #[test]
    fn run_tool_times_out_closes_stdin_and_ends_its_own_tree() {
        let dir = pid_dir("tool-timeout");
        let pidfile = dir.join("tree.pid");
        let _gg = PidfileGuard::new(pidfile.clone());
        let started = Instant::now();
        let cmd = child_command(&format!("tree-pidfile:{}", pidfile.display()));
        let mut start = None;
        let (r, _) = traced(
            cmd,
            Some(b"secret-on-stdin\n"),
            Duration::from_secs(1),
            try_open_job,
            &mut |e| {
                // Just created and unreaped: the start time read now is its own.
                if let ToolEvent::Spawned(pid) = e {
                    start = identity_of(pid);
                }
            },
        );
        let e = r.unwrap_err();
        let elapsed = started.elapsed();
        let (child, grandchild) = read_pidfile(&pidfile);
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(!e.to_string().contains("secret"), "{e}");
        assert!(
            elapsed >= Duration::from_secs(1) + TOOL_GRACE,
            "{elapsed:?}"
        );
        assert!(dir.join("tree.pid.eof").exists(), "stdin was never closed");
        assert_gone(child, start, "the tool child");
        assert!(wait_not_running(grandchild), "the tool's tree outlived it");
    }

    /// Records what `run_tool` did, for the tests that check the order of its steps.
    fn traced(
        cmd: Command,
        stdin: Option<&[u8]>,
        timeout: Duration,
        open: fn(&Child) -> io::Result<Job>,
        on_event: &mut dyn FnMut(ToolEvent),
    ) -> (io::Result<ToolOutput>, Vec<ToolEvent>) {
        traced_observing(cmd, stdin, timeout, open, &mut exited_unreaped, on_event)
    }

    /// `traced` with the exit observation replaced.
    fn traced_observing(
        cmd: Command,
        stdin: Option<&[u8]>,
        timeout: Duration,
        open: fn(&Child) -> io::Result<Job>,
        observe: &mut dyn FnMut(&mut Child) -> io::Result<bool>,
        on_event: &mut dyn FnMut(ToolEvent),
    ) -> (io::Result<ToolOutput>, Vec<ToolEvent>) {
        let mut events = Vec::new();
        let r = run_tool_with(cmd, stdin, timeout, open, observe, &mut |e| {
            on_event(e);
            events.push(e);
        });
        (r, events)
    }

    /// Review finding 1: the leader exits, a descendant keeps the output pipe open. The tree
    /// is signalled while the leader is still unreaped, the reap is the last step, and the
    /// descendant is ended when the output wait runs out.
    #[test]
    fn run_tool_signals_the_tree_only_before_reaping_its_leader() {
        let dir = pid_dir("tool-order");
        let pidfile = dir.join("holder.pid");
        let _gg = PidfileGuard::new(pidfile.clone());
        let cmd = child_command(&format!("pipe-holder:{}", pidfile.display()));
        let (mut leader, mut unreaped_at_signal) = (0, None);
        let (r, events) = traced(
            cmd,
            None,
            Duration::from_secs(60),
            try_open_job,
            &mut |e| match e {
                ToolEvent::Spawned(pid) => leader = pid,
                ToolEvent::SignalTree => unreaped_at_signal = Some(leader_unreaped(leader)),
                _ => {}
            },
        );
        println!("events: {events:?}");
        let e = r.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut, "{e}");
        // A `try_wait` in place of the non-reaping observation would fail here.
        assert_eq!(
            unreaped_at_signal,
            Some(true),
            "the leader was already reaped when the tree was signalled"
        );
        assert_eq!(events.last(), Some(&ToolEvent::Reap), "{events:?}");
        let reap = events.iter().position(|e| *e == ToolEvent::Reap).unwrap();
        assert_eq!(
            reap,
            events.len() - 1,
            "reaped more than once or too early: {events:?}"
        );
        assert!(
            events[..reap].contains(&ToolEvent::SignalTree),
            "{events:?}"
        );
        let (_, holder) = read_pidfile(&pidfile);
        assert!(
            wait_not_running(holder),
            "the descendant holding the pipe outlived the tool"
        );
    }

    /// Unix: the leader (already exited or not) is still our unreaped child, so `waitid`
    /// with `WNOWAIT` still finds it. Elsewhere there is nothing to check.
    #[cfg(unix)]
    fn leader_unreaped(pid: u32) -> bool {
        // SAFETY: a zeroed siginfo_t is a valid out buffer; WNOWAIT never reaps.
        unsafe {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            let r = libc::waitid(
                libc::P_PID,
                libc::id_t::from(pid),
                &mut info,
                libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
            );
            r == 0 && info.si_signo != 0
        }
    }

    #[cfg(not(unix))]
    fn leader_unreaped(_: u32) -> bool {
        true
    }

    /// Re-review item 5: the launcher signals the group of a leader that has exited while the
    /// leader is still an unreaped child (its pid and group id still ours), and reaps it last.
    #[cfg(unix)]
    #[test]
    fn os_launcher_signals_the_group_before_it_reaps_the_leader() {
        let dir = pid_dir("launcher-order");
        let pidfile = dir.join("holder.pid");
        let _gg = PidfileGuard::new(pidfile.clone());
        let l = OsLauncher::default();
        let s = spawn_child(&l, &format!("pipe-holder:{}", pidfile.display()));
        let _g = Guard(&l, s.pid, s.start_time);
        // The leader exits at once and leaves a descendant of its group running.
        let end = Instant::now() + Duration::from_secs(20);
        while !leader_unreaped(s.pid) {
            assert!(Instant::now() < end, "the leader never exited");
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut at_signal = None;
        let alive = l.is_alive_with(s.pid, s.start_time, &mut exited_unreaped, &mut |o| {
            at_signal = Some(leader_unreaped(o.child.id()));
            let _ = kill_own(o, true);
        });
        assert!(!alive);
        assert_eq!(
            at_signal,
            Some(true),
            "the leader was already reaped when the group was signalled"
        );
        let (_, holder) = read_pidfile(&pidfile);
        assert!(wait_not_running(holder), "the group was not signalled");
        // Reaped last: no zombie is left (waitid finds no child of that pid any more).
        assert!(!leader_unreaped(s.pid));
        assert!(l.children.lock().unwrap().is_empty());
    }

    /// Re-review finding 1: the observation reports that the leader is no longer our child
    /// (`ECHILD`: the kernel reaped it). Its pid and group id may be someone else's, so the
    /// group must never be signalled, on the normal-exit path ...
    #[cfg(unix)]
    #[test]
    fn run_tool_signals_nothing_once_the_leader_identity_is_lost_after_an_exit() {
        let mut observe = |c: &mut Child| -> io::Result<bool> {
            if exited_unreaped(c)? {
                return Err(identity_lost(io::Error::from_raw_os_error(libc::ECHILD)));
            }
            Ok(false)
        };
        let started = Instant::now();
        let (r, events) = traced_observing(
            child_command("echo"),
            None,
            Duration::from_secs(60),
            try_open_job,
            &mut observe,
            &mut |_| {},
        );
        println!("events: {events:?}");
        let e = r.unwrap_err();
        assert!(is_identity_lost(&e), "{e}");
        assert!(e.to_string().contains("could not be observed"), "{e}");
        assert!(!events.contains(&ToolEvent::SignalTree), "{events:?}");
        // Far below the 60 s timeout: only a wait for that timeout reaches this bound.
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "{:?}",
            started.elapsed()
        );
    }

    /// ... and on the deadline path (lost after the deadline, while stdin is already closed).
    #[cfg(unix)]
    #[test]
    fn run_tool_signals_nothing_once_the_leader_identity_is_lost_at_the_deadline() {
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen = closed.clone();
        let mut observe = move |_: &mut Child| -> io::Result<bool> {
            if seen.load(Ordering::SeqCst) {
                return Err(identity_lost(io::Error::from_raw_os_error(libc::ECHILD)));
            }
            Ok(false)
        };
        let (mut leader, mut start) = (0, 0);
        let (r, events) = traced_observing(
            child_command("sleep"),
            Some(b"input"),
            Duration::from_millis(300),
            try_open_job,
            &mut observe,
            &mut |e| match e {
                // Just created and unreaped: the start time read now is its own.
                ToolEvent::Spawned(pid) => {
                    leader = pid;
                    start = identity_of(pid).unwrap_or(0);
                }
                ToolEvent::StdinClosed => closed.store(true, Ordering::SeqCst),
                _ => {}
            },
        );
        // Nothing signalled it, so it still runs: the test ends it, only if it is still the
        // process recorded at spawn (identity unknown: nothing; it ends by itself).
        drop(GrandchildGuard(leader, start));
        println!("events: {events:?}");
        let e = r.unwrap_err();
        assert!(is_identity_lost(&e), "{e}");
        assert!(events.contains(&ToolEvent::StdinClosed), "{events:?}");
        assert!(!events.contains(&ToolEvent::SignalTree), "{events:?}");
        // The production reaper waits for it: no zombie is left.
        assert!(wait_reaped(leader), "the tool was left a zombie");
    }

    /// Waits up to 20 s for `pid` to be no child of ours at all: `waitid` answers `ECHILD`
    /// once it was reaped (it only reads, so a reused pid is never touched).
    #[cfg(unix)]
    fn wait_reaped(pid: u32) -> bool {
        let end = Instant::now() + Duration::from_secs(20);
        loop {
            // SAFETY: a zeroed siginfo_t is a valid out buffer; WNOWAIT never reaps.
            let r = unsafe {
                let mut info: libc::siginfo_t = std::mem::zeroed();
                libc::waitid(
                    libc::P_PID,
                    libc::id_t::from(pid),
                    &mut info,
                    libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
                )
            };
            if r != 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
                return true;
            }
            if Instant::now() >= end {
                return false;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Fix round 3, item A: the leader exits, its identity is lost, and a descendant keeps
    /// writing to the output pipe. Nothing is signalled, but the call closes its read ends
    /// before it returns, so the descendant's next write fails and it ends by itself.
    #[cfg(unix)]
    #[test]
    fn run_tool_closes_its_output_pipes_once_the_leader_identity_is_lost() {
        let dir = pid_dir("tool-lost-readers");
        let pidfile = dir.join("writer.pid");
        let _gg = PidfileGuard::new(pidfile.clone());
        let mut observe = |c: &mut Child| -> io::Result<bool> {
            if exited_unreaped(c)? {
                return Err(identity_lost(io::Error::from_raw_os_error(libc::ECHILD)));
            }
            Ok(false)
        };
        let (r, events) = traced_observing(
            child_command(&format!("pipe-writer:{}", pidfile.display())),
            None,
            Duration::from_secs(60),
            try_open_job,
            &mut observe,
            &mut |_| {},
        );
        println!("events: {events:?}");
        let e = r.unwrap_err();
        assert!(is_identity_lost(&e), "{e}");
        assert!(!events.contains(&ToolEvent::SignalTree), "{events:?}");
        let (_, writer) = read_pidfile(&pidfile);
        assert!(
            wait_not_running(writer),
            "the descendant kept writing: the read end was never closed"
        );
    }

    /// Item B: the observation fails with something other than `ECHILD` while the child still
    /// runs. Nothing is signalled, and the child is still reaped once it ends by itself.
    #[cfg(unix)]
    #[test]
    fn run_tool_reaps_a_child_it_can_no_longer_observe() {
        let mut observe = |_: &mut Child| -> io::Result<bool> {
            Err(identity_lost(io::Error::from_raw_os_error(libc::EPERM)))
        };
        let mut leader = 0;
        let (r, events) = traced_observing(
            child_command("nap"),
            None,
            Duration::from_secs(60),
            try_open_job,
            &mut observe,
            &mut |e| {
                if let ToolEvent::Spawned(pid) = e {
                    leader = pid;
                }
            },
        );
        println!("events: {events:?}");
        let e = r.unwrap_err();
        assert!(is_identity_lost(&e), "{e}");
        assert!(!events.contains(&ToolEvent::SignalTree), "{events:?}");
        assert!(wait_reaped(leader), "the tool was left a zombie");
    }

    /// Item B, launcher: an observation that fails while the child runs does not make it
    /// dead: still ours, kept, nothing signalled. The real observation then works as before.
    #[cfg(unix)]
    #[test]
    fn os_launcher_keeps_a_running_child_it_cannot_observe() {
        let l = OsLauncher::default();
        let s = spawn_child(&l, "sleep");
        let g = Guard(&l, s.pid, s.start_time);
        let mut gone = false;
        let alive = l.is_alive_with(
            s.pid,
            s.start_time,
            &mut |_| Err(identity_lost(io::Error::from_raw_os_error(libc::EPERM))),
            &mut |_| gone = true,
        );
        assert!(alive);
        assert!(l.children.lock().unwrap().contains_key(&s.pid));
        assert!(!gone);
        drop(g);
        assert!(l.children.lock().unwrap().is_empty());
    }

    /// Review finding 2: input larger than the pipe, a child that reads only after stdin was
    /// closed. It sees end of input after what the pipe held, never the rest; the error never
    /// carries the input.
    #[test]
    fn run_tool_closes_stdin_at_the_deadline_even_when_the_writer_is_blocked() {
        let dir = pid_dir("tool-stdin");
        let input = b"secret-input-".repeat(640 * 1024);
        let cmd = child_command(&format!("late-reader:{}", dir.display()));
        let go = dir.join("go");
        let started = Instant::now();
        let (r, events) = traced(
            cmd,
            Some(&input),
            Duration::from_secs(1),
            try_open_job,
            &mut |e| {
                // The child starts reading only once stdin is reported closed.
                if e == ToolEvent::StdinClosed {
                    std::fs::write(&go, "go").unwrap();
                }
            },
        );
        let elapsed = started.elapsed();
        println!("events: {events:?}; returned after {elapsed:?}");
        let e = r.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(!format!("{e} {e:?}").contains("secret"), "{e:?}");
        // Stdin was closed at the deadline, not whenever the blocked write happened to end:
        // the child read to EOF and exited within its grace.
        assert!(elapsed < Duration::from_secs(1) + TOOL_GRACE, "{elapsed:?}");
        let read: usize = {
            let end = Instant::now() + Duration::from_secs(20);
            loop {
                if let Ok(t) = std::fs::read_to_string(dir.join("read.txt")) {
                    break t.parse().unwrap();
                }
                assert!(Instant::now() < end, "the child never saw end of input");
                std::thread::sleep(Duration::from_millis(20));
            }
        };
        println!(
            "input {} bytes, the child read {read} before end of input",
            input.len()
        );
        assert!(
            read < input.len(),
            "the writer kept writing after the deadline"
        );
    }

    /// Review finding 3: no tool runs without tree isolation. The job step fails (seam): the
    /// child just created is ended and reaped, and the call fails.
    #[test]
    fn run_tool_refuses_to_run_a_tool_it_cannot_isolate() {
        let started = Instant::now();
        let failing: fn(&Child) -> io::Result<Job> = |_| Err(io::Error::other("injected"));
        let mut start = None;
        let (r, events) = traced(
            child_command("sleep"),
            None,
            Duration::from_secs(60),
            failing,
            &mut |e| {
                // Just created and unreaped: the start time read now is its own.
                if let ToolEvent::Spawned(pid) = e {
                    start = identity_of(pid);
                }
            },
        );
        println!("events: {events:?}");
        let e = r.unwrap_err();
        assert!(e.to_string().contains("isolate"), "{e}");
        // Only a hang or a tool that ran to its 60 s timeout can reach this bound.
        assert!(started.elapsed() < Duration::from_secs(20), "the tool ran");
        let Some(ToolEvent::Spawned(pid)) = events.first().copied() else {
            panic!("{events:?}");
        };
        assert_eq!(events.last(), Some(&ToolEvent::Reap), "{events:?}");
        assert_gone(pid, start, "the child that could not be isolated");
    }

    #[test]
    fn run_tool_caps_output() {
        let out = run_tool(child_command("flood"), None, Duration::from_secs(60)).unwrap();
        assert_eq!(out.code, Some(0));
        assert!(out.stdout.len() <= TOOL_OUTPUT_CAP, "{}", out.stdout.len());
        assert!(
            out.stdout.len() > TOOL_OUTPUT_CAP / 2,
            "{}",
            out.stdout.len()
        );
    }

    #[test]
    fn run_starter_leaves_the_grandchild_running_after_returning() {
        let dir = pid_dir("starter");
        let pidfile = dir.join("gc.pid");
        let _gg = PidfileGuard::new(pidfile.clone());
        let cmd = child_command(&format!("spawn-detached:{}", pidfile.display()));
        let r = run_starter(cmd, Duration::from_secs(60));
        report_ambient(&r);
        // PF31: whatever job this test process sits in, the starter starts.
        assert_eq!(r.unwrap(), Some(0));
        let (_, grandchild) = read_pidfile(&pidfile);
        // sync_gate holds no handle on the grandchild: it lives on its own.
        assert_eq!(sync_gate_probe::process_alive(grandchild), Some(true));
    }

    #[test]
    fn run_starter_timeout_ends_only_the_starter() {
        let dir = pid_dir("starter-timeout");
        let pidfile = dir.join("gc.pid");
        let _gg = PidfileGuard::new(pidfile.clone());
        let cmd = child_command(&format!("spawn-detached-then-sleep:{}", pidfile.display()));
        // The limit is the event "the grandchild exists", not a clock (a hard cap stays).
        let cap = Instant::now() + Duration::from_secs(30);
        let r = start_until(cmd, &mut || pidfile.exists() || Instant::now() >= cap);
        report_ambient(&r);
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::TimedOut);
        let (starter, grandchild) = read_pidfile(&pidfile);
        // The starter wrote its own start time while it lived (0 is unknown).
        let [(_, born), _] = parse_pidfile(&std::fs::read_to_string(&pidfile).unwrap()).unwrap();
        assert_gone(starter, Some(born).filter(|&b| b > 0), "the starter");
        assert_eq!(sync_gate_probe::process_alive(grandchild), Some(true));
    }

    #[test]
    fn run_starter_to_keeps_what_the_starter_printed() {
        let dir = pid_dir("starter-out");
        let out = dir.join("pg_ctl.out");
        std::fs::write(&out, "stale line from an earlier start\n").unwrap();
        let r = run_starter_to(child_command("say-boom:x"), Duration::from_secs(60), &out);
        report_ambient(&r);
        assert_eq!(r.unwrap(), Some(1));
        let got = std::fs::read_to_string(&out).unwrap();
        assert!(
            got.contains("out-boom") && got.contains("err-boom"),
            "{got:?}"
        );
        assert!(!got.contains("stale"), "truncated at each start: {got:?}");
    }

    #[test]
    fn run_starter_passes_arguments_verbatim() {
        let dir = pid_dir("starter-args");
        let out = dir.join("args.txt");
        let tricky = [
            "a b",
            "q\"x",
            r"tail\",
            r"sp tail\",
            "",
            r#"a\\b\"c"#,
            "\u{fc}n\u{ef}",
        ];
        let mut cmd = child_command(&format!("write-args:{}", out.display()));
        cmd.args(tricky);
        let r = run_starter(cmd, Duration::from_secs(60));
        report_ambient(&r);
        assert_eq!(r.unwrap(), Some(0));
        let got = std::fs::read_to_string(&out).unwrap();
        assert_eq!(got.split('\n').collect::<Vec<_>>(), tricky);
    }

    /// Issue 13: cmd.exe, run the way pg_ctl runs it (`cmd /C "postgres < nul >> log 2>&1"`),
    /// now and then exits 1 before it opens the log when its stdin, stdout and stderr are one
    /// handle. pg_ctl hands its own down, so the starter gets three distinct handles.
    #[cfg(windows)]
    #[test]
    fn run_starter_gives_the_starter_three_distinct_std_handles() {
        let dir = pid_dir("starter-handles");
        let report = dir.join("handles.txt");
        let mode = format!("std-handles:{}", report.display());
        for out in [None, Some(dir.join("out"))] {
            let r = run_starter_out(
                child_command(&mode),
                Duration::from_secs(60),
                out.as_deref(),
            );
            report_ambient(&r);
            assert_eq!(r.unwrap(), Some(0));
            let got = std::fs::read_to_string(&report).unwrap();
            let values: std::collections::HashSet<&str> = got.lines().collect();
            assert_eq!(values.len(), 3, "{got:?}");
        }
    }

    /// Stops the real cluster a test started (`pg_ctl stop -m immediate`), pass or fail.
    struct PgGuard {
        pg_ctl: PathBuf,
        data: PathBuf,
        stopped: bool,
    }
    impl PgGuard {
        /// Marked done only when the stop succeeded; otherwise `Drop` still tries.
        fn stop(&mut self, mode: &str) -> Option<i32> {
            let mut c = Command::new(&self.pg_ctl);
            c.arg("stop").arg("-D").arg(&self.data);
            c.args(["-m", mode, "-w", "-t", "30"]);
            let code = run_tool(c, None, Duration::from_secs(45)).ok()?.code;
            self.stopped = code == Some(0);
            code
        }
    }
    impl Drop for PgGuard {
        fn drop(&mut self) {
            if !self.stopped {
                let _ = self.stop("immediate");
            }
        }
    }

    /// A free loopback port, never the ones this machine or sync_gate already use.
    fn free_port() -> u16 {
        loop {
            let port = std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port();
            if port != 54329 && port != 28543 {
                return port;
            }
        }
    }

    #[test]
    fn run_starter_brings_up_a_real_postgres_that_outlives_the_starter() {
        let Some(bin) = std::env::var_os("SYNC_GATE_TEST_PG_BIN").map(PathBuf::from) else {
            assert!(
                std::env::var_os("CI").is_none(),
                "CI must set SYNC_GATE_TEST_PG_BIN"
            );
            println!("skipped: set SYNC_GATE_TEST_PG_BIN");
            return;
        };
        let tool = |name: &str| bin.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
        let dir = pid_dir("pg-start");
        let data = dir.join("data");
        let mut initdb = Command::new(tool("initdb"));
        initdb.arg("-D").arg(&data);
        initdb.args(["-U", "postgres", "-A", "trust", "-E", "UTF8", "--no-sync"]);
        let out = run_tool(initdb, None, Duration::from_secs(125)).unwrap();
        assert_eq!(out.code, Some(0), "{}", out.stderr);
        let port = free_port();
        let conf = data.join("postgresql.conf");
        let mut text = std::fs::read_to_string(&conf).unwrap();
        text.push_str(&format!(
            "\nport = {port}\nlisten_addresses = '127.0.0.1'\nunix_socket_directories = ''\n"
        ));
        std::fs::write(&conf, text).unwrap();

        let mut pg = PgGuard {
            pg_ctl: tool("pg_ctl"),
            data: data.clone(),
            stopped: false,
        };
        let mut start = Command::new(tool("pg_ctl"));
        start.arg("start").arg("-D").arg(&data);
        start.arg("-l").arg(dir.join("server.log"));
        start.args(["-w", "-t", "60"]);
        let r = run_starter(start, Duration::from_secs(75));
        report_ambient(&r);
        assert_eq!(r.unwrap(), Some(0));
        // `run_starter` has returned: every handle it had on the starter is closed.
        let mut psql = Command::new(tool("psql"));
        psql.args(["-h", "127.0.0.1", "-p", &port.to_string(), "-U", "postgres"]);
        psql.args(["-d", "postgres", "-Atc", "select 40 + 2"]);
        let out = run_tool(psql, None, Duration::from_secs(35)).unwrap();
        assert_eq!(out.code, Some(0), "{}", out.stderr);
        assert_eq!(out.stdout.trim(), "42");
        assert_eq!(pg.stop("fast"), Some(0));
    }

    #[cfg(windows)]
    #[test]
    fn windows_command_line_quotes_like_the_c_runtime() {
        let mut c = Command::new(r"C:\a b\x.exe");
        c.args([
            "plain",
            "a b",
            "q\"x",
            r"tail\",
            r"sp tail\",
            "",
            r"a\\b",
            "t\tab",
        ]);
        let line = String::from_utf16(&command_line(&c)).unwrap();
        // Backslashes double only before a quote, including the closing one.
        assert_eq!(
            line,
            r#""C:\a b\x.exe" plain "a b" "q\"x" tail\ "sp tail\\" "" a\\b "#.to_string()
                + "\"t\tab\"\0"
        );
    }

    /// A job object of the test's own, closed (and, with kill-on-close, its processes
    /// killed) on drop.
    #[cfg(windows)]
    struct TestJob(windows_sys::Win32::Foundation::HANDLE);

    #[cfg(windows)]
    impl TestJob {
        /// Kill-on-close, plus BREAKAWAY_OK when `breakaway`.
        fn new(breakaway: bool) -> Self {
            use windows_sys::Win32::System::JobObjects::{
                JOB_OBJECT_LIMIT_BREAKAWAY_OK, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            };
            let ba = if breakaway {
                JOB_OBJECT_LIMIT_BREAKAWAY_OK
            } else {
                0
            };
            Self::with_limits(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | ba)
        }

        fn with_limits(flags: u32) -> Self {
            use windows_sys::Win32::System::JobObjects::{
                CreateJobObjectW, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JobObjectExtendedLimitInformation, SetInformationJobObject,
            };
            // SAFETY: plain Win32 calls; the handle is owned by the returned guard.
            unsafe {
                let job = TestJob(CreateJobObjectW(std::ptr::null(), std::ptr::null()));
                assert!(!job.0.is_null());
                let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                info.BasicLimitInformation.LimitFlags = flags;
                let ok = SetInformationJobObject(
                    job.0,
                    JobObjectExtendedLimitInformation,
                    (&raw const info).cast(),
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                );
                assert_ne!(ok, 0);
                job
            }
        }

        fn assign(&self, child: &Child) {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
            // SAFETY: both handles are live for the call.
            let ok = unsafe { AssignProcessToJobObject(self.0, child.as_raw_handle() as _) };
            assert_ne!(ok, 0, "{}", io::Error::last_os_error());
        }

        /// This job's handle duplicated into `child`, as the value valid inside it.
        fn handle_in(&self, child: &Child) -> usize {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle};
            use windows_sys::Win32::System::Threading::GetCurrentProcess;
            let mut remote = std::ptr::null_mut();
            // SAFETY: live source and target process handles, a live job handle, valid out
            // pointer; the copy belongs to the child and closes when it exits.
            let ok = unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    self.0,
                    child.as_raw_handle() as _,
                    &mut remote,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            };
            assert_ne!(ok, 0, "{}", io::Error::last_os_error());
            remote as usize
        }
    }

    #[cfg(windows)]
    impl Drop for TestJob {
        fn drop(&mut self) {
            // SAFETY: the handle came from CreateJobObjectW and is closed once.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
        }
    }

    /// Spawns `mode` with piped stdin/stdout, puts it in `jobs` (in order), sends
    /// `go <handles of owned>` and returns its stdout lines with the guard.
    #[cfg(windows)]
    fn fixture_in_jobs(
        mode: &str,
        jobs: &[&TestJob],
        owned: &[&TestJob],
        extra: &[&str],
    ) -> (ChildGuard, Receiver<String>) {
        let mut c = child_command(mode);
        c.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut fixture = ChildGuard(c.spawn().unwrap());
        for job in jobs {
            job.assign(&fixture.0);
        }
        let mut words: Vec<String> = extra.iter().map(|w| w.to_string()).collect();
        words.extend(owned.iter().map(|j| j.handle_in(&fixture.0).to_string()));
        let mut stdin = fixture.0.stdin.take().unwrap();
        writeln!(stdin, "go {}", words.join(" ")).unwrap();
        let rx = lines_of(Box::new(fixture.0.stdout.take().unwrap()));
        (fixture, rx)
    }

    /// Waits up to 20 s for a fixture to exit (it exits right after its verdict line), so the
    /// job handles duplicated into it are closed before the test closes its own.
    #[cfg(windows)]
    fn wait_exit(fixture: &mut ChildGuard) {
        let end = Instant::now() + Duration::from_secs(20);
        while fixture.0.try_wait().unwrap().is_none() {
            assert!(Instant::now() < end, "fixture never exited");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Runs the "starter-in-job" fixture inside `jobs`, checking against `owned` (`extra`
    /// words go on its "go" line), and returns its probe line, its starter line, the
    /// grandchild pidfile it was given and the guard of that grandchild, installed first.
    #[cfg(windows)]
    fn starter_in_jobs(
        dir: &Path,
        jobs: &[&TestJob],
        owned: &[&TestJob],
        extra: &[&str],
    ) -> (String, String, PathBuf, PidfileGuard) {
        let pidfile = dir.join("gc.pid");
        let guard = PidfileGuard::new(pidfile.clone());
        let mode = format!("starter-in-job:{}", pidfile.display());
        let (mut fixture, rx) = fixture_in_jobs(&mode, jobs, owned, extra);
        let after = |line: String, tag: &str| line.split_once(tag).unwrap().1.to_string();
        let probe = after(wait_for(&rx, "probe:"), "probe:");
        let starter = after(wait_for(&rx, "starter:"), "starter:");
        wait_exit(&mut fixture);
        println!("measured: probe {probe}; starter {starter}");
        (probe, starter, pidfile, guard)
    }

    /// The grandchild a starter that ran left behind (its guard is already in place).
    #[cfg(windows)]
    fn grandchild_of(pidfile: &Path) -> u32 {
        read_pidfile(pidfile).1
    }

    #[cfg(windows)]
    fn assert_locked(starter: &str, pidfile: &Path) {
        assert!(
            starter.starts_with(&format!("err:{JOB_LOCKED}")),
            "{starter}"
        );
        assert!(!pidfile.exists(), "the starter ran");
    }

    #[cfg(windows)]
    #[test]
    fn a_server_started_from_a_breakaway_job_survives_the_job() {
        let dir = pid_dir("job-breakaway");
        let job = TestJob::new(true);
        // The job stands for one sync_gate owns: the starter must leave it and run.
        let (probe, starter, pidfile, _gg) = starter_in_jobs(&dir, &[&job], &[&job], &[]);
        assert!(probe.starts_with("created:"), "{probe}");
        assert_eq!(starter, "ok:Some(0):children=0");
        let grandchild = grandchild_of(&pidfile);
        // A sentinel in the same job shows when closing the job has killed what is in it.
        let mut sentinel = child_command("sleep");
        sentinel.stdin(Stdio::null()).stdout(Stdio::null());
        let sentinel = ChildGuard(sentinel.spawn().unwrap());
        job.assign(&sentinel.0);
        let sentinel_pid = sentinel.0.id();
        drop(job);
        assert!(
            wait_not_running(sentinel_pid),
            "closing the job killed nothing"
        );
        assert_eq!(sync_gate_probe::process_alive(grandchild), Some(true));
    }

    #[cfg(windows)]
    #[test]
    fn an_owned_job_without_breakaway_refuses_to_start() {
        let dir = pid_dir("job-locked");
        let job = TestJob::new(false);
        let (probe, starter, pidfile, _gg) = starter_in_jobs(&dir, &[&job], &[&job], &[]);
        // Measured: a job without BREAKAWAY_OK refuses the breakaway creation with
        // ERROR_ACCESS_DENIED; the retry without the flag lands in the owned job.
        assert_eq!(probe, "create-failed:Some(5)");
        assert_locked(&starter, &pidfile);
        // The never-run process is gone: the fixture has no child left.
        assert!(starter.ends_with("children=0"), "{starter}");
    }

    #[cfg(windows)]
    #[test]
    fn an_ambient_job_without_breakaway_lets_the_starter_run() {
        let dir = pid_dir("job-ambient");
        let job = TestJob::new(false);
        // Not declared sync_gate-owned: it stands for the job the daemon was started in.
        let (probe, starter, pidfile, _gg) = starter_in_jobs(&dir, &[&job], &[], &[]);
        assert_eq!(probe, "create-failed:Some(5)");
        assert_eq!(starter, "ok:Some(0):children=0");
        // It ran: its grandchild exists (inside the job, so it ends with it).
        let grandchild = grandchild_of(&pidfile);
        assert_eq!(sync_gate_probe::process_alive(grandchild), Some(true));
    }

    #[cfg(windows)]
    #[test]
    fn nested_jobs_refuse_only_when_the_starter_stays_in_an_owned_one() {
        let outer = TestJob::new(false);
        let inner = TestJob::new(true);
        let cases: [(&str, Vec<&TestJob>); 4] = [
            ("none", vec![]),
            ("inner", vec![&inner]),
            ("outer", vec![&outer]),
            ("both", vec![&inner, &outer]),
        ];
        for (name, owned) in cases {
            let dir = pid_dir(&format!("job-nested-{name}"));
            let (probe, starter, pidfile, _gg) =
                starter_in_jobs(&dir, &[&outer, &inner], &owned, &[]);
            println!("nested, owned {name}: probe {probe}; starter {starter}");
            // Measured: the breakaway creation succeeds, leaves the inner job (it allows it)
            // and stays in the outer one; only an owned outer job keeps it in.
            assert_eq!(probe, "created:in_job=Some(true)", "owned {name}");
            if matches!(name, "outer" | "both") {
                assert_locked(&starter, &pidfile);
            } else {
                assert_eq!(starter, "ok:Some(0):children=0", "owned {name}");
                let grandchild = grandchild_of(&pidfile);
                assert_eq!(sync_gate_probe::process_alive(grandchild), Some(true));
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn run_starter_refuses_inside_a_job_this_daemon_owns() {
        let dir = pid_dir("job-own-registry");
        let pidfile = dir.join("gc.pid");
        let _gg = PidfileGuard::new(pidfile.clone());
        let mode = format!("starter-in-own-job:{}", pidfile.display());
        let (mut fixture, rx) = fixture_in_jobs(&mode, &[], &[], &[]);
        let line = wait_for(&rx, "starter:");
        wait_exit(&mut fixture);
        let starter = line.split_once("starter:").unwrap().1;
        println!("measured: own-job registry: {starter}");
        assert_locked(starter, &pidfile);
    }

    /// PF33: a process this code created suspended is never left suspended. When ending the
    /// never-run starter fails, it is resumed and the error says so.
    #[cfg(windows)]
    #[test]
    fn a_starter_that_cannot_be_ended_is_resumed_not_left_frozen() {
        let dir = pid_dir("job-end-fails");
        let job = TestJob::new(false);
        let (_, starter, pidfile, _gg) = starter_in_jobs(&dir, &[&job], &[&job], &["end-fails"]);
        assert!(starter.starts_with("err:"), "{starter}");
        assert!(starter.contains("resumed"), "{starter}");
        // Resumed: it ran and wrote its marker.
        let (starter_pid, _) = read_pidfile(&pidfile);
        assert!(starter_pid > 0);
    }

    #[cfg(windows)]
    #[test]
    fn own_job_kills_on_close_reads_the_immediate_job() {
        use windows_sys::Win32::System::JobObjects::JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        println!(
            "measured: this test process: in a job = {}, kills on close = {:?}",
            current_in_job(),
            own_job_kills_on_close()
        );
        for (flags, want) in [
            (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, "Some(true)"),
            (0, "Some(false)"),
        ] {
            let job = TestJob::with_limits(flags);
            let (mut fixture, rx) = fixture_in_jobs("job-report", &[&job], &[], &[]);
            let line = wait_for(&rx, "jobreport:");
            wait_exit(&mut fixture);
            // The immediate job is the test's own, nested under whatever ambient job exists.
            assert!(line.ends_with(&format!("jobreport:{want}")), "{line}");
        }
    }

    fn child_args() -> [String; 4] {
        [
            "supervisor::tests::child_entry",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ]
        .map(String::from)
    }

    fn child_env(mode: &str) -> BTreeMap<String, String> {
        BTreeMap::from([("SYNC_GATE_TEST_CHILD".to_string(), mode.to_string())])
    }

    fn child_command(mode: &str) -> Command {
        let mut c = Command::new(std::env::current_exe().unwrap());
        c.args(child_args()).envs(child_env(mode));
        c
    }

    fn spawn_child(l: &OsLauncher, mode: &str) -> Spawned {
        let exe = std::env::current_exe().unwrap();
        l.spawn(
            exe.to_str().unwrap(),
            &child_args(),
            &child_env(mode),
            &[],
            None,
        )
        .unwrap()
    }

    /// Lines of a child's stdout, read on a helper thread so a test can never block forever.
    fn lines_of(out: Box<dyn Read + Send>) -> Receiver<String> {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        rx
    }

    /// The harness prints `test <name> ... ` on the same line, so match anywhere.
    fn wait_for(rx: &Receiver<String>, needle: &str) -> String {
        let end = Instant::now() + Duration::from_secs(20);
        while let Some(left) = end.checked_duration_since(Instant::now()) {
            match rx.recv_timeout(left) {
                Ok(l) if l.contains(needle) => return l,
                Ok(_) => {}
                Err(_) => break,
            }
        }
        panic!("child never printed {needle:?}");
    }

    /// Terminates the child (and its tree) even when an assertion fails.
    struct Guard<'a>(&'a OsLauncher, u32, u64);
    impl Drop for Guard<'_> {
        fn drop(&mut self) {
            let _ = self.0.terminate(self.1, self.2);
        }
    }

    /// Ends the grandchild a fixture writes to this pidfile, if it ever does. Installed
    /// before the fixture runs, so no result or assertion can leave the grandchild behind.
    /// The file carries the grandchild's identity (pid AND start time) as published by the
    /// fixture that held it; cleanup acts only on a process that still has that start time.
    /// A missing or unparsable file means nothing to end.
    struct PidfileGuard(PathBuf);
    impl PidfileGuard {
        fn new(path: PathBuf) -> Self {
            PidfileGuard(path)
        }
    }
    impl Drop for PidfileGuard {
        fn drop(&mut self) {
            let text = std::fs::read_to_string(&self.0).unwrap_or_default();
            if let Some([_, (pid, start)]) = parse_pidfile(&text) {
                drop(GrandchildGuard(pid, start));
            }
        }
    }

    /// Kills a process the test started if it is still the one recorded (pid and start time,
    /// read while it was held); a start time of 0 is unknown and nothing is done.
    struct GrandchildGuard(u32, u64);
    impl Drop for GrandchildGuard {
        fn drop(&mut self) {
            if self.1 == 0 || identity_of(self.0) != Some(self.1) {
                return;
            }
            #[cfg(unix)]
            if let Ok(p) = i32::try_from(self.0) {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(p),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
            #[cfg(windows)]
            let _ = kill_foreign(self.0, self.1, true);
        }
    }

    #[test]
    fn os_launcher_spawns_and_pipes() {
        let l = OsLauncher::default();
        let mut s = spawn_child(&l, "echo");
        let _g = Guard(&l, s.pid, s.start_time);
        assert!(s.start_time > 0 && s.exe.is_absolute());
        assert!(l.is_alive(s.pid, s.start_time));
        assert!(!l.is_alive(s.pid, s.start_time + 1));

        writeln!(s.stdin, "hello").unwrap();
        s.stdin.flush().unwrap();
        let rx = lines_of(s.stdout);
        let line = wait_for(&rx, "echo:hello");
        assert!(line.ends_with("echo:hello"), "{line:?}");

        stop_own(
            &l,
            s.pid,
            s.start_time,
            Some(s.stdin),
            Duration::from_secs(10),
        )
        .unwrap();
        assert_not_alive(&l, s.pid, s.start_time);
        // stop_own released the entry: nothing is left to reap or leak.
        assert!(l.children.lock().unwrap().is_empty());
    }

    #[test]
    fn os_launcher_removes_inherited_variables_it_is_told_to() {
        // PATH exists in the test process; the test never changes its own environment.
        assert!(std::env::var_os("PATH").is_some());
        let l = OsLauncher::default();
        let exe = std::env::current_exe().unwrap();
        let mut s = l
            .spawn(
                exe.to_str().unwrap(),
                &child_args(),
                &child_env("env"),
                &["PATH".to_string()],
                None,
            )
            .unwrap();
        let _g = Guard(&l, s.pid, s.start_time);
        writeln!(s.stdin, "PATH").unwrap();
        let rx = lines_of(s.stdout);
        let line = wait_for(&rx, "env:PATH=");
        assert!(line.ends_with("env:PATH=absent"), "{line:?}");
    }

    /// The extension keeps the case `PATHEXT` wrote; Windows file names ignore case.
    fn same_file(a: &Path, b: &Path) -> bool {
        if cfg!(windows) {
            a.to_string_lossy().to_lowercase() == b.to_string_lossy().to_lowercase()
        } else {
            a == b
        }
    }

    #[test]
    fn hubreload_the_os_launcher_uses_the_servers_path() {
        let dir = temp_dir("resolve-path");
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(windows)]
        let file = dir.join("fgx.cmd");
        #[cfg(unix)]
        let file = dir.join("fgx");
        std::fs::write(&file, "#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let l = OsLauncher::default();
        let path = dir.to_string_lossy().into_owned();
        let got = l.resolve("fgx", &BTreeMap::from([("PATH".to_string(), path.clone())]));
        assert!(
            got.as_deref().is_some_and(|g| same_file(g, &file)),
            "{got:?}"
        );
        // Windows names are case-insensitive, so is the server's `Path`.
        #[cfg(windows)]
        {
            let got = l.resolve("fgx", &BTreeMap::from([("Path".to_string(), path.clone())]));
            assert!(
                got.as_deref().is_some_and(|g| same_file(g, &file)),
                "{got:?}"
            );
        }
        // Without a PATH of its own: the daemon's (which does not have that folder).
        assert_eq!(l.resolve("fgx", &BTreeMap::new()), None);
        // A name with a folder part is itself.
        let sub = BTreeMap::from([("PATH".to_string(), path)]);
        assert_eq!(l.resolve("sub/fgx", &sub), Some(PathBuf::from("sub/fgx")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn hubreload_the_os_launcher_finds_a_name_with_an_extension_exactly() {
        let dir = temp_dir("exact-ext");
        std::fs::create_dir_all(&dir).unwrap();
        for f in ["tool.exe", "tool.exe.cmd"] {
            std::fs::write(dir.join(f), "").unwrap();
        }
        let env = BTreeMap::from([("PATH".to_string(), dir.to_string_lossy().into_owned())]);
        let l = OsLauncher::default();
        let got = l.resolve("tool.exe", &env);
        assert!(
            got.as_deref()
                .is_some_and(|g| same_file(g, &dir.join("tool.exe"))),
            "{got:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hubreload_the_os_launcher_never_runs_a_bare_name_it_did_not_find() {
        let dir = temp_dir("bare-none");
        let shims = dir.join("shims");
        std::fs::create_dir_all(&shims).unwrap();
        std::fs::write(shims.join(sync_gate_core::SHIMS_MANIFEST), "{}").unwrap();
        let marker = dir.join("ran");
        #[cfg(windows)]
        let name = "fgn.exe";
        #[cfg(unix)]
        let name = "fgn";
        std::fs::write(
            shims.join(name),
            format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o755);
            std::fs::set_permissions(shims.join(name), perms).unwrap();
        }
        let env = BTreeMap::from([("PATH".to_string(), shims.to_string_lossy().into_owned())]);
        let l = OsLauncher::default();
        assert_eq!(l.resolve(name, &env), None);
        let err = l.spawn(name, &[], &env, &[], None).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(!marker.exists(), "the shim ran");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn hubreload_the_os_launcher_finds_a_cmd_through_pathext() {
        let dir = temp_dir("pathext-cmd");
        std::fs::create_dir_all(&dir).unwrap();
        let exe = std::env::current_exe().unwrap();
        std::fs::write(
            dir.join("fgx.cmd"),
            format!("@\"{}\" %*\r\n", exe.display()),
        )
        .unwrap();
        // The server's PATH: the folder first, then the daemon's.
        let mut path = dir.clone().into_os_string();
        path.push(";");
        path.push(std::env::var_os("PATH").unwrap_or_default());
        let mut env = child_env("echo");
        env.insert("PATH".into(), path.to_string_lossy().into_owned());
        let l = OsLauncher::default();
        let mut s = l.spawn("fgx", &child_args(), &env, &[], None).unwrap();
        let g = Guard(&l, s.pid, s.start_time);
        writeln!(s.stdin, "hello").unwrap();
        s.stdin.flush().unwrap();
        let rx = lines_of(s.stdout);
        let line = wait_for(&rx, "echo:hello");
        assert!(line.ends_with("echo:hello"), "{line:?}");
        drop(g);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn os_launcher_terminates_a_live_child_and_refuses_a_wrong_identity() {
        let l = OsLauncher::default();
        let s = spawn_child(&l, "echo");
        let _g = Guard(&l, s.pid, s.start_time);
        // Wrong start time: treated as someone else's process, left alone.
        l.terminate(s.pid, s.start_time + 1).unwrap();
        assert!(l.is_alive(s.pid, s.start_time));
        // Start time 0 is unverifiable: also left alone.
        l.terminate(s.pid, 0).unwrap();
        assert!(l.is_alive(s.pid, s.start_time));
        // stdin still open, so only terminate can end it.
        l.terminate(s.pid, s.start_time).unwrap();
        assert_not_alive(&l, s.pid, s.start_time);
    }

    #[test]
    fn stop_own_stops_an_own_child_whose_start_time_is_unknown() {
        let l = OsLauncher::default();
        let s = spawn_child(&l, "sleep");
        let _g = Guard(&l, s.pid, s.start_time);
        // Simulate an unreadable start time at spawn: the held handle is the identity.
        // The job is parked outside the entry, so dropping the entry cannot hide a missed stop.
        let job = {
            let mut t = l.children.lock().unwrap();
            let o = t.get_mut(&s.pid).unwrap();
            o.start_time = 0;
            std::mem::take(&mut o.job)
        };
        // The "sleep" child ignores stdin EOF, so only terminate can end it.
        stop_own(&l, s.pid, 0, Some(s.stdin), Duration::from_millis(200)).unwrap();
        let end = Instant::now() + Duration::from_secs(10);
        while identity_of(s.pid) == Some(s.start_time) && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(50));
        }
        let gone = identity_of(s.pid) != Some(s.start_time);
        close_job(job);
        assert!(gone, "an own child with start time 0 must still be stopped");
    }

    #[test]
    fn leftover_is_signalled_only_as_a_foreign_group_leader() {
        // (pid, pgid, own pgid)
        assert!(leftover_may_be_signalled(500, Some(500), 100));
        assert!(
            !leftover_may_be_signalled(500, Some(400), 100),
            "not a leader"
        );
        assert!(
            !leftover_may_be_signalled(100, Some(100), 100),
            "daemon's own group"
        );
        assert!(
            !leftover_may_be_signalled(500, None, 100),
            "unreadable pgid"
        );
    }

    #[test]
    fn stop_own_takes_down_the_grandchild_too() {
        let l = OsLauncher::default();
        let s = spawn_child(&l, "tree");
        let _g = Guard(&l, s.pid, s.start_time);
        let rx = lines_of(s.stdout);
        let line = wait_for(&rx, "pids:");
        // `pids:<own>:<grandchild>:<its start time, read by the parent that holds it>`.
        let mut fields = line.rsplit(':');
        let gc_start: u64 = fields.next().unwrap().trim().parse().unwrap();
        let grandchild: u32 = fields.next().unwrap().parse().unwrap();
        let _gg = GrandchildGuard(grandchild, gc_start);

        // The tree child ignores stdin EOF, so only terminate can end it.
        stop_own(
            &l,
            s.pid,
            s.start_time,
            Some(s.stdin),
            Duration::from_millis(200),
        )
        .unwrap();
        // A zombie counts as ended: in a container nothing may reap the orphaned grandchild.
        assert!(
            wait_not_running(grandchild),
            "the grandchild outlived stop_own"
        );
        assert_not_alive(&l, s.pid, s.start_time);
    }

    #[test]
    fn stop_own_reports_the_exit_code_of_an_own_child() {
        let l = OsLauncher::default();
        let s = spawn_child(&l, "exit3");
        let _g = Guard(&l, s.pid, s.start_time);
        let code = stop_own(
            &l,
            s.pid,
            s.start_time,
            Some(s.stdin),
            Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!(code, Some(3));
    }

    /// Review F08: a new child that reuses a pid never reports the exit code kept for the
    /// child that had the pid before it.
    #[test]
    fn a_new_child_on_a_reused_pid_drops_the_old_exit_code() {
        let l = OsLauncher::default();
        let mut c = child_command("exit3").spawn().unwrap();
        c.wait().unwrap();
        let pid = c.id();
        l.exits.lock().unwrap().insert(pid, 7);
        l.track(
            pid,
            Owned {
                child: c,
                start_time: 0,
                job: 0,
            },
        );
        assert_eq!(l.exits.lock().unwrap().get(&pid), None, "old code kept");
        assert_eq!(l.reap(pid), Some(3));
    }

    /// Review F08: a child dropped without a code (killed by a signal on Unix) forgets the
    /// code kept for an older child on the same pid.
    #[test]
    fn a_child_gone_without_a_code_forgets_the_old_one() {
        let l = OsLauncher::default();
        l.note_exit(4242, Some(7));
        l.note_exit(4242, None);
        assert_eq!(l.reap(4242), None);
    }

    #[test]
    fn an_os_launcher_survives_a_poisoned_table() {
        let l = Arc::new(OsLauncher::default());
        let before = poisonings();
        let held = l.clone();
        let _ = std::thread::spawn(move || {
            let _t = held.children.lock().unwrap();
            panic!("poison the table");
        })
        .join();
        assert!(l.children.is_poisoned());
        // Neither panics; the poisoning is counted for the hub to note.
        assert!(!l.is_alive(u32::MAX - 1, 1));
        assert_eq!(l.reap(u32::MAX - 1), None);
        assert!(!l.children.is_poisoned(), "not recovered");
        assert!(poisonings() > before);
    }

    /// The start-time cleanup has a total deadline: a row not reached by then is neither
    /// signalled nor forgotten, it waits on disk for the next start.
    #[test]
    fn leftover_reaping_stops_at_its_deadline_and_keeps_the_rest() {
        let dir = temp_dir("deadline");
        let path = dir.join("services.json");
        let mut reg = Registry::load(&path);
        for (name, pid) in [("a", 10), ("b", 20), ("c", 30)] {
            reg.record(name, pid, 1, Path::new("/bin/x"));
        }
        let mut f = Fake::new(false, false);
        f.only = vec![10, 20, 30];
        for pid in [10, 20, 30] {
            f.exes.insert(pid, "/bin/x".into());
        }
        f.slow = Duration::from_millis(300);
        let deadline = Instant::now() + Duration::from_millis(100);
        assert_eq!(reap_leftovers_until(&f, &mut reg, deadline), 1);
        let terminated: Vec<_> = f
            .calls()
            .into_iter()
            .filter(|c| c.starts_with("terminate"))
            .collect();
        assert_eq!(terminated, ["terminate 10"]);
        let kept: Vec<_> = Registry::load(&path).leftovers();
        assert_eq!(kept.iter().map(|r| r.1).collect::<Vec<_>>(), vec![20, 30]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
