//! End to end with a real PostgreSQL: the real `sync_gate` binary against a daemon with
//! `Deps::os()` (in this process through `sync_gated::run_with`, or a child process for the crash
//! test), and the `psql` of `SYNC_GATE_TEST_PG_BIN` as the agent's command.
//!
//! The command is this test binary re-executed (`child_entry`, driven by `SYNC_GATE_TEST_CHILD`).
//! Modes: `env` (writes its pid and the connection variables it sees to `FG_TEST_OUT`, exits
//! with `FG_TEST_EXIT_CODE`, default 0), `hold` (as `env`, then waits for the file
//! `FG_TEST_STOP`), `psql-loop` (as `hold`; for each trigger file `<FG_TEST_TRIGGER>.<n>`, n = 1,
//! 2, ..., it runs `<FG_TEST_PSQL> -X -At -w -c "select <n>"` with its own environment and
//! writes the output to `<FG_TEST_RESULT>.<n>`) and `daemon` (runs `sync_gated::run_with` with
//! `FG_TEST_CONFIG`, `FG_TEST_SOCKET` and `FG_TEST_DATA`, writes `FG_TEST_OUT` once it serves,
//! and shuts down at `FG_TEST_STOP`). No path travels inside the mode string. Every fixture also
//! ends when the folder of its stop file is gone or after `FIXTURE_LIFETIME`.
//!
//! A project's `migrate` is this binary too, with its mode in its argv (`migrate:<mode>`), since
//! it inherits the command's `SYNC_GATE_TEST_CHILD`; see `migrate_entry`.
//!
//! Each real test has its own scratch folder (a space in its name) and free port and runs alone
//! (`testkit::serial`); without `SYNC_GATE_TEST_PG_BIN` it prints
//! `skipped: set SYNC_GATE_TEST_PG_BIN` and returns (under `CI` it fails).
//!
//! Two waits are bounded by something other than a deadline in this file: `testkit::serial()`
//! (std has no timed lock) lasts as long as the one test that holds it, and every test is itself
//! bounded; the testkit helpers that run a PostgreSQL tool go through production `run_tool`,
//! which enforces the tool's limit, ends its tree and reaps it.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, mpsc};
use std::time::{Duration, Instant};
use sync_gate_core::{
    Config, MIB, MachineSnapshot, Request, Response, ServiceStatus, StatusReport,
};
use sync_gate_probe::Probe;
use sync_gated::services::pg_sql::ADMIN_PREAMBLE;
use sync_gated::services::pg_tools::{ClusterPaths, OsPgTools, PgTools, ServerId};
use sync_gated::services::testkit::{
    Scratch, ServerGuard, free_port, pg_bin, psql_tcp, serial, user_server,
};
use sync_gated::supervisor::{ToolOutput, run_tool};
use sync_gated::{DaemonHandle, Deps, Measure, OsControl, OsLauncher};

static COUNTER: AtomicU32 = AtomicU32::new(0);

// Hard limits, each from a row of the plan's "Prazos" table.
/// "teste: cluster running": cold start 335 s + 25 s.
const RUNNING: Duration = Duration::from_secs(360);
/// "adocao ate running" (105 s) + the 25 s slack of the cold-start test row.
const ADOPTED: Duration = Duration::from_secs(130);
/// "teste: sync_gate run terminar (concessao que sai)": 75 s.
const RUN_ENDS: Duration = Duration::from_secs(75);
/// The command starts after a lease granted on a running server: the patience (30 s) + 5 s.
const STARTS: Duration = Duration::from_secs(35);
/// A run whose CLI migrates first, to its end: three requests within the patience (90 s), the
/// `migrate` (its wait for a session, `EVENT`, and its `psql`, `PSQL` + 5 s) and 15 s.
const MIGRATES: Duration = Duration::from_secs(200);
/// "o comando comeca quando a concessao demora mais que a paciencia": patience 1 s + 5 s.
const START_AFTER_GIVE_UP: Duration = Duration::from_secs(6);
/// "teste: banco sumir depois da devolucao": 410 s.
const DB_GONE: Duration = Duration::from_secs(410);
/// "demais eventos com o cluster de pe e fora da fila": 60 s (a fixture's `psql` included).
const EVENT: Duration = Duration::from_secs(60);
/// "um script psql": 30 s (`run_tool` adds its 5 s grace; the fixture adds the same).
const PSQL: Duration = Duration::from_secs(30);
/// The thread that collects a process's stderr.
const STDERR_JOIN: Duration = Duration::from_secs(60);
/// The lifetime of a fixture nobody stops: longer than any test (the crash test waits at most
/// RUNNING + ADOPTED + a few EVENTs while its loop lives).
const FIXTURE_LIFETIME: Duration = Duration::from_secs(900);
/// The daemon's own shutdown bounds added up (drain 5 s, hub 16 s, server wake 5 s, postgres
/// stop 85 s: 111 s), with a margin.
const DAEMON_SHUTDOWN: Duration = Duration::from_secs(120);
/// How long a killed process may take to be reaped.
const REAP: Duration = Duration::from_secs(10);

/// Kills the child (result ignored) and polls for its exit, never blocking in `wait`; whether
/// it was reaped within `limit`.
fn reap(child: &mut Child, limit: Duration) -> bool {
    let _ = child.kill();
    let start = Instant::now();
    loop {
        if let Ok(Some(_)) = child.try_wait() {
            return true;
        }
        if start.elapsed() >= limit {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Prints from a destructor without waiting: a detached writer that blocks forever on a dead
/// stderr is left behind and cannot hold up the test.
fn note(msg: String) {
    let _ = std::thread::Builder::new().spawn(move || {
        let _ = writeln!(std::io::stderr(), "{msg}");
    });
}

/// A failed cleanup fails a test whose assertions passed; during an unwind it is only noted.
fn cleanup_failed(msg: String) {
    if std::thread::panicking() {
        note(msg);
    } else {
        panic!("{msg}");
    }
}

const PG_VARS: [&str; 8] = [
    "PGHOST",
    "PGPORT",
    "PGUSER",
    "PGDATABASE",
    "PGPASSWORD",
    "PGSSLMODE",
    "PGSERVICE",
    "DATABASE_URL",
];

fn var_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("{name} is not set")))
}

/// `<p><suffix>`
fn suffixed(p: &Path, suffix: &str) -> PathBuf {
    let mut s: OsString = p.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

/// `<p>.<n>`
fn nth(p: &Path, n: u32) -> PathBuf {
    suffixed(p, &format!(".{n}"))
}

fn write_atomic(path: &Path, text: &str) {
    let tmp = suffixed(path, ".tmp");
    std::fs::write(&tmp, text).unwrap();
    std::fs::rename(&tmp, path).unwrap();
}

/// The stop file exists, its folder is gone, or the fixture has lived its lifetime.
fn stopped(stop: &Path, born: Instant) -> bool {
    stop.exists() || !stop.parent().is_some_and(Path::exists) || born.elapsed() >= FIXTURE_LIFETIME
}

fn wait_stop(stop: &Path) {
    let born = Instant::now();
    while !stopped(stop, born) {
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Child-process entry; inert unless `SYNC_GATE_TEST_CHILD` is set or an argument starts with
/// `migrate:`.
#[test]
fn child_entry() {
    if let Some(m) = std::env::args().find(|a| a.starts_with("migrate:")) {
        migrate_entry(&m["migrate:".len()..]);
    }
    let Ok(mode) = std::env::var("SYNC_GATE_TEST_CHILD") else {
        return;
    };
    if mode == "daemon" {
        daemon_child();
    }
    let mut text = format!("pid={}\n", std::process::id());
    for name in PG_VARS {
        if let Ok(v) = std::env::var(name) {
            text.push_str(&format!("{name}={v}\n"));
        }
    }
    write_atomic(&var_path("FG_TEST_OUT"), &text);
    match mode.as_str() {
        "env" => {
            let code = std::env::var("FG_TEST_EXIT_CODE")
                .ok()
                .and_then(|c| c.parse().ok())
                .unwrap_or(0);
            std::process::exit(code);
        }
        "hold" => {
            wait_stop(&var_path("FG_TEST_STOP"));
            std::process::exit(0);
        }
        "psql-loop" => psql_loop(),
        other => panic!("unknown child mode {other}"),
    }
}

/// One `psql` per trigger file, with this process's own environment (the lease's variables).
fn psql_loop() -> ! {
    let (stop, trigger) = (var_path("FG_TEST_STOP"), var_path("FG_TEST_TRIGGER"));
    let (result, psql) = (var_path("FG_TEST_RESULT"), var_path("FG_TEST_PSQL"));
    let born = Instant::now();
    let mut n = 1;
    while !stopped(&stop, born) {
        if !nth(&trigger, n).exists() {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }
        let (out, err) = (
            suffixed(&nth(&result, n), ".out"),
            suffixed(&nth(&result, n), ".err"),
        );
        let mut c = Command::new(&psql);
        c.args(["-X", "-At", "-w", "-c", &format!("select {n}")])
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(&out).unwrap())
            .stderr(std::fs::File::create(&err).unwrap());
        let code = exit_within(&mut c.spawn().unwrap(), PSQL + Duration::from_secs(5));
        let read = |p: &Path| std::fs::read_to_string(p).unwrap_or_default();
        let text = match code {
            Some(0) => read(&out).trim().to_string(),
            c => format!("error {c:?}: {}", read(&err).trim()),
        };
        write_atomic(&nth(&result, n), &text);
        n += 1;
    }
    std::process::exit(0);
}

/// The exit code of `child` once it exits; past `limit` it is ended and reaped (bounded) and the
/// result is `None`. An error here must not unwind past the live child: polling goes on to the
/// limit.
fn exit_within(child: &mut Child, limit: Duration) -> Option<i32> {
    let start = Instant::now();
    loop {
        if let Ok(Some(s)) = child.try_wait() {
            return s.code();
        }
        if start.elapsed() >= limit {
            reap(child, REAP);
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The project's `migrate`, run in the project folder with the candidate's variables: it appends
/// `run` to `migrate.log` and writes the `PGUSER` it got to `migrate.env`, then runs
/// `<FG_TEST_PSQL> -X -v ON_ERROR_STOP=1 -f schema.sql` and exits with its code. Modes: `psql`
/// (just that) and `psql-bg` (first leaves a session of its own behind, `SELECT pg_sleep(600)`
/// in a `psql` it never waits for, and waits until the server shows it).
fn migrate_entry(mode: &str) -> ! {
    let mut log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("migrate.log")
        .unwrap();
    writeln!(log, "run").unwrap();
    let user = std::env::var("PGUSER").unwrap_or_default();
    std::fs::write("migrate.env", format!("PGUSER={user}\n")).unwrap();
    let psql = var_path("FG_TEST_PSQL");
    let limit = PSQL + Duration::from_secs(5);
    match mode {
        "psql" => {}
        "psql-bg" => {
            let mut bg = Command::new(&psql);
            bg.args(["-X", "-c", LEFT_BEHIND])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            // Dropped, not waited for: the session outlives this process.
            drop(bg.spawn().unwrap());
            let seen = format!(
                "SELECT count(*) FROM pg_stat_activity WHERE usename = current_user \
                 AND query = '{LEFT_BEHIND}'"
            );
            let start = Instant::now();
            loop {
                let mut q = Command::new(&psql);
                q.args(["-X", "-A", "-t", "-c", &seen])
                    .stdin(Stdio::null())
                    .stdout(std::fs::File::create("seen.out").unwrap())
                    .stderr(Stdio::null());
                let code = exit_within(&mut q.spawn().unwrap(), limit);
                let out = std::fs::read_to_string("seen.out").unwrap_or_default();
                if code == Some(0) && out.trim() == "1" {
                    break;
                }
                // Without the session the test would prove nothing: the migration fails.
                if start.elapsed() >= EVENT {
                    std::process::exit(9);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        other => panic!("unknown migrate mode {other}"),
    }
    let mut c = Command::new(&psql);
    c.args(["-X", "-v", "ON_ERROR_STOP=1", "-f", SCHEMA])
        .stdin(Stdio::null());
    let code = exit_within(&mut c.spawn().unwrap(), limit);
    std::process::exit(code.unwrap_or(-1));
}

/// The watched file of a project with `migrate`, in the project folder.
const SCHEMA: &str = "schema.sql";

/// The query of the session `psql-bg` leaves behind.
const LEFT_BEHIND: &str = "SELECT pg_sleep(600)";

/// The argv of a `migrate` that is this binary in `migrate_entry`'s `mode`.
fn migrate_argv(mode: &str) -> Vec<String> {
    let exe = std::env::current_exe().unwrap();
    let mode = format!("migrate:{mode}");
    [
        exe.to_str().unwrap(),
        "child_entry",
        &mode,
        "--exact",
        "--nocapture",
        "--test-threads=1",
    ]
    .map(String::from)
    .to_vec()
}

/// A real daemon in this process until the stop file appears; the test may kill it instead.
fn daemon_child() -> ! {
    let text = std::fs::read_to_string(var_path("FG_TEST_CONFIG")).unwrap();
    let cfg = Config::from_toml(&text).unwrap();
    let socket = std::env::var("FG_TEST_SOCKET").unwrap();
    let d = sync_gated::run_with(
        cfg,
        &socket,
        fixed(),
        OsControl,
        Some(var_path("FG_TEST_DATA")),
        Arc::new(OsLauncher::default()),
    )
    .unwrap();
    write_atomic(&var_path("FG_TEST_OUT"), "ready");
    wait_stop(&var_path("FG_TEST_STOP"));
    d.shutdown();
    std::process::exit(0);
}

/// Real tree RSS, but a fixed machine with room for every job, so admission never queues.
struct FixedMachine(Probe);

impl Measure for FixedMachine {
    fn snapshot(&mut self) -> MachineSnapshot {
        MachineSnapshot {
            total: 65536 * MIB,
            available: 32768 * MIB,
            reclaimable: 0,
            swap_used: 0,
            swap_total: 0,
            vram: None,
        }
    }
    fn tree_rss(&mut self, pid: u32) -> u64 {
        self.0.tree_rss(pid)
    }
    fn start_time(&mut self, pid: u32) -> Option<u64> {
        sync_gate_probe::start_time(pid)
    }
}

fn fixed() -> FixedMachine {
    FixedMachine(Probe::new())
}

/// A spawned process of this test (a CLI, a daemon, a `psql`). Dropping it (a failed test)
/// writes its stop file, ends and reaps the process (std only signals a child it has not
/// reaped) and bounds the stderr thread.
struct Proc {
    child: Option<Child>,
    err: mpsc::Receiver<String>,
    stop: PathBuf,
}

struct Out {
    code: i32,
    stderr: String,
}

impl Out {
    /// What a failure message may say about a CLI process: never its text, which could carry a
    /// lease's secret.
    fn shape(&self) -> String {
        format!(
            "exit code {}, {} stderr bytes, `no shared database` line: {}",
            self.code,
            self.stderr.len(),
            self.stderr.contains("no shared database")
        )
    }

    /// The CLI's own lines (`sync_gate: ...`): reasons, never a lease's variables.
    fn notes(&self) -> Vec<&str> {
        self.stderr
            .lines()
            .filter(|l| l.starts_with("sync_gate:"))
            .collect()
    }
}

impl Proc {
    fn spawn(mut c: Command, stop: &Path) -> Proc {
        let (tx, err) = mpsc::channel();
        // The guard owns the child right after the spawn: nothing that can panic runs before.
        let mut p = Proc {
            child: Some(c.spawn().unwrap()),
            err,
            stop: stop.to_path_buf(),
        };
        let mut pipe = p.child.as_mut().and_then(|c| c.stderr.take());
        // A refused thread is an ordinary failure raised while `p` already owns the child.
        std::thread::Builder::new()
            .spawn(move || {
                // Bytes: a translated message that is not UTF-8 must not empty the whole text.
                let mut s = Vec::new();
                if let Some(p) = pipe.as_mut() {
                    let _ = p.read_to_end(&mut s);
                }
                let _ = tx.send(String::from_utf8_lossy(&s).into_owned());
            })
            .unwrap_or_else(|e| panic!("cannot start the stderr reader: {e}"));
        p
    }

    fn finish(self) -> Out {
        self.finish_within(RUN_ENDS)
    }

    /// Waits for the exit (the child stays in this guard until it is known to have exited),
    /// then for the end of stderr; past either bound it panics and the drop guard cleans up.
    fn finish_within(mut self, limit: Duration) -> Out {
        let child = self.child.as_mut().unwrap();
        let mut status = None;
        wait_for("the process exits", limit, || {
            status = child.try_wait().unwrap();
            status.is_some()
        });
        let Ok(stderr) = self.err.recv_timeout(STDERR_JOIN) else {
            panic!("the stderr of the process did not end within {STDERR_JOIN:?}");
        };
        Out {
            code: status.unwrap().code().unwrap_or(-1),
            stderr,
        }
    }

    /// Ends the process (the one this test started) and reaps it, bounded; its children are
    /// not touched. False if it was not reaped within `REAP` (it is left behind).
    fn kill(&mut self) -> bool {
        self.child.take().is_none_or(|mut c| reap(&mut c, REAP))
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = std::fs::write(&self.stop, "");
        let reaped = self.kill();
        // Bounded; past it the thread is left.
        let _ = self.err.recv_timeout(STDERR_JOIN);
        if !reaped {
            cleanup_failed(format!(
                "pg_e2e: a process was not reaped within {REAP:?}; leaving it"
            ));
        }
    }
}

/// Stops a server a test may have started, through `testkit::ServerGuard` (`pg_ctl stop -m
/// immediate` on its own data folder, only when the pid file proves it is that server); then
/// a `postmaster.pid` still there means a server was left running.
struct Stopper {
    guard: Option<ServerGuard>,
    pidfile: PathBuf,
    what: &'static str,
}

impl Stopper {
    fn new(guard: ServerGuard, data: &Path, what: &'static str) -> Stopper {
        Stopper {
            guard: Some(guard),
            pidfile: data.join("postmaster.pid"),
            what,
        }
    }
}

impl Drop for Stopper {
    fn drop(&mut self) {
        drop(self.guard.take());
        if self.pidfile.exists() {
            cleanup_failed(format!(
                "pg_e2e: {} may still run: {} exists",
                self.what,
                self.pidfile.display()
            ));
        }
    }
}

/// Removes a forged `postmaster.pid` on every path, so neither the guard nor the scratch folder
/// mistakes it for a live server of the test.
struct Forged(PathBuf);

impl Drop for Forged {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Bounded shutdown of an in-process daemon on a thread of its own (its shutdown prints with
/// `eprintln!`, and a panic there must not become a second panic of a maybe unwinding thread).
fn shutdown(d: DaemonHandle<OsControl>) -> Result<(), String> {
    let (tx, rx) = mpsc::channel();
    let spawned = std::thread::Builder::new().spawn(move || {
        d.shutdown();
        let _ = tx.send(());
    });
    match spawned.map(|_| rx.recv_timeout(DAEMON_SHUTDOWN)) {
        Ok(Ok(())) => Ok(()),
        Err(_) => Err("the thread for the daemon's shutdown could not be created".into()),
        Ok(Err(mpsc::RecvTimeoutError::Disconnected)) => {
            Err("the daemon's shutdown panicked".into())
        }
        Ok(Err(mpsc::RecvTimeoutError::Timeout)) => Err(format!(
            "the daemon did not shut down within {DAEMON_SHUTDOWN:?}"
        )),
    }
}

/// Per-test sandbox. Fields drop in order after `Drop::drop` stopped the daemon: the servers'
/// guards, then the scratch folder, then the lock that keeps real tests one at a time.
struct Fx {
    daemon: Option<DaemonHandle<OsControl>>,
    bin: PathBuf,
    port: u16,
    socket: String,
    /// `<data_dir>/pg/<major>`.
    root: PathBuf,
    /// The `migrate_entry` mode of the project's `migrate` (watching `schema.sql`); `None` = no
    /// `migrate`. The other project never has one.
    migrate: Option<String>,
    user: Option<Stopper>,
    _cluster: Option<Stopper>,
    dir: Scratch,
    _lock: MutexGuard<'static, ()>,
}

impl Fx {
    /// A sandbox with the real PostgreSQL of `SYNC_GATE_TEST_PG_BIN`; `None` = skipped.
    fn real(tag: &str) -> Option<Fx> {
        Some(Fx::new(tag, Some(pg_bin()?)))
    }

    /// `bin` = a real PostgreSQL `bin` folder (the cluster's guard is installed now, before any
    /// daemon can start a server); `None` = a `bin_dir` that does not exist.
    fn new(tag: &str, bin: Option<PathBuf>) -> Fx {
        let lock = serial();
        let dir = Scratch::new(tag);
        let major = match &bin {
            Some(b) => OsPgTools.major_version(b).unwrap().to_string(),
            None => "none".into(),
        };
        let root = dir.join("data").join("pg").join(major);
        let data = root.join("data");
        let cluster = bin
            .as_ref()
            .map(|b| Stopper::new(ServerGuard::new(b, &data), &data, "the sync_gate cluster"));
        let bin = bin.unwrap_or_else(|| dir.join("no-such-bin"));
        std::fs::create_dir_all(dir.join("proj")).unwrap();
        std::fs::create_dir_all(dir.join("other")).unwrap();
        let socket = if cfg!(windows) {
            format!(
                "sync_gate-pge2e-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::SeqCst)
            )
        } else {
            dir.join("d.sock").to_string_lossy().into_owned()
        };
        let fx = Fx {
            daemon: None,
            bin,
            port: free_port(),
            socket,
            root,
            migrate: None,
            user: None,
            _cluster: cluster,
            dir,
            _lock: lock,
        };
        fx.write_config("config.toml", 30);
        fx
    }

    fn file(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn data_dir(&self) -> PathBuf {
        self.dir.join("data")
    }

    fn proj(&self) -> PathBuf {
        self.dir.join("proj")
    }

    /// The folder of a second project, never with `migrate`.
    fn other(&self) -> PathBuf {
        self.dir.join("other")
    }

    fn psql_exe(&self) -> PathBuf {
        self.bin
            .join(format!("psql{}", std::env::consts::EXE_SUFFIX))
    }

    /// The configuration in the file `name` with this sandbox's port, the given patience, the
    /// project (with its `migrate`, if any) and the other project.
    fn write_config(&self, name: &str, wait_secs: u64) -> PathBuf {
        let mut text = format!(
            "tick_ms = 50\nreserve_fraction = 0.0\noptimism = 1.0\n\n[postgres]\nbin_dir = '{}'\n\
             port = {}\nlease_wait_secs = {wait_secs}\n\n[[postgres.project]]\ndir = '{}'\n",
            self.bin.display(),
            self.port,
            self.proj().display(),
        );
        if let Some(mode) = &self.migrate {
            // A JSON array of strings is a TOML array too.
            let argv = serde_json::to_string(&migrate_argv(mode)).unwrap();
            text.push_str(&format!("migrate = {argv}\nwatch = [\"{SCHEMA}\"]\n"));
        }
        text.push_str(&format!(
            "\n[[postgres.project]]\ndir = '{}'\n",
            self.other().display()
        ));
        let path = self.file(name);
        std::fs::write(&path, text).unwrap();
        path
    }

    fn start_daemon(&mut self) {
        self.start_daemon_with(Deps::os());
    }

    fn start_daemon_with(&mut self, deps: Deps) {
        assert!(self.daemon.is_none());
        let text = std::fs::read_to_string(self.file("config.toml")).unwrap();
        let cfg = Config::from_toml(&text).unwrap();
        self.daemon = Some(
            sync_gated::run_with_pg(
                cfg,
                &self.socket,
                fixed(),
                OsControl,
                Some(self.data_dir()),
                Arc::new(OsLauncher::default()),
                deps,
            )
            .unwrap(),
        );
    }

    fn stop_daemon(&mut self) {
        if let Some(d) = self.daemon.take()
            && let Err(e) = shutdown(d)
        {
            panic!("pg_e2e: {e}");
        }
    }

    /// The daemon as a child process (`daemon` mode) on this sandbox's socket and data folder;
    /// returns once it serves.
    fn spawn_daemon(&self, name: &str) -> Proc {
        let out = self.file(name);
        let stop = self.file(&format!("{name}.stop"));
        let mut c = Command::new(std::env::current_exe().unwrap());
        c.args(["child_entry", "--exact", "--nocapture", "--test-threads=1"])
            .env("SYNC_GATE_TEST_CHILD", "daemon")
            .env("FG_TEST_CONFIG", self.file("config.toml"))
            .env("FG_TEST_SOCKET", &self.socket)
            .env("FG_TEST_DATA", self.data_dir())
            .env("FG_TEST_OUT", &out)
            .env("FG_TEST_STOP", &stop)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let p = Proc::spawn(c, &stop);
        wait_file(&out, EVENT);
        p
    }

    /// `sync_gate` with this sandbox and the configuration file `cfg`, in the project folder;
    /// no `PG*` variable and no URL variable of this process reaches it, and `psql` prints
    /// untranslated messages.
    fn cli(&self, cfg: &Path) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_sync_gate"));
        for (k, _) in std::env::vars_os() {
            let k_up = k.to_string_lossy().to_ascii_uppercase();
            if k_up.starts_with("PG") || k_up.ends_with("_URL") {
                c.env_remove(k);
            }
        }
        c.env("SYNC_GATE_SOCKET", &self.socket)
            .env("SYNC_GATE_DATA_DIR", self.data_dir())
            .env("SYNC_GATE_CONFIG", cfg)
            .env("SYNC_GATE_FORCE_HEAVY", "1")
            .env_remove("SYNC_GATE_JOB")
            .env("PGCONNECT_TIMEOUT", "10")
            .env("LC_ALL", "C")
            .env_remove("LANGUAGE")
            .current_dir(self.proj())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        c
    }

    /// `sync_gate run -- <this test binary> child_entry` in `mode`; its files are named after
    /// `name` in the scratch folder.
    fn fixture(&self, mode: &str, name: &str, cfg: &Path) -> Command {
        let exe = std::env::current_exe().unwrap();
        let mut c = self.cli(cfg);
        c.env("SYNC_GATE_TEST_CHILD", mode)
            .env("FG_TEST_OUT", self.file(name))
            .env("FG_TEST_STOP", self.stop_file(name))
            .env("FG_TEST_TRIGGER", self.file(&format!("{name}.trigger")))
            .env("FG_TEST_RESULT", self.file(&format!("{name}.result")))
            .env("FG_TEST_PSQL", self.psql_exe());
        c.args(["run", "--", exe.to_str().unwrap()]);
        c.args(["child_entry", "--exact", "--nocapture", "--test-threads=1"]);
        c
    }

    fn stop_file(&self, name: &str) -> PathBuf {
        self.file(&format!("{name}.stop"))
    }

    fn spawn(&self, c: Command, name: &str) -> Proc {
        Proc::spawn(c, &self.stop_file(name))
    }

    /// Runs a fixture with the main configuration and returns its guard and output file.
    fn run(&self, mode: &str, name: &str) -> (Proc, PathBuf) {
        let c = self.fixture(mode, name, &self.file("config.toml"));
        (self.spawn(c, name), self.file(name))
    }

    /// A held command, once it runs, with the variables it got.
    fn hold(&self, name: &str) -> (Proc, BTreeMap<String, String>) {
        self.hold_in(name, &self.proj())
    }

    /// [`Fx::hold`] run in the folder `dir`.
    fn hold_in(&self, name: &str, dir: &Path) -> (Proc, BTreeMap<String, String>) {
        let mut c = self.fixture("hold", name, &self.file("config.toml"));
        c.current_dir(dir);
        let (p, out) = (self.spawn(c, name), self.file(name));
        wait_file(
            &out,
            if self.migrate.is_some() {
                MIGRATES
            } else {
                STARTS
            },
        );
        let e = read_env(&out);
        assert!(
            e.get("PGUSER").is_some_and(|u| u.starts_with("fg_l_")),
            "{name} got no lease: {:?}",
            redacted(&e)
        );
        (p, e)
    }

    /// `sync_gate run -- psql -X -w -v ON_ERROR_STOP=1 <args>` to its end.
    fn run_psql(&self, name: &str, args: &[&str]) -> Out {
        let mut c = self.cli(&self.file("config.toml"));
        c.arg("run").arg("--").arg(self.psql_exe());
        c.args(["-X", "-w", "-v", "ON_ERROR_STOP=1"]).args(args);
        self.spawn(c, name).finish()
    }

    fn stop(&self, name: &str) {
        std::fs::write(self.stop_file(name), "").unwrap();
    }

    /// The lease issued first (PF18), in the other project (no `migrate`): the server starts,
    /// then the test waits for `running`.
    fn warm(&self) {
        let mut c = self.fixture("env", "warm", &self.file("config.toml"));
        c.current_dir(self.other());
        let r = self.spawn(c, "warm").finish();
        assert_eq!(r.code, 0, "the warm-up lease failed: {}", r.shape());
        self.wait_running(RUNNING);
    }

    fn wait_running(&self, limit: Duration) {
        wait_for("postgres is running", limit, || {
            let s = self.service();
            assert!(!s.state.starts_with("failed"), "{}", s.state);
            s.state == "running"
        });
    }

    fn report(&self) -> StatusReport {
        match sync_gate::client::call_at(&self.socket, &Request::Status).unwrap() {
            Response::Status(s) => s,
            other => panic!("{other:?}"),
        }
    }

    fn service(&self) -> ServiceStatus {
        self.report().services.remove(0)
    }

    /// Waits until the registry says a lease belongs to a command with this pid.
    fn registered(&self, pid: &str) {
        let pid: u64 = pid.parse().unwrap();
        wait_for("the command is registered", EVENT, || {
            std::fs::read_to_string(self.root.join("leases.json"))
                .ok()
                .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                .is_some_and(|v| {
                    v["leases"]
                        .as_array()
                        .is_some_and(|l| l.iter().any(|r| r["command"]["pid"] == pid))
                })
        });
    }

    /// One query as the administrator over the cluster's private socket, after the preamble
    /// that keeps it out of the server log; bounded by `run_tool`.
    fn admin(&self, sql: &str) -> String {
        self.admin_in("postgres", sql)
    }

    /// [`Fx::admin`] in the database `db`.
    fn admin_in(&self, db: &str, sql: &str) -> String {
        let mut q = psql_command(&self.psql_exe());
        q.args(["-X", "-q", "-A", "-t", "-w", "-v", "ON_ERROR_STOP=1", "-h"])
            .arg(self.root.join("s"));
        q.args([
            "-p",
            &self.port.to_string(),
            "-U",
            "sync_gate",
            "-d",
            db,
            "-f",
            "-",
        ]);
        let input = format!("{ADMIN_PREAMBLE}{sql}\n");
        let out = run_tool(q, Some(input.as_bytes()), PSQL).unwrap();
        assert_eq!(out.code, Some(0), "admin query failed: {}", out.stderr);
        out.stdout.replace("\r\n", "\n")
    }

    fn count(&self, sql: &str) -> u32 {
        self.admin(sql).trim().parse().unwrap()
    }

    fn db_exists(&self, name: &str) -> bool {
        self.count(&format!(
            "SELECT count(*) FROM pg_database WHERE datname = '{name}'"
        )) == 1
    }

    fn role_exists(&self, name: &str) -> bool {
        self.count(&format!(
            "SELECT count(*) FROM pg_roles WHERE rolname = '{name}'"
        )) == 1
    }

    /// Database and role of the lease are gone (slow poll: each check is a `psql`).
    fn wait_lease_gone(&self, lease: &str) {
        wait_every(
            &format!("the database and role of {lease} are gone"),
            DB_GONE,
            Duration::from_millis(250),
            || !self.db_exists(lease) && !self.role_exists(lease),
        );
    }

    /// `psql -X -A -t -w -c <sql>` with a lease's variables (the test acting as that program).
    fn as_lease(&self, e: &BTreeMap<String, String>, sql: &str) -> ToolOutput {
        let mut q = psql_command(&self.psql_exe());
        for k in [
            "PGHOST",
            "PGPORT",
            "PGUSER",
            "PGDATABASE",
            "PGPASSWORD",
            "PGSSLMODE",
        ] {
            q.env(k, &e[k]);
        }
        q.args(["-X", "-A", "-t", "-w", "-v", "ON_ERROR_STOP=1", "-c", sql]);
        run_tool(q, None, PSQL).unwrap()
    }

    /// Runs `sync_gate status` and returns its exit code, stdout (written to a file of the scratch
    /// folder) and stderr. It asserts nothing and prints nothing: the caller scans first.
    fn status_text(&self) -> (i32, String, String) {
        let stdout = self.file("status.txt");
        let mut c = Command::new(env!("CARGO_BIN_EXE_sync_gate"));
        c.arg("status")
            .env("SYNC_GATE_SOCKET", &self.socket)
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(&stdout).unwrap())
            .stderr(Stdio::piped());
        let r = self.spawn(c, "status").finish();
        let text = std::fs::read(&stdout).unwrap_or_default();
        (
            r.code,
            String::from_utf8_lossy(&text).into_owned(),
            r.stderr,
        )
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        if let Some(d) = self.daemon.take()
            && let Err(e) = shutdown(d)
        {
            cleanup_failed(format!("pg_e2e: {e}"));
        }
    }
}

/// A `psql` with no inherited `PG*` variable and untranslated messages.
fn psql_command(exe: &Path) -> Command {
    let mut q = Command::new(exe);
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().to_ascii_uppercase().starts_with("PG") {
            q.env_remove(k);
        }
    }
    q.env("LC_ALL", "C").env("PGCONNECT_TIMEOUT", "10");
    q
}

/// Waits for a condition on state that emits no event (a file, the registry, the status, the
/// catalogue, a process exit through `try_wait`).
/// Ruling: where std offers no event, a bounded poll is allowed, only through this helper,
/// which panics with `what` past `limit`; a sleep then an assertion, or an unbounded poll, is not.
fn wait_for(what: &str, limit: Duration, ok: impl FnMut() -> bool) {
    wait_every(what, limit, Duration::from_millis(10), ok);
}

fn wait_every(what: &str, limit: Duration, every: Duration, mut ok: impl FnMut() -> bool) {
    let start = Instant::now();
    while !ok() {
        assert!(start.elapsed() < limit, "timed out after {limit:?}: {what}");
        std::thread::park_timeout(every);
    }
}

fn wait_file(path: &Path, limit: Duration) {
    wait_for(&format!("{} exists", path.display()), limit, || {
        path.exists()
    });
}

/// `NAME=value` lines of a fixture's output file, plus `pid`.
fn read_env(path: &Path) -> BTreeMap<String, String> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// The variables with every secret value replaced, safe to print.
fn redacted(e: &BTreeMap<String, String>) -> BTreeMap<&str, &str> {
    e.iter()
        .map(|(k, v)| {
            let secret = k == "PGPASSWORD" || k.ends_with("_URL");
            (k.as_str(), if secret { "<redacted>" } else { v.as_str() })
        })
        .collect()
}

/// The command ran with only the original `DATABASE_URL`: nothing injected, nothing removed.
fn assert_original(e: &BTreeMap<String, String>) {
    assert!(
        e.get("DATABASE_URL").map(String::as_str) == Some("postgres://mine"),
        "DATABASE_URL is not the original one"
    );
    let set: Vec<&String> = e.keys().filter(|k| *k != "pid").collect();
    assert!(set == ["DATABASE_URL"], "set variables: {:?}", redacted(e));
}

fn mine(c: &mut Command) {
    c.env("DATABASE_URL", "postgres://mine");
}

/// Writes trigger `n` of a `psql-loop` fixture and returns what its `psql` printed.
fn trigger(fx: &Fx, name: &str, n: u32) -> String {
    std::fs::write(nth(&fx.file(&format!("{name}.trigger")), n), "").unwrap();
    let result = nth(&fx.file(&format!("{name}.result")), n);
    wait_file(&result, EVENT);
    std::fs::read_to_string(result).unwrap()
}

#[test]
fn concurrent_runs_cannot_reach_each_others_databases() {
    let Some(mut fx) = Fx::real("iso") else {
        return;
    };
    fx.start_daemon();
    fx.warm();
    let (a, ea) = fx.hold("a");
    let theirs = ea["PGDATABASE"].clone();
    // Positive control: B reaches its own database.
    let own = fx.run_psql("own", &["-c", "select 1"]);
    assert_eq!(own.code, 0, "B's own database failed: {}", own.shape());
    for db in [theirs.as_str(), "postgres", "template0", "template1"] {
        let r = fx.run_psql("b", &["-d", db, "-c", "select 1"]);
        assert_ne!(r.code, 0, "B reached {db}");
        assert!(
            r.stderr.contains("rejects connection"),
            "{db}: no `rejects connection` line: {}",
            r.shape()
        );
    }
    fx.stop("a");
    assert_eq!(a.finish().code, 0);
}

#[test]
fn a_lease_cannot_create_databases_roles_or_switch_role() {
    let Some(mut fx) = Fx::real("perm") else {
        return;
    };
    fx.start_daemon();
    fx.warm();
    let (a, ea) = fx.hold("a");
    let set_role = format!("SET ROLE \"{}\"", ea["PGUSER"]);
    // R15: a framework that creates its own database fails here and stays out of `commands`.
    let rename = "DO $$ BEGIN EXECUTE format('ALTER DATABASE %I RENAME TO y', \
                  current_database()); END $$";
    for sql in [
        "CREATE DATABASE x",
        "CREATE ROLE x",
        set_role.as_str(),
        rename,
    ] {
        let r = fx.run_psql("b", &["-c", sql]);
        assert_ne!(r.code, 0, "{sql} succeeded");
        assert!(
            r.stderr.contains("permission denied"),
            "{sql}: no `permission denied` line: {}",
            r.shape()
        );
    }
    fx.stop("a");
    assert_eq!(a.finish().code, 0);
}

#[test]
fn release_drops_the_database_even_with_an_open_connection() {
    let Some(mut fx) = Fx::real("open") else {
        return;
    };
    fx.start_daemon();
    fx.warm();
    let (a, ea) = fx.hold("a");
    let lease = ea["PGUSER"].clone();
    // A session of A's program that stays in a query: longer than any wait of this test, so
    // only the drop can end it.
    let mut q = psql_command(&fx.psql_exe());
    for k in [
        "PGHOST",
        "PGPORT",
        "PGUSER",
        "PGDATABASE",
        "PGPASSWORD",
        "PGSSLMODE",
    ] {
        q.env(k, &ea[k]);
    }
    q.args(["-X", "-w", "-c", "SELECT pg_sleep(900)"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let session = fx.spawn(q, "session");
    wait_every(
        "A's session is open",
        EVENT,
        Duration::from_millis(250),
        || {
            fx.count(&format!(
                "SELECT count(*) FROM pg_stat_activity WHERE usename = '{lease}' \
                 AND backend_type = 'client backend'"
            )) == 1
        },
    );
    fx.stop("a");
    assert_eq!(a.finish().code, 0);
    let s = session.finish_within(DB_GONE);
    assert_ne!(s.code, 0, "the session ended on its own: {}", s.shape());
    fx.wait_lease_gone(&lease);
}

#[test]
fn the_cli_dies_and_the_command_keeps_its_database() {
    let Some(mut fx) = Fx::real("cli") else {
        return;
    };
    fx.start_daemon();
    fx.warm();
    let (mut a, out) = fx.run("psql-loop", "a");
    wait_file(&out, STARTS);
    let ea = read_env(&out);
    let lease = ea["PGUSER"].clone();
    fx.registered(&ea["pid"]);
    assert!(
        trigger(&fx, "a", 1) == "1",
        "psql-loop: the answer to trigger 1 is not \"1\""
    );
    assert!(a.kill(), "the CLI was not reaped within {REAP:?}");
    // A tick that began after the CLI died has judged the holders.
    let seen = fx.service().checks;
    wait_for("a tick after the CLI died", EVENT, || {
        fx.service().checks > seen + 1
    });
    assert!(fx.db_exists(&lease), "the database went with the CLI");
    assert!(
        trigger(&fx, "a", 2) == "2",
        "psql-loop: the answer to trigger 2 is not \"2\""
    );
    fx.stop("a");
    fx.wait_lease_gone(&lease);
}

#[test]
fn a_grant_from_another_lease_only_delays_the_role_drop() {
    let Some(mut fx) = Fx::real("grant") else {
        return;
    };
    fx.start_daemon();
    fx.warm();
    let (a, ea) = fx.hold("a");
    let (b, eb) = fx.hold("b");
    let (la, lb) = (ea["PGUSER"].clone(), eb["PGUSER"].clone());
    let g = fx.as_lease(
        &ea,
        &format!("CREATE TABLE t (x int); GRANT SELECT ON t TO \"{lb}\""),
    );
    assert_eq!(
        g.code,
        Some(0),
        "the grant failed (code {:?}, {} stderr bytes)",
        g.code,
        g.stderr.len()
    );
    fx.stop("b");
    assert_eq!(b.finish().code, 0);
    // Barrier: the daemon has tried to drop B's role and failed.
    let failed = format!("postgres cleanup of {lb} failed");
    wait_for("the drop of B's role failed", DB_GONE, || {
        fx.report().decisions.iter().any(|d| d.contains(&failed))
    });
    assert!(!fx.db_exists(&lb), "B's database is still there");
    assert!(fx.role_exists(&lb), "B's role is gone");
    assert_eq!(fx.service().cleanup_pending, 1);
    fx.stop("a");
    assert_eq!(a.finish().code, 0);
    fx.wait_lease_gone(&la);
    fx.wait_lease_gone(&lb);
    wait_for("no cleanup pending", EVENT, || {
        fx.service().cleanup_pending == 0
    });
}

#[test]
fn a_real_daemon_crash_is_adopted_and_queries_continue() {
    let Some(fx) = Fx::real("crash") else {
        return;
    };
    let mut d1 = fx.spawn_daemon("d1");
    fx.warm();
    let (a, out) = fx.run("psql-loop", "a");
    wait_file(&out, STARTS);
    let ea = read_env(&out);
    let lease = ea["PGUSER"].clone();
    fx.registered(&ea["pid"]);
    assert!(
        trigger(&fx, "a", 1) == "1",
        "psql-loop: the answer to trigger 1 is not \"1\""
    );
    assert!(d1.kill(), "the daemon was not reaped within {REAP:?}");
    // The server lives on without a daemon.
    assert!(
        trigger(&fx, "a", 2) == "2",
        "psql-loop: the answer to trigger 2 is not \"2\""
    );
    let d2 = fx.spawn_daemon("d2");
    wait_for("the new daemon adopted the server", ADOPTED, || {
        let s = fx.service();
        assert!(!s.state.starts_with("failed"), "{}", s.state);
        s.state == "running" && s.leases == 1
    });
    assert!(
        trigger(&fx, "a", 3) == "3",
        "psql-loop: the answer to trigger 3 is not \"3\""
    );
    fx.stop("a");
    assert_eq!(a.finish().code, 0);
    fx.wait_lease_gone(&lease);
    fx.stop("d2");
    let r = d2.finish_within(DAEMON_SHUTDOWN);
    assert_eq!(r.code, 0, "the second daemon failed: {}", r.shape());
}

/// The command ran without a shared database and with its own `DATABASE_URL`; then the daemon
/// has judged the server and refused it (the barrier of the later negative assertions).
fn fails_open(fx: &Fx, name: &str) {
    let mut c = fx.fixture("env", name, &fx.file("config.toml"));
    mine(&mut c);
    let r = fx.spawn(c, name).finish();
    assert_eq!(r.code, 0, "{name} failed: {}", r.shape());
    assert!(
        r.stderr.contains("no shared database"),
        "{name}: {}",
        r.shape()
    );
    assert_original(&read_env(&fx.file(name)));
    wait_for("the service failed", RUNNING, || {
        fx.service().state.starts_with("failed")
    });
}

#[test]
fn the_users_server_and_a_forged_identity_are_left_alone() {
    let Some(mut fx) = Fx::real("user") else {
        return;
    };
    let user_data = fx.file("user").join("data");
    let user_port = fx.port;
    let guard = user_server(&fx.bin, &fx.file("user"), user_port);
    fx.user = Some(Stopper::new(guard, &user_data, "the user's server"));
    let made = psql_tcp(
        &fx.bin,
        user_port,
        "postgres",
        "postgres",
        "CREATE DATABASE userdb",
    );
    assert_eq!(made.code, Some(0), "{}", made.stderr);
    let pidfile = std::fs::read_to_string(user_data.join("postmaster.pid")).unwrap();
    let mut lines = pidfile.lines();
    let user_pid: u32 = lines.next().unwrap().trim().parse().unwrap();
    let user_started: u64 = lines.nth(1).unwrap().trim().parse().unwrap();

    // The user's server sits on the configured port.
    fx.start_daemon();
    fails_open(&fx, "a");
    fx.stop_daemon();

    // Another port, and sync_gate's own pid file forged with the pid and start of the user's server.
    fx.port = free_port();
    fx.write_config("config.toml", 30);
    let data = fx.root.join("data");
    assert!(
        data.join("PG_VERSION").is_file(),
        "the cluster was not created"
    );
    let forged = Forged(data.join("postmaster.pid"));
    std::fs::write(
        &forged.0,
        format!(
            "{user_pid}\n{}\n{user_started}\n{}\n{}\n127.0.0.1\n  0         0\nready   \n",
            data.display(),
            fx.port,
            fx.root.join("s").display()
        ),
    )
    .unwrap();
    fx.start_daemon();
    fails_open(&fx, "b");
    fx.stop_daemon();
    drop(forged);

    let now = std::fs::read_to_string(user_data.join("postmaster.pid")).unwrap();
    assert_eq!(now, pidfile, "the user's server was restarted");
    assert_eq!(sync_gate_probe::process_alive(user_pid), Some(true));
    let out = psql_tcp(
        &fx.bin,
        user_port,
        "postgres",
        "userdb",
        "SELECT current_database()",
    );
    assert_eq!(out.code, Some(0), "{}", out.stderr);
    assert_eq!(out.stdout, "userdb\n");
}

fn all_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()));
    for e in entries {
        let e = e.unwrap_or_else(|e| panic!("cannot list {}: {e}", dir.display()));
        let p = e.path();
        if e.file_type().unwrap().is_dir() {
            all_files(&p, out);
        } else {
            out.push(p);
        }
    }
}

fn contains(hay: &[u8], needle: &str) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

#[test]
fn secrets_never_reach_disk_status_stderr_or_the_server_log() {
    let Some(mut fx) = Fx::real("secret") else {
        return;
    };
    fx.start_daemon();
    fx.warm();
    // The hold writes its variables to a file of the scratch folder, outside the data folder.
    let (a, ea) = fx.hold("a");
    let (secret, url) = (ea["PGPASSWORD"].clone(), ea["DATABASE_URL"].clone());
    let lease = ea["PGUSER"].clone();
    // Something for the server log while the lease is live: a failing statement of the lease.
    let bad = fx.as_lease(&ea, "SELECT 'not a number'::int");
    assert_ne!(bad.code, Some(0));
    // Every scan comes before any other assertion, and no message shows scanned text.
    let leaked = |text: &str| contains(text.as_bytes(), &secret) || contains(text.as_bytes(), &url);
    let (code, status, status_err) = fx.status_text();
    assert!(
        !leaked(&status),
        "the status output shows the password or the URL"
    );
    assert!(
        !leaked(&status_err),
        "the status stderr shows the password or the URL"
    );
    assert_eq!(code, 0, "sync_gate status failed");
    assert!(
        status.contains("postgres: running, 1 lease(s)"),
        "unexpected status output"
    );
    fx.stop("a");
    let r = a.finish();
    assert!(
        !leaked(&r.stderr),
        "the CLI's stderr shows the password or the URL"
    );
    assert_eq!(r.code, 0, "the command's CLI failed");
    fx.wait_lease_gone(&lease);
    // No lease is live: the daemon stops the server and lets go of every file.
    fx.stop_daemon();
    let mut files = Vec::new();
    all_files(&fx.data_dir(), &mut files);
    assert!(
        files.iter().any(|f| f.ends_with("server.log")),
        "no server log under the data folder"
    );
    for f in files {
        let bytes =
            std::fs::read(&f).unwrap_or_else(|e| panic!("cannot read {}: {e}", f.display()));
        assert!(
            !contains(&bytes, &secret),
            "{} has the password",
            f.display()
        );
        assert!(!contains(&bytes, &url), "{} has the URL", f.display());
    }
}

#[test]
fn bin_dir_missing_fails_open_with_the_original_env() {
    let mut fx = Fx::new("nobin", None);
    fx.start_daemon();
    let mut c = fx.fixture("env", "a", &fx.file("config.toml"));
    mine(&mut c);
    let r = fx.spawn(c, "a").finish();
    assert_eq!(r.code, 0, "the command failed: {}", r.shape());
    assert_eq!(
        r.stderr.matches("no shared database").count(),
        1,
        "not exactly one `no shared database` line: {}",
        r.shape()
    );
    assert_original(&read_env(&fx.file("a")));
}

/// The longest the gate holds `start` back; past it the gate is aborted, so a failing test
/// cannot leave the daemon's worker blocked. More than the cold-start wait of the test plus slack.
const GATE_LIMIT: Duration = Duration::from_secs(420);
/// "pg_ctl start -w -t 60": 75 s, plus 5 s of margin: how long the teardown waits for a `start`
/// it let through.
const START_BOUND: Duration = Duration::from_secs(80);
/// "partida a frio ate running": the daemon's patience in the cold-start test.
const COLD_START: Duration = Duration::from_secs(335);

#[derive(Clone, Copy, PartialEq)]
enum Phase {
    /// `start` waits.
    Closed,
    /// `start` goes on to launch the real server.
    Open,
    /// `start` fails at once and never launches PostgreSQL.
    Aborted,
}

struct GateState {
    phase: Phase,
    /// `start` was reached.
    entered: bool,
    /// A `start` that was let through has returned (with any result).
    returned: bool,
}

/// What the test controls: whether `start` was reached, whether it may go on, and (for the
/// teardown) whether a `start` that went on has returned.
struct Gate {
    st: Mutex<GateState>,
    cv: Condvar,
}

impl Gate {
    fn new() -> Arc<Gate> {
        Arc::new(Gate {
            st: Mutex::new(GateState {
                phase: Phase::Closed,
                entered: false,
                returned: false,
            }),
            cv: Condvar::new(),
        })
    }

    fn lock(&self) -> MutexGuard<'_, GateState> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Lets a waiting `start` go on (an aborted gate stays aborted).
    fn open(&self) {
        let mut st = self.lock();
        if st.phase == Phase::Closed {
            st.phase = Phase::Open;
        }
        self.cv.notify_all();
    }

    fn entered(&self) -> bool {
        self.lock().entered
    }

    /// Marks the gate reached and waits for it to leave `Closed`; true only when it was opened.
    /// `GATE_LIMIT` counts as `Aborted`.
    fn pass(&self) -> bool {
        let deadline = Instant::now() + GATE_LIMIT;
        let mut st = self.lock();
        st.entered = true;
        while st.phase == Phase::Closed {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                st.phase = Phase::Aborted;
                break;
            }
            st = self
                .cv
                .wait_timeout(st, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        st.phase == Phase::Open
    }

    fn start_returned(&self) {
        self.lock().returned = true;
        self.cv.notify_all();
    }

    /// Teardown step 1. A gate that never let a `start` through is aborted (a blocked or later
    /// `start` fails without launching anything); one that did is waited for until that `start`
    /// returned, at most `limit`. False if the wait timed out.
    fn settle(&self, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        let mut st = self.lock();
        if !st.entered || st.phase == Phase::Closed {
            st.phase = Phase::Aborted;
            self.cv.notify_all();
            return true;
        }
        while st.phase == Phase::Open && !st.returned {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            st = self
                .cv
                .wait_timeout(st, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        true
    }
}

/// Step 1 of the cold-start test's teardown, on every path (a panic included). The order is:
/// this guard (gate aborted, or the real `start` has returned), then `Fx::drop` (daemon shut
/// down), then `Fx`'s fields (`ServerGuard` stops the server, `Scratch` removes the folder).
/// It matters because `ServerGuard` looks for a pid file once: while a `start` is still
/// launching the server no pid file exists yet, nothing would be stopped, and the server would
/// come up afterwards and stay. Declared after `fx`, so it drops before it.
struct GateTeardown(Arc<Gate>);

impl Drop for GateTeardown {
    fn drop(&mut self) {
        if !self.0.settle(START_BOUND) {
            cleanup_failed(format!(
                "pg_e2e: the real `start` had not returned within {START_BOUND:?}"
            ));
        }
    }
}

/// Marks that the real `start` returned, also when it unwinds.
struct StartReturned<'a>(&'a Gate);

impl Drop for StartReturned<'_> {
    fn drop(&mut self) {
        self.0.start_returned();
    }
}

/// The real tools, but `start` first waits for the test's gate.
struct Gated {
    gate: Arc<Gate>,
}

impl PgTools for Gated {
    fn major_version(&self, bin: &Path) -> io::Result<u32> {
        OsPgTools.major_version(bin)
    }
    fn init(&self, c: &ClusterPaths, max_connections: u32) -> io::Result<()> {
        OsPgTools.init(c, max_connections)
    }
    fn start(&self, c: &ClusterPaths) -> io::Result<ServerId> {
        if !self.gate.pass() {
            return Err(io::Error::other("the test's gate was aborted"));
        }
        let _returned = StartReturned(&self.gate);
        OsPgTools.start(c)
    }
    fn server(&self, c: &ClusterPaths) -> Result<Option<ServerId>, String> {
        OsPgTools.server(c)
    }
    fn stop(&self, c: &ClusterPaths, id: ServerId) -> io::Result<()> {
        OsPgTools.stop(c, id)
    }
    fn sql(&self, c: &ClusterPaths, script: &str, secrets: &[&str]) -> io::Result<String> {
        OsPgTools.sql(c, script, secrets)
    }
    fn config_current(&self, c: &ClusterPaths, max_connections: u32) -> bool {
        OsPgTools.config_current(c, max_connections)
    }
}

/// PF18: a cold start that outlasts the command's patience, made certain by a gate in front of
/// the real `start`: the first command (patience 1 s) must time out while the gate is closed.
/// The daemon (in this process) waits `COLD_START` for `running`, so its answer cannot race the
/// CLI's 1 s.
#[test]
fn a_cold_start_longer_than_the_patience_runs_at_once_and_the_next_command_gets_a_database() {
    let Some(mut fx) = Fx::real("cold") else {
        return;
    };
    // Declared after `fx`, so it drops first (see `GateTeardown` for why the order matters).
    let gate = Gate::new();
    let _teardown = GateTeardown(gate.clone());
    fx.write_config("config.toml", 1);
    let mut deps = Deps::os();
    deps.tools = Arc::new(Gated { gate: gate.clone() });
    deps.lease_wait = Some(COLD_START);
    fx.start_daemon_with(deps);
    let mut c = fx.fixture("env", "a", &fx.file("config.toml"));
    mine(&mut c);
    let p = fx.spawn(c, "a");
    wait_file(&fx.file("a"), START_AFTER_GIVE_UP);
    let r = p.finish();
    assert_eq!(r.code, 0, "the first command failed: {}", r.shape());
    assert_eq!(
        r.stderr
            .matches("no shared database (timed out after 1 s)")
            .count(),
        1,
        "not exactly one timed-out line: {}",
        r.shape()
    );
    assert_original(&read_env(&fx.file("a")));
    // The server is wanted and held back: only now does the test let it start.
    wait_for("the daemon asked to start the server", RUNNING, || {
        gate.entered()
    });
    assert_ne!(fx.service().state, "running");
    gate.open();
    fx.wait_running(RUNNING);
    // The patience of the second command is the usual one: creating its role and database takes
    // longer than 1 s on a slow machine.
    fx.write_config("config.toml", 30);
    let (b, e) = fx.hold("b");
    let lease = e["PGUSER"].clone();
    assert!(fx.role_exists(&lease), "the role of the lease is missing");
    assert!(fx.db_exists(&lease), "the database of the lease is missing");
    fx.stop("b");
    assert_eq!(b.finish().code, 0);
    fx.wait_lease_gone(&lease);
}

// Template databases (slice 1b): the project's `migrate` is `migrate_entry`.

/// A watched file with one table and one row.
const PLAIN: &str = "CREATE TABLE t (x int);\nINSERT INTO t VALUES (1);\n";

impl Fx {
    /// A sandbox whose project runs `migrate` in `mode` on `schema.sql` (`sql`), with the daemon
    /// started and the server warmed through the other project; `None` = skipped.
    fn migrating(tag: &str, mode: &str, sql: &str) -> Option<Fx> {
        let mut fx = Fx::real(tag)?;
        fx.migrate = Some(mode.into());
        fx.write_config("config.toml", 30);
        fx.schema(sql);
        fx.start_daemon();
        fx.warm();
        Some(fx)
    }

    /// Replaces the watched file.
    fn schema(&self, sql: &str) {
        std::fs::write(self.proj().join(SCHEMA), sql).unwrap();
    }

    /// The template key of the project's files now, computed as the CLI does.
    fn key(&self) -> String {
        let argv = migrate_argv(self.migrate.as_deref().unwrap());
        sync_gate_core::template_key(&self.proj(), &argv, &[SCHEMA.into()], &[]).unwrap()
    }

    /// How many times the `migrate` ran.
    fn migrations(&self) -> usize {
        std::fs::read_to_string(self.proj().join("migrate.log"))
            .unwrap_or_default()
            .lines()
            .count()
    }

    /// The candidate of the last `migrate`: the `PGUSER` it got.
    fn candidate(&self) -> String {
        read_env(&self.proj().join("migrate.env"))["PGUSER"].clone()
    }

    /// The state of `key` in `templates.json`; `None` without a row.
    fn tpl_state(&self, key: &str) -> Option<String> {
        let text = std::fs::read_to_string(self.root.join("templates.json")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        v["templates"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["key"] == key)
            .map(|t| t["state"].as_str().unwrap().to_string())
    }

    /// `env` in the project with the user's own `DATABASE_URL`, to its end, and the variables
    /// it got.
    fn run_env(&self, name: &str) -> (Out, BTreeMap<String, String>) {
        let mut c = self.fixture("env", name, &self.file("config.toml"));
        mine(&mut c);
        let r = self.spawn(c, name).finish_within(MIGRATES);
        (r, read_env(&self.file(name)))
    }

    /// One statement as the lease of `e`, which must succeed; its output, trimmed.
    fn q(&self, e: &BTreeMap<String, String>, sql: &str) -> String {
        let r = self.as_lease(e, sql);
        assert_eq!(r.code, Some(0), "{sql}: {}", r.stderr);
        r.stdout.trim().to_string()
    }

    /// The run got a database of its own (no fallback line), not the candidate's.
    fn got_clone(&self, r: &Out, e: &BTreeMap<String, String>) {
        assert_eq!(r.code, 0, "{}: {:?}", r.shape(), r.notes());
        assert!(!r.stderr.contains("no shared database"), "{:?}", r.notes());
        let user = e.get("PGUSER").map_or("", String::as_str);
        assert!(user.starts_with("fg_l_"), "{:?}", redacted(e));
        assert_ne!(user, self.candidate(), "the command ran on the candidate");
    }
}

/// Everything the first test's `migrate` makes, owned by the candidate.
const RICH: &str = "\
CREATE SCHEMA app;
CREATE TABLE app.t (x int);
INSERT INTO app.t VALUES (1);
CREATE SEQUENCE app.s;
CREATE FUNCTION app.f() RETURNS int LANGUAGE sql AS 'SELECT 42';
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO PUBLIC;
CREATE EXTENSION pgcrypto;
SELECT lo_from_bytea(424242, 'large');
";

#[test]
fn sequences_functions_default_privileges_pgcrypto_and_a_large_object_survive_cloning() {
    let Some(fx) = Fx::migrating("rich", "psql", RICH) else {
        return;
    };
    let key = fx.key();
    let owner = format!("fg_o_{key}");
    let (a, ea) = fx.hold("a");
    let (b, eb) = fx.hold("b");
    assert_eq!(fx.migrations(), 1);
    assert_eq!(fx.tpl_state(&key).as_deref(), Some("ready"));
    assert!(
        fx.role_exists(&owner),
        "the template's owner role is missing"
    );
    let cand = fx.candidate();
    for e in [&ea, &eb] {
        let me = e["PGUSER"].as_str();
        assert_ne!(me, cand, "a command ran on the candidate");
        assert_eq!(
            fx.q(
                e,
                "SELECT (SELECT x FROM app.t), nextval('app.s'), app.f(), \
                 encode(digest('a', 'sha256'), 'hex')"
            ),
            "1|1|42|ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
        );
        // M4: the owner of each object the migrate made, from the catalogue of its kind.
        let owners = fx.q(
            e,
            "SELECT (SELECT relowner::regrole FROM pg_class WHERE oid = 'app.t'::regclass), \
             (SELECT relowner::regrole FROM pg_class WHERE oid = 'app.s'::regclass), \
             (SELECT proowner::regrole FROM pg_proc WHERE oid = 'app.f()'::regprocedure), \
             (SELECT nspowner::regrole FROM pg_namespace WHERE nspname = 'app'), \
             (SELECT lomowner::regrole FROM pg_largeobject_metadata WHERE oid = 424242), \
             (SELECT extowner::regrole FROM pg_extension WHERE extname = 'pgcrypto')",
        );
        assert_eq!(owners, [me; 6].join("|"));
        // pgcrypto's own objects stay the bootstrap superuser's (OID 10); `public` stays
        // pg_database_owner's.
        assert_eq!(
            fx.q(
                e,
                "SELECT count(*) > 0, bool_and(p.proowner = 10) FROM pg_depend d \
                 JOIN pg_proc p ON p.oid = d.objid WHERE d.classid = 'pg_proc'::regclass \
                 AND d.refclassid = 'pg_extension'::regclass AND d.deptype = 'e' \
                 AND d.refobjid = (SELECT oid FROM pg_extension WHERE extname = 'pgcrypto')"
            ),
            "t|t"
        );
        assert_eq!(
            fx.q(
                e,
                "SELECT nspowner::regrole FROM pg_namespace WHERE nspname = 'public'"
            ),
            "pg_database_owner"
        );
        // The large object is read and removed by the lease (the other clone's copy stays).
        assert_eq!(
            fx.q(e, "SELECT convert_from(lo_get(424242), 'UTF8')"),
            "large"
        );
        assert_eq!(fx.q(e, "SELECT lo_unlink(424242)"), "1");
        // New objects follow the default privileges recreated for the lease.
        fx.q(e, "CREATE TABLE n (x int)");
        fx.q(
            e,
            "CREATE FUNCTION g() RETURNS int LANGUAGE sql AS 'SELECT 1'",
        );
        assert_eq!(
            fx.q(
                e,
                "SELECT has_table_privilege('public', 'n', 'SELECT'), \
                 has_function_privilege('public', 'g()', 'EXECUTE')"
            ),
            "t|f"
        );
        // As the administrator, in the clone: nothing here depends on the template's owner.
        let deps = fx.admin_in(
            &e["PGDATABASE"],
            &format!(
                "SELECT count(*) FROM pg_catalog.pg_shdepend s WHERE s.dbid = \
                 (SELECT oid FROM pg_catalog.pg_database \
                 WHERE datname = pg_catalog.current_database()) \
                 AND s.refobjid = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = '{owner}')"
            ),
        );
        assert_eq!(deps.trim(), "0");
    }
    // A write in one clone is not in the other.
    fx.q(&ea, "INSERT INTO app.t VALUES (2)");
    assert_eq!(fx.q(&ea, "SELECT count(*) FROM app.t"), "2");
    assert_eq!(fx.q(&eb, "SELECT count(*) FROM app.t"), "1");
    fx.stop("a");
    fx.stop("b");
    assert_eq!(a.finish().code, 0);
    assert_eq!(b.finish().code, 0);
}

#[test]
fn a_lease_cannot_clone_a_template() {
    let Some(fx) = Fx::migrating("tplperm", "psql", PLAIN) else {
        return;
    };
    let (a, ea) = fx.hold("a");
    let tpl = format!("fg_t_{}", fx.key());
    assert!(fx.db_exists(&tpl), "no template database");
    let r = fx.as_lease(&ea, &format!("CREATE DATABASE x TEMPLATE \"{tpl}\""));
    assert_ne!(r.code, Some(0), "the lease cloned the template");
    assert!(r.stderr.contains("permission denied"), "{}", r.stderr);
    fx.stop("a");
    assert_eq!(a.finish().code, 0);
}

#[test]
fn a_new_key_replaces_the_template_while_a_clone_is_in_use() {
    let Some(fx) = Fx::migrating("newkey", "psql", PLAIN) else {
        return;
    };
    let k1 = fx.key();
    let (a, ea) = fx.hold("a");
    assert_eq!(fx.q(&ea, "SELECT x FROM t"), "1");
    fx.schema("CREATE TABLE t2 (y int);\n");
    let k2 = fx.key();
    assert_ne!(k1, k2);
    let (b, eb) = fx.hold("b");
    assert_eq!(fx.migrations(), 2);
    assert_ne!(eb["PGUSER"], fx.candidate(), "b ran on the candidate");
    assert_eq!(fx.q(&eb, "SELECT count(*) FROM t2"), "0");
    assert_eq!(fx.tpl_state(&k2).as_deref(), Some("ready"));
    let (t1, o1) = (format!("fg_t_{k1}"), format!("fg_o_{k1}"));
    wait_every(
        "the template of K1 is retired",
        EVENT,
        Duration::from_millis(250),
        || fx.tpl_state(&k1).is_none() && !fx.db_exists(&t1) && !fx.role_exists(&o1),
    );
    // The clone of K1 still answers.
    assert_eq!(fx.q(&ea, "SELECT x FROM t"), "1");
    fx.stop("a");
    fx.stop("b");
    assert_eq!(a.finish().code, 0);
    assert_eq!(b.finish().code, 0);
}

/// Review Focus 1: code left for the administrator by the migration (a function and an operator
/// of `public` that shadow the system ones, and a database setting that puts `public` first).
/// Both answer as the system ones would, so a caller that runs them goes on and commits the role.
const HOSTILE: &str = "\
CREATE TABLE t (x int);
CREATE FUNCTION public.fg_pwn() RETURNS void LANGUAGE plpgsql AS $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'fg_pwned') THEN
    EXECUTE 'CREATE ROLE fg_pwned'; END IF; END $$;
CREATE FUNCTION public.current_database() RETURNS name LANGUAGE plpgsql
  AS $$ BEGIN PERFORM public.fg_pwn(); RETURN pg_catalog.current_database(); END $$;
CREATE FUNCTION public.fg_ne(name, name) RETURNS boolean LANGUAGE plpgsql
  AS $$ BEGIN PERFORM public.fg_pwn(); RETURN $1::text OPERATOR(pg_catalog.<>) $2::text; END $$;
CREATE OPERATOR public.<> (LEFTARG = name, RIGHTARG = name, FUNCTION = public.fg_ne);
DO $$ BEGIN EXECUTE pg_catalog.format('ALTER DATABASE %I SET search_path = public, pg_catalog',
  pg_catalog.current_database()); END $$;
";

#[test]
fn a_migration_cannot_run_code_as_the_administrator() {
    let Some(fx) = Fx::migrating("hostile", "psql", HOSTILE) else {
        return;
    };
    let (a, ea) = fx.hold("a");
    assert!(
        !fx.role_exists("fg_pwned"),
        "code of the migration ran as the administrator"
    );
    assert_eq!(fx.migrations(), 1);
    assert_ne!(
        ea["PGUSER"],
        fx.candidate(),
        "the command ran on the candidate"
    );
    // The copy holds the trap, and the trap fires for whoever puts `public` first.
    assert_eq!(
        fx.q(
            &ea,
            "SELECT count(*) FROM pg_operator \
             WHERE oprname = '<>' AND oprnamespace = 'public'::regnamespace"
        ),
        "1"
    );
    let trap = fx.as_lease(
        &ea,
        "SET search_path = public, pg_catalog; SELECT current_database()",
    );
    assert!(
        trap.stderr.contains("permission denied to create role"),
        "{}",
        trap.stderr
    );
    fx.stop("a");
    assert_eq!(a.finish().code, 0);
}

/// Review Focus 5.
#[test]
fn migrations_that_reach_other_roles_are_refused() {
    let Some(fx) = Fx::migrating("reach", "psql", PLAIN) else {
        return;
    };
    let (a, ea) = fx.hold_in("a", &fx.other());
    let la = ea["PGUSER"].clone();
    let cases = [
        format!("CREATE TABLE t (x int);\nGRANT SELECT ON t TO \"{la}\";\n"),
        "CREATE TABLE t (x int);\nALTER TABLE t ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY p ON t TO CURRENT_USER USING (true);\n"
            .to_string(),
        // On 15.20, 16 and 17 the grant itself fails ("must have admin option"), and the migrate
        // exits with 3; where it succeeds, the promotion refuses the membership.
        format!(
            "CREATE TABLE t (x int);\nDO $$ BEGIN EXECUTE pg_catalog.format('GRANT %I TO %I', \
             current_user, '{la}'); END $$;\n"
        ),
    ];
    for (i, sql) in cases.iter().enumerate() {
        fx.schema(sql);
        let key = fx.key();
        let (r, e) = fx.run_env(&format!("c{i}"));
        assert_eq!(r.code, 0, "case {i}: {}", r.shape());
        assert!(
            r.stderr.contains("no shared database"),
            "case {i}: {:?}",
            r.notes()
        );
        println!("case {i}: {:?}", r.notes());
        assert_original(&e);
        assert_eq!(fx.migrations(), i + 1, "case {i}");
        assert_eq!(fx.tpl_state(&key).as_deref(), Some("failed"), "case {i}");
        fx.wait_lease_gone(&fx.candidate());
        // A gained nothing: no grant or policy names it in any database (the table's database
        // went with the candidate, so `has_table_privilege` has nothing left to name; a grant
        // to a role that is not pinned always leaves a row here), and no membership.
        assert_eq!(
            fx.count(&format!(
                "SELECT count(*) FROM pg_shdepend WHERE deptype <> 'o' \
                 AND refobjid = (SELECT oid FROM pg_roles WHERE rolname = '{la}')"
            )),
            0,
            "case {i}"
        );
        assert_eq!(
            fx.count(&format!(
                "SELECT count(*) FROM pg_auth_members m, pg_roles r \
                 WHERE r.rolname = '{la}' AND r.oid IN (m.roleid, m.member)"
            )),
            0,
            "case {i}"
        );
    }
    fx.stop("a");
    assert_eq!(a.finish().code, 0);
}

/// Review Focus 4.
#[test]
fn a_migration_that_leaves_a_session_open_still_becomes_a_template() {
    let Some(fx) = Fx::migrating("session", "psql-bg", PLAIN) else {
        return;
    };
    let key = fx.key();
    let (r, e) = fx.run_env("a");
    fx.got_clone(&r, &e);
    assert_eq!(fx.migrations(), 1);
    assert_eq!(fx.tpl_state(&key).as_deref(), Some("ready"));
    assert_eq!(
        fx.count(&format!(
            "SELECT count(*) FROM pg_stat_activity WHERE query = '{LEFT_BEHIND}'"
        )),
        0,
        "the session the migrate left is still open"
    );
}

#[test]
fn the_template_survives_a_daemon_restart() {
    let Some(mut fx) = Fx::migrating("restart", "psql", PLAIN) else {
        return;
    };
    let key = fx.key();
    let (r, e) = fx.run_env("a");
    fx.got_clone(&r, &e);
    fx.stop_daemon();
    fx.start_daemon();
    fx.warm();
    let (b, eb) = fx.hold("b");
    assert_eq!(fx.migrations(), 1, "the second daemon migrated again");
    assert_ne!(eb["PGUSER"], fx.candidate(), "b ran on the candidate");
    // The copy holds what the migration made, not an empty database.
    assert_eq!(fx.q(&eb, "SELECT x FROM t"), "1");
    assert_eq!(fx.tpl_state(&key).as_deref(), Some("ready"));
    fx.stop("b");
    assert_eq!(b.finish().code, 0);
}
