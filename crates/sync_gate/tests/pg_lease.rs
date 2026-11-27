//! The CLI side of the shared PostgreSQL lease: the real `sync_gate` binary against a daemon
//! started in-process with `sync_gated::run_with_pg` and the one `FakePg` (no real PostgreSQL).
//!
//! The command is this test binary re-executed (`child_entry`, driven by `SYNC_GATE_TEST_CHILD`).
//! Modes: `env` (writes its pid and the connection variables it sees to `FG_TEST_OUT`, exits
//! with `FG_TEST_EXIT_CODE`, default 0), `exit:<code>`, `hold` (as `env`, then waits for the file
//! `FG_TEST_STOP`). A project's `migrate` is the same binary with its mode as an extra argument
//! (`migrate_entry`). No path travels inside the mode string.

use interprocess::local_socket::{ListenerOptions, prelude::*};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant};
use sync_gate_core::ipc_name::{connect, connect_checked, server_is_ours, to_name};
use sync_gate_core::{Config, MIB, MachineSnapshot, Request, Response, StatusReport};
use sync_gate_probe::Probe;
use sync_gated::services::testkit::FakePg;
use sync_gated::{DaemonHandle, Deps, Measure, OsControl};

static COUNTER: AtomicU32 = AtomicU32::new(0);

// Hard limits, each from a row of the plan's "Prazos" table.
/// "sync_gate run terminar (concessao que sai)": 75 s.
const RUN_ENDS: Duration = Duration::from_secs(75);
/// The command starts after a lease that is granted at once: the test's patience (10 s) plus the
/// margin of the "o comando comeca" row (5 s).
const STARTS: Duration = Duration::from_secs(15);
/// "o comando comeca quando a concessao demora mais que a paciencia": patience 1 s + 5 s.
const START_AFTER_GIVE_UP: Duration = Duration::from_secs(6);
/// "banco sumir depois da devolucao": 410 s.
const DB_GONE: Duration = Duration::from_secs(410);
/// The grant reaches its role: "partida a frio ate running" 335 s + `name_taken` up to 3 x 35 s.
const ROLE_ASKED: Duration = Duration::from_secs(440);
/// "demais eventos com o cluster de pe e fora da fila": 60 s.
const EVENT: Duration = Duration::from_secs(60);
/// The thread that collects a process's stderr, and the lifetime of a fixture that nobody stops.
const STDERR_JOIN: Duration = Duration::from_secs(60);
const FIXTURE_LIFETIME: Duration = Duration::from_secs(60);
/// The daemon's own shutdown bounds added up (drain 5 s, hub wake 5 s, hub stop grace and slack
/// 10 s, hub ticker 1 s, server wake 5 s, postgres stop 85 s: 111 s), with a margin.
const DAEMON_SHUTDOWN: Duration = Duration::from_secs(120);
/// More than any limit above: rule D must never be what cleans in a test.
const QUIET_GRACE_NEVER: Duration = Duration::from_secs(600);
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

const PG_VARS: [&str; 8] = [
    "PGHOST",
    "PGPORT",
    "PGUSER",
    "PGDATABASE",
    "PGPASSWORD",
    "DATABASE_URL",
    "TEST_DATABASE_URL",
    "PGSERVICE",
];

fn out_path() -> PathBuf {
    PathBuf::from(std::env::var_os("FG_TEST_OUT").expect("FG_TEST_OUT"))
}

/// What the command prints on its stdout, and what the `ok` migrate prints on its own.
const COMMAND_SAYS: &str = "the command's own output";
const MIGRATE_SAYS: &str = "the migration's own output";

/// Appends `line` to the file `path`.
fn append(path: &Path, line: &str) {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    writeln!(f, "{line}").unwrap();
}

/// Child-process entry; inert unless `SYNC_GATE_TEST_CHILD` is set or an argument starts with
/// `migrate:` (a migrate inherits the command's variable, so its mode travels in its argv).
#[test]
fn child_entry() {
    let migrate = std::env::args().find(|a| a.starts_with("migrate:"));
    let Some(spec) = migrate.or_else(|| std::env::var("SYNC_GATE_TEST_CHILD").ok()) else {
        return;
    };
    let parts: Vec<&str> = spec.split(':').collect();
    if parts[0] == "migrate" {
        migrate_entry(&parts[1..]);
    }
    if parts[0] == "exit" {
        std::process::exit(parts[1].parse().unwrap());
    }
    append(&out_path().with_extension("runs"), "run");
    println!("{COMMAND_SAYS}");
    let mut text = format!("pid={}\n", std::process::id());
    for name in PG_VARS {
        if let Ok(v) = std::env::var(name) {
            text.push_str(&format!("{name}={v}\n"));
        }
    }
    let out = out_path();
    let tmp = out.with_extension("tmp");
    std::fs::write(&tmp, text).unwrap();
    std::fs::rename(&tmp, &out).unwrap();
    match parts[0] {
        "env" => {
            let code = std::env::var("FG_TEST_EXIT_CODE")
                .ok()
                .and_then(|c| c.parse().ok())
                .unwrap_or(0);
            std::process::exit(code);
        }
        "hold" => {
            let stop = PathBuf::from(std::env::var_os("FG_TEST_STOP").expect("FG_TEST_STOP"));
            let start = Instant::now();
            // Also ends when the sandbox is gone or after its fixed lifetime, so no fixture
            // outlives a failed test; the test never signals it by pid.
            while !stop.exists()
                && stop.parent().is_some_and(Path::exists)
                && start.elapsed() < FIXTURE_LIFETIME
            {
                std::thread::sleep(Duration::from_millis(50));
            }
            std::process::exit(0);
        }
        "nest" => {
            // A heavy command started inside the job by its name: the shim first on PATH runs it.
            // PATH set again so the lookup is the PATH's (Windows looks in other folders first).
            let st = Command::new("pytest")
                .args(SHIM_ARGS)
                .env("PATH", std::env::var_os("PATH").unwrap_or_default())
                .env("SYNC_GATE_TEST_CHILD", "env")
                .env("FG_TEST_OUT", out.with_extension("nested"))
                .status()
                .unwrap();
            std::process::exit(st.code().unwrap_or(1));
        }
        other => panic!("unknown child mode {other}"),
    }
}

/// The project's `migrate`. Names are relative to its working directory (the project), where
/// every run appends `run <pid>` to `migrate.log`, and `ended` when it exits by itself. Modes:
/// `ok` (writes the `PGUSER` and `DATABASE_URL` it got to `migrate.env`, prints a line on
/// stdout, exits 0), `fail` (exits 3), `hang:<name>` (waits for the file `name`, bounded like
/// `hold`), `touch:<name>` (changes the watched file `name`, exits 0).
fn migrate_entry(mode: &[&str]) -> ! {
    let log = Path::new("migrate.log");
    append(log, &format!("run {}", std::process::id()));
    let code = match mode {
        ["ok"] => {
            let mut text = String::new();
            for name in ["PGUSER", "DATABASE_URL"] {
                if let Ok(v) = std::env::var(name) {
                    text.push_str(&format!("{name}={v}\n"));
                }
            }
            std::fs::write("migrate.env", text).unwrap();
            println!("{MIGRATE_SAYS}");
            0
        }
        ["fail"] => 3,
        ["hang", name] => {
            let stop = PathBuf::from(std::env::var_os("FG_TEST_STOP").expect("FG_TEST_STOP"));
            let start = Instant::now();
            while !Path::new(name).exists()
                && stop.parent().is_some_and(Path::exists)
                && start.elapsed() < FIXTURE_LIFETIME
            {
                std::thread::sleep(Duration::from_millis(50));
            }
            0
        }
        ["touch", name] => {
            append(Path::new(name), "-- changed by the migration");
            0
        }
        other => panic!("unknown migrate mode {other:?}"),
    };
    append(log, "ended");
    std::process::exit(code);
}

/// A spawned CLI. Dropping it (a failed test) ends the CLI this test started (std only signals a
/// child it has not reaped), lets its fixture end by the stop file and bounds the stderr thread.
struct Proc {
    child: Option<Child>,
    err: mpsc::Receiver<String>,
    stop: PathBuf,
}

struct Out {
    code: i32,
    stderr: String,
}

impl Proc {
    fn spawn(mut c: Command, stop: &Path) -> Proc {
        let mut child = c.spawn().unwrap();
        let mut pipe = child.stderr.take();
        let (tx, err) = mpsc::channel();
        std::thread::spawn(move || {
            let mut s = String::new();
            if let Some(p) = pipe.as_mut() {
                let _ = p.read_to_string(&mut s);
            }
            let _ = tx.send(s);
        });
        Proc {
            child: Some(child),
            err,
            stop: stop.to_path_buf(),
        }
    }

    /// Waits for the exit (the child stays in this guard until it is known to have exited),
    /// then for the end of stderr; past either bound it panics and the drop guard cleans up.
    fn finish(mut self) -> Out {
        let child = self.child.as_mut().unwrap();
        let mut status = None;
        wait_for("the sync_gate process exits", RUN_ENDS, || {
            status = child.try_wait().unwrap();
            status.is_some()
        });
        let Ok(stderr) = self.err.recv_timeout(STDERR_JOIN) else {
            panic!("the stderr of the sync_gate process did not end within {STDERR_JOIN:?}");
        };
        Out {
            code: status.unwrap().code().unwrap_or(-1),
            stderr,
        }
    }

    /// Waits for the exit alone: `finish` also waits for the end of stderr, which a migrate the
    /// CLI left running holds open.
    fn exited(&mut self, limit: Duration) -> i32 {
        let child = self.child.as_mut().unwrap();
        let mut status = None;
        wait_for("the sync_gate process exits", limit, || {
            status = child.try_wait().unwrap();
            status.is_some()
        });
        status.unwrap().code().unwrap_or(-1)
    }

    /// Ends the CLI (the one this test started) and reaps it, bounded; its command is not
    /// touched. False if it was not reaped within `REAP` (it is left behind).
    fn kill(&mut self) -> bool {
        self.child.take().is_none_or(|mut c| reap(&mut c, REAP))
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = std::fs::write(&self.stop, "");
        if !self.kill() {
            note(format!(
                "pg_lease: the sync_gate process was not reaped within {REAP:?}; leaving it"
            ));
        }
        // No panic here (it may be a panic already): a bounded wait, then the thread is left.
        let _ = self.err.recv_timeout(STDERR_JOIN);
    }
}

/// Real tree RSS, but a fixed machine: `avail` of `total` is free whatever the children do.
struct FixedMachine {
    probe: Probe,
    total: u64,
    avail: u64,
}

impl Measure for FixedMachine {
    fn snapshot(&mut self) -> MachineSnapshot {
        MachineSnapshot {
            total: self.total,
            available: self.avail,
            reclaimable: 0,
            swap_used: 0,
            swap_total: 0,
            vram: None,
        }
    }
    fn tree_rss(&mut self, pid: u32) -> u64 {
        self.probe.tree_rss(pid)
    }
    fn start_time(&mut self, pid: u32) -> Option<u64> {
        sync_gate_probe::start_time(pid)
    }
}

struct Opts {
    max_leases: u32,
    wait_secs: u64,
    /// TOML array text.
    commands: &'static str,
    url_vars: &'static str,
    /// Room for exactly one unknown heavy job (the admission queue of plan 1) instead of many.
    one_job: bool,
    daemon: bool,
    quiet_grace: Duration,
    /// A recording proxy in front of the daemon (`Fx::proxy`).
    proxy: bool,
    /// The project's `migrate` argv and `watch` entries (both empty: no template).
    migrate: Vec<String>,
    watch: Vec<String>,
    migrate_secs: u64,
    /// `migrate` is the sandbox's `pytest` shim (`Fx::install_shims`) in this `migrate:` mode.
    migrate_shim: Option<&'static str>,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            max_leases: 8,
            wait_secs: 10,
            commands: "[]",
            url_vars: r#"["DATABASE_URL"]"#,
            one_job: false,
            daemon: true,
            quiet_grace: Duration::from_millis(300),
            proxy: false,
            migrate: Vec::new(),
            watch: Vec::new(),
            migrate_secs: 60,
            migrate_shim: None,
        }
    }
}

/// The test binary's arguments that run `child_entry` alone.
const SHIM_ARGS: [&str; 4] = ["child_entry", "--exact", "--nocapture", "--test-threads=1"];

fn exe_name(p: &str) -> String {
    if cfg!(windows) {
        format!("{p}.exe")
    } else {
        p.to_owned()
    }
}

/// Per-test sandbox: socket, data dir, project dir, `config.toml`, a daemon with `FakePg`.
struct Fx {
    daemon: Option<DaemonHandle<OsControl>>,
    dir: PathBuf,
    socket: String,
    proj: PathBuf,
    cfg_file: PathBuf,
    fake: Arc<FakePg>,
    proxy: Option<Proxy>,
}

impl Fx {
    fn new(o: Opts) -> Fx {
        let id = format!(
            "sync_gate-lease-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        let dir = std::env::temp_dir().join(&id);
        let proj = dir.join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        let socket = if cfg!(windows) {
            id
        } else {
            dir.join("s.sock").to_string_lossy().into_owned()
        };
        // A JSON array of strings is a TOML array too.
        let array = |v: &[String]| serde_json::to_string(v).unwrap();
        let migrate = match o.migrate_shim {
            Some(mode) => {
                let shim = dir.join("data").join("shims").join(exe_name("pytest"));
                let mut m = vec![shim.to_string_lossy().into_owned(), SHIM_ARGS[0].into()];
                m.push(mode.into());
                m.extend(SHIM_ARGS[1..].iter().map(|s| s.to_string()));
                m
            }
            None => o.migrate,
        };
        let text = format!(
            "tick_ms = 50\nreserve_fraction = 0.0\noptimism = 1.0\n\n[postgres]\nbin_dir = '{}'\n\
             max_leases = {}\nlease_wait_secs = {}\n\n[[postgres.project]]\ndir = '{}'\n\
             commands = {}\nurl_vars = {}\nmigrate = {}\nwatch = {}\nmigrate_timeout_secs = {}\n",
            dir.join("bin").display(),
            o.max_leases,
            o.wait_secs,
            proj.display(),
            o.commands,
            o.url_vars,
            array(&migrate),
            array(&o.watch),
            o.migrate_secs
        );
        let cfg_file = dir.join("config.toml");
        std::fs::write(&cfg_file, &text).unwrap();
        let fake = Arc::new(FakePg::default());
        let mut fx = Fx {
            daemon: None,
            dir,
            socket,
            proj,
            cfg_file,
            fake,
            proxy: None,
        };
        if o.daemon {
            let (total, avail) = if o.one_job {
                (4096 * MIB, 2048 * MIB)
            } else {
                (65536 * MIB, 32768 * MIB)
            };
            let m = FixedMachine {
                probe: Probe::new(),
                total,
                avail,
            };
            let mut deps = Deps::os();
            deps.tools = fx.fake.clone();
            // The fake server has no process: the probe answers for it, and for real ones as usual.
            let fake = fx.fake.clone();
            deps.probe = Arc::new(move |pid| match fake.server_id() {
                Some(id) if id.pid == pid => (Some(true), Some(id.start)),
                _ => (
                    sync_gate_probe::process_alive(pid),
                    sync_gate_probe::start_time(pid),
                ),
            });
            deps.quiet_grace = o.quiet_grace;
            deps.quiet_sample_every = Duration::from_millis(100);
            let cfg = Config::from_toml(&text).unwrap();
            let launcher = Arc::new(sync_gated::OsLauncher::default());
            fx.daemon = Some(
                sync_gated::run_with_pg(
                    cfg,
                    &fx.socket,
                    m,
                    OsControl,
                    Some(fx.data_dir()),
                    launcher,
                    deps,
                )
                .unwrap(),
            );
        }
        if o.proxy {
            fx.proxy = Some(Proxy::new(&fx));
        }
        fx
    }

    fn proxy(&self) -> &Proxy {
        self.proxy.as_ref().expect("Opts::proxy")
    }

    fn data_dir(&self) -> PathBuf {
        self.dir.join("data")
    }

    fn file(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn stop_file(&self) -> PathBuf {
        self.file("stop")
    }

    fn registry(&self) -> serde_json::Value {
        let path = self.data_dir().join("pg").join("17").join("leases.json");
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or(serde_json::Value::Null)
    }

    /// The CLI with this sandbox, its working directory in `cwd`, the fixture mode and files.
    fn base(&self, mode: &str, out: &Path, cwd: &Path) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_sync_gate"));
        for v in PG_VARS {
            c.env_remove(v);
        }
        c.env("SYNC_GATE_SOCKET", &self.socket)
            .env("SYNC_GATE_DATA_DIR", self.data_dir())
            .env("SYNC_GATE_CONFIG", &self.cfg_file)
            .env_remove("SYNC_GATE_JOB")
            .env("SYNC_GATE_FORCE_HEAVY", "1")
            .env("SYNC_GATE_TEST_CHILD", mode)
            .env("FG_TEST_OUT", out)
            .env("FG_TEST_STOP", self.stop_file())
            .current_dir(cwd)
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        c
    }

    /// `sync_gate run [extra] -- <this test binary> child_entry ...`
    fn run_cmd(&self, mode: &str, out: &Path, cwd: &Path, extra: &[&str]) -> Command {
        let exe = std::env::current_exe().unwrap();
        let mut c = self.base(mode, out, cwd);
        c.arg("run").args(extra).args(["--", exe.to_str().unwrap()]);
        c.args(["child_entry", "--exact", "--nocapture", "--test-threads=1"]);
        c
    }

    fn spawn(&self, c: Command) -> Proc {
        Proc::spawn(c, &self.stop_file())
    }

    fn run(&self, mode: &str, name: &str) -> (Proc, PathBuf) {
        let out = self.file(name);
        (self.spawn(self.run_cmd(mode, &out, &self.proj, &[])), out)
    }

    /// `sync_gate shims install` into this sandbox, and a `real` folder whose `pytest` and `cargo`
    /// are this test binary, found behind the shims as a shell would find them.
    fn install_shims(&self) {
        let out = Command::new(env!("CARGO_BIN_EXE_sync_gate"))
            .args(["shims", "install"])
            .env("SYNC_GATE_DATA_DIR", self.data_dir())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let real = self.file("real");
        std::fs::create_dir_all(&real).unwrap();
        let exe = std::env::current_exe().unwrap();
        for name in ["pytest", "cargo"] {
            let to = real.join(exe_name(name));
            if std::fs::hard_link(&exe, &to).is_err() {
                std::fs::copy(&exe, &to).unwrap();
            }
        }
    }

    /// The PATH of the shim runs: the shims, then the real `pytest`.
    fn shim_path(&self) -> std::ffi::OsString {
        std::env::join_paths([self.data_dir().join("shims"), self.file("real")]).unwrap()
    }

    /// `<shims>/pytest child_entry ...` in `cwd`: heavy by its name, nothing forced.
    fn shim_cmd(&self, mode: &str, out: &Path, cwd: &Path) -> Command {
        self.shim_cmd_as("pytest", mode, out, cwd)
    }

    /// `<shims>/cargo child_entry ...` in `cwd`: light by its signature (`child_entry` is no heavy
    /// cargo subcommand), nothing forced, so the CLI talks to the daemon only about the lease.
    /// `sync_gate run` always queues; a shim is the path a light command still takes.
    fn light_cmd(&self, mode: &str, out: &Path, cwd: &Path) -> Command {
        self.install_shims();
        self.shim_cmd_as("cargo", mode, out, cwd)
    }

    fn shim_cmd_as(&self, program: &str, mode: &str, out: &Path, cwd: &Path) -> Command {
        let mut c = Command::new(self.data_dir().join("shims").join(exe_name(program)));
        for v in PG_VARS {
            c.env_remove(v);
        }
        c.args(SHIM_ARGS)
            .env("PATH", self.shim_path())
            .env("SYNC_GATE_SOCKET", &self.socket)
            .env("SYNC_GATE_DATA_DIR", self.data_dir())
            .env("SYNC_GATE_CONFIG", &self.cfg_file)
            .env("SYNC_GATE_TEST_CHILD", mode)
            .env("FG_TEST_OUT", out)
            .env("FG_TEST_STOP", self.stop_file())
            .env_remove("SYNC_GATE_FORCE_HEAVY")
            .env_remove("SYNC_GATE_JOB")
            .env_remove("SYNC_GATE_SESSION")
            .current_dir(cwd)
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        c
    }

    /// How many admissions the daemon has decided.
    fn admitted(&self) -> usize {
        let d = self.status().decisions;
        d.iter().filter(|d| d.contains("admitted #")).count()
    }

    /// Starts a held command and waits until it runs; returns its pid.
    fn hold(&self, name: &str) -> (Proc, PathBuf, u64) {
        let (p, out) = self.run("hold", name);
        wait_file(&out, STARTS);
        let pid = read_env(&out)["pid"].parse().unwrap();
        (p, out, pid)
    }

    fn stop(&self) {
        std::fs::write(self.stop_file(), "").unwrap();
    }

    fn status(&self) -> StatusReport {
        match sync_gate::client::call_at(&self.socket, &Request::Status).unwrap() {
            Response::Status(s) => s,
            other => panic!("{other:?}"),
        }
    }

    /// Waits until the registry says the lease belongs to a command with this pid.
    fn registered(&self, pid: u64) {
        wait_for("the command is registered", EVENT, || {
            self.registry()["leases"]
                .as_array()
                .is_some_and(|l| l.iter().any(|r| r["command"]["pid"] == pid))
        });
    }

    /// Waits for a `FakePg` call that starts with `prefix` (already made or still to come).
    fn wait_call(&self, prefix: &str, limit: Duration) {
        let rx = self.fake.subscribe();
        let seen = |calls: Vec<String>| calls.iter().any(|c| c.starts_with(prefix));
        if seen(self.fake.calls()) {
            return;
        }
        let start = Instant::now();
        loop {
            let left = limit.saturating_sub(start.elapsed());
            match rx.recv_timeout(left) {
                Ok(c) if c.starts_with(prefix) => return,
                // Past the limit a queue of other calls must not keep the loop going.
                Ok(_) if !left.is_zero() => {}
                _ => panic!("no {prefix} call within {limit:?}: {:?}", self.fake.calls()),
            }
        }
    }

    /// Where the recording proxy of this sandbox listens.
    fn proxy_name(&self) -> String {
        if cfg!(windows) {
            format!("{}-proxy", self.socket)
        } else {
            self.dir.join("p.sock").to_string_lossy().into_owned()
        }
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::write(self.stop_file(), "");
        let mut failed = None;
        if let Some(d) = self.daemon.take() {
            // On a thread of its own: the daemon's shutdown prints with `eprintln!`, and a panic
            // there must not become a second panic of this (maybe unwinding) thread; bounded.
            let (tx, rx) = mpsc::channel();
            let spawned = std::thread::Builder::new().spawn(move || {
                d.shutdown();
                let _ = tx.send(());
            });
            failed = match spawned.map(|_| rx.recv_timeout(DAEMON_SHUTDOWN)) {
                Ok(Ok(())) => None,
                Err(_) => Some("the thread for the daemon's shutdown could not be created".into()),
                Ok(Err(mpsc::RecvTimeoutError::Disconnected)) => {
                    Some("the daemon's shutdown panicked".into())
                }
                Ok(Err(mpsc::RecvTimeoutError::Timeout)) => Some(format!(
                    "the daemon did not shut down within {DAEMON_SHUTDOWN:?}"
                )),
            };
        }
        // After the daemon (and the `FakePg` blockers, test locals dropped before `Fx`): a
        // relay ends only once its upstream answers or closes, and the proxy waits for them.
        drop(self.proxy.take());
        let _ = std::fs::remove_dir_all(&self.dir);
        // A failed shutdown fails a test whose assertions passed; during an unwind it is noted.
        if let Some(what) = failed {
            if std::thread::panicking() {
                note(format!("pg_lease: {what}; leaving it"));
            } else {
                panic!("pg_lease: {what}");
            }
        }
    }
}

/// Waits for a condition on state that emits no event (a file, the registry, the status
/// counter, a process exit through `try_wait`); everything that does emit one (a `FakePg`
/// call, the proxy) has its own wait.
/// Ruling: where std offers no event, a bounded poll is allowed, only through this helper,
/// which panics with `what` past `limit`; a sleep then an assertion, or an unbounded poll, is not.
fn wait_for(what: &str, limit: Duration, mut ok: impl FnMut() -> bool) {
    let start = Instant::now();
    while !ok() {
        assert!(start.elapsed() < limit, "timed out: {what}");
        std::thread::park_timeout(Duration::from_millis(10));
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

fn injected(e: &BTreeMap<String, String>) -> Vec<&str> {
    PG_VARS
        .iter()
        .copied()
        .filter(|v| e.contains_key(*v))
        .collect()
}

fn mine(c: &mut Command) {
    c.env("DATABASE_URL", "postgres://mine")
        .env("PGSERVICE", "x");
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

fn assert_original(e: &BTreeMap<String, String>) {
    assert!(
        e.get("DATABASE_URL").map(String::as_str) == Some("postgres://mine"),
        "DATABASE_URL is not the original one"
    );
    assert!(
        e.get("PGSERVICE").map(String::as_str) == Some("x"),
        "PGSERVICE is not the original one"
    );
    assert!(
        injected(e) == ["DATABASE_URL", "PGSERVICE"],
        "set variables: {:?}",
        redacted(e)
    );
}

#[test]
fn matching_project_gets_a_database_env() {
    let fx = Fx::new(Opts::default());
    let out = fx.file("a");
    let mut c = fx.run_cmd("env", &out, &fx.proj, &[]);
    c.env("PGSERVICE", "from-the-cli");
    let r = fx.spawn(c).finish();
    assert_eq!(r.code, 0, "{}", r.stderr);
    let e = read_env(&out);
    let user = &e["PGUSER"];
    assert!(user.starts_with("fg_l_"), "{user}");
    assert_eq!(&e["PGDATABASE"], user);
    assert!(e.contains_key("DATABASE_URL") && e.contains_key("PGPASSWORD"));
    assert!(!e.contains_key("PGSERVICE"), "PGSERVICE must be removed");
    assert!(!r.stderr.contains(&e["PGPASSWORD"]), "no secret on stderr");
}

#[test]
fn another_dir_or_command_gets_nothing() {
    // A directory outside the project (the project matches every command).
    let fx = Fx::new(Opts::default());
    let elsewhere = fx.file("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let out = fx.file("a");
    let r = fx.spawn(fx.run_cmd("env", &out, &elsewhere, &[])).finish();
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(injected(&read_env(&out)).is_empty());
    // A project that only matches `npm test`.
    let fx2 = Fx::new(Opts {
        commands: r#"["npm test"]"#,
        ..Opts::default()
    });
    let out2 = fx2.file("b");
    let r = fx2
        .spawn(fx2.run_cmd("env", &out2, &fx2.proj, &[]))
        .finish();
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(injected(&read_env(&out2)).is_empty());
    // A lease asks and is answered before its command starts, so both runs are over: nothing was asked.
    assert_eq!(fx.fake.count("create_role"), 0);
    assert_eq!(fx2.fake.count("create_role"), 0);
    assert!(!r.stderr.contains("no shared database"), "{}", r.stderr);
}

#[test]
fn the_command_is_registered_as_a_holder() {
    let fx = Fx::new(Opts::default());
    let (p, _out, pid) = fx.hold("a");
    fx.registered(pid);
    fx.stop();
    assert_eq!(p.finish().code, 0);
}

#[test]
fn killing_the_cli_keeps_the_database_while_the_command_lives() {
    let fx = Fx::new(Opts::default());
    let (mut p, _out, pid) = fx.hold("a");
    fx.registered(pid);
    assert!(p.kill(), "the CLI was not reaped within {REAP:?}");
    // A tick that began after the CLI died has judged the holders.
    let seen = fx.status().services[0].checks;
    wait_for("a tick after the CLI died", EVENT, || {
        fx.status().services[0].checks > seen + 1
    });
    assert_eq!(fx.fake.count("drop_role"), 0);
    assert_eq!(fx.fake.count("drop_database"), 0);
    fx.stop();
    fx.wait_call("sql drop_role", DB_GONE);
    assert!(fx.fake.roles().is_empty() && fx.fake.dbs().is_empty());
}

#[test]
fn the_lease_is_released_after_exit_and_the_exit_code_is_kept() {
    let fx = Fx::new(Opts::default());
    let out = fx.file("a");
    let mut c = fx.run_cmd("env", &out, &fx.proj, &[]);
    c.env("FG_TEST_EXIT_CODE", "3");
    let r = fx.spawn(c).finish();
    assert_eq!(r.code, 3, "{}", r.stderr);
    fx.wait_call("sql drop_role", DB_GONE);
    assert!(fx.fake.roles().is_empty() && fx.fake.dbs().is_empty());
}

#[test]
fn daemon_down_runs_with_the_original_env_and_warns_once() {
    let fx = Fx::new(Opts {
        daemon: false,
        ..Opts::default()
    });
    let out = fx.file("a");
    let mut c = fx.run_cmd("env", &out, &fx.proj, &[]);
    mine(&mut c);
    let r = fx.spawn(c).finish();
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        r.stderr
            .matches("no shared database (daemon not running)")
            .count(),
        1,
        "{}",
        r.stderr
    );
    assert_original(&read_env(&out));
}

#[test]
fn daemon_refusal_runs_with_the_original_env() {
    let fx = Fx::new(Opts {
        max_leases: 1,
        ..Opts::default()
    });
    let (_held, _o, _pid) = fx.hold("a");
    let out = fx.file("b");
    let mut c = fx.run_cmd("env", &out, &fx.proj, &[]);
    mine(&mut c);
    c.env("FG_TEST_EXIT_CODE", "9");
    let r = fx.spawn(c).finish();
    assert_eq!(r.code, 9, "{}", r.stderr);
    assert!(r.stderr.contains("in use"), "{}", r.stderr);
    assert_eq!(r.stderr.matches("no shared database").count(), 1);
    assert_original(&read_env(&out));
}

/// What the proxy saw of one request: its kind and, for the lease messages, the request id.
type Seen = (&'static str, Option<String>);

struct ProxyState {
    seen: Vec<Seen>,
    /// Connections accepted and not yet done relaying (counted by the accept thread).
    open: usize,
    accepting: bool,
    /// Every request's kind in arrival order, and again with `true` once it was answered.
    events: Vec<(&'static str, bool)>,
    /// The next `n` requests of this kind get an `Error` the proxy makes up.
    refuse: Option<(&'static str, u32)>,
    /// Requests of these kinds are read and never answered (until the proxy stops).
    stall: Vec<&'static str>,
    /// Requests of this kind wait until the first one's arrival plus the duration.
    gate: Option<(&'static str, Duration, Option<Instant>)>,
    /// Requests of this kind wait until one of the files exists.
    gate_file: Option<(&'static str, Vec<PathBuf>)>,
}

/// What the proxy does with one request.
enum Rule {
    Pass,
    Refuse,
    Stall,
    Until(Instant),
    AfterFile(Vec<PathBuf>),
}

fn kind_of(r: &Request) -> &'static str {
    match r {
        Request::Lease { .. } => "Lease",
        Request::LeaseGiveUp { .. } => "LeaseGiveUp",
        Request::LeaseHolder { .. } => "LeaseHolder",
        Request::TemplateReady { .. } => "TemplateReady",
        Request::ReleaseLease { .. } => "ReleaseLease",
        Request::Finished { .. } => "Finished",
        _ => "other",
    }
}

type Shared = Arc<(Mutex<ProxyState>, Condvar)>;

/// Applies its change to the proxy state when dropped, on every path, and wakes the waiters.
struct OnDrop(Shared, fn(&mut ProxyState));

impl Drop for OnDrop {
    fn drop(&mut self) {
        (self.1)(&mut self.0.0.lock().unwrap_or_else(|e| e.into_inner()));
        self.0.1.notify_all();
    }
}

/// Waits, bounded, while `busy` holds on the proxy state; false if it still holds at the limit.
fn wait_state(st: &Shared, limit: Duration, busy: impl Fn(&ProxyState) -> bool) -> bool {
    let g = st.0.lock().unwrap_or_else(|e| e.into_inner());
    let (_g, t) =
        st.1.wait_timeout_while(g, limit, |s| busy(s))
            .unwrap_or_else(|e| e.into_inner());
    !t.timed_out()
}

/// How long dropping the proxy waits for its accept thread and for its relays.
const PROXY_DRAIN: Duration = Duration::from_secs(10);

/// A socket the CLI is pointed at: for each connection it reads the request, records its kind and
/// request id (never the reply, which carries the variables), forwards the line to the real
/// daemon's socket and relays the reply. Test code only; the daemon is the real one.
struct Proxy {
    name: String,
    state: Shared,
    stop: Arc<AtomicBool>,
    accept: Option<std::thread::JoinHandle<()>>,
}

impl Proxy {
    fn new(fx: &Fx) -> Proxy {
        let name = fx.proxy_name();
        let listener = ListenerOptions::new()
            .name(to_name(&name).unwrap())
            .create_sync()
            .unwrap();
        let state: Shared = Arc::new((
            Mutex::new(ProxyState {
                seen: Vec::new(),
                open: 0,
                accepting: true,
                events: Vec::new(),
                refuse: None,
                stall: Vec::new(),
                gate: None,
                gate_file: None,
            }),
            Condvar::new(),
        ));
        let stop = Arc::new(AtomicBool::new(false));
        let (st, flag, target) = (state.clone(), stop.clone(), fx.socket.clone());
        let accept = std::thread::spawn(move || {
            let _ended = OnDrop(st.clone(), |s| s.accepting = false);
            // Sequential: a connection is counted open here, before its handler exists, so a
            // later connection's reply proves every earlier one is counted.
            while let Ok(conn) = listener.accept() {
                if flag.load(Ordering::SeqCst) {
                    break;
                }
                st.0.lock().unwrap_or_else(|e| e.into_inner()).open += 1;
                let open = OnDrop(st.clone(), |s| s.open -= 1);
                let (st, target) = (st.clone(), target.clone());
                std::thread::spawn(move || {
                    let _open = open;
                    relay(&conn, &st, &target);
                });
            }
        });
        Proxy {
            name,
            state,
            stop,
            accept: Some(accept),
        }
    }

    /// The lease messages seen so far, in order (other requests, the barrier's included, are
    /// not lease messages).
    fn seen(&self) -> Vec<Seen> {
        let g = self.state.0.lock().unwrap_or_else(|e| e.into_inner());
        g.seen.iter().filter(|s| s.0 != "other").cloned().collect()
    }

    fn with(&self, f: impl FnOnce(&mut ProxyState)) {
        f(&mut self.state.0.lock().unwrap_or_else(|e| e.into_inner()));
    }

    fn refuse(&self, kind: &'static str, times: u32) {
        self.with(|s| s.refuse = Some((kind, times)));
    }

    fn stall(&self, kinds: &[&'static str]) {
        self.with(|s| s.stall = kinds.to_vec());
    }

    fn gate_after_file(&self, kind: &'static str, files: Vec<PathBuf>) {
        self.with(|s| s.gate_file = Some((kind, files)));
    }

    fn gate(&self, kind: &'static str, hold: Duration) {
        self.with(|s| s.gate = Some((kind, hold, None)));
    }

    /// Where the first `(kind, answered)` event is, if any.
    fn first(&self, kind: &str, answered: bool) -> Option<usize> {
        let g = self.state.0.lock().unwrap_or_else(|e| e.into_inner());
        g.events.iter().position(|e| *e == (kind, answered))
    }

    /// The barrier of the negative assertions; call it once the CLI has exited (it joins its
    /// sends before exit). A `Status` of its own through the proxy is accepted after every
    /// connection the CLI made, each counted open by then; then, bounded, none is open any more:
    /// every request the CLI sent has been read, recorded and answered.
    fn wait_idle(&self) {
        match sync_gate::client::call_with_deadline(&self.name, &Request::Status, EVENT) {
            Ok(Response::Status(_)) => {}
            Ok(_) => panic!("the barrier's Status got another reply"),
            Err(e) => panic!("the barrier's Status failed: {e}"),
        }
        assert!(
            wait_state(&self.state, EVENT, |s| s.open > 0),
            "the proxy still has an open connection"
        );
    }
}

/// One connection of the proxy: request line in, recorded, forwarded, reply line back.
fn relay(conn: &LocalSocketStream, st: &Shared, target: &str) {
    let mut line = Vec::new();
    if BufReader::new(conn)
        .read_until(b'\n', &mut line)
        .unwrap_or(0)
        == 0
    {
        return;
    }
    let req = serde_json::from_slice::<Request>(&line).ok();
    let kind = req.as_ref().map_or("other", kind_of);
    let seen: Seen = match req {
        Some(Request::Lease { request, .. } | Request::LeaseGiveUp { request }) => {
            (kind, Some(request))
        }
        _ => ("other", None),
    };
    let rule = {
        let mut g = st.0.lock().unwrap_or_else(|e| e.into_inner());
        let s = &mut *g;
        s.seen.push(seen);
        s.events.push((kind, false));
        match (&mut s.refuse, &mut s.gate) {
            (Some((k, n)), _) if *k == kind && *n > 0 => {
                *n -= 1;
                Rule::Refuse
            }
            _ if s.stall.contains(&kind) => Rule::Stall,
            _ if s.gate_file.as_ref().is_some_and(|g| g.0 == kind) => {
                Rule::AfterFile(s.gate_file.clone().unwrap().1)
            }
            (_, Some((k, hold, at))) if *k == kind => {
                Rule::Until(*at.get_or_insert(Instant::now() + *hold))
            }
            _ => Rule::Pass,
        }
    };
    let mut reply = Vec::new();
    match rule {
        Rule::Pass => {}
        Rule::Refuse => {
            let refused = Response::Error {
                message: "refused by the test proxy".into(),
            };
            reply = serde_json::to_vec(&refused).unwrap();
            reply.push(b'\n');
        }
        // Ends when the proxy stops accepting (its drop).
        Rule::Stall => {
            wait_state(st, FIXTURE_LIFETIME, |s| s.accepting);
            return;
        }
        // Bounded.
        Rule::AfterFile(files) => {
            let limit = Instant::now() + FIXTURE_LIFETIME;
            while !files.iter().any(|f| f.exists()) && Instant::now() < limit {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        Rule::Until(at) => std::thread::sleep(at.saturating_duration_since(Instant::now())),
    }
    if reply.is_empty() {
        let Ok(up) = connect_checked(target, server_is_ours) else {
            return;
        };
        let mut up = BufReader::new(up);
        if up.get_mut().write_all(&line).is_err() || up.get_mut().flush().is_err() {
            return;
        }
        if up.read_until(b'\n', &mut reply).unwrap_or(0) == 0 {
            return;
        }
    }
    // Recorded before the CLI can read it: whatever it sends next comes after in `events`.
    st.0.lock()
        .unwrap_or_else(|e| e.into_inner())
        .events
        .push((kind, true));
    let mut w = conn;
    let _ = w.write_all(&reply);
    let _ = w.flush();
}

/// A connect that completes after `limit` leaves a helper thread holding one stream (acceptable
/// in a failing test); `None` if it failed, timed out or the thread could not be created.
fn connect_within(name: &str, limit: Duration) -> Option<interprocess::local_socket::Stream> {
    let (tx, rx) = mpsc::channel();
    let name = name.to_owned();
    std::thread::Builder::new()
        .spawn(move || {
            let _ = tx.send(connect(&name));
        })
        .ok()?;
    rx.recv_timeout(limit).ok()?.ok()
}

impl Drop for Proxy {
    /// Stops accepting, then waits (bounded) for the relays; a relay can only end once its
    /// upstream answers or closes, which is why `Fx` drops the proxy after the daemon.
    fn drop(&mut self) {
        // One deadline for the whole drop; every step gets what is left of it. Messages go
        // through a fallible write: `eprintln!` panics when stderr fails, and this may unwind.
        let deadline = Instant::now() + PROXY_DRAIN;
        let left = |d: Instant| d.saturating_duration_since(Instant::now());
        self.stop.store(true, Ordering::SeqCst);
        // The wake connection stays open until the accept thread is gone: on Windows a client
        // that closes before the accept is discarded and the accept would block again.
        let Some(wake) = connect_within(&self.name, left(deadline)) else {
            note("pg_lease: the proxy's wake connection failed; leaking its accept thread".into());
            return;
        };
        let stopped = wait_state(&self.state, left(deadline), |s| s.accepting);
        drop(wake);
        match self.accept.take() {
            // The thread has run its last statement (the `accepting` flag); only drops remain.
            Some(a) if stopped => {
                let _ = a.join();
            }
            _ => {
                note("pg_lease: the proxy's accept thread did not stop; leaving it".into());
            }
        }
        if !wait_state(&self.state, left(deadline), |s| s.open > 0) {
            note(format!(
                "pg_lease: a proxy relay is still open after {PROXY_DRAIN:?}; leaving it"
            ));
        }
    }
}

/// The CLI talks to the daemon through `proxy`.
fn through(c: &mut Command, fx: &Fx) {
    c.env("SYNC_GATE_SOCKET", fx.proxy_name());
}

#[test]
fn a_grant_slower_than_the_patience_lets_the_command_start_with_the_original_env() {
    // Rule D cannot be what cleans: the quiet window is longer than any wait of this test, so
    // only the give-up of that very request can drop the late grant.
    let fx = Fx::new(Opts {
        wait_secs: 1,
        quiet_grace: QUIET_GRACE_NEVER,
        proxy: true,
        ..Opts::default()
    });
    let proxy = fx.proxy();
    let blocked = fx.fake.block("create_role");
    let out = fx.file("a");
    let mut c = fx.run_cmd("env", &out, &fx.proj, &[]);
    mine(&mut c);
    through(&mut c, &fx);
    let p = fx.spawn(c);
    wait_file(&out, START_AFTER_GIVE_UP);
    let r = p.finish();
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        r.stderr
            .matches("no shared database (timed out after 1 s)")
            .count(),
        1,
        "{}",
        r.stderr
    );
    assert_original(&read_env(&out));
    assert!(fx.fake.wait_entered("create_role", ROLE_ASKED));
    drop(blocked);
    // The give-up of that request reached the daemon: the late grant is cleaned, nothing is left.
    fx.wait_call("sql drop_role", DB_GONE);
    wait_for("the registry has no row", EVENT, || {
        fx.registry()["leases"]
            .as_array()
            .is_some_and(Vec::is_empty)
    });
    assert!(fx.fake.roles().is_empty() && fx.fake.dbs().is_empty());
    proxy.wait_idle();
    let seen = proxy.seen();
    let kinds: Vec<_> = seen.iter().map(|s| s.0).collect();
    assert!(kinds == ["Lease", "LeaseGiveUp"], "{kinds:?}");
    assert!(seen[0].1 == seen[1].1, "the give-up is for another request");
}

#[test]
fn the_give_up_carries_the_request_id_of_the_lease() {
    let fx = Fx::new(Opts {
        wait_secs: 1,
        proxy: true,
        ..Opts::default()
    });
    let proxy = fx.proxy();
    let blocked = fx.fake.block("create_role");
    let out = fx.file("a");
    let mut c = fx.light_cmd("env", &out, &fx.proj);
    through(&mut c, &fx);
    let r = fx.spawn(c).finish();
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(fx.admitted(), 0, "a light command is never admitted");
    drop(blocked);
    proxy.wait_idle();
    let seen = proxy.seen();
    let kinds: Vec<_> = seen.iter().map(|s| s.0).collect();
    assert!(kinds == ["Lease", "LeaseGiveUp"], "{kinds:?}");
    let (asked, given) = (seen[0].1.clone().unwrap(), seen[1].1.clone().unwrap());
    assert!(asked == given, "the give-up is for another request");
    let ok = |s: &str| {
        (1..=64).contains(&s.len())
            && s.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase() || c == '-')
    };
    assert!(ok(&asked), "{asked}");
}

#[test]
fn a_daemon_error_runs_at_once_without_a_give_up() {
    let fx = Fx::new(Opts {
        max_leases: 1,
        wait_secs: 30,
        proxy: true,
        ..Opts::default()
    });
    let proxy = fx.proxy();
    let (held, _o, _pid) = fx.hold("a");
    let out = fx.file("b");
    let mut c = fx.light_cmd("env", &out, &fx.proj);
    mine(&mut c);
    through(&mut c, &fx);
    let admitted = fx.admitted();
    let started = Instant::now();
    let r = fx.spawn(c).finish();
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(fx.admitted(), admitted, "a light command is never admitted");
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "waited for the patience"
    );
    assert!(r.stderr.contains("in use"), "{}", r.stderr);
    assert_original(&read_env(&out));
    // The CLI has exited (it joins its sends first), the barrier's own request came back after
    // all of its connections, and none is open: a late give-up cannot slip past the assertion.
    proxy.wait_idle();
    let kinds: Vec<_> = proxy.seen().iter().map(|s| s.0).collect();
    assert!(kinds == ["Lease"], "{kinds:?}");
    fx.stop();
    assert_eq!(held.finish().code, 0);
}

fn all_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        if p.is_dir() {
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
fn a_queued_command_gets_its_database_when_it_runs_and_the_pending_file_has_no_secret() {
    let fx = Fx::new(Opts {
        one_job: true,
        proxy: true,
        ..Opts::default()
    });
    let proxy = fx.proxy();
    let (held, out_a, _pid) = fx.hold("a");
    let secret_a = read_env(&out_a)["PGPASSWORD"].clone();
    let out_b = fx.file("b");
    let mut cb = fx.run_cmd("env", &out_b, &fx.proj, &["--max-wait", "1"]);
    through(&mut cb, &fx);
    let b = fx.spawn(cb).finish();
    assert_eq!(b.code, 75, "{}", b.stderr);
    assert!(!out_b.exists(), "a queued command has not run");
    // While it is pending it asked for no database: the one role is the held command's.
    proxy.wait_idle();
    assert!(
        !proxy.seen().iter().any(|s| s.0.starts_with("Lease")),
        "a lease was requested while the command was queued"
    );
    assert_eq!(fx.fake.count("create_role"), 1);
    let n: u64 = b
        .stderr
        .split("sync_gate wait ")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no ticket number in {}", b.stderr));
    let pending = |fx: &Fx| {
        let mut files = Vec::new();
        all_files(&fx.data_dir().join("pending"), &mut files);
        files
    };
    let files = pending(&fx);
    assert!(!files.is_empty(), "the command is pending");
    for f in &files {
        let bytes = std::fs::read(f).unwrap();
        for needle in [
            secret_a.as_str(),
            "postgres://",
            "PGPASSWORD",
            "DATABASE_URL",
        ] {
            assert!(
                !contains(&bytes, needle),
                "{} has one of the lease's values",
                f.display()
            );
        }
    }
    fx.stop();
    assert_eq!(held.finish().code, 0);
    let ticket = n.to_string();
    let mut c = fx.base("env", &out_b, &fx.proj);
    c.args(["wait", &ticket, "--max-wait", "30"]);
    let w = fx.spawn(c).finish();
    assert_eq!(w.code, 0, "{}", w.stderr);
    let e = read_env(&out_b);
    assert!(e["PGUSER"].starts_with("fg_l_"), "{:?}", redacted(&e));
    assert_eq!(fx.fake.count("create_role"), 2);
    // Nothing the lease handed out is on disk in the data dir, pending or not.
    let mut files = Vec::new();
    all_files(&fx.data_dir(), &mut files);
    for f in files {
        // A file the daemon holds locked (its instance lock) cannot be read here and holds no text.
        let Ok(bytes) = std::fs::read(&f) else {
            continue;
        };
        for needle in [&e["PGPASSWORD"], &e["DATABASE_URL"]] {
            assert!(!contains(&bytes, needle), "{} has a secret", f.display());
        }
    }
    assert!(pending(&fx).is_empty(), "the pending file is gone");
}

#[test]
fn extra_url_vars_are_set() {
    let fx = Fx::new(Opts {
        url_vars: r#"["DATABASE_URL", "TEST_DATABASE_URL"]"#,
        ..Opts::default()
    });
    let out = fx.file("a");
    let r = fx.spawn(fx.run_cmd("env", &out, &fx.proj, &[])).finish();
    assert_eq!(r.code, 0, "{}", r.stderr);
    let e = read_env(&out);
    assert!(
        e["DATABASE_URL"].starts_with("postgres"),
        "{:?}",
        redacted(&e)
    );
    assert!(
        e["DATABASE_URL"] == e["TEST_DATABASE_URL"],
        "the two URL variables differ"
    );
}

#[test]
fn status_shows_the_postgres_line() {
    let fx = Fx::new(Opts::default());
    let (p, _out, pid) = fx.hold("a");
    fx.registered(pid);
    // Through `Proc`, so its exit is bounded and a hung CLI is ended; stdout goes to a file.
    let stdout = fx.file("status.txt");
    let mut c = Command::new(env!("CARGO_BIN_EXE_sync_gate"));
    c.arg("status")
        .env("SYNC_GATE_SOCKET", &fx.socket)
        .stdout(std::fs::File::create(&stdout).unwrap())
        .stderr(Stdio::piped());
    let r = fx.spawn(c).finish();
    assert_eq!(r.code, 0, "{}", r.stderr);
    let text = std::fs::read_to_string(&stdout).unwrap();
    assert!(text.contains("postgres: running, 1 lease(s)"), "{text}");
    fx.stop();
    assert_eq!(p.finish().code, 0);
}

/// The watched file of the projects below.
const SCHEMA: &str = "schema.sql";

/// The argv of a `migrate` that is this binary in `mode` (`migrate:...`).
fn migrate_argv(mode: &str) -> Vec<String> {
    let exe = std::env::current_exe().unwrap();
    let exe = exe.to_str().unwrap();
    [
        exe,
        "child_entry",
        mode,
        "--exact",
        "--nocapture",
        "--test-threads=1",
    ]
    .map(String::from)
    .to_vec()
}

/// A project whose `migrate` runs in `mode`, watching `schema.sql` (written here).
fn migrating(mode: &str, o: Opts) -> Fx {
    let fx = Fx::new(Opts {
        migrate: migrate_argv(mode),
        watch: vec![SCHEMA.into()],
        ..o
    });
    std::fs::write(fx.proj.join(SCHEMA), "create table t ();\n").unwrap();
    fx
}

impl Fx {
    /// What the migrate logged in the project (`run`, `ended`).
    fn migrate_log(&self) -> String {
        std::fs::read_to_string(self.proj.join("migrate.log")).unwrap_or_default()
    }

    fn migrations(&self) -> usize {
        self.migrate_log()
            .lines()
            .filter(|l| l.starts_with("run "))
            .count()
    }

    /// The pid of the (first) migrate.
    fn migrate_pid(&self) -> u64 {
        let log = self.migrate_log();
        let line = log
            .lines()
            .find(|l| l.starts_with("run "))
            .expect("a migrate ran");
        line["run ".len()..].parse().unwrap()
    }

    /// The process the registry records as the holder of the only lease row.
    fn holder_of_the_only_row(&self) -> serde_json::Value {
        let rows = self.registry()["leases"].clone();
        assert_eq!(rows.as_array().map(Vec::len), Some(1), "{rows}");
        rows[0]["command"]["pid"].clone()
    }

    /// `env` with the user's own settings, to the end: its output, variables and runs.
    fn run_mine(&self, name: &str) -> (Out, BTreeMap<String, String>, usize) {
        let out = self.file(name);
        let mut c = self.run_cmd("env", &out, &self.proj, &[]);
        mine(&mut c);
        let r = self.spawn(c).finish();
        (r, read_env(&out), runs(&out))
    }

    /// No lease database or role is left; a template's own may stay.
    fn no_lease_left(&self) -> bool {
        let lease = |n: &String| n.starts_with("fg_l_");
        !self.fake.dbs().keys().any(lease) && !self.fake.roles().keys().any(lease)
    }
}

/// How many times the command whose output file is `out` ran.
fn runs(out: &Path) -> usize {
    std::fs::read_to_string(out.with_extension("runs"))
        .unwrap_or_default()
        .lines()
        .count()
}

#[test]
fn the_first_run_migrates_and_the_command_gets_a_clone() {
    let fx = migrating("migrate:ok", Opts::default());
    let out = fx.file("a");
    let mut c = fx.run_cmd("env", &out, &fx.proj, &[]);
    mine(&mut c);
    let r = fx.spawn(c).finish();
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(!r.stderr.contains("no shared database"), "{}", r.stderr);
    assert_eq!(fx.migrations(), 1, "{}", fx.migrate_log());
    // Written relative to its working directory: it ran in the project.
    let m = read_env(&fx.proj.join("migrate.env"));
    let user = &m["PGUSER"];
    assert!(user.starts_with("fg_l_"), "{user}");
    assert!(
        m["DATABASE_URL"] != "postgres://mine" && m["DATABASE_URL"].contains(user.as_str()),
        "the migration's DATABASE_URL is not its lease's"
    );
    let e = read_env(&out);
    assert!(e["PGUSER"].starts_with("fg_l_"), "{:?}", redacted(&e));
    assert!(&e["PGUSER"] != user, "the command runs on the candidate");
    assert_eq!(runs(&out), 1);
    assert_eq!(fx.fake.count("create_database_from"), 1);
    // The next run gets a clone of the same template, with no migration.
    let out2 = fx.file("b");
    let r = fx.spawn(fx.run_cmd("env", &out2, &fx.proj, &[])).finish();
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(!r.stderr.contains("no shared database"), "{}", r.stderr);
    assert_eq!(fx.migrations(), 1, "{}", fx.migrate_log());
    let e2 = read_env(&out2);
    assert!(e2["PGUSER"].starts_with("fg_l_"), "{:?}", redacted(&e2));
    assert_eq!(fx.fake.count("create_database_from"), 2);
}

#[test]
fn failed_migration_runs_the_command_with_the_original_env() {
    let fx = migrating("migrate:fail", Opts::default());
    let (r, e, n) = fx.run_mine("a");
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(n, 1, "the command runs once");
    assert_original(&e);
    assert!(
        r.stderr.contains("the migration failed (exit 3)"),
        "{}",
        r.stderr
    );
    assert_eq!(r.stderr.matches("no shared database").count(), 1);
    assert_eq!(fx.migrations(), 1);
    // These files failed: the next run neither migrates nor gets a database.
    let (r, e, n) = fx.run_mine("b");
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(n, 1, "the command runs once");
    assert_original(&e);
    assert!(r.stderr.contains("failed before"), "{}", r.stderr);
    assert_eq!(fx.migrations(), 1, "{}", fx.migrate_log());
}

#[test]
fn migration_past_its_deadline_does_not_block_the_command() {
    let fx = migrating(
        "migrate:hang:release",
        Opts {
            migrate_secs: 1,
            ..Opts::default()
        },
    );
    let out = fx.file("a");
    let mut c = fx.run_cmd("env", &out, &fx.proj, &[]);
    mine(&mut c);
    let mut p = fx.spawn(c);
    p.exited(Duration::from_secs(30));
    assert_original(&read_env(&out));
    assert_eq!(runs(&out), 1);
    // Never ended by the CLI: it has not logged its end, and logs it once the file is there.
    assert_eq!(fx.migrations(), 1);
    assert!(!fx.migrate_log().contains("ended"), "{}", fx.migrate_log());
    std::fs::write(fx.proj.join("release"), "").unwrap();
    wait_for("the migration ends by itself", EVENT, || {
        fx.migrate_log().contains("ended")
    });
    let r = p.finish();
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stderr
            .contains("the migration is still running after 1 s"),
        "{}",
        r.stderr
    );
    // Its holder gone, the candidate is dropped.
    wait_for("the candidate is dropped", DB_GONE, || {
        fx.fake.roles().is_empty() && fx.fake.dbs().is_empty()
    });
}

#[test]
fn files_changed_during_the_migration_do_not_become_a_template() {
    let fx = migrating(&format!("migrate:touch:{SCHEMA}"), Opts::default());
    let (r, e, n) = fx.run_mine("a");
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(n, 1, "the command runs once");
    assert_original(&e);
    assert!(
        r.stderr
            .contains("the watched files changed during the migration"),
        "{}",
        r.stderr
    );
    assert_eq!(fx.migrations(), 1);
    assert_eq!(fx.fake.count("template_rename_db"), 0);
}

#[test]
fn files_changed_while_the_clone_is_made_are_not_trusted() {
    let fx = migrating("migrate:ok", Opts::default());
    let r = fx
        .spawn(fx.run_cmd("env", &fx.file("a"), &fx.proj, &[]))
        .finish();
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(!r.stderr.contains("no shared database"), "{}", r.stderr);
    let blocked = fx.fake.block("create_database_from");
    let out = fx.file("b");
    let mut c = fx.run_cmd("env", &out, &fx.proj, &[]);
    mine(&mut c);
    let p = fx.spawn(c);
    assert!(fx.fake.wait_entered("create_database_from", EVENT));
    std::fs::write(fx.proj.join(SCHEMA), "create table u ();\n").unwrap();
    drop(blocked);
    let r = p.finish();
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stderr
            .contains("changed while the database was being made"),
        "{}",
        r.stderr
    );
    assert_eq!(r.stderr.matches("no shared database").count(), 1);
    assert_original(&read_env(&out));
    assert_eq!(runs(&out), 1);
    assert_eq!(fx.migrations(), 1);
    // The clone goes back.
    wait_for("the clone is dropped", DB_GONE, || fx.no_lease_left());
}

#[test]
fn an_unreadable_watch_runs_with_the_original_env() {
    let fx = Fx::new(Opts {
        migrate: migrate_argv("migrate:ok"),
        watch: vec!["missing".into()],
        proxy: true,
        ..Opts::default()
    });
    let proxy = fx.proxy();
    let out = fx.file("a");
    let mut c = fx.run_cmd("env", &out, &fx.proj, &[]);
    mine(&mut c);
    through(&mut c, &fx);
    let r = fx.spawn(c).finish();
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stderr.contains("cannot read the watched path"),
        "{}",
        r.stderr
    );
    assert_original(&read_env(&out));
    assert_eq!(runs(&out), 1);
    assert_eq!(fx.migrations(), 0);
    proxy.wait_idle();
    let kinds: Vec<_> = proxy.seen().iter().map(|s| s.0).collect();
    assert!(kinds.is_empty(), "{kinds:?}");
}

#[test]
fn migrate_output_goes_to_stderr() {
    let fx = migrating("migrate:ok", Opts::default());
    let out = fx.file("a");
    let stdout = fx.file("stdout.txt");
    let mut c = fx.run_cmd("env", &out, &fx.proj, &[]);
    c.stdout(std::fs::File::create(&stdout).unwrap());
    let r = fx.spawn(c).finish();
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(fx.migrations(), 1);
    let text = std::fs::read_to_string(&stdout).unwrap();
    assert!(text.contains(COMMAND_SAYS), "{text}");
    assert!(!text.contains(MIGRATE_SAYS), "{text}");
    assert!(r.stderr.contains(MIGRATE_SAYS), "{}", r.stderr);
}

/// What a failed migration may add past the patience before the command starts: one try of the
/// registration still in flight (0.5 s) and the start of the command, with room.
const PAST_PATIENCE: Duration = Duration::from_secs(2);

/// `env` with the user's own settings, through the proxy; the CLI still running.
fn run_through(fx: &Fx, out: &Path) -> Proc {
    let mut c = fx.run_cmd("env", out, &fx.proj, &[]);
    mine(&mut c);
    through(&mut c, fx);
    fx.spawn(c)
}

#[test]
fn a_refused_registration_is_tried_again_before_the_migration_is_left() {
    // Patience 1 s: the registration at the spawn gives up after two or three refusals, so the
    // way out after the deadline (2 s) meets the rest and is the one accepted.
    let fx = migrating(
        "migrate:hang:release",
        Opts {
            wait_secs: 1,
            migrate_secs: 2,
            proxy: true,
            ..Opts::default()
        },
    );
    fx.proxy().refuse("LeaseHolder", 3);
    let out = fx.file("a");
    let mut p = run_through(&fx, &out);
    assert_eq!(p.exited(EVENT), 0);
    assert_original(&read_env(&out));
    assert_eq!(runs(&out), 1);
    // The live migrate holds its candidate, so the CLI's exit does not drop it.
    assert_eq!(fx.holder_of_the_only_row(), fx.migrate_pid());
    let seen = fx.status().services[0].checks;
    wait_for("a tick after the CLI exited", EVENT, || {
        fx.status().services[0].checks > seen + 1
    });
    assert_eq!(fx.fake.count("drop_role"), 0);
    std::fs::write(fx.proj.join("release"), "").unwrap();
    let r = p.finish();
    assert!(
        r.stderr
            .contains("the migration is still running after 2 s"),
        "{}",
        r.stderr
    );
    assert!(
        !r.stderr.contains("could not be registered"),
        "{}",
        r.stderr
    );
    wait_for("the candidate is dropped", DB_GONE, || {
        fx.fake.roles().is_empty() && fx.fake.dbs().is_empty()
    });
}

#[test]
fn a_migration_that_cannot_be_registered_says_so() {
    let fx = migrating(
        "migrate:hang:release",
        Opts {
            wait_secs: 1,
            migrate_secs: 1,
            proxy: true,
            ..Opts::default()
        },
    );
    fx.proxy().refuse("LeaseHolder", u32::MAX);
    let out = fx.file("a");
    let mut p = run_through(&fx, &out);
    assert_eq!(p.exited(EVENT), 0);
    assert_original(&read_env(&out));
    assert_eq!(runs(&out), 1);
    std::fs::write(fx.proj.join("release"), "").unwrap();
    let r = p.finish();
    assert!(r.stderr.contains("could not be registered"), "{}", r.stderr);
    assert_eq!(r.stderr.matches("no shared database").count(), 1);
}

#[test]
fn a_failed_migration_keeps_to_the_patience_when_the_daemon_does_not_answer() {
    let fx = migrating(
        "migrate:fail",
        Opts {
            wait_secs: 1,
            proxy: true,
            ..Opts::default()
        },
    );
    fx.proxy()
        .stall(&["LeaseHolder", "TemplateReady", "ReleaseLease"]);
    let out = fx.file("a");
    let p = run_through(&fx, &out);
    wait_for("the migration ends", EVENT, || {
        fx.migrate_log().contains("ended")
    });
    let limit = Duration::from_secs(1) + PAST_PATIENCE;
    wait_for(
        &format!("the command starts within {limit:?} of the migration's end"),
        limit,
        || out.exists(),
    );
    let r = p.finish();
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stderr.contains("the migration failed (exit 3)"),
        "{}",
        r.stderr
    );
    assert_original(&read_env(&out));
}

#[test]
fn an_unanswered_registration_does_not_hold_the_migration_past_its_deadline() {
    // A long patience exposes a registration that waits past the migrate's own deadline: the
    // command may start after the deadline (1 s) plus one patience (10 s), never two patiences.
    let fx = migrating(
        "migrate:hang:release",
        Opts {
            wait_secs: 10,
            migrate_secs: 1,
            proxy: true,
            ..Opts::default()
        },
    );
    fx.proxy().stall(&["LeaseHolder"]);
    let out = fx.file("a");
    let mut p = run_through(&fx, &out);
    wait_for("the migration starts", EVENT, || fx.migrations() == 1);
    let limit = Duration::from_secs(1 + 10) + PAST_PATIENCE;
    wait_for(
        &format!("the command starts within {limit:?} of the migration's start"),
        limit,
        || out.exists(),
    );
    assert_eq!(p.exited(EVENT), 0);
    assert_original(&read_env(&out));
    std::fs::write(fx.proj.join("release"), "").unwrap();
    let r = p.finish();
    assert!(r.stderr.contains("could not be registered"), "{}", r.stderr);
}

#[test]
fn an_interrupt_waits_for_the_migration_to_be_registered() {
    let fx = migrating(
        "migrate:hang:release",
        Opts {
            proxy: true,
            ..Opts::default()
        },
    );
    let proxy = fx.proxy();
    // Every registration waits 5 s at the proxy from the first one; the interrupt comes at 3 s,
    // once the migrate runs and while its registration is unanswered.
    proxy.gate("LeaseHolder", Duration::from_secs(5));
    let out = fx.file("a");
    let mut c = fx.run_cmd("env", &out, &fx.proj, &[]);
    c.env("SYNC_GATE_TEST_INTERRUPT_AFTER_MS", "3000");
    through(&mut c, &fx);
    let mut p = fx.spawn(c);
    assert_eq!(p.exited(EVENT), 130);
    assert_eq!(runs(&out), 0, "the command never ran");
    assert_eq!(fx.migrations(), 1);
    let answered = proxy.first("LeaseHolder", true);
    let finished = proxy.first("Finished", false);
    assert!(
        answered.is_some() && finished.is_some() && answered < finished,
        "the CLI ended before its migrate was registered: {answered:?} {finished:?}"
    );
    assert_eq!(fx.holder_of_the_only_row(), fx.migrate_pid());
    std::fs::write(fx.proj.join("release"), "").unwrap();
    p.finish();
    wait_for("the candidate is dropped", DB_GONE, || {
        fx.fake.roles().is_empty() && fx.fake.dbs().is_empty()
    });
}

#[test]
fn ctrl_c_during_the_migration_does_not_fail_the_key() {
    let fx = migrating(
        "migrate:hang:release",
        Opts {
            proxy: true,
            ..Opts::default()
        },
    );
    let out = fx.file("a");
    let mut c = fx.run_cmd("env", &out, &fx.proj, &[]);
    // The interrupt comes while the migrate hangs; the migrate itself is not signalled.
    c.env("SYNC_GATE_TEST_INTERRUPT_AFTER_MS", "2000");
    through(&mut c, &fx);
    let mut p = fx.spawn(c);
    assert_eq!(p.exited(EVENT), 130);
    assert_eq!(runs(&out), 0, "the command never ran");
    std::fs::write(fx.proj.join("release"), "").unwrap();
    let r = p.finish();
    assert!(
        r.stderr.contains("the migration was interrupted"),
        "{}",
        r.stderr
    );
    let templates = fx.data_dir().join("pg").join("17").join("templates.json");
    wait_for("the key's row is gone", EVENT, || {
        std::fs::read_to_string(&templates).is_ok_and(|t| {
            serde_json::from_str::<serde_json::Value>(&t)
                .is_ok_and(|v| v["templates"].as_array().is_some_and(Vec::is_empty))
        })
    });
    wait_for("the candidate is dropped", DB_GONE, || {
        fx.fake.roles().is_empty() && fx.fake.dbs().is_empty()
    });
    let again = fx.file("b");
    let mut p = run_through(&fx, &again);
    assert_eq!(p.exited(EVENT), 0);
    assert_eq!(fx.migrations(), 2, "the next run migrates again");
    p.finish();
}

/// The key's row is gone from `templates.json`.
fn key_is_free(fx: &Fx) -> bool {
    let templates = fx.data_dir().join("pg").join("17").join("templates.json");
    std::fs::read_to_string(templates).is_ok_and(|t| {
        serde_json::from_str::<serde_json::Value>(&t)
            .is_ok_and(|v| v["templates"].as_array().is_some_and(Vec::is_empty))
    })
}

#[test]
fn a_late_handler_cannot_end_the_cli_before_the_interrupted_migration_is_reported() {
    let fx = migrating(
        "migrate:hang:release",
        Opts {
            proxy: true,
            ..Opts::default()
        },
    );
    let proxy = fx.proxy();
    // Order forced: the handler has raised the flag and waits before the phase lock (marker);
    // the CLI's report reaches the proxy and is held; the test then lets the handler take the
    // lock (go). The handler says what it found: a phase that defers the exit (`.deferred`) or
    // one that ends the CLI (`.exits`); the proxy answers only after either appears. Phase
    // kept: `.deferred`. Phase restored early: `.exits`, the regression.
    let marker = fx.file("handler-before-the-lock");
    let deferred = fx.file("handler-before-the-lock.deferred");
    let exits = fx.file("handler-before-the-lock.exits");
    let go = fx.file("handler-go");
    proxy.gate_after_file("TemplateReady", vec![deferred.clone(), exits.clone()]);
    let out = fx.file("a");
    let mut c = fx.run_cmd("env", &out, &fx.proj, &[]);
    c.env("SYNC_GATE_TEST_INTERRUPT_AFTER_MS", "2000")
        .env("SYNC_GATE_TEST_HANDLER_MARK", &marker)
        .env("SYNC_GATE_TEST_HANDLER_GO", &go);
    through(&mut c, &fx);
    let mut p = fx.spawn(c);
    wait_file(&marker, EVENT.max(Duration::from_secs(10)));
    wait_for("the report is held at the proxy", EVENT, || {
        proxy.first("TemplateReady", false).is_some()
    });
    assert!(proxy.first("TemplateReady", true).is_none());
    std::fs::write(&go, "").unwrap();
    wait_for("the handler looked at the phase", EVENT, || {
        deferred.exists() || exits.exists()
    });
    assert!(
        !exits.exists(),
        "the handler would have ended the CLI while the report was pending"
    );
    assert!(deferred.exists());
    assert_eq!(p.exited(EVENT), 130);
    assert_eq!(runs(&out), 0, "the command never ran");
    assert!(
        proxy.first("TemplateReady", true).is_some(),
        "the CLI ended before its report was answered"
    );
    wait_for("the key's row is gone", EVENT, || key_is_free(&fx));
    std::fs::write(fx.proj.join("release"), "").unwrap();
    p.finish();
    wait_for("the candidate is dropped", DB_GONE, || {
        fx.fake.roles().is_empty() && fx.fake.dbs().is_empty()
    });
}

#[test]
fn ctrl_c_during_the_migration_of_a_light_command_does_not_run_it() {
    let fx = migrating(
        "migrate:hang:release",
        Opts {
            proxy: true,
            ..Opts::default()
        },
    );
    let out = fx.file("a");
    let mut c = fx.light_cmd("env", &out, &fx.proj);
    c.env("SYNC_GATE_TEST_INTERRUPT_AFTER_MS", "2000");
    through(&mut c, &fx);
    let mut p = fx.spawn(c);
    assert_eq!(p.exited(EVENT), 130);
    assert_eq!(runs(&out), 0, "the command never ran");
    assert_eq!(fx.admitted(), 0, "a light command is never admitted");
    wait_for("the key's row is gone", EVENT, || key_is_free(&fx));
    std::fs::write(fx.proj.join("release"), "").unwrap();
    p.finish();
    wait_for("the candidate is dropped", DB_GONE, || {
        fx.fake.roles().is_empty() && fx.fake.dbs().is_empty()
    });
}

// ---- through the shims: the program arrives as its resolved path ----

fn leased(e: &BTreeMap<String, String>) -> bool {
    e.get("PGUSER").is_some_and(|u| u.starts_with("fg_l_"))
}

#[test]
fn shimlease_a_project_whose_commands_name_the_program_is_selected() {
    let fx = Fx::new(Opts {
        commands: r#"["pytest child_entry"]"#,
        ..Opts::default()
    });
    fx.install_shims();
    let out = fx.file("a");
    let r = fx.spawn(fx.shim_cmd("env", &out, &fx.proj)).finish();
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(fx.admitted(), 1, "through the queue");
    let e = read_env(&out);
    assert!(leased(&e), "no database: {:?}", redacted(&e));
}

#[test]
fn shimlease_a_nested_heavy_command_keeps_the_jobs_database() {
    let fx = Fx::new(Opts::default());
    fx.install_shims();
    let out = fx.file("a");
    let r = fx.spawn(fx.shim_cmd("nest", &out, &fx.proj)).finish();
    assert_eq!(r.code, 0, "{}", r.stderr);
    let (outer, inner) = (read_env(&out), read_env(&out.with_extension("nested")));
    assert!(leased(&outer), "{:?}", redacted(&outer));
    assert!(
        inner.get("DATABASE_URL") == outer.get("DATABASE_URL"),
        "the nested command got another database: {:?}",
        redacted(&inner)
    );
    assert_eq!(fx.fake.count("create_role"), 1);
    assert_eq!(fx.admitted(), 1, "the nested command asked for no slot");
}

#[test]
fn shimlease_a_migrate_through_a_shim_runs_inside_the_admission() {
    // Room for one job: a migrate that asked for its own slot would wait behind its own job.
    let fx = Fx::new(Opts {
        one_job: true,
        migrate_shim: Some("migrate:ok"),
        watch: vec![SCHEMA.into()],
        migrate_secs: 20,
        ..Opts::default()
    });
    std::fs::write(fx.proj.join(SCHEMA), "create table t ();\n").unwrap();
    fx.install_shims();
    let out = fx.file("a");
    let r = fx.spawn(fx.shim_cmd("env", &out, &fx.proj)).finish();
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(fx.migrations(), 1, "{}", fx.migrate_log());
    assert_eq!(fx.admitted(), 1, "the migrate asked for no slot");
    let m = read_env(&fx.proj.join("migrate.env"));
    assert!(leased(&m), "the migrate ran without its candidate");
    let e = read_env(&out);
    assert!(leased(&e), "{:?}", redacted(&e));
    assert!(e["PGUSER"] != m["PGUSER"], "the command runs on a clone");
    assert_eq!(fx.fake.count("create_database_from"), 1);
}
