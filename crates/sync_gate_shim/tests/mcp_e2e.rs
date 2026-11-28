//! End to end of the MCP hub with real processes: `sync_gate_mcp` relays (this crate's binary)
//! against a daemon running in a thread of the test (`sync_gated::run_with`, real launcher).
//!
//! The MCP servers are this test binary re-executed in a child mode (`child_entry`, driven by
//! `SYNC_GATE_TEST_CHILD`): `mcp-legacy` needs `initialize`; `mcp-stateless` answers
//! `server/discover` and rejects `initialize`; `mcp-unsupported-first` and `mcp-reject-init-first`
//! misbehave in their first process only. Each server appends its pid to the file named by
//! `SYNC_GATE_TEST_PIDS` and `initialize <pid>` per `initialize` it receives to
//! `SYNC_GATE_TEST_INITS`. `daemon` runs the daemon as its own process; `hung` never ends.
//!
//! `measure_hub_memory` is not a test: it does nothing unless `SYNC_GATE_MEASURE_MEMORY` is set.

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};
use sync_gate_core::{Config, MIB, MachineSnapshot, McpStatus, Request, Response, StatusReport};
use sync_gated::{DaemonHandle, Measure, OsControl};

/// Hard limit of every test, counted from the creation of its sandbox.
const LIMIT: Duration = Duration::from_secs(60);
/// The watchdog fires this long after `LIMIT`, so the test's own checks fail first.
const WATCHDOG_SLACK: Duration = Duration::from_secs(30);
/// A server still running after this ends itself: the last resort if a test lost track of it.
const SERVER_LIFETIME: Duration = Duration::from_secs(150);
const CANARY: &str = "s3cr3t-canary";
static COUNTER: AtomicU32 = AtomicU32::new(0);

/// Re-executed as an MCP server (`mcp-legacy`, `mcp-stateless`) or, for the memory measurement,
/// as the daemon (`daemon`). Inert unless `SYNC_GATE_TEST_CHILD` is set.
#[test]
fn child_entry() {
    let Ok(mode) = std::env::var("SYNC_GATE_TEST_CHILD") else {
        return;
    };
    match mode.as_str() {
        "mcp-legacy" => serve(false, ""),
        "mcp-stateless" => serve(true, ""),
        "mcp-unsupported-first" => serve(false, "unsupported"),
        "mcp-reject-init-first" => serve(false, "reject-init"),
        "daemon" => daemon(),
        "hung" => {
            let _w = Watchdog::start("hung", Duration::from_millis(100), abort_with);
            loop {
                std::thread::park();
            }
        }
        other => panic!("unknown child mode {other}"),
    }
}

/// Appends one line to the file named by `var`, in one write so concurrent servers never mix.
fn append(var: &str, line: &str) {
    let path = std::env::var(var).unwrap();
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    f.write_all(format!("{line}\n").as_bytes()).unwrap();
}

/// `first`: how the first server started for the key (the hub's) misbehaves: `unsupported`
/// offers no version the hub speaks; `reject-init` is a legacy server that rejects `initialize`.
fn serve(stateless: bool, first: &str) -> ! {
    std::thread::spawn(|| {
        std::thread::sleep(SERVER_LIFETIME);
        std::process::exit(3);
    });
    let pid = std::process::id();
    let mut out = std::io::stdout().lock();
    // The harness printed `test child_entry ... ` without a newline.
    writeln!(out).unwrap();
    out.flush().unwrap();
    append("SYNC_GATE_TEST_PIDS", &pid.to_string());
    let is_first = std::fs::read_to_string(std::env::var("SYNC_GATE_TEST_PIDS").unwrap())
        .is_ok_and(|p| p.lines().next() == Some(&pid.to_string()));
    let first = if is_first { first } else { "" };
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let Ok(v) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        // Notifications and responses get no reply.
        let (Some(id), Some(method)) = (v.get("id"), v["method"].as_str()) else {
            continue;
        };
        let mut reply = match method {
            "initialize" => {
                append("SYNC_GATE_TEST_INITS", &format!("initialize {pid}"));
                if stateless || first == "reject-init" {
                    json!({"error":{"code":-32601,"message":"initialize is not supported"}})
                } else {
                    json!({"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},
                        "serverInfo":{"name":"fake-legacy","version":"1"}}})
                }
            }
            // A modern server that offers no version the hub speaks: the hub gives up on it.
            "server/discover" if first == "unsupported" => {
                json!({"result":{"resultType":"complete","supportedVersions":["2099-01-01"],
                    "capabilities":{"tools":{}}}})
            }
            "server/discover" if stateless => {
                json!({"result":{"resultType":"complete","supportedVersions":["2026-07-28"],
                    "capabilities":{"tools":{}},
                    "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"fake-stateless","version":"1"}}}})
            }
            "server/discover" => json!({"error":{"code":-32601,"message":"method not found"}}),
            // Says whether the secret arrived, never what it is.
            _ => json!({"result":{"pid":pid,"has_token":std::env::var_os("DOCS_TOKEN").is_some(),
                "mark":v["params"]["arguments"]["mark"]}}),
        };
        reply["jsonrpc"] = json!("2.0");
        reply["id"] = id.clone();
        writeln!(out, "{reply}").unwrap();
        out.flush().unwrap();
    }
    std::process::exit(0)
}

/// The daemon as its own process, as `sync_gated` runs it (real probe, control and launcher), on
/// the sandbox's socket and data dir. Shuts down cleanly when its stdin closes.
fn daemon() -> ! {
    let var = |n: &str| std::env::var(n).unwrap();
    let cfg =
        Config::from_toml(&std::fs::read_to_string(var("SYNC_GATE_CONFIG")).unwrap()).unwrap();
    let d = sync_gated::run_with(
        cfg,
        &var("SYNC_GATE_SOCKET"),
        sync_gate_probe::Probe::new(),
        OsControl,
        Some(PathBuf::from(var("SYNC_GATE_DATA_DIR"))),
        Arc::new(sync_gated::OsLauncher::default()),
    )
    .unwrap();
    let _ = std::io::stdin().read_to_end(&mut Vec::new());
    d.shutdown();
    std::process::exit(0)
}

/// Plenty of free memory, whatever the machine has: pool decisions never depend on the host.
struct Roomy;

impl Measure for Roomy {
    fn snapshot(&mut self) -> MachineSnapshot {
        MachineSnapshot {
            total: 16384 * MIB,
            available: 8192 * MIB,
            reclaimable: 0,
            swap_used: 0,
            swap_total: 0,
            vram: None,
        }
    }
    fn tree_rss(&mut self, _pid: u32) -> u64 {
        0
    }
    fn start_time(&mut self, _pid: u32) -> Option<u64> {
        None
    }
}

/// A TOML basic string: a JSON string literal is one.
fn quote(p: &Path) -> String {
    serde_json::to_string(&p.to_string_lossy()).unwrap()
}

/// One test's world: its own socket name, data dir and `config.toml`, a deadline, and the
/// daemon (in a thread of this process). Dropping it shuts the daemon down cleanly, which stops
/// every server the hub started, then removes the directory.
struct Sandbox {
    socket: String,
    dir: PathBuf,
    cfg: Config,
    until: Instant,
    daemon: Option<DaemonHandle>,
    #[allow(dead_code)] // held: dropping it ends the watchdog quietly
    _watchdog: Watchdog,
}

impl Sandbox {
    /// `servers`: (name, child mode, `mode` value, extra lines of the `[mcp.<name>]` table).
    fn new(servers: &[(&str, &str, &str, &str)]) -> Sandbox {
        let id = format!(
            "sync_gate_mcp-e2e-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        let dir = std::env::temp_dir().join(&id);
        std::fs::create_dir_all(dir.join("data")).unwrap();
        let socket = if cfg!(windows) {
            id
        } else {
            dir.join("s.sock").to_string_lossy().into_owned()
        };
        let exe = std::env::current_exe().unwrap();
        let mut toml = String::from("tick_ms = 100\n");
        for (name, child, mode, extra) in servers {
            toml += &format!(
                "[mcp.{name}]\ncommand = {}\n\
                 args = [\"child_entry\", \"--exact\", \"--nocapture\", \"--test-threads=1\"]\n\
                 mode = \"{mode}\"\n{extra}\n[mcp.{name}.env]\nSYNC_GATE_TEST_CHILD = \"{child}\"\n\
                 SYNC_GATE_TEST_PIDS = {}\nSYNC_GATE_TEST_INITS = {}\n",
                quote(&exe),
                quote(&dir.join(format!("{name}.pids"))),
                quote(&dir.join(format!("{name}.inits"))),
            );
        }
        std::fs::write(dir.join("config.toml"), &toml).unwrap();
        Sandbox {
            socket,
            cfg: Config::from_toml(&toml).unwrap(),
            dir,
            until: Instant::now() + LIMIT,
            daemon: None,
            _watchdog: Watchdog::start(
                std::thread::current().name().unwrap_or("?"),
                LIMIT + WATCHDOG_SLACK,
                abort_with,
            ),
        }
    }

    fn data_dir(&self) -> PathBuf {
        self.dir.join("data")
    }

    fn start_daemon(&mut self) {
        let launcher = Arc::new(sync_gated::OsLauncher::default());
        let d = sync_gated::run_with(
            self.cfg.clone(),
            &self.socket,
            Roomy,
            OsControl,
            Some(self.data_dir()),
            launcher,
        )
        .unwrap();
        self.daemon = Some(d);
    }

    /// Clean daemon shutdown (stops the hub's servers).
    fn shutdown(&mut self) {
        if let Some(d) = self.daemon.take() {
            d.shutdown();
        }
    }

    /// `sync_gate_mcp <server>` pointed at this sandbox, with `env` added to its environment.
    fn relay(&self, server: &str, env: &[(&str, &str)]) -> Relay {
        let mut c = Command::new(env!("CARGO_BIN_EXE_sync_gate_mcp"));
        c.arg(server)
            .env("SYNC_GATE_CONFIG", self.dir.join("config.toml"))
            .env("SYNC_GATE_SOCKET", &self.socket)
            .env("SYNC_GATE_DATA_DIR", self.data_dir())
            .envs(env.iter().copied())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        Relay::spawn(c, self.until)
    }

    fn status(&self) -> StatusReport {
        match sync_gate::client::call_at(&self.socket, &Request::Status) {
            Ok(Response::Status(s)) => s,
            other => panic!("status failed: {other:?}"),
        }
    }

    fn row(&self, server: &str) -> McpStatus {
        let st = self.status();
        st.mcp
            .into_iter()
            .find(|r| r.server == server)
            .unwrap_or_else(|| panic!("no status row for {server}"))
    }

    fn lines(&self, file: String) -> Vec<String> {
        std::fs::read_to_string(self.dir.join(file))
            .unwrap_or_default()
            .lines()
            .map(String::from)
            .collect()
    }

    /// Pids of the servers started for `server`, in start order.
    fn pids(&self, server: &str) -> Vec<u64> {
        self.lines(format!("{server}.pids"))
            .iter()
            .map(|l| l.parse().unwrap())
            .collect()
    }

    /// `initialize` requests the servers of `server` received.
    fn inits(&self, server: &str) -> usize {
        self.lines(format!("{server}.inits")).len()
    }

    /// `initialize` requests the server with this pid received.
    fn inits_of(&self, server: &str, pid: u64) -> usize {
        let line = format!("initialize {pid}");
        self.lines(format!("{server}.inits"))
            .iter()
            .filter(|l| **l == line)
            .count()
    }

    fn wait_for(&self, what: &str, mut ok: impl FnMut() -> bool) {
        while !ok() {
            assert!(Instant::now() < self.until, "timed out: {what}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Every file under the sandbox (config, data dir, pid files) without the canary.
    fn assert_no_canary_on_disk(&self) {
        assert_no_canary_under(&self.dir);
    }
}

/// A file that cannot be read cannot be cleared either, so it fails the scan instead of being skipped.
fn assert_no_canary_under(root: &Path) {
    let mut dirs = vec![root.to_path_buf()];
    while let Some(d) = dirs.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                dirs.push(p);
            } else if !p.is_file() {
                // a socket (Unix) holds no data and cannot be read
            } else if p.file_name().is_some_and(|n| n == "sync_gated.lock") {
                // the daemon holds a byte-range lock on it while it runs; it stores no data
            } else {
                let bytes = std::fs::read(&p)
                    .unwrap_or_else(|e| panic!("cannot read {} to scan it: {e}", p.display()));
                let text = String::from_utf8_lossy(&bytes);
                assert!(!text.contains(CANARY), "secret found in {}", p.display());
            }
        }
    }
}

/// What the hub says about itself (status notes, decisions, rows), what the relay prints and
/// what the daemon prints.
fn assert_no_canary_in_hub_output(status: &StatusReport, relay_stderr: &str, daemon_stderr: &str) {
    let status = serde_json::to_string(status).unwrap();
    assert!(
        !status.contains(CANARY),
        "secret in the hub status: {status}"
    );
    assert!(
        !relay_stderr.contains(CANARY),
        "secret in the relay stderr: {relay_stderr}"
    );
    assert!(
        !daemon_stderr.contains(CANARY),
        "secret in the daemon stderr: {daemon_stderr}"
    );
}

/// Collects what `pipe` yields; the receiver disconnects once the pipe has ended, and gets the
/// error first if a read failed.
fn capture(
    mut pipe: impl Read + Send + 'static,
) -> (Arc<Mutex<String>>, mpsc::Receiver<std::io::Error>) {
    let text = Arc::new(Mutex::new(String::new()));
    let (t, (ended, done)) = (text.clone(), mpsc::channel());
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match pipe.read(&mut buf) {
                Ok(0) => return,
                Ok(n) => t
                    .lock()
                    .unwrap()
                    .push_str(&String::from_utf8_lossy(&buf[..n])),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    let _ = ended.send(e);
                    return;
                }
            }
        }
    });
    (text, done)
}

/// Waits (until `by`) for a pipe [`capture`] reads to end; a read error is no end.
fn wait_end(done: &mpsc::Receiver<std::io::Error>, by: Instant) {
    match done.recv_timeout(by.saturating_duration_since(Instant::now())) {
        Err(mpsc::RecvTimeoutError::Disconnected) => {}
        Ok(e) => panic!("reading stderr failed: {e}"),
        Err(mpsc::RecvTimeoutError::Timeout) => panic!("stderr never ended"),
    }
}

/// A pipe that fails mid-way: its capture must not pass for one read to the end.
#[test]
#[should_panic(expected = "reading stderr failed")]
fn a_stderr_read_error_is_not_taken_for_its_end() {
    struct Broken(bool);
    impl Read for Broken {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if std::mem::replace(&mut self.0, true) {
                return Err(std::io::Error::other("broken pipe"));
            }
            buf[0] = b'x';
            Ok(1)
        }
    }
    let (_, done) = capture(Broken(false));
    wait_end(&done, Instant::now() + Duration::from_secs(5));
}

/// What a watchdog does when it fires: the message, then the whole test binary ends.
fn abort_with(message: String) {
    eprintln!("{message}");
    std::process::abort()
}

/// Aborts the whole test binary, with a message naming the test, when its owner outlives `limit`.
/// Independent of the test's own deadline checks: a test stuck in a blocking call still ends.
struct Watchdog(#[allow(dead_code)] mpsc::Sender<()>);

impl Watchdog {
    fn start(test: &str, limit: Duration, fire: impl FnOnce(String) + Send + 'static) -> Watchdog {
        let (tx, rx) = mpsc::channel::<()>();
        let test = test.to_string();
        std::thread::spawn(move || {
            // Dropping the sender (the test finished) disconnects: nothing to report.
            if rx.recv_timeout(limit) == Err(mpsc::RecvTimeoutError::Timeout) {
                fire(format!(
                    "watchdog: test {test} still running after {limit:?}"
                ));
            }
        });
        Watchdog(tx)
    }
}

#[test]
#[should_panic(expected = "cannot read")]
fn the_canary_scan_fails_on_an_unreadable_file() {
    let dir = std::env::temp_dir().join(format!(
        "sync_gate_mcp-scan-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("locked");
    std::fs::write(&file, "x").unwrap();
    #[cfg(windows)]
    let _hold = {
        use std::os::windows::fs::OpenOptionsExt;
        // share mode 0: nobody else can open it while this handle lives
        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&file)
            .unwrap()
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).unwrap();
    }
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(
                    self.0.join("locked"),
                    std::fs::Permissions::from_mode(0o600),
                );
            }
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _c = Cleanup(dir.clone());
    assert_no_canary_under(&dir);
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        self.shutdown();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A running `sync_gate_mcp` process. Dropping it (a failed test) kills it: its direct server, if
/// any, then sees its stdin close and exits; a hub session is dropped by the daemon.
struct Relay {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: mpsc::Receiver<Value>,
    seen: Vec<Value>,
    err: Arc<Mutex<String>>,
    err_done: Option<mpsc::Receiver<std::io::Error>>,
    until: Instant,
}

impl Relay {
    fn spawn(mut c: Command, until: Instant) -> Relay {
        let mut child = c.spawn().unwrap();
        let stdin = child.stdin.take();
        let out = child.stdout.take().unwrap();
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines() {
                let Ok(line) = line else { break };
                // A directly started server is this test binary: its harness lines are not JSON.
                if let Ok(v) = serde_json::from_str::<Value>(&line)
                    && tx.send(v).is_err()
                {
                    break;
                }
            }
        });
        let (err, err_done) = capture(child.stderr.take().unwrap());
        Relay {
            child,
            stdin,
            lines,
            seen: Vec::new(),
            err,
            err_done: Some(err_done),
            until,
        }
    }

    fn send(&mut self, v: Value) {
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{v}").unwrap();
        stdin.flush().unwrap();
    }

    fn reply(&mut self, id: i64) -> Value {
        self.reply_by(id, self.until)
    }

    /// The response with this id; panics if it has not arrived by `by`.
    fn reply_by(&mut self, id: i64, by: Instant) -> Value {
        loop {
            let found = self
                .seen
                .iter()
                .position(|v| v["id"] == id && v.get("method").is_none());
            if let Some(i) = found {
                return self.seen.remove(i);
            }
            match self
                .lines
                .recv_timeout(by.saturating_duration_since(Instant::now()))
            {
                Ok(v) => self.seen.push(v),
                Err(_) => panic!("no reply for id {id} in time; stderr: {}", self.stderr()),
            }
        }
    }

    /// `initialize` (id 0) and `notifications/initialized`; returns the initialize result.
    fn open(&mut self) -> Value {
        self.send(initialize());
        let r = result(self.reply(0));
        self.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
        r
    }

    /// A `tools/call` with this id; returns its result.
    fn call(&mut self, id: i64) -> Value {
        self.send(tools_call(id));
        result(self.reply(id))
    }

    fn stderr(&self) -> String {
        self.err.lock().unwrap().clone()
    }

    /// Like [`Relay::close`], then reads its stderr to the end: what it printed while exiting too.
    fn close_with_stderr(mut self) -> (i32, String) {
        let (done, err, until) = (self.err_done.take().unwrap(), self.err.clone(), self.until);
        let code = self.close();
        wait_end(&done, until);
        let text = err.lock().unwrap().clone();
        (code, text)
    }

    /// Closes the client's stdin and waits for the relay to exit; returns its exit code.
    fn close(mut self) -> i32 {
        self.stdin = None;
        loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                return s.code().unwrap_or(-1);
            }
            assert!(Instant::now() < self.until, "relay did not exit");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stdin = None;
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill(); // tests only: the relay is this test's own child
        }
        let _ = self.child.wait();
    }
}

fn initialize() -> Value {
    json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25",
        "capabilities":{},"clientInfo":{"name":"mcp-e2e","version":"1"}}})
}

fn tools_call(id: i64) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"pid","arguments":{}}})
}

fn tools_call_marked(id: i64, mark: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
        "params":{"name":"pid","arguments":{"mark":mark}}})
}

fn result(v: Value) -> Value {
    assert!(v.get("result").is_some(), "expected a result: {v}");
    v["result"].clone()
}

/// Ends a server process the test identified through its pid file (test code only).
fn terminate(pid: u64) {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::{
            Foundation::CloseHandle,
            System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess},
        };
        let handle = OpenProcess(PROCESS_TERMINATE, 0, pid as u32);
        assert!(!handle.is_null(), "cannot open server {pid}");
        TerminateProcess(handle, 1);
        CloseHandle(handle);
    }
    #[cfg(unix)]
    {
        use nix::sys::signal::{Signal, kill};
        kill(nix::unistd::Pid::from_raw(pid as i32), Signal::SIGKILL).unwrap();
    }
}

fn shared(child: &str) -> Sandbox {
    let mut sb = Sandbox::new(&[("docs", child, "shared", "")]);
    sb.start_daemon();
    sb
}

/// Ten relays for one shared server, all asking at once; returns the sandbox for the counts.
fn ten_sessions(child: &str) -> Sandbox {
    let sb = shared(child);
    let mut relays: Vec<Relay> = (0..10).map(|_| sb.relay("docs", &[])).collect();
    for r in &mut relays {
        r.send(initialize());
    }
    for i in 0..relays.len() {
        let first = relays[i].reply(0);
        if first.get("result").is_none() {
            let errs: Vec<String> = relays.iter().map(|r| r.stderr()).collect();
            let st = sb.status();
            panic!(
                "relay {i}: {first}\nstderr of every relay: {errs:?}\ndecisions: {:?}\nrows: {:?}",
                st.decisions, st.mcp
            );
        }
        let r = &mut relays[i];
        r.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
        r.send(tools_call(1));
    }
    let pids: Vec<Value> = relays
        .iter_mut()
        .map(|r| result(r.reply(1))["pid"].clone())
        .collect();
    let server = sb.pids("docs");
    let errs: Vec<String> = relays.iter().map(|r| r.stderr()).collect();
    assert_eq!(
        server.len(),
        1,
        "server pids: {server:?}; stderr of every relay: {errs:?}"
    );
    assert!(pids.iter().all(|p| *p == server[0]), "{pids:?}");
    let row = sb.row("docs");
    assert_eq!((row.instances, row.clients), (1, 10), "{row:?}");
    for r in relays {
        assert!(r.stderr().is_empty(), "{}", r.stderr());
        assert_eq!(r.close(), 0);
    }
    sb
}

#[test]
fn ten_sessions_one_legacy_server_process() {
    let sb = ten_sessions("mcp-legacy");
    assert_eq!(sb.inits("docs"), 1);
}

#[test]
fn ten_sessions_one_stateless_server_process() {
    let sb = ten_sessions("mcp-stateless");
    assert_eq!(sb.inits("docs"), 0);
}

#[test]
fn killing_the_server_restarts_it_and_sessions_continue() {
    let sb = shared("mcp-legacy");
    let mut r = sb.relay("docs", &[]);
    r.open();
    let first = r.call(1)["pid"].as_u64().unwrap();
    assert_eq!(sb.pids("docs"), [first]);
    terminate(first);
    let killed = Instant::now();
    sb.wait_for("the server was not started again", || {
        sb.pids("docs").len() == 2
    });
    r.send(tools_call(2));
    let second = result(r.reply_by(2, killed + Duration::from_secs(30)))["pid"].clone();
    assert_eq!(second, sb.pids("docs")[1]);
    let st = sb.status();
    let row = st.mcp.iter().find(|m| m.server == "docs").unwrap();
    assert_eq!(row.restarts, 1, "{row:?}");
    assert!(
        st.decisions
            .iter()
            .any(|d| d.contains("mcp docs: restarted")),
        "{:?}",
        st.decisions
    );
    assert!(r.stderr().is_empty(), "{}", r.stderr());
    assert_eq!(r.close(), 0);
}

#[test]
fn daemon_abort_mid_session_falls_back_to_direct() {
    let mut sb = shared("mcp-legacy");
    let mut r = sb.relay("docs", &[]);
    r.open();
    let hub_pid = r.call(1)["pid"].clone();
    sb.daemon.take().unwrap().abort();
    sb.wait_for("the relay never noticed the hub loss", || {
        r.stderr().contains("hub connection lost")
    });
    let direct = r.call(2)["pid"].clone();
    let pids = sb.pids("docs");
    assert_eq!(pids.len(), 2, "{pids:?}");
    assert_eq!(direct, pids[1]);
    assert_ne!(direct, hub_pid);
    assert_eq!(r.close(), 0);
}

/// The hub starts servers with the daemon's PATH: a command found only through the session's
/// PATH cannot start there, so the hub lets go of the session and the relay runs it directly.
#[test]
fn server_the_daemon_cannot_find_runs_per_session() {
    let mut sb = Sandbox::new(&[("docs", "mcp-legacy", "shared", "")]);
    let name = format!("sync_gate-e2e-fake-mcp-{}", std::process::id());
    let bin = sb.dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let exe = std::env::current_exe().unwrap();
    std::fs::copy(
        &exe,
        bin.join(format!("{name}{}", std::env::consts::EXE_SUFFIX)),
    )
    .unwrap();
    let file = sb.dir.join("config.toml");
    let full = format!("command = {}", quote(&exe));
    let toml = std::fs::read_to_string(&file).unwrap();
    assert!(toml.contains(&full), "{toml}");
    let toml = toml.replace(&full, &format!("command = \"{name}\""));
    std::fs::write(&file, &toml).unwrap();
    sb.cfg = Config::from_toml(&toml).unwrap();
    sb.start_daemon();
    let path = std::env::var_os("PATH").unwrap_or_default();
    let dirs = std::iter::once(bin.clone()).chain(std::env::split_paths(&path));
    let path = std::env::join_paths(dirs).unwrap();
    let mut r = sb.relay("docs", &[("PATH", path.to_str().unwrap())]);
    r.open();
    // Only the relay's own server ever ran.
    assert_eq!(r.call(1)["pid"], sb.pids("docs")[0]);
    assert_eq!(sb.pids("docs").len(), 1);
    // The daemon finds no safe file for the name, so it never spawns it: the hello (which now
    // carries the relay's own file) answers per-session (no warning: starting it is the
    // session's job) and says why.
    assert!(!r.stderr().contains("directly"), "{}", r.stderr());
    // The exact file of the relay's PATH (Windows folds the extension's case).
    let file = bin.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    let want = format!(
        "mcp docs: this session runs '{name}' from {}, the hub from nowhere",
        file.display()
    )
    .to_lowercase();
    assert!(
        sb.status()
            .decisions
            .iter()
            .any(|d| d.to_lowercase().contains(&want)),
        "{:?}",
        sb.status().decisions
    );
    assert_eq!(r.close(), 0);
}

#[test]
fn daemon_down_from_the_start_runs_directly() {
    let sb = Sandbox::new(&[("docs", "mcp-legacy", "shared", "")]);
    let mut r = sb.relay("docs", &[]);
    r.open();
    assert_eq!(r.call(1)["pid"], sb.pids("docs")[0]);
    // The relay logs before it answers, but the thread that reads its stderr can lag.
    sb.wait_for("the relay never said the hub was not available", || {
        r.stderr().contains("hub not available")
    });
    assert_eq!(r.close(), 0);
}

#[test]
fn per_session_server_gets_one_process_per_session() {
    let mut sb = Sandbox::new(&[("docs", "mcp-legacy", "per-session", "")]);
    sb.start_daemon();
    let mut relays: Vec<Relay> = (0..3).map(|_| sb.relay("docs", &[])).collect();
    let mut seen: Vec<u64> = relays
        .iter_mut()
        .map(|r| {
            r.open();
            r.call(1)["pid"].as_u64().unwrap()
        })
        .collect();
    let mut started = sb.pids("docs");
    seen.sort_unstable();
    seen.dedup();
    started.sort_unstable();
    assert_eq!(seen.len(), 3, "{seen:?}");
    assert_eq!(seen, started);
    assert_eq!(sb.row("docs").instances, 0, "the hub must not run it");
    for r in relays {
        assert!(r.stderr().is_empty(), "{}", r.stderr());
        assert_eq!(r.close(), 0);
    }
}

#[test]
fn secrets_from_env_from_never_reach_status_or_disk() {
    let sb = Sandbox::new(&[(
        "docs",
        "mcp-legacy",
        "shared",
        "env_from = [\"DOCS_TOKEN\"]",
    )]);
    // Its own process, so that what the daemon prints is scanned too.
    let mut daemon = sb.spawn_daemon();
    let mut r = sb.relay("docs", &[("DOCS_TOKEN", CANARY)]);
    r.open();
    assert_eq!(
        r.call(1)["has_token"],
        true,
        "the secret never reached the server"
    );
    assert!(sb.data_dir().join("services.json").exists());
    let status = sb.status();
    sb.assert_no_canary_on_disk();
    let (code, stderr) = r.close_with_stderr();
    assert_eq!(code, 0);
    let daemon_stderr = daemon.stop();
    sb.assert_no_canary_on_disk();
    assert_no_canary_in_hub_output(&status, &stderr, &daemon_stderr);
}

/// The first server of `docs` (the hub's) offers no protocol version the hub speaks, so the hub
/// gives up on it before any `initialize`; the relay then runs its own copy, which answers.
#[test]
fn a_server_with_no_supported_version_falls_back_end_to_end() {
    let sb = shared("mcp-unsupported-first");
    let mut r = sb.relay("docs", &[]);
    r.open();
    let pid = r.call(1)["pid"].as_u64().unwrap();
    let pids = sb.pids("docs");
    assert_eq!(
        pids.len(),
        2,
        "the hub's server and the relay's own: {pids:?}"
    );
    assert_eq!(pid, pids[1], "the session was not served by its own server");
    // The cause is the version: the hub's server never saw an initialize, the relay's got one.
    assert_eq!(sb.inits_of("docs", pids[0]), 0);
    assert_eq!(sb.inits_of("docs", pids[1]), 1);
    assert!(
        r.stderr().contains("running 'docs' directly"),
        "{}",
        r.stderr()
    );
    assert_eq!(r.close(), 0);
}

/// The hub's server (a legacy one) receives the hub's `initialize` and rejects it. The hub lets
/// go of the key without answering the session, and the relay runs its own copy, which answers.
#[test]
fn a_server_that_rejects_initialize_falls_back_end_to_end() {
    let sb = shared("mcp-reject-init-first");
    let mut r = sb.relay("docs", &[]);
    r.open();
    let pid = r.call(1)["pid"].as_u64().unwrap();
    let pids = sb.pids("docs");
    assert_eq!(
        pids.len(),
        2,
        "the hub's server and the relay's own: {pids:?}"
    );
    assert_eq!(pid, pids[1], "the session was not served by its own server");
    // The cause is the rejection: the hub's server got (and refused) one initialize.
    assert_eq!(sb.inits_of("docs", pids[0]), 1);
    assert_eq!(sb.inits_of("docs", pids[1]), 1);
    assert!(
        sb.status()
            .decisions
            .iter()
            .any(|d| d.contains("unavailable through the hub (initialize rejected)")),
        "{:?}",
        sb.status().decisions
    );
    assert!(
        r.stderr().contains("running 'docs' directly"),
        "{}",
        r.stderr()
    );
    assert_eq!(r.close(), 0);
}

/// Every session sends the same ids with its own mark through ONE shared server; each must get
/// its own mark back.
#[test]
fn replies_reach_the_session_that_asked() {
    let sb = shared("mcp-legacy");
    let mut relays: Vec<Relay> = (0..4).map(|_| sb.relay("docs", &[])).collect();
    for r in &mut relays {
        r.open();
    }
    for (i, r) in relays.iter_mut().enumerate() {
        r.send(tools_call_marked(1, &format!("session-{i}")));
        r.send(tools_call_marked(2, &format!("session-{i}-b")));
    }
    let mut served = Vec::new();
    for (i, r) in relays.iter_mut().enumerate() {
        let a = result(r.reply(1));
        assert_eq!(a["mark"], format!("session-{i}"));
        assert_eq!(result(r.reply(2))["mark"], format!("session-{i}-b"));
        served.push(a["pid"].as_u64().unwrap());
    }
    // Sessions with servers of their own would each get their own mark back too.
    let pids = sb.pids("docs");
    assert_eq!(pids.len(), 1, "one server for every session: {pids:?}");
    assert!(served.iter().all(|p| *p == pids[0]), "{served:?} {pids:?}");
    let row = sb.row("docs");
    assert_eq!((row.instances, row.clients), (1, 4), "{row:?}");
    for r in relays {
        assert_eq!(r.close(), 0);
    }
}

#[test]
fn the_canary_scan_covers_hub_output() {
    let sb = shared("mcp-legacy");
    let clean = sb.status();
    assert_no_canary_in_hub_output(&clean, "", "");
    // The hub's status notes and the relay's stderr are both scanned.
    let mut noted = clean.clone();
    noted.decisions.push(format!("mcp docs: leaked {CANARY}"));
    let caught = std::panic::catch_unwind(|| assert_no_canary_in_hub_output(&noted, "", ""));
    assert!(
        caught.is_err(),
        "a canary in the status notes passed the scan"
    );
    let caught = std::panic::catch_unwind(|| {
        assert_no_canary_in_hub_output(&clean, &format!("sync_gate_mcp: {CANARY}"), "")
    });
    assert!(
        caught.is_err(),
        "a canary in the relay stderr passed the scan"
    );
    let caught = std::panic::catch_unwind(|| {
        assert_no_canary_in_hub_output(&clean, "", &format!("sync_gated: {CANARY}"))
    });
    assert!(
        caught.is_err(),
        "a canary in the daemon stderr passed the scan"
    );
}

/// A test binary stuck for good (`hung` mode: a 100 ms watchdog with the sandbox's own abort,
/// then a thread that never returns) really ends, and says which test it was.
#[test]
fn a_hung_test_is_aborted_by_its_own_watchdog() {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["child_entry", "--exact", "--nocapture", "--test-threads=1"])
        .env("SYNC_GATE_TEST_CHILD", "hung")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let until = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= until {
            let _ = child.kill(); // tests only: this test's own child
            let _ = child.wait();
            panic!("the watchdog never ended the hung process");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    assert!(!status.success(), "{status:?}");
    assert!(err.contains("watchdog: test hung still running"), "{err}");
}

#[test]
fn a_watchdog_dropped_in_time_stays_quiet() {
    let fired = Arc::new(Mutex::new(false));
    let f = fired.clone();
    drop(Watchdog::start(
        "quick",
        Duration::from_millis(200),
        move |_| *f.lock().unwrap() = true,
    ));
    std::thread::sleep(Duration::from_millis(400));
    assert!(!*fired.lock().unwrap(), "a finished test was aborted");
}

/// The daemon as its own process (this binary in `daemon` mode), with its stderr collected.
struct DaemonProcess {
    child: Child,
    err: Arc<Mutex<String>>,
    err_done: mpsc::Receiver<std::io::Error>,
}

impl DaemonProcess {
    /// Clean shutdown (its stdin closes), killing it only if it has not exited after 20 s.
    fn end(&mut self) {
        drop(self.child.stdin.take());
        let until = Instant::now() + Duration::from_secs(20);
        while Instant::now() < until && self.child.try_wait().ok().flatten().is_none() {
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill(); // tests only: this test's own child; no-op once it exited
        let _ = self.child.wait();
    }

    /// [`DaemonProcess::end`], then all it printed to stderr, read to the end.
    fn stop(&mut self) -> String {
        self.end();
        wait_end(&self.err_done, Instant::now() + Duration::from_secs(5));
        self.err.lock().unwrap().clone()
    }
}

impl Drop for DaemonProcess {
    fn drop(&mut self) {
        self.end();
    }
}

impl Sandbox {
    /// Starts the daemon as its own process on this sandbox and waits until it answers.
    fn spawn_daemon(&self) -> DaemonProcess {
        let mut c = Command::new(std::env::current_exe().unwrap());
        c.args(["child_entry", "--exact", "--nocapture", "--test-threads=1"])
            .env("SYNC_GATE_TEST_CHILD", "daemon")
            .env("SYNC_GATE_CONFIG", self.dir.join("config.toml"))
            .env("SYNC_GATE_SOCKET", &self.socket)
            .env("SYNC_GATE_DATA_DIR", self.data_dir())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = c.spawn().unwrap();
        let (err, err_done) = capture(child.stderr.take().unwrap());
        let daemon = DaemonProcess {
            child,
            err,
            err_done,
        };
        self.wait_for("the daemon never answered", || {
            sync_gate::client::call_at(&self.socket, &Request::Status).is_ok()
        });
        daemon
    }
}

/// Not a test; does nothing unless `SYNC_GATE_MEASURE_MEMORY` is set. Run by hand on a release
/// build, on Windows:
///
/// `SYNC_GATE_MEASURE_MEMORY=1 cargo test --release -p sync_gate_shim --test mcp_e2e measure_hub_memory -- --nocapture`
///
/// The daemon runs as its own process (this binary in `daemon` mode: `sync_gated::run_with` with
/// the real probe, control and launcher, as `sync_gated` does). Five shared servers, ten relays
/// each (initialize and one `tools/call` per relay); prints the working set and private bytes of
/// the daemon and of the relays twice: loaded (right after the last reply) and idle (30 s later).
/// Without the variable it prints one "skipped" line to stderr (also on non-Windows).
#[test]
fn measure_hub_memory() {
    if std::env::var_os("SYNC_GATE_MEASURE_MEMORY").is_none() {
        eprintln!("measure_hub_memory: skipped (set SYNC_GATE_MEASURE_MEMORY=1 to measure)");
        return;
    }
    let names = ["s1", "s2", "s3", "s4", "s5"];
    let mut sb = Sandbox::new(&names.map(|n| (n, "mcp-legacy", "shared", "")));
    sb.until = Instant::now() + Duration::from_secs(120);
    let daemon = sb.spawn_daemon();
    let mut relays: Vec<Relay> = names
        .iter()
        .flat_map(|n| (0..10).map(|_| sb.relay(n, &[])).collect::<Vec<_>>())
        .collect();
    for r in &mut relays {
        r.send(initialize());
    }
    for r in &mut relays {
        result(r.reply(0));
        r.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
        r.send(tools_call(1));
    }
    for r in &mut relays {
        result(r.reply(1));
    }
    for n in names {
        let row = sb.row(n);
        assert_eq!((row.instances, row.clients), (1, 10), "{row:?}");
    }
    let relay_pids: Vec<u32> = relays.iter().map(|r| r.child.id()).collect();
    report_memory(
        "loaded (right after the last reply)",
        daemon.child.id(),
        &relay_pids,
    );
    std::thread::sleep(Duration::from_secs(30));
    report_memory("idle (30 s later)", daemon.child.id(), &relay_pids);
    for r in relays {
        assert_eq!(r.close(), 0);
    }
    drop(daemon);
}

#[cfg(windows)]
fn report_memory(phase: &str, daemon: u32, relays: &[u32]) {
    println!("== {phase}");
    let ids: Vec<String> = std::iter::once(daemon)
        .chain(relays.iter().copied())
        .map(|p| p.to_string())
        .collect();
    let script = format!(
        "Get-Process -Id {} | ForEach-Object {{ '{{0}} {{1}} {{2}}' -f $_.Id, $_.WorkingSet64, $_.PrivateMemorySize64 }}",
        ids.join(",")
    );
    let out = Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .unwrap();
    let mut rows = std::collections::HashMap::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let f: Vec<u64> = line
            .split_whitespace()
            .map(|x| x.parse().unwrap())
            .collect();
        rows.insert(f[0] as u32, (f[1], f[2]));
    }
    let mib = |b: u64| b as f64 / MIB as f64;
    let (ws, pb) = rows[&daemon];
    println!(
        "daemon {daemon}: working set {:.1} MiB, private {:.1} MiB",
        mib(ws),
        mib(pb)
    );
    let r: Vec<(u64, u64)> = relays.iter().map(|p| rows[p]).collect();
    let (sw, sp) = r.iter().fold((0, 0), |(a, b), (w, p)| (a + w, b + p));
    let (minw, maxw) = (r.iter().map(|x| x.0).min(), r.iter().map(|x| x.0).max());
    let (minp, maxp) = (r.iter().map(|x| x.1).min(), r.iter().map(|x| x.1).max());
    println!(
        "relay ({} processes): working set min {:.2} max {:.2} MiB, private min {:.2} max {:.2} MiB",
        r.len(),
        mib(minw.unwrap()),
        mib(maxw.unwrap()),
        mib(minp.unwrap()),
        mib(maxp.unwrap())
    );
    println!(
        "sum over the relays: working set {:.1} MiB, private {:.1} MiB",
        mib(sw),
        mib(sp)
    );
}

#[cfg(not(windows))]
fn report_memory(phase: &str, daemon: u32, relays: &[u32]) {
    eprintln!(
        "measure_hub_memory: {phase} skipped: measured on Windows only (daemon pid {daemon}, {} relays)",
        relays.len()
    );
}
