//! The relay behind `sync_gate_mcp <server>`: stands in for an MCP server and connects the
//! client's stdio to the daemon's hub, or runs the real server itself when the hub is not there.
//!
//! Fail-open is the point: a session must never be worse off because sync_gate exists. Without
//! a reachable hub (not running, slow, refusing, or `per-session` mode) the relay starts the
//! configured command exactly as the agent would have. If the hub goes away mid-session it
//! starts the server directly, replays the client's `initialize`, and keeps relaying.
//!
//! Test or advanced overrides read from the environment: `SYNC_GATE_CONFIG` (path of
//! `config.toml`) and `SYNC_GATE_SOCKET` (control socket name; the hub is `<name>-mcp`).

mod direct;
mod relay;
mod transport;

use interprocess::local_socket::Stream;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use sync_gate_core::ipc_name::{connect_checked, is_foreign, server_is_ours};
use sync_gate_core::{Config, HubHello, HubReply, McpMode, McpServer, hub_socket_name};
use transport::{Connection, Worker};

pub(crate) type Reader = Box<dyn BufRead + Send>;
pub(crate) type Writer = Box<dyn Write + Send>;

/// Longest the relay waits for the hub's answer to its hello before starting the server itself.
const HELLO_DEADLINE: Duration = Duration::from_secs(2);
const EXIT_GRACE: Duration = Duration::from_secs(5);
const BUF: usize = 16 * 1024;

/// Injectable deadlines for deterministic session tests.
#[derive(Clone)]
pub struct RunOptions {
    pub hello_timeout: Duration,
    pub exit_grace: Duration,
    pub write_timeout: Duration,
    pub shutdown: Shutdown,
    /// Test seam: fail session worker creation after this many successful starts.
    pub thread_budget: Option<usize>,
    /// Test seam: the check of who serves the hub pipe answers "not this user".
    pub foreign_hub: bool,
    /// Test seam: runs right after the program is resolved, before the hello and any spawn.
    #[cfg(debug_assertions)]
    pub after_resolve: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            hello_timeout: HELLO_DEADLINE,
            exit_grace: EXIT_GRACE,
            write_timeout: Duration::from_secs(10),
            shutdown: Shutdown::default(),
            thread_budget: None,
            foreign_hub: false,
            #[cfg(debug_assertions)]
            after_resolve: None,
        }
    }
}

/// The same shutdown request used by the signal handler and by embedded callers.
#[derive(Default)]
struct Signal {
    requested: std::sync::atomic::AtomicBool,
    finished: std::sync::atomic::AtomicBool,
    /// Wakes the session's event loop; it only queues an event, so it never blocks.
    wake: Mutex<Option<Box<dyn Fn() + Send>>>,
}

impl Signal {
    fn request(&self) {
        self.requested
            .store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(wake) = self.wake.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            wake();
        }
    }
}

#[derive(Clone, Default)]
pub struct Shutdown(Arc<Signal>);

impl Shutdown {
    pub fn request(&self) {
        self.0.request();
    }
    /// The session registers how to be woken; a request made earlier is seen by `requested`.
    pub(crate) fn on_request(&self, wake: Box<dyn Fn() + Send>) {
        *self.0.wake.lock().unwrap_or_else(|e| e.into_inner()) = Some(wake);
    }
    pub(crate) fn requested(&self) -> bool {
        self.0.requested.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// [`run_with`] with injectable deadlines and shutdown.
pub fn run_with_options(
    cfg: &Config,
    hub_name: &str,
    server: &str,
    stdin: impl Read + Send + 'static,
    stdout: impl Write + Send + 'static,
    stderr: impl Write + Send + 'static,
    options: RunOptions,
) -> i32 {
    go(
        cfg,
        hub_name,
        server,
        Io {
            stdin: Box::new(stdin),
            stdout: Box::new(stdout),
            stderr: Box::new(stderr),
        },
        options,
    )
}

/// Only the session owner writes stderr.
pub(crate) struct Log(Writer);

impl Log {
    pub(crate) fn line(&mut self, msg: &str) {
        let _ = writeln!(self.0, "{msg}");
        let _ = self.0.flush();
    }
}

/// `$SYNC_GATE_CONFIG`, else `config.toml` in the per-user config dir.
pub fn config_path() -> Option<PathBuf> {
    match std::env::var_os("SYNC_GATE_CONFIG") {
        Some(p) => Some(PathBuf::from(p)),
        None => directories::ProjectDirs::from("dev", "sync_labs", "sync_gate")
            .map(|d| d.config_dir().join("config.toml")),
    }
}

/// Missing file means defaults; an unreadable or invalid one is an error.
pub fn load_config() -> Result<Config, String> {
    let Some(path) = config_path() else {
        return Ok(Config::default());
    };
    match sync_gate_core::read_config(&path) {
        // The parser's text can quote the file (an `env` value): a category and a position only.
        Ok(text) => Config::from_toml(&text).map_err(|e| {
            format!(
                "{}: {}",
                path.display(),
                sync_gate_core::ConfigLoadError::parse(&text, &e)
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
    }
}

/// The hub socket: `<SYNC_GATE_SOCKET>-mcp` when that override is set and not empty, else the
/// per-user default.
pub fn hub_name() -> String {
    hub_socket_name()
}

static SESSIONS: Mutex<Vec<std::sync::Weak<Signal>>> = Mutex::new(Vec::new());
/// Set by the first signal, so a session that registers afterwards still sees it.
static SHUTDOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn signal_sessions() -> Vec<Arc<Signal>> {
    SHUTDOWN.store(true, std::sync::atomic::Ordering::SeqCst);
    let sessions: Vec<_> = SESSIONS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter_map(std::sync::Weak::upgrade)
        .collect();
    for flag in &sessions {
        flag.request();
    }
    sessions
}

/// Ctrl+C, SIGTERM and console close request the same cleanup as stdin EOF.
pub fn exit_on_signal() {
    let _ = ctrlc::set_handler(|| {
        signal_sessions();
    });
    #[cfg(windows)]
    // Console close terminates the process when its handler returns; wait for session cleanup.
    unsafe {
        windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(console_close), 1);
    }
}

#[cfg(windows)]
unsafe extern "system" fn console_close(event: u32) -> windows_sys::core::BOOL {
    use windows_sys::Win32::System::Console::{
        CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
    };
    if !matches!(
        event,
        CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT
    ) {
        return 0;
    }
    let sessions = signal_sessions();
    let until = Instant::now() + EXIT_GRACE;
    while sessions
        .iter()
        .any(|s| !s.finished.load(std::sync::atomic::Ordering::SeqCst))
        && Instant::now() < until
    {
        std::thread::sleep(transport::TICK);
    }
    1
}

struct Completion(Arc<Signal>);
impl Drop for Completion {
    fn drop(&mut self) {
        self.0
            .finished
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

struct Io {
    stdin: Box<dyn Read + Send>,
    stdout: Writer,
    stderr: Writer,
}

/// `sync_gate_mcp <server>` on the process's real stdio. Returns the exit code.
pub fn run_process(server: &str) -> i32 {
    // A raw duplicate avoids the global stdout buffer retaining a lock during cancellation.
    #[cfg(windows)]
    let stdout = {
        use std::os::windows::io::AsHandle;
        std::io::stdout()
            .as_handle()
            .try_clone_to_owned()
            .map(std::fs::File::from)
    };
    #[cfg(unix)]
    let stdout = {
        use std::os::fd::AsFd;
        std::io::stdout()
            .as_fd()
            .try_clone_to_owned()
            .map(std::fs::File::from)
    };
    let stdout = match stdout {
        Ok(stdout) => stdout,
        Err(_) => {
            eprintln!("sync_gate_mcp: cannot open client stdout");
            return 1;
        }
    };
    go_env(
        server,
        Io {
            stdin: Box::new(std::io::stdin()),
            stdout: Box::new(stdout),
            stderr: Box::new(std::io::stderr()),
        },
    )
}

/// Like [`run_process`] with the client's streams given (stderr stays the process's).
pub fn run(
    server: &str,
    stdin: impl Read + Send + 'static,
    stdout: impl Write + Send + 'static,
) -> i32 {
    go_env(
        server,
        Io {
            stdin: Box::new(stdin),
            stdout: Box::new(stdout),
            stderr: Box::new(std::io::stderr()),
        },
    )
}

/// The testable seam: config and hub socket are arguments; the process environment is read only
/// for the `env_from` values and the current directory the hello carries.
pub fn run_with(
    cfg: &Config,
    hub_name: &str,
    server: &str,
    stdin: impl Read + Send + 'static,
    stdout: impl Write + Send + 'static,
    stderr: impl Write + Send + 'static,
) -> i32 {
    let io = Io {
        stdin: Box::new(stdin),
        stdout: Box::new(stdout),
        stderr: Box::new(stderr),
    };
    go(cfg, hub_name, server, io, RunOptions::default())
}

fn go_env(server: &str, io: Io) -> i32 {
    let why = match load_config() {
        Ok(cfg) if cfg.mcp.contains_key(server) => {
            return go(&cfg, &hub_name(), server, io, RunOptions::default());
        }
        Ok(_) => format!("unknown server '{server}'"),
        Err(e) => e,
    };
    // The config cannot start it: the agent's original launch, if adoption recorded one. Nothing
    // the record holds goes to stderr, only why it is not used.
    let original = match sync_gate_core::data_dir() {
        None => Err("no per-user data folder".to_string()),
        Some(dir) => sync_gate_core::adopted::read_adopted(&dir)
            .map(|a| sync_gate_core::adopted::find_original(&a, server))
            .map_err(|e| format!("adoption record refused: {e}")),
    };
    let mut log = Log(io.stderr);
    let (command, args) = match original {
        Ok(Some(launch)) => launch,
        Ok(None) => {
            log.line(&format!("sync_gate_mcp: {why}"));
            return 2;
        }
        Err(e) => {
            log.line(&format!("sync_gate_mcp: {why}; {e}"));
            return 2;
        }
    };
    log.line(&format!(
        "sync_gate_mcp: {why}; running '{server}' from the adoption record"
    ));
    // Folder and environment are the relay's: what the agent would give the server.
    let srv = McpServer {
        command,
        args,
        mode: McpMode::PerSession,
        cwd: None,
        ..Default::default()
    };
    let cfg = Config {
        mcp: std::collections::BTreeMap::from([(server.to_string(), srv)]),
        ..Config::default()
    };
    let io = Io {
        stderr: log.0,
        ..io
    };
    go(&cfg, &hub_name(), server, io, RunOptions::default())
}

fn go(cfg: &Config, hub_name: &str, server: &str, io: Io, options: RunOptions) -> i32 {
    let _completion = Completion(options.shutdown.0.clone());
    {
        let mut sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
        sessions.retain(|s| s.strong_count() > 0);
        sessions.push(Arc::downgrade(&options.shutdown.0));
    }
    // Registered first, then checked: a signal either saw this session or left the flag set.
    if SHUTDOWN.load(std::sync::atomic::Ordering::SeqCst) {
        options.shutdown.request();
    }
    let mut log = Log(io.stderr);
    let Some(srv) = cfg.mcp.get(server) else {
        log.line(&format!("sync_gate_mcp: unknown server '{server}'"));
        return 2;
    };
    // Resolved once: this file goes in the hello and into every direct start. A bare name with
    // no safe file ends here, before any handshake (a hello without `program` reads as an old
    // relay, and the hub must not pick its own).
    let program = match direct::resolve(server, srv) {
        Ok(p) => p,
        Err(msg) if srv.mode == McpMode::Shared => {
            log.line(&msg);
            return 127;
        }
        // Per session the start itself reports it, after the shutdown check.
        Err(_) => None,
    };
    #[cfg(debug_assertions)]
    if let Some(f) = &options.after_resolve {
        f();
    }
    let mut hub = None;
    if srv.mode == McpMode::Shared {
        let ours: fn(&Stream) -> bool = if options.foreign_hub {
            |_| false
        } else {
            server_is_ours
        };
        match handshake(
            hub_name,
            &hello(server, srv, program.clone()),
            options.hello_timeout,
            &options.shutdown,
            ours,
        ) {
            Hs::Hub(conn, r, w) => hub = Some((conn, r, w)),
            // The daemon says this server is not shared: starting it is our job, no warning.
            Hs::PerSession => {}
            Hs::Foreign => log.line(
                "sync_gate_mcp: hub pipe is not owned by this user; running the server directly",
            ),
            Hs::Unavailable => log.line(&format!(
                "sync_gate_mcp: hub not available, running '{server}' directly"
            )),
        }
    }
    if options.shutdown.requested() {
        return 0;
    }
    relay::run(
        server,
        srv,
        program,
        log,
        Box::new(BufReader::with_capacity(BUF, io.stdin)),
        io.stdout,
        hub,
        options,
    )
}

fn hello(server: &str, srv: &McpServer, program: Option<std::path::PathBuf>) -> HubHello {
    HubHello {
        server: server.into(),
        cwd: std::env::current_dir().unwrap_or_default(),
        env: srv
            .env_from
            .iter()
            .filter_map(|n| std::env::var(n).ok().map(|v| (n.clone(), v)))
            .collect(),
        client: "sync_gate_mcp".into(),
        program,
    }
}

enum Hs {
    /// The hub took the connection: its read side (possibly holding bytes already) and write side.
    Hub(Connection, Reader, Writer),
    PerSession,
    /// Another user serves the hub name: nothing was written to it.
    Foreign,
    Unavailable,
}

/// Connects, checks with `ours` that the hub is this user's (before writing anything: the hello
/// carries `env_from` secrets), sends the hello and reads the one-line reply, all within
/// [`HELLO_DEADLINE`]. A late answer is abandoned: the helper thread drops the connection when
/// it finishes.
fn handshake(
    name: &str,
    hello: &HubHello,
    timeout: Duration,
    shutdown: &Shutdown,
    ours: fn(&Stream) -> bool,
) -> Hs {
    let Ok(mut line) = serde_json::to_vec(hello) else {
        return Hs::Unavailable;
    };
    line.push(b'\n');
    let (tx, rx) = mpsc::channel();
    let name = name.to_owned();
    let until = Instant::now() + timeout;
    let Ok(connecting) = Worker::start(move |_| {
        let _ = tx.send(connect_checked(&name, ours));
    }) else {
        return Hs::Unavailable;
    };
    let stream = loop {
        if shutdown.requested() || Instant::now() >= until {
            return Hs::Unavailable;
        }
        match rx.recv_timeout(transport::TICK) {
            Ok(Ok(stream)) => break stream,
            Ok(Err(e)) if is_foreign(&e) => return Hs::Foreign,
            Ok(Err(_)) | Err(mpsc::RecvTimeoutError::Disconnected) => return Hs::Unavailable,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    connecting.finish(until);
    let conn = Connection::new(stream);
    let (mut r, mut w) = conn.halves();
    let (tx, rx) = mpsc::channel();
    let Ok(worker) = Worker::start(move |_| {
        let reply = exchange(&mut r, &mut w, &line);
        let _ = tx.send((reply, r, w));
    }) else {
        return Hs::Unavailable;
    };
    loop {
        if shutdown.requested() || Instant::now() >= until {
            break;
        }
        match rx.recv_timeout(transport::TICK) {
            Ok((Some(HubReply::Ok), r, w)) => {
                worker.finish(until);
                return Hs::Hub(conn, r, w);
            }
            Ok((reply, _, _)) => {
                conn.close();
                worker.finish(Instant::now() + Duration::from_millis(100));
                return if reply == Some(HubReply::PerSession) {
                    Hs::PerSession
                } else {
                    Hs::Unavailable
                };
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
    conn.close();
    worker.finish(Instant::now() + Duration::from_millis(100));
    Hs::Unavailable
}

fn exchange(r: &mut Reader, w: &mut Writer, line: &[u8]) -> Option<HubReply> {
    w.write_all(line).ok()?;
    let mut reply = Vec::new();
    // A hub's reply is tiny; the cap keeps a rogue peer from making us buffer without bound.
    let got = r.take(64 * 1024).read_until(b'\n', &mut reply);
    if got.is_err() || reply.last() != Some(&b'\n') {
        return None;
    }
    serde_json::from_slice(&reply).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// A signal before any session registered must still stop the session that starts later.
    /// This binary's other tests start no sessions, so the process-wide flag cannot leak.
    #[test]
    fn signal_before_the_session_registers_is_not_lost() {
        signal_sessions();
        let srv = McpServer {
            command: "sync_gate-no-such-command".into(),
            mode: McpMode::PerSession,
            ..McpServer::default()
        };
        let cfg = Config {
            mcp: BTreeMap::from([("docs".to_string(), srv)]),
            ..Config::default()
        };
        // Honoured: 0 before anything starts. Swallowed: the missing command gives 127.
        let code = run_with_options(
            &cfg,
            "unused",
            "docs",
            std::io::empty(),
            std::io::sink(),
            std::io::sink(),
            RunOptions::default(),
        );
        assert_eq!(code, 0);
    }
}
