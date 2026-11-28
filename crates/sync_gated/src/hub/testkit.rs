//! Test doubles for the hub: in-memory pipes, a fake `Launcher` whose children are driven by
//! the test (the test plays the MCP server), and in-memory client connections.

use super::Hub;
use crate::ipc::Closer;
use crate::supervisor::{Launcher, Spawned};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use sync_gate_core::{Config, HubHello, HubReply, McpMode, McpServer};

/// Every wait in these tests panics after this long instead of hanging.
pub const WAIT: Duration = Duration::from_secs(10);

/// Signals after the reply worker has finished, including any action after its last flush.
pub fn signal_thread_exit(tx: mpsc::Sender<()>) {
    struct Signal(mpsc::Sender<()>);
    impl Drop for Signal {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }
    thread_local! {
        static SIGNAL: std::cell::RefCell<Option<Signal>> = const { std::cell::RefCell::new(None) };
    }
    SIGNAL.with(|s| *s.borrow_mut() = Some(Signal(tx)));
}

struct PipeState {
    buf: VecDeque<u8>,
    cap: usize,
    writer_gone: bool,
    reader_gone: bool,
}

/// One direction of an in-memory byte stream holding at most `cap` bytes (a full pipe blocks
/// the writer, like a peer that stops reading).
#[derive(Clone)]
pub struct Pipe(Arc<(Mutex<PipeState>, Condvar)>);

pub struct PipeW(Pipe);
pub struct PipeR(Pipe);

pub fn pipe(cap: usize) -> (PipeW, PipeR, Pipe) {
    let p = Pipe(Arc::new((
        Mutex::new(PipeState {
            buf: VecDeque::new(),
            cap,
            writer_gone: false,
            reader_gone: false,
        }),
        Condvar::new(),
    )));
    (PipeW(p.clone()), PipeR(p.clone()), p)
}

impl Pipe {
    /// Forced close of both ends: blocked reads see EOF, writes fail.
    pub fn close(&self) {
        let (m, cv) = &*self.0;
        let mut st = m.lock().unwrap();
        st.writer_gone = true;
        st.reader_gone = true;
        cv.notify_all();
    }
    pub fn writer_gone(&self) -> bool {
        self.0.0.lock().unwrap().writer_gone
    }
}

impl Write for PipeW {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let (m, cv) = &*self.0.0;
        let mut st = m.lock().unwrap();
        loop {
            if st.reader_gone {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            if st.buf.len() < st.cap {
                break;
            }
            st = cv.wait(st).unwrap();
        }
        let n = (st.cap - st.buf.len()).min(data.len());
        st.buf.extend(&data[..n]);
        cv.notify_all();
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for PipeW {
    fn drop(&mut self) {
        let (m, cv) = &*self.0.0;
        m.lock().unwrap().writer_gone = true;
        cv.notify_all();
    }
}

impl Read for PipeR {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let (m, cv) = &*self.0.0;
        let mut st = m.lock().unwrap();
        loop {
            if !st.buf.is_empty() {
                let n = st.buf.len().min(out.len());
                for (o, b) in out.iter_mut().zip(st.buf.drain(..n)) {
                    *o = b;
                }
                cv.notify_all();
                return Ok(n);
            }
            if st.writer_gone {
                return Ok(0);
            }
            st = cv.wait(st).unwrap();
        }
    }
}

impl Drop for PipeR {
    fn drop(&mut self) {
        let (m, cv) = &*self.0.0;
        m.lock().unwrap().reader_gone = true;
        cv.notify_all();
    }
}

/// Lines from `r`, read on a helper thread so the test only ever waits with a deadline.
pub fn lines(r: impl Read + Send + 'static) -> Receiver<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(r).lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

pub fn recv_json(rx: &Receiver<String>, what: &str) -> Value {
    let line = rx
        .recv_timeout(WAIT)
        .unwrap_or_else(|e| panic!("no line from {what}: {e}"));
    serde_json::from_str(&line).unwrap_or_else(|e| panic!("{what} sent {line:?}: {e}"))
}

/// Polls `cond` until true; panics after `WAIT`.
pub fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let end = Instant::now() + WAIT;
    while !cond() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// A child the test plays: it reads what the hub wrote to its stdin and writes its stdout.
pub struct FakeChild {
    pub pid: u32,
    pub env: BTreeMap<String, String>,
    /// Names the hub asked to remove from the inherited environment.
    pub env_remove: Vec<String>,
    pub cwd: Option<PathBuf>,
    /// What the hub asked to run.
    pub command: String,
    pub args: Vec<String>,
    input: Receiver<String>,
    output: Option<PipeW>,
}

impl FakeChild {
    /// True when the hub writes nothing to the child within `wait`.
    pub fn stays_silent(&self, wait: Duration) -> bool {
        self.input.recv_timeout(wait).is_err()
    }

    pub fn next(&self) -> Value {
        recv_json(&self.input, "the hub (child stdin)")
    }

    pub fn send(&mut self, v: Value) {
        self.send_raw(&v.to_string());
    }

    /// One raw line (for lines `Value` cannot hold, like over-deep JSON).
    pub fn send_raw(&mut self, line: &str) {
        let out = self.output.as_mut().expect("child stdout open");
        writeln!(out, "{line}").unwrap();
    }

    /// Answers the hub's `server/discover` probe as a stateless server of the current revision.
    pub fn handshake(&mut self) {
        let probe = self.next();
        assert_eq!(probe["method"], "server/discover", "{probe}");
        let result = json!({"supportedVersions": ["2026-07-28"], "capabilities": {"tools": {}}});
        self.send(json!({"jsonrpc": "2.0", "id": probe["id"], "result": result}));
    }

    /// Answers the probe as a legacy server (no `server/discover`), then `initialize`, with
    /// resource subscriptions offered.
    pub fn handshake_legacy(&mut self) {
        let probe = self.next();
        assert_eq!(probe["method"], "server/discover", "{probe}");
        let no = json!({"code": -32601, "message": "no"});
        self.send(json!({"jsonrpc": "2.0", "id": probe["id"], "error": no}));
        let init = self.next();
        assert_eq!(init["method"], "initialize", "{init}");
        let result = json!({"protocolVersion": "2025-11-25", "capabilities": {"resources": {"subscribe": true}}, "serverInfo": {"name": "s", "version": "1"}});
        self.send(json!({"jsonrpc": "2.0", "id": init["id"], "result": result}));
        assert_eq!(self.next()["method"], "notifications/initialized");
    }

    /// Answers the next request with `{"echo": <method>}`; returns the request.
    pub fn answer(&mut self) -> Value {
        let req = self.next();
        let result = json!({"echo": req["method"]});
        self.send(json!({"jsonrpc": "2.0", "id": req["id"], "result": result}));
        req
    }
}

/// Records every call. A child is alive until terminated, or until its stdin closes unless
/// `ignore_eof` (a server that ignores stdin EOF).
#[derive(Default)]
pub struct FakeLauncher {
    log: Mutex<Vec<String>>,
    alive: Mutex<HashSet<u32>>,
    stdins: Mutex<HashMap<u32, Pipe>>,
    children: Mutex<VecDeque<FakeChild>>,
    spawns: AtomicU32,
    pub ignore_eof: AtomicBool,
    /// That many next spawns fail (like a command not on the daemon's PATH).
    pub fail_spawns: AtomicU32,
    /// What `resolve` answers for every command; unset, the command as given.
    pub resolved: Mutex<Option<PathBuf>>,
    /// `resolve` finds nothing (a bare name on no safe folder of the PATH).
    pub unresolvable: AtomicBool,
    /// Exit code `reap` reports per pid; absent = unknown.
    pub exit_codes: Mutex<HashMap<u32, i32>>,
    /// Launch id given to each pid: a call naming another one is not about that child.
    launches: Mutex<HashMap<u32, u64>>,
}

impl FakeLauncher {
    pub fn spawns(&self) -> u32 {
        self.spawns.load(Ordering::SeqCst)
    }
    pub fn calls(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
    /// The next spawned child not yet taken.
    pub fn take_child(&self) -> FakeChild {
        let mut child = None;
        wait_until("a spawned child", || {
            child = self.children.lock().unwrap().pop_front();
            child.is_some()
        });
        child.unwrap()
    }
    /// `is_alive` without recording a call.
    pub fn is_alive_quiet(&self, pid: u32) -> bool {
        let eof = self
            .stdins
            .lock()
            .unwrap()
            .get(&pid)
            .is_some_and(Pipe::writer_gone);
        self.alive.lock().unwrap().contains(&pid)
            && (self.ignore_eof.load(Ordering::SeqCst) || !eof)
    }
    fn ours(&self, pid: u32, launch: u64) -> bool {
        self.launches.lock().unwrap().get(&pid) == Some(&launch)
    }
    /// The child dies: it is no longer alive and its stdout closes.
    pub fn kill(&self, child: &mut FakeChild) {
        self.alive.lock().unwrap().remove(&child.pid);
        child.output = None;
    }
}

impl Launcher for FakeLauncher {
    fn spawn(
        &self,
        command: &str,
        args: &[String],
        env: &BTreeMap<String, String>,
        env_remove: &[String],
        cwd: Option<&Path>,
    ) -> io::Result<Spawned> {
        let mut left = self.fail_spawns.load(Ordering::SeqCst);
        let failing = loop {
            if left == 0 {
                break false;
            }
            match self.fail_spawns.compare_exchange(
                left,
                left - 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break true,
                Err(now) => left = now,
            }
        };
        if failing {
            self.log.lock().unwrap().push("spawn failed".into());
            return Err(io::ErrorKind::NotFound.into());
        }
        let n = self.spawns.fetch_add(1, Ordering::SeqCst);
        let pid = 100 + n;
        let (hub_in, child_in, stdin_pipe) = pipe(1 << 20);
        let (child_out, hub_out, _) = pipe(1 << 20);
        self.log.lock().unwrap().push(format!("spawn {pid}"));
        self.alive.lock().unwrap().insert(pid);
        self.stdins.lock().unwrap().insert(pid, stdin_pipe);
        self.launches.lock().unwrap().insert(pid, u64::from(n) + 1);
        self.children.lock().unwrap().push_back(FakeChild {
            pid,
            env: env.clone(),
            env_remove: env_remove.to_vec(),
            cwd: cwd.map(Path::to_path_buf),
            command: command.to_string(),
            args: args.to_vec(),
            input: lines(child_in),
            output: Some(child_out),
        });
        Ok(Spawned {
            pid,
            start_time: 1,
            launch: u64::from(n) + 1,
            exe: PathBuf::from("/fake/mcp-server"),
            stdin: Box::new(hub_in),
            stdout: Box::new(hub_out),
        })
    }
    fn is_alive(&self, pid: u32, _start_time: u64, launch: u64) -> bool {
        self.log.lock().unwrap().push(format!("is_alive {pid}"));
        self.ours(pid, launch) && self.is_alive_quiet(pid)
    }
    fn terminate(&self, pid: u32, _start_time: u64, launch: u64) -> io::Result<()> {
        self.log.lock().unwrap().push(format!("terminate {pid}"));
        if self.ours(pid, launch) {
            self.alive.lock().unwrap().remove(&pid);
        }
        Ok(())
    }
    fn reap(&self, pid: u32, launch: u64) -> Option<i32> {
        self.log.lock().unwrap().push(format!("reap {pid}"));
        let code = self.exit_codes.lock().unwrap().get(&pid).copied();
        code.filter(|_| self.ours(pid, launch))
    }
    fn resolve(&self, command: &str, _env: &BTreeMap<String, String>) -> Option<PathBuf> {
        if self.unresolvable.load(Ordering::SeqCst) {
            return None;
        }
        let set = self.resolved.lock().unwrap().clone();
        set.or_else(|| Some(PathBuf::from(command)))
    }
}

/// An in-memory relay connection. `stuck` clients never read what the hub sends them.
pub struct TestClient {
    to_hub: Option<PipeW>,
    from_hub: Receiver<String>,
    pub closed: Arc<AtomicBool>,
    /// Keeps a stuck client's read end open (and unread).
    _held: Option<PipeR>,
}

impl TestClient {
    pub fn send(&mut self, v: Value) {
        self.send_raw(&v.to_string());
    }
    /// One raw line (for lines `Value` cannot hold, like over-deep JSON).
    pub fn send_raw(&mut self, line: &str) {
        let w = self.to_hub.as_mut().expect("connection open");
        writeln!(w, "{line}").unwrap();
    }
    pub fn recv(&self) -> Value {
        recv_json(&self.from_hub, "the hub (client side)")
    }
    pub fn reply(&self) -> HubReply {
        serde_json::from_value(self.recv()).unwrap()
    }
    /// Every line the hub still sent before it closed this connection (waits for the close).
    pub fn rest(&self) -> Vec<String> {
        let mut rest = Vec::new();
        loop {
            match self.from_hub.recv_timeout(WAIT) {
                Ok(line) => rest.push(line),
                Err(mpsc::RecvTimeoutError::Disconnected) => return rest,
                Err(mpsc::RecvTimeoutError::Timeout) => panic!("the hub kept the connection open"),
            }
        }
    }
    /// The relay goes away: the hub sees EOF.
    pub fn hang_up(&mut self) {
        self.to_hub = None;
    }
    /// Bytes the hub wrote that a stuck client has not read (0 for other clients).
    pub fn unread(&self) -> usize {
        self._held
            .as_ref()
            .map_or(0, |r| r.0.0.0.lock().unwrap().buf.len())
    }
}

pub fn hello(server: &str, env: &[(&str, &str)], cwd: &str) -> HubHello {
    HubHello {
        server: server.into(),
        cwd: PathBuf::from(cwd),
        env: env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        client: "test".into(),
        program: None,
    }
}

fn conn(cap: usize) -> (PipeW, PipeR, PipeR, PipeW, Closer, Arc<AtomicBool>) {
    let (to_hub, hub_reads, p1) = pipe(1 << 20);
    let (hub_writes, from_hub, p2) = pipe(cap);
    let closed = Arc::new(AtomicBool::new(false));
    let flag = closed.clone();
    let close: Closer = Arc::new(move || {
        flag.store(true, Ordering::SeqCst);
        p1.close();
        p2.close();
    });
    (to_hub, hub_reads, from_hub, hub_writes, close, closed)
}

pub fn connect(hub: &Hub, h: HubHello) -> TestClient {
    let (to_hub, hub_reads, from_hub, hub_writes, close, closed) = conn(1 << 20);
    hub.attach(h, Box::new(hub_reads), Box::new(hub_writes), close);
    TestClient {
        to_hub: Some(to_hub),
        from_hub: lines(from_hub),
        closed,
        _held: None,
    }
}

/// A client whose close only stops its input: everything the hub already queued for it is
/// still delivered, then EOF (like a Unix socket `shutdown`). `rest()` then shows exactly what
/// the hub handed to this client, whoever wins the race between its writer and the close.
pub fn connect_draining(hub: &Hub, h: HubHello) -> TestClient {
    let (to_hub, hub_reads, p1) = pipe(1 << 20);
    let (hub_writes, from_hub, _) = pipe(1 << 20);
    let closed = Arc::new(AtomicBool::new(false));
    let flag = closed.clone();
    let close: Closer = Arc::new(move || {
        flag.store(true, Ordering::SeqCst);
        p1.close();
    });
    hub.attach(h, Box::new(hub_reads), Box::new(hub_writes), close);
    TestClient {
        to_hub: Some(to_hub),
        from_hub: lines(from_hub),
        closed,
        _held: None,
    }
}

/// Bytes a stuck client's pipe holds: more than the hello reply, less than an `initialize` reply.
pub const STUCK_PIPE_BYTES: usize = 64;

/// A client whose consumer is stuck: the hub can push at most `STUCK_PIPE_BYTES` into its pipe.
pub fn connect_stuck(hub: &Hub, h: HubHello) -> TestClient {
    let (to_hub, hub_reads, from_hub, hub_writes, close, closed) = conn(STUCK_PIPE_BYTES);
    hub.attach(h, Box::new(hub_reads), Box::new(hub_writes), close);
    TestClient {
        to_hub: Some(to_hub),
        from_hub: mpsc::channel().1,
        closed,
        _held: Some(from_hub),
    }
}

/// A raw connection handed to `Hub::serve_conn`, for hello tests.
pub fn raw_conn(hub: Arc<Hub>) -> TestClient {
    let (to_hub, hub_reads, from_hub, hub_writes, close, closed) = conn(1 << 20);
    std::thread::spawn(move || hub.serve_conn(Box::new(hub_reads), Box::new(hub_writes), close));
    TestClient {
        to_hub: Some(to_hub),
        from_hub: lines(from_hub),
        closed,
        _held: None,
    }
}

/// `docs` (shared, `env_from = ["TOKEN"]`), `files` (shared, `cwd = "inherit"`) and `browser`
/// (per-session).
pub fn config() -> Config {
    let shared = McpServer {
        command: "docs-mcp".into(),
        mode: McpMode::Shared,
        idle_stop_secs: 10,
        ..McpServer::default()
    };
    let mut cfg = Config::default();
    cfg.mcp.insert(
        "docs".into(),
        McpServer {
            env_from: vec!["TOKEN".into()],
            ..shared.clone()
        },
    );
    cfg.mcp.insert(
        "files".into(),
        McpServer {
            cwd: Some("inherit".into()),
            ..shared
        },
    );
    cfg.mcp.insert(
        "browser".into(),
        McpServer {
            command: "browser-mcp".into(),
            ..McpServer::default()
        },
    );
    cfg
}

pub fn request(id: u64, method: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": {}})
}
