//! MCP hub: runs each `shared` MCP server ONCE per server key and serves every agent session
//! through it. A relay connects to the hub socket, sends a `HubHello` line, and after `Ok` the
//! connection carries MCP lines; a [`Mux`] per child does the protocol work.
//!
//! Elastic pool: a key runs up to `max_instances` children ("units"), each with its own `Mux`.
//! With more than one allowed, a request goes to the least loaded ready unit with fewer than
//! `max_in_flight` requests, or waits in the key's FIFO hub queue; `Hub::tick` grows the pool
//! when the queue waits and memory allows (`sync_gate_hub::decide`) and stops idle extra units.
//! Every client of the key is a client of every unit's mux.
//!
//! Fail open (ruling P22): a key is UNAVAILABLE THROUGH THE HUB while its first unit could not
//! be spawned or is in its crash-loop pause (both end with the pause), or came up unsupported
//! (for the daemon's life). Becoming unavailable closes every client of the key at once without
//! answering any of their requests, and a hello for the key is refused meanwhile: the relay
//! then runs the server directly (the hub runs it with the daemon's PATH, environment and
//! directory, where it may fail while the session's own copy would work). Extra units never
//! make a key unavailable.
//!
//! Servers added later: a hello for a name the hub does not know rereads the config's `[mcp]`
//! (at most once every `RELOAD_EVERY`) and adds the names it does not have yet; a server it
//! has is never changed or removed (that still takes a daemon restart). A session whose relay
//! resolves a bare command to another file than the hub would run gets `PerSession`.
//!
//! Threads (none polling; stoppers and refusal replies get 128 KiB of stack, readers, writers
//! and connection threads `PARSE_THREAD_STACK` because they may parse or drop JSON values): per client one reader (client ->
//! mux) and one writer (drains the client's bounded queue); per child one stdout reader (child
//! -> mux) and one stdin writer (drains the child's bounded queue); short-lived stopper threads
//! run `stop_own`. Deadlines (hello, probe and request timeouts, backoff restarts, crash-loop
//! pause, idle stop) are driven by [`Hub::tick`].
//!
//! Locks: `Inner::map` may be taken before ONE key lock, never after one. A key lock
//! (`Instance::st`) guards every unit's `Mux` together with everything they route to (client
//! queues, the hub queue, the child queues, the child states). Under it the code only does
//! non-blocking queue pushes and closer calls; every blocking write happens on a writer thread.
//! `servers`, `restarts`, `notes`, `memory`, `registry` and the fake/real launcher's own locks
//! are leaves. `reloaded` is taken only on a connection thread holding no other lock.
//!
//! Secrets: the `env_from` values of a `HubHello` live only in [`Key`] (memory), which has no
//! `Debug`. Everything shown or persisted (notes, report, registry, errors) names the server only.
//!
//! The daemon only ever stops processes it started itself, and only through the supervisor
//! (`stop_own`); nothing here calls a process-terminating API.

use crate::ipc::{Closer, PARSE_THREAD_STACK, STREAM_THREAD_STACK};
use crate::supervisor::{
    Backoff, Launcher, Registry, Spawned, is_bare, path_has_relative_entry, stop_own,
};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use sync_gate_core::{
    Config, ConfigLoadError, HubHello, HubReply, Kind, McpMode, McpServer, McpStatus, classify,
    error_response,
};
use sync_gate_hub::{
    ClientId, MAX_MESSAGE_BYTES, MAX_QUEUED_BYTES_PER_CLIENT, MAX_QUEUED_PER_CLIENT, Mux, Out,
    PoolAction, PoolStats, decide, pick_instance, wants_to_grow,
};

/// Messages a client's outgoing queue holds; one more and the client is disconnected.
pub const CLIENT_QUEUE_MESSAGES: usize = 256;
/// Bytes a client's outgoing queue holds (an empty queue always takes one message of any size).
pub const CLIENT_QUEUE_BYTES: usize = 8 * 1024 * 1024;
/// Messages queued for a child's stdin; beyond it messages are dropped (and time out).
pub const CHILD_QUEUE_MESSAGES: usize = 1024;
/// Bytes queued for a child's stdin (an empty queue always takes one message of any size).
pub const CHILD_QUEUE_BYTES: usize = 32 * 1024 * 1024;
/// Longest `HubHello` line.
pub const MAX_HELLO_BYTES: usize = 1024 * 1024;
/// A connection that has not sent its hello by then is closed (at the next tick).
pub const HELLO_DEADLINE: Duration = Duration::from_secs(5);
/// Time a refused connection gets to take its (best-effort) reply before the tick closes it.
pub const REFUSAL_GRACE: Duration = Duration::from_secs(1);
/// Time a child gets to exit after its stdin closes, before it is terminated.
const STOP_GRACE: Duration = Duration::from_secs(5);
/// `stop_own` may add two 2 s terminate rounds to the grace; shutdown waits that much more.
const STOP_SLACK: Duration = Duration::from_secs(5);
pub(crate) const CRASH_WINDOW: Duration = Duration::from_secs(60);
pub(crate) const CRASH_LIMIT: usize = 5;
pub(crate) const CRASH_PAUSE: Duration = Duration::from_secs(300);
/// Uptime after which the restart backoff starts over.
const STABLE_UPTIME: Duration = Duration::from_secs(60);
/// Notes kept until the daemon tick moves them to the decision log.
const MAX_NOTES: usize = 200;
/// A line buffer that grew past this is released after use.
const KEEP_BUF: usize = 1024 * 1024;
/// Deepest `[`/`{` nesting accepted in a line. serde_json allows 128, but building, writing
/// and dropping a `Value` that deep overflowed the 128 KiB hub thread stacks (debug build).
pub const MAX_JSON_DEPTH: usize = 64;
const KEEPS_CRASHING: &str = "mcp server keeps crashing";
/// The hello reply for a key that cannot run through the hub; the relay then runs it directly.
const UNAVAILABLE: &str = "server unavailable through the hub";
/// A hello for an unknown name rereads the config at most once per this long.
const RELOAD_EVERY: Duration = Duration::from_secs(2);

/// Rereads the config's `[mcp]` servers (the daemon's `main` passes one that reads its config
/// file); the error says only that it did not load, never what the file held.
pub type McpReload =
    Arc<dyn Fn() -> Result<BTreeMap<String, McpServer>, ConfigLoadError> + Send + Sync>;

/// What decides sharing: same key, same child. Holds `env_from` values: never shown or stored.
#[derive(Clone, PartialEq, Eq, Hash)]
struct Key {
    server: String,
    env: BTreeMap<String, String>,
    /// Only for `cwd = "inherit"` servers.
    cwd: Option<PathBuf>,
    /// A bare command: the file the hub compared with the session's, and the only one it starts.
    program: Option<PathBuf>,
}

/// Sending end of a bounded outgoing queue drained by one writer thread.
struct Queue {
    tx: SyncSender<Vec<u8>>,
    bytes: Arc<AtomicUsize>,
    max_bytes: usize,
}

impl Queue {
    fn new(messages: usize, max_bytes: usize) -> (Queue, Receiver<Vec<u8>>, Arc<AtomicUsize>) {
        let (tx, rx) = mpsc::sync_channel(messages);
        let bytes = Arc::new(AtomicUsize::new(0));
        let q = Queue {
            tx,
            bytes: bytes.clone(),
            max_bytes,
        };
        (q, rx, bytes)
    }

    /// Never blocks; false when the queue is full or its writer is gone.
    fn push(&self, line: Vec<u8>) -> bool {
        let n = line.len();
        let queued = self.bytes.load(Ordering::SeqCst);
        if queued > 0 && queued.saturating_add(n) > self.max_bytes {
            return false;
        }
        self.bytes.fetch_add(n, Ordering::SeqCst);
        if self.tx.try_send(line).is_err() {
            self.bytes.fetch_sub(n, Ordering::SeqCst);
            return false;
        }
        true
    }
}

/// Writer thread body: one line per message until every sender is gone or a write fails.
/// No flush per message: a socket write is delivered at once, a `ChildStdin` is unbuffered,
/// and on a Windows named pipe `flush` is `FlushFileBuffers`, which waits for the peer to read
/// everything (a stuck client would pin this thread there, and every message would wait for
/// the relay). Dropped unflushed, a pipe goes to interprocess's "limbo" (flush, then close).
fn drain(rx: Receiver<Vec<u8>>, bytes: Arc<AtomicUsize>, mut w: Box<dyn Write + Send>) {
    for mut line in rx {
        let n = line.len();
        line.push(b'\n');
        let r = w.write_all(&line);
        bytes.fetch_sub(n, Ordering::SeqCst);
        if r.is_err() {
            return;
        }
    }
}

enum Child {
    /// No process; the next client starts one.
    Stopped,
    /// A spawn is in progress outside the lock.
    Starting,
    Running(Run),
    /// After a crash: restart at `until` (after the backoff, or the crash-loop pause).
    Waiting {
        until: Instant,
        crash_loop: bool,
    },
    /// Speaks no supported protocol version: stopped and never restarted by this instance.
    Unsupported,
}

struct Run {
    pid: u32,
    start_time: u64,
    /// Tags the child's reader thread, so a stale one cannot touch a newer child.
    generation: u64,
    stdin: Queue,
    started: Instant,
    full_noted: bool,
}

struct Peer {
    q: Queue,
    close: Closer,
}

/// One child of a key's pool, with its own mux and restart state.
struct Unit {
    /// Stable within the key (indexes shift when a unit is removed).
    id: u64,
    mux: Mux,
    child: Child,
    backoff: Backoff,
    crashes: VecDeque<Instant>,
    /// Why the next start is a restart; `None` for a start on demand.
    restarting: Option<&'static str>,
    rss: u64,
    /// Since when nothing is in flight here (for shrinking).
    quiet_since: Option<Instant>,
}

/// A request waiting in the hub queue for a unit with room.
struct Waiting {
    client: ClientId,
    rid: Value,
    line: String,
    since: Instant,
    deadline: Instant,
}

/// Everything of one key, under one lock: the clients, the hub queue and the units.
struct Inst {
    units: Vec<Unit>,
    clients: HashMap<ClientId, Peer>,
    queue: VecDeque<Waiting>,
    idle_since: Option<Instant>,
    /// Removed from the map (idle or shutdown): a spawn finishing now must stop its child.
    retired: bool,
    next_unit: u64,
    /// Largest RSS measured for one unit of this key.
    peak_rss: u64,
    /// "not scaling, memory is the limit" already written for the current backlog.
    memory_noted: bool,
}

/// One server key (a pool of units).
struct Instance {
    key: Key,
    st: Mutex<Inst>,
}

type Slot = Arc<Mutex<Option<Box<dyn Write + Send>>>>;

struct Map {
    instances: HashMap<Key, Arc<Instance>>,
    /// Connections still owing their hello: deadline, closer, and the writer (for the timeout
    /// reply; `serve_conn` takes it back when the hello arrives in time).
    hellos: HashMap<u64, (Instant, Closer, Slot)>,
    /// Refused connections: the tick closes each one at its deadline, whatever its reply
    /// thread is doing. The slot keeps its writer alive until after the close, even if its
    /// flush failed (dropping an unflushed Windows pipe otherwise sends it to limbo).
    closing: Vec<(Instant, Closer, Slot)>,
    next_client: ClientId,
    next_hello: u64,
}

struct Inner {
    /// The configured servers; a reload only ever adds names. Read through `server`.
    servers: Mutex<BTreeMap<String, Arc<McpServer>>>,
    reload: Option<McpReload>,
    /// When the config was last reread; held while it is reread.
    reloaded: Mutex<Option<Instant>>,
    launcher: Arc<dyn Launcher>,
    registry: Option<Mutex<Registry>>,
    map: Mutex<Map>,
    notes: Mutex<VecDeque<String>>,
    restarts: Mutex<BTreeMap<String, u32>>,
    stopped: AtomicBool,
    next_generation: AtomicU64,
    stop_grace: Duration,
    /// Free and reserve bytes from the daemon's last snapshot; `None`: the pool does not grow.
    memory: Mutex<Option<(u64, u64)>>,
}

pub struct Hub {
    inner: Arc<Inner>,
}

/// A panic on another thread must not take the hub down with it.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// A hub thread that only moves bytes (stoppers, refusal replies): small stack. A failure to
/// start one is reported, never a panic.
fn spawn(f: impl FnOnce() + Send + 'static) -> io::Result<()> {
    spawn_with(STREAM_THREAD_STACK, f)
}

/// A hub thread that may parse or drop JSON values (readers, and writers whose detach drops
/// queued messages): `PARSE_THREAD_STACK`.
fn spawn_parsing(f: impl FnOnce() + Send + 'static) -> io::Result<()> {
    spawn_with(PARSE_THREAD_STACK, f)
}

fn spawn_with(stack: usize, f: impl FnOnce() + Send + 'static) -> io::Result<()> {
    std::thread::Builder::new()
        .stack_size(stack)
        .spawn(f)
        .map(drop)
}

/// Runs `f` on a hub thread, or right here when no thread can be started.
fn spawn_or_inline(f: impl FnOnce() + Send + 'static) {
    let slot = Arc::new(Mutex::new(Some(f)));
    let theirs = slot.clone();
    let started = spawn(move || {
        if let Some(f) = lock(&theirs).take() {
            f()
        }
    });
    if started.is_err() {
        if let Some(f) = lock(&slot).take() {
            f()
        }
    }
}

fn shutting_down() -> HubReply {
    HubReply::Error {
        message: "sync_gated is shutting down".into(),
    }
}

fn running(c: Child) -> Option<Run> {
    match c {
        Child::Running(r) => Some(r),
        _ => None,
    }
}

fn crash_looping(c: &Child) -> bool {
    matches!(
        c,
        Child::Waiting {
            crash_loop: true,
            ..
        }
    )
}

/// Requests in flight on a unit, for the pool decisions.
fn load(u: &Unit) -> u32 {
    u32::try_from(u.mux.in_flight()).unwrap_or(u32::MAX)
}

/// One reply before the connection is closed: flushed, because closing discards unread data.
fn write_reply(w: &mut dyn Write, r: &HubReply) {
    if let Ok(mut line) = serde_json::to_vec(r) {
        line.push(b'\n');
        let _ = w.write_all(&line).and_then(|()| w.flush());
    }
}

pub(crate) enum Line {
    Eof,
    /// The line (without its newline) is in the buffer.
    Data,
    /// Longer than the cap: dropped, and the stream is positioned after it.
    TooLong,
}

/// Reads one newline-terminated line of at most `cap` bytes into `buf`, never buffering more
/// than `cap`. A last line without a newline counts as a line.
pub(crate) fn read_line(r: &mut impl BufRead, cap: usize, buf: &mut Vec<u8>) -> io::Result<Line> {
    buf.clear();
    let mut over = false;
    loop {
        let avail = match r.fill_buf() {
            Ok(a) => a,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if avail.is_empty() {
            return Ok(match (over, buf.is_empty()) {
                (true, _) => Line::TooLong,
                (false, true) => Line::Eof,
                (false, false) => Line::Data,
            });
        }
        let (used, found) = match avail.iter().position(|&b| b == b'\n') {
            Some(i) => (i + 1, true),
            None => (avail.len(), false),
        };
        let chunk = &avail[..used - usize::from(found)];
        if !over {
            if buf.len() + chunk.len() > cap {
                over = true;
                *buf = Vec::new();
            } else {
                buf.extend_from_slice(chunk);
            }
        }
        r.consume(used);
        if found {
            return Ok(if over { Line::TooLong } else { Line::Data });
        }
    }
}

/// True when a JSON line nests deeper than `MAX_JSON_DEPTH`. Cheap: no allocation, no parsing.
fn too_deep(line: &[u8]) -> bool {
    let (mut depth, mut in_string, mut escaped) = (0usize, false, false);
    for &b in line {
        if in_string {
            match b {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth += 1;
                if depth > MAX_JSON_DEPTH {
                    return true;
                }
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

/// Mux notes start with `<server>: `; the log shows them as `mcp <server>: ...`.
fn mux_note(server: &str, note: &str) -> String {
    let rest = note
        .strip_prefix(server)
        .and_then(|r| r.strip_prefix(": "))
        .unwrap_or(note);
    format!("mcp {server}: {rest}")
}

impl Hub {
    pub fn new(
        cfg: &Config,
        launcher: Arc<dyn Launcher>,
        data_dir: Option<&Path>,
        reload: Option<McpReload>,
    ) -> Hub {
        Hub {
            inner: Arc::new(Inner {
                servers: Mutex::new(
                    cfg.mcp
                        .iter()
                        .map(|(name, s)| (name.clone(), Arc::new(s.clone())))
                        .collect(),
                ),
                reload,
                reloaded: Mutex::new(None),
                launcher,
                registry: data_dir.map(|d| Mutex::new(Registry::load(&d.join("services.json")))),
                map: Mutex::new(Map {
                    instances: HashMap::new(),
                    hellos: HashMap::new(),
                    closing: Vec::new(),
                    next_client: 1,
                    next_hello: 0,
                }),
                notes: Mutex::new(VecDeque::new()),
                restarts: Mutex::new(BTreeMap::new()),
                stopped: AtomicBool::new(false),
                next_generation: AtomicU64::new(1),
                stop_grace: STOP_GRACE,
                memory: Mutex::new(None),
            }),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_stop_grace(mut self, grace: Duration) -> Hub {
        Arc::get_mut(&mut self.inner)
            .expect("set before the hub is shared")
            .stop_grace = grace;
        self
    }

    /// A new hub connection: reads the `HubHello` (at most `MAX_HELLO_BYTES`, within
    /// `HELLO_DEADLINE`, enforced by `tick`), then attaches it. Runs on the connection's thread.
    pub fn serve_conn(&self, r: Box<dyn Read + Send>, w: Box<dyn Write + Send>, close: Closer) {
        let slot: Slot = Arc::new(Mutex::new(Some(w)));
        let ticket = {
            let mut map = lock(&self.inner.map);
            // Checked under the map lock: `close_all` sets `stopped` before it drains `hellos`,
            // so either we see it here or it sees our ticket.
            if self.inner.stopped.load(Ordering::SeqCst) {
                drop(map);
                let w = lock(&slot).take();
                return self.inner.refuse(w, close, shutting_down(), Instant::now());
            }
            map.next_hello += 1;
            let t = map.next_hello;
            map.hellos.insert(
                t,
                (Instant::now() + HELLO_DEADLINE, close.clone(), slot.clone()),
            );
            t
        };
        let mut r = BufReader::new(r);
        let mut buf = Vec::new();
        let got = read_line(&mut r, MAX_HELLO_BYTES, &mut buf);
        let timed_out = lock(&self.inner.map).hellos.remove(&ticket).is_none();
        let w = lock(&slot).take();
        let hello = match got {
            _ if timed_out => return,
            Ok(Line::Eof) | Err(_) => return,
            Ok(Line::TooLong) => Err("hello exceeds 1 MiB"),
            Ok(Line::Data) if too_deep(&buf) => Err("hello nested too deeply"),
            // The serde error could quote the hello (and its secrets): keep it generic.
            Ok(Line::Data) => serde_json::from_slice::<HubHello>(&buf)
                .map_err(|_| "expected one HubHello JSON line"),
        };
        drop(buf);
        let Some(w) = w else {
            return close();
        };
        match hello {
            Ok(h) => self.attach(h, Box::new(r), w, close),
            Err(message) => {
                let reply = HubReply::Error {
                    message: message.into(),
                };
                self.inner.refuse(Some(w), close, reply, Instant::now());
            }
        }
    }

    /// Answers the hello on `w` and, for a shared server, makes the connection a client of the
    /// child for its key (started on demand). Returns at once: the connection gets its own
    /// reader and writer threads. `close` forcibly ends the connection.
    pub fn attach(
        &self,
        hello: HubHello,
        r: Box<dyn Read + Send>,
        w: Box<dyn Write + Send>,
        close: Closer,
    ) {
        let inner = &self.inner;
        let refuse = |w: Box<dyn Write + Send>, reply: HubReply| {
            inner.refuse(Some(w), close.clone(), reply, Instant::now());
        };
        if inner.stopped.load(Ordering::SeqCst) {
            return refuse(w, shutting_down());
        }
        let found = inner.server(&hello.server);
        let Some(srv) = found.or_else(|| inner.reload(&hello.server)) else {
            return refuse(w, HubReply::Unknown);
        };
        if srv.mode == McpMode::PerSession {
            return refuse(w, HubReply::PerSession);
        }
        let mut key = Key {
            server: hello.server.clone(),
            env: srv
                .env_from
                .iter()
                .filter_map(|n| hello.env.get(n).map(|v| (n.clone(), v.clone())))
                .collect(),
            cwd: srv.inherits_cwd().then(|| hello.cwd.clone()),
            program: None,
        };
        // A bare command is shared only when the hub runs the file the session would: it finds
        // one on a safe folder, the PATH does not depend on the session's folder, and the relay
        // (an older one says nothing) names the same file. Else that session runs it itself.
        if is_bare(&srv.command) {
            let env = launch_env(&srv, &key.env);
            let q = inner.launcher.resolve(&srv.command, &env);
            let why = match (&q, &hello.program) {
                (None, None) => Some(format!(
                    "'{}' is on no safe folder of the hub's PATH",
                    srv.command
                )),
                // The hub resolves from its own folder; with any configured folder (the session's
                // or a fixed one) the child runs elsewhere, so a relative entry could name
                // another file.
                _ if srv.cwd.is_some() && path_has_relative_entry(&env) => Some(format!(
                    "the PATH for '{}' has a relative entry and the server runs in another folder",
                    srv.command
                )),
                // The launcher takes text: a path that is not Unicode could only be passed lossily,
                // and the lossy name may be another existing file.
                (Some(q), _) if q.to_str().is_none() => Some(format!(
                    "the path the hub found for '{}' is not Unicode",
                    srv.command
                )),
                (q, Some(p)) if !q.as_deref().is_some_and(|q| same_program(q, p)) => {
                    let hub = q
                        .as_deref()
                        .map_or_else(|| "nowhere".into(), |q| q.display().to_string());
                    Some(format!(
                        "this session runs '{}' from {}, the hub from {hub}",
                        srv.command,
                        p.display()
                    ))
                }
                _ => None,
            };
            if let Some(why) = why {
                inner.note(format!(
                    "mcp {}: {why}; that session runs it itself",
                    hello.server
                ));
                return refuse(w, HubReply::PerSession);
            }
            // Started by this path, never searched again: gone by then, the start fails.
            key.program = q;
        }
        drop(hello);
        let (q, rx, bytes) = Queue::new(CLIENT_QUEUE_MESSAGES, CLIENT_QUEUE_BYTES);
        q.push(serde_json::to_vec(&HubReply::Ok).unwrap_or_default());
        let (inst, id, starts) = {
            let mut map = lock(&inner.map);
            if inner.stopped.load(Ordering::SeqCst) {
                drop(map);
                return refuse(w, shutting_down());
            }
            let id = map.next_client;
            map.next_client = map.next_client.wrapping_add(1);
            let timeout = Duration::from_secs(srv.request_timeout_secs);
            let inst = map
                .instances
                .entry(key)
                .or_insert_with_key(|k| Arc::new(Instance::new(k.clone(), timeout)))
                .clone();
            let mut g = lock(&inst.st);
            if unavailable(&g) {
                drop(g);
                drop(map);
                let reply = HubReply::Error {
                    message: UNAVAILABLE.into(),
                };
                return refuse(w, reply);
            }
            g.clients.insert(
                id,
                Peer {
                    q,
                    close: close.clone(),
                },
            );
            g.idle_since = None;
            let mut starts = Vec::new();
            for u in &mut g.units {
                u.mux.client_attached(id);
                if matches!(u.child, Child::Stopped) {
                    u.child = Child::Starting;
                    starts.push(u.id);
                }
            }
            drop(g);
            (inst, id, starts)
        };
        let threads = {
            let (inner2, inst2, close2) = (inner.clone(), inst.clone(), close.clone());
            spawn_parsing(move || {
                drain(rx, bytes, w);
                inner2.drop_client(&inst2, id, Instant::now());
                close2();
            })
        }
        .and_then(|()| {
            let (inner2, inst2, close2) = (inner.clone(), inst.clone(), close.clone());
            spawn_parsing(move || inner2.client_reader(&inst2, id, r, &close2))
        });
        if let Err(e) = threads {
            inner.note(format!(
                "mcp {}: cannot serve a client: {e}",
                inst.key.server
            ));
            inner.drop_client(&inst, id, Instant::now());
            close();
        }
        for uid in starts {
            inner.start_child(&inst, uid);
        }
    }

    /// Free memory and the reserve the pool must leave, from the daemon's latest snapshot.
    /// Until this is called the pool does not grow.
    pub fn set_memory(&self, free_bytes: u64, reserve_bytes: u64) {
        *lock(&self.inner.memory) = Some((free_bytes, reserve_bytes));
    }

    /// Time-based work: hello deadlines, mux deadlines, restarts after backoff, idle stop.
    pub fn tick(&self, now: Instant) {
        let inner = &self.inner;
        let mut starts = Vec::new();
        let mut stops = Vec::new();
        let mut timeouts = Vec::new();
        let mut due_closes = Vec::new();
        {
            let mut map = lock(&inner.map);
            let (due, later) = std::mem::take(&mut map.closing)
                .into_iter()
                .partition::<Vec<_>, _>(|(deadline, _, _)| now >= *deadline);
            map.closing = later;
            due_closes.extend(due);
            let late: Vec<u64> = map
                .hellos
                .iter()
                .filter(|(_, (deadline, _, _))| now >= *deadline)
                .map(|(t, _)| *t)
                .collect();
            for t in late {
                if let Some((_, close, slot)) = map.hellos.remove(&t) {
                    timeouts.push((close, slot));
                }
            }
            // One budget for every key: instances still starting or not measured yet, and
            // those approved below, are taken off the snapshot's free memory before a key grows.
            let mut spent: u64 = map
                .instances
                .values()
                .map(|i| unmeasured(&lock(&i.st)))
                .fold(0, u64::saturating_add);
            let snapshot = *lock(&inner.memory);
            let mut idle = Vec::new();
            for (key, inst) in &map.instances {
                let server = &key.server;
                let mut guard = lock(&inst.st);
                let g = &mut *guard;
                for i in 0..g.units.len() {
                    let outs = g.units[i].mux.tick(now);
                    // A key this event makes unavailable drops its clients before they get
                    // these answers (ruling P22); otherwise check_all changes nothing here.
                    let gone = inner.check_all(server, g, now);
                    stops.extend(gone.into_iter().map(|r| (server.clone(), r)));
                    inner.dispatch(server, g, i, outs, now);
                }
                inner.expire_queue(server, g, now);
                let memory = snapshot.map(|(free, reserve)| (free.saturating_sub(spent), reserve));
                let (pool_starts, pool_stops) = inner.scale(server, g, memory, now);
                spent = spent.saturating_add(g.peak_rss.saturating_mul(pool_starts.len() as u64));
                starts.extend(pool_starts.into_iter().map(|uid| (inst.clone(), uid)));
                stops.extend(pool_stops.into_iter().map(|r| (server.clone(), r)));
                inner.settle(server, g, now);
                stops.extend(
                    inner
                        .check_all(server, g, now)
                        .into_iter()
                        .map(|r| (server.clone(), r)),
                );
                let has_clients = !g.clients.is_empty();
                for u in &mut g.units {
                    let due = match &u.child {
                        Child::Running(r) => {
                            now.saturating_duration_since(r.started) >= STABLE_UPTIME
                        }
                        Child::Waiting { until, .. } => now >= *until,
                        _ => false,
                    };
                    if due {
                        if matches!(u.child, Child::Running(_)) {
                            u.backoff.reset();
                        } else if !has_clients {
                            u.child = Child::Stopped;
                            u.restarting = None;
                        } else {
                            u.child = Child::Starting;
                            starts.push((inst.clone(), u.id));
                        }
                    }
                }
                let idle_for =
                    Duration::from_secs(inner.server(server).map_or(0, |s| s.idle_stop_secs));
                // A crash-loop pause keeps the crash history: no idle retirement until it ends.
                // An unsupported first unit keeps the key refused for the daemon's life.
                let is_idle = g.clients.is_empty()
                    && !unavailable(g)
                    && !g
                        .units
                        .iter()
                        .any(|u| matches!(u.child, Child::Starting) || crash_looping(&u.child))
                    && g.idle_since.is_some_and(|t| now >= t + idle_for);
                if is_idle {
                    g.retired = true;
                    for u in &mut g.units {
                        let child = std::mem::replace(&mut u.child, Child::Stopped);
                        stops.extend(running(child).map(|r| (server.clone(), r)));
                    }
                    idle.push(key.clone());
                }
            }
            for k in idle {
                map.instances.remove(&k);
            }
        }
        for (_, close, slot) in due_closes {
            close();
            drop(slot);
        }
        for (close, slot) in timeouts {
            let w = lock(&slot).take();
            let reply = HubReply::Error {
                message: "hello timed out".into(),
            };
            inner.refuse(w, close, reply, now);
        }
        for (inst, uid) in starts {
            inner.start_child(&inst, uid);
        }
        for (server, run) in stops {
            inner.stop_later(server, run);
        }
    }

    /// Asks `rss_of` (outside every lock) for each running child's tree RSS, for `report`.
    pub fn measure(&self, mut rss_of: impl FnMut(u32) -> u64) {
        let mut pids: Vec<(Arc<Instance>, u32)> = Vec::new();
        for i in lock(&self.inner.map).instances.values() {
            for u in &lock(&i.st).units {
                if let Child::Running(r) = &u.child {
                    pids.push((i.clone(), r.pid));
                }
            }
        }
        for (inst, pid) in pids {
            let rss = rss_of(pid);
            let mut guard = lock(&inst.st);
            let g = &mut *guard;
            let unit = g
                .units
                .iter_mut()
                .find(|u| matches!(&u.child, Child::Running(r) if r.pid == pid));
            if let Some(u) = unit {
                u.rss = rss;
                g.peak_rss = g.peak_rss.max(rss);
            }
        }
    }

    /// Decisions made since the last call, for the daemon's decision log.
    pub fn take_notes(&self) -> Vec<String> {
        lock(&self.inner.notes).drain(..).collect()
    }

    /// One row per configured server, summed over its instances.
    pub fn report(&self) -> Vec<McpStatus> {
        let inner = &self.inner;
        let servers = lock(&inner.servers).clone();
        let restarts = lock(&inner.restarts).clone();
        let mut rows: BTreeMap<&str, McpStatus> = servers
            .iter()
            .map(|(name, s)| {
                let row = McpStatus {
                    server: name.clone(),
                    mode: match s.mode {
                        McpMode::Shared => "shared",
                        McpMode::PerSession => "per-session",
                    }
                    .into(),
                    instances: 0,
                    clients: 0,
                    in_flight: 0,
                    rss: 0,
                    restarts: restarts.get(name).copied().unwrap_or(0),
                };
                (name.as_str(), row)
            })
            .collect();
        let map = lock(&inner.map);
        for inst in map.instances.values() {
            let g = lock(&inst.st);
            let Some(row) = rows.get_mut(inst.key.server.as_str()) else {
                continue;
            };
            for u in &g.units {
                if matches!(u.child, Child::Running(_)) {
                    row.instances += 1;
                    row.rss = row.rss.saturating_add(u.rss);
                }
                row.in_flight += load(u);
            }
            row.clients += g.clients.len() as u32;
        }
        rows.into_values().collect()
    }

    /// Clean stop: no new connections are attached, every client connection is closed, and
    /// each child is stopped with `stop_own` (in parallel). Returns within the stop grace plus
    /// `STOP_SLACK` whatever the children do.
    pub fn shutdown(&self) {
        let runs = self.close_all();
        let (tx, rx) = mpsc::channel();
        let mut started = 0;
        for (server, run) in runs {
            let inner = self.inner.clone();
            let tx = tx.clone();
            // A stopper that cannot start leaves the child to its stdin EOF (closed by now)
            // and its registry row to the next start's `reap_leftovers`.
            if spawn(move || {
                inner.stop_now(&server, run);
                let _ = tx.send(());
            })
            .is_ok()
            {
                started += 1;
            }
        }
        let deadline = Instant::now() + self.inner.stop_grace + STOP_SLACK;
        for _ in 0..started {
            let left = deadline.saturating_duration_since(Instant::now());
            if rx.recv_timeout(left).is_err() {
                eprintln!("sync_gated: mcp servers still stopping at shutdown; leaving them");
                return;
            }
        }
    }

    /// Simulated crash: connections close and children lose their stdin, but nothing is
    /// stopped (they exit on EOF; `reap_leftovers` covers the rest at the next start).
    pub fn abort(&self) {
        drop(self.close_all());
    }

    fn close_all(&self) -> Vec<(String, Run)> {
        let inner = &self.inner;
        inner.stopped.store(true, Ordering::SeqCst);
        let (instances, hellos, closing) = {
            let mut map = lock(&inner.map);
            (
                std::mem::take(&mut map.instances),
                std::mem::take(&mut map.hellos),
                std::mem::take(&mut map.closing),
            )
        };
        for (_, close, _) in hellos.into_values() {
            close();
        }
        for (_, close, slot) in closing {
            close();
            drop(slot);
        }
        let mut runs = Vec::new();
        for (key, inst) in instances {
            let mut g = lock(&inst.st);
            g.retired = true;
            for (_, p) in g.clients.drain() {
                (p.close)();
            }
            // Like requests waiting in a mux: their clients are closed, nobody gets a reply.
            g.queue.clear();
            for u in &mut g.units {
                let child = std::mem::replace(&mut u.child, Child::Stopped);
                runs.extend(running(child).map(|r| (key.server.clone(), r)));
            }
        }
        runs
    }
}

impl Instance {
    fn new(key: Key, request_timeout: Duration) -> Instance {
        Instance {
            st: Mutex::new(Inst {
                units: vec![Unit::new(0, &key.server, request_timeout)],
                clients: HashMap::new(),
                queue: VecDeque::new(),
                idle_since: None,
                retired: false,
                next_unit: 1,
                peak_rss: 0,
                memory_noted: false,
            }),
            key,
        }
    }
}

impl Unit {
    fn new(id: u64, server: &str, request_timeout: Duration) -> Unit {
        Unit {
            id,
            mux: Mux::new(server, request_timeout),
            child: Child::Stopped,
            backoff: Backoff::default(),
            crashes: VecDeque::new(),
            restarting: None,
            rss: 0,
            quiet_since: None,
        }
    }
}

impl Inner {
    /// Refuses a connection: a best-effort reply on its own thread, and the close at `now +
    /// REFUSAL_GRACE` owned by the tick, independent of the reply write. The reply thread never
    /// closes after a successful write: closing discards what the peer has not read yet (a named
    /// pipe disconnect on Windows), which dropped the reply. Once stopped, close immediately
    /// without writing or registering a deadline: no tick remains to own cleanup.
    fn refuse(
        &self,
        w: Option<Box<dyn Write + Send>>,
        close: Closer,
        reply: HubReply,
        now: Instant,
    ) {
        // `close_all` sets `stopped` before taking this lock to drain `closing`: if we
        // are not stopped here, shutdown will close this entry.
        let slot: Slot = Arc::new(Mutex::new(w));
        {
            let mut map = lock(&self.map);
            if self.stopped.load(Ordering::SeqCst) {
                drop(map);
                close();
                return;
            }
            map.closing
                .push((now + REFUSAL_GRACE, close.clone(), slot.clone()));
        }
        let theirs = slot.clone();
        // No thread: close at once, which also drops the reply.
        if spawn(move || {
            let w = lock(&theirs).take();
            if let Some(mut w) = w {
                write_reply(&mut w, &reply);
                *lock(&theirs) = Some(w);
            }
        })
        .is_err()
        {
            close();
            lock(&slot).take();
        }
    }

    fn note(&self, msg: String) {
        let mut notes = lock(&self.notes);
        if notes.len() == MAX_NOTES {
            notes.pop_front();
        }
        notes.push_back(msg);
    }

    /// The configured server `name`, including those a reload added.
    fn server(&self, name: &str) -> Option<Arc<McpServer>> {
        lock(&self.servers).get(name).cloned()
    }

    /// A hello named a server the hub does not know: rereads the config (at most once every
    /// `RELOAD_EVERY`) and adds every server it does not have yet, never changing or removing
    /// one. A config that does not load changes nothing. Then looks `name` up again.
    fn reload(&self, name: &str) -> Option<Arc<McpServer>> {
        let reload = self.reload.as_ref()?;
        let now = Instant::now();
        // Held while rereading: a hello for the same new name waits here, then finds it.
        let mut last = lock(&self.reloaded);
        if last.is_none_or(|t| now.saturating_duration_since(t) >= RELOAD_EVERY) {
            *last = Some(now);
            match reload() {
                // A category and a location, never parser text: it can quote an `env` value, and
                // notes reach `sync_gate status`.
                Err(e) => self.note(format!("mcp: {e}")),
                Ok(mcp) => {
                    let mut added = Vec::new();
                    {
                        let mut servers = lock(&self.servers);
                        for (n, srv) in mcp {
                            if let std::collections::btree_map::Entry::Vacant(v) = servers.entry(n)
                            {
                                added.push(v.key().clone());
                                v.insert(Arc::new(srv));
                            }
                        }
                    }
                    for n in added {
                        self.note(format!("mcp {n}: added from the config"));
                    }
                }
            }
        }
        drop(last);
        self.server(name)
    }

    /// Performs what unit `i`'s mux asked for, without blocking: pushes to queues, records notes.
    /// A client whose queue is full is disconnected (from every unit, and its queued requests
    /// dropped), and what its detach produces is performed too.
    fn dispatch(&self, server: &str, g: &mut Inst, i: usize, outs: Vec<Out>, now: Instant) {
        let mut work: VecDeque<(usize, Out)> = outs.into_iter().map(|o| (i, o)).collect();
        while let Some((i, out)) = work.pop_front() {
            match out {
                Out::ToChild(line) => {
                    if let Some(Child::Running(run)) = g.units.get_mut(i).map(|u| &mut u.child) {
                        if !run.stdin.push(line.into_bytes()) && !run.full_noted {
                            run.full_noted = true;
                            self.note(format!(
                                "mcp {server}: child input queue full; messages dropped"
                            ));
                        }
                    }
                }
                Out::ToClient(c, line) => {
                    let full = g
                        .clients
                        .get(&c)
                        .is_some_and(|p| !p.q.push(line.into_bytes()));
                    if let Some(p) = full.then(|| g.clients.remove(&c)).flatten() {
                        (p.close)();
                        self.note(format!(
                            "mcp {server}: client disconnected (output queue full)"
                        ));
                        g.queue.retain(|w| w.client != c);
                        for (j, u) in g.units.iter_mut().enumerate() {
                            work.extend(u.mux.client_detached(c).into_iter().map(|o| (j, o)));
                        }
                    }
                }
                Out::Note(n) => self.note(mux_note(server, &n)),
            }
        }
        if g.clients.is_empty() && g.idle_since.is_none() {
            g.idle_since = Some(now);
        }
    }

    /// After any mux event: a child a mux gave up on is taken out (to be stopped by the
    /// caller, outside the lock). `failed` restarts through the backoff; `unsupported` does not.
    fn check_all(&self, server: &str, g: &mut Inst, now: Instant) -> Vec<Run> {
        let mut stops = Vec::new();
        for i in 0..g.units.len() {
            let u = &mut g.units[i];
            if u.mux.unsupported() {
                if matches!(u.child, Child::Unsupported) {
                    continue;
                }
                let old = std::mem::replace(&mut u.child, Child::Unsupported);
                self.note(format!(
                    "mcp {server}: no supported protocol version; not restarting"
                ));
                stops.extend(running(old));
                if i == 0 {
                    self.fall_back(server, g, "unsupported protocol version", now);
                }
            } else if u.mux.failed() && matches!(u.child, Child::Running(_)) {
                let old = std::mem::replace(&mut u.child, Child::Stopped);
                let outs = u.mux.child_exited();
                self.crashed(server, g, i, now, "initialize failed");
                // After a fall-back the clients are gone: nobody is answered.
                self.dispatch(server, g, i, outs, now);
                stops.extend(running(old));
            }
        }
        stops
    }

    /// Unit `i`'s child is gone or given up on: wait for the backoff, or pause after a crash
    /// loop (which, for the first unit, makes the key unavailable through the hub).
    fn crashed(&self, server: &str, g: &mut Inst, i: usize, now: Instant, why: &'static str) {
        let u = &mut g.units[i];
        u.crashes
            .retain(|t| now.saturating_duration_since(*t) < CRASH_WINDOW);
        u.crashes.push_back(now);
        u.restarting = Some(why);
        if u.crashes.len() < CRASH_LIMIT {
            u.child = Child::Waiting {
                until: now + u.backoff.next(),
                crash_loop: false,
            };
            return;
        }
        pause(u, now);
        self.note(format!(
            "mcp {server}: keeps crashing ({CRASH_LIMIT} exits in 60 s); pausing restarts for 5 min"
        ));
        if i == 0 {
            self.fall_back(server, g, "keeps crashing", now);
        }
    }

    /// The key cannot run through the hub (ruling P22): every client is closed at once and none
    /// of their queued or in-flight requests is answered; the relay answers its in-flight ones,
    /// replays only `initialize` and continues on a direct server. One note per transition.
    fn fall_back(&self, server: &str, g: &mut Inst, reason: &str, now: Instant) {
        g.queue.clear();
        let gone: Vec<(ClientId, Peer)> = g.clients.drain().collect();
        for (_, p) in &gone {
            (p.close)();
        }
        // Removed first, so what the detaches produce for these clients is dropped.
        for (c, _) in gone {
            for i in 0..g.units.len() {
                let outs = g.units[i].mux.client_detached(c);
                self.dispatch(server, g, i, outs, now);
            }
        }
        self.note(format!(
            "mcp {server}: unavailable through the hub ({reason}); sessions run it directly"
        ));
    }

    /// Starts the child of unit `uid` marked `Starting`. Blocking spawn, outside every lock.
    fn start_child(self: &Arc<Self>, inst: &Arc<Instance>, uid: u64) {
        let server = &inst.key.server;
        let Some(srv) = self.server(server) else {
            return;
        };
        let env = launch_env(&srv, &inst.key.env);
        // A forwarded name the session does not have must not come from the daemon's environment.
        let env_remove: Vec<String> = srv
            .env_from
            .iter()
            .filter(|n| !inst.key.env.contains_key(*n))
            .cloned()
            .collect();
        let cwd = if srv.inherits_cwd() {
            inst.key.cwd.as_deref()
        } else {
            srv.cwd.as_deref().map(Path::new)
        };
        // Once the hub was told to stop (or the key retired, or the unit shrunk) nothing is
        // spawned. `close_all` sets `stopped` before it takes this lock, so a stop that arrives
        // after this check is caught by the check after the spawn (the child is recorded first).
        {
            let g = lock(&inst.st);
            let starting = g
                .units
                .iter()
                .any(|u| u.id == uid && matches!(u.child, Child::Starting));
            if !starting || g.retired || self.stopped.load(Ordering::SeqCst) {
                return;
            }
        }
        let now = Instant::now();
        // The hello never approves a path that is not Unicode; if one got here anyway, the empty
        // name fails the start (never a lossy name, which could be another file).
        let program = inst
            .key
            .program
            .as_deref()
            .map(|p| p.to_str().unwrap_or(""));
        let spawned = self.launcher.spawn(
            program.unwrap_or(&srv.command),
            &srv.args,
            &env,
            &env_remove,
            cwd,
        );
        drop(env);
        let Spawned {
            pid,
            start_time,
            exe,
            stdin,
            stdout,
        } = match spawned {
            Ok(s) => s,
            Err(e) => {
                let mut guard = lock(&inst.st);
                let g = &mut *guard;
                let unit = g
                    .units
                    .iter()
                    .position(|u| u.id == uid && matches!(u.child, Child::Starting));
                if let Some(i) = unit {
                    self.note(format!("mcp {server}: cannot start: {e}"));
                    if i == 0 {
                        // Never retried in a tight loop: the same pause as a crash loop.
                        g.units[0].restarting = None;
                        pause(&mut g.units[0], now);
                        self.fall_back(server, g, "cannot start", now);
                    } else {
                        self.crashed(server, g, i, now, "start failed");
                    }
                }
                return;
            }
        };
        if let Some(reg) = &self.registry {
            lock(reg).record(server, pid, start_time, &exe);
        }
        let generation = self.next_generation.fetch_add(1, Ordering::SeqCst);
        let (q, rx, bytes) = Queue::new(CHILD_QUEUE_MESSAGES, CHILD_QUEUE_BYTES);
        let run = Run {
            pid,
            start_time,
            generation,
            stdin: q,
            started: now,
            full_noted: false,
        };
        let mut guard = lock(&inst.st);
        let g = &mut *guard;
        // Gone means shrunk (or retired) while the spawn ran: stop what was started.
        let unit = g
            .units
            .iter()
            .position(|u| u.id == uid && matches!(u.child, Child::Starting));
        let i = match unit {
            Some(i) if !g.retired && !self.stopped.load(Ordering::SeqCst) => i,
            _ => {
                drop(guard);
                drop((stdin, stdout));
                return self.stop_now(server, run);
            }
        };
        // Threads start under the lock so the reader cannot see the child before it is Running.
        let threads = spawn_parsing(move || drain(rx, bytes, stdin)).and_then(|()| {
            let (me, inst2) = (self.clone(), inst.clone());
            spawn_parsing(move || me.child_reader(&inst2, generation, stdout))
        });
        if let Err(e) = threads {
            self.note(format!("mcp {server}: cannot serve the child: {e}"));
            self.crashed(server, g, i, now, "start failed");
            drop(guard);
            return self.stop_now(server, run);
        }
        let u = &mut g.units[i];
        u.child = Child::Running(run);
        // A new process: not measured yet.
        u.rss = 0;
        if let Some(why) = u.restarting.take() {
            *lock(&self.restarts).entry(server.clone()).or_default() += 1;
            self.note(format!("mcp {server}: restarted ({why})"));
        }
        let outs = u.mux.child_started(now);
        self.dispatch(server, g, i, outs, now);
    }

    /// Stops an own child through the supervisor and forgets its registry row. Blocking.
    fn stop_now(&self, server: &str, run: Run) {
        let Run {
            pid,
            start_time,
            stdin,
            ..
        } = run;
        // Dropping the queue ends the writer thread, which closes the child's stdin.
        drop(stdin);
        if let Err(e) = stop_own(&*self.launcher, pid, start_time, None, self.stop_grace) {
            self.note(format!("mcp {server}: cannot stop pid {pid}: {e}"));
            return;
        }
        if let Some(reg) = &self.registry {
            lock(reg).forget(pid);
        }
    }

    fn stop_later(self: &Arc<Self>, server: String, run: Run) {
        let me = self.clone();
        spawn_or_inline(move || me.stop_now(&server, run));
    }

    fn client_reader(
        self: &Arc<Self>,
        inst: &Arc<Instance>,
        id: ClientId,
        r: Box<dyn Read + Send>,
        close: &Closer,
    ) {
        let mut r = BufReader::new(r);
        let mut buf = Vec::new();
        loop {
            let alive = match read_line(&mut r, MAX_MESSAGE_BYTES, &mut buf) {
                Ok(Line::Data) if !too_deep(&buf) => {
                    let line = String::from_utf8_lossy(&buf);
                    self.client_line(inst, id, Some(&line), Instant::now())
                }
                Ok(Line::Data | Line::TooLong) => self.client_line(inst, id, None, Instant::now()),
                Ok(Line::Eof) | Err(_) => false,
            };
            if buf.capacity() > KEEP_BUF {
                buf = Vec::new();
            }
            if !alive {
                break;
            }
        }
        self.drop_client(inst, id, Instant::now());
        close();
    }

    /// One line from a client (`None`: oversized or nested too deeply). False once the client is detached.
    fn client_line(
        self: &Arc<Self>,
        inst: &Arc<Instance>,
        id: ClientId,
        line: Option<&str>,
        now: Instant,
    ) -> bool {
        let server = &inst.key.server;
        let stops = {
            let mut guard = lock(&inst.st);
            let g = &mut *guard;
            if !g.clients.contains_key(&id) {
                return false;
            }
            match line {
                // Same reply as the mux's oversize path, without handing it 64 MiB.
                None => {
                    let e = error_response(&Value::Null, -32700, "parse error").to_string();
                    self.dispatch(server, g, 0, vec![Out::ToClient(id, e)], now);
                }
                Some(l) => self.route(server, g, id, l, now),
            }
            self.settle(server, g, now);
            self.check_all(server, g, now)
        };
        for run in stops {
            self.stop_later(server.clone(), run);
        }
        true
    }

    /// `max_instances` and `max_in_flight` of a server.
    fn limits(&self, server: &str) -> (u32, u32) {
        self.server(server)
            .map_or((1, u32::MAX), |s| (s.max_instances, s.max_in_flight))
    }

    fn request_timeout(&self, server: &str) -> Duration {
        Duration::from_secs(self.server(server).map_or(0, |s| s.request_timeout_secs))
    }

    /// Sends one client line to its unit, or queues it in the hub (see the module docs).
    fn route(&self, server: &str, g: &mut Inst, c: ClientId, line: &str, now: Instant) {
        let (max_instances, max_in_flight) = self.limits(server);
        // One instance: no cap, no hub queue, every line to the single mux (as before pools).
        let parsed = if max_instances > 1 {
            serde_json::from_str::<Value>(line.trim()).ok()
        } else {
            None
        };
        let Some(v) = parsed else {
            return self.to_unit(server, g, 0, c, line, now);
        };
        match classify(&v) {
            Kind::Request { id: rid, method } if method != "initialize" => {
                match target(g, c, max_in_flight) {
                    Some(i) => self.to_unit(server, g, i, c, line, now),
                    None => self.enqueue(server, g, c, rid, line, now),
                }
            }
            Kind::Notification { method } if method == "notifications/cancelled" => {
                if let Some(t) = v.pointer("/params/requestId") {
                    g.queue.retain(|w| w.client != c || w.rid != *t);
                }
                // Each mux ignores ids it does not own.
                for i in 0..g.units.len() {
                    self.to_unit(server, g, i, c, line, now);
                }
            }
            _ => self.to_unit(server, g, 0, c, line, now),
        }
    }

    fn to_unit(&self, server: &str, g: &mut Inst, i: usize, c: ClientId, line: &str, now: Instant) {
        let u = &mut g.units[i];
        // An extra unit in its crash-loop pause (a subscriber pinned to it): the hub answers.
        let outs = if crash_looping(&u.child) {
            keeps_crashing(c, line)
        } else {
            u.mux.client_line(c, line, now)
        };
        self.dispatch(server, g, i, outs, now);
    }

    /// Queues a request for a unit with room, within the per-client bounds of a mux's queue.
    fn enqueue(
        &self,
        server: &str,
        g: &mut Inst,
        c: ClientId,
        rid: Value,
        line: &str,
        now: Instant,
    ) {
        let (n, bytes) = g
            .queue
            .iter()
            .filter(|w| w.client == c)
            .fold((0, 0), |(n, b), w| (n + 1, b + w.line.len()));
        if n >= MAX_QUEUED_PER_CLIENT || bytes + line.len() > MAX_QUEUED_BYTES_PER_CLIENT {
            let busy = error_response(&rid, -32000, "mcp server busy").to_string();
            return self.dispatch(server, g, 0, vec![Out::ToClient(c, busy)], now);
        }
        g.queue.push_back(Waiting {
            client: c,
            rid,
            line: line.to_string(),
            since: now,
            deadline: now + self.request_timeout(server),
        });
    }

    /// Answers queued requests whose deadline passed, as a mux answers a timed-out request.
    fn expire_queue(&self, server: &str, g: &mut Inst, now: Instant) {
        let (expired, keep): (Vec<Waiting>, Vec<Waiting>) = std::mem::take(&mut g.queue)
            .into_iter()
            .partition(|w| now >= w.deadline);
        g.queue = keep.into();
        for w in expired {
            let e = error_response(&w.rid, -32001, "request timed out").to_string();
            self.dispatch(server, g, 0, vec![Out::ToClient(w.client, e)], now);
        }
    }

    /// After any event that may have made room or changed a handshake: serves the hub queue in
    /// order, shares handshakes across units, and tracks how long each unit has been quiet.
    fn settle(&self, server: &str, g: &mut Inst, now: Instant) {
        let (_, max_in_flight) = self.limits(server);
        let mut i = 0;
        while i < g.queue.len() {
            match target(g, g.queue[i].client, max_in_flight) {
                Some(u) => {
                    if let Some(w) = g.queue.remove(i) {
                        self.to_unit(server, g, u, w.client, &w.line, now);
                    }
                }
                None => i += 1,
            }
        }
        if g.units.len() > 1 {
            let shaken: Vec<ClientId> = g
                .clients
                .keys()
                .copied()
                .filter(|c| g.units.iter().any(|u| u.mux.handshaken(*c)))
                .collect();
            for u in &mut g.units {
                for c in &shaken {
                    u.mux.mark_handshaken(*c);
                }
            }
        }
        for u in &mut g.units {
            if u.mux.in_flight() > 0 {
                u.quiet_since = None;
            } else if u.quiet_since.is_none() {
                u.quiet_since = Some(now);
            }
        }
    }

    /// The pool decision of one key (tick only). Returns units to start and children to stop.
    fn scale(
        &self,
        server: &str,
        g: &mut Inst,
        memory: Option<(u64, u64)>,
        now: Instant,
    ) -> (Vec<u64>, Vec<Run>) {
        let (max_instances, max_in_flight) = self.limits(server);
        let (mut starts, mut stops) = (Vec::new(), Vec::new());
        if max_instances <= 1 {
            return (starts, stops);
        }
        let s = stats(g, now);
        if s.queued == 0 {
            g.memory_noted = false;
        }
        let Some((free, reserve)) = memory else {
            return (starts, stops);
        };
        match decide(&s, max_instances, max_in_flight, free, reserve) {
            PoolAction::Grow => {
                g.memory_noted = false;
                let mut u = Unit::new(g.next_unit, server, self.request_timeout(server));
                g.next_unit += 1;
                // Handshakes are shared by `settle`, before the child can send anything.
                for c in g.clients.keys() {
                    u.mux.client_attached(*c);
                }
                u.child = Child::Starting;
                u.quiet_since = Some(now);
                starts.push(u.id);
                g.units.push(u);
                self.note(format!(
                    "mcp {server}: scaling up to {} instances",
                    g.units.len()
                ));
            }
            PoolAction::Shrink { instance } if instance < g.units.len() => {
                let u = g.units.remove(instance);
                stops.extend(running(u.child));
                let n = g.units.len();
                let s = if n == 1 { "" } else { "s" };
                self.note(format!("mcp {server}: scaling down to {n} instance{s}"));
            }
            PoolAction::Shrink { .. } => {}
            PoolAction::None => {
                if wants_to_grow(&s, max_instances, max_in_flight) && !g.memory_noted {
                    g.memory_noted = true;
                    self.note(format!("mcp {server}: not scaling, memory is the limit"));
                }
            }
        }
        (starts, stops)
    }

    fn drop_client(&self, inst: &Instance, id: ClientId, now: Instant) {
        let server = &inst.key.server;
        let mut guard = lock(&inst.st);
        let g = &mut *guard;
        if g.clients.remove(&id).is_none() {
            return;
        }
        // Its queued requests go silently.
        g.queue.retain(|w| w.client != id);
        for i in 0..g.units.len() {
            let outs = g.units[i].mux.client_detached(id);
            self.dispatch(server, g, i, outs, now);
        }
        self.settle(server, g, now);
    }

    fn child_reader(
        self: &Arc<Self>,
        inst: &Arc<Instance>,
        generation: u64,
        out: Box<dyn Read + Send>,
    ) {
        let mut r = BufReader::new(out);
        let mut buf = Vec::new();
        loop {
            let current = match read_line(&mut r, MAX_MESSAGE_BYTES, &mut buf) {
                Ok(Line::Data) if !too_deep(&buf) => {
                    let line = String::from_utf8_lossy(&buf);
                    self.child_line(inst, generation, Some(&line))
                }
                Ok(Line::Data | Line::TooLong) => self.child_line(inst, generation, None),
                Ok(Line::Eof) | Err(_) => break,
            };
            if buf.capacity() > KEEP_BUF {
                buf = Vec::new();
            }
            if !current {
                return;
            }
        }
        self.child_gone(inst, generation, Instant::now());
    }

    /// One line from the child (`None`: oversized or nested too deeply). False once this child is no longer current.
    fn child_line(
        self: &Arc<Self>,
        inst: &Arc<Instance>,
        generation: u64,
        line: Option<&str>,
    ) -> bool {
        let server = &inst.key.server;
        let now = Instant::now();
        let stops = {
            let mut guard = lock(&inst.st);
            let g = &mut *guard;
            let Some(i) = unit_of(g, generation) else {
                return false;
            };
            let outs = match line {
                Some(l) => g.units[i].mux.child_line(l, now),
                None => vec![Out::Note(format!(
                    "{server}: unusable line from child dropped (too long or too deeply nested)"
                ))],
            };
            // Before the dispatch: a key this line makes unavailable (unsupported, or the
            // failure that starts the crash-loop pause) drops its clients first, so none of
            // them gets the answers the mux just produced (ruling P22).
            let stops = self.check_all(server, g, now);
            self.dispatch(server, g, i, outs, now);
            self.settle(server, g, now);
            stops
        };
        for run in stops {
            self.stop_later(server.clone(), run);
        }
        true
    }

    /// The current child's stdout ended: it crashed (or closed its output). Runs on that
    /// child's reader thread, which then makes sure the process is gone.
    fn child_gone(&self, inst: &Instance, generation: u64, now: Instant) {
        let server = &inst.key.server;
        let run = {
            let mut guard = lock(&inst.st);
            let g = &mut *guard;
            let Some(i) = unit_of(g, generation) else {
                return;
            };
            let old = std::mem::replace(&mut g.units[i].child, Child::Stopped);
            let outs = g.units[i].mux.child_exited();
            self.crashed(server, g, i, now, "child exited");
            // After a fall-back the clients are gone: nobody is answered.
            self.dispatch(server, g, i, outs, now);
            running(old)
        };
        if let Some(run) = run {
            self.stop_now(server, run);
        }
    }
}

/// What a server's child gets on top of the daemon's environment: its fixed `env`, then the
/// session's `env_from` values (the key's).
fn launch_env(srv: &McpServer, key_env: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut env = srv.env.clone();
    env.extend(key_env.iter().map(|(k, v)| (k.clone(), v.clone())));
    env
}

/// The same file: canonical paths (as given when one does not resolve), ignoring case on Windows.
fn same_program(a: &Path, b: &Path) -> bool {
    let canon = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let (a, b) = (canon(a), canon(b));
    if cfg!(windows) {
        a.to_string_lossy().to_lowercase() == b.to_string_lossy().to_lowercase()
    } else {
        a == b
    }
}

/// The unit whose current child has this generation.
fn unit_of(g: &Inst, generation: u64) -> Option<usize> {
    g.units
        .iter()
        .position(|u| matches!(&u.child, Child::Running(r) if r.generation == generation))
}

/// Where a request of client `c` goes now; `None`: it waits in the hub queue.
fn target(g: &Inst, c: ClientId, max_in_flight: u32) -> Option<usize> {
    let room = |u: &Unit| u.mux.ready() && load(u) < max_in_flight;
    let single = g.units.len() == 1;
    // A subscriber stays on the unit that holds its subscription.
    if let Some(p) = g.units.iter().position(|u| u.mux.holds_subscriptions(c)) {
        let u = &g.units[p];
        let fallback = !u.mux.ready() && (single || crash_looping(&u.child));
        return (room(u) || fallback).then_some(p);
    }
    let loads: Vec<u32> = g
        .units
        .iter()
        .map(|u| {
            if u.mux.ready() {
                load(u)
            } else {
                max_in_flight
            }
        })
        .collect();
    // Nothing ready with one unit: it queues in its mux as before pools. (Every unit dead
    // means the first one is, and then the key has no clients: see `fall_back`.)
    pick_instance(&loads, max_in_flight)
        .or_else(|| (single && !g.units.iter().any(|u| u.mux.ready())).then_some(0))
}

/// The pool as `decide` sees it. Requests waiting for a subscriber's unit are left out (a new
/// unit would not serve them) and that unit never counts as idle. Neither does a unit in its
/// crash-loop pause or one that came up unsupported: shrinking them would drop the Task 5 state
/// that stops respawning, and the pool would grow a fresh copy at once. With 0 in flight they
/// also block growth (`wants_to_grow` needs every unit full); unsupported, for good.
fn stats(g: &Inst, now: Instant) -> PoolStats {
    let pinned = |c: ClientId| g.units.iter().any(|u| u.mux.holds_subscriptions(c));
    let free: Vec<&Waiting> = g.queue.iter().filter(|w| !pinned(w.client)).collect();
    PoolStats {
        instances: u32::try_from(g.units.len()).unwrap_or(u32::MAX),
        in_flight: g.units.iter().map(load).collect(),
        queued: u32::try_from(free.len()).unwrap_or(u32::MAX),
        oldest_wait: free
            .first()
            .map_or(Duration::ZERO, |w| now.saturating_duration_since(w.since)),
        idle_for: g
            .units
            .iter()
            .map(|u| {
                let holds = g.clients.keys().any(|c| u.mux.holds_subscriptions(*c));
                let kept = crash_looping(&u.child) || matches!(u.child, Child::Unsupported);
                match u.quiet_since {
                    Some(t) if !holds && !kept => now.saturating_duration_since(t),
                    _ => Duration::ZERO,
                }
            })
            .collect(),
        instance_rss: g.peak_rss,
    }
}

/// Estimated memory of a key's instances that the last snapshot may not show yet: starting,
/// or running but not measured since they started.
fn unmeasured(g: &Inst) -> u64 {
    let n = g
        .units
        .iter()
        .filter(|u| match u.child {
            Child::Starting => true,
            Child::Running(_) => u.rss == 0,
            _ => false,
        })
        .count();
    g.peak_rss.saturating_mul(n as u64)
}

/// True while the key cannot run through the hub: its first unit is in its crash-loop pause
/// (also after a spawn error) or came up unsupported.
fn unavailable(g: &Inst) -> bool {
    g.units
        .first()
        .is_some_and(|u| crash_looping(&u.child) || matches!(u.child, Child::Unsupported))
}

/// The crash-loop pause: no restart until it ends.
fn pause(u: &mut Unit, now: Instant) {
    u.crashes.clear();
    u.child = Child::Waiting {
        until: now + CRASH_PAUSE,
        crash_loop: true,
    };
}

/// An extra unit in its crash-loop pause: the hub answers its pinned subscribers itself.
fn keeps_crashing(id: ClientId, line: &str) -> Vec<Out> {
    let Ok(v) = serde_json::from_str::<Value>(line.trim()) else {
        return Vec::new();
    };
    match classify(&v) {
        Kind::Request { id: rid, .. } => vec![Out::ToClient(
            id,
            error_response(&rid, -32000, KEEPS_CRASHING).to_string(),
        )],
        _ => Vec::new(),
    }
}

#[cfg(test)]
pub(crate) mod testkit;

#[cfg(test)]
mod tests;
