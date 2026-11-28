//! The relay against a scripted test hub (`sync_gated::ipc::serve_stream`) and a directly started
//! server: this test binary re-executed in `mcp-echo` mode (`SYNC_GATE_TEST_CHILD`).

use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use sync_gate_core::{Config, HubHello, HubReply, McpMode, McpServer};

const BOUND: Duration = Duration::from_secs(30);
static COUNTER: AtomicU32 = AtomicU32::new(0);

/// Re-executed as the directly started server. Mode `mcp-echo:<exit code>:<file>`: answers every
/// request with `{"echo": <method>}`, appends every received method to `<file>`, and exits with
/// the code on stdin EOF.
#[test]
fn child_entry() {
    let Ok(spec) = std::env::var("SYNC_GATE_TEST_CHILD") else {
        return;
    };
    if spec == "exit" {
        std::process::exit(0);
    }
    if let Some(file) = spec.strip_prefix("ignore:") {
        let starting = format!("{file}.starting");
        std::fs::write(&starting, std::process::id().to_string()).unwrap();
        std::fs::rename(starting, file).unwrap();
        let mut bytes = Vec::new();
        std::io::stdin().read_to_end(&mut bytes).unwrap();
        std::fs::write(format!("{file}.eof"), b"eof").unwrap();
        loop {
            std::thread::park();
        }
    }
    if let Some(file) = spec.strip_prefix("stall:") {
        // Publishes its pid, reads one byte (`<file>.got`: a write to it has begun) and then
        // never reads again, so a large write to it stays blocked.
        let starting = format!("{file}.starting");
        std::fs::write(&starting, std::process::id().to_string()).unwrap();
        std::fs::rename(starting, file).unwrap();
        std::io::stdin().read_exact(&mut [0u8]).unwrap();
        std::fs::write(format!("{file}.got"), b"1").unwrap();
        loop {
            std::thread::park();
        }
    }
    if spec == "never" {
        let mut bytes = Vec::new();
        std::io::stdin().read_to_end(&mut bytes).unwrap();
        std::process::exit(0);
    }
    if spec == "close-stdout" {
        #[cfg(windows)]
        unsafe {
            use windows_sys::Win32::{
                Foundation::CloseHandle,
                System::Console::{GetStdHandle, STD_OUTPUT_HANDLE},
            };
            CloseHandle(GetStdHandle(STD_OUTPUT_HANDLE));
        }
        #[cfg(unix)]
        {
            use std::os::fd::FromRawFd;
            drop(unsafe { std::fs::File::from_raw_fd(1) });
        }
        let mut bytes = Vec::new();
        std::io::stdin().read_to_end(&mut bytes).unwrap();
        std::process::exit(0);
    }
    let mut parts = spec.splitn(3, ':');
    assert_eq!(parts.next(), Some("mcp-echo"));
    let code: i32 = parts.next().unwrap().parse().unwrap();
    let file = parts.next().unwrap().to_string();
    let mut log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&file)
        .unwrap();
    // The harness prints `test child_entry ... ` without a newline first.
    println!();
    if let Ok(ms) = std::env::var("SYNC_GATE_TEST_START_DELAY_MS") {
        std::thread::sleep(Duration::from_millis(ms.parse().unwrap()));
    }
    // `SYNC_GATE_TEST_NEED_INIT`: a strict server that refuses every request before `initialize`.
    let strict = std::env::var_os("SYNC_GATE_TEST_NEED_INIT").is_some();
    // `SYNC_GATE_TEST_REJECT_INIT`: answers `initialize` with an error and stays uninitialized.
    let rejects = std::env::var_os("SYNC_GATE_TEST_REJECT_INIT").is_some();
    let mut initialized = false;
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        if let Ok(file) = std::env::var("SYNC_GATE_TEST_LINES") {
            let mut log = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(file)
                .unwrap();
            writeln!(log, "{line}").unwrap();
        }
        let Ok(v) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let method = v["method"].as_str().unwrap_or_default().to_string();
        writeln!(log, "{method}").unwrap();
        initialized |= method == "initialize" && !rejects;
        // `SYNC_GATE_TEST_INIT_REPLY`: a 2 MiB reply to `initialize` that is not a success:
        // `truncated` (its line ends mid-JSON) or `both` (a `result`, then an `error`).
        if let Ok(kind) = std::env::var("SYNC_GATE_TEST_INIT_REPLY")
            && method == "initialize"
        {
            let (id, pad) = (&v["id"], "x".repeat(2 << 20));
            let head = format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{{"padding":"{pad}""#);
            let line = if kind == "truncated" {
                head
            } else {
                format!(r#"{head}}},"error":{{"code":-1,"message":"no"}}}}"#)
            };
            println!("{line}");
            std::io::stdout().flush().unwrap();
            continue;
        }
        if v.get("id").is_some() && method == "initialize" && rejects {
            let reply = json!({"jsonrpc":"2.0","id":v["id"],"error":{"code":-32603,"message":"initialize refused"}});
            println!("{reply}");
            std::io::stdout().flush().unwrap();
        } else if v.get("id").is_some() && strict && !initialized {
            let reply = json!({"jsonrpc":"2.0","id":v["id"],"error":{"code":-32002,"message":"not initialized"}});
            println!("{reply}");
            std::io::stdout().flush().unwrap();
        } else if v.get("id").is_some() {
            if method == "initialize" && std::env::var_os("SYNC_GATE_TEST_ROOTS").is_some() {
                println!(
                    "{}",
                    json!({"jsonrpc":"2.0","id":v["id"],"method":"roots/list"})
                );
            }
            let result = if method == "initialize"
                && std::env::var_os("SYNC_GATE_TEST_BIG_REPLY").is_some()
            {
                json!({"padding":"x".repeat(2 << 20)})
            } else if method == "initialize" && std::env::var_os("SYNC_GATE_TEST_CWD").is_some() {
                let cwd = std::env::current_dir().unwrap();
                json!({"echo":method,"cwd":cwd.to_string_lossy()})
            } else {
                json!({"echo":method})
            };
            let reply = json!({"jsonrpc":"2.0","id":v["id"],"result":result});
            println!("{reply}");
            std::io::stdout().flush().unwrap();
        }
    }
    if let Ok(file) = std::env::var("SYNC_GATE_TEST_EOF") {
        std::fs::write(file, b"eof").unwrap();
    }
    std::process::exit(code);
}

fn tmp_name(tag: &str) -> String {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let id = format!("sync_gate_shim-{}-{n}-{tag}", std::process::id());
    if cfg!(windows) {
        id
    } else {
        std::env::temp_dir().join(id).to_string_lossy().into_owned()
    }
}

/// A config with one server `docs` whose command is this test binary in `mcp-echo` mode.
fn config(mode: McpMode, exit_code: i32, methods: &std::path::Path) -> Config {
    let exe = std::env::current_exe().unwrap();
    let srv = McpServer {
        command: exe.to_string_lossy().into_owned(),
        args: ["child_entry", "--exact", "--nocapture", "--test-threads=1"]
            .map(String::from)
            .to_vec(),
        env: BTreeMap::from([(
            "SYNC_GATE_TEST_CHILD".to_string(),
            format!("mcp-echo:{exit_code}:{}", methods.display()),
        )]),
        env_from: vec!["PATH".into()],
        mode,
        ..McpServer::default()
    };
    Config {
        mcp: BTreeMap::from([("docs".to_string(), srv)]),
        ..Config::default()
    }
}

/// The client's stdin: bytes sent through a channel; EOF when the sender is dropped. The third
/// field counts the bytes the relay has taken.
struct Stdin(mpsc::Receiver<Vec<u8>>, Vec<u8>, Arc<AtomicUsize>);

impl Read for Stdin {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.1.is_empty() {
            match self.0.recv() {
                Ok(b) => self.1 = b,
                Err(_) => return Ok(0),
            }
        }
        let n = buf.len().min(self.1.len());
        buf[..n].copy_from_slice(&self.1[..n]);
        self.1.drain(..n);
        self.2.fetch_add(n, Ordering::SeqCst);
        Ok(n)
    }
}

/// Captured output (the client's stdout or the relay's stderr).
#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl Write for Sink {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Sink {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }

    /// JSON lines so far (a directly started test binary also prints harness lines: skipped).
    fn json(&self) -> Vec<Value> {
        self.text()
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    /// Waits for the JSON line with this id.
    fn reply(&self, id: i64) -> Value {
        let start = Instant::now();
        loop {
            if let Some(v) = self.json().into_iter().find(|v| v["id"] == id) {
                return v;
            }
            assert!(
                start.elapsed() < BOUND,
                "no reply for id {id}: {}",
                self.text()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// A relay running on its own thread.
struct Session {
    stdin: Option<mpsc::Sender<Vec<u8>>>,
    /// Bytes of the client's stdin the relay has read.
    read: Arc<AtomicUsize>,
    out: Sink,
    err: Sink,
    done: mpsc::Receiver<i32>,
}

impl Session {
    fn start(cfg: Config, hub: &str, server: &str) -> Session {
        Self::with_options(cfg, hub, server, sync_gate_shim::RunOptions::default())
    }

    fn with_options(
        cfg: Config,
        hub: &str,
        server: &str,
        options: sync_gate_shim::RunOptions,
    ) -> Session {
        let out = Sink::default();
        Self::with_stdout(cfg, hub, server, options, out.clone(), out)
    }

    /// `stdout` is what the relay writes to; `out` is the sink the test reads.
    fn with_stdout(
        cfg: Config,
        hub: &str,
        server: &str,
        options: sync_gate_shim::RunOptions,
        stdout: impl Write + Send + 'static,
        out: Sink,
    ) -> Session {
        let (tx, rx) = mpsc::channel();
        let err = Sink::default();
        let (o, e, hub, server) = (stdout, err.clone(), hub.to_string(), server.to_string());
        let (dtx, done) = mpsc::channel();
        let read = Arc::new(AtomicUsize::new(0));
        let r = read.clone();
        std::thread::spawn(move || {
            let code = sync_gate_shim::run_with_options(
                &cfg,
                &hub,
                &server,
                Stdin(rx, Vec::new(), r),
                o,
                e,
                options,
            );
            let _ = dtx.send(code);
        });
        Session {
            stdin: Some(tx),
            read,
            out,
            err,
            done,
        }
    }

    fn send(&self, v: Value) {
        self.stdin
            .as_ref()
            .unwrap()
            .send(format!("{v}\n").into_bytes())
            .unwrap();
    }

    /// Closes the client's stdin and returns the relay's exit code.
    fn finish(&mut self) -> i32 {
        self.stdin = None;
        self.done.recv_timeout(BOUND).expect("relay did not exit")
    }
}

fn request(id: i64, method: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":method})
}

/// What a test hub saw.
#[derive(Default)]
struct Seen {
    hello: Option<HubHello>,
    lines: Vec<Value>,
    connections: u32,
}

/// A hub answering the hello with `reply`; after `Ok` it answers every request with
/// `{"hub":<method>}`, except that a `tools/call` with id 5 closes the connection unanswered
/// when `drop_on_5` is set.
fn test_hub(
    name: &str,
    reply: HubReply,
    drop_on_5: bool,
) -> (sync_gated::ipc::ServerHandle, Arc<Mutex<Seen>>) {
    test_hub_dropping_on(name, reply, drop_on_5.then_some(5))
}

/// Like [`test_hub`], closing the connection unanswered at the request with this id.
fn test_hub_dropping_on(
    name: &str,
    reply: HubReply,
    drop_id: Option<i64>,
) -> (sync_gated::ipc::ServerHandle, Arc<Mutex<Seen>>) {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let s = seen.clone();
    let handle = sync_gated::ipc::serve_stream(name, move |r, mut w, close| {
        s.lock().unwrap().connections += 1;
        let mut r = BufReader::new(r);
        let mut line = String::new();
        if r.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        s.lock().unwrap().hello = serde_json::from_str(&line).ok();
        writeln!(w, "{}", serde_json::to_string(&reply).unwrap()).unwrap();
        if reply != HubReply::Ok {
            return;
        }
        line.clear();
        while r.read_line(&mut line).unwrap_or(0) > 0 {
            let v: Value = serde_json::from_str(&line).unwrap();
            line.clear();
            s.lock().unwrap().lines.push(v.clone());
            if drop_id.is_some_and(|id| v["id"] == id) {
                close();
                return;
            }
            // Requests 5.. before the dropped id stay unanswered, so they are in flight at the drop.
            let unanswered =
                drop_id.is_some_and(|d| v["id"].as_i64().is_some_and(|i| i >= 5 && i < d));
            if v.get("id").is_some() && !unanswered {
                let m = v["method"].clone();
                let r = json!({"jsonrpc":"2.0","id":v["id"],"result":{"hub":m}});
                if writeln!(w, "{r}").is_err() {
                    return;
                }
            }
        }
    })
    .unwrap();
    (handle, seen)
}

fn methods(file: &std::path::Path) -> Vec<String> {
    std::fs::read_to_string(file)
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect()
}

fn methods_file(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir()
        .join("trabalho/sync_gate/2026-11-13-task6-fix2/tests")
        .join(std::process::id().to_string());
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join(tmp_name(tag).replace(['/', '\\'], "_"));
    let _ = std::fs::remove_file(&p);
    p
}

#[test]
fn shared_server_goes_through_the_hub() {
    let (name, file) = (tmp_name("hub1"), methods_file("m1"));
    let (hub, seen) = test_hub(&name, HubReply::Ok, false);
    let mut s = Session::start(config(McpMode::Shared, 0, &file), &name, "docs");
    s.send(request(1, "tools/list"));
    assert_eq!(s.out.reply(1)["result"], json!({"hub":"tools/list"}));
    assert_eq!(s.finish(), 0);
    {
        let seen = seen.lock().unwrap();
        let hello = seen.hello.as_ref().unwrap();
        assert_eq!(hello.server, "docs");
        assert_eq!(hello.cwd, std::env::current_dir().unwrap());
        assert!(hello.env.contains_key("PATH") || hello.env.contains_key("Path"));
        assert_eq!(seen.lines.len(), 1);
    }
    assert!(methods(&file).is_empty(), "the real server must not run");
    assert!(s.err.text().is_empty(), "{}", s.err.text());
    hub.shutdown();
}

#[test]
fn per_session_server_is_run_directly() {
    let (name, file) = (tmp_name("hub2"), methods_file("m2"));
    let (hub, seen) = test_hub(&name, HubReply::Ok, false);
    let mut s = Session::start(config(McpMode::PerSession, 7, &file), &name, "docs");
    s.send(request(1, "tools/list"));
    assert_eq!(s.out.reply(1)["result"], json!({"echo":"tools/list"}));
    assert_eq!(s.finish(), 7, "the exit code is the server's");
    assert_eq!(seen.lock().unwrap().connections, 0);
    hub.shutdown();
}

#[test]
fn hub_replying_per_session_runs_the_server_without_a_warning() {
    let (name, file) = (tmp_name("hub3"), methods_file("m3"));
    let (hub, _) = test_hub(&name, HubReply::PerSession, false);
    let mut s = Session::start(config(McpMode::Shared, 0, &file), &name, "docs");
    s.send(request(1, "tools/list"));
    assert_eq!(s.out.reply(1)["result"], json!({"echo":"tools/list"}));
    assert_eq!(s.finish(), 0);
    assert!(s.err.text().is_empty(), "{}", s.err.text());
    hub.shutdown();
}

#[test]
fn hub_down_fails_open_with_one_warning() {
    let (name, file) = (tmp_name("nohub"), methods_file("m4"));
    let mut s = Session::start(config(McpMode::Shared, 0, &file), &name, "docs");
    s.send(request(1, "tools/list"));
    assert_eq!(s.out.reply(1)["result"], json!({"echo":"tools/list"}));
    assert_eq!(s.finish(), 0);
    let err = s.err.text();
    assert_eq!(err.matches("hub not available").count(), 1, "{err}");
    assert!(err.contains("running 'docs' directly"), "{err}");
}

#[test]
fn hub_lost_mid_session_replays_initialize_and_fails_in_flight() {
    let (name, file) = (tmp_name("hub5"), methods_file("m5"));
    let (hub, _) = test_hub(&name, HubReply::Ok, true);
    let mut s = Session::start(config(McpMode::Shared, 0, &file), &name, "docs");
    s.send(request(0, "initialize"));
    assert_eq!(s.out.reply(0)["result"], json!({"hub":"initialize"}));
    s.send(request(5, "tools/call"));
    let e = s.out.reply(5);
    assert_eq!(e["error"]["code"], -32000, "{e}");
    assert_eq!(
        e["error"]["message"],
        "hub connection lost; request not completed"
    );
    s.send(request(6, "tools/call"));
    assert_eq!(s.out.reply(6)["result"], json!({"echo":"tools/call"}));
    assert_eq!(s.finish(), 0);
    // The replayed initialize reply is swallowed; every in-flight id got exactly one reply
    // (all matches counted, not the first).
    for id in [0, 5, 6] {
        assert_eq!(
            s.out.json().iter().filter(|v| v["id"] == id).count(),
            1,
            "{}",
            s.out.text()
        );
    }
    assert_eq!(
        methods(&file),
        ["initialize", "notifications/initialized", "tools/call"]
    );
    assert_eq!(
        s.err
            .text()
            .matches("hub connection lost, running 'docs' directly")
            .count(),
        1
    );
    hub.shutdown();
}

#[test]
fn unknown_server_exits_2() {
    let file = methods_file("m6");
    let mut s = Session::start(config(McpMode::Shared, 0, &file), &tmp_name("x"), "nope");
    assert_eq!(s.done.recv_timeout(BOUND).unwrap(), 2);
    assert!(
        s.err.text().contains("unknown server 'nope'"),
        "{}",
        s.err.text()
    );
    s.stdin = None;
}

#[test]
fn unstartable_server_exits_127() {
    let mut cfg = config(McpMode::PerSession, 0, &methods_file("m7"));
    cfg.mcp.get_mut("docs").unwrap().command = "sync_gate-no-such-command".into();
    let s = Session::start(cfg, &tmp_name("x"), "docs");
    assert_eq!(s.done.recv_timeout(BOUND).unwrap(), 127);
    assert!(
        s.err.text().contains("cannot start 'docs':"),
        "{}",
        s.err.text()
    );
}

#[test]
fn stdin_eof_exits_0_and_leaves_the_hub_child_alone() {
    let (name, file) = (tmp_name("hub8"), methods_file("m8"));
    let (hub, seen) = test_hub(&name, HubReply::Ok, false);
    let mut s = Session::start(config(McpMode::Shared, 0, &file), &name, "docs");
    s.send(request(1, "tools/list"));
    s.out.reply(1);
    assert_eq!(s.finish(), 0);
    // Nothing but the client's own request reached the hub: no stop request of any kind.
    let seen = seen.lock().unwrap();
    assert_eq!(seen.lines.len(), 1);
    assert_eq!(seen.lines[0]["method"], "tools/list");
    assert!(methods(&file).is_empty());
    drop(seen);
    hub.shutdown();
}

#[test]
fn long_lines_pass_through_untouched() {
    let (name, file) = (tmp_name("hub9"), methods_file("m9"));
    let (hub, seen) = test_hub(&name, HubReply::Ok, false);
    let mut s = Session::start(config(McpMode::Shared, 0, &file), &name, "docs");
    // Over the 1 MiB parse limit: streamed while its id is tracked from the prefix.
    let big =
        json!({"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"x":"a".repeat(2 << 20)}});
    s.send(big);
    s.out.reply(9);
    assert_eq!(s.finish(), 0);
    assert_eq!(seen.lock().unwrap().lines.len(), 1);
    hub.shutdown();
}

#[test]
fn hub_eof_discards_an_unterminated_reply() {
    let name = tmp_name("partial");
    let (sent, received) = mpsc::channel();
    let hub = sync_gated::ipc::serve_stream(&name, move |r, mut w, _close| {
        let mut r = BufReader::new(r);
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        w.write_all(b"\"Ok\"\n{\"broken\":").unwrap();
        drop(r);
        drop(w);
        sent.send(()).unwrap();
    })
    .unwrap();
    let file = methods_file("partial");
    let mut s = Session::start(config(McpMode::Shared, 0, &file), &name, "docs");
    received.recv_timeout(BOUND).expect("hub never closed");
    wait_for("fallback did not start", || {
        s.err.text().contains("hub connection lost")
    });
    s.send(request(6, "tools/list"));
    assert_eq!(s.out.reply(6)["result"], json!({"echo":"tools/list"}));
    assert_eq!(s.finish(), 0);
    assert!(!s.out.text().contains("broken"), "{}", s.out.text());
    hub.shutdown();
}

#[test]
fn hub_closes_after_ok_before_initialize_and_client_lines_are_not_lost() {
    let name = tmp_name("immediate-close");
    let hub = sync_gated::ipc::serve_stream(&name, move |r, mut w, _close| {
        let mut r = BufReader::new(r);
        let mut hello = String::new();
        r.read_line(&mut hello).unwrap();
        w.write_all(b"\"Ok\"\n").unwrap();
    })
    .unwrap();
    let file = methods_file("immediate-close");
    let mut s = Session::start(config(McpMode::Shared, 0, &file), &name, "docs");
    wait_for(
        "hub EOF did not trigger fallback before any client line",
        || s.err.text().contains("hub connection lost"),
    );
    s.send(request(1, "tools/list"));
    assert_eq!(s.out.reply(1)["result"], json!({"echo":"tools/list"}));
    assert_eq!(s.finish(), 0);
    assert_eq!(methods(&file), ["tools/list"]);
    assert_eq!(s.out.json().iter().filter(|v| v["id"] == 1).count(), 1);
    assert_eq!(s.err.text().lines().count(), 1);
    hub.shutdown();
}

#[test]
fn hub_eof_really_closes_both_halves() {
    let name = tmp_name("close");
    let (closed, seen_close) = mpsc::channel();
    let hub = sync_gated::ipc::serve_stream(&name, move |r, mut w, _close| {
        let mut r = BufReader::new(r);
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        w.write_all(b"\"Ok\"\n").unwrap();
        line.clear();
        r.read_line(&mut line).unwrap();
        w.write_all(b"{\"id\":1,\"result\":{}}\n").unwrap();
        line.clear();
        let n = r.read_line(&mut line).unwrap_or(0);
        closed.send(n).unwrap();
    })
    .unwrap();
    let mut s = Session::start(
        config(McpMode::Shared, 0, &methods_file("close")),
        &name,
        "docs",
    );
    s.send(request(1, "tools/list"));
    s.out.reply(1);
    assert_eq!(s.finish(), 0);
    assert_eq!(
        seen_close
            .recv_timeout(Duration::from_millis(100))
            .expect("relay left its hub socket open"),
        0
    );
    hub.shutdown();
}

fn short_options() -> sync_gate_shim::RunOptions {
    // The hello deadline stays at its default: a short one makes every hub test depend on the
    // machine's load. Only the hello-timeout test shortens it.
    sync_gate_shim::RunOptions {
        exit_grace: Duration::from_millis(80),
        write_timeout: Duration::from_millis(80),
        ..Default::default()
    }
}

/// How long "nothing happened" is watched: several `short_options` write timeouts (80 ms).
const ABSENCE_WINDOW: Duration = Duration::from_millis(320);

fn wait_for(message: &str, mut condition: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < until, "{message}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn hello_timeout_closes_connection_and_launches_direct() {
    let name = tmp_name("hello-timeout");
    let (closed, observed) = mpsc::channel();
    let hub = sync_gated::ipc::serve_stream(&name, move |r, _w, _close| {
        let mut r = BufReader::new(r);
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        line.clear();
        let _ = r.read_line(&mut line);
        closed.send(()).unwrap();
    })
    .unwrap();
    let mut s = Session::with_options(
        config(McpMode::Shared, 0, &methods_file("hello")),
        &name,
        "docs",
        sync_gate_shim::RunOptions {
            hello_timeout: Duration::from_millis(80),
            ..short_options()
        },
    );
    s.send(request(1, "tools/list"));
    let closed = observed.recv_timeout(Duration::from_secs(5));
    let reply = s.out.reply(1);
    assert_eq!(s.finish(), 0);
    assert!(closed.is_ok(), "hello timeout left its socket open");
    assert_eq!(reply["result"], json!({"echo":"tools/list"}));
    assert_eq!(s.err.text().lines().count(), 1);
    hub.shutdown();
}

#[test]
fn a_hub_pipe_of_another_user_gets_no_byte_and_the_server_runs_directly() {
    let name = tmp_name("foreign");
    let (got, received) = mpsc::channel();
    let hub = sync_gated::ipc::serve_stream(&name, move |mut r, _w, _close| {
        // Everything the relay sends before it hangs up (the hello would carry its secrets).
        let mut bytes = Vec::new();
        let _ = r.read_to_end(&mut bytes);
        let _ = got.send(bytes.len());
    })
    .unwrap();
    let mut s = Session::with_options(
        config(McpMode::Shared, 0, &methods_file("foreign")),
        &name,
        "docs",
        sync_gate_shim::RunOptions {
            foreign_hub: true,
            ..short_options()
        },
    );
    s.send(request(1, "tools/list"));
    assert_eq!(s.out.reply(1)["result"], json!({"echo":"tools/list"}));
    assert_eq!(s.finish(), 0);
    assert_eq!(received.recv_timeout(Duration::from_secs(5)), Ok(0));
    assert_eq!(
        s.err.text().trim_end(),
        "sync_gate_mcp: hub pipe is not owned by this user; running the server directly"
    );
    hub.shutdown();
}

#[test]
fn hub_error_is_fail_open_without_echoing_secrets() {
    let name = tmp_name("refused");
    let (hub, _) = test_hub(
        &name,
        HubReply::Error {
            message: "SECRET_FROM_ENV".into(),
        },
        false,
    );
    let mut s = Session::start(
        config(McpMode::Shared, 0, &methods_file("refused")),
        &name,
        "docs",
    );
    s.send(request(1, "tools/list"));
    assert_eq!(s.out.reply(1)["result"], json!({"echo":"tools/list"}));
    assert_eq!(s.finish(), 0);
    assert_eq!(s.err.text().lines().count(), 1);
    assert!(!s.err.text().contains("SECRET_FROM_ENV"));
    hub.shutdown();
}

fn replay_failure(spec: &str) {
    let name = tmp_name(spec);
    // Dropping at 6 means both 5 and 6 are in flight, whatever the scheduling.
    let (hub, _) = test_hub_dropping_on(&name, HubReply::Ok, Some(6));
    let mut cfg = config(McpMode::Shared, 0, &methods_file(spec));
    cfg.mcp
        .get_mut("docs")
        .unwrap()
        .env
        .insert("SYNC_GATE_TEST_CHILD".into(), spec.into());
    // The replayed `initialize` gets the server's request timeout, as the hub gives a child's.
    cfg.mcp.get_mut("docs").unwrap().request_timeout_secs = 1;
    let mut s = Session::with_options(cfg, &name, "docs", short_options());
    s.send(request(0, "initialize"));
    s.out.reply(0);
    s.send(request(5, "tools/call"));
    s.send(request(6, "tools/list"));
    let result = s.done.recv_timeout(Duration::from_secs(5));
    if result.is_err() {
        s.stdin = None;
        let _ = s.done.recv_timeout(BOUND);
    }
    assert_eq!(result.expect("replay did not time out"), 1);
    for id in [5, 6] {
        let replies: Vec<_> = s.out.json().into_iter().filter(|v| v["id"] == id).collect();
        assert_eq!(replies.len(), 1, "id {id}: {}", s.out.text());
        assert_eq!(
            replies[0]["error"],
            json!({"code":-32000,"message":"hub connection lost; direct server unavailable"})
        );
    }
    assert_eq!(
        s.err
            .text()
            .matches("could not continue 'docs' directly after losing the hub")
            .count(),
        1
    );
    s.stdin = None;
    hub.shutdown();
}

#[test]
fn replay_exit_fails_inflight_and_held_requests() {
    replay_failure("exit");
}
#[test]
fn replay_stdout_eof_fails_inflight_and_held_requests() {
    replay_failure("close-stdout");
}
#[test]
fn replay_timeout_fails_inflight_and_held_requests() {
    replay_failure("never");
}

fn cut_client_line(with_id: bool) {
    let name = tmp_name("cut-input");
    let (cut, observed) = mpsc::channel();
    let hub = sync_gated::ipc::serve_stream(&name, move |r, mut w, close| {
        let mut r = BufReader::new(r);
        let mut hello = String::new();
        r.read_line(&mut hello).unwrap();
        w.write_all(b"\"Ok\"\n").unwrap();
        let mut prefix = vec![0; (1 << 20) + 1];
        r.read_exact(&mut prefix).unwrap();
        close();
        cut.send(()).unwrap();
    })
    .unwrap();
    let file = methods_file("cut-input");
    let mut s = Session::start(config(McpMode::Shared, 0, &file), &name, "docs");
    let mut prefix = if with_id {
        b"{\"jsonrpc\":\"2.0\",\"id\":51,\"method\":\"tools/call\",\"params\":\"".to_vec()
    } else {
        b"{\"jsonrpc\":\"2.0\",\"method\":\"notification\",\"params\":\"".to_vec()
    };
    prefix.extend(vec![b'x'; (1 << 20) + 16384]);
    s.stdin.as_ref().unwrap().send(prefix).unwrap();
    observed
        .recv_timeout(BOUND)
        .expect("hub did not receive the long prefix");
    wait_for("fallback never started", || {
        s.err.text().contains("hub connection lost")
    });
    // This suffix is a valid request by itself: forwarding it to the child is observable.
    s.stdin
        .as_ref()
        .unwrap()
        .send(b"{\"id\":52,\"method\":\"suffix-must-not-arrive\"}\n".to_vec())
        .unwrap();
    s.send(request(6, "tools/list"));
    s.out.reply(6);
    assert_eq!(s.finish(), 0);
    assert!(!methods(&file).contains(&"suffix-must-not-arrive".to_string()));
    if with_id {
        let replies: Vec<_> = s.out.json().into_iter().filter(|v| v["id"] == 51).collect();
        assert_eq!(replies.len(), 1, "large request was lost: {}", s.out.text());
        assert_eq!(
            replies[0]["error"],
            json!({"code":-32000,"message":"hub connection lost; request not completed"})
        );
    } else {
        assert_eq!(s.err.text().matches("sync_gate_mcp: a large request was cut by the hub loss and could not be completed").count(),1);
    }
    hub.shutdown();
}

#[test]
fn long_client_line_stays_on_its_original_destination() {
    cut_client_line(true);
}
#[test]
fn cut_large_line_without_id_has_one_diagnostic() {
    cut_client_line(false);
}

#[test]
fn streamed_hub_fragment_ends_before_the_next_message() {
    let name = tmp_name("cut-output");
    let (cut, observed) = mpsc::channel();
    let hub = sync_gated::ipc::serve_stream(&name, move |r, mut w, close| {
        let mut r = BufReader::new(r);
        let mut hello = String::new();
        r.read_line(&mut hello).unwrap();
        w.write_all(b"\"Ok\"\n").unwrap();
        hello.clear();
        r.read_line(&mut hello).unwrap();
        w.write_all(&vec![b'x'; (1 << 20) + 16384]).unwrap();
        cut.send(close).unwrap();
    })
    .unwrap();
    let mut s = Session::start(
        config(McpMode::Shared, 0, &methods_file("cut-output")),
        &name,
        "docs",
    );
    s.send(request(5, "tools/call"));
    let close = observed.recv_timeout(BOUND).unwrap();
    wait_for("long output never streamed", || {
        s.out.text().len() > (1 << 20)
    });
    close();
    wait_for("fallback never started", || {
        s.err.text().contains("hub connection lost")
    });
    s.send(request(6, "tools/list"));
    s.out.reply(6);
    assert_eq!(s.finish(), 0);
    let out = s.out.text();
    let tail = out.trim_start_matches('x');
    assert!(
        tail.starts_with('\n'),
        "unterminated fragment corrupted the following message"
    );
    hub.shutdown();
}

#[test]
fn blocked_hub_write_still_falls_back() {
    let name = tmp_name("blocked");
    let (ready, observed) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let released = Mutex::new(released);
    let hub = sync_gated::ipc::serve_stream(&name, move |r, mut w, close| {
        let mut r = BufReader::new(r);
        let mut hello = String::new();
        r.read_line(&mut hello).unwrap();
        w.write_all(b"\"Ok\"\n").unwrap();
        ready.send(close).unwrap();
        let _ = released.lock().unwrap().recv_timeout(BOUND);
    })
    .unwrap();
    let mut s = Session::with_options(
        config(McpMode::Shared, 0, &methods_file("blocked")),
        &name,
        "docs",
        short_options(),
    );
    let close = observed.recv_timeout(BOUND).unwrap();
    s.stdin.as_ref().unwrap().send(vec![b'x'; 4 << 20]).unwrap();
    let until = Instant::now() + Duration::from_secs(5);
    while !s.err.text().contains("hub connection lost") && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(5));
    }
    let fell_back = s.err.text().contains("hub connection lost");
    close();
    release.send(()).unwrap();
    s.stdin.as_ref().unwrap().send(b"\n".to_vec()).unwrap();
    s.send(request(6, "tools/list"));
    s.out.reply(6);
    assert_eq!(s.finish(), 0);
    assert!(fell_back, "blocked hub write prevented fallback");
    assert_eq!(s.err.text().matches("running 'docs' directly").count(), 1);
    hub.shutdown();
}

#[test]
fn tracking_applies_backpressure_before_reading_request_4097() {
    let name = tmp_name("backpressure");
    let (full, reached) = mpsc::channel();
    let (free, freed) = mpsc::channel();
    let freed = Mutex::new(freed);
    let hub = sync_gated::ipc::serve_stream(&name, move |r, mut w, _close| {
        let mut r = BufReader::new(r);
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        w.write_all(b"\"Ok\"\n").unwrap();
        for _ in 0..4096 {
            line.clear();
            r.read_line(&mut line).unwrap();
        }
        full.send(()).unwrap();
        freed.lock().unwrap().recv_timeout(BOUND).unwrap();
        w.write_all(b"{\"id\":0,\"result\":{}}\n").unwrap();
        line.clear();
        r.read_line(&mut line).unwrap();
        w.write_all(b"{\"id\":4096,\"result\":{}}\n").unwrap();
        line.clear();
        let _ = r.read_line(&mut line);
    })
    .unwrap();
    struct Counted {
        inner: Stdin,
        reads: Arc<AtomicU32>,
    }
    impl Read for Counted {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.inner.read(b)
        }
    }
    let (tx, rx) = mpsc::channel();
    let reads = Arc::new(AtomicU32::new(0));
    let (out, err) = (Sink::default(), Sink::default());
    let (done, result) = mpsc::channel();
    let (o, e, n, c) = (out.clone(), err.clone(), name.clone(), reads.clone());
    std::thread::spawn(move || {
        done.send(sync_gate_shim::run_with(
            &config(McpMode::Shared, 0, &methods_file("bp")),
            &n,
            "docs",
            Counted {
                inner: Stdin(rx, Vec::new(), Arc::default()),
                reads: c,
            },
            o,
            e,
        ))
        .unwrap();
    });
    for id in 0..4096 {
        tx.send(format!("{}\n", request(id, "tools/list")).into_bytes())
            .unwrap();
    }
    reached.recv_timeout(BOUND).unwrap();
    let read_at_capacity = reads.load(Ordering::SeqCst);
    tx.send(format!("{}\n", request(4096, "tools/list")).into_bytes())
        .unwrap();
    std::thread::sleep(Duration::from_millis(50));
    let read_while_full = reads.load(Ordering::SeqCst);
    free.send(()).unwrap();
    out.reply(4096);
    drop(tx);
    assert_eq!(result.recv_timeout(BOUND).unwrap(), 0);
    assert_eq!(
        read_while_full, read_at_capacity,
        "read stdin while tracking table was full"
    );
    assert_eq!(err.text().matches("too many requests in flight").count(), 1);
    hub.shutdown();
}

#[test]
fn signal_shutdown_uses_the_stdin_eof_path() {
    let opts = short_options();
    let shutdown = opts.shutdown.clone();
    let mut s = Session::with_options(
        config(McpMode::PerSession, 7, &methods_file("signal")),
        &tmp_name("signal"),
        "docs",
        opts,
    );
    s.send(request(1, "tools/list"));
    s.out.reply(1);
    shutdown.request();
    let result = s.done.recv_timeout(Duration::from_secs(5));
    if result.is_err() {
        s.stdin = None;
        let _ = s.done.recv_timeout(BOUND);
    }
    assert_eq!(result.expect("signal bypassed session cleanup"), 0);
    s.stdin = None;
}

struct TestChild(u32);
impl Drop for TestChild {
    fn drop(&mut self) {
        #[cfg(windows)]
        unsafe {
            use windows_sys::Win32::{
                Foundation::CloseHandle,
                System::Threading::{
                    OpenProcess, PROCESS_TERMINATE, SYNCHRONIZATION_SYNCHRONIZE, TerminateProcess,
                    WaitForSingleObject,
                },
            };
            let handle = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZATION_SYNCHRONIZE, 0, self.0);
            if !handle.is_null() {
                TerminateProcess(handle, 0);
                WaitForSingleObject(handle, 5000);
                CloseHandle(handle);
            }
        }
        #[cfg(unix)]
        {
            let pid = nix::unistd::Pid::from_raw(self.0 as i32);
            let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
            let _ = nix::sys::wait::waitpid(pid, None);
        }
    }
}

#[test]
fn direct_eof_is_bounded_without_terminating_the_child() {
    let file = methods_file("ignores-eof");
    let mut cfg = config(McpMode::PerSession, 0, &file);
    cfg.mcp.get_mut("docs").unwrap().env.insert(
        "SYNC_GATE_TEST_CHILD".into(),
        format!("ignore:{}", file.display()),
    );
    let mut s = Session::with_options(cfg, &tmp_name("ignore"), "docs", short_options());
    wait_for("child never recorded its pid", || file.exists());
    let pid = std::fs::read_to_string(&file).unwrap().parse().unwrap();
    let child = TestChild(pid);
    s.stdin = None;
    let result = s.done.recv_timeout(Duration::from_secs(5));
    let eof_file = std::path::PathBuf::from(format!("{}.eof", file.display()));
    let saw_eof = eof_file.exists();
    // The test owns cleanup; the relay must only have closed stdin.
    #[cfg(windows)]
    let alive = unsafe {
        use windows_sys::Win32::{
            Foundation::{CloseHandle, WAIT_TIMEOUT},
            System::Threading::{OpenProcess, SYNCHRONIZATION_SYNCHRONIZE, WaitForSingleObject},
        };
        let h = OpenProcess(SYNCHRONIZATION_SYNCHRONIZE, 0, pid);
        let alive = !h.is_null() && WaitForSingleObject(h, 0) == WAIT_TIMEOUT;
        if !h.is_null() {
            CloseHandle(h);
        }
        alive
    };
    #[cfg(unix)]
    let alive = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), None).is_ok();
    drop(child);
    if result.is_err() {
        let _ = s.done.recv_timeout(BOUND);
    }
    assert_eq!(result.expect("direct relay ignored its exit bound"), 0);
    assert!(saw_eof, "child stdin was not closed");
    assert!(alive, "relay terminated its direct child");
}

#[test]
fn replay_is_byte_identical_and_oversized_reply_is_swallowed() {
    replay_bytes(false);
}

#[test]
fn server_request_with_replay_id_is_not_swallowed() {
    replay_bytes(true);
}

fn replay_bytes(roots: bool) {
    let name = tmp_name("big-replay");
    let (hub, _) = test_hub(&name, HubReply::Ok, true);
    let raw = methods_file("raw-init");
    let file = methods_file("big-replay");
    let mut cfg = config(McpMode::Shared, 0, &file);
    let env = &mut cfg.mcp.get_mut("docs").unwrap().env;
    env.insert(
        "SYNC_GATE_TEST_LINES".into(),
        raw.to_string_lossy().into_owned(),
    );
    env.insert("SYNC_GATE_TEST_BIG_REPLY".into(), "1".into());
    if roots {
        env.insert("SYNC_GATE_TEST_ROOTS".into(), "1".into());
    }
    let mut s = Session::start(cfg, &name, "docs");
    let init = b"{ \"method\": \"initialize\", \"id\" : 0, \"jsonrpc\":\"2.0\", \"params\": {\"clientInfo\":{\"name\":\"exact bytes\"}} }\n".to_vec();
    s.stdin.as_ref().unwrap().send(init.clone()).unwrap();
    s.out.reply(0);
    s.send(request(5, "tools/call"));
    // Held during replay, then delivered exactly once after initialized.
    wait_for("fallback never started", || {
        s.err.text().contains("hub connection lost")
    });
    s.send(request(6, "tools/list"));
    s.send(request(7, "tools/call"));
    assert_eq!(
        s.out.reply(5)["error"]["message"],
        "hub connection lost; request not completed"
    );
    assert_eq!(s.out.reply(6)["result"], json!({"echo":"tools/list"}));
    assert_eq!(s.out.reply(7)["result"], json!({"echo":"tools/call"}));
    assert_eq!(s.finish(), 0);
    let lines = std::fs::read(&raw).unwrap();
    assert!(lines.starts_with(&init));
    assert_eq!(
        methods(&file),
        [
            "initialize",
            "notifications/initialized",
            "tools/list",
            "tools/call"
        ]
    );
    for id in [0, 5, 6, 7] {
        assert_eq!(
            s.out
                .json()
                .iter()
                .filter(|v| v["id"] == id && v.get("method").is_none())
                .count(),
            1
        );
    }
    assert_eq!(
        s.out
            .json()
            .iter()
            .filter(|v| v["method"] == "roots/list")
            .count(),
        usize::from(roots)
    );
    assert!(!s.out.text().contains("padding"));
    hub.shutdown();
}

#[test]
fn blocked_client_output_does_not_prevent_signal_cleanup() {
    blocked_output(true);
}
#[test]
fn blocked_client_output_does_not_prevent_eof_cleanup() {
    blocked_output(false);
}
fn blocked_output(signal: bool) {
    struct Blocked {
        entered: mpsc::Sender<()>,
        release: Option<mpsc::Receiver<()>>,
        finished: mpsc::Sender<()>,
    }
    impl Drop for Blocked {
        fn drop(&mut self) {
            let _ = self.finished.send(());
        }
    }
    impl Write for Blocked {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            if let Some(release) = self.release.take() {
                self.entered.send(()).unwrap();
                release
                    .recv_timeout(BOUND)
                    .expect("test did not release stdout");
            }
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let file = methods_file("blocked-output");
    let eof = methods_file("blocked-output-eof");
    let mut cfg = config(McpMode::PerSession, 0, &file);
    cfg.mcp.get_mut("docs").unwrap().env.insert(
        "SYNC_GATE_TEST_EOF".into(),
        eof.to_string_lossy().into_owned(),
    );
    let options = short_options();
    let shutdown = options.shutdown.clone();
    let (input, stdin) = mpsc::channel();
    let (entered, writing) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let (finished, stopped) = mpsc::channel();
    let (done, result) = mpsc::channel();
    let err = Sink::default();
    let e = err.clone();
    std::thread::spawn(move || {
        done.send(sync_gate_shim::run_with_options(
            &cfg,
            &tmp_name("bo"),
            "docs",
            Stdin(stdin, Vec::new(), Arc::default()),
            Blocked {
                entered,
                release: Some(released),
                finished,
            },
            e,
            options,
        ))
        .unwrap();
    });
    writing
        .recv_timeout(BOUND)
        .expect("stdout was not exercised");
    wait_for("child never entered its fixture", || file.exists());
    let mut input = Some(input);
    if signal {
        shutdown.request();
    } else {
        input = None;
    }
    let code = result.recv_timeout(Duration::from_secs(5));
    release.send(()).unwrap();
    stopped
        .recv_timeout(BOUND)
        .expect("output worker retained the test sink");
    drop(input);
    if code.is_err() {
        let _ = result.recv_timeout(BOUND);
    }
    assert_eq!(code.expect("blocked stdout prevented session cleanup"), 0);
    assert!(eof.exists(), "child stdin was not closed on shutdown");
}

#[test]
fn fallback_spawn_failure_answers_inflight_and_held_requests() {
    // A path, not a bare name: a bare name nobody holds ends before the hub (exit 127 at once).
    let missing = std::env::temp_dir().join("sync_gate-no-such-command");
    fallback_spawn_failure(missing.to_string_lossy().into_owned(), 127);
}

#[test]
fn fallback_unexecutable_server_exits_126_with_errors() {
    fallback_spawn_failure(
        std::env::current_dir()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
        126,
    );
}

fn fallback_spawn_failure(command: String, code: i32) {
    let name = tmp_name("spawn-failure");
    // Dropping at 6 means both 5 and 6 are in flight, whatever the scheduling.
    let (hub, _) = test_hub_dropping_on(&name, HubReply::Ok, Some(6));
    let mut cfg = config(McpMode::Shared, 0, &methods_file("spawn-failure"));
    cfg.mcp.get_mut("docs").unwrap().command = command;
    let mut s = Session::with_options(cfg, &name, "docs", short_options());
    s.send(request(0, "initialize"));
    s.out.reply(0);
    s.send(request(5, "tools/call"));
    s.send(request(6, "tools/list"));
    assert_eq!(s.done.recv_timeout(BOUND).unwrap(), code);
    for id in [5, 6] {
        assert_eq!(
            s.out.reply(id)["error"],
            json!({"code":-32000,"message":"hub connection lost; direct server unavailable"})
        );
    }
    s.stdin = None;
    hub.shutdown();
}

#[test]
fn thread_spawn_failure_closes_child_stdin_and_keeps_child_owned() {
    let file = methods_file("thread-failure");
    let eof = methods_file("thread-failure-eof");
    let mut cfg = config(McpMode::PerSession, 0, &file);
    cfg.mcp.get_mut("docs").unwrap().env.insert(
        "SYNC_GATE_TEST_EOF".into(),
        eof.to_string_lossy().into_owned(),
    );
    let mut options = short_options();
    options.thread_budget = Some(2);
    options.exit_grace = Duration::from_secs(5);
    let mut s = Session::with_options(cfg, &tmp_name("thread-failure"), "docs", options);
    let result = s.done.recv_timeout(BOUND);
    s.stdin = None;
    if result.is_err() {
        let _ = s.done.recv_timeout(BOUND);
    }
    let closed = eof.exists();
    assert_eq!(result.expect("thread failure did not end the relay"), 1);
    assert!(
        closed,
        "thread failure dropped child ownership without closing stdin"
    );
    assert!(s.err.text().contains("cannot start relay threads"));
}

/// A client stdout that accepts nothing until `open`, then records everything.
#[derive(Clone)]
struct Gated {
    open: Arc<std::sync::atomic::AtomicBool>,
    entered: Arc<std::sync::atomic::AtomicBool>,
    sink: Sink,
}
impl Gated {
    fn new(sink: &Sink) -> Self {
        Self {
            open: Arc::default(),
            entered: Arc::default(),
            sink: sink.clone(),
        }
    }
    fn open(&self) {
        self.open.store(true, Ordering::SeqCst);
    }
}
impl Write for Gated {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.entered.store(true, Ordering::SeqCst);
        while !self.open.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
        }
        self.sink.clone().write(b)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The client stops reading its stdout for several times the write timeout: the relay waits.
fn client_stops_reading(mode: McpMode) {
    let name = tmp_name("gated");
    let hub = (mode == McpMode::Shared).then(|| test_hub(&name, HubReply::Ok, false).0);
    let out = Sink::default();
    let gate = Gated::new(&out);
    let mut s = Session::with_stdout(
        config(mode, 0, &methods_file("gated")),
        &name,
        "docs",
        short_options(),
        gate.clone(),
        out,
    );
    s.send(request(1, "tools/list"));
    wait_for("the relay never wrote to the client", || {
        gate.entered.load(Ordering::SeqCst)
    });
    // Absence window: returns at once if the session ends, else after a few write timeouts.
    let window = s.done.recv_timeout(ABSENCE_WINDOW);
    gate.open();
    assert!(
        matches!(window, Err(mpsc::RecvTimeoutError::Timeout)),
        "a client that stopped reading ended the session: {}",
        s.err.text()
    );
    s.out.reply(1);
    s.send(request(2, "tools/list"));
    s.out.reply(2);
    assert_eq!(s.finish(), 0);
    assert!(
        !s.err.text().contains("stopped reading"),
        "{}",
        s.err.text()
    );
    if let Some(hub) = hub {
        hub.shutdown();
    }
}

#[test]
fn client_that_stops_reading_is_not_disconnected_in_hub_mode() {
    client_stops_reading(McpMode::Shared);
}
#[test]
fn client_that_stops_reading_is_not_disconnected_in_direct_mode() {
    client_stops_reading(McpMode::PerSession);
}

fn big_request(id: i64) -> Vec<u8> {
    format!(
        "{}\n",
        json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"x":"a".repeat(2 << 20)}})
    )
    .into_bytes()
}

#[test]
fn direct_child_that_stops_reading_stdin_does_not_end_the_session() {
    let file = methods_file("slow-reader");
    let mut cfg = config(McpMode::PerSession, 0, &file);
    cfg.mcp
        .get_mut("docs")
        .unwrap()
        .env
        .insert("SYNC_GATE_TEST_START_DELAY_MS".into(), "1000".into());
    let mut s = Session::with_options(cfg, &tmp_name("slow"), "docs", short_options());
    // Larger than any pipe buffer: the relay's write blocks until the child reads.
    let request = big_request(1);
    s.stdin.as_ref().unwrap().send(request.clone()).unwrap();
    // The child exists (it opens its file first) and is in its start delay; the relay took the
    // first 1 MiB piece off stdin and is writing it: that write cannot finish yet.
    wait_for("the child never started", || file.exists());
    wait_for("the relay never took the first piece", || {
        s.read.load(Ordering::SeqCst) >= 1 << 20
    });
    let window = s.done.recv_timeout(ABSENCE_WINDOW);
    assert!(
        matches!(window, Err(mpsc::RecvTimeoutError::Timeout)),
        "a direct server busy for a while ended the session: {window:?} {}",
        s.err.text()
    );
    // Still blocked on that write after the window: the rest of the line was not read.
    assert!(
        s.read.load(Ordering::SeqCst) < request.len(),
        "the write never blocked: the whole request was read"
    );
    assert_eq!(s.out.reply(1)["result"], json!({"echo":"tools/call"}));
    assert_eq!(s.finish(), 0);
}

#[test]
fn shutdown_returns_while_a_write_to_the_direct_child_is_blocked() {
    let file = methods_file("stall");
    let mut cfg = config(McpMode::PerSession, 0, &file);
    cfg.mcp.get_mut("docs").unwrap().env.insert(
        "SYNC_GATE_TEST_CHILD".into(),
        format!("stall:{}", file.display()),
    );
    let options = short_options();
    let shutdown = options.shutdown.clone();
    let s = Session::with_options(cfg, &tmp_name("stall"), "docs", options);
    wait_for("child never recorded its pid", || file.exists());
    let _child = TestChild(std::fs::read_to_string(&file).unwrap().parse().unwrap());
    s.stdin.as_ref().unwrap().send(big_request(1)).unwrap();
    // A byte of the 1 MiB piece reached the child, which reads no more: the write is blocked.
    let got = std::path::PathBuf::from(format!("{}.got", file.display()));
    wait_for("the write to the child never began", || got.exists());
    shutdown.request();
    let code = s
        .done
        .recv_timeout(Duration::from_secs(5))
        .expect("shutdown did not return while a child write was blocked");
    assert_eq!(code, 0);
}

#[test]
fn initialize_in_flight_when_the_hub_is_lost_is_answered_by_the_direct_server() {
    let (name, file) = (tmp_name("init-flight"), methods_file("init-flight"));
    // The hub reads the initialize (id 5 closes the connection) and never answers it.
    let (hub, _) = test_hub(&name, HubReply::Ok, true);
    let mut s = Session::start(config(McpMode::Shared, 0, &file), &name, "docs");
    s.send(request(5, "initialize"));
    let reply = s.out.reply(5);
    assert_eq!(reply["result"], json!({"echo":"initialize"}), "{reply}");
    // The client sends its own notification after the reply; the relay must not add another.
    s.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    s.send(request(6, "tools/list"));
    s.out.reply(6);
    assert_eq!(s.finish(), 0);
    let expected = json!({"jsonrpc":"2.0","id":5,"result":{"echo":"initialize"}}).to_string();
    let text = s.out.text();
    assert_eq!(text.lines().filter(|l| *l == expected).count(), 1, "{text}");
    assert_eq!(s.out.json().iter().filter(|v| v["id"] == 5).count(), 1);
    assert_eq!(
        methods(&file),
        ["initialize", "notifications/initialized", "tools/list"]
    );
    hub.shutdown();
}

#[test]
fn large_client_response_is_not_tracked_as_a_request() {
    let name = tmp_name("big-response");
    let hub = sync_gated::ipc::serve_stream(&name, move |r, mut w, close| {
        let mut r = BufReader::new(r);
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        w.write_all(b"\"Ok\"\n").unwrap();
        line.clear();
        r.read_line(&mut line).unwrap();
        line.clear();
        r.read_line(&mut line).unwrap();
        close();
    })
    .unwrap();
    let mut s = Session::start(
        config(McpMode::Shared, 0, &methods_file("big-response")),
        &name,
        "docs",
    );
    // A response to a server request, over the parse limit: it has an id but no method.
    let response =
        json!({"jsonrpc":"2.0","id":"srv-1","result":{"x":"a".repeat(2 << 20)}}).to_string();
    s.stdin
        .as_ref()
        .unwrap()
        .send(format!("{response}\n").into_bytes())
        .unwrap();
    s.send(request(5, "tools/call"));
    wait_for("fallback never started", || {
        s.err.text().contains("hub connection lost")
    });
    s.send(request(6, "tools/list"));
    s.out.reply(6);
    assert_eq!(s.finish(), 0);
    assert_eq!(s.out.json().iter().filter(|v| v["id"] == 5).count(), 1);
    assert_eq!(
        s.out.json().iter().filter(|v| v["id"] == "srv-1").count(),
        0,
        "a client response was answered as a lost request: {}",
        s.out.text()
    );
    hub.shutdown();
}

/// A first `initialize` (id 0) with about `padding` bytes of params, its fields in this order.
fn initialize_line(padding: usize, params_first: bool) -> String {
    let params = format!(r#"{{"padding":"{}"}}"#, "x".repeat(padding));
    if params_first {
        format!(r#"{{"params":{params},"jsonrpc":"2.0","id":0,"method":"initialize"}}"#)
    } else {
        format!(r#"{{"jsonrpc":"2.0","id":0,"method":"initialize","params":{params}}}"#)
    }
}

/// A strict direct server (refuses every request before `initialize`, logs every line it reads)
/// behind a hub that drops the connection at id 5, after the client's first line `init`.
/// Returns the session, the methods file and the lines file.
fn strict_fallback(
    tag: &str,
    init: &str,
    edit: impl FnOnce(&mut McpServer),
) -> (
    Session,
    std::path::PathBuf,
    std::path::PathBuf,
    impl FnOnce(),
) {
    let (name, file, lines) = (
        tmp_name(tag),
        methods_file(tag),
        methods_file(&format!("{tag}-lines")),
    );
    let (hub, _) = test_hub(&name, HubReply::Ok, true);
    let mut cfg = config(McpMode::Shared, 0, &file);
    let srv = cfg.mcp.get_mut("docs").unwrap();
    srv.env
        .insert("SYNC_GATE_TEST_NEED_INIT".into(), "1".into());
    srv.env
        .insert("SYNC_GATE_TEST_LINES".into(), lines.display().to_string());
    edit(srv);
    let s = Session::start(cfg, &name, "docs");
    s.stdin
        .as_ref()
        .unwrap()
        .send(format!("{init}\n").into_bytes())
        .unwrap();
    s.out.reply(0);
    s.send(request(5, "tools/call"));
    (s, file, lines, move || hub.shutdown())
}

/// The replay reaches the strict direct server once and byte for byte, whatever its size (one
/// piece past the 64 KiB field scan, or several pieces) and the order of its fields.
#[test]
fn a_large_initialize_is_replayed_to_the_direct_server() {
    for (padding, params_first) in [(3 << 19, false), (3 << 19, true), (100 << 10, true)] {
        let case = format!("padding {padding}, params first {params_first}");
        let init = initialize_line(padding, params_first);
        let (mut s, file, lines, stop) = strict_fallback("mid-init", &init, |_| {});
        wait_for("fallback never started", || {
            s.err.text().contains("hub connection lost")
        });
        s.send(request(6, "tools/list"));
        let reply = s.out.reply(6);
        assert_eq!(
            reply["result"],
            json!({"echo":"tools/list"}),
            "{case}: {reply}"
        );
        assert_eq!(s.finish(), 0);
        let m = methods(&file);
        assert_eq!(
            m.first().map(String::as_str),
            Some("initialize"),
            "{case}: {m:?}"
        );
        assert_eq!(
            m.iter().filter(|m| *m == "initialize").count(),
            1,
            "{case}: {m:?}"
        );
        let got = std::fs::read_to_string(&lines).unwrap();
        assert!(
            got.lines().next() == Some(init.as_str()),
            "{case}: the replayed initialize differs from the client's"
        );
        assert_eq!(s.out.json().iter().filter(|v| v["id"] == 5).count(), 1);
        stop();
    }
}

/// Over the limit, in either field order: the session ends with an error and the direct server
/// is never started (its command cannot start, so any attempt would say "cannot start").
#[test]
fn an_initialize_over_the_limit_ends_the_session_with_an_error() {
    for params_first in [true, false] {
        let init = initialize_line(9 << 20, params_first);
        let missing = std::env::temp_dir().join(tmp_name("no-such-server"));
        let (s, _, _, stop) = strict_fallback("big-init", &init, |srv| {
            srv.command = missing.to_string_lossy().into_owned();
        });
        let code = s.done.recv_timeout(BOUND).expect("session did not end");
        let text = s.err.text();
        assert!(
            !text.contains("cannot start"),
            "params first {params_first}: a direct start was tried: {text}"
        );
        assert_eq!(code, 1, "params first {params_first}: {text}");
        assert!(text.contains("initialize too large to replay"), "{text}");
        assert!(!text.contains("running 'docs' directly"), "{text}");
        assert_eq!(s.out.json().iter().filter(|v| v["id"] == 5).count(), 1);
        stop();
    }
}

/// The direct server refuses the replayed initialize: the session ends instead of going on with
/// a server that is not initialized.
#[test]
fn a_refused_replay_ends_the_session() {
    replay_not_accepted(
        "replay-refused",
        ("SYNC_GATE_TEST_REJECT_INIT", "1"),
        "refused the replayed initialize",
    );
}

/// The reply is read whole before the session goes on: an error past the start of a 2 MiB reply
/// is still a refusal, and a reply cut mid-JSON is no success.
#[test]
fn a_replay_reply_checked_whole_ends_the_session_unless_it_is_a_success() {
    replay_not_accepted(
        "replay-both",
        ("SYNC_GATE_TEST_INIT_REPLY", "both"),
        "refused the replayed initialize",
    );
    replay_not_accepted(
        "replay-cut",
        ("SYNC_GATE_TEST_INIT_REPLY", "truncated"),
        "gave no valid reply to the replayed initialize",
    );
}

fn replay_not_accepted(tag: &str, (key, value): (&str, &str), says: &str) {
    let init = initialize_line(16, false);
    let (s, file, _, stop) = strict_fallback(tag, &init, |srv| {
        srv.env.insert(key.into(), value.into());
    });
    let code = s
        .done
        .recv_timeout(Duration::from_secs(10))
        .unwrap_or_else(|e| panic!("{tag}: the session went on after its replay: {e:?}"));
    let text = s.err.text();
    assert_eq!(code, 1, "{tag}: {text}");
    assert!(text.contains(says), "{tag}: {text}");
    let e = s.out.reply(5);
    assert_eq!(
        e["error"]["message"], "hub connection lost; direct server unavailable",
        "{tag}: {e}"
    );
    let m = methods(&file);
    assert!(
        !m.contains(&"notifications/initialized".into()),
        "{tag}: {m:?}"
    );
    stop();
}

/// An `initialize` the relay cannot parse (nested past serde_json's depth limit) is not taken
/// for "no initialize": the direct server is never started without its replay.
#[test]
fn an_initialize_that_cannot_be_parsed_ends_the_session_with_an_error() {
    let name = tmp_name("deep-init");
    // Reads the hello, the initialize and id 5, then drops the connection; it parses nothing.
    let hub = sync_gated::ipc::serve_stream(&name, move |r, mut w, close| {
        let mut r = BufReader::new(r);
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        w.write_all(b"\"Ok\"\n").unwrap();
        r.read_line(&mut line).unwrap();
        r.read_line(&mut line).unwrap();
        close();
    })
    .unwrap();
    let mut cfg = config(McpMode::Shared, 0, &methods_file("deep-init"));
    let missing = std::env::temp_dir().join(tmp_name("no-such-server"));
    cfg.mcp.get_mut("docs").unwrap().command = missing.to_string_lossy().into_owned();
    let s = Session::start(cfg, &name, "docs");
    let deep = format!("{}{}", "[".repeat(200), "]".repeat(200));
    let init =
        format!(r#"{{"jsonrpc":"2.0","id":0,"method":"initialize","params":{{"x":{deep}}}}}"#);
    assert!(
        serde_json::from_str::<Value>(&init).is_err(),
        "not too deep"
    );
    s.stdin
        .as_ref()
        .unwrap()
        .send(format!("{init}\n").into_bytes())
        .unwrap();
    s.send(request(5, "tools/call"));
    let code = s.done.recv_timeout(BOUND).expect("session did not end");
    let text = s.err.text();
    assert!(
        !text.contains("cannot start"),
        "a direct start was tried: {text}"
    );
    assert_eq!(code, 1, "{text}");
    assert!(text.contains("initialize could not be read"), "{text}");
    assert_eq!(s.out.json().iter().filter(|v| v["id"] == 5).count(), 1);
    hub.shutdown();
}

/// The hub disappears while the client's initialize (below the limit) is still arriving: the
/// session ends and says so, without calling it too large or announcing a direct start.
#[test]
fn a_hub_lost_mid_initialize_ends_the_session_truthfully() {
    let name = tmp_name("cut-init");
    let hub = sync_gated::ipc::serve_stream(&name, move |r, mut w, close| {
        let mut r = BufReader::new(r);
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        w.write_all(b"\"Ok\"\n").unwrap();
        let _ = r.read_exact(&mut vec![0; 64 << 10]);
        close();
    })
    .unwrap();
    let s = Session::start(
        config(McpMode::Shared, 0, &methods_file("cut-init")),
        &name,
        "docs",
    );
    // 1.5 MiB without its end: the rest of the line has not arrived when the hub goes.
    let init = initialize_line(3 << 19, false);
    s.stdin
        .as_ref()
        .unwrap()
        .send(init.as_bytes()[..init.len() - 100].to_vec())
        .unwrap();
    let code = s.done.recv_timeout(BOUND).expect("session did not end");
    let text = s.err.text();
    assert_eq!(code, 1, "{text}");
    assert!(text.contains("initialize was still arriving"), "{text}");
    assert!(!text.contains("too large"), "{text}");
    assert!(!text.contains("running 'docs' directly"), "{text}");
    hub.shutdown();
}

// ---- Task 11: the relay runs the adopted server when the config cannot ----

mod adopted {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use sync_gate_core::{ConfigLoadError, MIB, MachineSnapshot, Request, Response};

    const SENTINEL: &str = "SECRET-SENTINEL";

    /// One test's folder: data dir, config path, marker file; removed on drop.
    struct World {
        dir: PathBuf,
        marker: PathBuf,
    }

    impl World {
        fn new(tag: &str) -> World {
            let dir = std::env::temp_dir().join(tmp_name(tag));
            std::fs::create_dir_all(dir.join("data")).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                for d in [&dir, &dir.join("data")] {
                    std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700)).unwrap();
                }
            }
            World {
                marker: dir.join("marker"),
                dir,
            }
        }
        fn data(&self) -> PathBuf {
            self.dir.join("data")
        }
        fn config(&self) -> PathBuf {
            self.dir.join("config.toml")
        }
        /// The record `adopt` would write, for the fake server (this test binary).
        fn record(&self, command: &str, args: &[&str]) {
            let entry = json!({
                "agent": "codex", "file": self.dir.join("codex.toml"), "server": "docs",
                "original": {"command": format!("\"{command}\""), "args": null},
                "original_command": command, "original_args": args,
                "adopted_command": "sync_gate_mcp", "adopted_args": ["docs"],
                "inserted_args": false
            });
            let rec = json!({"version": 1, "entries": [entry]});
            let path = self.data().join("mcp-adopted.json");
            std::fs::write(&path, serde_json::to_vec(&rec).unwrap()).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        fn record_fake(&self) {
            let exe = std::env::current_exe().unwrap();
            self.record(
                &exe.to_string_lossy(),
                &["child_entry", "--exact", "--nocapture", "--test-threads=1"],
            );
        }
        fn relay(&self, server: &str, cwd: Option<&Path>, env: &[(&str, String)]) -> Relay {
            let mut c = Command::new(env!("CARGO_BIN_EXE_sync_gate_mcp"));
            c.arg(server)
                .env("SYNC_GATE_CONFIG", self.config())
                .env("SYNC_GATE_DATA_DIR", self.data())
                .env("SYNC_GATE_SOCKET", tmp_name("nohub"))
                .env(
                    "SYNC_GATE_TEST_CHILD",
                    format!("mcp-echo:0:{}", self.marker.display()),
                )
                .env("SYNC_GATE_TEST_CWD", "1")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            for (k, v) in env {
                c.env(k, v);
            }
            if let Some(d) = cwd {
                c.current_dir(d);
            }
            Relay::start(c)
        }
    }

    impl Drop for World {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    struct Relay {
        child: Child,
        lines: mpsc::Receiver<Value>,
        err: Arc<Mutex<String>>,
        /// Every raw stdout line, JSON or not.
        raw: Arc<Mutex<Vec<String>>>,
    }

    impl Relay {
        fn start(mut c: Command) -> Relay {
            let mut child = c.spawn().unwrap();
            let out = child.stdout.take().unwrap();
            let (tx, lines) = mpsc::channel();
            let raw = Arc::new(Mutex::new(Vec::new()));
            let seen = raw.clone();
            std::thread::spawn(move || {
                for l in BufReader::new(out).lines().map_while(Result::ok) {
                    seen.lock().unwrap().push(l.clone());
                    // The fake server is a test binary: its harness lines are not JSON.
                    if let Ok(v) = serde_json::from_str::<Value>(&l)
                        && tx.send(v).is_err()
                    {
                        break;
                    }
                }
            });
            let err = Arc::new(Mutex::new(String::new()));
            let (mut pipe, e) = (child.stderr.take().unwrap(), err.clone());
            std::thread::spawn(move || {
                let mut buf = [0u8; 1024];
                while let Ok(n) = pipe.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    e.lock()
                        .unwrap()
                        .push_str(&String::from_utf8_lossy(&buf[..n]));
                }
            });
            Relay {
                child,
                lines,
                err,
                raw,
            }
        }
        /// Raw stdout must be MCP JSON only: the fake server's libtest harness lines are the one
        /// allowed exception; a diagnostic of the relay's would show here.
        fn assert_stdout_is_mcp_only(&self) {
            for l in self.raw.lock().unwrap().iter() {
                let harness =
                    l.is_empty() || l == "." || l.starts_with("running ") || l.starts_with("test ");
                assert!(
                    harness || serde_json::from_str::<Value>(l).is_ok(),
                    "stray stdout line: {l}"
                );
                assert!(!l.contains("sync_gate_mcp"), "relay text on stdout: {l}");
            }
        }
        fn stdout_text(&self) -> String {
            self.raw.lock().unwrap().join("\n")
        }
        /// Sends `initialize` and returns its reply.
        fn initialize(&mut self) -> Value {
            let stdin = self.child.stdin.as_mut().unwrap();
            writeln!(stdin, "{}", request(1, "initialize")).unwrap();
            stdin.flush().unwrap();
            self.lines
                .recv_timeout(BOUND)
                .unwrap_or_else(|_| panic!("no reply; stderr: {}", self.stderr()))
        }
        fn stderr(&self) -> String {
            self.err.lock().unwrap().clone()
        }
        /// Closes stdin and returns the exit code (bounded).
        fn finish(&mut self) -> i32 {
            drop(self.child.stdin.take());
            let until = Instant::now() + BOUND;
            loop {
                if let Some(s) = self.child.try_wait().unwrap() {
                    // The stderr thread may still hold the last bytes.
                    std::thread::sleep(Duration::from_millis(50));
                    return s.code().unwrap_or(-1);
                }
                assert!(Instant::now() < until, "relay did not exit");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    impl Drop for Relay {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn assert_runs_the_original(w: &World, reason: &str) {
        w.record_fake();
        let mut r = w.relay("docs", None, &[]);
        assert_eq!(r.initialize()["result"]["echo"], "initialize");
        assert_eq!(r.finish(), 0);
        let err = r.stderr();
        assert!(err.contains("adoption record"), "{err}");
        assert!(err.contains(reason), "{err}");
        r.assert_stdout_is_mcp_only();
    }

    #[test]
    fn relay_adopted_missing_config_runs_the_original() {
        assert_runs_the_original(&World::new("a1"), "unknown server 'docs'");
    }

    #[test]
    fn relay_adopted_empty_config_runs_the_original() {
        let w = World::new("a2");
        std::fs::write(w.config(), "").unwrap();
        assert_runs_the_original(&w, "unknown server 'docs'");
    }

    #[test]
    fn relay_adopted_config_without_the_server_runs_the_original() {
        let w = World::new("a3");
        std::fs::write(w.config(), "[mcp.other]\ncommand = \"x\"\n").unwrap();
        assert_runs_the_original(&w, "unknown server 'docs'");
    }

    #[test]
    fn relay_adopted_invalid_config_runs_the_original() {
        let w = World::new("a4");
        std::fs::write(w.config(), "[mcp.docs\nnot toml").unwrap();
        assert_runs_the_original(&w, "config did not load");
    }

    /// A broken config whose line holds a secret: the fallback says where, never what.
    #[test]
    fn relay_adopted_broken_config_prints_no_file_content() {
        let w = World::new("a11");
        let text =
            format!("[mcp.docs]\ncommand = \"x\"\nenv = {{ TOKEN = \"{SENTINEL}\" }} junk\n");
        std::fs::write(w.config(), text).unwrap();
        w.record_fake();
        let mut r = w.relay("docs", None, &[]);
        assert_eq!(r.initialize()["result"]["echo"], "initialize");
        assert_eq!(r.finish(), 0);
        let err = r.stderr();
        assert!(err.contains("config did not load"), "{err}");
        assert!(err.contains("line 3"), "{err}");
        for out in [&err, &r.stdout_text()] {
            assert!(!out.contains("SECRET"), "{out}");
            assert!(!out.contains("TOKEN"), "{out}");
        }
        r.assert_stdout_is_mcp_only();
    }

    /// A registry whose value has the wrong type: category and position, never the value.
    #[test]
    fn relay_adopted_broken_record_prints_no_file_content() {
        let w = World::new("a12");
        let path = w.data().join("mcp-adopted.json");
        let text = format!("{{\"version\":1,\"entries\":[{{\"original_args\":\"{SENTINEL}\"}}]}}");
        std::fs::write(&path, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut r = w.relay("docs", None, &[]);
        assert_eq!(r.finish(), 2);
        let err = r.stderr();
        assert!(err.contains("adoption record refused"), "{err}");
        assert!(err.contains("line 1, column"), "{err}");
        for out in [&err, &r.stdout_text()] {
            assert!(!out.contains("SECRET"), "{out}");
            assert!(!out.contains("original_args"), "{out}");
        }
        assert!(!w.marker.exists());
        r.assert_stdout_is_mcp_only();
    }

    /// A record that is a link, or has another link, is not what `adopt` wrote: nothing runs.
    #[cfg(unix)]
    #[test]
    fn relay_adopted_record_that_is_a_link_is_not_used() {
        let w = World::new("a13");
        w.record_fake();
        let rec = w.data().join("mcp-adopted.json");
        let real = w.data().join("real.json");
        std::fs::rename(&rec, &real).unwrap();
        std::os::unix::fs::symlink(&real, &rec).unwrap();
        let mut r = w.relay("docs", None, &[]);
        assert_eq!(r.finish(), 2);
        assert!(r.stderr().contains("is a link"), "{}", r.stderr());
        assert!(!w.marker.exists(), "the fake server started");
        r.assert_stdout_is_mcp_only();
    }

    #[cfg(unix)]
    #[test]
    fn relay_adopted_record_with_another_link_is_not_used() {
        let w = World::new("a14");
        w.record_fake();
        let rec = w.data().join("mcp-adopted.json");
        std::fs::hard_link(&rec, w.data().join("other.json")).unwrap();
        let mut r = w.relay("docs", None, &[]);
        assert_eq!(r.finish(), 2);
        assert!(r.stderr().contains("more than one link"), "{}", r.stderr());
        assert!(!w.marker.exists(), "the fake server started");
        r.assert_stdout_is_mcp_only();
    }

    /// A shared server whose bare command only a shims folder holds: 127 before the hub is
    /// asked (a hello without `program` would let the hub pick its own file).
    #[test]
    fn relay_adopted_bare_command_without_a_safe_file_exits_127_before_the_hub() {
        let w = World::new("a15");
        let shims = w.dir.join("shims");
        std::fs::create_dir_all(&shims).unwrap();
        std::fs::write(shims.join(sync_gate_core::SHIMS_MANIFEST), "{}").unwrap();
        std::fs::write(
            w.config(),
            "[mcp.docs]\ncommand = \"docs-mcp\"\nmode = \"shared\"\n",
        )
        .unwrap();
        let socket = tmp_name("hub-127");
        let (hub, seen) = test_hub(&format!("{socket}-mcp"), HubReply::PerSession, false);
        let path = shims.to_string_lossy().into_owned();
        let mut r = w.relay(
            "docs",
            None,
            &[("PATH", path), ("SYNC_GATE_SOCKET", socket)],
        );
        assert_eq!(r.finish(), 127);
        let err = r.stderr();
        assert!(
            err.contains("docs-mcp") && err.contains("no safe folder"),
            "{err}"
        );
        assert_eq!(err.trim().lines().count(), 1, "{err}");
        {
            let seen = seen.lock().unwrap();
            assert!(
                seen.hello.is_none() && seen.connections == 0,
                "hub was asked"
            );
        }
        r.assert_stdout_is_mcp_only();
        hub.shutdown();
    }

    /// The hello names the exact file found through the PATH: the same one the relay would spawn.
    #[cfg(unix)]
    #[test]
    fn relay_adopted_hello_carries_the_exact_program() {
        let w = World::new("a16");
        let bin = w.dir.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let tool = bin.join("tool");
        install_fake(&tool);
        std::fs::write(
            w.config(),
            "[mcp.docs]\ncommand = \"tool\"\nmode = \"shared\"\n\
             args = [\"child_entry\", \"--exact\", \"--nocapture\", \"--test-threads=1\"]\n",
        )
        .unwrap();
        let socket = tmp_name("hub-prog");
        let (hub, seen) = test_hub(&format!("{socket}-mcp"), HubReply::PerSession, false);
        let path = bin.to_string_lossy().into_owned();
        let mut r = w.relay(
            "docs",
            None,
            &[("PATH", path), ("SYNC_GATE_SOCKET", socket)],
        );
        assert_eq!(r.initialize()["result"]["echo"], "initialize");
        assert_eq!(r.finish(), 0);
        let hello = seen.lock().unwrap().hello.clone().expect("no hello");
        assert_eq!(hello.program, Some(tool));
        r.assert_stdout_is_mcp_only();
        hub.shutdown();
    }

    /// Relative PATH entries are the server's: `bin` is `B/bin`, not the relay's `A/bin`.
    #[cfg(unix)]
    #[test]
    fn relay_adopted_relative_path_is_resolved_in_the_server_folder() {
        let w = World::new("a17");
        let (a, b) = (w.dir.join("A"), w.dir.join("B"));
        for d in [&a, &b] {
            std::fs::create_dir_all(d.join("bin")).unwrap();
        }
        // The wrong one: a script that only leaves a mark.
        let wrong = a.join("bin/tool");
        std::fs::write(
            &wrong,
            format!("#!/bin/sh\ntouch {}/ran-in-a\n", w.dir.display()),
        )
        .unwrap();
        make_executable(&wrong);
        install_fake(&b.join("bin/tool"));
        std::fs::write(
            w.config(),
            format!(
                "[mcp.docs]\ncommand = \"tool\"\ncwd = \"{}\"\nenv = {{ PATH = \"bin\" }}\n\
                 args = [\"child_entry\", \"--exact\", \"--nocapture\", \"--test-threads=1\"]\n",
                b.display()
            ),
        )
        .unwrap();
        let mut r = w.relay("docs", Some(&a), &[]);
        let reply = r.initialize();
        assert_eq!(reply["result"]["echo"], "initialize");
        assert_eq!(reply["result"]["cwd"], b.to_string_lossy().as_ref());
        assert_eq!(r.finish(), 0);
        assert!(!w.dir.join("ran-in-a").exists(), "A/bin/tool ran");
        r.assert_stdout_is_mcp_only();
    }

    #[cfg(unix)]
    fn make_executable(p: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// This test binary, copied as the server `to` points at.
    #[cfg(unix)]
    fn install_fake(to: &Path) {
        std::fs::copy(std::env::current_exe().unwrap(), to).unwrap();
        make_executable(to);
    }

    #[test]
    fn relay_adopted_without_a_record_exits_2() {
        let w = World::new("a5");
        let mut r = w.relay("docs", None, &[]);
        assert_eq!(r.finish(), 2);
        assert!(
            r.stderr().contains("unknown server 'docs'"),
            "{}",
            r.stderr()
        );
        assert!(!w.marker.exists());
    }

    #[cfg(unix)]
    #[test]
    fn relay_adopted_record_in_an_unsafe_folder_is_not_used() {
        use std::os::unix::fs::PermissionsExt;
        let w = World::new("a6");
        w.record_fake();
        std::fs::set_permissions(w.data(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let mut r = w.relay("docs", None, &[]);
        assert_eq!(r.finish(), 2);
        assert!(
            r.stderr().contains("adoption record refused"),
            "{}",
            r.stderr()
        );
        assert!(!w.marker.exists(), "the fake server started");
    }

    #[cfg(unix)]
    #[test]
    fn relay_adopted_record_others_can_write_is_not_used() {
        use std::os::unix::fs::PermissionsExt;
        let w = World::new("a7");
        w.record_fake();
        let rec = w.data().join("mcp-adopted.json");
        std::fs::set_permissions(&rec, std::fs::Permissions::from_mode(0o666)).unwrap();
        let mut r = w.relay("docs", None, &[]);
        assert_eq!(r.finish(), 2);
        assert!(
            r.stderr().contains("adoption record refused"),
            "{}",
            r.stderr()
        );
        assert!(!w.marker.exists(), "the fake server started");
    }

    #[cfg(windows)]
    #[test]
    fn relay_adopted_direct_finds_a_cmd_through_pathext() {
        let w = World::new("a8");
        let bin = w.dir.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let exe = std::env::current_exe().unwrap();
        std::fs::write(
            bin.join("fgtool.cmd"),
            format!(
                "@\"{}\" child_entry --exact --nocapture --test-threads=1\r\n",
                exe.display()
            ),
        )
        .unwrap();
        w.record("fgtool", &[]);
        let path = format!(
            "{};{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let mut r = w.relay("docs", None, &[("PATH", path)]);
        assert_eq!(r.initialize()["result"]["echo"], "initialize");
        assert_eq!(r.finish(), 0);
    }

    /// Plenty of memory whatever the host has, so pool decisions never depend on it.
    struct Roomy;

    impl sync_gated::Measure for Roomy {
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

    /// A daemon started with an empty config and a reload that reads `w`'s config; a Codex file
    /// whose `docs` server is the fake one, adopted afterwards.
    fn daemon_then_adopt(w: &World, any_folder: bool) -> (sync_gated::DaemonHandle, String) {
        std::fs::write(w.config(), "tick_ms = 100\n").unwrap();
        let socket = tmp_name("hub-adopt");
        let cfg_path = w.config();
        let reload: sync_gated::McpReload = Arc::new(move || {
            let text =
                std::fs::read_to_string(&cfg_path).map_err(|_| ConfigLoadError::unreadable())?;
            Config::from_toml(&text)
                .map(|c| c.mcp)
                .map_err(|e| ConfigLoadError::parse(&text, &e))
        });
        let deps = sync_gated::Deps {
            mcp_reload: Some(reload),
            ..sync_gated::Deps::os()
        };
        let d = sync_gated::run_with_pg(
            Config::default(),
            &socket,
            Roomy,
            sync_gated::OsControl,
            Some(w.data()),
            Arc::new(sync_gated::OsLauncher::default()),
            deps,
        )
        .unwrap();
        let exe =
            serde_json::to_string(&std::env::current_exe().unwrap().to_string_lossy()).unwrap();
        let codex = w.dir.join("codex.toml");
        std::fs::write(
            &codex,
            format!(
                "[mcp_servers.docs]\ncommand = {exe}\n\
                 args = [\"child_entry\", \"--exact\", \"--nocapture\", \"--test-threads=1\"]\n\
                 env_vars = [\"SYNC_GATE_TEST_CHILD\", \"SYNC_GATE_TEST_CWD\"]\n"
            ),
        )
        .unwrap();
        let code = sync_gate::adopt::adopt(&sync_gate::adopt::AdoptOptions {
            agent: sync_gate::adopt::AgentArg::Codex,
            dry_run: false,
            any_folder,
            claude_config: None,
            codex_config: Some(codex),
            servers: vec!["docs".into()],
            sync_gate_config: Some(w.config()),
            data_dir: Some(w.data()),
        });
        assert_eq!(code, 0, "adopt failed");
        (d, socket)
    }

    fn hub_relay(w: &World, socket: &str, cwd: Option<&Path>) -> Relay {
        w.relay("docs", cwd, &[("SYNC_GATE_SOCKET", socket.to_string())])
    }

    #[test]
    fn relay_adopted_daemon_started_before_adopt_shares_one_server() {
        let w = World::new("a9");
        let (d, socket) = daemon_then_adopt(&w, true);
        let mut a = hub_relay(&w, &socket, None);
        let mut b = hub_relay(&w, &socket, None);
        assert_eq!(a.initialize()["result"]["echo"], "initialize");
        assert_eq!(b.initialize()["result"]["echo"], "initialize");
        let Ok(Response::Status(st)) = sync_gate::client::call_at(&socket, &Request::Status) else {
            panic!("status failed");
        };
        let row = st.mcp.iter().find(|r| r.server == "docs").expect("no row");
        assert_eq!((row.instances, row.clients), (1, 2), "{row:?}");
        drop((a, b));
        d.shutdown();
    }

    #[test]
    fn relay_adopted_two_folders_get_their_own_server() {
        let w = World::new("a10");
        let (d, socket) = daemon_then_adopt(&w, false);
        let (fa, fb) = (w.dir.join("folder-a"), w.dir.join("folder-b"));
        std::fs::create_dir_all(&fa).unwrap();
        std::fs::create_dir_all(&fb).unwrap();
        let mut a = hub_relay(&w, &socket, Some(&fa));
        let mut b = hub_relay(&w, &socket, Some(&fb));
        let cwd_of = |r: &mut Relay| {
            let v = r.initialize();
            PathBuf::from(v["result"]["cwd"].as_str().expect("no cwd").to_string())
        };
        let (ca, cb) = (cwd_of(&mut a), cwd_of(&mut b));
        assert_eq!(ca.file_name().unwrap(), "folder-a", "{ca:?}");
        assert_eq!(cb.file_name().unwrap(), "folder-b", "{cb:?}");
        drop((a, b));
        d.shutdown();
    }
}

/// The relay resolves the program once; the hello and every spawn use that file. The seam runs
/// right after the one resolution and makes the file appear or disappear.
#[cfg(debug_assertions)]
mod resolved_once {
    use super::*;
    use std::path::PathBuf;

    fn tool_name() -> &'static str {
        if cfg!(windows) { "tool.exe" } else { "tool" }
    }

    /// A folder for one test; the server `tool` is this test binary copied there.
    fn folder(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(tmp_name(tag));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn install(dir: &std::path::Path) -> PathBuf {
        let to = dir.join(tool_name());
        std::fs::copy(std::env::current_exe().unwrap(), &to).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&to, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        to
    }

    /// A bare `tool` found only through the server's own `PATH` = `dir`.
    fn bare_config(mode: McpMode, dir: &std::path::Path, methods: &std::path::Path) -> Config {
        let mut cfg = config(mode, 0, methods);
        let srv = cfg.mcp.get_mut("docs").unwrap();
        srv.command = "tool".into();
        srv.env
            .insert("PATH".into(), dir.to_string_lossy().into_owned());
        cfg
    }

    /// Windows spells the extension from PATHEXT (`.EXE`): the file is the same.
    fn assert_same_file(got: Option<PathBuf>, want: &std::path::Path) {
        let got = got.expect("hello without a program");
        assert!(
            got.to_string_lossy()
                .eq_ignore_ascii_case(&want.to_string_lossy()),
            "{got:?} != {want:?}"
        );
    }

    fn options(seam: impl Fn() + Send + Sync + 'static) -> sync_gate_shim::RunOptions {
        sync_gate_shim::RunOptions {
            after_resolve: Some(Arc::new(seam)),
            ..short_options()
        }
    }

    /// A candidate that appears after the one resolution is never used, per session or shared.
    #[test]
    fn candidate_that_appears_after_the_resolution_is_never_started() {
        for mode in [McpMode::PerSession, McpMode::Shared] {
            let (dir, file) = (folder("late"), methods_file("late"));
            let hub_name = tmp_name("hub-late");
            let (hub, seen) = test_hub(&hub_name, HubReply::PerSession, false);
            let d = dir.clone();
            let mut s = Session::with_options(
                bare_config(mode, &dir, &file),
                &hub_name,
                "docs",
                options(move || {
                    install(&d);
                }),
            );
            assert_eq!(s.done.recv_timeout(BOUND).unwrap(), 127, "{mode:?}");
            assert!(s.err.text().contains("no safe folder"), "{}", s.err.text());
            assert!(methods(&file).is_empty(), "{mode:?}: a server started");
            assert!(seen.lock().unwrap().hello.is_none(), "{mode:?}: hub asked");
            s.stdin = None;
            hub.shutdown();
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// A candidate that disappears after the one resolution is a normal spawn error (127, fail
    /// open path), and the hello still named the resolved file.
    #[test]
    fn candidate_that_disappears_after_the_resolution_fails_the_spawn() {
        let (dir, file) = (folder("gone"), methods_file("gone"));
        let tool = install(&dir);
        let hub_name = tmp_name("hub-gone");
        let (hub, seen) = test_hub(&hub_name, HubReply::PerSession, false);
        let t = tool.clone();
        let mut s = Session::with_options(
            bare_config(McpMode::Shared, &dir, &file),
            &hub_name,
            "docs",
            options(move || {
                std::fs::remove_file(&t).unwrap();
            }),
        );
        assert_eq!(s.done.recv_timeout(BOUND).unwrap(), 127);
        let err = s.err.text();
        assert!(err.contains("cannot start 'docs':"), "{err}");
        assert!(!err.contains("no safe folder"), "searched again: {err}");
        assert!(methods(&file).is_empty());
        let hello = seen.lock().unwrap().hello.clone().expect("no hello");
        assert_same_file(hello.program, &tool);
        s.stdin = None;
        hub.shutdown();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// With nothing moving, the hello names the file and the same file is the server.
    #[test]
    fn hello_carries_the_resolved_program_and_it_is_the_one_started() {
        let (dir, file) = (folder("same"), methods_file("same"));
        let tool = install(&dir);
        let hub_name = tmp_name("hub-same");
        let (hub, seen) = test_hub(&hub_name, HubReply::PerSession, false);
        let mut s = Session::with_options(
            bare_config(McpMode::Shared, &dir, &file),
            &hub_name,
            "docs",
            options(|| {}),
        );
        s.send(request(1, "tools/list"));
        assert_eq!(s.out.reply(1)["result"], json!({"echo":"tools/list"}));
        assert_eq!(s.finish(), 0);
        let hello = seen.lock().unwrap().hello.clone().expect("no hello");
        assert_same_file(hello.program, &tool);
        hub.shutdown();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
