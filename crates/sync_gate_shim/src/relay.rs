//! The caller owns session state, the child and the connection. Workers only move bytes.
use crate::transport::{Connection, TICK, Worker};
use crate::{BUF, Log, Reader, RunOptions, Shutdown, Writer, direct};
use serde_json::Value;
use std::collections::{HashSet, VecDeque};
use std::io::{self, BufReader, Write};
use std::process::{Child, Stdio};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use sync_gate_core::{Kind, McpServer, classify, error_response};

const MAX_PARSED_LINE: usize = 1 << 20;
/// Bytes of content, not of memory: the stored `initialize` (kept across pieces for replay) and
/// the reply to its replay (kept until checked) each stop at this size. Parsing either, and the
/// copy sent as replay, allocate on top of it, more for JSON with many small values; the relay
/// has no ceiling on its total memory. Measured: a real client sends well under 100 KiB; 8 MiB is
/// the per-client queue limit, so one stored line never outweighs what the hub holds for a session.
const MAX_STORED_INITIALIZE: usize = 8 << 20;
/// Counts requests, not their bytes: an id is as long as the client writes it (up to the 1 MiB
/// first piece, or 8 MiB for a stored initialize), so this bounds memory only as far as the
/// client's own ids do.
const MAX_TRACKED: usize = 4096;
const LOST: &str = "hub connection lost; request not completed";
const UNAVAILABLE: &str = "hub connection lost; direct server unavailable";
const DRAIN_GRACE: Duration = Duration::from_secs(2);

struct Piece {
    bytes: Vec<u8>,
    first: bool,
    end: bool,
    streamed: bool,
}
/// Short incomplete output stays buffered; long lines use at most 1 MiB plus one chunk.
struct Lines {
    r: Reader,
    long: bool,
}
impl Lines {
    fn next(&mut self) -> Option<Piece> {
        let first = !self.long;
        let limit = if first { MAX_PARSED_LINE } else { BUF };
        let mut bytes = Vec::new();
        loop {
            let buf = match self.r.fill_buf() {
                Ok([]) => break,
                Ok(b) => b,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            };
            let n = buf
                .iter()
                .position(|b| *b == b'\n')
                .map_or(buf.len(), |i| i + 1)
                .min(limit - bytes.len());
            let end = buf[n - 1] == b'\n';
            bytes.extend_from_slice(&buf[..n]);
            self.r.consume(n);
            if end || bytes.len() == limit {
                let streamed = self.long || !end;
                self.long = !end;
                return Some(Piece {
                    bytes,
                    first,
                    end,
                    streamed,
                });
            }
        }
        if bytes.is_empty() {
            None
        } else {
            Some(Piece {
                bytes,
                first,
                end: false,
                streamed: self.long,
            })
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Source {
    Hub,
    Child,
}
enum Event {
    Input(Piece),
    InputEnd,
    Output(Source, Piece),
    OutputEnd(Source),
    Written(Source, u64, bool),
    ClientWritten(Option<Source>, bool),
    /// A shutdown was requested: re-check the flag.
    Wake,
}

type OutputLine = (Vec<u8>, Option<Source>);
/// Writes to the client have no timeout: without sync_gate a client that stops reading would
/// block the server just the same. Closing the queue or cancelling the I/O ends the worker.
struct Output {
    queue: VecDeque<OutputLine>,
    send: Option<SyncSender<OutputLine>>,
    worker: Option<Worker>,
    busy: bool,
}
impl Output {
    fn new(mut out: Writer, tx: &Sender<Event>) -> io::Result<Self> {
        let (send, rx) = mpsc::sync_channel::<OutputLine>(1);
        let tx = tx.clone();
        let worker = Worker::start(move |stop| {
            while let Ok((bytes, ack)) = rx.recv() {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                let ok = out.write_all(&bytes).and_then(|()| out.flush()).is_ok();
                if tx.send(Event::ClientWritten(ack, ok)).is_err() || !ok {
                    return;
                }
            }
        })?;
        Ok(Self {
            queue: VecDeque::new(),
            send: Some(send),
            worker: Some(worker),
            busy: false,
        })
    }
    fn push(&mut self, bytes: Vec<u8>, ack: Option<Source>) {
        self.queue.push_back((bytes, ack));
    }
    fn flush(&mut self) -> bool {
        if !self.busy
            && let Some(line) = self.queue.pop_front()
        {
            if self.send.as_ref().is_none_or(|s| s.try_send(line).is_err()) {
                return false;
            }
            self.busy = true;
        }
        true
    }
    fn finish(&mut self, rx: &Receiver<Event>, until: Instant, shutdown: &Shutdown) {
        while !shutdown.requested() && (!self.queue.is_empty() || self.busy) {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() || !self.flush() {
                break;
            }
            match rx.recv_timeout(left) {
                Ok(Event::ClientWritten(_, ok)) => {
                    self.busy = false;
                    if !ok {
                        break;
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                _ => {}
            }
        }
        self.send = None;
        if let Some(worker) = self.worker.take() {
            worker.cancel();
            worker.finish(until.min(Instant::now() + Duration::from_millis(100)));
        }
    }
}

struct Endpoint {
    write: Option<SyncSender<(u64, Vec<u8>)>>,
    ack: Sender<()>,
    writer: Worker,
    reader: Worker,
}
impl Endpoint {
    fn start(
        r: Reader,
        mut w: Writer,
        source: Source,
        tx: &Sender<Event>,
        budget: &mut Option<usize>,
    ) -> Result<Self, (io::Error, Option<Reader>)> {
        let (write, rx) = mpsc::sync_channel::<(u64, Vec<u8>)>(1);
        let txw = tx.clone();
        // Blocks on the queue and on the write; dropping the queue or cancelling the I/O ends it.
        let writer = Worker::budgeted(budget, move |stop| {
            while let Ok((serial, bytes)) = rx.recv() {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                let ok = w.write_all(&bytes).is_ok();
                let _ = txw.send(Event::Written(source, serial, ok));
                if !ok {
                    break;
                }
            }
        })
        .map_err(|e| (e, None))?;
        let (ack, credits) = mpsc::channel();
        let txr = tx.clone();
        let slot = Arc::new(Mutex::new(Some(r)));
        let reader_slot = slot.clone();
        let reader = match Worker::budgeted(budget, move |stop| {
            let r = reader_slot.lock().unwrap_or_else(|e| e.into_inner()).take();
            let Some(r) = r else {
                return;
            };
            let mut lines = Lines { r, long: false };
            while !stop.load(Ordering::SeqCst) {
                let Some(piece) = lines.next() else {
                    break;
                };
                if txr.send(Event::Output(source, piece)).is_err() {
                    return;
                }
                // One piece at a time: wait for the session's credit; dropping it ends this.
                if credits.recv().is_err() {
                    return;
                }
            }
            let _ = txr.send(Event::OutputEnd(source));
        }) {
            Ok(worker) => worker,
            Err(e) => {
                writer.cancel();
                drop(write);
                writer.finish(Instant::now() + Duration::from_millis(100));
                let r = slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                return Err((e, r));
            }
        };
        Ok(Self {
            write: Some(write),
            ack,
            writer,
            reader,
        })
    }
    fn send(&self, serial: u64, bytes: Vec<u8>) -> bool {
        self.write
            .as_ref()
            .is_some_and(|w| w.try_send((serial, bytes)).is_ok())
    }
    fn close_stdin(&mut self) {
        self.write = None;
        self.writer.cancel();
    }
    fn stop(self, until: Instant) {
        let Self {
            write,
            ack,
            writer,
            reader,
        } = self;
        // Dropping both queues wakes idle workers; the cancel calls interrupt blocked I/O.
        drop((write, ack));
        writer.cancel();
        reader.cancel();
        writer.finish(until);
        reader.finish(until);
    }
}

struct Session<'a> {
    name: &'a str,
    srv: &'a McpServer,
    /// Resolved once at relay start; the only file any direct start may run.
    program: Option<std::path::PathBuf>,
    log: Log,
    out: Output,
    options: RunOptions,
    conn: Option<Connection>,
    endpoint: Option<Endpoint>,
    child: Option<Child>,
    spare_output: Option<Reader>,
    source: Source,
    tx: Sender<Event>,
    flight: HashSet<String>,
    initialize: Option<(String, Vec<u8>)>,
    /// Why a line that may be the first `initialize` was not stored (too large, unreadable).
    initialize_lost: Option<&'static str>,
    /// A line that may be the first `initialize` is still arriving (bytes so far).
    init_partial: Option<Vec<u8>>,
    replay: Option<(String, Instant)>,
    /// The replayed `initialize` is still the client's own request: its reply goes to the client.
    replay_is_client: bool,
    forwarding: bool,
    held: Option<Piece>,
    line_source: Source,
    input_pending: bool,
    writing: Option<(u64, Instant)>,
    serial: u64,
    output_open: bool,
    output_id: Option<String>,
    input_open: bool,
    unknown_large: bool,
    /// The reply to a silent replay, kept until it is whole and checked.
    swallowed: Option<Vec<u8>>,
    noted: bool,
    cleanup_until: Option<Instant>,
}

#[allow(clippy::too_many_arguments)] // one session: every part is a different input
pub(crate) fn run(
    name: &str,
    srv: &McpServer,
    program: Option<std::path::PathBuf>,
    log: Log,
    stdin: Reader,
    stdout: Writer,
    hub: Option<(Connection, Reader, Writer)>,
    mut options: RunOptions,
) -> i32 {
    let (tx, rx) = mpsc::channel();
    let out = match Output::new(stdout, &tx) {
        Ok(out) => out,
        Err(_) => {
            let mut log = log;
            log.line("sync_gate_mcp: cannot start output thread");
            return 1;
        }
    };
    let wake = tx.clone();
    options.shutdown.on_request(Box::new(move || {
        let _ = wake.send(Event::Wake);
    }));
    let (read, credits) = mpsc::channel();
    let txi = tx.clone();
    let input = Worker::budgeted(&mut options.thread_budget, move |stop| {
        let mut lines = Lines {
            r: stdin,
            long: false,
        };
        while !stop.load(Ordering::SeqCst) && credits.recv().is_ok() {
            match lines.next() {
                Some(piece) => {
                    if txi.send(Event::Input(piece)).is_err() {
                        return;
                    }
                }
                None => {
                    let _ = txi.send(Event::InputEnd);
                    return;
                }
            }
        }
    });
    let mut session = Session {
        name,
        srv,
        program,
        log,
        out,
        options,
        conn: None,
        endpoint: None,
        child: None,
        spare_output: None,
        source: Source::Hub,
        tx,
        flight: HashSet::new(),
        initialize: None,
        initialize_lost: None,
        init_partial: None,
        replay: None,
        replay_is_client: false,
        forwarding: false,
        held: None,
        line_source: Source::Hub,
        input_pending: false,
        writing: None,
        serial: 0,
        output_open: false,
        output_id: None,
        input_open: false,
        unknown_large: false,
        swallowed: None,
        noted: false,
        cleanup_until: None,
    };
    let result = match input.as_ref() {
        Err(_) => {
            session
                .log
                .line("sync_gate_mcp: cannot start relay threads");
            1
        }
        Ok(_) => {
            let start = match hub {
                Some((conn, r, w)) => {
                    session.conn = Some(conn);
                    session.open(r, w, Source::Hub)
                }
                None => session.start_child(),
            };
            match start {
                Ok(()) => {
                    if session.conn.is_some() {
                        crate::transport::trim_working_set();
                    }
                    session.events(&rx, &read)
                }
                Err(code) => code,
            }
        }
    };
    drop(read);
    session.cleanup(&rx);
    drop(rx);
    if let Ok(input) = input {
        input.cancel();
        input.finish(Instant::now() + TICK);
    }
    if session.options.shutdown.requested() {
        0
    } else {
        result
    }
}

impl Session<'_> {
    fn open(&mut self, r: Reader, w: Writer, source: Source) -> Result<(), i32> {
        match Endpoint::start(r, w, source, &self.tx, &mut self.options.thread_budget) {
            Ok(endpoint) => {
                self.endpoint = Some(endpoint);
                self.source = source;
                Ok(())
            }
            Err((_, r)) => {
                self.spare_output = r;
                self.log.line("sync_gate_mcp: cannot start relay threads");
                Err(1)
            }
        }
    }
    fn start_child(&mut self) -> Result<(), i32> {
        let child = direct::spawn(
            self.name,
            self.srv,
            self.program.as_deref(),
            Stdio::piped(),
            Stdio::piped(),
        );
        self.child = Some(match child {
            Ok(child) => child,
            Err((code, msg)) => {
                self.log.line(&msg);
                return Err(code);
            }
        });
        let Some(child) = self.child.as_mut() else {
            return Err(1);
        };
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            return Err(1);
        };
        self.open(
            Box::new(BufReader::with_capacity(BUF, stdout)),
            Box::new(stdin),
            Source::Child,
        )
    }
    fn put(&mut self, bytes: &[u8]) {
        self.out.push(bytes.to_vec(), None);
    }
    fn send(&mut self, bytes: Vec<u8>) -> bool {
        self.serial = self.serial.wrapping_add(1);
        if self
            .endpoint
            .as_ref()
            .is_some_and(|e| e.send(self.serial, bytes))
        {
            self.writing = Some((self.serial, Instant::now()));
            true
        } else {
            false
        }
    }
    fn errors(&mut self, message: &str) {
        if self.output_open {
            self.put(b"\n");
            self.output_open = false;
        }
        for key in std::mem::take(&mut self.flight) {
            if let Ok(id) = serde_json::from_str::<Value>(&key) {
                self.put(format!("{}\n", error_response(&id, -32000, message)).as_bytes());
            }
        }
    }
    fn stop_endpoint(&mut self) {
        if let Some(conn) = self.conn.take() {
            conn.close();
        }
        if let Some(e) = self.endpoint.take() {
            e.stop(Instant::now() + Duration::from_millis(100));
        }
    }
    fn fallback(&mut self) -> Result<(), i32> {
        if self.source != Source::Hub {
            return Ok(());
        }
        self.stop_endpoint();
        self.writing = None;
        if self.input_open && self.unknown_large {
            self.log.line(
                "sync_gate_mcp: a large request was cut by the hub loss and could not be completed",
            );
        }
        if self.output_open {
            self.put(b"\n");
            self.output_open = false;
        }
        self.source = Source::Child;
        // Decided before anything is announced: a direct server that never saw `initialize`
        // would refuse every request.
        let refused = if self.init_partial.take().is_some() {
            Some("hub connection lost while the client's initialize was still arriving")
        } else {
            self.initialize_lost.filter(|_| self.initialize.is_none())
        };
        if let Some(why) = refused {
            self.log.line(&format!(
                "sync_gate_mcp: {why}; not starting '{}' directly without it",
                self.name
            ));
            return Err(1);
        }
        self.log.line(&format!(
            "sync_gate_mcp: hub connection lost, running '{}' directly",
            self.name
        ));
        self.start_child()?;
        if let Some((id, line)) = self.initialize.clone() {
            // Still unanswered: the replay is the client's own request and its reply is forwarded.
            self.replay_is_client = self.flight.contains(&id);
            // The deadline the hub gives a child's `initialize`: the server's request timeout
            // (a server that starts slowly, like a first `npx` download, gets the same room).
            let deadline = Duration::from_secs(self.srv.request_timeout_secs);
            self.replay = Some((id, Instant::now() + deadline));
            if !self.send(line) {
                return Err(1);
            }
        } else {
            self.errors(LOST);
        }
        Ok(())
    }
    fn fail_replay(&mut self, rx: &Receiver<Event>, code: i32) -> i32 {
        // One client read may already have been admitted before the hub disappeared.
        if self.held.is_none() && self.input_pending {
            let until = Instant::now() + self.options.exit_grace.min(Duration::from_millis(100));
            loop {
                let left = until.saturating_duration_since(Instant::now());
                match rx.recv_timeout(left) {
                    Ok(Event::Input(piece)) => {
                        self.held = Some(piece);
                        break;
                    }
                    Ok(Event::InputEnd) | Err(_) => break,
                    Ok(Event::ClientWritten(_, _)) => self.out.busy = false,
                    _ => {}
                }
            }
        }
        if let Some(piece) = self.held.take()
            && piece.first
            && let Some(id) = request_id(&piece.bytes)
        {
            self.flight.insert(id);
        }
        self.errors(UNAVAILABLE);
        self.log.line(&format!(
            "sync_gate_mcp: could not continue '{}' directly after losing the hub",
            self.name
        ));
        code
    }
    fn events(&mut self, rx: &Receiver<Event>, read: &Sender<()>) -> i32 {
        let (mut eof, mut signalled, mut closing, mut exited, mut output_done) =
            (false, false, None, None, false);
        loop {
            if !self.out.flush() {
                self.log.line("sync_gate_mcp: client output closed");
                return 1;
            }
            if self.options.shutdown.requested() && !signalled {
                signalled = true;
                eof = true;
                if self.source == Source::Hub {
                    return 0;
                }
                if let Some(e) = self.endpoint.as_mut() {
                    e.close_stdin();
                }
                closing =
                    Some(Instant::now() + self.options.exit_grace.min(Duration::from_secs(5)));
                self.cleanup_until = closing;
            }
            if let Some(child) = self.child.as_mut() {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        if self.replay.is_some() {
                            return self.fail_replay(rx, 1);
                        }
                        exited = Some(direct::exit_code(status));
                        if closing.is_none() {
                            closing = Some(Instant::now() + DRAIN_GRACE);
                        }
                    }
                    Err(_) => {
                        self.log
                            .line("sync_gate_mcp: could not inspect direct server");
                        return 1;
                    }
                    Ok(None) => {}
                }
            }
            if self
                .replay
                .as_ref()
                .is_some_and(|(_, until)| Instant::now() >= *until)
            {
                return self.fail_replay(rx, 1);
            }
            if (exited.is_some() && output_done) || closing.is_some_and(|t| Instant::now() >= t) {
                return if signalled {
                    0
                } else {
                    exited.unwrap_or(if eof { 0 } else { 1 })
                };
            }
            // Only a hub that stopped reading times out. A client or a direct server that stops
            // reading just makes the relay wait, as it would make the other side wait without us.
            if !eof
                && self
                    .hub_write_deadline()
                    .is_some_and(|t| Instant::now() >= t)
                && let Err(code) = self.fallback()
            {
                return self.fail_replay(rx, code);
            }
            let full = self.source == Source::Hub && self.flight.len() >= MAX_TRACKED;
            if full && !self.noted {
                self.noted = true;
                self.log
                    .line("sync_gate_mcp: too many requests in flight, waiting for replies");
            }
            if !eof
                && !self.input_pending
                && self.held.is_none()
                && self.writing.is_none()
                && (!full || self.input_open)
            {
                if read.send(()).is_err() {
                    return 1;
                }
                self.input_pending = true;
            }
            // Block until something happens. A timeout is armed only for a pending deadline; the
            // exit check polls only while a closing grace period is running.
            let mut next = closing;
            if let Some((_, t)) = &self.replay {
                next = earlier(next, *t);
            }
            if let Some(t) = self.hub_write_deadline().filter(|_| !eof) {
                next = earlier(next, t);
            }
            if closing.is_some() && exited.is_none() && self.child.is_some() {
                next = earlier(next, Instant::now() + TICK);
            }
            let received = match next {
                None => rx.recv().map_err(|_| mpsc::RecvTimeoutError::Disconnected),
                Some(t) => rx.recv_timeout(t.saturating_duration_since(Instant::now())),
            };
            let event = match received {
                Ok(event) => event,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(_) => return 1,
            };
            match event {
                Event::ClientWritten(source, ok) => {
                    self.out.busy = false;
                    if !ok && !eof {
                        self.log.line("sync_gate_mcp: client output closed");
                        return 1;
                    }
                    if source == Some(self.source)
                        && let Some(e) = &self.endpoint
                    {
                        let _ = e.ack.send(());
                    }
                }
                Event::Input(piece) => {
                    self.input_pending = false;
                    if eof {
                        continue;
                    }
                    if self.replay.is_some() {
                        self.held = Some(piece);
                    } else if !self.forward(piece) {
                        if self.source == Source::Hub {
                            if let Err(code) = self.fallback() {
                                return self.fail_replay(rx, code);
                            }
                        } else {
                            self.log.line("sync_gate_mcp: direct server input closed");
                            return 1;
                        }
                    }
                }
                Event::InputEnd => {
                    self.input_pending = false;
                    if self.replay.is_some() {
                        return self.fail_replay(rx, 1);
                    }
                    eof = true;
                    if self.source == Source::Hub {
                        return 0;
                    }
                    if let Some(e) = self.endpoint.as_mut() {
                        e.close_stdin();
                    }
                    closing =
                        Some(Instant::now() + self.options.exit_grace.min(Duration::from_secs(5)));
                    self.cleanup_until = closing;
                }
                Event::Written(source, serial, ok) if source == self.source => {
                    if self.writing.is_some_and(|(active, _)| active == serial) {
                        self.writing = None;
                    }
                    if !ok && !eof {
                        if source == Source::Hub {
                            if let Err(code) = self.fallback() {
                                return self.fail_replay(rx, code);
                            }
                        } else if self.replay.is_some() {
                            return self.fail_replay(rx, 1);
                        } else {
                            self.log.line("sync_gate_mcp: direct server input closed");
                            return 1;
                        }
                    }
                }
                Event::Output(source, piece) if source == self.source => {
                    if self.replay.is_some()
                        && piece.first
                        && response_id(&piece.bytes).is_some_and(|id| {
                            self.replay.as_ref().is_some_and(|(key, _)| id == *key)
                        })
                    {
                        // The client's own initialize: its reply, error or not, is the client's to
                        // judge, as with a direct server; the session goes on either way.
                        if self.replay_is_client {
                            self.forwarding = true;
                        } else {
                            self.swallowed = Some(Vec::new());
                        }
                    }
                    if let Some(reply) = self.swallowed.as_mut() {
                        if let Some(e) = &self.endpoint {
                            let _ = e.ack.send(());
                        }
                        // The client was told it is initialized: only a whole, checked success
                        // lets the session go on with this server.
                        let why = if reply.len() + piece.bytes.len() > MAX_STORED_INITIALIZE {
                            // shortcut: a reply over 8 MiB to the replayed initialize ends the
                            // session, check it while streaming if real servers send that much.
                            Some("replied to the replayed initialize with more than 8 MiB")
                        } else {
                            reply.extend_from_slice(&piece.bytes);
                            let key = self.replay.as_ref().map_or("", |(key, _)| key.as_str());
                            piece.end.then(|| not_accepted(reply, key)).flatten()
                        };
                        if let Some(why) = why {
                            self.log
                                .line(&format!("sync_gate_mcp: '{}' {why}", self.name));
                            return self.fail_replay(rx, 1);
                        }
                        if piece.end {
                            self.swallowed = None;
                            self.replay = None;
                            if !self.send(
                                b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n"
                                    .to_vec(),
                            ) {
                                return self.fail_replay(rx, 1);
                            }
                            self.errors(LOST);
                        }
                        continue;
                    }
                    if !piece.streamed
                        && !piece.end
                        && (source == Source::Hub || self.replay.is_some())
                    {
                        if let Some(e) = &self.endpoint {
                            let _ = e.ack.send(());
                        }
                        continue;
                    }
                    if piece.first {
                        self.output_id = response_id(&piece.bytes);
                    }
                    if piece.end
                        && let Some(id) = self.output_id.take()
                    {
                        self.flight.remove(&id);
                    }
                    self.output_open = !piece.end;
                    let end = piece.end;
                    // Only one output piece per endpoint is admitted until its write completes;
                    // the rest of the queue is at most MAX_TRACKED + 1 error replies, each as
                    // long as the id it echoes.
                    self.out.push(piece.bytes, Some(source));
                    if self.forwarding && end {
                        // The client's own initialize is answered; the rest was lost with the hub.
                        self.forwarding = false;
                        self.replay = None;
                        self.errors(LOST);
                    }
                }
                Event::OutputEnd(source) if source == self.source => {
                    if source == Source::Hub {
                        if let Err(code) = self.fallback() {
                            return self.fail_replay(rx, code);
                        }
                    } else if self.replay.is_some() {
                        return self.fail_replay(rx, 1);
                    } else {
                        output_done = true;
                        if closing.is_none() {
                            closing = Some(
                                Instant::now()
                                    + self.options.exit_grace.min(Duration::from_secs(5)),
                            );
                        }
                    }
                }
                _ => {}
            }
            if self.replay.is_none()
                && self.writing.is_none()
                && let Some(piece) = self.held.take()
                && !self.forward(piece)
            {
                self.log.line("sync_gate_mcp: direct server input closed");
                return 1;
            }
        }
    }
    /// When the pending hub write times out; none while the destination is not the hub.
    fn hub_write_deadline(&self) -> Option<Instant> {
        match self.writing {
            Some((_, t)) if self.source == Source::Hub => Some(t + self.options.write_timeout),
            _ => None,
        }
    }
    fn forward(&mut self, piece: Piece) -> bool {
        self.input_open = piece.streamed && !piece.end;
        if piece.first {
            self.line_source = self.source;
            let id = request_id(&piece.bytes);
            self.unknown_large = piece.streamed && id.is_none();
            if self.source == Source::Hub {
                if let Some(id) = id {
                    self.flight.insert(id);
                }
                // JSON fields come in any order: until it has an `initialize`, the relay keeps
                // every object whose start does not show another method, and reads it whole.
                if self.initialize.is_none()
                    && self.initialize_lost.is_none()
                    && piece.bytes.trim_ascii_start().first() == Some(&b'{')
                    && prefix_value(&piece.bytes, "method").is_none_or(|v| v == "initialize")
                {
                    self.init_partial = Some(Vec::new());
                }
            }
        }
        if self.source == Source::Hub
            && let Some(buf) = self.init_partial.as_mut()
        {
            if buf.len() + piece.bytes.len() > MAX_STORED_INITIALIZE {
                // Too large to keep is too large to tell; MCP sends `initialize` first, so a
                // line this size before it is taken for one.
                // shortcut: an undecided line over 8 MiB before the initialize disables the
                // fallback, classify it while streaming if larger compliant handshakes appear.
                self.init_partial = None;
                self.initialize_lost = Some("hub connection lost; initialize too large to replay");
            } else {
                buf.extend_from_slice(&piece.bytes);
                if piece.end
                    && let Some(line) = self.init_partial.take()
                {
                    match parse(&line) {
                        Some(Kind::Request { id, method }) if method == "initialize" => {
                            // Its id may lie past the start the first piece was scanned for.
                            let id = id.to_string();
                            self.flight.insert(id.clone());
                            self.initialize = Some((id, line));
                        }
                        Some(_) => {}
                        // Unreadable (too deep, not JSON) is not "no initialize": it may be one.
                        None => {
                            self.initialize_lost =
                                Some("hub connection lost; initialize could not be read to replay");
                        }
                    }
                }
            }
        }
        if self.line_source != self.source {
            return true;
        }
        self.send(piece.bytes)
    }
    fn cleanup(&mut self, rx: &Receiver<Event>) {
        let until = self.cleanup_until.unwrap_or_else(|| {
            Instant::now() + self.options.exit_grace.min(Duration::from_secs(5))
        });
        self.stop_endpoint();
        self.out.finish(rx, until, &self.options.shutdown);
        if let Some(child) = self.child.as_mut() {
            child.stdin.take();
            while Instant::now() < until {
                match child.try_wait() {
                    Ok(Some(_)) | Err(_) => break,
                    Ok(None) => std::thread::sleep(TICK),
                }
            }
        }
    }
}

fn earlier(a: Option<Instant>, b: Instant) -> Option<Instant> {
    Some(a.map_or(b, |a| a.min(b)))
}
fn parse(bytes: &[u8]) -> Option<Kind> {
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .map(|v| classify(&v))
}
fn request_id(bytes: &[u8]) -> Option<String> {
    match parse(bytes) {
        Some(Kind::Request { id, .. }) => Some(id.to_string()),
        // Too large to parse: only a message with a top-level method is a request. A large
        // response (it has an id but no method) must not be tracked.
        None if prefix_field(bytes, "method").is_some() => scan_id(bytes),
        _ => None,
    }
}
fn response_id(bytes: &[u8]) -> Option<String> {
    match parse(bytes) {
        Some(Kind::Response { id }) => Some(id.to_string()),
        None if prefix_field(bytes, "method").is_none()
            && (prefix_field(bytes, "result").is_some()
                || prefix_field(bytes, "error").is_some()) =>
        {
            scan_id(bytes)
        }
        _ => None,
    }
}
/// Why the whole reply to a silent replay is not a success for `key`; `None` when it is.
fn not_accepted(reply: &[u8], key: &str) -> Option<&'static str> {
    let Ok(v) = serde_json::from_slice::<Value>(reply) else {
        return Some("gave no valid reply to the replayed initialize");
    };
    if v.get("error").is_some() {
        Some("refused the replayed initialize")
    } else if v.get("result").is_some()
        && matches!(classify(&v), Kind::Response { id } if serde_json::from_str::<Value>(key).is_ok_and(|k| k == id))
    {
        None
    } else {
        Some("gave no valid reply to the replayed initialize")
    }
}
/// Tolerant top-level id scan: ignores strings, nested ids and the rest of a huge JSON value.
fn scan_id(bytes: &[u8]) -> Option<String> {
    let id = prefix_value(bytes, "id")?;
    if id.is_string() || id.is_number() || id.is_null() {
        Some(id.to_string())
    } else {
        None
    }
}
fn prefix_value(bytes: &[u8], field: &str) -> Option<Value> {
    serde_json::Deserializer::from_slice(prefix_field(bytes, field)?)
        .into_iter::<Value>()
        .next()?
        .ok()
}
fn prefix_field<'a>(bytes: &'a [u8], field: &str) -> Option<&'a [u8]> {
    let bytes = &bytes[..bytes.len().min(64 * 1024)];
    let (mut i, mut depth) = (0, 0usize);
    while i < bytes.len() {
        match bytes[i] {
            b'{' | b'[' => {
                depth += 1;
                i += 1;
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                i += 1;
            }
            b'"' => {
                let start = i;
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\\' {
                        i += 2;
                    } else if bytes[i] == b'"' {
                        i += 1;
                        break;
                    } else {
                        i += 1;
                    }
                }
                if i > bytes.len() {
                    return None;
                }
                if depth != 1
                    || serde_json::from_slice::<String>(&bytes[start..i])
                        .ok()
                        .as_deref()
                        != Some(field)
                {
                    continue;
                }
                while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                if bytes.get(i) != Some(&b':') {
                    continue;
                }
                i += 1;
                return Some(&bytes[i..]);
            }
            _ => i += 1,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_scan_only_recovers_complete_top_level_ids() {
        assert_eq!(
            scan_id(br#"{"nested":{"id":9},"text":"escaped \"id\":7","id":"client-3","rest":"#),
            Some("\"client-3\"".into())
        );
        assert_eq!(scan_id(br#"{"id":-12,"result":"#), Some("-12".into()));
        assert_eq!(scan_id(br#"{"id":null,"result":"#), Some("null".into()));
        assert_eq!(scan_id(br#"{"nested":{"id":9},"id":"unfinished"#), None);
        assert_eq!(scan_id(br#"{"nested":{"id":9},"result":"#), None);
    }
}
