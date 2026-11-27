//! Pure state machine that multiplexes many MCP clients onto ONE child MCP
//! server of the `initialize` generation. No I/O, no threads, no clock: the
//! caller feeds lines and the current `Instant`, and writes what comes back.
//!
//! Phases of the child: `Stopped -> Probing -> Initializing -> Ready`, with the
//! side exits `Stateless` (child answered the `server/discover` probe with a
//! `DiscoverResult`: no `initialize`, clients are served from that result),
//! `Unsupported` (child speaks no version the hub knows) and `Failed`
//! (initialize failed or timed out). Requests that arrive before
//! `Ready` wait in a per-client queue (with a deadline) and are served, in
//! order, once ready.
//!
//! Resource subscriptions are tracked per uri: `Pending` while the first
//! `resources/subscribe` is in flight to the child (later subscribers wait for
//! its outcome), then `Active` with the set of subscribed clients.

use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};
use sync_gate_core::{Kind, classify, error_response, result_response};

pub type ClientId = u32;

/// Protocol generation of the child, known once the probe is answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Era {
    Legacy,
    Stateless,
}

/// What the caller must do. Lines carry no trailing newline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Out {
    ToChild(String),
    ToClient(ClientId, String),
    /// Decision worth surfacing in `status`. Never contains message payloads.
    Note(String),
}

pub const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;
/// Requests in flight to the child for one client.
pub const MAX_IN_FLIGHT_PER_CLIENT: usize = 256;
/// Total bytes one client may have queued before the child is ready.
pub const MAX_QUEUED_BYTES_PER_CLIENT: usize = 8 * 1024 * 1024;
/// Resource uris one client may hold (active, first subscriber or waiter).
pub const MAX_SUBSCRIPTIONS_PER_CLIENT: usize = 1024;
/// Requests one client may have queued before the child is ready.
pub const MAX_QUEUED_PER_CLIENT: usize = 256;
const NOTED_METHODS_CAP: usize = 64;
const METHOD_NOTE_MAX: usize = 128;
const MODERN_VERSION: &str = "2026-07-28";
const LEGACY_VERSION: &str = "2025-11-25";
const UNSUPPORTED_VERSION: i64 = -32022;
const LEGACY_VERSIONS: [&str; 4] = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
/// Not a valid method name, so a child cannot collide with it.
const NOTE_SUBSCRIPTIONS: &str = "\u{0}subscriptions";
const NO_VERSION: &str = "mcp server speaks no supported version";
const META_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
const META_INFO: &str = "io.modelcontextprotocol/clientInfo";
const META_CAPS: &str = "io.modelcontextprotocol/clientCapabilities";

#[derive(Debug, Clone, Copy)]
enum Phase {
    Stopped,
    Probing {
        id: u64,
        deadline: Instant,
    },
    Initializing {
        id: u64,
        deadline: Instant,
    },
    Ready,
    Stateless,
    /// Child answered the probe but speaks no version the hub supports.
    Unsupported,
    Failed,
}

struct Queued {
    msg: Value,
    bytes: usize,
    deadline: Instant,
}

#[derive(Default)]
struct ClientState {
    /// Requests waiting for the child, in arrival order.
    queue: VecDeque<Queued>,
    queued_bytes: usize,
    /// The client has sent `initialize` and been answered by the hub.
    handshaken: bool,
}

/// Why a request is in flight to the child.
enum Role {
    Plain,
    /// First `resources/subscribe` of a uri; waiters live in `Sub::Pending`.
    Subscribe(String),
    /// Hub-originated re-subscribe after a child restart.
    Resub(String),
}

struct Pending {
    /// `None` when nobody should get the reply (abandoned or hub-originated).
    client: Option<ClientId>,
    orig_id: Value,
    deadline: Instant,
    /// A legacy client on a stateless child: it cannot answer `input_required`.
    strict: bool,
    /// Hub-side progress token and the client's original one.
    token: Option<(String, Value)>,
    role: Role,
}

enum Sub {
    /// `left`: clients that unsubscribed again while the subscribe was in flight.
    Pending {
        waiters: Vec<(ClientId, Value)>,
        left: BTreeSet<ClientId>,
    },
    Active(BTreeSet<ClientId>),
}

pub struct Mux {
    server: String,
    request_timeout: Duration,
    next_id: u64,
    phase: Phase,
    era: Option<Era>,
    init_result: Option<Value>,
    /// The child's `DiscoverResult` (stateless era only).
    discover: Option<Value>,
    clients: BTreeMap<ClientId, ClientState>,
    pending: BTreeMap<u64, Pending>,
    tokens: HashMap<String, u64>,
    subs: HashMap<String, Sub>,
    noted: HashSet<String>,
}

impl Mux {
    pub fn new(server: &str, request_timeout: Duration) -> Mux {
        Mux {
            server: server.to_string(),
            request_timeout,
            next_id: 1,
            phase: Phase::Stopped,
            era: None,
            init_result: None,
            discover: None,
            clients: BTreeMap::new(),
            pending: BTreeMap::new(),
            tokens: HashMap::new(),
            subs: HashMap::new(),
            noted: HashSet::new(),
        }
    }

    pub fn era(&self) -> Option<Era> {
        self.era
    }
    pub fn clients(&self) -> usize {
        self.clients.len()
    }
    /// True when the child is alive but unusable (initialize failed or timed out):
    /// restarting it may help, so the host should restart it.
    pub fn failed(&self) -> bool {
        matches!(self.phase, Phase::Failed)
    }
    /// True when the child speaks no protocol version the hub supports: restarting
    /// will not help, so the host should stop the child and leave the server
    /// marked unavailable.
    pub fn unsupported(&self) -> bool {
        matches!(self.phase, Phase::Unsupported)
    }
    pub fn in_flight(&self) -> usize {
        self.pending.len()
    }
    /// True when the child serves requests (initialized, or stateless).
    pub fn ready(&self) -> bool {
        matches!(self.phase, Phase::Ready | Phase::Stateless)
    }
    /// True when the client holds a resource subscription here (active, first or waiter).
    pub fn holds_subscriptions(&self, c: ClientId) -> bool {
        !self.held_uris(c).is_empty()
    }
    pub fn handshaken(&self, c: ClientId) -> bool {
        self.clients.get(&c).is_some_and(|cl| cl.handshaken)
    }
    /// The client handshook through another mux of the same pool: it gets broadcasts here too.
    pub fn mark_handshaken(&mut self, c: ClientId) {
        if let Some(cl) = self.clients.get_mut(&c) {
            cl.handshaken = true;
        }
    }

    fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    // ---- child lifecycle -------------------------------------------------

    /// The child process is up: start generation detection.
    pub fn child_started(&mut self, now: Instant) -> Vec<Out> {
        let id = self.next_id();
        self.phase = Phase::Probing {
            id,
            deadline: now + PROBE_TIMEOUT,
        };
        let meta = hub_meta();
        let probe =
            json!({"jsonrpc":"2.0","id":id,"method":"server/discover","params":{"_meta":meta}});
        vec![Out::ToChild(probe.to_string())]
    }

    /// The child process is gone: fail what was in flight and forget its session.
    pub fn child_exited(&mut self) -> Vec<Out> {
        let mut out = vec![];
        for (_, p) in std::mem::take(&mut self.pending) {
            let who = p.client.map(|c| (c, p.orig_id.clone()));
            match p.role {
                Role::Plain => {
                    if let Some((c, id)) = who {
                        push_client(
                            &mut out,
                            c,
                            error_response(&id, -32000, "mcp server restarted"),
                        );
                    }
                }
                Role::Subscribe(uri) => {
                    self.fail_subscribe(&uri, who, -32000, "mcp server restarted", &mut out)
                }
                // Active uris stay and are restored by the next child.
                Role::Resub(_) => {}
            }
        }
        self.tokens.clear();
        self.init_result = None;
        self.discover = None;
        self.era = None;
        self.phase = Phase::Stopped;
        out
    }

    fn start_initialize(&mut self, now: Instant, out: &mut Vec<Out>) {
        let id = self.next_id();
        self.phase = Phase::Initializing {
            id,
            deadline: now + self.request_timeout,
        };
        let params = json!({"protocolVersion": LEGACY_VERSION, "capabilities": {}, "clientInfo": hub_info()});
        let msg = json!({"jsonrpc":"2.0","id":id,"method":"initialize","params":params});
        out.push(Out::ToChild(msg.to_string()));
    }

    /// The child answered `server/discover`: no `initialize`. Legacy clients get
    /// an `initialize` result built from the `DiscoverResult`.
    fn set_stateless(&mut self, discover: Value, now: Instant, out: &mut Vec<Out>) {
        self.reset_subscriptions();
        let mut discover = discover;
        // Advertise only what the hub serves: it refuses subscriptions and sends no list_changed here.
        if let Some(caps) = discover
            .get_mut("capabilities")
            .and_then(Value::as_object_mut)
        {
            for (cap, key) in [
                ("resources", "subscribe"),
                ("resources", "listChanged"),
                ("tools", "listChanged"),
                ("prompts", "listChanged"),
            ] {
                if let Some(o) = caps.get_mut(cap).and_then(Value::as_object_mut) {
                    o.remove(key);
                }
            }
        }
        let mut init = json!({
            "protocolVersion": LEGACY_VERSION,
            "capabilities": discover.get("capabilities").cloned().unwrap_or_else(|| json!({})),
            "serverInfo": discover.pointer("/_meta/io.modelcontextprotocol~1serverInfo").cloned()
                .unwrap_or_else(|| json!({"name": self.server, "version": "unknown"})),
        });
        if let Some(i) = discover.get("instructions") {
            init["instructions"] = i.clone();
        }
        self.init_result = Some(init);
        self.discover = Some(discover);
        self.era = Some(Era::Stateless);
        self.phase = Phase::Stateless;
        self.serve_queued(now, out);
    }

    /// Entries from an earlier legacy child can never be restored or undone now.
    fn reset_subscriptions(&mut self) {
        self.subs.clear();
        let restores: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, p)| matches!(p.role, Role::Resub(_)))
            .map(|(h, _)| *h)
            .collect();
        for h in restores {
            self.take_pending(h);
        }
    }

    /// Modern child that offers no version the hub speaks: no fallback to `initialize`.
    fn set_unsupported(&mut self, out: &mut Vec<Out>) {
        self.reset_subscriptions();
        self.era = Some(Era::Stateless);
        self.phase = Phase::Unsupported;
        out.push(Out::Note(format!(
            "{}: child speaks no supported protocol version",
            self.server
        )));
        self.fail_queued(-32000, NO_VERSION, out);
    }

    fn set_failed(&mut self, why: &str, out: &mut Vec<Out>) {
        self.phase = Phase::Failed;
        out.push(Out::Note(format!("{}: {why}", self.server)));
        self.fail_queued(-32000, "mcp server failed to initialize", out);
    }

    fn set_ready(&mut self, result: Value, now: Instant, out: &mut Vec<Out>) {
        self.init_result = Some(result);
        self.era = Some(Era::Legacy);
        self.phase = Phase::Ready;
        out.push(Out::ToChild(
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}).to_string(),
        ));
        // A restarted child lost its subscriptions: restore the active ones.
        let uris: Vec<String> = self
            .subs
            .iter()
            .filter(|(_, s)| matches!(s, Sub::Active(_)))
            .map(|(u, _)| u.clone())
            .collect();
        for uri in uris {
            let hub = self.next_id();
            let msg = json!({"jsonrpc":"2.0","id":hub,"method":"resources/subscribe","params":{"uri":uri}});
            self.pending.insert(
                hub,
                Pending {
                    client: None,
                    orig_id: Value::Null,
                    deadline: now + self.request_timeout,
                    token: None,
                    role: Role::Resub(uri),
                    strict: false,
                },
            );
            out.push(Out::ToChild(msg.to_string()));
        }
        self.serve_queued(now, out);
    }

    /// Serves, in order, what clients queued while the child was not ready.
    fn serve_queued(&mut self, now: Instant, out: &mut Vec<Out>) {
        let ids: Vec<ClientId> = self.clients.keys().copied().collect();
        for c in ids {
            let queued = match self.clients.get_mut(&c) {
                Some(cl) => {
                    cl.queued_bytes = 0;
                    std::mem::take(&mut cl.queue)
                }
                None => continue,
            };
            for q in queued {
                if let Kind::Request { id, method } = classify(&q.msg) {
                    self.serve(c, id, &method, q.msg, now, out);
                }
            }
        }
    }

    fn fail_queued(&mut self, code: i64, message: &str, out: &mut Vec<Out>) {
        for (c, cl) in &mut self.clients {
            cl.queued_bytes = 0;
            for q in cl.queue.drain(..) {
                push_client(out, *c, error_response(&q.msg["id"], code, message));
            }
        }
    }

    // ---- time ------------------------------------------------------------

    pub fn tick(&mut self, now: Instant) -> Vec<Out> {
        let mut out = vec![];
        match self.phase {
            Phase::Probing { deadline, .. } if now >= deadline => {
                self.start_initialize(now, &mut out)
            }
            Phase::Initializing { deadline, .. } if now >= deadline => {
                self.set_failed("child did not answer initialize in time", &mut out);
            }
            _ => {}
        }
        for (c, cl) in &mut self.clients {
            let (expired, keep): (Vec<Queued>, Vec<Queued>) =
                cl.queue.drain(..).partition(|q| now >= q.deadline);
            cl.queued_bytes = keep.iter().map(|q| q.bytes).sum();
            cl.queue = keep.into();
            for q in expired {
                push_client(
                    &mut out,
                    *c,
                    error_response(&q.msg["id"], -32001, "request timed out"),
                );
            }
        }
        let expired: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, p)| now >= p.deadline)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            let Some(p) = self.take_pending(id) else {
                continue;
            };
            let who = p.client.map(|c| (c, p.orig_id.clone()));
            match p.role {
                Role::Plain => {
                    if let Some((c, rid)) = who {
                        push_client(
                            &mut out,
                            c,
                            error_response(&rid, -32001, "request timed out"),
                        );
                    }
                }
                Role::Subscribe(uri) => {
                    self.fail_subscribe(&uri, who, -32001, "request timed out", &mut out)
                }
                Role::Resub(uri) => self.drop_restored(&uri, &mut out),
            }
            out.push(cancel_to_child(
                &json!({"requestId": id, "reason": "request timed out"}),
            ));
        }
        out
    }

    // ---- clients ---------------------------------------------------------

    pub fn client_attached(&mut self, id: ClientId) {
        self.clients.entry(id).or_default();
    }

    /// Cancels the client's in-flight requests and drops its subscriptions.
    pub fn client_detached(&mut self, id: ClientId) -> Vec<Out> {
        let mut out = vec![];
        if self.clients.remove(&id).is_none() {
            return out;
        }
        for sub in self.subs.values_mut() {
            if let Sub::Pending { waiters, left } = sub {
                waiters.retain(|(c, _)| *c != id);
                left.remove(&id);
            }
        }
        let mine: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, p)| p.client == Some(id))
            .map(|(h, _)| *h)
            .collect();
        for hub in mine {
            let params = json!({"requestId": hub, "reason": "client detached"});
            out.extend(self.abandon(hub, params));
        }
        let emptied: Vec<String> = self
            .subs
            .iter_mut()
            .filter_map(|(uri, s)| match s {
                Sub::Active(set) => (set.remove(&id) && set.is_empty()).then(|| uri.clone()),
                Sub::Pending { .. } => None,
            })
            .collect();
        for uri in emptied {
            self.subs.remove(&uri);
            self.forget_restore(&uri);
            if matches!(self.phase, Phase::Ready) {
                self.unsubscribe_on_child(&uri, &mut out);
            }
        }
        out
    }

    /// Stops tracking a restore request for `uri`, so its late reply or timeout
    /// cannot touch the entry a newer subscriber now owns.
    fn forget_restore(&mut self, uri: &str) {
        let hubs: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, p)| matches!(&p.role, Role::Resub(u) if u == uri))
            .map(|(h, _)| *h)
            .collect();
        for h in hubs {
            self.take_pending(h);
        }
    }

    /// Fire-and-forget `resources/unsubscribe`; its reply is dropped as an unknown id.
    fn unsubscribe_on_child(&mut self, uri: &str, out: &mut Vec<Out>) {
        let hub = self.next_id();
        out.push(Out::ToChild(
            json!({"jsonrpc":"2.0","id":hub,"method":"resources/unsubscribe","params":{"uri":uri}})
                .to_string(),
        ));
    }

    /// A client no longer wants request `hub`. A subscribe other clients are
    /// waiting on stays in flight (its reply just goes nowhere); anything else
    /// is forgotten and cancelled on the child with `cancel_params`.
    fn abandon(&mut self, hub: u64, cancel_params: Value) -> Option<Out> {
        let shared = self
            .pending
            .get(&hub)
            .is_some_and(|p| matches!(&p.role, Role::Subscribe(u) if self.has_waiters(u)));
        if shared {
            if let Some(p) = self.pending.get_mut(&hub) {
                p.client = None;
            }
            return None;
        }
        let p = self.take_pending(hub)?;
        if let Role::Subscribe(uri) = &p.role {
            self.subs.remove(uri);
        }
        Some(cancel_to_child(&cancel_params))
    }

    fn has_waiters(&self, uri: &str) -> bool {
        matches!(self.subs.get(uri), Some(Sub::Pending { waiters, .. }) if !waiters.is_empty())
    }

    pub fn client_line(&mut self, id: ClientId, line: &str, now: Instant) -> Vec<Out> {
        let mut out = vec![];
        if !self.clients.contains_key(&id) {
            out.push(Out::Note(format!(
                "{}: line from unknown client {id} dropped",
                self.server
            )));
            return out;
        }
        let err = |code, msg: &str, rid: &Value| error_response(rid, code, msg);
        if line.len() > MAX_MESSAGE_BYTES {
            // Too big to parse, so its id cannot be read: parse error with a null id.
            push_client(&mut out, id, err(-32700, "parse error", &Value::Null));
            return out;
        }
        let Ok(v) = serde_json::from_str::<Value>(line.trim()) else {
            push_client(&mut out, id, err(-32700, "parse error", &Value::Null));
            return out;
        };
        match classify(&v) {
            Kind::Request { id: rid, method } => {
                self.client_request(id, rid, &method, v, line.len(), now, &mut out)
            }
            Kind::Notification { method } => self.client_notification(id, &method, &v, &mut out),
            Kind::Response { .. } => {} // the hub never forwards server requests to clients
            Kind::Invalid => {
                let readable = v
                    .get("id")
                    .filter(|i| i.is_string() || i.is_i64() || i.is_u64());
                let e = match readable {
                    Some(rid) => err(-32600, "invalid request", rid),
                    None => err(-32700, "parse error", &Value::Null),
                };
                push_client(&mut out, id, e);
            }
        }
        out
    }

    #[allow(clippy::too_many_arguments)]
    fn client_request(
        &mut self,
        c: ClientId,
        rid: Value,
        method: &str,
        v: Value,
        bytes: usize,
        now: Instant,
        out: &mut Vec<Out>,
    ) {
        match self.phase {
            Phase::Ready | Phase::Stateless => self.serve(c, rid, method, v, now, out),
            Phase::Unsupported => push_client(out, c, error_response(&rid, -32000, NO_VERSION)),
            Phase::Failed => push_client(
                out,
                c,
                error_response(&rid, -32000, "mcp server failed to initialize"),
            ),
            Phase::Stopped | Phase::Probing { .. } | Phase::Initializing { .. } => {
                let deadline = now + self.request_timeout;
                let Some(cl) = self.clients.get_mut(&c) else {
                    return;
                };
                if cl.queue.len() >= MAX_QUEUED_PER_CLIENT
                    || cl.queued_bytes + bytes > MAX_QUEUED_BYTES_PER_CLIENT
                {
                    push_client(out, c, error_response(&rid, -32000, "mcp server not ready"));
                } else {
                    cl.queued_bytes += bytes;
                    cl.queue.push_back(Queued {
                        msg: v,
                        bytes,
                        deadline,
                    });
                }
            }
        }
    }

    /// Load of one client on the child: its own in-flight requests, plus the
    /// subscribes it waits on and the ownerless ones kept alive for it.
    fn over_cap(&self, c: ClientId) -> bool {
        let waits_on = |uri: &str| {
            matches!(self.subs.get(uri), Some(Sub::Pending { waiters, .. })
                if waiters.iter().any(|(w, _)| *w == c))
        };
        let mut n = 0;
        for p in self.pending.values() {
            match (&p.client, &p.role) {
                (Some(o), _) if *o == c => n += 1,
                (None, Role::Subscribe(u)) if waits_on(u) => n += 1,
                _ => {}
            }
        }
        for sub in self.subs.values() {
            if let Sub::Pending { waiters, .. } = sub {
                n += waiters.iter().filter(|(w, _)| *w == c).count();
            }
        }
        n >= MAX_IN_FLIGHT_PER_CLIENT
    }

    /// Resource uris the client holds: active, first subscriber or waiter.
    fn held_uris(&self, c: ClientId) -> HashSet<&str> {
        let mut held: HashSet<&str> = self
            .subs
            .iter()
            .filter(|(_, s)| match s {
                Sub::Active(set) => set.contains(&c),
                Sub::Pending { waiters, .. } => waiters.iter().any(|(w, _)| *w == c),
            })
            .map(|(u, _)| u.as_str())
            .collect();
        for p in self.pending.values() {
            if let (Some(o), Role::Subscribe(u)) = (&p.client, &p.role)
                && *o == c
            {
                held.insert(u.as_str());
            }
        }
        held
    }

    /// Serves one request while the child is `Ready` or `Stateless`.
    fn serve(
        &mut self,
        c: ClientId,
        rid: Value,
        method: &str,
        v: Value,
        now: Instant,
        out: &mut Vec<Out>,
    ) {
        let over = self.over_cap(c);
        let stateless = matches!(self.phase, Phase::Stateless);
        // A request is modern when it carries its own protocol version.
        let modern = v
            .pointer("/params/_meta/io.modelcontextprotocol~1protocolVersion")
            .and_then(Value::as_str)
            .is_some_and(|ver| !LEGACY_VERSIONS.contains(&ver));
        if modern && let Some(cl) = self.clients.get_mut(&c) {
            cl.handshaken = true;
        }
        let strict = stateless && !modern;
        let local = |out: &mut Vec<Out>, r: Value| push_client(out, c, result_response(&rid, r));
        let too_many = |out: &mut Vec<Out>| {
            push_client(
                out,
                c,
                error_response(&rid, -32000, "too many requests in flight"),
            )
        };
        let uri = v
            .pointer("/params/uri")
            .and_then(Value::as_str)
            .map(str::to_string);
        match (method, uri) {
            ("initialize", _) => {
                if let Some(cl) = self.clients.get_mut(&c) {
                    cl.handshaken = true;
                }
                let cached = self.init_result.clone().unwrap_or_else(|| json!({}));
                local(out, cached);
            }
            ("ping" | "logging/setLevel", _) => local(out, json!({})),
            ("server/discover", _) if stateless && modern => {
                local(out, self.discover.clone().unwrap_or_else(|| json!({})))
            }
            ("server/discover", _) => {
                push_client(out, c, error_response(&rid, -32601, "method not found"))
            }
            // `subscriptions/listen` streams replace subscribe in the new revision;
            // sharing them across clients is not built, so refuse (see report).
            ("resources/subscribe" | "resources/unsubscribe" | "subscriptions/listen", _)
                if stateless =>
            {
                push_client(
                    out,
                    c,
                    error_response(
                        &rid,
                        -32601,
                        "subscriptions are not supported through the hub for this server",
                    ),
                );
                if self.noted.insert(NOTE_SUBSCRIPTIONS.to_string()) {
                    out.push(Out::Note(format!(
                        "{}: subscriptions refused on a stateless child",
                        self.server
                    )));
                }
            }
            ("resources/subscribe" | "resources/unsubscribe", None) => {
                push_client(
                    out,
                    c,
                    error_response(&rid, -32602, "invalid params: uri required"),
                );
            }
            ("resources/subscribe", Some(uri)) => {
                let held = self.held_uris(c);
                if !held.contains(uri.as_str()) && held.len() >= MAX_SUBSCRIPTIONS_PER_CLIENT {
                    push_client(
                        out,
                        c,
                        error_response(&rid, -32000, "too many subscriptions"),
                    );
                    return;
                }
                match self.subs.get_mut(&uri) {
                    Some(Sub::Active(set)) => {
                        set.insert(c);
                        local(out, json!({}));
                    }
                    Some(Sub::Pending { .. }) if over => too_many(out),
                    // The first subscribe is in flight: wait for its outcome.
                    Some(Sub::Pending { waiters, left }) => {
                        left.remove(&c);
                        waiters.push((c, rid));
                    }
                    None if over => too_many(out),
                    None => {
                        self.subs.insert(
                            uri.clone(),
                            Sub::Pending {
                                waiters: vec![],
                                left: BTreeSet::new(),
                            },
                        );
                        self.forward(c, rid, v, now, Role::Subscribe(uri), false, out);
                    }
                }
            }
            ("resources/unsubscribe", Some(uri)) => match self.subs.get_mut(&uri) {
                Some(Sub::Active(set)) if set.contains(&c) && set.len() == 1 => {
                    if over {
                        too_many(out);
                    } else {
                        self.subs.remove(&uri);
                        self.forget_restore(&uri);
                        self.forward(c, rid, v, now, Role::Plain, false, out);
                    }
                }
                Some(Sub::Active(set)) => {
                    set.remove(&c);
                    local(out, json!({}));
                }
                Some(Sub::Pending { left, .. }) => {
                    left.insert(c);
                    local(out, json!({}));
                }
                None => local(out, json!({})),
            },
            _ if over => too_many(out),
            _ => self.forward(c, rid, v, now, Role::Plain, strict, out),
        }
    }

    /// Sends the client's request to the child under a fresh hub id. `strict`
    /// adds the per-request `_meta` a stateless child expects from a legacy client.
    #[allow(clippy::too_many_arguments)]
    fn forward(
        &mut self,
        c: ClientId,
        rid: Value,
        mut msg: Value,
        now: Instant,
        role: Role,
        strict: bool,
        out: &mut Vec<Out>,
    ) {
        let hub = self.next_id();
        msg["id"] = json!(hub);
        if strict {
            inject_meta(&mut msg);
        }
        let mut token = None;
        if let Some(t) = msg.pointer_mut("/params/_meta/progressToken")
            && (t.is_string() || t.is_i64() || t.is_u64())
        {
            let mine = format!("fg-{hub}");
            token = Some((mine.clone(), std::mem::replace(t, json!(mine))));
        }
        if let Some((mine, _)) = &token {
            self.tokens.insert(mine.clone(), hub);
        }
        self.pending.insert(
            hub,
            Pending {
                client: Some(c),
                orig_id: rid,
                deadline: now + self.request_timeout,
                strict,
                token,
                role,
            },
        );
        out.push(Out::ToChild(msg.to_string()));
    }

    fn client_notification(&mut self, c: ClientId, method: &str, v: &Value, out: &mut Vec<Out>) {
        // `notifications/initialized` and anything else a client sends are swallowed.
        if method != "notifications/cancelled" {
            return;
        }
        let Some(target) = v.pointer("/params/requestId") else {
            return;
        };
        let hub = self
            .pending
            .iter()
            .find(|(_, p)| p.client == Some(c) && p.orig_id == *target)
            .map(|(h, _)| *h);
        match hub {
            Some(hub) => {
                let mut params = v["params"].clone();
                params["requestId"] = json!(hub);
                out.extend(self.abandon(hub, params));
            }
            None => {
                // A waiter's own subscribe: no reply, and it does not become active.
                let waiting = self.subs.values_mut().find_map(|s| match s {
                    Sub::Pending { waiters, .. } => waiters
                        .iter()
                        .position(|(w, r)| *w == c && r == target)
                        .map(|i| waiters.remove(i)),
                    Sub::Active(_) => None,
                });
                if waiting.is_none()
                    && let Some(cl) = self.clients.get_mut(&c)
                {
                    cl.queue.retain(|q| q.msg["id"] != *target);
                    cl.queued_bytes = cl.queue.iter().map(|q| q.bytes).sum();
                }
            }
        }
    }

    // ---- child output ----------------------------------------------------

    pub fn child_line(&mut self, line: &str, now: Instant) -> Vec<Out> {
        let mut out = vec![];
        if line.len() > MAX_MESSAGE_BYTES {
            out.push(Out::Note(format!(
                "{}: oversized line from child dropped",
                self.server
            )));
            return out;
        }
        let Ok(v) = serde_json::from_str::<Value>(line.trim()) else {
            out.push(Out::Note(format!(
                "{}: non-json line from child dropped",
                self.server
            )));
            return out;
        };
        match classify(&v) {
            Kind::Response { id } => self.child_response(&id, v, now, &mut out),
            Kind::Request { id, method } => {
                let reply = if method == "ping" {
                    result_response(&id, json!({}))
                } else {
                    error_response(&id, -32601, "method not found")
                };
                out.push(Out::ToChild(reply.to_string()));
            }
            Kind::Notification { method } => self.child_notification(&method, &v, &mut out),
            Kind::Invalid => out.push(Out::Note(format!(
                "{}: invalid message from child dropped",
                self.server
            ))),
        }
        out
    }

    fn child_response(&mut self, id: &Value, mut v: Value, now: Instant, out: &mut Vec<Out>) {
        let Some(hub) = id.as_u64() else { return };
        let error_code = v.pointer("/error/code").and_then(Value::as_i64);
        let failed = v.get("error").is_some();
        match self.phase {
            Phase::Probing { id: p, .. } if p == hub => {
                // Modern outcomes skip `initialize`: a real DiscoverResult, or a recognized
                // modern error. Anything else (including a loose `{}` result) is a legacy server.
                let versions = v
                    .pointer("/result/supportedVersions")
                    .and_then(Value::as_array);
                if let Some(vs) = versions {
                    if vs.iter().any(|x| x == MODERN_VERSION) {
                        self.set_stateless(v["result"].take(), now, out);
                    } else {
                        self.set_unsupported(out);
                    }
                } else if error_code == Some(UNSUPPORTED_VERSION) {
                    self.set_unsupported(out);
                } else {
                    self.start_initialize(now, out);
                }
            }
            Phase::Initializing { id: p, .. } if p == hub => match (failed, v.get_mut("result")) {
                (false, Some(r)) => {
                    let result = r.take();
                    self.set_ready(result, now, out);
                }
                _ => self.set_failed("child rejected initialize", out),
            },
            _ => {
                // Unknown ids (cancelled, detached, timed out) are dropped silently.
                let Some(p) = self.take_pending(hub) else {
                    return;
                };
                match p.role {
                    Role::Plain => {
                        if let Some(c) = p.client {
                            let needs_input = v
                                .pointer("/result/resultType")
                                .is_some_and(|t| t != "complete");
                            if p.strict && needs_input {
                                let m = "server requires input not supported through the hub";
                                push_client(out, c, error_response(&p.orig_id, -32000, m));
                                return;
                            }
                            v["id"] = p.orig_id;
                            push_client_raw(out, c, &v);
                        }
                    }
                    Role::Subscribe(uri) => {
                        let first = p.client.map(|c| (c, p.orig_id));
                        self.finish_subscribe(&uri, first, &v, failed, out);
                    }
                    Role::Resub(uri) => {
                        if failed {
                            self.drop_restored(&uri, out);
                        }
                    }
                }
            }
        }
    }

    /// The first subscribe of `uri` got its outcome: answer it and every waiter.
    fn finish_subscribe(
        &mut self,
        uri: &str,
        first: Option<(ClientId, Value)>,
        reply: &Value,
        failed: bool,
        out: &mut Vec<Out>,
    ) {
        let (waiters, left) = match self.subs.remove(uri) {
            Some(Sub::Pending { waiters, left }) => (waiters, left),
            _ => (vec![], BTreeSet::new()),
        };
        self.forget_restore(uri);
        let answered: Vec<(ClientId, Value)> = first.into_iter().chain(waiters).collect();
        if !failed {
            // Clients that unsubscribed meanwhile get their reply but are not subscribed.
            let members: BTreeSet<ClientId> = answered
                .iter()
                .map(|(c, _)| *c)
                .filter(|c| !left.contains(c))
                .collect();
            if members.is_empty() {
                // Everyone left while the subscribe was in flight: undo it.
                self.unsubscribe_on_child(uri, out);
            } else {
                self.subs.insert(uri.to_string(), Sub::Active(members));
            }
        }
        for (c, rid) in answered {
            let mut m = reply.clone();
            m["id"] = rid;
            push_client_raw(out, c, &m);
        }
    }

    /// The first subscribe of `uri` failed without a child reply (timeout, exit).
    fn fail_subscribe(
        &mut self,
        uri: &str,
        first: Option<(ClientId, Value)>,
        code: i64,
        message: &str,
        out: &mut Vec<Out>,
    ) {
        let waiters = match self.subs.remove(uri) {
            Some(Sub::Pending { waiters, .. }) => waiters,
            _ => vec![],
        };
        for (c, rid) in first.into_iter().chain(waiters) {
            push_client(out, c, error_response(&rid, code, message));
        }
    }

    /// The new child refused (or never answered) a restored subscription.
    fn drop_restored(&mut self, uri: &str, out: &mut Vec<Out>) {
        // A newer Pending entry for the same uri belongs to someone else's subscribe.
        if matches!(self.subs.get(uri), Some(Sub::Active(_))) {
            self.subs.remove(uri);
        }
        out.push(Out::Note(format!(
            "{}: child refused to restore a resource subscription; dropped",
            self.server
        )));
    }

    fn child_notification(&mut self, method: &str, v: &Value, out: &mut Vec<Out>) {
        if method == "notifications/progress" {
            let hub = v
                .pointer("/params/progressToken")
                .and_then(Value::as_str)
                .and_then(|t| self.tokens.get(t));
            if let Some((p, c)) = hub
                .and_then(|h| self.pending.get(h))
                .and_then(|p| p.client.map(|c| (p, c)))
            {
                let mut msg = v.clone();
                if let Some((_, orig)) = &p.token {
                    msg["params"]["progressToken"] = orig.clone();
                }
                push_client_raw(out, c, &msg);
            }
        } else if method.starts_with("notifications/") && method.ends_with("/list_changed") {
            for (c, cl) in &self.clients {
                if cl.handshaken {
                    push_client_raw(out, *c, v);
                }
            }
        } else if method == "notifications/resources/updated" {
            let uri = v.pointer("/params/uri").and_then(Value::as_str);
            if let Some(Sub::Active(set)) = uri.and_then(|u| self.subs.get(u)) {
                for c in set {
                    push_client_raw(out, *c, v);
                }
            }
        } else {
            let name = truncate(method, METHOD_NOTE_MAX);
            if self.noted.len() < NOTED_METHODS_CAP && self.noted.insert(name.to_string()) {
                out.push(Out::Note(format!(
                    "{}: dropped child notification {name}",
                    self.server
                )));
            }
        }
    }

    // ---- helpers ---------------------------------------------------------

    /// Removes a pending request and its progress token mapping.
    fn take_pending(&mut self, hub: u64) -> Option<Pending> {
        let p = self.pending.remove(&hub)?;
        if let Some((t, _)) = &p.token {
            self.tokens.remove(t);
        }
        Some(p)
    }
}

/// Longest prefix of `s` that is at most `max` bytes and ends on a char boundary.
fn truncate(s: &str, max: usize) -> &str {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn hub_meta() -> Value {
    json!({META_VERSION: MODERN_VERSION, META_INFO: hub_info(), META_CAPS: {}})
}

/// Adds the hub's per-request `_meta` to a legacy client's request.
fn inject_meta(msg: &mut Value) {
    let Some(obj) = msg.as_object_mut() else {
        return;
    };
    let params = obj.entry("params").or_insert_with(|| json!({}));
    if params.is_null() {
        *params = json!({});
    }
    let Some(po) = params.as_object_mut() else {
        return;
    };
    let meta = po.entry("_meta").or_insert_with(|| json!({}));
    if let (Some(m), Some(h)) = (meta.as_object_mut(), hub_meta().as_object()) {
        for (k, v) in h {
            m.insert(k.clone(), v.clone());
        }
    }
}

fn hub_info() -> Value {
    json!({"name": "sync_gate_hub", "version": env!("CARGO_PKG_VERSION")})
}

fn cancel_to_child(params: &Value) -> Out {
    Out::ToChild(
        json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":params}).to_string(),
    )
}

fn push_client(out: &mut Vec<Out>, c: ClientId, v: Value) {
    push_client_raw(out, c, &v);
}

fn push_client_raw(out: &mut Vec<Out>, c: ClientId, v: &Value) {
    out.push(Out::ToClient(c, v.to_string()));
}

#[cfg(test)]
mod tests;
