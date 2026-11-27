//! Daemon-owned background services. Today one: the shared PostgreSQL server, which gives each
//! `sync_gate run` of a declared project a database and a role of its own (a lease). Leases are
//! recorded in `<data_dir>/pg/<major>/leases.json` (no secret) before anything is created, and a
//! role or database is only ever dropped by its creation mark. One worker thread runs every
//! tool call, from one queue; `lease` only waits, and `tick`, `set_holder`, `release` and
//! `give_up` never call a tool. All time inside the decisions comes from `tick(now)`.

pub mod pg_sql;
pub mod pg_tools;
#[cfg(any(test, feature = "testkit"))]
pub mod testkit;

use crate::hub::{CRASH_LIMIT, CRASH_PAUSE, CRASH_WINDOW};
use crate::supervisor::Backoff;
use pg_sql::{
    SqlError, bootstrap_sql, candidate_oids, clone_adopt, create_database, create_database_from,
    create_extensions, create_role, db_activity, db_by_oid, drop_database, drop_role,
    drop_template_role, is_lease_name, lease_env, lease_name, lease_roles, missing_extensions,
    name_taken, owned_databases, redact, template_check, template_names_free, template_own,
    template_rename_db, template_rename_role, template_seal, template_state,
};
use pg_tools::{
    ClusterPaths, OsPgTools, PG_MIN_MAJOR, PgTools, ServerId, write_checked, write_target_refused,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, RwLock, mpsc};
use std::time::{Duration, Instant};
use sync_gate_core::{
    Config, Holder, PgConfig, Response, SERVICE_POSTGRES, Secret, ServiceStatus, is_template_key,
};

/// Admission threshold (R22, ruling P4): no new lease is granted while this many or more rows
/// are `releasing`. A give-back is never refused, so the count may pass it for a moment, bounded
/// by `max_leases` plus this threshold.
pub const MAX_PENDING_RELEASES: usize = 32;
/// Given-up request ids remembered (R30); the oldest leaves first.
pub const ABANDONED_KEEP: usize = 256;
const MAX_NOTES: usize = 200;
/// A registry with more rows than this is not one sync_gate wrote: read as unreadable.
const MAX_ROWS: usize = 1024;
/// Same for `templates.json`.
const MAX_TEMPLATE_ROWS: usize = 1024;
/// `failed` rows kept per project (C6): the newest by `seq`.
const MAX_FAILED_PER_PROJECT: usize = 16;
/// How long `shutdown` waits for the cluster to stop (stop 80 s + 5): after it, the server is
/// left up and the next daemon adopts it (ruling PF15).
const SHUTDOWN_STOP_BOUND: Duration = Duration::from_secs(85);
const QUIET_GRACE: Duration = Duration::from_secs(600);
const QUIET_SAMPLE_EVERY: Duration = Duration::from_secs(30);

const ABANDONED: &str = "request abandoned";
const NOT_RUNNING: &str = "postgres is not running";
const STILL_STARTING: &str = "postgres is still starting";
const STALE: &str = "configuration changed; restarting when idle";
const TEMPLATES_UNREADABLE: &str = "postgres template registry was unreadable; templates are off until the cluster directory is deleted";
const UNREADABLE: &str = "postgres lease registry was unreadable; leftover cleanup is off until the cluster directory is deleted";

/// R5: whether a recorded process still runs. `Unknown` never authorises anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    Alive,
    Gone,
    Unknown,
}

/// `start` = the recorded start time, `alive` and `start_now` = what the process table says
/// now. Gone only when the table was read and the pid is absent, or its start time is another
/// (a reused pid); every comparison is exact (ruling PF7).
pub fn liveness(start: Option<u64>, alive: Option<bool>, start_now: Option<u64>) -> Liveness {
    match (alive, start, start_now) {
        (Some(false), _, _) => Liveness::Gone,
        (_, Some(s), Some(t)) if t != s => Liveness::Gone,
        (_, Some(_), Some(_)) => Liveness::Alive,
        _ => Liveness::Unknown,
    }
}

/// pid -> (alive, start time now).
pub type Probe = Arc<dyn Fn(u32) -> (Option<bool>, Option<u64>) + Send + Sync>;
/// bytes -> that many random bytes as lowercase hex.
pub type Random = Arc<dyn Fn(usize) -> io::Result<String> + Send + Sync>;

pub struct Deps {
    pub tools: Arc<dyn PgTools>,
    pub probe: Probe,
    pub random: Random,
    /// The lease's patience for the `running` state; `None` = `[postgres] lease_wait_secs`.
    pub lease_wait: Option<Duration>,
    pub quiet_grace: Duration,
    pub quiet_sample_every: Duration,
    /// Rereads the config's `[mcp]` for the hub (see [`crate::hub::McpReload`]); `None`: never.
    pub mcp_reload: Option<crate::hub::McpReload>,
    /// Template-registry recovery steps that fail with `injected` (tests).
    #[cfg(test)]
    pub tpl_fail: u32,
}

impl Deps {
    pub fn os() -> Deps {
        Deps {
            tools: Arc::new(OsPgTools),
            probe: Arc::new(|pid| {
                (
                    sync_gate_probe::process_alive(pid),
                    sync_gate_probe::start_time(pid),
                )
            }),
            random: Arc::new(random_hex),
            lease_wait: None,
            quiet_grace: QUIET_GRACE,
            quiet_sample_every: QUIET_SAMPLE_EVERY,
            mcp_reload: None,
            #[cfg(test)]
            tpl_fail: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum RowState {
    Creating,
    Granted,
    Releasing,
}

/// One lease as `leases.json` holds it. No secret.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct DiskRow {
    lease: String,
    token: String,
    project: PathBuf,
    r#gen: u64,
    state: RowState,
    cli: Holder,
    command: Option<Holder>,
}

#[derive(Deserialize)]
struct Disk {
    version: u32,
    unknown_before: bool,
    leases: Vec<DiskRow>,
}

#[derive(Serialize)]
struct DiskOut<'a> {
    version: u32,
    unknown_before: bool,
    leases: Vec<&'a DiskRow>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum TplState {
    Preparing,
    Ready,
    Failed,
}

/// One template database as `templates.json` holds it. No secret.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct TplRow {
    key: String,
    project: PathBuf,
    state: TplState,
    /// The candidate: the name and mark of its lease.
    lease: String,
    token: String,
    /// Identity of the candidate's database and role.
    db_oid: u32,
    role_oid: u32,
    /// `next_seq` at creation and again whenever the row becomes `ready` or `failed`.
    seq: u64,
}

#[derive(Deserialize)]
struct TplDisk {
    version: u32,
    unknown_before: bool,
    next_seq: u64,
    templates: Vec<TplRow>,
}

#[derive(Serialize)]
struct TplOut<'a> {
    version: u32,
    unknown_before: bool,
    next_seq: u64,
    templates: &'a [TplRow],
}

/// A window with no session in the lease's database, on one server run.
#[derive(Clone, Copy)]
struct Quiet {
    server: ServerId,
    since: Instant,
    sessions: i64,
}

struct Row {
    disk: DiskRow,
    quiet: Option<Quiet>,
    retry_at: Option<Instant>,
    backoff: Backoff,
    /// The request that created it; in memory only (R30).
    request: String,
    last_sample: Option<Instant>,
}

impl Row {
    fn new(disk: DiskRow, request: String) -> Row {
        Row {
            disk,
            quiet: None,
            retry_at: None,
            backoff: Backoff::default(),
            request,
            last_sample: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Phase {
    Stopped,
    Starting,
    Reconciling,
    Running,
    Failed(String),
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Kind {
    Release,
    Sample,
    Decide,
}

struct Grant {
    /// The admitted call's entry in `State::open`.
    open: u64,
    request: String,
    project: PathBuf,
    cli: Holder,
    url_vars: Vec<String>,
    /// The CLI's list; granted only while it is the daemon's (`template_choice`).
    extensions: Vec<String>,
    /// The template key the CLI computed; `None` for a project without `migrate`.
    template: Option<String>,
    reply: mpsc::Sender<Response>,
}

/// A candidate whose `migrate` ended with code 0 waits to become its key's template.
struct Promote {
    lease: String,
    reply: mpsc::Sender<Response>,
}

/// What a request with this template key gets (`template_choice`).
enum TplChoice {
    /// A copy of the key's template.
    Clone,
    /// An empty candidate for the key's first migration.
    Prepare,
    Refuse(&'static str),
}

enum Item {
    Adopt,
    Stop,
    Restart,
    Start,
    Promote(Promote),
    Grant(Grant),
    Release(String),
    Sample(String),
    Decide(String, u64),
    /// The retry of a failed retirement (M2).
    Retire,
    IdleStop,
}

/// An admitted lease call. It counts in the admission until its grant has a row, and its
/// give-up lives here, so the bounded `abandoned` history can forget the request without
/// reviving the grant (ruling P2).
struct Open {
    id: u64,
    has_row: bool,
    request: String,
    given_up: bool,
}

struct State {
    phase: Phase,
    /// Adopted with a configuration that is not ours any more: no new lease (R12).
    stale: bool,
    /// Off for good (no worker, a link where the registry is written); the reason.
    disabled: Option<String>,
    server: Option<ServerId>,
    paths: Option<ClusterPaths>,
    loaded: bool,
    unknown_before: bool,
    rows: Vec<Row>,
    /// `templates.json` was read (or set aside) this run; independent of `loaded`.
    tpl_loaded: bool,
    /// The template registry was lost: no template is trusted, none is built.
    tpl_unknown: bool,
    templates: Vec<TplRow>,
    next_seq: u64,
    /// Keys of the `preparing` rows a previous daemon left, until their reconciliation
    /// succeeds. A migration this daemon authorised is never among them.
    inherited: HashSet<String>,
    /// Template upkeep is owed: a retirement (one failed, or a template became `ready` outside
    /// a promotion) or an inherited row whose reconciliation failed. The tick queues
    /// `Item::Retire` from `retire_at` on (M2), and the server is neither stopped nor left
    /// stopped meanwhile.
    retire_pending: bool,
    retire_at: Option<Instant>,
    retire_backoff: Backoff,
    /// The last template registry write failed: the tick writes it again from then on.
    tpl_retry_at: Option<Instant>,
    tpl_backoff: Backoff,
    /// The same for the lease registry. While set, memory may be ahead of `leases.json`, so
    /// no `failed` row is pruned (its candidate may still be on disk).
    lease_retry_at: Option<Instant>,
    lease_backoff: Backoff,
    /// A prune was held back by an unwritten lease registry: the tick runs it once written.
    prune_owed: bool,
    /// Template recovery steps still to fail with `injected` (tests).
    #[cfg(test)]
    tpl_fail: u32,
    /// Lease registry writes still to fail (tests, ruling PF-A).
    #[cfg(test)]
    lease_fail: u32,
    /// The last instant `tick` passed (ruling PF14).
    now: Instant,
    retry_at: Option<Instant>,
    backoff: Backoff,
    crashes: VecDeque<Instant>,
    restarts: u32,
    checks: u64,
    unknown_holders: u32,
    rss: u64,
    /// An adoption of an existing cluster failed: `tick` asks for it again once the backoff
    /// passed (final review P2).
    readopt: bool,
    /// An adoption retry is queued or running: `tick` asks for no second one.
    retrying: bool,
    // The queue: flags for the server's own work, then grants, releases and samples/decisions.
    adopt: bool,
    stop: bool,
    restart: bool,
    start: bool,
    retire: bool,
    idle_stop: bool,
    promotes: VecDeque<Promote>,
    /// Candidates whose promotion is queued or running: no other report changes their row.
    promoting: HashSet<String>,
    grants: VecDeque<Grant>,
    releases: VecDeque<String>,
    checks_q: VecDeque<(Kind, String, u64)>,
    /// (kind, lease) waiting or running: at most one of each.
    queued: HashSet<(Kind, String)>,
    busy: bool,
    exited: bool,
    /// Admitted lease calls, queued or with their grant running.
    open: Vec<Open>,
    next_open: u64,
    abandoned: VecDeque<String>,
    notes: VecDeque<String>,
    idle_since: Option<Instant>,
    bound_noted: bool,
    shutdown: bool,
    closed: bool,
    /// Every registry write, as `lease=state` items joined with `;` (tests).
    #[cfg(any(test, feature = "testkit"))]
    writes: VecDeque<String>,
}

fn err(msg: impl Into<String>) -> Response {
    Response::Error {
        message: msg.into(),
    }
}

fn in_use(max: u32) -> String {
    format!("all {max} postgres databases are in use")
}

fn cleanups_pending() -> String {
    format!(
        "{MAX_PENDING_RELEASES} postgres cleanups are pending; no new database until they finish or the cluster is reset"
    )
}

/// `<live sessions>|<sessions so far>`, both read and non-negative (R26).
fn parse_activity(out: &str) -> Option<(i64, i64)> {
    let (live, total) = out.trim().split_once('|')?;
    let (live, total) = (live.trim().parse().ok()?, total.trim().parse().ok()?);
    (live >= 0 && total >= 0).then_some((live, total))
}

/// `<role oid>|<database oid>` of one candidate, both set.
fn parse_oids(out: &str) -> Option<(u32, u32)> {
    let (role, db) = out.trim().split_once('|')?;
    let (role, db) = (role.trim().parse().ok()?, db.trim().parse().ok()?);
    (role != 0 && db != 0).then_some((role, db))
}

/// After a registry write: a failed one is due again at `now` plus the backoff.
fn retry_after(ok: bool, now: Instant, at: &mut Option<Instant>, backoff: &mut Backoff) {
    if ok {
        *at = None;
        backoff.reset();
    } else {
        *at = Some(now + backoff.next());
    }
}

fn token_ok(t: &str) -> bool {
    !t.is_empty() && t.len() <= 64 && t.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A registry sync_gate could have written: version 1, bounded, valid names and tokens, no
/// lease twice.
fn parse_registry(bytes: &[u8]) -> Option<Disk> {
    let d: Disk = serde_json::from_slice(bytes).ok()?;
    let mut names = HashSet::new();
    let ok = d.version == 1
        && d.leases.len() <= MAX_ROWS
        && d.leases.iter().all(|r| {
            is_lease_name(&r.lease) && token_ok(&r.token) && names.insert(r.lease.clone())
        });
    ok.then_some(d)
}

/// A template registry sync_gate could have written: version 1, bounded, valid keys, names,
/// tokens and OIDs, `seq` below `next_seq`, no key twice.
fn parse_templates(bytes: &[u8]) -> Option<TplDisk> {
    let d: TplDisk = serde_json::from_slice(bytes).ok()?;
    let mut keys = HashSet::new();
    let ok = d.version == 1
        && d.templates.len() <= MAX_TEMPLATE_ROWS
        && d.templates.iter().all(|r| {
            is_template_key(&r.key)
                && is_lease_name(&r.lease)
                && token_ok(&r.token)
                && r.db_oid != 0
                && r.role_oid != 0
                && r.seq < d.next_seq
                && keys.insert(r.key.clone())
        });
    ok.then_some(d)
}

/// The decision for a request of `project` with template key `key`, the same at admission and
/// in the worker; `None` = an empty lease of a project without `migrate`. `same_extensions`:
/// the CLI's extension list is the daemon's, in order (the CLI keyed the template on it).
fn template_choice(
    st: &State,
    migrate: bool,
    same_extensions: bool,
    project: &Path,
    key: Option<&str>,
) -> Option<TplChoice> {
    let refuse = |why| Some(TplChoice::Refuse(why));
    if !same_extensions {
        return refuse(
            "the daemon's configuration is older than this command's (extensions differ); \
             restart the daemon",
        );
    }
    let key = match (migrate, key) {
        (false, None) => return None,
        (true, Some(k)) => k,
        _ => return refuse("the daemon and the CLI disagree about migrate for this project"),
    };
    if !is_template_key(key) {
        return refuse("bad template key");
    }
    if st.tpl_unknown {
        return refuse(
            "the template registry is unknown; delete the cluster directory to reset it",
        );
    }
    match st.templates.iter().find(|t| t.key == key) {
        None => Some(TplChoice::Prepare),
        Some(t) if t.project != project => refuse("the template key belongs to another project"),
        Some(t) => match t.state {
            TplState::Ready => Some(TplChoice::Clone),
            TplState::Preparing => refuse("a migration for this project is running"),
            TplState::Failed => refuse("the migration for these files failed before"),
        },
    }
}

impl State {
    fn live(&self) -> usize {
        self.rows
            .iter()
            .filter(|r| matches!(r.disk.state, RowState::Creating | RowState::Granted))
            .count()
    }

    fn releasing(&self) -> usize {
        self.rows
            .iter()
            .filter(|r| r.disk.state == RowState::Releasing)
            .count()
    }

    fn row(&mut self, lease: &str) -> Option<&mut Row> {
        self.rows.iter_mut().find(|r| r.disk.lease == lease)
    }

    fn note(&mut self, msg: String) {
        if self.notes.len() == MAX_NOTES {
            self.notes.pop_front();
        }
        self.notes.push_back(msg);
    }

    fn abandoned(&self, request: &str) -> bool {
        !request.is_empty() && self.abandoned.iter().any(|a| a == request)
    }

    /// The admitted call `open` was given up while queued or running.
    fn given_up(&self, open: u64) -> bool {
        self.open.iter().any(|o| o.id == open && o.given_up)
    }

    fn retry_due(&self) -> bool {
        self.retry_at.is_none_or(|t| self.now >= t)
    }

    fn state_text(&self) -> String {
        if let Some(why) = &self.disabled {
            return format!("failed: {why}");
        }
        match &self.phase {
            Phase::Running if self.stale => format!("failed: {STALE}"),
            Phase::Stopped => "stopped".into(),
            Phase::Starting => "starting".into(),
            Phase::Reconciling => "reconciling".into(),
            Phase::Running => "running".into(),
            Phase::Failed(why) => format!("failed: {why}"),
        }
    }

    /// Writes the registry. A failed write is written again by the tick after a backoff, and
    /// until then no `failed` template row is pruned.
    fn save(&mut self) -> io::Result<()> {
        let r = self.write_leases();
        retry_after(
            r.is_ok(),
            self.now,
            &mut self.lease_retry_at,
            &mut self.lease_backoff,
        );
        r
    }

    /// A link or foreign entry where it is written disables the service (ruling PF8).
    fn write_leases(&mut self) -> io::Result<()> {
        #[cfg(test)]
        if self.lease_fail > 0 {
            self.lease_fail -= 1;
            return Err(io::Error::other("injected"));
        }
        let Some(c) = &self.paths else {
            return Err(io::Error::other("the cluster folder is not known yet"));
        };
        if write_target_refused(&c.leases) {
            let why = format!(
                "link or unexpected file where the lease registry is written: {}",
                c.leases.display()
            );
            self.disabled = Some(why.clone());
            return Err(io::Error::other(why));
        }
        let out = DiskOut {
            version: 1,
            unknown_before: self.unknown_before,
            leases: self.rows.iter().map(|r| &r.disk).collect(),
        };
        let bytes = serde_json::to_vec_pretty(&out)?;
        write_checked(&c.leases, &bytes)?;
        #[cfg(any(test, feature = "testkit"))]
        {
            let line = self
                .rows
                .iter()
                .map(|r| {
                    let d = &r.disk;
                    format!("{}={}", d.lease, format!("{:?}", d.state).to_lowercase())
                })
                .collect::<Vec<_>>()
                .join(";");
            if self.writes.len() >= 1024 {
                self.writes.pop_front();
            }
            self.writes.push_back(line);
        }
        Ok(())
    }

    /// Test-only: the next template recovery step fails while the counter lasts.
    fn injected(&mut self) -> io::Result<()> {
        #[cfg(test)]
        if self.tpl_fail > 0 {
            self.tpl_fail -= 1;
            return Err(io::Error::other("injected"));
        }
        Ok(())
    }

    /// Writes the template registry. A failed write is written again by the tick after a
    /// backoff, so what memory holds always reaches the disk.
    fn save_templates(&mut self) -> io::Result<()> {
        let r = self.write_templates();
        retry_after(
            r.is_ok(),
            self.now,
            &mut self.tpl_retry_at,
            &mut self.tpl_backoff,
        );
        r
    }

    /// Refused the same way as [`State::save`].
    fn write_templates(&mut self) -> io::Result<()> {
        self.injected()?;
        let Some(c) = &self.paths else {
            return Err(io::Error::other("the cluster folder is not known yet"));
        };
        if write_target_refused(&c.templates) {
            let why = format!(
                "link or unexpected file where the template registry is written: {}",
                c.templates.display()
            );
            self.disabled = Some(why.clone());
            return Err(io::Error::other(why));
        }
        let out = TplOut {
            version: 1,
            unknown_before: self.tpl_unknown,
            next_seq: self.next_seq,
            templates: &self.templates,
        };
        write_checked(&c.templates, &serde_json::to_vec_pretty(&out)?)
    }

    /// Queues a release, a sample or a decision unless one for the lease waits or runs.
    fn enqueue(&mut self, kind: Kind, lease: &str, r#gen: u64) {
        if !self.queued.insert((kind, lease.to_string())) {
            return;
        }
        match kind {
            Kind::Release => self.releases.push_back(lease.into()),
            _ => self.checks_q.push_back((kind, lease.into(), r#gen)),
        }
    }

    /// A granted (or failed) row becomes `releasing`, recorded, and goes to the worker.
    fn begin_release(&mut self, lease: &str) {
        if let Some(r) = self.row(lease) {
            r.disk.state = RowState::Releasing;
            r.retry_at = None;
        }
        // Not recorded: the disk keeps `granted`/`creating`, which the next start also
        // releases (rule D or reconciliation).
        let _ = self.save();
        self.enqueue(Kind::Release, lease, 0);
    }

    fn set_has_row(&mut self, open: u64, has: bool) {
        if let Some(o) = self.open.iter_mut().find(|o| o.id == open) {
            o.has_row = has;
        }
    }

    /// Answers every queued grant and promotion with `msg`.
    fn drop_grants(&mut self, msg: &str) {
        for g in self.grants.drain(..) {
            let _ = g.reply.send(err(msg));
        }
        for p in self.promotes.drain(..) {
            self.promoting.remove(&p.lease);
            let _ = p.reply.send(err(msg));
        }
    }

    /// Template `key` becomes `state` with the next `seq` (the order rule).
    fn set_tpl(&mut self, key: &str, state: TplState) {
        if let Some(t) = self.templates.iter_mut().find(|t| t.key == key) {
            t.state = state;
            t.seq = self.next_seq;
            self.next_seq += 1;
        }
    }

    /// C5, C6: in every project, the `failed` rows beyond the newest `MAX_FAILED_PER_PROJECT`
    /// leave once their candidate is no longer in the lease registry; the others leave in a
    /// later prune. "No longer in the lease registry" is read from memory, so nothing is
    /// pruned while `leases.json` lags behind it (the tick prunes once it is written). In
    /// memory only; true when a row left.
    fn prune_failed(&mut self) -> bool {
        if self.tpl_unknown {
            return false;
        }
        self.prune_owed = self.lease_retry_at.is_some();
        if self.prune_owed {
            return false;
        }
        let failed = |t: &&TplRow| t.state == TplState::Failed;
        let newer = |t: &TplRow| {
            let all = self.templates.iter().filter(failed);
            all.filter(|n| n.project == t.project && n.seq > t.seq)
                .count()
        };
        let gone = |t: &TplRow| !self.rows.iter().any(|r| r.disk.lease == t.lease);
        let old: HashSet<String> = self
            .templates
            .iter()
            .filter(failed)
            .filter(|t| newer(t) >= MAX_FAILED_PER_PROJECT && gone(t))
            .map(|t| t.key.clone())
            .collect();
        self.templates.retain(|t| !old.contains(&t.key));
        !old.is_empty()
    }

    /// A start or an adoption failed, or the server died: the next try waits for the
    /// backoff, or 5 minutes after five failures in 60 s (the hub's crash window).
    fn crashed(&mut self) {
        let now = self.now;
        self.crashes
            .retain(|t| now.saturating_duration_since(*t) < CRASH_WINDOW);
        self.crashes.push_back(now);
        let wait = if self.crashes.len() < CRASH_LIMIT {
            self.backoff.next()
        } else {
            CRASH_PAUSE
        };
        self.retry_at = Some(now + wait);
    }

    fn failed(&mut self, why: String) {
        self.phase = Phase::Failed(why);
        self.server = None;
        self.crashed();
    }

    fn next_item(&mut self) -> Option<Item> {
        if self.closed {
            return None;
        }
        if std::mem::take(&mut self.adopt) {
            return Some(Item::Adopt);
        }
        if self.shutdown {
            return std::mem::take(&mut self.stop).then_some(Item::Stop);
        }
        if std::mem::take(&mut self.restart) {
            return Some(Item::Restart);
        }
        if std::mem::take(&mut self.start) {
            return Some(Item::Start);
        }
        if let Some(p) = self.promotes.pop_front() {
            return Some(Item::Promote(p));
        }
        if let Some(g) = self.grants.pop_front() {
            return Some(Item::Grant(g));
        }
        if let Some(l) = self.releases.pop_front() {
            return Some(Item::Release(l));
        }
        if let Some((kind, l, r#gen)) = self.checks_q.pop_front() {
            return Some(match kind {
                Kind::Decide => Item::Decide(l, r#gen),
                _ => Item::Sample(l),
            });
        }
        if std::mem::take(&mut self.retire) {
            return Some(Item::Retire);
        }
        std::mem::take(&mut self.idle_stop).then_some(Item::IdleStop)
    }

    fn idle(&self) -> bool {
        !(self.busy
            || self.adopt
            || self.stop
            || self.restart
            || self.start
            || self.retire
            || self.idle_stop)
            && self.promotes.is_empty()
            && self.grants.is_empty()
            && self.releases.is_empty()
            && self.checks_q.is_empty()
    }
}

struct Inner {
    pg: PgConfig,
    data_dir: PathBuf,
    deps: Deps,
    state: Mutex<State>,
    /// The worker waits here for work.
    work: Condvar,
    /// Lease calls, `wait_idle` and `shutdown` wait here for state changes.
    changed: Condvar,
    /// `init`, `start` and `stop` write; `sql` reads.
    admin: RwLock<()>,
}

enum Mode {
    Unconfigured,
    NoDataDir,
    On(Arc<Inner>),
}

pub struct Services {
    mode: Mode,
}

/// Removes an admitted lease call from the admission count when the call returns.
struct OpenGuard<'a> {
    inner: &'a Inner,
    id: u64,
}

impl Drop for OpenGuard<'_> {
    fn drop(&mut self) {
        self.inner.lock().open.retain(|o| o.id != self.id);
        self.inner.changed.notify_all();
    }
}

impl Services {
    pub fn new(cfg: &Config, data_dir: Option<&Path>, deps: Deps) -> Services {
        let Some(pg) = cfg.postgres.clone() else {
            return Services {
                mode: Mode::Unconfigured,
            };
        };
        let Some(data_dir) = data_dir else {
            return Services {
                mode: Mode::NoDataDir,
            };
        };
        #[cfg(test)]
        let deps_tpl_fail = deps.tpl_fail;
        let inner = Arc::new(Inner {
            pg,
            data_dir: data_dir.to_path_buf(),
            deps,
            state: Mutex::new(State {
                phase: Phase::Stopped,
                stale: false,
                disabled: None,
                server: None,
                paths: None,
                loaded: false,
                unknown_before: false,
                rows: Vec::new(),
                tpl_loaded: false,
                tpl_unknown: false,
                templates: Vec::new(),
                next_seq: 1,
                inherited: HashSet::new(),
                retire_pending: false,
                retire_at: None,
                retire_backoff: Backoff::default(),
                tpl_retry_at: None,
                tpl_backoff: Backoff::default(),
                lease_retry_at: None,
                lease_backoff: Backoff::default(),
                prune_owed: false,
                #[cfg(test)]
                tpl_fail: deps_tpl_fail,
                #[cfg(test)]
                lease_fail: 0,
                now: Instant::now(),
                retry_at: None,
                backoff: Backoff::default(),
                crashes: VecDeque::new(),
                restarts: 0,
                checks: 0,
                unknown_holders: 0,
                rss: 0,
                readopt: false,
                retrying: false,
                adopt: true,
                stop: false,
                restart: false,
                start: false,
                retire: false,
                idle_stop: false,
                promotes: VecDeque::new(),
                promoting: HashSet::new(),
                grants: VecDeque::new(),
                releases: VecDeque::new(),
                checks_q: VecDeque::new(),
                queued: HashSet::new(),
                busy: false,
                exited: false,
                open: Vec::new(),
                next_open: 0,
                abandoned: VecDeque::new(),
                notes: VecDeque::new(),
                idle_since: None,
                bound_noted: false,
                shutdown: false,
                closed: false,
                #[cfg(any(test, feature = "testkit"))]
                writes: VecDeque::new(),
            }),
            work: Condvar::new(),
            changed: Condvar::new(),
            admin: RwLock::new(()),
        });
        let worker = inner.clone();
        let spawned = std::thread::Builder::new()
            .name("sync_gated-postgres".into())
            .spawn(move || worker.work_loop());
        if let Err(e) = spawned {
            let mut st = inner.lock();
            st.adopt = false;
            st.exited = true;
            st.disabled = Some(format!("cannot start the postgres worker: {e}"));
        }
        Services {
            mode: Mode::On(inner),
        }
    }

    fn on(&self) -> Result<&Arc<Inner>, &'static str> {
        match &self.mode {
            Mode::Unconfigured => Err("postgres is not configured"),
            Mode::NoDataDir => Err("postgres needs a data dir"),
            Mode::On(i) => Ok(i),
        }
    }

    /// A database for the command about to run (R16, R30): `Leased`, or `Prepare` for the
    /// first request of a new template key. Blocks until it is granted or refused; every
    /// refusal is an `Error` the CLI fails open on. `extensions` is the project's list as the CLI
    /// read it.
    pub fn lease(
        &self,
        project: &Path,
        cli: Holder,
        request: &str,
        template: Option<&str>,
        extensions: &[String],
    ) -> Response {
        let inner = match self.on() {
            Ok(i) => i,
            Err(e) => return err(e),
        };
        let Some(proj) = inner.pg.project.iter().find(|p| p.dir == project) else {
            return err(format!(
                "project not configured for postgres: {}",
                project.display()
            ));
        };
        let max = inner.pg.max_leases;
        let id = {
            let mut st = inner.lock();
            if let Some(e) = refusal(&st) {
                return e;
            }
            if st.abandoned(request) {
                return err(ABANDONED);
            }
            // Before the registry is read, the worker decides alone.
            let migrate = !proj.migrate.is_empty();
            let same = proj.extensions == extensions;
            let choice = if st.tpl_loaded {
                template_choice(&st, migrate, same, project, template)
            } else {
                None
            };
            if let Some(TplChoice::Refuse(why)) = choice {
                return err(why);
            }
            let waiting = st.open.iter().filter(|o| !o.has_row).count();
            if st.live() + waiting >= max as usize {
                return err(in_use(max));
            }
            let id = st.next_open;
            st.next_open += 1;
            st.open.push(Open {
                id,
                has_row: false,
                request: request.to_string(),
                given_up: false,
            });
            id
        };
        let _open = OpenGuard { inner, id };
        let patience = inner
            .deps
            .lease_wait
            .unwrap_or(Duration::from_secs(inner.pg.lease_wait_secs));
        let deadline = Instant::now() + patience;
        let mut st = inner.lock();
        loop {
            if let Some(e) = refusal(&st) {
                return e;
            }
            if st.given_up(id) {
                return err(ABANDONED);
            }
            match &st.phase {
                Phase::Running if st.stale => return err(format!("postgres failed: {STALE}")),
                Phase::Running => break,
                Phase::Failed(why) if !st.retry_due() => {
                    return err(format!("postgres failed: {why}"));
                }
                // Inside a crash backoff the tick asks for the start once it is due.
                Phase::Stopped | Phase::Failed(_) if st.retry_due() => {
                    if !st.start {
                        st.start = true;
                        inner.work.notify_all();
                    }
                }
                Phase::Stopped | Phase::Starting | Phase::Reconciling | Phase::Failed(_) => {}
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return err(STILL_STARTING);
            }
            st = inner
                .changed
                .wait_timeout(st, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        let (tx, rx) = mpsc::channel();
        st.grants.push_back(Grant {
            open: id,
            request: request.to_string(),
            project: project.to_path_buf(),
            cli,
            url_vars: proj.url_vars.clone(),
            extensions: extensions.to_vec(),
            template: template.map(String::from),
            reply: tx,
        });
        inner.work.notify_all();
        drop(st);
        // Every path that drops a queued grant answers it first; a lost sender is a stop.
        rx.recv().unwrap_or_else(|_| err(NOT_RUNNING))
    }

    /// The CLI stopped waiting for `request` (R30): whatever that request has or gets is
    /// given back. Always `Ack`, at once.
    pub fn give_up(&self, request: &str) -> Response {
        let Ok(inner) = self.on() else {
            return Response::Ack;
        };
        if request.is_empty() {
            return Response::Ack;
        }
        let mut st = inner.lock();
        if !st.abandoned(request) {
            if st.abandoned.len() == ABANDONED_KEEP {
                st.abandoned.pop_front();
            }
            st.abandoned.push_back(request.to_string());
        }
        for o in st.open.iter_mut().filter(|o| o.request == request) {
            o.given_up = true;
        }
        if let Some(i) = st.grants.iter().position(|g| g.request == request)
            && let Some(g) = st.grants.remove(i)
        {
            let _ = g.reply.send(err(ABANDONED));
        }
        let granted = st
            .rows
            .iter()
            .find(|r| {
                r.request == request
                    && r.disk.state == RowState::Granted
                    && r.disk.command.is_none()
            })
            .map(|r| r.disk.lease.clone());
        if let Some(lease) = granted {
            st.begin_release(&lease);
        }
        drop(st);
        inner.changed.notify_all();
        inner.work.notify_all();
        Response::Ack
    }

    /// The `migrate` on candidate `lease` ended. `ok` false: its key is `failed` (the lease
    /// itself goes back by the usual rules). `ok` true: blocks until the worker has promoted
    /// the candidate (`Ack`) or refused it (`Error`).
    pub fn template_ready(&self, lease: &str, ok: bool, interrupted: bool) -> Response {
        if ok && interrupted {
            return err("bad template report");
        }
        let inner = match self.on() {
            Ok(i) => i,
            Err(e) => return err(e),
        };
        let mut st = inner.lock();
        let preparing = |t: &TplRow| t.lease == lease && t.state == TplState::Preparing;
        let Some(key) = st
            .templates
            .iter()
            .find(|t| preparing(t))
            .map(|t| t.key.clone())
        else {
            return err("unknown template");
        };
        // One report per candidate: a promotion under way decides the row alone.
        if st.promoting.contains(lease) {
            return err("a promotion of this template is in progress");
        }
        if !ok && interrupted {
            // Not a failure of the key: it is free again; the candidate leaves by its own paths.
            st.templates.retain(|t| t.key != key);
            return match st.save_templates() {
                Ok(()) => Response::Ack,
                Err(e) => err(format!("cannot record the template: {e}")),
            };
        }
        if !ok {
            st.set_tpl(&key, TplState::Failed);
            st.prune_failed();
            // Failed in memory either way: no second migration of these files in this run.
            return match st.save_templates() {
                Ok(()) => Response::Ack,
                Err(e) => err(format!("cannot record the template: {e}")),
            };
        }
        if let Some(e) = refusal(&st) {
            return e;
        }
        let (tx, rx) = mpsc::channel();
        st.promoting.insert(lease.to_string());
        st.promotes.push_back(Promote {
            lease: lease.to_string(),
            reply: tx,
        });
        inner.work.notify_all();
        drop(st);
        // Every path that drops a queued promotion answers it first.
        rx.recv().unwrap_or_else(|_| err(NOT_RUNNING))
    }

    /// The command's process now holds the lease.
    pub fn set_holder(&self, lease: &str, command: Holder) -> Response {
        let inner = match self.on() {
            Ok(i) => i,
            Err(e) => return err(e),
        };
        let mut st = inner.lock();
        let Some(r) = st.row(lease) else {
            return err("unknown lease");
        };
        match (r.disk.state, r.disk.command) {
            (RowState::Granted, None) => {
                r.disk.command = Some(command);
                r.disk.r#gen += 1;
                if let Err(e) = st.save() {
                    if let Some(r) = st.row(lease) {
                        r.disk.command = None;
                        r.disk.r#gen -= 1;
                    }
                    return err(format!("cannot record the lease holder: {e}"));
                }
                Response::Ack
            }
            (RowState::Granted, Some(c)) if c == command => Response::Ack,
            (RowState::Granted, Some(_)) => err("holder already set"),
            _ => err("unknown lease"),
        }
    }

    /// The command ended: its database goes back.
    pub fn release(&self, lease: &str) -> Response {
        let Ok(inner) = self.on() else {
            return Response::Ack;
        };
        let mut st = inner.lock();
        if st
            .row(lease)
            .is_some_and(|r| r.disk.state == RowState::Granted)
        {
            st.begin_release(lease);
            inner.work.notify_all();
        }
        Response::Ack
    }

    /// Examines the server and every holder; queues work, never calls a tool.
    pub fn tick(&self, now: Instant) {
        let Mode::On(inner) = &self.mode else {
            return;
        };
        let probe = |h: &Holder| {
            let (alive, start_now) = (inner.deps.probe)(h.pid);
            liveness(h.start, alive, start_now)
        };
        let mut st = inner.lock();
        if now > st.now {
            st.now = now;
        }
        let now = st.now;
        st.checks += 1;
        if st.shutdown || st.closed {
            return;
        }
        if let (Some(id), Phase::Running | Phase::Reconciling) = (st.server, &st.phase) {
            let (alive, start_now) = (inner.deps.probe)(id.pid);
            if liveness(Some(id.start), alive, start_now) == Liveness::Gone {
                st.note("postgres stopped unexpectedly".into());
                st.restarts += 1;
                st.phase = Phase::Stopped;
                st.server = None;
                st.stale = false;
                st.drop_grants(NOT_RUNNING);
                st.crashed();
            }
        }
        if st.readopt
            && !st.retrying
            && matches!(st.phase, Phase::Failed(_))
            && st.retry_due()
            && st.disabled.is_none()
        {
            st.adopt = true;
            st.retrying = true;
        }
        if matches!(st.phase, Phase::Stopped | Phase::Failed(_))
            && (!st.rows.is_empty() || !st.open.is_empty() || st.retire_pending)
            && st.retry_due()
            && st.disabled.is_none()
        {
            st.start = true;
        }
        let running = st.phase == Phase::Running && st.server.is_some();
        let every = inner.deps.quiet_sample_every;
        let mut unknown = 0;
        let mut todo = Vec::new();
        for r in st.rows.iter_mut() {
            match r.disk.state {
                RowState::Granted => {
                    let cli = probe(&r.disk.cli);
                    let cmd = r.disk.command.as_ref().map(probe);
                    if cli == Liveness::Unknown || cmd == Some(Liveness::Unknown) {
                        unknown += 1;
                    }
                    let gone = cli == Liveness::Gone && cmd.is_none_or(|c| c == Liveness::Gone);
                    if running && gone {
                        if r.disk.command.is_none()
                            && r.last_sample
                                .is_none_or(|t| now.saturating_duration_since(t) >= every)
                        {
                            r.last_sample = Some(now);
                            todo.push((Kind::Sample, r.disk.lease.clone(), r.disk.r#gen));
                        }
                        todo.push((Kind::Decide, r.disk.lease.clone(), r.disk.r#gen));
                    }
                }
                RowState::Releasing if running && r.retry_at.is_none_or(|t| now >= t) => {
                    todo.push((Kind::Release, r.disk.lease.clone(), 0));
                }
                _ => {}
            }
        }
        st.unknown_holders = unknown;
        for (kind, lease, r#gen) in todo {
            st.enqueue(kind, &lease, r#gen);
        }
        if running && st.retire_pending && st.retire_at.is_none_or(|t| now >= t) {
            st.retire = true;
        }
        // File writes, no tool: what memory holds reaches the disk, the leases first, then the
        // prune they held back, then the templates.
        let writable = st.disabled.is_none();
        if writable
            && st.lease_retry_at.is_some_and(|t| now >= t)
            && let Err(e) = st.save()
        {
            st.note(format!("postgres lease registry write failed: {e}"));
        }
        if st.prune_owed
            && st.prune_failed()
            && let Err(e) = st.save_templates()
        {
            st.note(format!("postgres template registry write failed: {e}"));
        }
        if writable
            && st.tpl_retry_at.is_some_and(|t| now >= t)
            && let Err(e) = st.save_templates()
        {
            st.note(format!("postgres template registry write failed: {e}"));
        }
        if !st.rows.is_empty() || !st.open.is_empty() || st.retire_pending {
            st.idle_since = None;
        } else if running {
            if st.stale {
                st.restart = st.retry_due();
            } else if inner.pg.idle_stop_secs > 0 {
                let since = *st.idle_since.get_or_insert(now);
                if now.saturating_duration_since(since)
                    >= Duration::from_secs(inner.pg.idle_stop_secs)
                {
                    st.idle_stop = true;
                }
            }
        }
        if !st.idle() {
            inner.work.notify_all();
        }
    }

    /// The server's resident memory, through the caller's measurement.
    pub fn measure(&self, mut rss_of: impl FnMut(u32) -> u64) {
        let Mode::On(inner) = &self.mode else {
            return;
        };
        let pid = inner.lock().server.map(|s| s.pid);
        let rss = pid.map_or(0, &mut rss_of);
        inner.lock().rss = rss;
    }

    pub fn take_notes(&self) -> Vec<String> {
        match &self.mode {
            Mode::On(inner) => inner.lock().notes.drain(..).collect(),
            _ => Vec::new(),
        }
    }

    /// One row when `[postgres]` is configured.
    pub fn report(&self) -> Vec<ServiceStatus> {
        let row = |state: String| ServiceStatus {
            service: SERVICE_POSTGRES.into(),
            state,
            leases: 0,
            unknown_holders: 0,
            cleanup_pending: 0,
            rss: 0,
            restarts: 0,
            checks: 0,
        };
        match &self.mode {
            Mode::Unconfigured => Vec::new(),
            Mode::NoDataDir => vec![row("failed: postgres needs a data dir".into())],
            Mode::On(inner) => {
                let st = inner.lock();
                vec![ServiceStatus {
                    leases: st.live() as u32,
                    unknown_holders: st.unknown_holders,
                    cleanup_pending: st.releasing() as u32,
                    rss: st.rss,
                    restarts: st.restarts,
                    checks: st.checks,
                    ..row(st.state_text())
                }]
            }
        }
    }

    /// Daemon exit: stops the cluster only when no lease is live, within its own bound
    /// (ruling PF15); with live leases the server is left running for the next daemon.
    pub fn shutdown(&self) {
        let Mode::On(inner) = &self.mode else {
            return;
        };
        let mut st = inner.lock();
        if st.shutdown {
            return;
        }
        st.shutdown = true;
        st.drop_grants(NOT_RUNNING);
        // Lease calls still waiting for `running` see the shutdown at once.
        inner.changed.notify_all();
        st.releases.clear();
        st.checks_q.clear();
        st.queued.clear();
        st.adopt = false;
        st.retrying = false;
        st.start = false;
        st.restart = false;
        st.retire = false;
        st.idle_stop = false;
        let live = st.live();
        if st.server.is_none() {
            inner.work.notify_all();
            return;
        }
        if live > 0 {
            st.note(format!("postgres left running for {live} active lease(s)"));
            inner.work.notify_all();
            return;
        }
        st.stop = true;
        inner.work.notify_all();
        let deadline = Instant::now() + SHUTDOWN_STOP_BOUND;
        while !st.exited {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            st = inner
                .changed
                .wait_timeout(st, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    /// True once the worker queue is empty and the worker runs nothing; false at `deadline`.
    pub fn wait_idle(&self, deadline: Instant) -> bool {
        let Mode::On(inner) = &self.mode else {
            return true;
        };
        let mut st = inner.lock();
        loop {
            if st.idle() || st.exited {
                return true;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            st = inner
                .changed
                .wait_timeout(st, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    /// Items waiting in the queue (not the one running), by kind: `grant`, `release`,
    /// `sample` or `decide` (tests).
    #[cfg(any(test, feature = "testkit"))]
    pub fn queued_items(&self, kind: &str) -> usize {
        let Mode::On(inner) = &self.mode else {
            return 0;
        };
        let st = inner.lock();
        let checks = |k: Kind| st.checks_q.iter().filter(|q| q.0 == k).count();
        match kind {
            "grant" => st.grants.len(),
            "release" => st.releases.len(),
            "sample" => checks(Kind::Sample),
            "decide" => checks(Kind::Decide),
            _ => 0,
        }
    }

    /// Every registry write so far (the last 1,024), as `lease=state` items joined with `;`
    /// (tests).
    #[cfg(any(test, feature = "testkit"))]
    pub fn registry_writes(&self) -> Vec<String> {
        let Mode::On(inner) = &self.mode else {
            return Vec::new();
        };
        let st = inner.lock();
        st.writes.iter().cloned().collect()
    }

    /// `shutdown` has begun (tests).
    #[cfg(test)]
    fn shutting_down(&self) -> bool {
        matches!(&self.mode, Mode::On(inner) if inner.lock().shutdown)
    }
}

impl Drop for Services {
    fn drop(&mut self) {
        if let Mode::On(inner) = &self.mode {
            let mut st = inner.lock();
            st.closed = true;
            st.drop_grants(NOT_RUNNING);
            inner.work.notify_all();
            inner.changed.notify_all();
        }
    }
}

/// Why no lease can be asked for now, whatever the phase.
fn refusal(st: &State) -> Option<Response> {
    if let Some(why) = &st.disabled {
        return Some(err(format!("postgres failed: {why}")));
    }
    // From `shutdown` on, nothing new is granted (ruling P1).
    (st.shutdown || st.closed).then(|| err(NOT_RUNNING))
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn live(&self, h: &Holder) -> Liveness {
        let (alive, start_now) = (self.deps.probe)(h.pid);
        liveness(h.start, alive, start_now)
    }

    fn sql(&self, c: &ClusterPaths, script: &str, secrets: &[&str]) -> io::Result<String> {
        let _r = self.admin.read().unwrap_or_else(|e| e.into_inner());
        self.deps.tools.sql(c, script, secrets)
    }

    fn work_loop(self: Arc<Self>) {
        loop {
            let item = {
                let mut st = self.lock();
                loop {
                    if let Some(item) = st.next_item() {
                        st.busy = true;
                        break item;
                    }
                    if st.closed || st.shutdown {
                        st.exited = true;
                        st.drop_grants(NOT_RUNNING);
                        self.changed.notify_all();
                        return;
                    }
                    st = self.work.wait(st).unwrap_or_else(|e| e.into_inner());
                }
            };
            let key = match &item {
                Item::Release(l) => Some((Kind::Release, l.clone())),
                Item::Sample(l) => Some((Kind::Sample, l.clone())),
                Item::Decide(l, _) => Some((Kind::Decide, l.clone())),
                _ => None,
            };
            match item {
                Item::Adopt => {
                    self.bring_up(true);
                    self.lock().retrying = false;
                }
                Item::Start => self.bring_up(false),
                Item::Stop => {
                    self.stop_server(None);
                }
                Item::Restart => self.restart(),
                Item::IdleStop => {
                    self.stop_server(Some("postgres stopped (idle)"));
                }
                Item::Promote(p) => {
                    let r = self.promote(&p.lease);
                    self.lock().promoting.remove(&p.lease);
                    let _ = p.reply.send(r);
                }
                Item::Grant(g) => {
                    let reply = g.reply.clone();
                    let _ = reply.send(self.grant(g));
                }
                Item::Release(l) => self.release(&l),
                Item::Sample(l) => {
                    self.sample(&l);
                }
                Item::Decide(l, r#gen) => self.decide(&l, r#gen),
                Item::Retire => {
                    let c = {
                        let st = self.lock();
                        let due = st.retire_pending && st.retire_at.is_none_or(|t| st.now >= t);
                        let running = st.phase == Phase::Running;
                        st.paths.clone().filter(|_| due && running)
                    };
                    // Inherited rows not reconciled yet, then the retirement.
                    if let Some(c) = c {
                        self.reconcile_templates(&c);
                    }
                }
            }
            let mut st = self.lock();
            if let Some(k) = key {
                st.queued.remove(&k);
            }
            st.busy = false;
            self.changed.notify_all();
        }
    }

    /// Start on demand (`adopt_only` false) or the adoption a new daemon tries first: a server
    /// whose identity `server` proves is adopted; otherwise it is started only on demand.
    fn bring_up(&self, adopt_only: bool) {
        {
            let mut st = self.lock();
            let up = st.server.is_some() && matches!(st.phase, Phase::Running);
            // A retry is owed only while its deadline has passed and the adoption is needed.
            let owed = st.readopt
                && matches!(st.phase, Phase::Failed(_))
                && st.retry_due()
                && st.disabled.is_none();
            if adopt_only && st.retrying && !owed {
                self.changed.notify_all();
                return;
            }
            if st.closed || up || (!adopt_only && !st.retry_due()) {
                self.changed.notify_all();
                return;
            }
            if !adopt_only {
                st.phase = Phase::Starting;
                self.changed.notify_all();
            }
        }
        let result = self.server_up(adopt_only);
        let (c, id) = match result {
            Ok(Some(up)) => up,
            Ok(None) => {
                let mut st = self.lock();
                st.phase = Phase::Stopped;
                st.readopt = false;
                // Ruling P3: leases on disk stay supervised. The registry of an existing
                // cluster is loaded (same loader, same "unreadable means unknown" rule); while
                // it holds a row the tick asks for a start, with its backoff.
                let existing = st.paths.clone().filter(|c| c.record.exists());
                if let (true, false, Some(c)) = (adopt_only, st.loaded, existing.clone()) {
                    match load_registry(&mut st, &c) {
                        Ok(()) => st.loaded = true,
                        Err(why) => st.failed(why),
                    }
                }
                // The same for templates: upkeep a previous daemon owed (an inherited row, or
                // a project with two `ready` rows) asks for a start too.
                if let (true, false, Some(c)) = (adopt_only, st.tpl_loaded, existing) {
                    if load_templates(&mut st, &c).is_ok() {
                        st.tpl_loaded = true;
                    }
                    let ready: Vec<&Path> = st
                        .templates
                        .iter()
                        .filter(|t| t.state == TplState::Ready)
                        .map(|t| t.project.as_path())
                        .collect();
                    let two = ready
                        .iter()
                        .enumerate()
                        .any(|(i, p)| ready[..i].contains(p));
                    st.retire_pending |= !st.tpl_unknown && (two || !st.inherited.is_empty());
                }
                self.changed.notify_all();
                return;
            }
            Err(why) => {
                let mut st = self.lock();
                // An existing cluster's leases stay supervised: the adoption is tried again.
                st.readopt |= adopt_only && st.paths.as_ref().is_some_and(|c| c.record.exists());
                st.failed(why);
                st.drop_grants(NOT_RUNNING);
                self.changed.notify_all();
                return;
            }
        };
        let stale = !self
            .deps
            .tools
            .config_current(&c, self.pg.max_connections());
        {
            let mut st = self.lock();
            st.phase = Phase::Reconciling;
            st.server = Some(id);
            st.stale = stale;
            self.changed.notify_all();
        }
        let reconciled = self.reconcile(&c);
        let mut st = self.lock();
        match reconciled {
            Ok(()) => {
                st.phase = Phase::Running;
                st.readopt = false;
                st.backoff.reset();
                st.retry_at = None;
                // Rows reconciliation left `releasing` (leftovers included) go back now.
                let pending: Vec<String> = st
                    .rows
                    .iter()
                    .filter(|r| r.disk.state == RowState::Releasing)
                    .map(|r| r.disk.lease.clone())
                    .collect();
                for l in pending {
                    st.enqueue(Kind::Release, &l, 0);
                }
                if st.rows.is_empty() {
                    st.idle_since = Some(st.now);
                }
            }
            Err(why) => {
                // The server stays up; it is adopted again on the next try.
                st.readopt |= adopt_only;
                st.failed(why);
                st.drop_grants(NOT_RUNNING);
            }
        }
        self.changed.notify_all();
    }

    /// Up to "server started" (R12): version, paths, then adoption or `init` + `start`.
    fn server_up(&self, adopt_only: bool) -> Result<Option<(ClusterPaths, ServerId)>, String> {
        let tools = &self.deps.tools;
        let major = tools
            .major_version(&self.pg.bin_dir)
            .map_err(|e| e.to_string())?;
        if major < PG_MIN_MAJOR {
            return Err(format!(
                "PostgreSQL {PG_MIN_MAJOR} or newer is required; bin_dir has {major}"
            ));
        }
        let root = self.data_dir.join("pg").join(major.to_string());
        let c = ClusterPaths::new(&self.pg.bin_dir, &root, self.pg.port);
        if !c.socket_path_ok() {
            return Err(format!(
                "the socket path is too long or has a comma: {}",
                c.sock.display()
            ));
        }
        self.lock().paths = Some(c.clone());
        if adopt_only {
            // No cluster yet: nothing to adopt, and nothing is created before a lease.
            if !c.record.exists() {
                return Ok(None);
            }
            return Ok(tools.server(&c)?.map(|id| (c, id)));
        }
        {
            let _w = self.admin.write().unwrap_or_else(|e| e.into_inner());
            tools
                .init(&c, self.pg.max_connections())
                .map_err(|e| e.to_string())?;
        }
        if let Some(id) = tools.server(&c)? {
            return Ok(Some((c, id)));
        }
        let _w = self.admin.write().unwrap_or_else(|e| e.into_inner());
        let id = tools.start(&c).map_err(|e| e.to_string())?;
        Ok(Some((c, id)))
    }

    /// Up to "reconciliation finished": bootstrap, registry, leftovers (R12, R19).
    fn reconcile(&self, c: &ClusterPaths) -> Result<(), String> {
        self.sql(c, &bootstrap_sql(), &[])
            .map_err(|e| e.to_string())?;
        let known = {
            let mut st = self.lock();
            if !st.loaded {
                load_registry(&mut st, c)?;
                st.loaded = true;
            }
            if !st.tpl_loaded {
                load_templates(&mut st, c)?;
                st.tpl_loaded = true;
            }
            for r in st.rows.iter_mut() {
                r.quiet = None;
                r.last_sample = None;
                // The reply never left: nobody holds it.
                if r.disk.state == RowState::Creating {
                    r.disk.state = RowState::Releasing;
                }
            }
            st.save()
                .map_err(|e| format!("cannot write the lease registry: {e}"))?;
            !st.unknown_before
        };
        self.reconcile_templates(c);
        if !known {
            return Ok(());
        }
        let out = self
            .sql(c, &lease_roles(), &[])
            .map_err(|e| e.to_string())?;
        let mut st = self.lock();
        let (mut added, mut left) = (false, 0);
        for line in out.lines() {
            let Some((role, token)) = line.trim().split_once('|') else {
                continue;
            };
            // A role whose name a row holds with another token is not touched.
            if !is_lease_name(role)
                || !token_ok(token)
                || st.rows.iter().any(|r| r.disk.lease == role)
            {
                continue;
            }
            if st.releasing() >= MAX_PENDING_RELEASES {
                left += 1;
                continue;
            }
            let disk = DiskRow {
                lease: role.into(),
                token: token.into(),
                project: PathBuf::new(),
                r#gen: 0,
                state: RowState::Releasing,
                cli: Holder {
                    pid: 0,
                    start: None,
                },
                command: None,
            };
            st.rows.push(Row::new(disk, String::new()));
            added = true;
        }
        if left > 0 {
            st.note(format!(
                "postgres: {left} leftover lease role(s) wait for a later start"
            ));
        }
        if added {
            st.save()
                .map_err(|e| format!("cannot write the lease registry: {e}"))?;
        }
        Ok(())
    }

    /// Stops the proven server: at shutdown (`note` None) or when idle. The state shows
    /// `stopped` from the start, so a lease that arrives meanwhile asks for a new start.
    fn stop_server(&self, note: Option<&str>) -> bool {
        let (c, id) = {
            let mut st = self.lock();
            let idle = st.rows.is_empty() && st.open.is_empty() && st.phase == Phase::Running;
            let (Some(c), Some(id)) = (st.paths.clone(), st.server) else {
                return false;
            };
            if note.is_some() && !idle {
                return false;
            }
            // The shutdown stop, re-checked right before the tool (ruling P1): a lease that
            // became live while it was queued keeps the server.
            let live = st.live();
            if note.is_none() && live > 0 {
                st.note(format!("postgres left running for {live} active lease(s)"));
                return false;
            }
            st.phase = Phase::Stopped;
            self.changed.notify_all();
            (c, id)
        };
        let r = {
            let _w = self.admin.write().unwrap_or_else(|e| e.into_inner());
            self.deps.tools.stop(&c, id)
        };
        let mut st = self.lock();
        st.server = None;
        st.idle_since = None;
        self.changed.notify_all();
        match r {
            Ok(()) => {
                if let Some(n) = note {
                    st.note(n.into());
                }
                true
            }
            Err(e) => {
                st.note(format!("postgres stop failed: {e}"));
                false
            }
        }
    }

    /// Adopted with another configuration and now idle: stop, then start with ours.
    fn restart(&self) {
        let ready = {
            let st = self.lock();
            st.stale && st.rows.is_empty() && st.open.is_empty() && st.phase == Phase::Running
        };
        if !ready {
            return;
        }
        if self.stop_server(None) {
            self.lock().stale = false;
            self.bring_up(false);
        } else {
            // The next lease adopts it again, still stale; an idle tick retries after the
            // backoff.
            self.lock().crashed();
        }
    }

    /// Steps 1 to 7 of a grant (R16, R19, R22, R30). With a template key the database is a
    /// copy of the key's template, or the empty candidate of its first migration.
    fn grant(&self, g: Grant) -> Response {
        let random =
            |n| (self.deps.random)(n).map_err(|e| format!("cannot draw random bytes: {e}"));
        let max = self.pg.max_leases;
        let proj = self.pg.project.iter().find(|p| p.dir == g.project);
        let migrate = proj.is_some_and(|p| !p.migrate.is_empty());
        let same = proj.is_some_and(|p| p.extensions == g.extensions);
        let mut chosen = None;
        let mut choice = None;
        for _ in 0..3 {
            let (c, lease, token) = {
                let mut st = self.lock();
                if st.phase != Phase::Running || st.stale || st.shutdown || st.closed {
                    return err(NOT_RUNNING);
                }
                if st.given_up(g.open) {
                    return err(ABANDONED);
                }
                // Decided again: only this worker adds or promotes templates, so it holds
                // until the reply.
                let key = g.template.as_deref();
                choice = template_choice(&st, migrate, same, &g.project, key);
                match choice {
                    Some(TplChoice::Refuse(why)) => return err(why),
                    // C5: a new key needs its place in the registry before anything exists.
                    Some(TplChoice::Prepare) if st.templates.len() >= MAX_TEMPLATE_ROWS => {
                        return err(
                            "the template registry is full; delete the cluster directory to reset it",
                        );
                    }
                    _ => {}
                }
                if st.releasing() >= MAX_PENDING_RELEASES {
                    if !st.bound_noted {
                        st.bound_noted = true;
                        st.note(cleanups_pending());
                    }
                    return err(cleanups_pending());
                }
                if st.live() >= max as usize {
                    return err(in_use(max));
                }
                let Some(c) = st.paths.clone() else {
                    return err(NOT_RUNNING);
                };
                drop(st);
                let names = random(8).and_then(|h| {
                    let lease = lease_name(&h).map_err(|e| e.to_string())?;
                    Ok((lease, random(8)?))
                });
                let (lease, token) = match names {
                    Ok(n) => n,
                    Err(e) => return err(e),
                };
                let mut st = self.lock();
                // A shutdown that came during the unlocked draw: no row, nothing created.
                if st.shutdown || st.closed {
                    return err(NOT_RUNNING);
                }
                // A promoted candidate's name is free in the catalogue but still recorded.
                if st.rows.iter().any(|r| r.disk.lease == lease)
                    || st.templates.iter().any(|t| t.lease == lease)
                {
                    continue;
                }
                let disk = DiskRow {
                    lease: lease.clone(),
                    token: token.clone(),
                    project: g.project.clone(),
                    r#gen: 1,
                    state: RowState::Creating,
                    cli: g.cli,
                    command: None,
                };
                st.rows.push(Row::new(disk, g.request.clone()));
                if let Err(e) = st.save() {
                    st.rows.retain(|r| r.disk.lease != lease);
                    return err(format!("cannot record the lease: {e}"));
                }
                // From here the row counts in the admission, not the open call.
                st.set_has_row(g.open, true);
                (c, lease, token)
            };
            let taken = name_taken(&lease)
                .map_err(|e| e.to_string())
                .and_then(|s| self.sql(&c, &s, &[]).map_err(|e| e.to_string()));
            match taken {
                Ok(out) if out.trim() == "f" => {
                    chosen = Some((c, lease, token));
                    break;
                }
                Ok(_) => {
                    let mut st = self.lock();
                    st.rows.retain(|r| r.disk.lease != lease);
                    st.set_has_row(g.open, false);
                    let _ = st.save();
                }
                Err(e) => return self.grant_failed(&lease, e, &[]),
            }
        }
        let Some((c, lease, token)) = chosen else {
            return err("no free postgres lease name after 3 tries");
        };
        let password = match random(16) {
            Ok(p) => p,
            Err(e) => return self.grant_failed(&lease, e, &[]),
        };
        let pw = password.as_str();
        let run = |s: Result<String, SqlError>| {
            s.map_err(|e| e.to_string())
                .and_then(|s| self.sql(&c, &s, &[pw]).map_err(|e| e.to_string()))
        };
        let key = g.template.as_deref().unwrap_or_default();
        let created = run(create_role(
            &lease,
            &token,
            pw,
            self.pg.connections_per_lease,
        ))
        .and_then(|_| match choice {
            Some(TplChoice::Clone) => {
                run(create_database_from(&lease, key)).and_then(|_| run(clone_adopt(&lease, key)))
            }
            _ => run(create_database(&lease)),
        });
        if let Err(e) = created {
            return self.grant_failed(&lease, e, &[pw]);
        }
        // Created only in an empty database, before any project code ran there (the candidate
        // too, before its `migrate`). A copy holds the migration's objects, so it is only
        // checked; the list is part of the key, so its template was made with them.
        let exts = &g.extensions;
        let ready = match choice {
            _ if exts.is_empty() => Ok(()),
            Some(TplChoice::Clone) => match run(missing_extensions(&lease, exts)) {
                Ok(out) if out.trim().is_empty() => Ok(()),
                Ok(out) => Err(format!(
                    "the template lacks extension(s) {}; a new template is made when a watched \
                     file or the extensions list changes",
                    out.split_whitespace().collect::<Vec<_>>().join(", ")
                )),
                Err(e) => Err(format!(
                    "cannot check extension(s) {}: {e}",
                    exts.join(", ")
                )),
            },
            _ => run(create_extensions(&lease, exts))
                .map(drop)
                .map_err(|e| format!("cannot create extension(s) {}: {e}", exts.join(", "))),
        };
        if let Err(why) = ready {
            return self.grant_failed(&lease, why, &[pw]);
        }
        let mut st = self.lock();
        if st.given_up(g.open) {
            st.begin_release(&lease);
            self.work.notify_all();
            return err(ABANDONED);
        }
        if let Some(r) = st.row(&lease) {
            r.disk.state = RowState::Granted;
        }
        if let Err(e) = st.save() {
            drop(st);
            return self.grant_failed(&lease, e.to_string(), &[pw]);
        }
        drop(st);
        let env = match lease_env(&lease, pw, self.pg.port, &g.url_vars) {
            Ok(env) => env,
            Err(e) => return self.grant_failed(&lease, e.to_string(), &[pw]),
        };
        match choice {
            Some(TplChoice::Prepare) => self.prepare(&c, &g, lease, &token, env),
            Some(TplChoice::Clone) => Response::Leased {
                lease,
                env,
                template: g.template,
                extensions: g.extensions,
            },
            _ => Response::Leased {
                lease,
                env,
                template: None,
                extensions: g.extensions,
            },
        }
    }

    /// Steps 3 and 4 of a preparation: the candidate's identity is recorded as `preparing`
    /// before `Prepare` authorises its migration.
    fn prepare(
        &self,
        c: &ClusterPaths,
        g: &Grant,
        lease: String,
        token: &str,
        env: BTreeMap<String, Secret>,
    ) -> Response {
        let oids = candidate_oids(&lease, token)
            .map_err(|e| e.to_string())
            .and_then(|s| self.sql(c, &s, &[]).map_err(|e| e.to_string()));
        let (role_oid, db_oid) = match oids.map(|out| parse_oids(&out)) {
            Ok(Some(o)) => o,
            Ok(None) => {
                let why = "the candidate's role or database is missing".to_string();
                return self.grant_failed(&lease, why, &[]);
            }
            Err(e) => return self.grant_failed(&lease, e, &[]),
        };
        let key = g.template.clone().unwrap_or_default();
        let mut st = self.lock();
        // Given back meanwhile (a give-up): nothing to authorise, its release is queued.
        if st
            .row(&lease)
            .is_none_or(|r| r.disk.state != RowState::Granted)
        {
            return err(ABANDONED);
        }
        let seq = st.next_seq;
        st.next_seq += 1;
        st.templates.push(TplRow {
            key: key.clone(),
            project: g.project.clone(),
            state: TplState::Preparing,
            lease: lease.clone(),
            token: token.into(),
            db_oid,
            role_oid,
            seq,
        });
        if let Err(e) = st.save_templates() {
            st.templates.retain(|t| t.key != key);
            drop(st);
            return self.grant_failed(&lease, format!("cannot record the template: {e}"), &[]);
        }
        Response::Prepare {
            lease,
            env,
            extensions: g.extensions.clone(),
        }
    }

    /// S0 to S5b: the candidate `lease` becomes its key's template. `Ack` once `ready` is
    /// recorded; a refused step leaves the key `failed` and gives the candidate back.
    fn promote(&self, lease: &str) -> Response {
        let (c, t) = {
            let st = self.lock();
            if st.phase != Phase::Running || st.shutdown || st.closed {
                return err(NOT_RUNNING);
            }
            let Some(c) = st.paths.clone() else {
                return err(NOT_RUNNING);
            };
            let preparing = |t: &&TplRow| t.lease == lease && t.state == TplState::Preparing;
            let Some(t) = st.templates.iter().find(preparing).cloned() else {
                return err("unknown template");
            };
            (c, t)
        };
        let (key, token) = (t.key.as_str(), t.token.as_str());
        let run = |s| self.run(&c, s);
        // A step that must print `t`; any other output fails with `why`.
        let check = |s, why: &str| match run(s) {
            Ok(out) if out.trim() == "t" => Ok(()),
            Ok(_) => Err(why.to_string()),
            Err(e) => Err(e),
        };
        // S0 touches nothing (C4); S1 to S4b are the durable steps.
        let steps = check(
            template_names_free(key),
            "the template name is already taken",
        )
        .and_then(|()| {
            let why = "a session of the migrated database did not end";
            check(template_seal(lease, token), why)
        })
        .and_then(|()| {
            let why = "the migrated database grants to another role, has row security \
                       policies, or holds objects of another owner";
            check(template_check(lease), why)
        })
        .and_then(|()| run(template_own(lease)))
        .and_then(|_| run(template_rename_role(lease, token, key)))
        .and_then(|_| run(template_rename_db(lease, key)));
        let mut st = self.lock();
        // Only a row still `preparing` for this candidate becomes `ready`; one that changed
        // meanwhile is left as it is.
        let preparing = st
            .templates
            .iter()
            .any(|r| r.key == key && r.lease == lease && r.state == TplState::Preparing);
        let steps = match steps {
            Ok(_) if !preparing => Err("the template is no longer preparing".to_string()),
            s => s,
        };
        if let Err(why) = steps {
            if preparing {
                st.set_tpl(key, TplState::Failed);
                st.prune_failed();
                if let Err(e) = st.save_templates() {
                    st.note(format!("postgres template registry write failed: {e}"));
                }
            }
            st.note(format!("postgres template {key} failed: {why}"));
            st.begin_release(lease);
            self.work.notify_all();
            return err(format!("postgres template failed: {why}"));
        }
        // S5a.
        st.set_tpl(key, TplState::Ready);
        if let Err(e) = st.save_templates() {
            // M1: a complete template the registry does not hold yet. Nothing is dropped;
            // the candidate's exit finds it in the catalogue and records it.
            if let Some(r) = st.templates.iter_mut().find(|r| r.key == key) {
                r.state = TplState::Preparing;
                r.seq = t.seq;
            }
            return err(format!("cannot record the template: {e}"));
        }
        // S5b: the candidate's lease row goes; a failed write keeps it, and its exit or the
        // reconciliation removes it without dropping anything.
        if let Some(i) = st.rows.iter().position(|r| r.disk.lease == lease) {
            let row = st.rows.remove(i);
            if let Err(e) = st.save() {
                st.rows.insert(i, row);
                st.note(format!("postgres lease registry write failed: {e}"));
            }
        }
        drop(st);
        // S6: a failure stays pending and never changes the answer.
        self.retire(&c);
        Response::Ack
    }

    /// S6, and after every start or failed try: in each project every `ready` row but the
    /// newest by `seq` (M3) retires, oldest first: its database and role dropped by identity,
    /// then the row leaves, recorded. A failure keeps the row and is tried again from
    /// `retire_at` (M2). Never with an unknown registry.
    fn retire(&self, c: &ClusterPaths) {
        loop {
            let t = {
                let mut st = self.lock();
                if st.tpl_unknown {
                    return;
                }
                let ready = |t: &&TplRow| t.state == TplState::Ready;
                let newer = |t: &TplRow| {
                    let mut all = st.templates.iter().filter(ready);
                    all.any(|n| n.project == t.project && n.seq > t.seq)
                };
                let old = st.templates.iter().filter(ready).filter(|t| newer(t));
                let Some(t) = old.min_by_key(|t| t.seq).cloned() else {
                    // Inherited rows still to reconcile keep the upkeep owed.
                    if st.inherited.is_empty() {
                        st.retire_pending = false;
                        st.retire_at = None;
                        st.retire_backoff.reset();
                    }
                    return;
                };
                t
            };
            let done = self.drop_by_identity(c, &t);
            let mut st = self.lock();
            let why = match done {
                Err(why) => why,
                Ok(()) => {
                    let same = |r: &TplRow| r.key == t.key && r.seq == t.seq;
                    let Some(i) = st.templates.iter().position(same) else {
                        continue;
                    };
                    let row = st.templates.remove(i);
                    match st.save_templates() {
                        Ok(()) => continue,
                        Err(e) => {
                            st.templates.insert(i, row);
                            format!("cannot record the template: {e}")
                        }
                    }
                }
            };
            st.note(format!(
                "postgres retire of template {} failed: {}",
                t.key,
                redact(&why, &[])
            ));
            st.retire_pending = true;
            let wait = st.retire_backoff.next();
            st.retire_at = Some(st.now + wait);
            return;
        }
    }

    /// R21 and S5b after a restart, on every start and on `Item::Retire`: an inherited
    /// `preparing` row becomes `ready` when the catalogue holds its complete template and
    /// `failed` otherwise (its candidate then leaves by rule D); one whose query fails stays
    /// inherited, owed, and is asked again after a backoff. The `failed` rows of every project
    /// are pruned, and the lease row of a `ready` row leaves, dropping nothing. Then the older
    /// templates retire. Never with an unknown registry; a template problem is a note, never a
    /// failed start.
    fn reconcile_templates(&self, c: &ClusterPaths) {
        let inherited: Vec<TplRow> = {
            let mut st = self.lock();
            if st.tpl_unknown {
                return;
            }
            let p = |t: &&TplRow| t.state == TplState::Preparing && st.inherited.contains(&t.key);
            let rows: Vec<TplRow> = st.templates.iter().filter(p).cloned().collect();
            // A row decided meanwhile (a report, its candidate's exit) is no longer inherited.
            st.inherited = rows.iter().map(|t| t.key.clone()).collect();
            rows
        };
        let mut settled = Vec::new();
        for t in inherited {
            match self.run(c, template_state(&t.key, t.db_oid, t.role_oid)) {
                Ok(out) => settled.push((t, out.trim() == "t")),
                Err(e) => {
                    self.lock()
                        .note(format!("postgres template {}: {}", t.key, redact(&e, &[])))
                }
            }
        }
        let owed = {
            let mut st = self.lock();
            let mut changed = false;
            for (t, ready) in &settled {
                st.inherited.remove(&t.key);
                let same = |r: &TplRow| {
                    r.key == t.key && r.lease == t.lease && r.state == TplState::Preparing
                };
                if st.templates.iter().any(same) {
                    let to = if *ready {
                        TplState::Ready
                    } else {
                        TplState::Failed
                    };
                    st.set_tpl(&t.key, to);
                    changed = true;
                }
            }
            changed |= st.prune_failed();
            if changed && let Err(e) = st.save_templates() {
                st.note(format!("postgres template registry write failed: {e}"));
            }
            let ready = |t: &&TplRow| t.state == TplState::Ready;
            let promoted: HashSet<String> = st
                .templates
                .iter()
                .filter(ready)
                .map(|t| t.lease.clone())
                .collect();
            let before = st.rows.len();
            st.rows.retain(|r| !promoted.contains(&r.disk.lease));
            if st.rows.len() < before
                && let Err(e) = st.save()
            {
                st.note(format!("postgres lease registry write failed: {e}"));
            }
            !st.inherited.is_empty()
        };
        self.retire(c);
        if owed {
            let mut st = self.lock();
            st.retire_pending = true;
            let wait = st.retire_backoff.next();
            st.retire_at = Some(st.now + wait);
        }
    }

    /// A grant step failed after its row was written: the row goes back by its mark.
    fn grant_failed(&self, lease: &str, why: String, secrets: &[&str]) -> Response {
        let why = redact(&why, secrets);
        let mut st = self.lock();
        st.note(format!("postgres lease {lease} failed: {why}"));
        st.begin_release(lease);
        self.work.notify_all();
        err(format!("postgres lease failed: {why}"))
    }

    /// Runs one built script; either failure as text.
    fn run(&self, c: &ClusterPaths, s: Result<String, SqlError>) -> Result<String, String> {
        s.map_err(|e| e.to_string())
            .and_then(|s| self.sql(c, &s, &[]).map_err(|e| e.to_string()))
    }

    /// The lease's own path: its databases and role, found by its creation mark.
    fn drop_by_mark(&self, c: &ClusterPaths, lease: &str, token: &str) -> Result<(), String> {
        let owned = self.run(c, owned_databases(lease, token))?;
        for db in owned.lines().map(str::trim).filter(|d| !d.is_empty()) {
            self.run(c, drop_database(db))?;
        }
        self.run(c, drop_role(lease, token)).map(|_| ())
    }

    /// C4: the database and role recorded in `t`, each only while its OID still names the
    /// candidate or the template of `t.key`; the database first.
    fn drop_by_identity(&self, c: &ClusterPaths, t: &TplRow) -> Result<(), String> {
        let name = self.run(c, db_by_oid(t.db_oid, t.role_oid, &t.lease, &t.key))?;
        for db in name.lines().map(str::trim).filter(|d| !d.is_empty()) {
            self.run(c, drop_database(db))?;
        }
        let role = drop_template_role(t.role_oid, &t.lease, &t.token, &t.key);
        self.run(c, role).map(|_| ())
    }

    /// C3: the exit of the candidate of `t`. `ready`: nothing is dropped. `preparing`: a
    /// complete template in the catalogue is recorded `ready` and nothing is dropped; otherwise
    /// the candidate is dropped by identity and the row becomes `failed` when its `migrate` was
    /// recorded, or leaves. `failed`: dropped by identity. Then the lease's own path finds
    /// nothing or the rest.
    fn candidate_exit(&self, c: &ClusterPaths, t: &TplRow) -> Result<(), String> {
        if t.state == TplState::Ready {
            return Ok(());
        }
        if t.state == TplState::Preparing {
            let out = self.run(c, template_state(&t.key, t.db_oid, t.role_oid))?;
            if out.trim() == "t" {
                // M1: promoted, never recorded.
                return self.settle(t, Some(TplState::Ready));
            }
        }
        self.drop_by_identity(c, t)?;
        self.drop_by_mark(c, &t.lease, &t.token)?;
        if t.state == TplState::Failed {
            return Ok(());
        }
        let ran = self
            .lock()
            .row(&t.lease)
            .is_some_and(|r| r.disk.command.is_some());
        self.settle(t, ran.then_some(TplState::Failed))
    }

    /// The `preparing` row `t` becomes `to`, or leaves (`None`), recorded. A row that changed
    /// meanwhile, or a write that fails, is an error: the release tries again from the row.
    fn settle(&self, t: &TplRow, to: Option<TplState>) -> Result<(), String> {
        let mut st = self.lock();
        let same = |r: &TplRow| r.key == t.key && r.lease == t.lease;
        let Some(i) = st
            .templates
            .iter()
            .position(|r| same(r) && r.state == TplState::Preparing)
        else {
            return Err(format!("template {} changed meanwhile", t.key));
        };
        let old = st.templates[i].clone();
        match to {
            Some(s) => st.set_tpl(&t.key, s),
            None => {
                st.templates.remove(i);
            }
        }
        if let Err(e) = st.save_templates() {
            match to {
                Some(_) => st.templates[i] = old,
                None => st.templates.insert(i, old),
            }
            return Err(format!("cannot record the template: {e}"));
        }
        // The project's older templates retire on the next tick, as after a promotion.
        st.retire_pending |= to == Some(TplState::Ready);
        Ok(())
    }

    /// Gives a `releasing` row back by its mark, a template's candidate by its template row
    /// first (C3); a failure retries after the backoff.
    fn release(&self, lease: &str) {
        let (c, token, tpl) = {
            let mut st = self.lock();
            let Some(c) = st.paths.clone() else { return };
            let token = match st.row(lease) {
                Some(r) if r.disk.state == RowState::Releasing => r.disk.token.clone(),
                _ => return,
            };
            // An unknown registry removes no template (R12). Name and mark: a name alone could
            // be another lease's.
            let tpl = st
                .templates
                .iter()
                .find(|t| t.lease == lease && t.token == token)
                .cloned();
            (c, token, tpl.filter(|_| !st.tpl_unknown))
        };
        let done = match &tpl {
            Some(t) => self.candidate_exit(&c, t),
            None => self.drop_by_mark(&c, lease, &token),
        };
        let mut st = self.lock();
        match done {
            Ok(()) => {
                st.rows.retain(|r| r.disk.lease != lease);
                if let Err(e) = st.save() {
                    st.note(format!("postgres lease registry write failed: {e}"));
                }
                // C6: a failed row's candidate left (the prune waits until that is on disk).
                if tpl.is_some()
                    && st.prune_failed()
                    && let Err(e) = st.save_templates()
                {
                    st.note(format!("postgres template registry write failed: {e}"));
                }
                if st.releasing() < MAX_PENDING_RELEASES {
                    st.bound_noted = false;
                }
                if st.rows.is_empty() {
                    st.idle_since = Some(st.now);
                }
            }
            Err(why) => {
                let now = st.now;
                if let Some(r) = st.row(lease) {
                    r.retry_at = Some(now + r.backoff.next());
                }
                st.note(format!(
                    "postgres cleanup of {lease} failed: {}",
                    redact(&why, &[])
                ));
            }
        }
    }

    /// Rule D's sample: only a well-read one changes `quiet` (R26).
    fn sample(&self, lease: &str) -> Option<(i64, i64)> {
        let c = {
            let mut st = self.lock();
            let c = st.paths.clone()?;
            let r = st.row(lease)?;
            if r.disk.state != RowState::Granted || r.disk.command.is_some() {
                return None;
            }
            c
        };
        let parsed = db_activity(lease)
            .ok()
            .and_then(|s| self.sql(&c, &s, &[]).ok())
            .and_then(|out| parse_activity(&out));
        let mut st = self.lock();
        let (server, now) = (st.server, st.now);
        if let (Some((live, sessions)), Some(id), Some(r)) = (parsed, server, st.row(lease)) {
            if live > 0 {
                r.quiet = None;
            } else if r
                .quiet
                .is_none_or(|q| q.server != id || q.sessions != sessions)
            {
                r.quiet = Some(Quiet {
                    server: id,
                    since: now,
                    sessions,
                });
            }
        }
        parsed
    }

    /// Rule D: every condition, checked under the state lock right before acting.
    fn decide(&self, lease: &str, r#gen: u64) {
        let needs_sample = {
            let mut st = self.lock();
            match st.row(lease) {
                Some(r) if r.disk.state == RowState::Granted && r.disk.r#gen == r#gen => {
                    r.disk.command.is_none()
                }
                _ => return,
            }
        };
        let sample = if needs_sample {
            self.sample(lease)
        } else {
            None
        };
        let mut st = self.lock();
        let (server, now, grace) = (st.server, st.now, self.deps.quiet_grace);
        let Some(r) = st.row(lease) else { return };
        if r.disk.state != RowState::Granted || r.disk.r#gen != r#gen {
            return;
        }
        if self.live(&r.disk.cli) != Liveness::Gone {
            return;
        }
        match r.disk.command {
            Some(h) => {
                if self.live(&h) != Liveness::Gone {
                    return;
                }
            }
            None => {
                let Some(q) = r.quiet else { return };
                let quiet_long =
                    Some(q.server) == server && now.saturating_duration_since(q.since) >= grace;
                if !quiet_long || sample != Some((0, q.sessions)) {
                    return;
                }
            }
        }
        r.disk.state = RowState::Releasing;
        if st.save().is_err() {
            // Stays granted; the next tick decides again.
            if let Some(r) = st.row(lease) {
                r.disk.state = RowState::Granted;
            }
            return;
        }
        st.enqueue(Kind::Release, lease, 0);
    }
}

/// Loads `leases.json` (R12): readable = known; absent or unreadable in an existing cluster =
/// unknown (the unreadable file is set aside), and leftover cleanup stays off for good.
fn load_registry(st: &mut State, c: &ClusterPaths) -> Result<(), String> {
    let unknown = match std::fs::read(&c.leases) {
        Ok(bytes) => match parse_registry(&bytes) {
            Some(d) => {
                st.unknown_before = d.unknown_before;
                st.rows = d
                    .leases
                    .into_iter()
                    .map(|d| Row::new(d, String::new()))
                    .collect();
                return Ok(());
            }
            None => true,
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => c.record.exists(),
        Err(_) => true,
    };
    st.rows.clear();
    if !unknown {
        return Ok(());
    }
    if c.leases.exists() {
        let mut aside = c.leases.as_os_str().to_owned();
        aside.push(".unreadable");
        std::fs::rename(&c.leases, PathBuf::from(aside))
            .map_err(|e| format!("cannot set aside the unreadable lease registry: {e}"))?;
    }
    st.unknown_before = true;
    st.note(UNREADABLE.into());
    st.save()
        .map_err(|e| format!("cannot write the lease registry: {e}"))
}

/// Loads `templates.json` like [`load_registry`], on its own: absent or unreadable in an
/// existing cluster = unknown for templates only (the unreadable file is set aside).
fn load_templates(st: &mut State, c: &ClusterPaths) -> Result<(), String> {
    let unknown = match std::fs::read(&c.templates) {
        Ok(bytes) => match parse_templates(&bytes) {
            Some(d) => {
                st.tpl_unknown = d.unknown_before;
                st.next_seq = d.next_seq;
                st.templates = d.templates;
                // A previous daemon's migrations: reconciled until that succeeds.
                let preparing = st
                    .templates
                    .iter()
                    .filter(|t| t.state == TplState::Preparing);
                st.inherited = preparing.map(|t| t.key.clone()).collect();
                return Ok(());
            }
            None => true,
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => c.record.exists(),
        Err(_) => true,
    };
    st.templates.clear();
    st.next_seq = 1;
    if !unknown {
        return Ok(());
    }
    // Off first: the recovery below is best effort and never fails the reconciliation, so
    // leases of the databases without a template go on (a note says what did not work).
    st.tpl_unknown = true;
    st.tpl_loaded = true;
    st.note(TEMPLATES_UNREADABLE.into());
    if c.templates.exists() {
        let mut aside = c.templates.as_os_str().to_owned();
        aside.push(".unreadable");
        let moved = st
            .injected()
            .and_then(|()| std::fs::rename(&c.templates, PathBuf::from(aside)));
        if let Err(e) = moved {
            st.note(format!(
                "cannot set aside the unreadable template registry: {e}"
            ));
        }
    }
    if let Err(e) = st.save_templates() {
        st.note(format!("cannot write the template registry: {e}"));
    }
    Ok(())
}

/// `bytes` random bytes from the operating system, as lowercase hex.
pub fn random_hex(bytes: usize) -> io::Result<String> {
    use std::fmt::Write;
    let mut buf = vec![0u8; bytes];
    fill_random(&mut buf)?;
    let mut hex = String::with_capacity(bytes * 2);
    for b in buf {
        let _ = write!(hex, "{b:02x}");
    }
    Ok(hex)
}

#[cfg(unix)]
fn fill_random(buf: &mut [u8]) -> io::Result<()> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")?.read_exact(buf)
}

#[cfg(windows)]
fn fill_random(buf: &mut [u8]) -> io::Result<()> {
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
    };
    let len = u32::try_from(buf.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `buf` is `len` writable bytes; no algorithm handle with the system RNG flag.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            buf.as_mut_ptr(),
            len,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        return Err(io::Error::other(format!(
            "BCryptGenRandom failed: {status:#x}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;

// Named apart from the `tests` module.
#[cfg(test)]
mod random_tests {
    use super::random_hex;

    #[test]
    fn random_hex_is_long_and_fresh() {
        let (a, b) = (random_hex(16).unwrap(), random_hex(16).unwrap());
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }
}
