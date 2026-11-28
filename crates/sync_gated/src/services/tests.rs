//! The shared PostgreSQL service against `FakePg`: no real server. Time is injected through
//! `tick(t0 + n s)`; every wait is on an event (`wait_idle`, a blocked `FakePg` step) with a
//! hard limit.

use super::testkit::{ALWAYS, Blocked, FakePg, Scratch};
use super::*;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use sync_gate_core::{PgProject, Request};

/// Hard limit of every wait in these tests (FakePg answers in microseconds).
const LIMIT: Duration = Duration::from_secs(10);
/// Hard limit for a lease reply or a helper thread (ruling F2): past it the test panics.
const DONE: Duration = Duration::from_secs(60);
const CLI: u32 = 10;
const CMD: u32 = 20;

fn holder(pid: u32) -> Holder {
    Holder {
        pid,
        start: Some(1000 + u64::from(pid)),
    }
}

type Table = HashMap<u32, (Option<bool>, Option<u64>)>;

/// The process table the probe reads: pid -> (alive, start time). Unlisted = unreadable.
#[derive(Clone, Default)]
struct Procs(Arc<Mutex<Table>>);

impl Procs {
    fn set(&self, pid: u32, alive: Option<bool>, start: Option<u64>) {
        self.0.lock().unwrap().insert(pid, (alive, start));
    }
    fn alive(&self, pid: u32) {
        self.set(pid, Some(true), holder(pid).start);
    }
    fn gone(&self, pid: u32) {
        self.set(pid, Some(false), None);
    }
    fn probe(&self) -> Probe {
        let m = self.0.clone();
        Arc::new(move |pid| m.lock().unwrap().get(&pid).copied().unwrap_or((None, None)))
    }
}

/// The next draw says so on the first channel, then waits until the second one's sender drops.
type Gate = Arc<Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>>;

/// Planned values first, then distinct counter values of the asked length.
#[derive(Clone, Default)]
struct Rand(Arc<Mutex<VecDeque<String>>>, Arc<AtomicU64>, Gate);

impl Rand {
    fn push(&self, s: &str) {
        self.0.lock().unwrap().push_back(s.into());
    }
    /// Holds the next draw: the receiver says it was entered; dropping the sender (the
    /// guard) lets it go, and so does [`DONE`].
    fn block(&self) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (entered_tx, entered) = mpsc::channel();
        let (go, go_rx) = mpsc::channel();
        *self.2.lock().unwrap() = Some((entered_tx, go_rx));
        (entered, go)
    }
    fn random(&self) -> Random {
        let (q, n, gate) = (self.0.clone(), self.1.clone(), self.2.clone());
        Arc::new(move |bytes| {
            let held = gate.lock().unwrap().take();
            if let Some((entered, go)) = held {
                let _ = entered.send(());
                let _ = go.recv_timeout(DONE);
            }
            if let Some(s) = q.lock().unwrap().pop_front() {
                return Ok(s);
            }
            let k = n.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(format!("{k:0w$x}", w = bytes * 2))
        })
    }
}

struct Fx {
    /// First: fields drop in order, so the service ends before its folder goes.
    s: Option<Arc<Services>>,
    dir: Scratch,
    proj: PathBuf,
    fake: Arc<FakePg>,
    procs: Procs,
    rand: Rand,
    pg: PgConfig,
    lease_wait: Duration,
    sample_every: Duration,
    tpl_fail: u32,
    t0: Instant,
    /// The extensions the CLI sends; `None`: the daemon's own list for the project.
    cli_ext: Option<Vec<String>>,
}

impl Fx {
    /// Everything but the service; tweak and seed, then `open`.
    fn bare(tag: &str) -> Fx {
        let dir = Scratch::new(&format!("svc-{tag}"));
        let proj = dir.join("proj");
        let pg = PgConfig {
            bin_dir: dir.join("bin"),
            project: vec![PgProject {
                dir: proj.clone(),
                commands: Vec::new(),
                url_vars: vec!["DATABASE_URL".into()],
                migrate: Vec::new(),
                watch: Vec::new(),
                migrate_timeout_secs: 300,
                extensions: Vec::new(),
            }],
            ..PgConfig::default()
        };
        let procs = Procs::default();
        procs.alive(CLI);
        procs.alive(CMD);
        Fx {
            dir,
            proj,
            fake: Arc::new(FakePg::default()),
            procs,
            rand: Rand::default(),
            pg,
            lease_wait: LIMIT,
            sample_every: Duration::from_secs(30),
            tpl_fail: 0,
            s: None,
            t0: Instant::now(),
            cli_ext: None,
        }
    }

    fn new(tag: &str) -> Fx {
        let mut fx = Fx::bare(tag);
        fx.open();
        fx
    }

    /// `proj` runs `migrate = ["m"]` over `watch = ["db"]`; [`Fx::plain`], in the same
    /// configuration, declares no migration.
    fn migrating(tag: &str) -> Fx {
        let mut fx = Fx::bare(tag);
        let plain = PgProject {
            dir: fx.plain(),
            ..fx.pg.project[0].clone()
        };
        fx.pg.project[0].migrate = vec!["m".into()];
        fx.pg.project[0].watch = vec!["db".into()];
        fx.pg.project.push(plain);
        fx.open();
        fx
    }

    fn plain(&self) -> PathBuf {
        self.dir.join("plain")
    }

    fn deps(&self) -> Deps {
        Deps {
            tools: self.fake.clone(),
            probe: self.procs.probe(),
            random: self.rand.random(),
            lease_wait: Some(self.lease_wait),
            quiet_grace: Duration::from_secs(600),
            quiet_sample_every: self.sample_every,
            mcp_reload: None,
            tpl_fail: self.tpl_fail,
        }
    }

    fn cfg(&self) -> Config {
        Config {
            postgres: Some(self.pg.clone()),
            ..Config::default()
        }
    }

    /// A new service over the same folder and catalogue (the previous one is dropped first).
    fn open(&mut self) {
        if let Some(old) = self.s.take() {
            assert!(old.wait_idle(Instant::now() + LIMIT));
            drop(old);
        }
        let s = Services::new(&self.cfg(), Some(&*self.dir), self.deps());
        self.s = Some(Arc::new(s));
        self.idle();
    }

    fn s(&self) -> &Services {
        self.s.as_deref().unwrap()
    }

    fn lease_bg(&self, cli: Holder, request: &str) -> mpsc::Receiver<Response> {
        self.lease_in(&self.proj, cli, request, None)
    }

    /// The lease call on a thread of its own; its reply comes on the channel ([`reply`]).
    fn lease_in(
        &self,
        proj: &Path,
        cli: Holder,
        request: &str,
        key: Option<&str>,
    ) -> mpsc::Receiver<Response> {
        let s = self.s.clone().unwrap();
        let own = self.pg.project.iter().find(|p| p.dir == proj);
        let ext = self
            .cli_ext
            .clone()
            .unwrap_or_else(|| own.map(|p| p.extensions.clone()).unwrap_or_default());
        let (proj, request) = (proj.to_path_buf(), request.to_string());
        let key = key.map(String::from);
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let r = s.lease(&proj, cli, &request, key.as_deref(), &ext);
            // Gone before the reply, so the test owns the last reference.
            drop(s);
            let _ = tx.send(r);
        });
        rx
    }

    /// A request of `proj` with template key `key`, on a thread of its own.
    fn keyed_bg(&self, key: &str) -> mpsc::Receiver<Response> {
        self.lease_in(&self.proj, holder(CLI), "", Some(key))
    }

    fn keyed(&self, key: &str) -> Response {
        reply(self.keyed_bg(key))
    }

    /// `template_ready` on a thread of its own.
    fn ready_bg(&self, lease: &str, ok: bool) -> mpsc::Receiver<Response> {
        let (s, lease) = (self.s.clone().unwrap(), lease.to_string());
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let r = s.template_ready(&lease, ok, false);
            drop(s);
            let _ = tx.send(r);
        });
        rx
    }

    /// `template_ready` within [`DONE`], or a panic that says so.
    fn ready(&self, lease: &str, ok: bool) -> Response {
        reply(self.ready_bg(lease, ok))
    }

    fn root(&self) -> PathBuf {
        self.dir.join("pg").join("17")
    }

    fn registry(&self) -> String {
        std::fs::read_to_string(self.root().join("leases.json")).unwrap_or_default()
    }

    fn templates(&self) -> String {
        std::fs::read_to_string(self.root().join("templates.json")).unwrap_or_default()
    }

    /// The running service's next `n` template registry writes fail (ruling PF-A).
    fn fail_template_writes(&self, n: u32) {
        match &self.s().mode {
            Mode::On(inner) => inner.lock().tpl_fail = n,
            _ => panic!("service is off"),
        }
    }

    /// The running service's next `n` lease registry writes fail (ruling PF-A).
    fn fail_lease_writes(&self, n: u32) {
        match &self.s().mode {
            Mode::On(inner) => inner.lock().lease_fail = n,
            _ => panic!("service is off"),
        }
    }

    fn lease_r(&self, request: &str) -> Response {
        reply(self.lease_bg(holder(CLI), request))
    }

    fn leased(&self) -> String {
        leased(self.lease_r(""))
    }

    fn idle(&self) {
        assert!(
            self.s().wait_idle(Instant::now() + LIMIT),
            "worker never idle"
        );
    }

    /// `tick(t0 + secs)`, then the barrier that the worker did what it queued.
    fn tick(&self, secs: u64) {
        self.s().tick(self.t0 + Duration::from_secs(secs));
        self.idle();
    }

    /// (`tpl_loaded`, `tpl_unknown`) of the running service.
    fn tpl_flags(&self) -> (bool, bool) {
        match &self.s().mode {
            Mode::On(inner) => {
                let st = inner.lock();
                (st.tpl_loaded, st.tpl_unknown)
            }
            _ => panic!("service is off"),
        }
    }

    fn state(&self) -> String {
        self.s().report()[0].state.clone()
    }

    fn drops(&self) -> usize {
        self.fake.count("drop_role")
    }

    /// Spins (no sleep) until `n` grants wait in the queue.
    fn wait_queued(&self, n: usize) {
        let deadline = Instant::now() + LIMIT;
        while self.s().queued_items("grant") < n {
            assert!(Instant::now() < deadline, "grants never queued");
            std::thread::yield_now();
        }
    }
}

/// A lease reply within [`DONE`], or a panic that says so.
fn reply(rx: mpsc::Receiver<Response>) -> Response {
    rx.recv_timeout(DONE)
        .unwrap_or_else(|_| panic!("no lease reply within {DONE:?}"))
}

fn leased(r: Response) -> String {
    match r {
        Response::Leased { lease, .. } => lease,
        other => panic!("not leased: {other:?}"),
    }
}

fn error(r: Response) -> String {
    match r {
        Response::Error { message } => message,
        other => panic!("not an error: {other:?}"),
    }
}

/// The candidate of a `Prepare`.
fn prepared(r: Response) -> String {
    match r {
        Response::Prepare { lease, env, .. } => {
            assert_eq!(env["PGDATABASE"].expose(), lease);
            lease
        }
        other => panic!("not prepare: {other:?}"),
    }
}

/// The state `leases.json` records for `lease`.
fn disk_state(fx: &Fx, lease: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(&fx.registry()).ok()?;
    let row = v["leases"]
        .as_array()?
        .iter()
        .find(|r| r["lease"] == lease)?;
    row["state"].as_str().map(Into::into)
}

fn password(r: &Response) -> String {
    match r {
        Response::Leased { env, .. } => env["PGPASSWORD"].expose().to_string(),
        other => panic!("not leased: {other:?}"),
    }
}

/// `leases.json` of an existing cluster with these rows; the cluster is "running" as `id`.
fn seed(fx: &Fx, rows: &str, id: ServerId) {
    let root = fx.root();
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("cluster.json"), "{}").unwrap();
    if !rows.is_empty() {
        std::fs::write(
            root.join("leases.json"),
            format!(r#"{{"version":1,"unknown_before":false,"leases":[{rows}]}}"#),
        )
        .unwrap();
    }
    fx.fake.set_server(Ok(Some(id)));
}

fn row(lease: &str, token: &str, state: &str, cli: u32, command: Option<u32>) -> String {
    let h = |p: u32| format!(r#"{{"pid":{p},"start":{}}}"#, 1000 + p);
    let command = command.map_or("null".into(), h);
    format!(
        r#"{{"lease":"{lease}","token":"{token}","project":"p","gen":1,"state":"{state}","cli":{},"command":{command}}}"#,
        h(cli)
    )
}

const SERVER: ServerId = ServerId { pid: 800, start: 1 };

#[test]
fn liveness_is_conservative() {
    assert!(matches!(
        liveness(Some(5), Some(false), None),
        Liveness::Gone
    ));
    assert!(matches!(
        liveness(Some(5), Some(true), Some(9)),
        Liveness::Gone
    )); // pid reused
    assert!(matches!(
        liveness(Some(5), Some(true), Some(5)),
        Liveness::Alive
    ));
    assert!(matches!(
        liveness(Some(5), Some(true), None),
        Liveness::Unknown
    )); // unreadable start
    assert!(matches!(
        liveness(None, Some(true), Some(5)),
        Liveness::Unknown
    )); // start never known
    assert!(matches!(liveness(Some(5), None, None), Liveness::Unknown)); // table unreadable
}

// R16

#[test]
fn cli_dead_before_spawn_is_dropped_after_the_quiet_grace() {
    let fx = Fx::new("d1");
    let l = fx.leased();
    fx.procs.gone(CLI);
    fx.tick(1);
    fx.tick(600);
    assert_eq!(fx.drops(), 0, "inside the grace");
    fx.tick(601);
    assert_eq!(fx.drops(), 1);
    assert!(!fx.fake.roles().contains_key(&l));
    assert!(!fx.registry().contains(&l));
}

#[test]
fn cli_dead_after_spawn_with_a_live_session_is_kept() {
    let fx = Fx::new("d2");
    let l = fx.leased();
    fx.procs.gone(CLI);
    fx.fake.set_activity(Ok("1|1"));
    // Five ticks beyond the grace.
    for t in [1, 700, 1400, 2100, 2800, 3500] {
        fx.tick(t);
    }
    assert_eq!(fx.drops(), 0);
    assert!(fx.fake.roles().contains_key(&l));
    assert_eq!(fx.s().report()[0].unknown_holders, 0);
}

#[test]
fn daemon_down_during_the_hand_over_keeps_a_live_session() {
    let mut fx = Fx::new("d3");
    let l = fx.leased();
    assert!(fx.registry().contains("granted"));
    fx.open();
    assert_eq!(fx.fake.count("start"), 1, "the running server is adopted");
    fx.procs.gone(CLI);
    fx.fake.set_activity(Ok("1|1"));
    fx.tick(1);
    fx.tick(700);
    assert_eq!(fx.drops(), 0);
    fx.fake.set_activity(Ok("0|1"));
    fx.tick(800);
    fx.tick(1399);
    assert_eq!(
        fx.drops(),
        0,
        "the grace counts from the first quiet sample"
    );
    fx.tick(1400);
    assert_eq!(fx.drops(), 1);
    assert!(!fx.registry().contains(&l));
}

#[test]
fn a_session_between_samples_restarts_the_grace() {
    let fx = Fx::new("d4");
    fx.leased();
    fx.procs.gone(CLI);
    fx.fake.set_activity(Ok("0|1"));
    fx.tick(1);
    fx.fake.set_activity(Ok("0|2"));
    fx.tick(100);
    fx.tick(601);
    assert_eq!(fx.drops(), 0);
    fx.tick(700);
    assert_eq!(fx.drops(), 1);
}

#[test]
fn a_server_restart_restarts_the_grace() {
    // The session counter falls (a restarted server starts from zero).
    let fx = Fx::new("d5a");
    fx.leased();
    fx.procs.gone(CLI);
    fx.fake.set_activity(Ok("0|5"));
    fx.tick(1);
    fx.fake.set_activity(Ok("0|0"));
    fx.tick(500);
    fx.tick(601);
    assert_eq!(fx.drops(), 0);
    fx.tick(1100);
    assert_eq!(fx.drops(), 1);

    // Another server identity.
    let fx = Fx::new("d5b");
    fx.leased();
    fx.procs.gone(CLI);
    fx.tick(1);
    let old = fx.fake.server_id().unwrap();
    fx.procs.gone(old.pid);
    fx.fake.set_server(Ok(None));
    fx.tick(500);
    fx.tick(502);
    assert_ne!(fx.fake.server_id(), Some(old), "restarted");
    fx.tick(700);
    assert_eq!(
        fx.drops(),
        0,
        "the window started again with the new server"
    );
    fx.tick(1299);
    assert_eq!(fx.drops(), 0);
    fx.tick(1300);
    assert_eq!(fx.drops(), 1);
}

#[test]
fn both_recorded_holders_must_be_gone() {
    let fx = Fx::new("d6");
    let l = fx.leased();
    assert_eq!(fx.s().set_holder(&l, holder(CMD)), Response::Ack);
    fx.procs.gone(CLI);
    fx.tick(1);
    assert_eq!(fx.drops(), 0);
    fx.procs.alive(CLI);
    fx.procs.gone(CMD);
    fx.tick(2);
    assert_eq!(fx.drops(), 0);
    fx.procs.gone(CLI);
    fx.tick(3);
    assert_eq!(fx.drops(), 1, "no grace with a recorded command");
}

#[test]
fn reused_pid_counts_as_gone() {
    let fx = Fx::new("d7");
    let l = fx.leased();
    fx.s().set_holder(&l, holder(CMD));
    fx.procs.set(CMD, Some(true), Some(999));
    fx.procs.gone(CLI);
    fx.tick(1);
    assert_eq!(fx.drops(), 1);
}

#[test]
fn unknown_holder_never_drops() {
    let fx = Fx::new("d8");
    fx.leased();
    fx.procs.set(CLI, Some(true), None);
    fx.tick(1);
    fx.tick(700);
    fx.tick(1400);
    assert_eq!(fx.drops(), 0);
    assert_eq!(fx.fake.count("db_activity"), 0);
    assert_eq!(fx.s().report()[0].unknown_holders, 1);
}

#[test]
fn a_stale_cleanup_decision_is_not_executed() {
    let mut fx = Fx::bare("d9");
    fx.sample_every = Duration::from_secs(3600);
    fx.open();
    let l = fx.leased();
    fx.procs.gone(CLI);
    fx.tick(1);
    let b = fx.fake.block("db_activity");
    fx.s().tick(fx.t0 + Duration::from_secs(700));
    assert!(
        fx.fake.wait_entered("db_activity", LIMIT),
        "the decision samples"
    );
    assert_eq!(fx.s().set_holder(&l, holder(CMD)), Response::Ack);
    drop(b);
    fx.idle();
    assert_eq!(fx.drops(), 0);
    let reg = fx.registry();
    assert!(
        reg.contains("granted") && reg.contains(r#""pid": 20"#),
        "{reg}"
    );
}

/// Rule D's final checks, one at a time (ruling T1): a no-command lease whose CLI is Gone and
/// whose grace has passed, with its decision held in its own sample at t = 700.
fn decision_held(tag: &str) -> (Fx, String, Blocked) {
    let mut fx = Fx::bare(tag);
    fx.sample_every = Duration::from_secs(3600);
    fx.open();
    let l = fx.leased();
    fx.procs.gone(CLI);
    fx.tick(1);
    let b = fx.fake.block("db_activity");
    fx.s().tick(fx.t0 + Duration::from_secs(700));
    assert!(
        fx.fake.wait_entered("db_activity", LIMIT),
        "the decision samples"
    );
    (fx, l, b)
}

#[test]
fn a_decision_made_before_a_holder_arrived_is_not_executed() {
    // Item 1 alone: the command recorded meanwhile is Gone too, so only `gen` stops the drop.
    let (fx, l, b) = decision_held("d9b");
    fx.procs.gone(CMD);
    assert_eq!(fx.s().set_holder(&l, holder(CMD)), Response::Ack);
    drop(b);
    fx.idle();
    assert_eq!(fx.drops(), 0);
    assert_eq!(disk_state(&fx, &l).as_deref(), Some("granted"));
}

#[test]
fn a_decision_rechecks_the_cli_right_before_acting() {
    // Item 2: the CLI is back (same start) while the decision samples.
    let (fx, l, b) = decision_held("d9c");
    fx.procs.alive(CLI);
    drop(b);
    fx.idle();
    assert_eq!(fx.drops(), 0);
    assert_eq!(disk_state(&fx, &l).as_deref(), Some("granted"));
}

#[test]
fn a_decision_rechecks_the_command_right_before_acting() {
    // Item 3: the decision waits behind a held release; the command comes back meanwhile.
    let fx = Fx::new("d9d");
    let l = fx.leased();
    assert_eq!(fx.s().set_holder(&l, holder(CMD)), Response::Ack);
    let other = fx.leased();
    fx.procs.gone(CLI);
    fx.procs.gone(CMD);
    let b = fx.fake.block("owned_databases");
    fx.s().release(&other);
    assert!(
        fx.fake.wait_entered("owned_databases", LIMIT),
        "worker held"
    );
    fx.s().tick(fx.t0 + Duration::from_secs(1));
    assert_eq!(fx.s().queued_items("decide"), 1);
    fx.procs.alive(CMD);
    drop(b);
    fx.idle();
    assert!(fx.fake.roles().contains_key(&l) && fx.fake.dbs().contains_key(&l));
    assert_eq!(disk_state(&fx, &l).as_deref(), Some("granted"));
}

#[test]
fn holder_messages_follow_the_state_table() {
    let fx = Fx::new("d10");
    let l = fx.leased();
    assert_eq!(fx.s().set_holder(&l, holder(CMD)), Response::Ack);
    assert_eq!(fx.s().set_holder(&l, holder(CMD)), Response::Ack);
    assert_eq!(
        error(fx.s().set_holder(&l, holder(21))),
        "holder already set"
    );
    let b = fx.fake.block("owned_databases");
    assert_eq!(fx.s().release(&l), Response::Ack);
    assert!(fx.fake.wait_entered("owned_databases", LIMIT));
    assert_eq!(error(fx.s().set_holder(&l, holder(CMD))), "unknown lease");
    assert_eq!(fx.s().release(&l), Response::Ack, "already releasing");
    drop(b);
    fx.idle();
    assert_eq!(error(fx.s().set_holder(&l, holder(CMD))), "unknown lease");
    assert_eq!(fx.s().release("fg_l_0000000000000bad"), Response::Ack);
}

// R19

#[test]
fn a_name_collision_with_a_live_lease_picks_another_name() {
    let fx = Fx::new("n1");
    let l1 = fx.leased();
    fx.rand.push(l1.strip_prefix("fg_l_").unwrap());
    let l2 = fx.leased();
    assert_ne!(l1, l2);
    let roles = fx.fake.roles();
    assert!(roles.contains_key(&l1) && roles.contains_key(&l2));
    let reg = fx.registry();
    assert!(reg.contains(&l1) && reg.contains(&l2));
}

#[test]
fn a_failed_create_never_drops_what_this_attempt_did_not_create() {
    let fx = Fx::new("n2");
    let warm = fx.leased();
    fx.s().release(&warm);
    fx.idle();
    let x = "fg_l_00000000000000ee";
    fx.fake.add_role(x, Some("feedfeedfeedfeed"));
    fx.fake.add_db(x, x);
    fx.fake.lie_name_taken();
    fx.rand.push("00000000000000ee");
    fx.rand.push("0123456789abcdef");
    let e = error(fx.lease_r(""));
    assert!(e.contains("already exists"), "{e}");
    fx.idle();
    assert_eq!(fx.fake.roles()[x].as_deref(), Some("feedfeedfeedfeed"));
    assert_eq!(fx.fake.dbs()[x], x);
    assert!(
        fx.fake
            .calls()
            .contains(&format!("sql drop_role {x} 0123456789abcdef"))
    );
    assert!(!fx.registry().contains(x));
}

#[test]
fn a_failed_rollback_stays_pending_retries_and_blocks_nobody() {
    let fx = Fx::new("n3");
    fx.fake.fail("drop_role", 2, "drop failed");
    let first = fx.lease_r("");
    let pw = password(&first);
    let l = leased(first);
    fx.s().release(&l);
    fx.idle();
    assert_eq!(fx.s().report()[0].cleanup_pending, 1);
    let notes = fx.s().take_notes();
    assert!(
        notes
            .iter()
            .any(|n| n.contains(&format!("postgres cleanup of {l} failed")))
    );
    assert!(notes.iter().all(|n| !n.contains(&pw)));
    fx.leased();
    fx.tick(2);
    assert!(fx.registry().contains(&l), "second failure");
    fx.tick(5);
    assert!(!fx.registry().contains(&l));
    assert_eq!(fx.s().report()[0].cleanup_pending, 0);
}

// R22, R24, R26

#[test]
fn a_lease_request_at_the_pending_cleanup_bound_fails_open_with_the_reason() {
    let fx = Fx::new("b1");
    fx.fake.fail("drop_role", ALWAYS, "drop failed");
    for _ in 0..MAX_PENDING_RELEASES {
        let l = fx.leased();
        fx.s().release(&l);
        fx.idle();
    }
    assert_eq!(fx.s().report()[0].cleanup_pending, 32);
    fx.s().take_notes();
    let e = error(fx.lease_r(""));
    assert!(e.contains("cleanups are pending"), "{e}");
    error(fx.lease_r(""));
    fx.idle();
    assert_eq!(fx.fake.count("create_role"), 32);
    let bound: Vec<_> = fx
        .s()
        .take_notes()
        .into_iter()
        .filter(|n| n.contains("cleanups are pending"))
        .collect();
    assert_eq!(bound.len(), 1);
    fx.fake.fail("drop_role", 0, "");
    fx.tick(100);
    assert_eq!(fx.s().report()[0].cleanup_pending, 0);
    fx.leased();
}

// R30

#[test]
fn eight_simultaneous_requests_all_get_a_database_and_the_ninth_fails_at_once() {
    let fx = Fx::new("q1");
    let warm = fx.leased();
    fx.s().release(&warm);
    fx.idle();
    let b = fx.fake.block("name_taken");
    let before = fx.fake.count("create_role");
    let mut rxs = Vec::new();
    for i in 0..8 {
        rxs.push(fx.lease_bg(holder(CLI), &format!("r{i}")));
        if i == 0 {
            assert!(fx.fake.wait_entered("name_taken", LIMIT));
        } else {
            fx.wait_queued(i);
        }
    }
    // Answered while the worker is still held: a ninth that waited would never get a reply.
    let e = error(fx.lease_r("r9"));
    assert_eq!(e, "all 8 postgres databases are in use");
    drop(b);
    let results: Vec<Response> = rxs.into_iter().map(reply).collect();
    let pws: HashSet<String> = results.iter().map(password).collect();
    let names: Vec<String> = results.into_iter().map(leased).collect();
    assert_eq!(pws.len(), 8);
    assert_eq!(names.iter().collect::<HashSet<_>>().len(), 8);
    let created: Vec<String> = fx
        .fake
        .calls()
        .into_iter()
        .filter(|c| c.starts_with("sql create_role"))
        .skip(before)
        .map(|c| c.split(' ').nth(2).unwrap().to_string())
        .collect();
    assert_eq!(created, names, "in order of arrival");
}

/// A running cluster with nothing leased.
fn warm(tag: &str) -> Fx {
    let fx = Fx::new(tag);
    let l = fx.leased();
    fx.s().release(&l);
    fx.idle();
    fx
}

#[test]
fn give_up_while_the_grant_is_queued_removes_it_and_creates_nothing() {
    let fx = warm("g1");
    let writes = fx.s().registry_writes().len();
    let b = fx.fake.block("name_taken");
    let a = fx.lease_bg(holder(CLI), "a");
    assert!(fx.fake.wait_entered("name_taken", LIMIT));
    let r = fx.lease_bg(holder(CLI), "R");
    fx.wait_queued(1);
    let mark = fx.fake.calls().len();
    assert_eq!(fx.s().give_up("R"), Response::Ack);
    // Answered while the worker is still held: the queued grant was taken out.
    assert_eq!(error(reply(r)), "request abandoned");
    drop(b);
    let la = leased(reply(a));
    fx.idle();
    // Every tool call after the give-up is a's; the catalogue holds a's role and database only.
    let after = fx.fake.calls().split_off(mark);
    assert!(
        !after.is_empty() && after.iter().all(|c| c.contains(&la)),
        "{after:?}"
    );
    assert_eq!(
        fx.fake.roles().into_keys().collect::<Vec<_>>(),
        std::slice::from_ref(&la)
    );
    // Nothing was ever written for R: every write since `warm` holds a's lease alone.
    let w = fx.s().registry_writes().split_off(writes);
    assert!(
        w.iter()
            .all(|x| x.starts_with(&format!("{la}=")) && !x.contains(';')),
        "{w:?}"
    );
    assert_eq!(fx.fake.dbs().into_keys().collect::<Vec<_>>(), [la]);
    assert_eq!(fx.registry().matches("\"lease\"").count(), 1);
}

#[test]
fn give_up_while_the_grant_is_in_progress_releases_it_when_the_steps_end() {
    let fx = warm("g2");
    let b = fx.fake.block("create_database");
    let r = fx.lease_bg(holder(CLI), "R");
    assert!(fx.fake.wait_entered("create_database", LIMIT));
    let reg = fx.registry();
    assert!(
        reg.contains("creating") && !reg.contains("granted"),
        "{reg}"
    );
    assert_eq!(fx.s().give_up("R"), Response::Ack);
    // Ruling P2: R leaving the bounded history does not revive its grant.
    for i in 0..ABANDONED_KEEP {
        assert_eq!(fx.s().give_up(&format!("other{i}")), Response::Ack);
    }
    let cleanup = fx.fake.block("owned_databases");
    drop(b);
    assert_eq!(error(reply(r)), "request abandoned");
    assert!(
        fx.fake.wait_entered("owned_databases", LIMIT),
        "given back by its mark"
    );
    let reg = fx.registry();
    assert!(
        reg.contains("releasing") && !reg.contains("granted"),
        "{reg}"
    );
    drop(cleanup);
    fx.idle();
    assert!(fx.fake.roles().is_empty() && fx.fake.dbs().is_empty());
    assert_eq!(fx.registry().matches("\"lease\"").count(), 0);
    // A request that was given up is never written as granted, not even for an instant.
    let w = fx.s().registry_writes();
    // `warm` leased and released once before R: R's row is the last one created.
    let last = w.iter().rev().find(|x| x.contains("=creating")).unwrap();
    let lease = last.split('=').next().unwrap().to_string();
    let at = |state: &str| {
        w.iter()
            .position(|x| x.contains(&format!("{lease}={state}")))
    };
    let (made, released) = (at("creating").unwrap(), at("releasing").unwrap());
    assert!(made < released, "{w:?}");
    assert!(at("granted").is_none(), "{w:?}");
    assert!(!w.last().unwrap().contains(&lease), "{w:?}");
}

#[test]
fn give_up_after_the_grant_completed_releases_it_by_the_normal_path() {
    let fx = Fx::new("g3");
    let l = leased(fx.lease_r("R"));
    assert_eq!(fx.s().give_up("R"), Response::Ack);
    fx.idle();
    assert!(!fx.fake.roles().contains_key(&l) && !fx.fake.dbs().contains_key(&l));
    assert!(!fx.registry().contains(&l));
    assert_eq!(fx.fake.count("db_activity"), 0, "rule D took no part");
    assert_eq!(fx.s().give_up("R"), Response::Ack);
    fx.idle();
    let l2 = leased(fx.lease_r("S"));
    assert_eq!(fx.s().set_holder(&l2, holder(CMD)), Response::Ack);
    assert_eq!(fx.s().give_up("S"), Response::Ack);
    fx.idle();
    assert!(fx.fake.roles().contains_key(&l2) && fx.fake.dbs().contains_key(&l2));
    assert_eq!(disk_state(&fx, &l2).as_deref(), Some("granted"));
}

#[test]
fn a_lease_request_that_arrives_after_its_give_up_is_refused() {
    let fx = Fx::new("g4");
    let calls = fx.fake.calls();
    assert_eq!(fx.s().give_up("R"), Response::Ack);
    assert_eq!(error(fx.lease_r("R")), "request abandoned");
    fx.idle();
    assert_eq!(fx.fake.calls(), calls, "no call to the tools");
    for i in 0..ABANDONED_KEEP {
        fx.s().give_up(&format!("x{i}"));
    }
    leased(fx.lease_r("R"));
}

#[test]
fn a_lost_give_up_is_cleaned_by_the_holder_rules() {
    let mut fx = Fx::new("g5");
    let l = leased(fx.lease_r("R"));
    fx.procs.gone(CLI);
    fx.tick(1);
    fx.tick(600);
    assert_eq!(fx.drops(), 0);
    fx.tick(601);
    assert!(!fx.fake.roles().contains_key(&l));
    let l2 = leased(fx.lease_r("S"));
    fx.open();
    fx.tick(1000);
    fx.tick(1599);
    assert!(fx.fake.roles().contains_key(&l2));
    fx.tick(1600);
    assert!(!fx.fake.roles().contains_key(&l2));
}

#[test]
fn grants_run_before_releases_and_samples() {
    let fx = Fx::new("o1");
    let (h1, h2) = (holder(11), holder(12));
    fx.procs.alive(11);
    fx.procs.alive(12);
    let l1 = leased(reply(fx.lease_bg(h1, "")));
    let l2 = leased(reply(fx.lease_bg(h2, "")));
    fx.procs.gone(11);
    let b = fx.fake.block("db_activity");
    fx.s().tick(fx.t0 + Duration::from_secs(1));
    assert!(fx.fake.wait_entered("db_activity", LIMIT), "worker busy");
    let mark = fx.fake.calls().len();
    fx.procs.gone(12);
    fx.s().tick(fx.t0 + Duration::from_secs(2)); // a sample for l2
    fx.s().release(&l1); // a release
    let g = fx.lease_bg(holder(CLI), ""); // a grant
    fx.wait_queued(1);
    drop(b);
    leased(reply(g));
    fx.idle();
    let after: Vec<String> = fx.fake.calls().split_off(mark);
    let at = |prefix: &str| after.iter().position(|c| c.starts_with(prefix)).unwrap();
    let grant = at("sql name_taken");
    let release = at(&format!("sql owned_databases {l1}"));
    let sample = at(&format!("sql db_activity {l2}"));
    assert!(grant < release && release < sample, "{after:?}");
}

#[test]
fn a_tick_never_queues_a_second_item_for_the_same_lease() {
    let fx = Fx::new("o2");
    fx.leased();
    fx.procs.gone(CLI);
    let b = fx.fake.block("db_activity");
    fx.s().tick(fx.t0 + Duration::from_secs(1));
    assert!(fx.fake.wait_entered("db_activity", LIMIT));
    for t in [100, 200, 300, 400] {
        fx.s().tick(fx.t0 + Duration::from_secs(t));
    }
    assert_eq!(fx.s().queued_items("sample"), 0, "one sample, running");
    assert_eq!(fx.s().queued_items("decide"), 1, "one decision, waiting");
    drop(b);
    fx.idle();
    assert_eq!(
        fx.fake.count("db_activity"),
        2,
        "one sample and one decision (which samples), not one per tick"
    );

    // A running decision.
    let mut fx = Fx::bare("o2c");
    fx.sample_every = Duration::from_secs(3600);
    fx.open();
    fx.leased();
    fx.procs.gone(CLI);
    fx.tick(1);
    let b = fx.fake.block("db_activity");
    fx.s().tick(fx.t0 + Duration::from_secs(30));
    assert!(
        fx.fake.wait_entered("db_activity", LIMIT),
        "the decision samples"
    );
    let before = fx.fake.count("db_activity");
    for t in [200, 300, 400, 500] {
        fx.s().tick(fx.t0 + Duration::from_secs(t));
    }
    assert_eq!(fx.s().queued_items("decide"), 0);
    drop(b);
    fx.idle();
    assert_eq!(fx.fake.count("db_activity"), before);

    // A running release: the queue itself, not the tool calls.
    let fx = Fx::new("o2b");
    let l = fx.leased();
    let b = fx.fake.block("owned_databases");
    fx.s().release(&l);
    assert!(fx.fake.wait_entered("owned_databases", LIMIT));
    for t in [1, 2, 3, 4, 5] {
        fx.s().tick(fx.t0 + Duration::from_secs(t));
    }
    assert_eq!(fx.s().queued_items("release"), 0);
    drop(b);
    fx.idle();
    assert_eq!(fx.fake.count("owned_databases"), 1);
}

#[test]
fn no_lease_is_granted_before_reconciliation_finished() {
    let mut fx = Fx::bare("o3");
    fx.lease_wait = Duration::from_millis(50);
    fx.open();
    let b = fx.fake.block("lease_roles");
    assert_eq!(error(fx.lease_r("")), "postgres is still starting");
    assert!(fx.fake.wait_entered("lease_roles", LIMIT));
    assert_eq!(fx.state(), "reconciling");
    // The worker is held on purpose: the "no grant" check comes after the barrier.
    let mark = fx.fake.calls().len();
    drop(b);
    fx.idle();
    let after = fx.fake.calls().split_off(mark);
    assert!(
        after.iter().all(|c| !c.contains("create_role")),
        "{after:?}"
    );
    assert_eq!(fx.state(), "running");
    fx.leased();
}

#[test]
fn a_failed_or_uncertain_session_sample_never_authorises_a_drop() {
    let fx = Fx::new("o4");
    fx.leased();
    fx.procs.gone(CLI);
    fx.fake.set_activity(Ok("0|3"));
    fx.tick(1);
    fx.fake.set_activity(Err("sample failed"));
    fx.tick(700);
    fx.fake.set_activity(Ok("garbage"));
    fx.tick(800);
    fx.fake.set_activity(Ok("0|-1"));
    fx.tick(900);
    assert_eq!(fx.drops(), 0);
    // The window kept its start (t = 1): one well-read, stable sample is enough now.
    fx.fake.set_activity(Ok("0|3"));
    fx.tick(1000);
    assert_eq!(fx.drops(), 1);
}

// R12 and the rest

#[test]
fn first_lease_starts_the_cluster_once() {
    let fx = Fx::new("s1");
    let (a, b) = (fx.leased(), fx.leased());
    assert_ne!(a, b);
    for (step, n) in [
        ("init", 1),
        ("start", 1),
        ("bootstrap", 1),
        ("create_role", 2),
    ] {
        assert_eq!(fx.fake.count(step), n, "{step}");
    }
}

#[test]
fn lease_reply_carries_the_env_contract() {
    let fx = Fx::new("s2");
    let Response::Leased {
        lease,
        env,
        template: None,
        ..
    } = fx.lease_r("")
    else {
        panic!()
    };
    assert_eq!(env["PGPORT"].expose(), "28543");
    assert_eq!(env["PGUSER"].expose(), lease);
    assert_eq!(env["PGDATABASE"].expose(), lease);
    let pw = env["PGPASSWORD"].expose();
    assert!(pw.len() == 32 && pw.bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(env["DATABASE_URL"].expose().contains(&lease));
}

#[test]
fn lease_is_on_disk_before_the_reply() {
    let fx = Fx::new("s3");
    let b = fx.fake.block("create_role");
    let r = fx.lease_bg(holder(CLI), "");
    assert!(fx.fake.wait_entered("create_role", LIMIT));
    let call = fx.fake.calls().into_iter().last().unwrap();
    let token = call.split(' ').nth(3).unwrap().to_string();
    let reg = fx.registry();
    assert!(reg.contains("creating") && reg.contains(&token), "{reg}");
    drop(b);
    leased(reply(r));
    assert!(fx.registry().contains("granted"));
}

#[test]
fn a_failed_registry_write_grants_nothing() {
    let fx = warm("s4");
    let leases = fx.root().join("leases.json");
    #[cfg(unix)]
    let _hold = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(fx.root(), std::fs::Permissions::from_mode(0o500)).unwrap();
        struct Restore(PathBuf);
        impl Drop for Restore {
            fn drop(&mut self) {
                let p = std::fs::Permissions::from_mode(0o700);
                let _ = std::fs::set_permissions(&self.0, p);
            }
        }
        Restore(fx.root())
    };
    #[cfg(windows)]
    let _hold = {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&leases)
            .unwrap()
    };
    let e = error(fx.lease_r(""));
    assert!(e.contains("cannot record the lease"), "{e}");
    fx.idle();
    assert_eq!(fx.fake.count("create_role"), 1, "only the warm-up");
    drop(_hold);
    let _ = leases;
}

#[test]
fn a_link_where_the_registry_is_written_disables_the_service() {
    // Ruling PF8: a `.tmp` sibling that is a link (or not a file) is never written through.
    let fx = warm("s4b");
    let tmp = fx.root().join("leases.json.tmp");
    #[cfg(unix)]
    std::os::unix::fs::symlink(fx.dir.join("elsewhere"), &tmp).unwrap();
    #[cfg(windows)]
    std::fs::create_dir(&tmp).unwrap();
    error(fx.lease_r(""));
    fx.idle();
    assert!(
        fx.state().starts_with("failed: link or unexpected file"),
        "{}",
        fx.state()
    );
    assert!(error(fx.lease_r("")).starts_with("postgres failed: link"));
    assert_eq!(fx.fake.count("create_role"), 1, "only the warm-up");
    assert!(!fx.dir.join("elsewhere").exists());
}

#[cfg(windows)]
#[test]
fn a_junction_where_the_registry_is_written_disables_the_service() {
    // Ruling PF8 with a real reparse point: a junction made by `mklink /J`.
    let fx = warm("s4c");
    let elsewhere = fx.dir.join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    let tmp = fx.root().join("leases.json.tmp");
    let out = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(&tmp)
        .arg(&elsewhere)
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    error(fx.lease_r(""));
    fx.idle();
    assert!(
        fx.state().starts_with("failed: link or unexpected file"),
        "{}",
        fx.state()
    );
    assert_eq!(fx.fake.count("create_role"), 1, "only the warm-up");
    assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
}

/// C5d: a lease registry others can change disables the service with the reason, and is left as
/// it was.
#[test]
fn a_registry_others_can_change_disables_the_service() {
    let fx = warm("s4d");
    let leases = fx.root().join("leases.json");
    let before = std::fs::read(&leases).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&leases, std::fs::Permissions::from_mode(0o666)).unwrap();
    }
    #[cfg(windows)]
    {
        let out = std::process::Command::new("icacls")
            .arg(&leases)
            .args(["/grant", "*S-1-1-0:(W)"])
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
    }
    error(fx.lease_r(""));
    fx.idle();
    assert!(fx.state().starts_with("failed:"), "{}", fx.state());
    assert!(
        fx.state().contains("writable by other users"),
        "{}",
        fx.state()
    );
    assert_eq!(std::fs::read(&leases).unwrap(), before);
}

/// 14.3, Windows: a registry another program holds open (an error of the system, not a refusal)
/// fails that write only; the service stays on and writes once it is closed.
#[cfg(windows)]
#[test]
fn a_registry_held_open_does_not_disable_the_service() {
    use std::os::windows::fs::OpenOptionsExt;
    let fx = warm("s4e");
    let leases = fx.root().join("leases.json");
    let held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&leases)
        .unwrap();
    let _ = fx.lease_r("");
    fx.idle();
    assert!(!fx.state().starts_with("failed:"), "{}", fx.state());
    drop(held);
    fx.tick(5);
    fx.leased();
    assert!(!fx.state().starts_with("failed:"), "{}", fx.state());
}

#[test]
fn crash_between_any_two_steps_is_reconciled() {
    let mut fx = Fx::bare("s5");
    let (a, b, c, d, e) = (
        "fg_l_000000000000000a",
        "fg_l_000000000000000b",
        "fg_l_000000000000000c",
        "fg_l_000000000000000d",
        "fg_l_000000000000000e",
    );
    let rows = [
        row(a, "aa", "creating", 31, None),
        row(b, "bb", "creating", 31, None),
        row(c, "cc", "releasing", 31, None),
        row(d, "dd", "granted", 31, Some(32)),
        row(e, "ee", "granted", 33, None),
    ];
    seed(&fx, &rows.join(","), SERVER);
    for (l, t) in [(b, "bb"), (c, "cc"), (d, "dd"), (e, "ee")] {
        fx.fake.add_role(l, Some(t));
        fx.fake.add_db(l, l);
    }
    fx.procs.gone(31);
    fx.procs.gone(32);
    fx.procs.alive(33);
    fx.open();
    fx.tick(1);
    let roles: Vec<String> = fx.fake.roles().into_keys().collect();
    let dbs: Vec<String> = fx.fake.dbs().into_keys().collect();
    assert_eq!(roles, [e]);
    assert_eq!(dbs, [e]);
    let reg = fx.registry();
    assert!(
        reg.contains(e) && [a, b, c, d].iter().all(|l| !reg.contains(l)),
        "{reg}"
    );
}

#[test]
fn unreadable_or_missing_registry_disables_leftover_cleanup() {
    for garbage in [Some("not json"), None] {
        let mut fx = Fx::bare("s6");
        seed(&fx, "", SERVER);
        if let Some(g) = garbage {
            std::fs::write(fx.root().join("leases.json"), g).unwrap();
        }
        let x = "fg_l_00000000000000aa";
        fx.fake.add_role(x, Some("abab"));
        fx.open();
        fx.tick(1);
        assert!(fx.fake.roles().contains_key(x), "{garbage:?}");
        assert_eq!(fx.drops(), 0);
        assert_eq!(fx.fake.count("lease_roles"), 0);
        let notes = fx.s().take_notes();
        assert!(
            notes.iter().any(|n| n.contains("registry was unreadable")),
            "{notes:?}"
        );
        assert_eq!(
            fx.root().join("leases.json.unreadable").exists(),
            garbage.is_some()
        );
        assert!(fx.registry().contains(r#""unknown_before": true"#));
        // Still unknown for the next daemon.
        fx.open();
        fx.tick(2);
        assert!(fx.fake.roles().contains_key(x));
    }
}

const LEASES_KNOWN: &str = r#"{"version":1,"unknown_before":false,"leases":[]}"#;

fn tpl_json(version: u32, next_seq: u64, rows: &[String]) -> String {
    format!(
        r#"{{"version":{version},"unknown_before":false,"next_seq":{next_seq},"templates":[{}]}}"#,
        rows.join(",")
    )
}

#[allow(clippy::too_many_arguments)]
fn tpl_row(
    key: &str,
    project: &Path,
    state: &str,
    lease: &str,
    token: &str,
    db_oid: u32,
    role_oid: u32,
    seq: u64,
) -> String {
    serde_json::json!({
        "key": key, "project": project, "state": state, "lease": lease, "token": token,
        "db_oid": db_oid, "role_oid": role_oid, "seq": seq,
    })
    .to_string()
}

/// `templates.json` with these rows, `next_seq` past the highest `seq`.
fn seed_templates(fx: &Fx, rows: &[String]) {
    let seq = |r: &String| serde_json::from_str::<serde_json::Value>(r).unwrap()["seq"].as_u64();
    let next = rows.iter().filter_map(seq).max().unwrap_or(0) + 1;
    let text = tpl_json(1, next, rows);
    std::fs::write(fx.root().join("templates.json"), text).unwrap();
}

/// The row of `key` in `templates.json`.
fn tpl(fx: &Fx, key: &str) -> Option<serde_json::Value> {
    let v: serde_json::Value = serde_json::from_str(&fx.templates()).ok()?;
    v["templates"]
        .as_array()?
        .iter()
        .find(|r| r["key"] == key)
        .cloned()
}

fn tpl_state(fx: &Fx, key: &str) -> Option<String> {
    tpl(fx, key)?["state"].as_str().map(Into::into)
}

#[test]
fn parse_templates_accepts_only_what_it_wrote() {
    let (k1, k2) = ("0123456789abcdef", "fedcba9876543210");
    let (l, p) = ("fg_l_00000000000000aa", Path::new("p"));
    let tpl_row = |k: &str, st: &str, l: &str, token: &str, oid: u32, seq: u64| {
        tpl_row(k, p, st, l, token, oid, oid, seq)
    };
    let ok = |k: &str, st: &str, seq: u64| tpl_row(k, st, l, "abab", 5, seq);
    assert!(parse_templates(pg_tools::TEMPLATES_EMPTY.as_bytes()).is_some());
    let three = [
        ok(k1, "preparing", 1),
        ok(k2, "ready", 2),
        ok("0000000000000001", "failed", 3),
    ];
    assert!(parse_templates(tpl_json(1, 4, &three).as_bytes()).is_some());
    let many: Vec<String> = (0..1025u64)
        .map(|i| ok(&format!("{i:016x}"), "ready", 1))
        .collect();
    let bad: Vec<(&str, String)> = vec![
        ("version", tpl_json(2, 4, &three[..1])),
        ("key", tpl_json(1, 4, &[ok("XYZ", "ready", 1)])),
        (
            "lease",
            tpl_json(1, 4, &[tpl_row(k1, "ready", "bad", "abab", 5, 1)]),
        ),
        (
            "token",
            tpl_json(1, 4, &[tpl_row(k1, "ready", l, "zz", 5, 1)]),
        ),
        (
            "oid",
            tpl_json(1, 4, &[tpl_row(k1, "ready", l, "abab", 0, 1)]),
        ),
        ("seq equal", tpl_json(1, 1, &[ok(k1, "ready", 1)])),
        ("seq above", tpl_json(1, 1, &[ok(k1, "ready", 9)])),
        (
            "repeated key",
            tpl_json(1, 4, &[ok(k1, "ready", 1), ok(k1, "failed", 2)]),
        ),
        ("too many", tpl_json(1, 4, &many)),
        ("truncated", tpl_json(1, 4, &three)[..40].to_string()),
    ];
    for (what, text) in bad {
        assert!(parse_templates(text.as_bytes()).is_none(), "{what}");
    }
}

fn template_notes(fx: &Fx) -> usize {
    fx.s()
        .take_notes()
        .iter()
        .filter(|n| n.contains(TEMPLATES_UNREADABLE))
        .count()
}

#[test]
fn missing_template_state_never_authorises_a_migration() {
    let mut fx = Fx::bare("t1");
    seed(&fx, "", SERVER);
    // A known, empty lease registry: only the templates are missing.
    std::fs::write(fx.root().join("leases.json"), LEASES_KNOWN).unwrap();
    fx.open();
    fx.tick(1);
    assert!(fx.templates().contains(r#""unknown_before": true"#));
    assert_eq!(template_notes(&fx), 1);
    // The lease registry stays known: the two states are independent.
    assert!(fx.registry().contains(r#""unknown_before": false"#));
}

#[test]
fn corrupt_template_state_survives_a_restart_as_unknown() {
    let mut fx = Fx::bare("t2");
    seed(&fx, "", SERVER);
    // A known, empty lease registry: only the templates are missing.
    std::fs::write(fx.root().join("leases.json"), LEASES_KNOWN).unwrap();
    std::fs::write(fx.root().join("templates.json"), "not json").unwrap();
    fx.open();
    fx.tick(1);
    assert!(fx.root().join("templates.json.unreadable").exists());
    assert!(fx.templates().contains(r#""unknown_before": true"#));
    assert_eq!(template_notes(&fx), 1);
    fx.open();
    fx.tick(2);
    assert!(fx.templates().contains(r#""unknown_before": true"#));
    assert_eq!(template_notes(&fx), 0, "the note is written once");
    assert_eq!(fx.tpl_flags(), (true, true));
}

#[test]
fn a_failed_template_recovery_never_stops_the_leases() {
    // The rename and the marked write both fail: templates stay off, leases go on.
    let mut fx = Fx::bare("t4");
    fx.tpl_fail = 2;
    seed(&fx, "", SERVER);
    std::fs::write(fx.root().join("leases.json"), LEASES_KNOWN).unwrap();
    std::fs::write(fx.root().join("templates.json"), "not json").unwrap();
    fx.open();
    fx.tick(1);
    assert_eq!(fx.tpl_flags(), (true, true));
    assert!(!fx.state().starts_with("failed"), "{}", fx.state());
    let notes = fx.s().take_notes();
    assert!(
        notes
            .iter()
            .any(|n| n.contains("cannot write the template")),
        "{notes:?}"
    );
    fx.leased();
}

#[test]
fn a_new_cluster_starts_with_known_empty_templates() {
    let mut fx = Fx::new("t3");
    fx.leased();
    fx.idle();
    assert_eq!(fx.templates(), pg_tools::TEMPLATES_EMPTY);
    let d = parse_templates(pg_tools::TEMPLATES_EMPTY.as_bytes()).unwrap();
    assert_eq!((d.next_seq, d.unknown_before), (1, false));
    fx.open();
    fx.tick(1);
    assert_eq!(fx.templates(), pg_tools::TEMPLATES_EMPTY);
    assert_eq!(template_notes(&fx), 0);
}

const K1: &str = "00000000000000a1";
const K2: &str = "00000000000000a2";
const K3: &str = "00000000000000a3";

#[test]
fn a_new_key_prepares_a_candidate_and_records_it_first() {
    let fx = Fx::migrating("k1");
    let cand = prepared(fx.keyed(K1));
    let t = tpl(&fx, K1).expect("the key is recorded");
    assert_eq!(t["state"], "preparing");
    assert_eq!(t["lease"], cand.as_str());
    assert_eq!(t["db_oid"], fx.fake.oid_of_db(&cand).unwrap());
    assert_eq!(t["role_oid"], fx.fake.oid_of_role(&cand).unwrap());
    assert_eq!(disk_state(&fx, &cand).as_deref(), Some("granted"));
}

#[test]
fn a_candidate_is_not_authorised_when_the_record_cannot_be_written() {
    // Ruling PF-A: an injected write failure; a folder at the path would disable the service.
    let fx = Fx::migrating("k2");
    fx.fail_template_writes(1);
    let e = error(fx.keyed(K1));
    assert!(e.contains("cannot record the template"), "{e}");
    fx.idle();
    assert_eq!(fx.fake.count("candidate_oids"), 1);
    assert!(fx.fake.roles().is_empty() && fx.fake.dbs().is_empty());
    assert!(tpl(&fx, K1).is_none(), "{}", fx.templates());
    assert!(!fx.registry().contains("fg_l_"), "{}", fx.registry());
}

#[test]
fn two_concurrent_requests_for_a_new_key_migrate_once() {
    let fx = Fx::migrating("k3");
    let b = fx.fake.block("create_role");
    let first = fx.keyed_bg(K1);
    assert!(fx.fake.wait_entered("create_role", LIMIT));
    // Admitted while the first has no record yet: the worker decides again.
    let second = fx.keyed_bg(K1);
    fx.wait_queued(1);
    drop(b);
    prepared(reply(first));
    let e = error(reply(second));
    assert!(e.contains("a migration for this project is running"), "{e}");
    fx.idle();
    assert_eq!(fx.fake.count("create_role"), 1);
}

#[test]
fn a_failed_key_is_not_migrated_again() {
    let fx = Fx::migrating("k4");
    let cand = prepared(fx.keyed(K1));
    assert_eq!(fx.ready(&cand, false), Response::Ack);
    assert_eq!(tpl_state(&fx, K1).as_deref(), Some("failed"));
    let e = error(fx.keyed(K1));
    assert!(e.contains("failed before"), "{e}");
    fx.idle();
    assert_eq!(fx.fake.count("create_role"), 1);
}

#[test]
fn an_interrupted_migration_frees_the_key() {
    let fx = Fx::migrating("k4i");
    let cand = prepared(fx.keyed(K1));
    assert_eq!(fx.s().template_ready(&cand, false, true), Response::Ack);
    assert!(tpl(&fx, K1).is_none(), "{}", fx.templates());
    let again = prepared(fx.keyed(K1));
    assert_ne!(again, cand);
}

#[test]
fn a_contradictory_report_is_refused() {
    let fx = Fx::migrating("k4c");
    let cand = prepared(fx.keyed(K1));
    let e = error(fx.s().template_ready(&cand, true, true));
    assert!(e.contains("bad template report"), "{e}");
    assert_eq!(tpl_state(&fx, K1).as_deref(), Some("preparing"));
}

#[test]
fn a_ready_key_grants_a_clone() {
    let fx = Fx::migrating("k5");
    let cand = prepared(fx.keyed(K1));
    assert_eq!(fx.ready(&cand, true), Response::Ack);
    let (tdb, town) = (format!("fg_t_{K1}"), format!("fg_o_{K1}"));
    assert_eq!(
        fx.fake.owner_roles(),
        BTreeMap::from([(town, K1.to_string())])
    );
    assert_eq!(fx.fake.db_owner(&tdb).as_deref(), Some("sync_gate"));
    assert_eq!(disk_state(&fx, &cand), None, "{}", fx.registry());
    assert_eq!(tpl_state(&fx, K1).as_deref(), Some("ready"));
    let created = fx.fake.count("create_database");
    match fx.keyed(K1) {
        Response::Leased {
            lease, template, ..
        } => {
            assert_eq!(template.as_deref(), Some(K1));
            assert_eq!(fx.fake.db_owner(&lease), Some(lease.clone()));
        }
        other => panic!("not leased: {other:?}"),
    }
    assert_eq!(fx.fake.count("create_database"), created);
    assert_eq!(fx.fake.count("create_database_from"), 1);
    assert_eq!(fx.fake.count("clone_adopt"), 1);
}

#[test]
fn promotion_is_refused_when_the_check_fails() {
    let fx = Fx::migrating("k6");
    let cand = prepared(fx.keyed(K1));
    fx.fake.set_template_check(Ok("f"));
    let e = error(fx.ready(&cand, true));
    assert!(e.contains("grants to another role"), "{e}");
    fx.idle();
    assert_eq!(tpl_state(&fx, K1).as_deref(), Some("failed"));
    assert!(fx.fake.roles().is_empty() && fx.fake.dbs().is_empty());
}

#[test]
fn promotion_fails_when_a_session_does_not_end() {
    let fx = Fx::migrating("k7");
    let cand = prepared(fx.keyed(K1));
    fx.fake.set_terminated(false);
    error(fx.ready(&cand, true));
    fx.idle();
    assert_eq!(tpl_state(&fx, K1).as_deref(), Some("failed"));
    assert_eq!(fx.fake.count("template_own"), 0);
}

#[test]
fn a_promotion_in_progress_refuses_every_other_report() {
    let fx = Fx::migrating("k12");
    let cand = prepared(fx.keyed(K1));
    let b = fx.fake.block("template_seal");
    let first = fx.ready_bg(&cand, true);
    assert!(fx.fake.wait_entered("template_seal", LIMIT));
    for ok in [false, true] {
        let e = error(fx.ready(&cand, ok));
        assert!(
            e.contains("a promotion of this template is in progress"),
            "{ok}: {e}"
        );
        assert_eq!(tpl_state(&fx, K1).as_deref(), Some("preparing"));
    }
    drop(b);
    assert_eq!(reply(first), Response::Ack);
    assert_eq!(tpl_state(&fx, K1).as_deref(), Some("ready"));
    assert_eq!(fx.fake.count("template_seal"), 1);
    // Finished: the mark is gone, and the key is no longer preparing.
    assert_eq!(error(fx.ready(&cand, false)), "unknown template");
}

#[test]
fn a_promotion_never_overwrites_a_row_that_left_preparing() {
    let fx = Fx::migrating("k13");
    let cand = prepared(fx.keyed(K1));
    let b = fx.fake.block("template_seal");
    let first = fx.ready_bg(&cand, true);
    assert!(fx.fake.wait_entered("template_seal", LIMIT));
    // No report can do this any more; the promotion checks again anyway.
    match &fx.s().mode {
        Mode::On(inner) => inner.lock().set_tpl(K1, TplState::Failed),
        _ => panic!("service is off"),
    }
    drop(b);
    let e = error(reply(first));
    assert!(e.contains("no longer preparing"), "{e}");
    fx.idle();
    let st = match &fx.s().mode {
        Mode::On(inner) => inner.lock().templates[0].state,
        _ => panic!("service is off"),
    };
    assert_eq!(st, TplState::Failed);
    assert_eq!(
        tpl_state(&fx, K1).as_deref(),
        Some("preparing"),
        "never ready"
    );
}

#[test]
fn a_preexisting_template_name_is_never_touched() {
    let fx = Fx::migrating("k8");
    let (tdb, town) = (format!("fg_t_{K1}"), format!("fg_o_{K1}"));
    fx.fake.add_db(&tdb, "sync_gate");
    fx.fake.add_role(&town, None);
    let cand = prepared(fx.keyed(K1));
    let e = error(fx.ready(&cand, true));
    assert!(e.contains("already taken"), "{e}");
    fx.idle();
    assert_eq!(tpl_state(&fx, K1).as_deref(), Some("failed"));
    assert_eq!(fx.fake.count("template_seal"), 0);
    assert_eq!(fx.fake.dbs(), BTreeMap::from([(tdb, "sync_gate".into())]));
    assert_eq!(fx.fake.roles(), BTreeMap::from([(town, None)]));
}

#[test]
fn the_key_must_match_the_project_and_the_configuration() {
    let mut fx = Fx::migrating("k9");
    seed(&fx, "", SERVER);
    std::fs::write(fx.root().join("leases.json"), LEASES_KNOWN).unwrap();
    let elsewhere = fx.dir.join("elsewhere");
    let row = tpl_row(
        K2,
        &elsewhere,
        "ready",
        "fg_l_00000000000000b2",
        "abab",
        7,
        8,
        1,
    );
    seed_templates(&fx, &[row]);
    fx.open();
    let plain = fx.plain();
    for (proj, key, why) in [
        (&fx.proj, Some(K2), "belongs to another project"),
        (&fx.proj, None, "disagree about migrate"),
        (&plain, Some(K1), "disagree about migrate"),
        (&fx.proj, Some("zz"), "bad template key"),
    ] {
        let e = error(reply(fx.lease_in(proj, holder(CLI), "", key)));
        assert!(e.contains(why), "{key:?}: {e}");
    }
    fx.idle();
    assert_eq!(fx.fake.count("create_role"), 0);
}

#[test]
fn a_full_template_registry_creates_nothing() {
    let mut fx = Fx::migrating("k11");
    seed(&fx, "", SERVER);
    std::fs::write(fx.root().join("leases.json"), LEASES_KNOWN).unwrap();
    // One failure in each of as many other projects: nothing prunes or retires them.
    let rows: Vec<String> = (0..MAX_TEMPLATE_ROWS as u64)
        .map(|i| {
            let n = format!("{:016x}", 0x1000 + i);
            let (lease, other) = (format!("fg_l_{n}"), fx.dir.join(&n));
            tpl_row(&n, &other, "failed", &lease, "abab", 7, 8, i + 1)
        })
        .collect();
    seed_templates(&fx, &rows);
    fx.open();
    let e = error(fx.keyed(K1));
    assert!(e.contains("the template registry is full"), "{e}");
    fx.idle();
    assert_eq!(fx.fake.count("create_role"), 0);
    assert!(tpl(&fx, K1).is_none());
}

#[test]
fn an_unknown_template_registry_refuses_keys_and_keeps_empty_leases() {
    let mut fx = Fx::migrating("k10");
    seed(&fx, "", SERVER);
    // A known lease registry and no template registry: templates unknown.
    std::fs::write(fx.root().join("leases.json"), LEASES_KNOWN).unwrap();
    fx.open();
    assert_eq!(fx.tpl_flags(), (true, true));
    let e = error(fx.keyed(K1));
    assert!(e.contains("template registry is unknown"), "{e}");
    match reply(fx.lease_in(&fx.plain(), holder(CLI), "", None)) {
        Response::Leased { template: None, .. } => {}
        other => panic!("not leased: {other:?}"),
    }
    fx.idle();
    assert_eq!(fx.fake.count("create_role"), 1);
    assert_eq!(fx.fake.count("db_by_oid"), 0);
    assert_eq!(fx.fake.count("drop_template_role"), 0);

    // Rows of a registry marked unknown are never acted on: no retire, no candidate exit by
    // template; the lease itself still goes back by its mark.
    let mut fx = Fx::migrating("k10b");
    let (l, t) = ("fg_l_00000000000000c3", "c3");
    seed(&fx, &row(l, t, "granted", 31, Some(32)), SERVER);
    fx.procs.gone(31);
    fx.procs.gone(32);
    fx.fake.add_role(l, Some(t));
    fx.fake.add_db(l, l);
    let (db, role) = (
        fx.fake.oid_of_db(l).unwrap(),
        fx.fake.oid_of_role(l).unwrap(),
    );
    let (b1, b2) = ("fg_l_00000000000000b1", "fg_l_00000000000000b2");
    let rows = [
        tpl_row(K1, &fx.proj, "ready", b1, "b1", 7, 8, 1),
        tpl_row(K2, &fx.proj, "ready", b2, "b2", 9, 10, 2),
        tpl_row(K3, &fx.proj, "preparing", l, t, db, role, 3),
    ];
    let unknown =
        tpl_json(1, 4, &rows).replace(r#""unknown_before":false"#, r#""unknown_before":true"#);
    std::fs::write(fx.root().join("templates.json"), unknown).unwrap();
    fx.open();
    fx.tick(1);
    assert_eq!(fx.tpl_flags(), (true, true));
    assert!(fx.fake.roles().is_empty() && fx.fake.dbs().is_empty());
    assert_eq!(disk_state(&fx, l), None);
    for step in ["template_state", "db_by_oid", "drop_template_role"] {
        assert_eq!(fx.fake.count(step), 0, "{step}");
    }
}

/// `script` run on the fake's catalogue, the way the daemon runs it.
fn apply(fx: &Fx, script: Result<String, SqlError>) {
    let c = ClusterPaths::new(&fx.pg.bin_dir, &fx.root(), fx.pg.port);
    fx.fake.sql(&c, &script.unwrap(), &[]).unwrap();
}

/// Neither a database nor a role is left in the fake.
fn catalogue_empty(fx: &Fx) -> bool {
    fx.fake.roles().is_empty() && fx.fake.dbs().is_empty()
}

/// The fake holds the template of `key`: its database the administrator's, its role marked.
fn holds_template(fx: &Fx, key: &str) -> bool {
    let (db, owner) = (format!("fg_t_{key}"), format!("fg_o_{key}"));
    fx.fake.db_owner(&db).as_deref() == Some("sync_gate")
        && fx.fake.owner_roles().get(&owner).map(String::as_str) == Some(key)
}

#[test]
fn cli_death_after_prepare_is_handled_without_a_restart() {
    // No `migrate` recorded: rule D's quiet grace, then the key is forgotten.
    let fx = Fx::migrating("x1");
    let cand = prepared(fx.keyed(K1));
    fx.procs.gone(CLI);
    fx.tick(1);
    fx.tick(600);
    assert!(fx.fake.roles().contains_key(&cand), "inside the grace");
    fx.tick(601);
    assert!(catalogue_empty(&fx));
    assert_eq!(tpl(&fx, K1), None, "{}", fx.templates());
    assert_eq!(disk_state(&fx, &cand), None);
    fx.procs.alive(CLI);
    prepared(fx.keyed(K1));

    // The `migrate` recorded: both gone, the key failed.
    let fx = Fx::migrating("x2");
    let cand = prepared(fx.keyed(K1));
    assert_eq!(fx.s().set_holder(&cand, holder(CMD)), Response::Ack);
    fx.procs.gone(CLI);
    fx.procs.gone(CMD);
    fx.tick(1);
    assert!(catalogue_empty(&fx));
    assert_eq!(tpl_state(&fx, K1).as_deref(), Some("failed"));
    assert_eq!(disk_state(&fx, &cand), None);
}

#[test]
fn a_candidate_given_up_before_any_migration_frees_the_key() {
    let fx = Fx::migrating("x3");
    let cand = prepared(reply(fx.lease_in(&fx.proj, holder(CLI), "R", Some(K1))));
    assert_eq!(fx.s().give_up("R"), Response::Ack);
    fx.idle();
    assert!(catalogue_empty(&fx));
    assert_eq!(tpl(&fx, K1), None, "{}", fx.templates());
    assert_eq!(disk_state(&fx, &cand), None);
    prepared(fx.keyed(K1));
}

#[test]
fn promotion_crash_between_steps_reconciles() {
    let (l, token) = ("fg_l_00000000000000c1", "c1");
    // (a) nothing, (b) sealed, (c) the database the administrator's, (d) the role renamed,
    // (e) both renamed, still `preparing`, (f) `ready` recorded, the lease row still there.
    for (n, name) in ["a", "b", "c", "d", "e", "f"].into_iter().enumerate() {
        let mut fx = Fx::migrating(&format!("pc{name}"));
        seed(&fx, &row(l, token, "granted", 31, Some(32)), SERVER);
        fx.procs.gone(31);
        fx.procs.gone(32);
        fx.fake.add_role(l, Some(token));
        fx.fake.add_db(l, l);
        let (db, role) = (
            fx.fake.oid_of_db(l).unwrap(),
            fx.fake.oid_of_role(l).unwrap(),
        );
        let steps = [
            template_seal(l, token),
            template_own(l),
            template_rename_role(l, token, K1),
            template_rename_db(l, K1),
        ];
        for s in steps.into_iter().take(n) {
            apply(&fx, s);
        }
        let state = if name == "f" { "ready" } else { "preparing" };
        seed_templates(&fx, &[tpl_row(K1, &fx.proj, state, l, token, db, role, 1)]);
        fx.open();
        fx.tick(1);
        assert_eq!(disk_state(&fx, l), None, "{name}: {}", fx.registry());
        if n < 4 {
            assert_eq!(tpl_state(&fx, K1).as_deref(), Some("failed"), "{name}");
            let (roles, dbs) = (fx.fake.roles(), fx.fake.dbs());
            assert!(catalogue_empty(&fx), "{name}: {roles:?} {dbs:?}");
        } else {
            assert_eq!(tpl_state(&fx, K1).as_deref(), Some("ready"), "{name}");
            assert!(holds_template(&fx, K1), "{name}");
            for step in ["drop_database", "drop_template_role", "drop_role"] {
                assert_eq!(fx.fake.count(step), 0, "{name}: {step}");
            }
        }
    }
}

#[test]
fn a_promotion_failing_after_its_owner_change_drops_the_candidate_by_identity() {
    // S3 gave the database to the administrator; the lease's own path cannot find it.
    for (tag, step) in [
        ("pf4a", "template_rename_role"),
        ("pf4b", "template_rename_db"),
    ] {
        let fx = Fx::migrating(tag);
        let cand = prepared(fx.keyed(K1));
        fx.fake.fail(step, 1, "ERROR:  injected");
        error(fx.ready(&cand, true));
        fx.idle();
        assert_eq!(tpl_state(&fx, K1).as_deref(), Some("failed"), "{step}");
        let (roles, dbs) = (fx.fake.roles(), fx.fake.dbs());
        assert!(catalogue_empty(&fx), "{step}: {roles:?} {dbs:?}");
        assert_eq!(disk_state(&fx, &cand), None, "{step}");
    }
}

#[test]
fn a_template_written_but_not_recorded_is_never_dropped() {
    // M1: S5a's write fails; the candidate's exit finds the complete template and records it.
    let fx = Fx::migrating("m1");
    promoted(&fx, K2);
    let cand = prepared(fx.keyed(K1));
    assert_eq!(fx.s().set_holder(&cand, holder(CMD)), Response::Ack);
    fx.fail_template_writes(1);
    let e = error(fx.ready(&cand, true));
    assert!(e.contains("cannot record the template"), "{e}");
    assert_eq!(tpl_state(&fx, K1).as_deref(), Some("preparing"));
    fx.procs.gone(CLI);
    fx.procs.gone(CMD);
    fx.tick(1);
    assert_eq!(disk_state(&fx, &cand), None, "{}", fx.registry());
    assert!(holds_template(&fx, K1));
    assert_eq!(tpl_state(&fx, K1).as_deref(), Some("ready"));
    // K1 is now the project's newest template: the next tick retires K2.
    fx.tick(2);
    assert_eq!(tpl(&fx, K2), None, "{}", fx.templates());
    assert!(holds_template(&fx, K1) && !holds_template(&fx, K2));
}

#[test]
fn a_lease_row_left_after_s5b_is_removed_without_dropping() {
    // M1: S5b's write fails; rule D, or the next daemon, removes the row and drops nothing.
    for restart in [false, true] {
        let mut fx = Fx::migrating(if restart { "m2b" } else { "m2a" });
        let cand = prepared(fx.keyed(K1));
        assert_eq!(fx.s().set_holder(&cand, holder(CMD)), Response::Ack);
        fx.fail_lease_writes(1);
        assert_eq!(fx.ready(&cand, true), Response::Ack);
        assert_eq!(tpl_state(&fx, K1).as_deref(), Some("ready"));
        assert_eq!(disk_state(&fx, &cand).as_deref(), Some("granted"));
        if restart {
            fx.open();
        } else {
            fx.procs.gone(CLI);
            fx.procs.gone(CMD);
            fx.tick(1);
        }
        assert_eq!(disk_state(&fx, &cand), None, "{restart}: {}", fx.registry());
        assert!(holds_template(&fx, K1), "{restart}");
        for step in ["drop_database", "drop_template_role", "drop_role"] {
            assert_eq!(fx.fake.count(step), 0, "{restart}: {step}");
        }
        fx.procs.alive(CLI);
        match fx.keyed(K1) {
            Response::Leased { template, .. } => assert_eq!(template.as_deref(), Some(K1)),
            other => panic!("{restart}: not leased: {other:?}"),
        }
    }
}

#[test]
fn restart_during_a_live_migration_keeps_the_candidate() {
    let mut fx = Fx::migrating("r1");
    let cand = prepared(fx.keyed(K1));
    assert_eq!(fx.s().set_holder(&cand, holder(CMD)), Response::Ack);
    fx.procs.gone(CLI);
    fx.open();
    fx.tick(1);
    assert_eq!(tpl_state(&fx, K1).as_deref(), Some("failed"));
    assert!(fx.fake.roles().contains_key(&cand) && fx.fake.dbs().contains_key(&cand));
    assert_eq!(disk_state(&fx, &cand).as_deref(), Some("granted"));
}

#[test]
fn restart_after_the_migration_deadline_drops_the_candidate_when_the_process_is_gone() {
    let mut fx = Fx::migrating("r2");
    let cand = prepared(fx.keyed(K1));
    assert_eq!(fx.s().set_holder(&cand, holder(CMD)), Response::Ack);
    fx.procs.gone(CLI);
    fx.procs.gone(CMD);
    fx.open();
    fx.tick(1);
    assert_eq!(tpl_state(&fx, K1).as_deref(), Some("failed"));
    assert!(catalogue_empty(&fx));
    assert_eq!(disk_state(&fx, &cand), None);
}

/// A candidate of `key` promoted to its template.
fn promoted(fx: &Fx, key: &str) {
    let cand = prepared(fx.keyed(key));
    assert_eq!(fx.ready(&cand, true), Response::Ack);
}

#[test]
fn a_new_key_replaces_the_projects_template_and_live_clones_survive() {
    let fx = Fx::migrating("n1");
    promoted(&fx, K1);
    let (c1, c2) = (leased(fx.keyed(K1)), leased(fx.keyed(K1)));
    assert_eq!(fx.s().release(&c1), Response::Ack);
    fx.idle();
    assert!(holds_template(&fx, K1));
    let dbs = fx.fake.dbs();
    assert!(dbs.contains_key(&c2) && !dbs.contains_key(&c1), "{dbs:?}");
    promoted(&fx, K2);
    assert_eq!(tpl(&fx, K1), None, "{}", fx.templates());
    assert_eq!(tpl_state(&fx, K2).as_deref(), Some("ready"));
    let (dbs, roles) = (fx.fake.dbs(), fx.fake.roles());
    assert!(!dbs.contains_key(&format!("fg_t_{K1}")), "{dbs:?}");
    assert!(!roles.contains_key(&format!("fg_o_{K1}")), "{roles:?}");
    assert!(holds_template(&fx, K2));
    assert!(
        dbs.contains_key(&c2) && roles.contains_key(&c2),
        "the live clone survives"
    );
}

#[test]
fn the_newest_template_is_the_last_promoted() {
    // M3: K2 is prepared first and promoted last.
    let fx = Fx::migrating("n2");
    let c2 = prepared(fx.keyed(K2));
    let c1 = prepared(fx.keyed(K1));
    assert_eq!(fx.ready(&c1, true), Response::Ack);
    assert_eq!(fx.ready(&c2, true), Response::Ack);
    assert_eq!(tpl(&fx, K1), None, "{}", fx.templates());
    assert_eq!(tpl_state(&fx, K2).as_deref(), Some("ready"));
    assert!(holds_template(&fx, K2) && !holds_template(&fx, K1));
}

#[test]
fn a_candidate_name_in_the_template_registry_is_never_drawn_again() {
    // Final review: after the promotion the name is free in the catalogue, still recorded.
    let mut fx = Fx::migrating("r1");
    let cand = prepared(fx.keyed(K1));
    assert_eq!(fx.ready(&cand, true), Response::Ack);
    assert_eq!(fx.s().release(&cand), Response::Ack);
    fx.idle();
    assert_eq!(disk_state(&fx, &cand), None);
    fx.rand.push(cand.strip_prefix("fg_l_").unwrap());
    let l = leased(reply(fx.lease_in(&fx.plain(), holder(CLI), "", None)));
    assert_ne!(l, cand);

    // A role of that name with another mark is not the candidate: it goes by its own mark.
    fx.fake.add_role(&cand, Some("feedfeedfeedfeed"));
    fx.fake.add_db(&cand, &cand);
    fx.open();
    fx.tick(1);
    let (dbs, roles) = (fx.fake.dbs(), fx.fake.roles());
    assert!(
        !dbs.contains_key(&cand) && !roles.contains_key(&cand),
        "{roles:?}"
    );
    assert_eq!(tpl_state(&fx, K1).as_deref(), Some("ready"));
    assert!(holds_template(&fx, K1));
}

#[test]
fn a_retire_that_fails_is_retried() {
    // M2.
    let fx = Fx::migrating("n3");
    promoted(&fx, K1);
    fx.fake.fail("drop_database", 1, "ERROR:  injected");
    promoted(&fx, K2);
    assert_eq!(tpl_state(&fx, K1).as_deref(), Some("ready"));
    assert!(holds_template(&fx, K1));
    fx.tick(5);
    assert_eq!(tpl(&fx, K1), None, "{}", fx.templates());
    assert!(!holds_template(&fx, K1) && holds_template(&fx, K2));
    assert!(!fx.fake.dbs().contains_key(&format!("fg_t_{K1}")));
}

#[test]
fn a_pending_retire_keeps_the_server_up_and_starts_a_stopped_one() {
    // M2: no lease, a retire pending: past idle_stop_secs the server stays up.
    let fx = Fx::migrating("n4");
    promoted(&fx, K1);
    fx.fake.fail("drop_database", ALWAYS, "ERROR:  injected");
    promoted(&fx, K2);
    for t in [1, 700, 1400] {
        fx.tick(t);
    }
    assert_eq!(fx.fake.count("stop"), 0);
    assert_eq!(fx.state(), "running");
    assert!(holds_template(&fx, K1));

    // The server went away with the retire pending: the tick starts it to finish.
    let fx = Fx::migrating("n5");
    promoted(&fx, K1);
    fx.fake.fail("drop_database", 1, "ERROR:  injected");
    promoted(&fx, K2);
    assert!(holds_template(&fx, K1));
    let id = fx.fake.server_id().unwrap();
    fx.procs.gone(id.pid);
    fx.fake.set_server(Ok(None));
    fx.tick(1);
    assert_eq!(fx.state(), "stopped");
    fx.tick(10);
    assert_eq!(fx.fake.count("start"), 2);
    assert_eq!(tpl(&fx, K1), None, "{}", fx.templates());
    assert!(!holds_template(&fx, K1) && holds_template(&fx, K2));
}

/// Template key `i` of a run of failures.
fn fkey(i: u64) -> String {
    format!("{:016x}", 0xf00 + i)
}

/// `key` prepared, reported failed, and its candidate given back.
fn fail_key(fx: &Fx, key: &str) {
    let cand = prepared(fx.keyed(key));
    assert_eq!(fx.ready(&cand, false), Response::Ack);
    assert_eq!(fx.s().release(&cand), Response::Ack);
    fx.idle();
}

/// Keys of the `failed` rows in `templates.json`.
fn failed_keys(fx: &Fx) -> Vec<String> {
    let v: serde_json::Value = serde_json::from_str(&fx.templates()).unwrap();
    let rows = v["templates"].as_array().unwrap().iter();
    rows.filter(|r| r["state"] == "failed")
        .map(|r| r["key"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn failed_keys_are_remembered_and_the_registry_never_overflows() {
    // C5, C6, through the public flow.
    let fx = Fx::migrating("f1");
    let n = MAX_FAILED_PER_PROJECT as u64;
    for i in 0..n {
        fail_key(&fx, &fkey(i));
    }
    promoted(&fx, K1);
    assert_eq!(failed_keys(&fx).len(), MAX_FAILED_PER_PROJECT);
    fail_key(&fx, &fkey(n));
    let failed = failed_keys(&fx);
    assert_eq!(failed.len(), MAX_FAILED_PER_PROJECT, "{failed:?}");
    assert!(!failed.contains(&fkey(0)) && failed.contains(&fkey(n)));
    assert_eq!(tpl_state(&fx, K1).as_deref(), Some("ready"));

    // Full of rows that cannot leave: their candidates are still in `leases.json`.
    let mut fx = Fx::migrating("f2");
    let n = MAX_TEMPLATE_ROWS as u64 - 1;
    let leases: Vec<String> = (0..n)
        .map(|i| format!("fg_l_{:016x}", 0x2000 + i))
        .collect();
    let rows: Vec<String> = leases
        .iter()
        .map(|l| row(l, "ab", "granted", CLI, None))
        .collect();
    seed(&fx, &rows.join(","), SERVER);
    let tpls: Vec<String> = (0..n)
        .map(|i| {
            let l = &leases[i as usize];
            tpl_row(&fkey(0x100 + i), &fx.proj, "failed", l, "ab", 7, 8, i + 1)
        })
        .collect();
    seed_templates(&fx, &tpls);
    // The configuration caps leases at 64; this many recorded candidates need more.
    fx.pg.max_leases = 2 * MAX_TEMPLATE_ROWS as u32;
    fx.open();
    let cand = prepared(fx.keyed(K1));
    assert_eq!(fx.ready(&cand, false), Response::Ack);
    assert_eq!(
        failed_keys(&fx).len(),
        MAX_TEMPLATE_ROWS,
        "none could leave"
    );
    let e = error(fx.keyed(K2));
    assert!(e.contains("registry is full"), "{e}");
    fx.idle();
    assert_eq!(fx.fake.count("create_role"), 1, "only K1's candidate");
    assert_eq!(tpl(&fx, K2), None);
}

#[test]
fn a_pruned_failed_key_runs_once_more() {
    // C6.
    let fx = Fx::migrating("f3");
    for i in 0..=MAX_FAILED_PER_PROJECT as u64 {
        fail_key(&fx, &fkey(i));
    }
    assert_eq!(tpl(&fx, &fkey(0)), None, "{}", fx.templates());
    prepared(fx.keyed(&fkey(0)));
}

/// `fkey(0)` failed with its candidate still recorded, and 16 newer failures put it past the
/// cap; returns that candidate.
fn past_the_cap(fx: &Fx) -> String {
    let c0 = prepared(fx.keyed(&fkey(0)));
    assert_eq!(fx.ready(&c0, false), Response::Ack);
    for i in 1..=MAX_FAILED_PER_PROJECT as u64 {
        fail_key(fx, &fkey(i));
    }
    assert!(
        tpl(fx, &fkey(0)).is_some(),
        "its candidate is still recorded"
    );
    c0
}

#[test]
fn a_prune_waits_for_its_lease_row_and_a_failed_write_is_retried() {
    // The lease row's removal is not recorded (`begin_release`'s write, then the worker's):
    // the candidate may still be on disk, so the row stays.
    let fx = Fx::migrating("f4");
    let c0 = past_the_cap(&fx);
    fx.fail_lease_writes(2);
    assert_eq!(fx.s().release(&c0), Response::Ack);
    fx.idle();
    assert!(tpl(&fx, &fkey(0)).is_some(), "{}", fx.templates());

    // The prune's own write fails: the tick writes the registry again after a backoff.
    let fx = Fx::migrating("f5");
    let c0 = past_the_cap(&fx);
    fx.fail_template_writes(1);
    assert_eq!(fx.s().release(&c0), Response::Ack);
    fx.idle();
    assert!(tpl(&fx, &fkey(0)).is_some(), "the write failed");
    fx.tick(5);
    assert_eq!(tpl(&fx, &fkey(0)), None, "{}", fx.templates());
    assert_eq!(failed_keys(&fx).len(), MAX_FAILED_PER_PROJECT);
}

#[test]
fn a_prune_never_outruns_a_lease_registry_write() {
    // `fkey(0)`'s candidate leaves, but `leases.json` still holds it; another failure then
    // asks for a prune, which must not drop the row while the disk holds its candidate.
    let fx = Fx::migrating("f7");
    let c0 = past_the_cap(&fx);
    let other = prepared(fx.keyed(&fkey(0x80)));
    fx.fail_lease_writes(2);
    assert_eq!(fx.s().release(&c0), Response::Ack);
    fx.idle();
    assert_eq!(disk_state(&fx, &c0).as_deref(), Some("granted"));
    assert_eq!(fx.ready(&other, false), Response::Ack);
    assert_eq!(tpl_state(&fx, &fkey(0x80)).as_deref(), Some("failed"));
    assert!(tpl(&fx, &fkey(0)).is_some(), "{}", fx.templates());
    // The tick writes `leases.json` again; the prune it held back follows.
    fx.tick(5);
    assert_eq!(disk_state(&fx, &c0), None, "{}", fx.registry());
    assert_eq!(tpl(&fx, &fkey(0)), None, "{}", fx.templates());
}

#[test]
fn the_reconciliation_prunes_every_project() {
    let mut fx = Fx::migrating("f6");
    seed(&fx, "", SERVER);
    std::fs::write(fx.root().join("leases.json"), LEASES_KNOWN).unwrap();
    let n = MAX_FAILED_PER_PROJECT as u64 + 1;
    let other = fx.dir.join("elsewhere");
    let mut rows = Vec::new();
    for (proj, base) in [(&fx.proj, 0), (&other, 0x40)] {
        for i in 0..n {
            let (key, seq) = (fkey(base + i), base + i + 1);
            let lease = format!("fg_l_{:016x}", 0x3000 + base + i);
            rows.push(tpl_row(&key, proj, "failed", &lease, "ab", 7, 8, seq));
        }
    }
    seed_templates(&fx, &rows);
    fx.open();
    let failed = failed_keys(&fx);
    assert_eq!(failed.len(), 2 * MAX_FAILED_PER_PROJECT, "{failed:?}");
    assert!(!failed.contains(&fkey(0)) && !failed.contains(&fkey(0x40)));
}

#[test]
fn a_failed_reconciliation_of_an_inherited_row_is_retried() {
    // No lease registry: the candidate is in no lease row and no sweep runs, so only the
    // reconciliation can settle the row.
    let mut fx = Fx::migrating("i1");
    seed(&fx, "", SERVER);
    let (l, t) = ("fg_l_00000000000000c4", "c4");
    fx.fake.add_role(l, Some(t));
    fx.fake.add_db(l, l);
    let (db, role) = (
        fx.fake.oid_of_db(l).unwrap(),
        fx.fake.oid_of_role(l).unwrap(),
    );
    seed_templates(
        &fx,
        &[tpl_row(K1, &fx.proj, "preparing", l, t, db, role, 1)],
    );
    fx.fake.fail("template_state", 1, "ERROR:  injected");
    fx.open();
    assert_eq!(tpl_state(&fx, K1).as_deref(), Some("preparing"));
    // A migration this daemon authorised is never reconciled.
    prepared(fx.keyed(K2));
    fx.tick(5);
    assert_eq!(tpl_state(&fx, K1).as_deref(), Some("failed"));
    assert_eq!(tpl_state(&fx, K2).as_deref(), Some("preparing"));
    let asked = format!("template_state {K2}");
    assert!(fx.fake.calls().iter().all(|c| !c.contains(&asked)));
}

#[test]
fn a_pending_retire_survives_a_restart_with_the_server_stopped() {
    let mut fx = Fx::migrating("n6");
    promoted(&fx, K1);
    fx.fake.fail("drop_database", ALWAYS, "ERROR:  injected");
    promoted(&fx, K2);
    assert!(holds_template(&fx, K1));
    // Daemon and server go away; the next daemon finds the server stopped, no lease on disk.
    fx.fake.fail("drop_database", 0, "");
    fx.fake.set_server(Ok(None));
    fx.open();
    assert_eq!(fx.state(), "stopped");
    fx.tick(1);
    assert_eq!(fx.fake.count("start"), 2);
    assert_eq!(tpl(&fx, K1), None, "{}", fx.templates());
    assert!(!holds_template(&fx, K1) && holds_template(&fx, K2));
}

#[test]
fn a_marked_role_without_a_record_is_cleaned_up_with_a_known_registry() {
    // Ruling PF16: the positive side of the leftover rule.
    let fx = Fx::new("s6b");
    let x = "fg_l_00000000000000ab";
    fx.fake.add_role(x, Some("abab"));
    fx.fake.add_db(x, x);
    fx.leased();
    fx.idle();
    assert!(!fx.fake.roles().contains_key(x));
    assert!(!fx.fake.dbs().contains_key(x));
}

#[test]
fn unmarked_sync_gate_like_roles_are_never_touched() {
    let fx = Fx::new("s7");
    let x = "fg_l_0123456789abcdef";
    fx.fake.add_role(x, None);
    fx.fake.add_db(x, x);
    fx.leased();
    fx.tick(1);
    assert!(fx.fake.roles().contains_key(x) && fx.fake.dbs().contains_key(x));
    assert!(fx.fake.calls().iter().all(|c| !c.contains(x)));
}

#[test]
fn max_leases_is_an_error_not_a_wait() {
    let mut fx = Fx::bare("s8");
    fx.pg.max_leases = 1;
    fx.open();
    let l = fx.leased();
    // A wait would show as a missing reply at the bound (`DONE`), never as a pass.
    assert!(error(fx.lease_r("")).contains("in use"));
    fx.idle();
    assert_eq!(fx.fake.count("create_role"), 1);
    let b = fx.fake.block("owned_databases");
    fx.s().release(&l);
    assert!(fx.fake.wait_entered("owned_databases", LIMIT));
    let g = fx.lease_bg(holder(CLI), "");
    fx.wait_queued(1); // admitted: a releasing row does not count
    drop(b);
    leased(reply(g));
}

#[test]
fn slow_start_fails_open_after_the_lease_wait() {
    let mut fx = Fx::bare("s9");
    fx.lease_wait = Duration::from_millis(50);
    fx.open();
    let b = fx.fake.block("start");
    assert_eq!(error(fx.lease_r("")), "postgres is still starting");
    assert!(fx.fake.wait_entered("start", LIMIT));
    drop(b);
    fx.idle();
    // Bounded by `DONE`: the started cluster serves the next lease.
    fx.leased();
    assert_eq!(fx.fake.count("start"), 1);
}

#[test]
fn job_locked_start_fails_open() {
    let fx = Fx::new("s10");
    fx.fake.fail("start", 1, crate::supervisor::JOB_LOCKED);
    assert!(error(fx.lease_r("")).contains(crate::supervisor::JOB_LOCKED));
    assert_eq!(
        fx.state(),
        "failed: postgres cannot be started outside the daemon's job object"
    );
}

#[test]
fn unconfigured_cases_are_errors() {
    let fx = Fx::new("s11");
    let none = Services::new(&Config::default(), Some(&*fx.dir), fx.deps());
    assert_eq!(
        error(none.lease(&fx.proj, holder(CLI), "", None, &[])),
        "postgres is not configured"
    );
    assert!(none.report().is_empty());
    let no_dir = Services::new(&fx.cfg(), None, fx.deps());
    assert_eq!(
        error(no_dir.lease(&fx.proj, holder(CLI), "", None, &[])),
        "postgres needs a data dir"
    );
    let other = fx.dir.join("other");
    assert_eq!(
        error(fx.s().lease(&other, holder(CLI), "", None, &[])),
        format!("project not configured for postgres: {}", other.display())
    );
    // Ruling PF3: the service name is checked where the daemon dispatches requests.
    let core = crate::Core::new(
        Config::default(),
        sync_gate_core::CostModel::default(),
        crate::OsControl,
        None,
    );
    let hub = crate::Hub::new(
        &Config::default(),
        Arc::new(crate::OsLauncher::default()),
        None,
        None,
    );
    let req = Request::Lease {
        service: "redis".into(),
        project: fx.proj.clone(),
        holder: holder(CLI),
        request: String::new(),
        template: None,
        extensions: Vec::new(),
    };
    let r = crate::respond(&core, &hub, fx.s(), req, Instant::now());
    assert_eq!(error(r), "unknown service");
    fx.idle();
    assert_eq!(fx.fake.count("create_role"), 0);
}

#[test]
fn postgres_14_is_refused() {
    let fx = Fx::new("s12");
    fx.fake.set_major(PG_MIN_MAJOR - 1);
    let e = error(fx.lease_r(""));
    assert!(e.contains(&format!("{PG_MIN_MAJOR} or newer")), "{e}");
    fx.idle();
    assert_eq!(fx.fake.count("init"), 0);
}

#[test]
fn start_failure_backs_off_without_retrying_at_once() {
    let fx = Fx::new("s13");
    fx.fake.fail("start", 1, "start failed");
    assert!(error(fx.lease_r("")).contains("start failed"));
    assert!(error(fx.lease_r("")).contains("start failed"));
    fx.idle();
    assert_eq!(fx.fake.count("start"), 1);
    fx.tick(2);
    fx.leased();
    assert_eq!(fx.fake.count("start"), 2);
}

#[test]
fn five_start_failures_in_a_minute_pause_restarts_for_five_minutes() {
    // Ruling PF16: the hub's crash window (5 in 60 s -> 300 s), with explicit instants.
    let fx = Fx::new("s13b");
    fx.fake.fail("start", ALWAYS, "start failed");
    error(fx.lease_r(""));
    for t in [2, 5, 10, 19] {
        fx.tick(t);
        error(fx.lease_r(""));
    }
    assert_eq!(fx.fake.count("start"), 5);
    fx.tick(100);
    error(fx.lease_r(""));
    assert_eq!(fx.fake.count("start"), 5, "paused");
    fx.tick(320);
    error(fx.lease_r(""));
    assert_eq!(fx.fake.count("start"), 6);
}

#[test]
fn crash_restarts_only_while_leases_are_active() {
    let fx = Fx::new("s14");
    fx.leased();
    let id = fx.fake.server_id().unwrap();
    fx.procs.gone(id.pid);
    fx.fake.set_server(Ok(None));
    fx.tick(1);
    assert!(
        fx.s()
            .take_notes()
            .contains(&"postgres stopped unexpectedly".to_string())
    );
    fx.tick(3);
    assert_eq!(fx.fake.count("start"), 2);
    assert_eq!(fx.s().report()[0].restarts, 1);

    let fx = Fx::new("s14b");
    let l = fx.leased();
    fx.s().release(&l);
    fx.idle();
    let id = fx.fake.server_id().unwrap();
    fx.procs.gone(id.pid);
    fx.fake.set_server(Ok(None));
    fx.tick(1);
    fx.tick(10);
    assert_eq!(fx.fake.count("start"), 1);
    assert_eq!(fx.s().report()[0].restarts, 1);
    assert_eq!(fx.state(), "stopped");
}

#[test]
fn leases_on_disk_are_supervised_when_the_new_daemon_finds_no_server() {
    // Ruling P3: daemon and server both went down; a durable live lease brings the server
    // back without any new lease request.
    let mut fx = Fx::bare("s14c");
    let x = "fg_l_00000000000000ce";
    seed(&fx, &row(x, "ce", "granted", CLI, None), SERVER);
    fx.fake.set_server(Ok(None));
    fx.fake.add_role(x, Some("ce"));
    fx.fake.add_db(x, x);
    fx.open();
    fx.tick(1);
    fx.tick(2);
    assert_eq!(fx.fake.count("start"), 1);
    assert_eq!(fx.state(), "running");
    assert!(fx.fake.roles().contains_key(x) && fx.fake.dbs().contains_key(x));
    let reg = fx.registry();
    assert!(reg.contains(x) && reg.contains("granted"), "{reg}");
    assert_eq!(fx.s().report()[0].leases, 1);

    // An empty registry: nothing to supervise, nothing started.
    let mut fx = Fx::bare("s14d");
    seed(&fx, "", SERVER);
    std::fs::write(
        fx.root().join("leases.json"),
        r#"{"version":1,"unknown_before":false,"leases":[]}"#,
    )
    .unwrap();
    fx.fake.set_server(Ok(None));
    fx.open();
    fx.tick(1);
    fx.tick(2);
    assert_eq!(fx.fake.count("start"), 0);
    assert_eq!(fx.state(), "stopped");
}

#[test]
fn idle_cluster_stops_after_idle_stop_secs() {
    let fx = Fx::new("s15");
    let l = fx.leased();
    fx.s().release(&l);
    fx.idle();
    fx.tick(599);
    assert_eq!(fx.fake.count("stop"), 0);
    fx.tick(601);
    assert_eq!(fx.fake.count("stop"), 1);
    assert!(
        fx.s()
            .take_notes()
            .contains(&"postgres stopped (idle)".to_string())
    );
    assert_eq!(fx.state(), "stopped");
}

#[test]
fn shutdown_stops_only_an_idle_cluster() {
    let fx = Fx::new("s16");
    fx.leased();
    fx.s().shutdown();
    fx.idle();
    assert_eq!(fx.fake.count("stop"), 0);
    assert!(
        fx.s()
            .take_notes()
            .contains(&"postgres left running for 1 active lease(s)".to_string())
    );

    let fx = Fx::new("s16b");
    let l = fx.leased();
    fx.s().release(&l);
    fx.idle();
    fx.s().shutdown();
    assert_eq!(fx.fake.count("stop"), 1);
    assert_eq!(fx.fake.server_id(), None);
}

#[test]
fn shutdown_never_stops_a_lease_granted_while_its_stop_was_queued() {
    // Ruling P1: a grant held before its row exists, then `shutdown`, then the grant goes on.
    let fx = warm("s16c");
    let (entered, go) = fx.rand.block();
    let r = fx.lease_bg(holder(CLI), "R");
    entered
        .recv_timeout(LIMIT)
        .expect("the grant draws its name");
    let s = fx.s.clone().unwrap();
    let (done_tx, done) = mpsc::channel();
    std::thread::spawn(move || {
        s.shutdown();
        drop(s);
        let _ = done_tx.send(());
    });
    let deadline = Instant::now() + LIMIT;
    while !fx.s().shutting_down() {
        assert!(Instant::now() < deadline, "shutdown never began");
        std::thread::yield_now();
    }
    drop(go);
    let r = reply(r);
    done.recv_timeout(DONE).expect("shutdown never returned");
    fx.idle();
    let stopped = fx.fake.count("stop");
    let notes = fx.s().take_notes();
    match r {
        Response::Error { message } => {
            assert_eq!(message, "postgres is not running");
            assert_eq!(fx.fake.count("create_role"), 1, "only the warm-up");
            assert_eq!(fx.registry().matches("\"lease\"").count(), 0);
            assert_eq!(stopped, 1, "nothing live: the stop ran");
        }
        Response::Leased { .. } => {
            assert_eq!(stopped, 0, "granted AND stopped");
            assert!(
                notes.contains(&"postgres left running for 1 active lease(s)".to_string()),
                "{notes:?}"
            );
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(error(fx.lease_r("late")), "postgres is not running");
}

#[test]
fn adoption_requires_proven_identity() {
    let mut fx = Fx::bare("s17");
    seed(&fx, "", SERVER);
    fx.fake
        .set_server(Err("pid file names another server".into()));
    fx.open();
    assert_eq!(fx.state(), "failed: pid file names another server");
    for step in ["stop", "init", "start"] {
        assert_eq!(fx.fake.count(step), 0, "{step}");
    }
    assert!(fx.fake.calls().iter().all(|c| !c.starts_with("sql")));
}

/// Neither `init`, `start`, `stop` nor any SQL ran.
fn untouched(fx: &Fx) {
    for step in ["init", "start", "stop"] {
        assert_eq!(fx.fake.count(step), 0, "{step}");
    }
    assert!(fx.fake.calls().iter().all(|c| !c.starts_with("sql")));
}

#[test]
fn a_failed_adoption_is_retried_on_the_backoff() {
    // Final review P2: no row is in memory, yet the adoption is tried again.
    let mut fx = Fx::bare("s17b");
    let x = "fg_l_00000000000000cf";
    seed(&fx, &row(x, "cf", "granted", CLI, Some(CMD)), SERVER);
    fx.fake.add_role(x, Some("cf"));
    fx.fake.add_db(x, x);
    fx.procs.gone(CLI);
    fx.procs.gone(CMD);
    fx.fake.set_server(Err("identity query timed out".into()));
    fx.open();
    assert_eq!(fx.state(), "failed: identity query timed out");
    assert_eq!(fx.fake.count("server"), 1);
    untouched(&fx);
    fx.tick(0);
    assert_eq!(fx.fake.count("server"), 1, "inside the backoff");
    fx.tick(2);
    assert_eq!(fx.fake.count("server"), 2);
    assert_eq!(fx.state(), "failed: identity query timed out");
    untouched(&fx);

    fx.fake.set_server(Ok(Some(SERVER)));
    fx.tick(5);
    assert_eq!(fx.fake.count("server"), 3);
    assert_eq!(fx.state(), "running");
    fx.tick(6);
    assert_eq!(fx.drops(), 1);
    assert!(!fx.fake.roles().contains_key(x) && !fx.fake.dbs().contains_key(x));
    assert!(!fx.registry().contains(x));
}

#[test]
fn five_failed_adoptions_in_a_minute_pause_retries_for_five_minutes() {
    let mut fx = Fx::bare("s17c");
    seed(&fx, "", SERVER);
    fx.fake.set_server(Err("identity query timed out".into()));
    fx.open();
    for t in [2, 5, 10, 19] {
        fx.tick(t);
    }
    assert_eq!(fx.fake.count("server"), 5);
    fx.tick(100);
    assert_eq!(fx.fake.count("server"), 5, "paused");
    fx.tick(320);
    assert_eq!(fx.fake.count("server"), 6);
    untouched(&fx);
}

#[test]
fn ticks_during_an_adoption_retry_queue_no_second_one() {
    // Final review (second wave): one retry at a time; the back-off it installs is honoured.
    let mut fx = Fx::bare("s17d");
    seed(&fx, "", SERVER);
    fx.fake.set_server(Err("identity query timed out".into()));
    fx.open();
    assert_eq!(fx.fake.count("server"), 1);
    let b = fx.fake.block("server");
    fx.s().tick(fx.t0 + Duration::from_secs(2));
    assert!(fx.fake.wait_entered("server", LIMIT), "the retry runs");
    fx.s().tick(fx.t0 + Duration::from_secs(3));
    fx.s().tick(fx.t0 + Duration::from_secs(4));
    drop(b);
    fx.idle();
    assert_eq!(fx.fake.count("server"), 2, "exactly one more call");
    fx.tick(4);
    assert_eq!(fx.fake.count("server"), 2, "inside the new back-off");
    fx.tick(40);
    assert_eq!(fx.fake.count("server"), 3, "after it, exactly one");
    untouched(&fx);
}

#[test]
fn ticks_during_the_fifth_adoption_retry_do_not_break_the_pause() {
    let mut fx = Fx::bare("s17e");
    seed(&fx, "", SERVER);
    fx.fake.set_server(Err("identity query timed out".into()));
    fx.open();
    for t in [2, 5, 10] {
        fx.tick(t);
    }
    assert_eq!(fx.fake.count("server"), 4);
    let b = fx.fake.block("server");
    fx.s().tick(fx.t0 + Duration::from_secs(19));
    assert!(
        fx.fake.wait_entered("server", LIMIT),
        "the fifth attempt runs"
    );
    fx.s().tick(fx.t0 + Duration::from_secs(20));
    fx.s().tick(fx.t0 + Duration::from_secs(30));
    drop(b);
    fx.idle();
    assert_eq!(fx.fake.count("server"), 5, "no sixth attempt");
    fx.tick(200);
    assert_eq!(fx.fake.count("server"), 5, "paused");
    fx.tick(340);
    assert_eq!(fx.fake.count("server"), 6);
    untouched(&fx);
}

#[test]
fn adoption_with_changed_config_grants_nothing_until_idle() {
    let mut fx = Fx::bare("s18");
    let x = "fg_l_00000000000000cd";
    seed(&fx, &row(x, "cd", "granted", CLI, None), SERVER);
    fx.fake.add_role(x, Some("cd"));
    fx.fake.add_db(x, x);
    fx.fake.set_config_current(false);
    fx.open();
    assert_eq!(
        fx.state(),
        "failed: configuration changed; restarting when idle"
    );
    assert!(error(fx.lease_r("")).contains("configuration changed"));
    fx.idle();
    assert_eq!(fx.fake.count("create_role"), 0);
    fx.tick(1);
    assert_eq!(fx.fake.count("stop"), 0, "a lease is live");
    fx.s().release(x);
    fx.idle();
    fx.tick(2);
    assert_eq!(fx.fake.count("stop"), 1);
    assert_eq!(fx.fake.count("start"), 1);
    assert_eq!(fx.state(), "running");
    fx.leased();
}

#[test]
fn secrets_never_reach_report_notes_or_disk() {
    let fx = Fx::new("s19");
    let r = fx.lease_r("");
    let pw = password(&r);
    leased(r);
    let pw2 = "cafecafecafecafecafecafecafecafe";
    fx.rand.push("00000000000000f1");
    fx.rand.push("00000000000000f2");
    fx.rand.push(pw2);
    fx.fake
        .fail("create_role", 1, "ERROR:  bad password {password}");
    let e = error(fx.lease_r(""));
    assert!(e.contains("***") && !e.contains(pw2), "{e}");
    fx.idle();
    let notes = fx.s().take_notes().join("\n");
    let report = format!("{:?}", fx.s().report());
    let disk = fx.registry();
    for secret in [pw.as_str(), pw2] {
        assert!(!notes.contains(secret), "{notes}");
        assert!(!report.contains(secret));
        assert!(!disk.contains(secret));
    }
    assert!(notes.contains("***"), "{notes}");
}

/// Where the call `call` is in the fake's log; fails the test when it is missing.
fn call_at(fx: &Fx, call: &str) -> usize {
    let calls = fx.fake.calls();
    calls
        .iter()
        .position(|c| c == call)
        .unwrap_or_else(|| panic!("no {call:?} in {calls:?}"))
}

/// The next grant of `rx` stops in the blocked `step`: no reply yet, the row still `creating`.
/// The lease it is creating.
fn held_in(fx: &Fx, rx: &mpsc::Receiver<Response>, step: &str) -> String {
    assert!(
        fx.fake.wait_entered(step, LIMIT),
        "{step}: calls so far {:?}",
        fx.fake.calls()
    );
    assert!(rx.try_recv().is_err(), "a reply before {step}");
    let last = fx.fake.calls().pop().unwrap();
    let lease = last.split(' ').nth(2).unwrap().to_string();
    assert_eq!(disk_state(fx, &lease).as_deref(), Some("creating"));
    lease
}

/// `Fx::migrating` whose project declares `extensions`.
fn migrating_with(tag: &str, extensions: &[&str]) -> Fx {
    let mut fx = Fx::migrating(tag);
    fx.pg.project[0].extensions = extensions.iter().map(|e| e.to_string()).collect();
    fx.open();
    fx
}

/// Calls of `create_extensions` for `lease`.
fn creates_for(fx: &Fx, lease: &str) -> usize {
    let prefix = format!("sql create_extensions {lease} ");
    let calls = fx.fake.calls();
    calls.iter().filter(|c| c.starts_with(&prefix)).count()
}

#[test]
fn declared_extensions_are_created_before_the_lease_is_granted() {
    // 1a: an empty database.
    let mut fx = Fx::bare("x1");
    fx.pg.project[0].extensions = vec!["pg_trgm".into(), "citext".into()];
    fx.open();
    let held = fx.fake.block("create_extensions");
    let rx = fx.lease_bg(holder(CLI), "");
    let l = held_in(&fx, &rx, "create_extensions");
    drop(held);
    assert_eq!(leased(reply(rx)), l);
    let ext = call_at(&fx, &format!("sql create_extensions {l} pg_trgm citext"));
    assert!(call_at(&fx, &format!("sql create_database {l}")) < ext);

    // 1b: the candidate, still empty, gets them before its `migrate`.
    let fx = migrating_with("x2", &["pg_trgm"]);
    let held = fx.fake.block("create_extensions");
    let rx = fx.keyed_bg(K1);
    let cand = held_in(&fx, &rx, "create_extensions");
    drop(held);
    assert_eq!(prepared(reply(rx)), cand);
    assert_eq!(fx.ready(&cand, true), Response::Ack);
    // A copy already holds the migration's objects: it is only checked, never given one.
    let held = fx.fake.block("missing_extensions");
    let rx = fx.keyed_bg(K1);
    let l = held_in(&fx, &rx, "missing_extensions");
    drop(held);
    assert_eq!(leased(reply(rx)), l);
    let adopt = call_at(&fx, &format!("sql clone_adopt {l} {K1}"));
    assert!(call_at(&fx, &format!("sql create_database_from {l} {K1}")) < adopt);
    assert!(adopt < call_at(&fx, &format!("sql missing_extensions {l} pg_trgm")));
    assert_eq!(creates_for(&fx, &l), 0);
    assert_eq!(fx.fake.count("create_extensions"), 1);

    // A project without `extensions` (here the plain one) runs neither step.
    leased(reply(fx.lease_in(&fx.plain(), holder(CLI), "", None)));
    assert_eq!(fx.fake.count("create_extensions"), 1);
    assert_eq!(fx.fake.count("missing_extensions"), 1);
}

#[test]
fn a_copy_without_a_declared_extension_is_refused_and_never_given_it() {
    // The template of K1 lacks citext, which daemon and CLI both declare now (here by reusing
    // K1; in practice a migration that dropped it).
    let mut fx = migrating_with("x4", &["pg_trgm"]);
    promoted(&fx, K1);
    fx.pg.project[0].extensions = vec!["pg_trgm".into(), "citext".into()];
    fx.open();
    let e = error(fx.keyed(K1));
    assert!(e.contains("citext") && !e.contains("pg_trgm"), "{e}");
    assert!(e.contains("new template"), "{e}");
    fx.idle();
    let calls = fx.fake.calls();
    let copy = calls
        .iter()
        .find_map(|c| c.strip_prefix("sql missing_extensions "))
        .and_then(|rest| rest.split(' ').next())
        .expect("the copy was checked");
    assert_eq!(creates_for(&fx, copy), 0, "{calls:?}");
    assert_eq!(fx.fake.count("create_extensions"), 1, "the candidate only");
    // Given back, and the template stays as it is.
    let dbs = fx.fake.dbs();
    assert!(!dbs.contains_key(copy), "{dbs:?}");
    assert!(!fx.registry().contains(copy), "{}", fx.registry());
    assert!(holds_template(&fx, K1));
    assert_eq!(tpl_state(&fx, K1).as_deref(), Some("ready"));
}

#[test]
fn a_daemon_with_other_extensions_than_the_cli_refuses_before_creating_anything() {
    const STALE_EXT: &str = "the daemon's configuration is older than this command's \
                             (extensions differ); restart the daemon";
    // The review's sequence: the daemon declares none, the CLI added citext (and keyed on it).
    let mut fx = Fx::migrating("x5");
    fx.cli_ext = Some(vec!["citext".into()]);
    assert_eq!(error(fx.keyed(K1)), STALE_EXT);
    // A project without `migrate` too: its empty database would lack them as well.
    let plain = fx.lease_in(&fx.plain(), holder(CLI), "", None);
    assert_eq!(error(reply(plain)), STALE_EXT);
    fx.idle();
    assert_eq!(fx.fake.count("create_role"), 0, "{:?}", fx.fake.calls());
    assert!(tpl(&fx, K1).is_none(), "{}", fx.templates());
    assert!(!fx.registry().contains("fg_l_"), "{}", fx.registry());
    // The same lists keep working.
    fx.cli_ext = None;
    prepared(fx.keyed(K1));

    // The lists are compared in order: the order is part of the key.
    let mut fx = migrating_with("x6", &["pg_trgm", "citext"]);
    fx.cli_ext = Some(vec!["citext".into(), "pg_trgm".into()]);
    assert_eq!(error(fx.keyed(K1)), STALE_EXT);
    fx.idle();
    assert_eq!(fx.fake.count("create_role"), 0);
    fx.cli_ext = None;
    prepared(fx.keyed(K1));
}

#[test]
fn a_failed_extension_fails_open_and_names_it() {
    let mut fx = Fx::bare("x3");
    fx.pg.project[0].extensions = vec!["pg_trgm".into(), "file_fdw".into()];
    fx.open();
    fx.fake.fail("create_extensions", 1, "ERROR:  injected");
    let e = error(fx.lease_r(""));
    assert!(
        e.contains("pg_trgm, file_fdw") && e.contains("ERROR:  injected"),
        "{e}"
    );
    fx.idle();
    assert!(
        catalogue_empty(&fx),
        "{:?} {:?}",
        fx.fake.roles(),
        fx.fake.dbs()
    );
    assert!(!fx.registry().contains("fg_l_"), "{}", fx.registry());
    let notes = fx.s().take_notes().join("\n");
    assert!(notes.contains("file_fdw"), "{notes}");
    // The next lease is not held back by the failed one.
    leased(fx.lease_r(""));
}

#[test]
fn the_fake_refuses_a_script_no_builder_wrote() {
    // Ruling F1: the token predicate is part of what the tests prove, not something the fake
    // applies on its own.
    let fake = FakePg::default();
    fake.set_server(Ok(Some(SERVER)));
    let (n, t) = ("fg_l_00000000000000aa", "abab");
    fake.add_role(n, Some(t));
    let c = ClusterPaths::new(Path::new("bin"), Path::new("root"), 1);
    let full = pg_sql::drop_role(n, t).unwrap();
    let unsafe_sql = full.replace(
        &format!(" AND shobj_description(r.oid, 'pg_authid') = 'sync_gate:lease:{t}'"),
        "",
    );
    assert_ne!(unsafe_sql, full);
    let e = fake.sql(&c, &unsafe_sql, &[]).unwrap_err();
    assert!(e.to_string().contains("unrecognised script"), "{e}");
    assert!(fake.roles().contains_key(n));
    let last = fake.calls().pop().unwrap();
    assert!(last.starts_with("unrecognised:"), "{last}");
    fake.sql(&c, &full, &[]).unwrap();
    assert!(!fake.roles().contains_key(n));
}

#[test]
fn the_fake_runs_every_template_builder() {
    use pg_sql::{
        candidate_oids, clone_adopt, create_database_from, create_extensions, db_by_oid,
        drop_template_role, missing_extensions, template_check, template_names_free, template_own,
        template_rename_db, template_rename_role, template_seal, template_state,
    };
    let fake = FakePg::default();
    fake.set_server(Ok(Some(SERVER)));
    let c = ClusterPaths::new(Path::new("bin"), Path::new("root"), 1);
    let run = |s: Result<String, pg_sql::SqlError>| fake.sql(&c, &s.unwrap(), &[]);
    let ok = |s| run(s).unwrap();
    let (l, t, tdb) = ("fg_l_00000000000000aa", "abab", format!("fg_t_{K1}"));
    let exts = |names: &[&str]| names.iter().map(|n| n.to_string()).collect::<Vec<_>>();
    ok(create_role(l, t, "pw", 5));
    ok(create_database(l));
    ok(create_extensions(l, &exts(&["pg_trgm"])));
    assert!(
        fake.calls()
            .contains(&format!("sql create_extensions {l} pg_trgm"))
    );
    let nowhere = create_extensions("fg_l_00000000000000dd", &exts(&["pg_trgm"]));
    assert!(run(nowhere).is_err(), "no database");
    let (role, db) = (fake.oid_of_role(l).unwrap(), fake.oid_of_db(l).unwrap());
    assert_eq!(ok(candidate_oids(l, t)), format!("{role}|{db}\n"));
    assert_eq!(ok(candidate_oids(l, "cdcd")), "", "another mark");
    assert!(
        run(template_seal("fg_l_00000000000000cc", t)).is_err(),
        "no mark"
    );
    assert_eq!(ok(template_names_free(K1)), "t\n");
    assert_eq!(ok(template_seal(l, t)), "t\n");
    assert_eq!(ok(template_check(l)), "t\n");
    ok(template_own(l));
    assert_eq!(ok(template_state(K1, db, role)), "f\n", "not renamed yet");
    ok(template_rename_role(l, t, K1));
    ok(template_rename_db(l, K1));
    assert_eq!(ok(template_state(K1, db, role)), "t\n");
    assert_eq!(ok(template_state(K1, db, role + 1)), "f\n", "another role");
    assert_eq!(ok(template_names_free(K1)), "f\n");
    assert_eq!(fake.db_owner(&tdb).as_deref(), Some("sync_gate"));
    let clone = "fg_l_00000000000000bb";
    ok(create_role(clone, t, "pw", 5));
    ok(create_database_from(clone, K1));
    ok(clone_adopt(clone, K1));
    // The copy has what the template had.
    assert_eq!(ok(missing_extensions(clone, &exts(&["pg_trgm"]))), "");
    let both = exts(&["pg_trgm", "uuid-ossp"]);
    assert_eq!(ok(missing_extensions(clone, &both)), "uuid-ossp\n");
    assert!(
        run(missing_extensions("fg_l_00000000000000dd", &both)).is_err(),
        "no database"
    );
    assert_eq!(fake.db_owner(clone).as_deref(), Some(clone));
    assert!(run(create_database_from(clone, K2)).is_err(), "no template");
    assert_eq!(ok(db_by_oid(db + 1, role, l, K1)), "", "another database");
    assert_eq!(ok(db_by_oid(db, role, l, K1)), format!("{tdb}\n"));
    ok(drop_database(&tdb));
    ok(drop_template_role(role + 1, l, t, K1));
    assert_eq!(
        fake.owner_roles().len(),
        1,
        "another OID is not the template's"
    );
    ok(drop_template_role(role, l, t, K1));
    assert!(fake.owner_roles().is_empty());
    let calls = fake.calls();
    assert!(
        calls.iter().all(|c| !c.starts_with("unrecognised")),
        "{calls:?}"
    );
}

#[test]
fn the_fake_decodes_a_doubled_quote_in_an_identifier() {
    let fake = FakePg::default();
    fake.set_server(Ok(Some(SERVER)));
    fake.add_db("a\"b", "owner");
    let c = ClusterPaths::new(Path::new("bin"), Path::new("root"), 1);
    fake.sql(&c, &pg_sql::drop_database("a\"b").unwrap(), &[])
        .unwrap();
    assert!(fake.dbs().is_empty());
}

/// One request line over the daemon's socket, on a thread of its own: a reply that does not
/// come within [`DONE`] fails the test instead of hanging it.
fn call(name: &str, req: &Request) -> Response {
    use std::io::{BufRead, BufReader, Write};
    let (name, req) = (name.to_string(), req.clone());
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut conn = sync_gate_core::ipc_name::connect(&name).unwrap();
        let mut line = serde_json::to_string(&req).unwrap();
        line.push('\n');
        conn.write_all(line.as_bytes()).unwrap();
        let mut reply = String::new();
        BufReader::new(conn).read_line(&mut reply).unwrap();
        let _ = tx.send(serde_json::from_str::<Response>(&reply).unwrap());
    });
    rx.recv_timeout(DONE)
        .unwrap_or_else(|_| panic!("no reply over the socket within {DONE:?}"))
}

/// The daemon's measurement, which also paces the test: in every tick after the service has
/// a server, it says so (the service's tick is done by then) and waits for the test's go.
struct Paced {
    probe: sync_gate_probe::Probe,
    fake: Arc<FakePg>,
    ticked: mpsc::Sender<()>,
    go: mpsc::Receiver<()>,
}

impl crate::Measure for Paced {
    fn snapshot(&mut self) -> sync_gate_core::MachineSnapshot {
        self.probe.snapshot()
    }
    fn tree_rss(&mut self, pid: u32) -> u64 {
        if Some(pid) != self.fake.server_id().map(|s| s.pid) {
            return self.probe.tree_rss(pid);
        }
        if self.ticked.send(()).is_ok() {
            let _ = self.go.recv_timeout(DONE);
        }
        0
    }
    fn start_time(&mut self, pid: u32) -> Option<u64> {
        sync_gate_probe::start_time(pid)
    }
}

/// Shuts the daemon down on every path; the pacing ends first so its ticker can stop.
struct Daemon {
    h: Option<crate::DaemonHandle>,
    go: Option<mpsc::Sender<()>>,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.go.take();
        if let Some(h) = self.h.take() {
            h.shutdown();
        }
    }
}

fn status(name: &str) -> ServiceStatus {
    match call(name, &Request::Status) {
        Response::Status(s) => s.services[0].clone(),
        other => panic!("{other:?}"),
    }
}

#[test]
fn status_has_a_postgres_row() {
    let fx = Fx::bare("s20");
    let name = {
        let n = format!("sync_gate-test-{}-svc-status", std::process::id());
        if cfg!(windows) {
            n
        } else {
            std::env::temp_dir().join(n).to_string_lossy().into_owned()
        }
    };
    let cfg = Config {
        tick_ms: 20,
        ..fx.cfg()
    };
    let (ticked_tx, ticked) = mpsc::channel();
    let (go, go_rx) = mpsc::channel();
    let paced = Paced {
        probe: sync_gate_probe::Probe::new(),
        fake: fx.fake.clone(),
        ticked: ticked_tx,
        go: go_rx,
    };
    let h = crate::run_with_pg(
        cfg,
        &name,
        paced,
        crate::OsControl,
        Some(fx.dir.join("data")),
        Arc::new(crate::OsLauncher::default()),
        fx.deps(),
    )
    .unwrap();
    let d = Daemon {
        h: Some(h),
        go: Some(go),
    };
    let lease = Request::Lease {
        service: SERVICE_POSTGRES.into(),
        project: fx.proj.clone(),
        holder: holder(CLI),
        request: "s20".into(),
        template: None,
        extensions: Vec::new(),
    };
    leased(call(&name, &lease));
    let s = status(&name);
    assert_eq!(
        (s.service.as_str(), s.state.as_str()),
        ("postgres", "running")
    );
    assert_eq!(s.leases, 1);
    // Between a tick's report and the go the ticker is held, so each read sees one tick.
    let mut checks = Vec::new();
    for _ in 0..4 {
        ticked.recv_timeout(DONE).expect("no tick within the bound");
        checks.push(status(&name).checks);
        d.go.as_ref().unwrap().send(()).unwrap();
    }
    assert!(
        checks.windows(2).all(|w| w[1] == w[0] + 1),
        "one check per tick: {checks:?}"
    );
    drop(d);
    assert_eq!(fx.fake.count("stop"), 0, "a live lease keeps the server");
}

#[test]
fn every_grant_echoes_the_extension_list_it_used() {
    let fx = migrating_with("x7", &["pg_trgm", "citext"]);
    let want = vec!["pg_trgm".to_string(), "citext".to_string()];
    let Response::Prepare {
        lease, extensions, ..
    } = fx.keyed(K1)
    else {
        panic!("not prepare");
    };
    assert_eq!(extensions, want);
    assert_eq!(fx.ready(&lease, true), Response::Ack);
    match fx.keyed(K1) {
        Response::Leased { extensions, .. } => assert_eq!(extensions, want),
        other => panic!("not leased: {other:?}"),
    }
}
