//! Daemon tests with a fake `Measure`, a recording `Control` and an injected clock.

use crate::control_loop::{Caller, Control, Core, GUEST_MAX_TICKETS, Measure};
use crate::guest::{Guest, respond_guest};
use crate::hub::testkit::{FakeLauncher, config as hub_config, connect, hello, wait_until};
use crate::store;
use std::collections::HashMap;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use sync_gate_core::{
    Config, CostModel, ERR_BUSY, GuestOf, HubReply, MIB, MachineSnapshot, PRIOR_HEAVY, Request,
    Response, TicketId, signature,
};
use sync_gate_probe::still_ours;
use sync_gate_probe::{FrozenUnit, GuestUnit, IdentKind};

const GIB: u64 = 1024 * MIB;

#[derive(Default)]
struct FakeMeasure {
    snap: Option<MachineSnapshot>,
    rss: HashMap<u32, u64>,
    /// Start time per pid; absent = unknown.
    starts: HashMap<u32, u64>,
}

impl Measure for FakeMeasure {
    fn snapshot(&mut self) -> MachineSnapshot {
        self.snap.unwrap_or(snap(0, 0))
    }
    fn tree_rss(&mut self, pid: u32) -> u64 {
        self.rss.get(&pid).copied().unwrap_or(0)
    }
    fn start_time(&mut self, pid: u32) -> Option<u64> {
        self.starts.get(&pid).copied()
    }
}

/// Records every call. The token is one unit per suspended pid, with start time `1000 + pid`
/// unless `starts` says otherwise; `fail_resumes` makes that many resume calls fail.
#[derive(Clone, Default)]
struct FakeControl {
    log: Arc<Mutex<Vec<(&'static str, u32)>>>,
    fail_resumes: Arc<Mutex<u32>>,
    starts: Arc<Mutex<HashMap<u32, u64>>>,
    /// The next suspend fails with its unit still frozen (a rollback that could not resume).
    fail_suspend: Arc<Mutex<bool>>,
    block_resume: Arc<Mutex<Option<ResumeBlock>>>,
    panic_resume: Arc<std::sync::atomic::AtomicBool>,
    /// When set, `suspend` records this file's content at the moment it is called.
    watch: Arc<Mutex<Option<PathBuf>>>,
    seen_at_suspend: Arc<Mutex<Vec<String>>>,
    /// That many `resume_tree` calls fail.
    fail_trees: Arc<Mutex<u32>>,
    /// `suspend_as` calls: (pid, root start, ident).
    as_calls: Arc<Mutex<Vec<(u32, u64, String)>>>,
    /// What the next `suspend_as` plans and how it ends (None: one unit, success).
    as_script: Arc<Mutex<Option<AsScript>>>,
    /// When set, `suspend_as` records this file's content right after `plan` returned.
    guest_watch: Arc<Mutex<Option<PathBuf>>>,
    seen_at_plan: Arc<Mutex<Vec<String>>>,
    /// Every `resume_guest_units` call; while `fail_recover` > 0 a call fails for every unit.
    recovered: Arc<Mutex<Vec<Vec<GuestUnit>>>>,
    fail_recover: Arc<Mutex<u32>>,
    next_token: Arc<std::sync::atomic::AtomicU64>,
}

/// A fake pause: an owner part (units) and a guest part (guest units, under token `id`).
#[derive(Debug)]
struct FakeToken {
    id: u64,
    units: Vec<FrozenUnit>,
    guest: Vec<GuestUnit>,
}

/// `suspend_as` plans `plan`; `left` None = success, Some(k) = failure with the first k frozen.
struct AsScript {
    plan: Vec<GuestUnit>,
    left: Option<usize>,
}

fn gunit(pid: u32, tid: u32, ident: &str) -> GuestUnit {
    GuestUnit {
        pid,
        tid,
        created: 5000 + u64::from(pid),
        ident: ident.into(),
    }
}

struct ResumeBlock {
    entered: std::sync::mpsc::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

impl FakeControl {
    fn calls(&self) -> Vec<(&'static str, u32)> {
        self.log.lock().unwrap().clone()
    }
    fn fail_next_resumes(&self, n: u32) {
        *self.fail_resumes.lock().unwrap() = n;
    }
}

impl Control for FakeControl {
    type Token = FakeToken;
    fn suspend(&self, pid: u32) -> Result<Self::Token, (Self::Token, io::Error)> {
        if let Some(path) = self.watch.lock().unwrap().as_ref() {
            let text = std::fs::read_to_string(path).unwrap_or_default();
            self.seen_at_suspend.lock().unwrap().push(text);
        }
        let failed = std::mem::take(&mut *self.fail_suspend.lock().unwrap());
        let what = if failed { "suspend-failed" } else { "suspend" };
        self.log.lock().unwrap().push((what, pid));
        let start_time = self.start_time(pid).unwrap_or(0);
        let token = FakeToken {
            id: 0,
            units: vec![FrozenUnit {
                pid,
                tid: 0,
                start_time,
            }],
            guest: Vec::new(),
        };
        if failed {
            return Err((token, io::ErrorKind::PermissionDenied.into()));
        }
        Ok(token)
    }
    fn resume(&self, token: Self::Token) -> Result<(), (Self::Token, io::Error)> {
        assert!(
            !self
                .panic_resume
                .swap(false, std::sync::atomic::Ordering::SeqCst),
            "injected resume panic"
        );
        let block = self.block_resume.lock().unwrap().take();
        if let Some(block) = block {
            block.entered.send(()).unwrap();
            block.release.recv().unwrap();
        }
        let mut fails = self.fail_resumes.lock().unwrap();
        for u in &token.units {
            self.log.lock().unwrap().push((
                if *fails > 0 {
                    "resume-failed"
                } else {
                    "resume"
                },
                u.pid,
            ));
        }
        if !token.guest.is_empty() {
            let what = if *fails > 0 {
                "resume-as-failed"
            } else {
                "resume-as"
            };
            self.log.lock().unwrap().push((what, token.id as u32));
        }
        if *fails > 0 {
            *fails -= 1;
            return Err((token, io::ErrorKind::PermissionDenied.into()));
        }
        Ok(())
    }
    fn units(&self, token: &Self::Token) -> Vec<FrozenUnit> {
        token.units.clone()
    }
    fn token(&self, units: Vec<FrozenUnit>) -> Self::Token {
        FakeToken {
            id: 0,
            units,
            guest: Vec::new(),
        }
    }
    fn resume_tree(&self, root: u32) -> io::Result<()> {
        let mut fails = self.fail_trees.lock().unwrap();
        let failed = *fails > 0;
        *fails = fails.saturating_sub(1);
        let what = if failed {
            "resume-tree-failed"
        } else {
            "resume-tree"
        };
        self.log.lock().unwrap().push((what, root));
        if failed {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(())
    }
    fn start_time(&self, pid: u32) -> Option<u64> {
        Some(
            self.starts
                .lock()
                .unwrap()
                .get(&pid)
                .copied()
                .unwrap_or(1000 + pid as u64),
        )
    }
    fn suspend_as(
        &self,
        pid: u32,
        start: u64,
        ident: &str,
        plan: &mut dyn FnMut(&[GuestUnit]) -> io::Result<()>,
    ) -> Result<Self::Token, (Self::Token, io::Error)> {
        self.as_calls
            .lock()
            .unwrap()
            .push((pid, start, ident.to_string()));
        self.log.lock().unwrap().push(("suspend-as", pid));
        let script = self.as_script.lock().unwrap().take();
        let (units, left) =
            script.map_or_else(|| (vec![gunit(pid, 1, ident)], None), |s| (s.plan, s.left));
        let planned = plan(&units);
        if let Some(path) = self.guest_watch.lock().unwrap().as_ref() {
            let text = std::fs::read_to_string(path).unwrap_or_default();
            self.seen_at_plan.lock().unwrap().push(text);
        }
        let id = self.next_token.fetch_add(1, Ordering::SeqCst) + 1;
        let token = |guest: Vec<GuestUnit>| FakeToken {
            id,
            units: Vec::new(),
            guest,
        };
        if let Err(e) = planned {
            return Err((token(Vec::new()), e));
        }
        match left {
            None => Ok(token(units)),
            Some(k) => Err((
                token(units[..k].to_vec()),
                io::Error::other("rollback failed"),
            )),
        }
    }
    fn guest_units(&self, token: &Self::Token) -> Vec<GuestUnit> {
        token.guest.clone()
    }
    fn resume_guest_units(&self, units: Vec<GuestUnit>) -> Vec<GuestUnit> {
        self.recovered.lock().unwrap().push(units.clone());
        let mut fails = self.fail_recover.lock().unwrap();
        if *fails > 0 {
            *fails -= 1;
            return units;
        }
        Vec::new()
    }
}

fn snap(total: u64, available: u64) -> MachineSnapshot {
    MachineSnapshot {
        total,
        available,
        reclaimable: 0,
        swap_used: 0,
        swap_total: 0,
        vram: None,
    }
}

fn free(available: u64) -> Option<MachineSnapshot> {
    Some(snap(16 * GIB, available))
}

fn core(cfg: Config) -> (Core<FakeControl>, FakeControl) {
    let ctl = FakeControl::default();
    (Core::new(cfg, CostModel::default(), ctl.clone(), None), ctl)
}

fn acquire(c: &Core<FakeControl>, cmd: &str, now: Instant) -> Response {
    c.handle(
        Request::Acquire {
            argv: cmd.split(' ').map(String::from).collect(),
            cwd: PathBuf::from("/r/site"),
            session: "s1".into(),
            heavy: true,
        },
        now,
    )
}

fn sig(cmd: &str) -> sync_gate_core::JobSignature {
    let argv: Vec<OsString> = cmd.split(' ').map(OsString::from).collect();
    signature(&argv, Path::new("/r/site")).unwrap()
}

fn admitted(r: &Response) -> TicketId {
    match r {
        Response::Admitted { id } => *id,
        other => panic!("expected Admitted, got {other:?}"),
    }
}

fn decisions(c: &Core<FakeControl>) -> Vec<String> {
    match c.handle(Request::Status, Instant::now()) {
        Response::Status(r) => r.decisions,
        other => panic!("{other:?}"),
    }
}

fn has_decision(c: &Core<FakeControl>, needle: &str) -> bool {
    decisions(c).iter().any(|d| d.contains(needle))
}

#[test]
fn acquire_fast_path_admits() {
    let (c, _) = core(Config::default());
    let t0 = Instant::now();
    c.tick(
        &mut FakeMeasure {
            snap: free(8 * GIB),
            ..Default::default()
        },
        t0,
    );
    admitted(&acquire(&c, "cargo build", t0));
}

#[test]
fn acquire_without_room_queues() {
    let (c, _) = core(Config::default());
    let t0 = Instant::now();
    c.tick(
        &mut FakeMeasure {
            snap: free(GIB),
            ..Default::default()
        },
        t0,
    );
    assert!(matches!(
        acquire(&c, "cargo build", t0),
        Response::Queued { position: 0, .. }
    ));
}

#[test]
fn finished_records_cost_and_frees_slot() {
    let (c, _) = core(Config::default());
    let t0 = Instant::now();
    // budget = 3 GiB * 1.25 - 1.6 GiB reserve = 2.15 GiB: one 1.5 GiB prior fits, not two
    let mut m = FakeMeasure {
        snap: free(3 * GIB),
        ..Default::default()
    };
    c.tick(&mut m, t0);
    let a = admitted(&acquire(&c, "cargo build", t0));
    let b = match acquire(&c, "cargo build", t0) {
        Response::Queued { id, .. } => id,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        c.handle(Request::Started { id: a, pid: 100 }, t0),
        Response::Ack
    );
    let r = c.handle(
        Request::Finished {
            id: a,
            peak_rss: 700 * MIB,
            exit_code: Some(0),
        },
        t0,
    );
    assert_eq!(r, Response::Ack);
    assert_eq!(c.estimate(&sig("cargo build")), 700 * MIB);
    c.tick(&mut m, t0 + Duration::from_millis(500));
    assert!(
        has_decision(&c, &format!("admitted #{b}")),
        "{:?}",
        decisions(&c)
    );
}

/// Two running jobs (pids 100 and 200); returns their ids.
fn two_running(c: &Core<FakeControl>, m: &mut FakeMeasure, t0: Instant) -> (TicketId, TicketId) {
    m.snap = free(8 * GIB);
    c.tick(m, t0);
    let a = admitted(&acquire(c, "cargo build", t0));
    let b = admitted(&acquire(c, "cargo test", t0));
    c.handle(Request::Started { id: a, pid: 100 }, t0);
    c.handle(Request::Started { id: b, pid: 200 }, t0);
    (a, b)
}

#[test]
fn pressure_pauses_then_resumes() {
    let (c, ctl) = core(Config::default());
    let t0 = Instant::now();
    let mut m = FakeMeasure::default();
    let (_, b) = two_running(&c, &mut m, t0);
    // pressure threshold is 0.8 GiB; b grows by 900 MiB over the window
    for (i, (avail, rss_b)) in [(600, 100), (400, 500), (200, 1000)]
        .into_iter()
        .enumerate()
    {
        m.snap = free(avail * MIB);
        m.rss = HashMap::from([(100, 100 * MIB), (200, rss_b * MIB)]);
        c.tick(&mut m, t0 + Duration::from_millis(500 * i as u64));
    }
    assert_eq!(ctl.calls(), vec![("suspend", 200)]);
    assert!(
        has_decision(
            &c,
            &format!("paused #{b}: fastest grower: +900 MiB in window")
        ),
        "{:?}",
        decisions(&c)
    );
    // room again: 8 GiB free minus b's 1000 MiB peak is above the 1.6 GiB reserve
    m.snap = free(8 * GIB);
    c.tick(&mut m, t0 + Duration::from_secs(2));
    assert_eq!(ctl.calls(), vec![("suspend", 200), ("resume", 200)]);
    assert!(
        has_decision(&c, &format!("resumed #{b}")),
        "{:?}",
        decisions(&c)
    );
}

#[test]
fn shutdown_resumes_paused() {
    let ctl = FakeControl::default();
    let name = test_socket("shutdown");
    // a long tick keeps the background thread from resuming the job before shutdown does
    let cfg = Config {
        tick_ms: 60_000,
        ..Config::default()
    };
    let h = crate::run_with(
        cfg,
        &name,
        FakeMeasure {
            snap: free(8 * GIB),
            ..Default::default()
        },
        ctl.clone(),
        None,
        Arc::new(crate::OsLauncher::default()),
    )
    .unwrap();
    let t0 = Instant::now();
    let id = admitted(&acquire(&h.core, "cargo build", t0));
    h.core.handle(Request::Started { id, pid: 4242 }, t0);
    h.core.pause_for_test(id, t0);
    assert_eq!(ctl.calls(), vec![("suspend", 4242)]);
    h.shutdown();
    assert_eq!(ctl.calls(), vec![("suspend", 4242), ("resume", 4242)]);
}

fn test_socket(tag: &str) -> String {
    let n = format!("sync_gate-test-{}-{tag}", std::process::id());
    if cfg!(windows) {
        n
    } else {
        std::env::temp_dir().join(n).to_string_lossy().into_owned()
    }
}

fn temp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sync_gated-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

#[test]
fn store_roundtrip_and_atomic() {
    let dir = temp_dir("store");
    let path = dir.join("nested").join("cost.json");
    let mut m = CostModel::default();
    m.record(&sig("cargo build"), 900 * MIB);
    store::save(&path, &m).unwrap();
    let back = store::load(&path);
    assert_eq!(
        back.estimate(&sig("cargo build"), true),
        m.estimate(&sig("cargo build"), true)
    );
    assert!(!path.with_file_name("cost.json.tmp").exists());
    // missing file: default; corrupt file: default and moved aside
    assert_eq!(
        store::load(&dir.join("none.json"))
            .estimate(&sig("x"), true)
            .peak_bytes,
        PRIOR_HEAVY
    );
    std::fs::write(&path, "{not json").unwrap();
    assert_eq!(
        store::load(&path)
            .estimate(&sig("cargo build"), true)
            .peak_bytes,
        PRIOR_HEAVY
    );
    assert!(path.with_file_name("cost.json.bad").exists());
    assert!(!path.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn finished_persists_cost_model() {
    let dir = temp_dir("persist");
    let path = dir.join("cost.json");
    let c = Core::new(
        Config::default(),
        CostModel::default(),
        FakeControl::default(),
        Some(dir.clone()),
    );
    let t0 = Instant::now();
    c.tick(
        &mut FakeMeasure {
            snap: free(8 * GIB),
            ..Default::default()
        },
        t0,
    );
    let id = admitted(&acquire(&c, "cargo build", t0));
    c.handle(
        Request::Finished {
            id,
            peak_rss: 300 * MIB,
            exit_code: None,
        },
        t0,
    );
    assert_eq!(
        store::load(&path)
            .estimate(&sig("cargo build"), true)
            .peak_bytes,
        300 * MIB
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn r13a_gone_process_is_released_and_recorded() {
    let (c, _) = core(Config::default());
    let t0 = Instant::now();
    let mut m = FakeMeasure::default();
    let (a, _) = two_running(&c, &mut m, t0);
    m.rss = HashMap::from([(100, 400 * MIB), (200, 50 * MIB)]);
    c.tick(&mut m, t0 + Duration::from_millis(500));
    m.rss.remove(&100);
    c.tick(&mut m, t0 + Duration::from_secs(1));
    assert!(
        has_decision(&c, &format!("released #{a}")),
        "{:?}",
        decisions(&c)
    );
    assert_eq!(c.estimate(&sig("cargo build")), 400 * MIB);
    assert!(matches!(
        c.handle(Request::Started { id: a, pid: 1 }, t0),
        Response::Error { .. }
    ));
}

#[test]
fn r13b_admitted_but_never_started_is_released() {
    let (c, _) = core(Config::default());
    let t0 = Instant::now();
    let mut m = FakeMeasure {
        snap: free(8 * GIB),
        ..Default::default()
    };
    c.tick(&mut m, t0);
    let a = admitted(&acquire(&c, "cargo build", t0));
    c.tick(&mut m, t0 + Duration::from_secs(9));
    assert!(!has_decision(&c, &format!("released #{a}")));
    c.tick(&mut m, t0 + Duration::from_secs(11));
    assert!(
        has_decision(&c, &format!("released #{a}")),
        "{:?}",
        decisions(&c)
    );
}

#[test]
fn r13c_abandoned_queued_ticket_is_cancelled() {
    let cfg = Config {
        max_wait_secs: 10,
        ..Config::default()
    };
    let (c, _) = core(cfg);
    let t0 = Instant::now();
    let mut m = FakeMeasure {
        snap: free(GIB),
        ..Default::default()
    };
    c.tick(&mut m, t0);
    let Response::Queued { id, .. } = acquire(&c, "cargo build", t0) else {
        panic!()
    };
    c.tick(&mut m, t0 + Duration::from_secs(39));
    assert!(!has_decision(&c, &format!("cancelled #{id}")));
    c.tick(&mut m, t0 + Duration::from_secs(41));
    assert!(
        has_decision(&c, &format!("cancelled #{id}")),
        "{:?}",
        decisions(&c)
    );
    assert!(matches!(
        c.handle(
            Request::Wait {
                id,
                timeout_secs: None
            },
            t0
        ),
        Response::Error { .. }
    ));
}

#[test]
fn wait_times_out_to_queued() {
    let cfg = Config {
        max_wait_secs: 0,
        ..Config::default()
    };
    let (c, _) = core(cfg);
    let t0 = Instant::now();
    c.tick(
        &mut FakeMeasure {
            snap: free(GIB),
            ..Default::default()
        },
        t0,
    );
    let Response::Queued { id, .. } = acquire(&c, "cargo build", t0) else {
        panic!()
    };
    assert_eq!(
        c.handle(
            Request::Wait {
                id,
                timeout_secs: None
            },
            t0
        ),
        Response::Queued { id, position: 0 }
    );
    assert!(matches!(
        c.handle(
            Request::Wait {
                id: 999,
                timeout_secs: None
            },
            t0
        ),
        Response::Error { .. }
    ));
}

#[test]
fn wait_returns_admitted_when_a_tick_admits() {
    let (c, _) = core(Config::default());
    let c = Arc::new(c);
    let t0 = Instant::now();
    let mut m = FakeMeasure {
        snap: free(GIB),
        ..Default::default()
    };
    c.tick(&mut m, t0);
    let Response::Queued { id, .. } = acquire(&c, "cargo build", t0) else {
        panic!()
    };
    let waiter = {
        let c = c.clone();
        std::thread::spawn(move || {
            c.handle(
                Request::Wait {
                    id,
                    timeout_secs: None,
                },
                Instant::now(),
            )
        })
    };
    // tick until the waiter is registered, then free memory
    while !c.has_waiter(id) {
        std::thread::yield_now();
    }
    m.snap = free(8 * GIB);
    c.tick(&mut m, t0);
    assert_eq!(waiter.join().unwrap(), Response::Admitted { id });
}

#[test]
fn no_data_snapshot_neither_admits_nor_pauses() {
    let (c, ctl) = core(Config::default());
    let t0 = Instant::now();
    let mut m = FakeMeasure::default();
    let (_, _) = two_running(&c, &mut m, t0);
    m.snap = Some(snap(0, 0));
    m.rss = HashMap::from([(100, 100 * MIB), (200, 100 * MIB)]);
    for i in 0..6 {
        m.rss.insert(200, (100 + 300 * i) * MIB);
        c.tick(&mut m, t0 + Duration::from_millis(500 * i));
    }
    assert!(matches!(
        acquire(&c, "cargo build", t0),
        Response::Queued { .. }
    ));
    assert!(ctl.calls().is_empty());
}

#[test]
fn status_reports_running_queued_and_decisions() {
    let (c, _) = core(Config::default());
    let t0 = Instant::now();
    c.tick(
        &mut FakeMeasure {
            snap: free(3 * GIB),
            ..Default::default()
        },
        t0,
    );
    let a = admitted(&acquire(&c, "cargo build", t0));
    let Response::Queued { id: b, .. } = acquire(&c, "cargo test", t0) else {
        panic!()
    };
    let Response::Status(r) = c.handle(Request::Status, t0) else {
        panic!()
    };
    assert_eq!(r.running, vec![(a, sig("cargo build").key, 0)]);
    assert_eq!(r.queued, vec![(b, sig("cargo test").key, 0)]);
    assert!(r.decisions[0].starts_with('['), "{:?}", r.decisions);
    assert_eq!(r.snapshot.total, 16 * GIB);
}

// ---- fix round 1 ----

fn paused_ids(c: &Core<FakeControl>) -> Vec<TicketId> {
    match c.handle(Request::Status, Instant::now()) {
        Response::Status(r) => r.paused,
        other => panic!("{other:?}"),
    }
}

/// One running job (pid 100) paused through the real pause path.
fn one_paused(c: &Core<FakeControl>, m: &mut FakeMeasure, t0: Instant) -> TicketId {
    m.snap = free(8 * GIB);
    m.rss = HashMap::from([(100, 500 * MIB)]);
    c.tick(m, t0);
    let a = admitted(&acquire(c, "cargo build", t0));
    c.handle(Request::Started { id: a, pid: 100 }, t0);
    c.tick(m, t0);
    c.pause_for_test(a, t0);
    a
}

#[test]
fn r16_paused_job_holds_new_admissions() {
    let (c, _) = core(Config::default());
    let t0 = Instant::now();
    let mut m = FakeMeasure::default();
    let a = one_paused(&c, &mut m, t0);
    // pressure keeps it paused; plenty of budget for the scheduler would otherwise admit
    m.snap = free(700 * MIB);
    let Response::Queued { id: b, .. } = acquire(&c, "cargo test", t0) else {
        panic!("admitted while #{a} is paused")
    };
    c.tick(&mut m, t0 + Duration::from_millis(500));
    acquire(&c, "cargo check", t0);
    let held = decisions(&c)
        .iter()
        .filter(|d| d.contains("admission held"))
        .count();
    assert_eq!(held, 1, "{:?}", decisions(&c));
    assert!(!has_decision(&c, &format!("admitted #{b}")));
    // memory back: a resumes, then b is admitted on a later tick
    m.snap = free(8 * GIB);
    c.tick(&mut m, t0 + Duration::from_secs(1));
    c.tick(&mut m, t0 + Duration::from_millis(1500));
    assert!(
        has_decision(&c, &format!("resumed #{a}")),
        "{:?}",
        decisions(&c)
    );
    assert!(
        has_decision(&c, &format!("admitted #{b}")),
        "{:?}",
        decisions(&c)
    );
}

#[test]
fn r16_resume_does_not_subtract_the_paused_peak() {
    let (c, ctl) = core(Config::default());
    let t0 = Instant::now();
    let mut m = FakeMeasure::default();
    let a = one_paused(&c, &mut m, t0);
    // 1.7 GiB free >= 1.6 GiB reserve, although free minus a's 500 MiB peak is not
    m.snap = free(1700 * MIB);
    c.tick(&mut m, t0 + Duration::from_secs(1));
    assert_eq!(ctl.calls(), vec![("suspend", 100), ("resume", 100)]);
    assert!(paused_ids(&c).is_empty(), "#{a} still paused");
}

#[test]
fn r16_max_pause_resumes_anyway() {
    let (c, ctl) = core(Config::default());
    let t0 = Instant::now();
    let mut m = FakeMeasure::default();
    let a = one_paused(&c, &mut m, t0);
    m.snap = free(300 * MIB); // still under pressure
    c.tick(&mut m, t0 + Duration::from_secs(299));
    assert_eq!(paused_ids(&c), vec![a]);
    c.tick(&mut m, t0 + Duration::from_secs(301));
    assert!(
        has_decision(&c, &format!("resumed #{a} after max pause (300 s)")),
        "{:?}",
        decisions(&c)
    );
    assert_eq!(ctl.calls(), vec![("suspend", 100), ("resume", 100)]);
}

#[test]
fn failed_resume_keeps_job_paused_and_retries_next_tick() {
    let (c, ctl) = core(Config::default());
    let t0 = Instant::now();
    let mut m = FakeMeasure::default();
    let a = one_paused(&c, &mut m, t0);
    ctl.fail_next_resumes(1);
    m.snap = free(8 * GIB);
    c.tick(&mut m, t0 + Duration::from_secs(1));
    assert_eq!(paused_ids(&c), vec![a]);
    assert!(
        has_decision(&c, &format!("resume #{a} failed")),
        "{:?}",
        decisions(&c)
    );
    c.tick(&mut m, t0 + Duration::from_millis(1500));
    assert!(paused_ids(&c).is_empty());
    assert_eq!(
        ctl.calls(),
        vec![("suspend", 100), ("resume-failed", 100), ("resume", 100)]
    );
}

#[test]
fn paused_token_is_resumed_on_finished_cancel_and_gone() {
    for how in ["finished", "gone"] {
        let (c, ctl) = core(Config::default());
        let t0 = Instant::now();
        let mut m = FakeMeasure::default();
        let a = one_paused(&c, &mut m, t0);
        match how {
            "finished" => {
                let r = c.handle(
                    Request::Finished {
                        id: a,
                        peak_rss: 0,
                        exit_code: None,
                    },
                    t0,
                );
                assert_eq!(r, Response::Ack);
            }
            _ => {
                m.rss.clear();
                m.snap = free(300 * MIB); // under pressure: only the reaper may resume
                c.tick(&mut m, t0 + Duration::from_secs(1));
            }
        }
        assert_eq!(
            ctl.calls(),
            vec![("suspend", 100), ("resume", 100)],
            "{how}"
        );
    }
}

#[test]
fn paused_set_is_persisted_on_pause_and_cleared_on_resume() {
    let dir = temp_dir("paused");
    let ctl = FakeControl::default();
    let c = Core::new(
        Config::default(),
        CostModel::default(),
        ctl.clone(),
        Some(dir.clone()),
    );
    let t0 = Instant::now();
    let mut m = FakeMeasure::default();
    one_paused(&c, &mut m, t0);
    let file = dir.join("paused.json");
    let saved = sync_gate_probe::load_record(&file).unwrap().unwrap();
    assert_eq!(saved.units, vec![(100, 0, 1100)]);
    assert!(saved.intents.is_empty());
    m.snap = free(8 * GIB);
    c.tick(&mut m, t0 + Duration::from_secs(1));
    let saved = sync_gate_probe::load_record(&file).unwrap().unwrap();
    assert_eq!(saved, sync_gate_probe::PausedRecord::default());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn r15_reused_pid_is_skipped_matching_unit_is_resumed() {
    let units = vec![
        FrozenUnit {
            pid: 1,
            tid: 10,
            start_time: 111,
        },
        FrozenUnit {
            pid: 2,
            tid: 20,
            start_time: 222,
        },
        FrozenUnit {
            pid: 3,
            tid: 30,
            start_time: 333,
        },
    ];
    let now_running = HashMap::from([(1, 111), (2, 999)]); // 2 was reused, 3 is gone
    let live = still_ours(units.clone(), |pid| now_running.get(&pid).copied());
    assert_eq!(live, vec![units[0]]);
}

#[test]
fn r15_startup_resumes_units_left_by_a_previous_run() {
    let dir = temp_dir("recover");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("paused.json"), "[[4242,0,111],[4343,0,222]]").unwrap();
    let ctl = FakeControl::default();
    ctl.starts
        .lock()
        .unwrap()
        .extend([(4242, 111), (4343, 999)]);
    let c = Core::new(
        Config::default(),
        CostModel::default(),
        ctl.clone(),
        Some(dir.clone()),
    );
    c.recover_paused(Instant::now());
    assert_eq!(ctl.calls(), vec![("resume", 4242)]);
    assert!(
        has_decision(&c, "resumed 1 units left paused by a previous run"),
        "{:?}",
        decisions(&c)
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("paused.json")).unwrap(),
        r#"{"units":[],"intents":[]}"#
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn r17_timed_out_wait_makes_ticket_dormant_until_waited_again() {
    let cfg = Config {
        max_wait_secs: 0,
        ..Config::default()
    };
    let (c, _) = core(cfg);
    let t0 = Instant::now();
    let mut m = FakeMeasure {
        snap: free(GIB),
        ..Default::default()
    };
    c.tick(&mut m, t0);
    let Response::Queued { id, .. } = acquire(&c, "cargo build", t0) else {
        panic!()
    };
    assert_eq!(
        c.handle(
            Request::Wait {
                id,
                timeout_secs: None
            },
            t0
        ),
        Response::Queued { id, position: 0 }
    );
    // room appears, but nobody waits: a dormant ticket is never admitted
    m.snap = free(8 * GIB);
    c.tick(&mut m, t0 + Duration::from_secs(1));
    assert!(
        !has_decision(&c, &format!("admitted #{id}")),
        "{:?}",
        decisions(&c)
    );
    // `sync_gate wait N`: re-enqueued with its original age and admitted
    assert_eq!(
        c.handle(
            Request::Wait {
                id,
                timeout_secs: None
            },
            t0
        ),
        Response::Admitted { id }
    );
}

#[test]
fn r17_dormant_ticket_expires_after_a_day() {
    let cfg = Config {
        max_wait_secs: 0,
        ..Config::default()
    };
    let (c, _) = core(cfg);
    let t0 = Instant::now();
    let mut m = FakeMeasure {
        snap: free(GIB),
        ..Default::default()
    };
    c.tick(&mut m, t0);
    let Response::Queued { id, .. } = acquire(&c, "cargo build", t0) else {
        panic!()
    };
    c.handle(
        Request::Wait {
            id,
            timeout_secs: None,
        },
        t0,
    );
    c.tick(&mut m, t0 + Duration::from_secs(23 * 3600));
    assert!(!has_decision(&c, &format!("expired #{id}")));
    c.tick(&mut m, t0 + Duration::from_secs(25 * 3600));
    assert!(
        has_decision(&c, &format!("expired #{id}")),
        "{:?}",
        decisions(&c)
    );
    assert!(matches!(
        c.handle(
            Request::Wait {
                id,
                timeout_secs: None
            },
            t0
        ),
        Response::Error { .. }
    ));
}

#[cfg(unix)]
#[test]
fn a_readable_pending_folder_is_tightened_at_start() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_dir("pending-mode");
    let pending = dir.join("pending");
    std::fs::create_dir_all(&pending).unwrap();
    std::fs::set_permissions(&pending, std::fs::Permissions::from_mode(0o755)).unwrap();
    let h = crate::run_with(
        Config {
            tick_ms: 60_000,
            ..Config::default()
        },
        &test_socket("pending-mode"),
        FakeMeasure {
            snap: free(8 * GIB),
            ..Default::default()
        },
        FakeControl::default(),
        Some(dir.clone()),
        Arc::new(crate::OsLauncher::default()),
    )
    .unwrap();
    let mode = std::fs::metadata(&pending).unwrap().permissions().mode() & 0o777;
    h.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(mode, 0o700);
}

// ---- fix round 2 ----

#[test]
fn second_daemon_fails_before_touching_the_paused_state() {
    let dir = temp_dir("single");
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = Config {
        tick_ms: 60_000,
        ..Config::default()
    };
    let measure = || FakeMeasure {
        snap: free(8 * GIB),
        ..Default::default()
    };
    let first = crate::run_with(
        cfg.clone(),
        &test_socket("single-a"),
        measure(),
        FakeControl::default(),
        Some(dir.clone()),
        Arc::new(crate::OsLauncher::default()),
    )
    .unwrap();
    // the live daemon's paused set, with a unit the second daemon would consider its own
    let paused = "[[4242,0,111]]";
    std::fs::write(dir.join("paused.json"), paused).unwrap();
    let ctl2 = FakeControl::default();
    ctl2.starts.lock().unwrap().insert(4242, 111);
    // A short retry window: a live daemon never lets go, so the full 2 s would only slow the test.
    let second = crate::run_with_lock_wait(
        cfg.clone(),
        &test_socket("single-b"),
        measure(),
        ctl2.clone(),
        Some(dir.clone()),
        Arc::new(crate::OsLauncher::default()),
        Duration::from_millis(100),
    );
    assert_eq!(
        second.err().map(|e| e.kind()),
        Some(io::ErrorKind::AddrInUse)
    );
    assert!(ctl2.calls().is_empty(), "{:?}", ctl2.calls());
    assert_eq!(
        std::fs::read_to_string(dir.join("paused.json")).unwrap(),
        paused
    );
    first.shutdown();
    // the guard is released with the first daemon
    let third = crate::run_with(
        cfg,
        &test_socket("single-c"),
        measure(),
        FakeControl::default(),
        Some(dir.clone()),
        Arc::new(crate::OsLauncher::default()),
    )
    .unwrap();
    third.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn resumed_job_is_not_a_victim_during_cooldown() {
    let (c, ctl) = core(Config::default());
    let t0 = Instant::now();
    let mut m = FakeMeasure::default();
    one_paused(&c, &mut m, t0);
    let suspends = |ctl: &FakeControl| ctl.calls().iter().filter(|c| c.0 == "suspend").count();
    // under growing pressure; the 300 s max pause resumes it at 301 s
    let mut k = 0u64;
    let mut step = |m: &mut FakeMeasure, at: Duration| {
        k += 1;
        m.snap = free((700 - 10 * k) * MIB);
        m.rss = HashMap::from([(100, (600 + 100 * k) * MIB)]);
        c.tick(m, t0 + at);
    };
    for ms in (301_000..=304_000).step_by(500) {
        step(&mut m, Duration::from_millis(ms));
    }
    assert!(paused_ids(&c).is_empty());
    assert_eq!(suspends(&ctl), 1, "paused again inside the cooldown");
    for ms in (362_000..=364_000).step_by(500) {
        step(&mut m, Duration::from_millis(ms));
    }
    assert_eq!(suspends(&ctl), 2, "{:?}", decisions(&c));
}

#[test]
fn failing_resume_is_logged_once_per_30s_but_retried_every_tick() {
    let (c, ctl) = core(Config::default());
    let t0 = Instant::now();
    let mut m = FakeMeasure::default();
    let a = one_paused(&c, &mut m, t0);
    ctl.fail_next_resumes(1000);
    m.snap = free(8 * GIB);
    let ticks = 39;
    for i in 0..ticks {
        c.tick(&mut m, t0 + Duration::from_millis(1000 + 500 * i));
    }
    let logged = |c: &Core<FakeControl>| {
        decisions(c)
            .iter()
            .filter(|d| d.contains(&format!("resume #{a} failed")))
            .count()
    };
    assert_eq!(logged(&c), 1, "{:?}", decisions(&c));
    let tries = ctl
        .calls()
        .iter()
        .filter(|c| c.0 == "resume-failed")
        .count();
    assert_eq!(tries, ticks as usize);
    c.tick(&mut m, t0 + Duration::from_secs(32));
    assert_eq!(logged(&c), 2);
    assert_eq!(paused_ids(&c), vec![a]);
}

#[test]
fn recovery_reports_failed_units_separately() {
    let dir = temp_dir("recover-fail");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("paused.json"), "[[4242,0,111]]").unwrap();
    let ctl = FakeControl::default();
    ctl.starts.lock().unwrap().insert(4242, 111);
    ctl.fail_next_resumes(1);
    let c = Core::new(
        Config::default(),
        CostModel::default(),
        ctl.clone(),
        Some(dir.clone()),
    );
    c.recover_paused(Instant::now());
    assert!(
        has_decision(
            &c,
            "resumed 0 units left paused by a previous run; 1 failed, retrying"
        ),
        "{:?}",
        decisions(&c)
    );
    // the failed unit stays recorded until a retry succeeds
    assert_eq!(
        std::fs::read_to_string(dir.join("paused.json")).unwrap(),
        r#"{"units":[[4242,0,111]],"intents":[]}"#
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wait_timeout_secs_caps_the_daemon_wait_and_goes_dormant() {
    // max_wait is 90 s: without the cap this call would block for a minute and a half.
    let (c, _) = core(Config::default());
    let t0 = Instant::now();
    let mut m = FakeMeasure {
        snap: free(GIB),
        ..Default::default()
    };
    c.tick(&mut m, t0);
    let Response::Queued { id, .. } = acquire(&c, "cargo build", t0) else {
        panic!()
    };
    assert_eq!(
        c.handle(
            Request::Wait {
                id,
                timeout_secs: Some(0)
            },
            t0
        ),
        Response::Queued { id, position: 0 }
    );
    m.snap = free(8 * GIB);
    c.tick(&mut m, t0 + Duration::from_secs(1));
    assert!(!has_decision(&c, &format!("admitted #{id}")), "dormant");
}

#[test]
fn ticket_ids_start_at_unix_millis() {
    // Read before the core exists: the id base is taken in `Core::new`.
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let (c, _) = core(Config::default());
    let t0 = Instant::now();
    let Response::Queued { id: a, .. } = acquire(&c, "cargo build", t0) else {
        panic!()
    };
    let Response::Queued { id: b, .. } = acquire(&c, "cargo test", t0) else {
        panic!()
    };
    assert!(a >= before, "{a} < {before}");
    assert_eq!(b, a + 1);
}

/// A queued ticket admitted by a tick, with nobody waiting on it yet.
fn admitted_unclaimed(c: &Core<FakeControl>, t0: Instant) -> TicketId {
    let mut m = FakeMeasure {
        snap: free(GIB),
        ..Default::default()
    };
    c.tick(&mut m, t0);
    let Response::Queued { id, .. } = acquire(c, "cargo build", t0) else {
        panic!()
    };
    m.snap = free(8 * GIB);
    c.tick(&mut m, t0);
    assert!(has_decision(c, &format!("admitted #{id}")));
    id
}

#[test]
fn admitted_ticket_is_handed_to_exactly_one_waiter() {
    let (c, _) = core(Config::default());
    let c = Arc::new(c);
    let id = admitted_unclaimed(&c, Instant::now());
    let waiters: Vec<_> = (0..2)
        .map(|_| {
            let c = c.clone();
            std::thread::spawn(move || {
                c.handle(
                    Request::Wait {
                        id,
                        timeout_secs: Some(1),
                    },
                    Instant::now(),
                )
            })
        })
        .collect();
    let replies: Vec<Response> = waiters.into_iter().map(|w| w.join().unwrap()).collect();
    let wins = replies
        .iter()
        .filter(|r| **r == Response::Admitted { id })
        .count();
    assert_eq!(wins, 1, "{replies:?}");
    assert!(
        replies.iter().any(|r| matches!(r,
            Response::Error { message } if message.contains("admitted to another client"))),
        "{replies:?}"
    );
    // A ticket admitted straight from Acquire already belongs to that client.
    let (c, _) = core(Config::default());
    let t0 = Instant::now();
    c.tick(
        &mut FakeMeasure {
            snap: free(8 * GIB),
            ..Default::default()
        },
        t0,
    );
    let a = admitted(&acquire(&c, "cargo build", t0));
    let wait = Request::Wait {
        id: a,
        timeout_secs: Some(0),
    };
    assert!(matches!(c.handle(wait, t0), Response::Error { .. }));
}

#[test]
fn huge_wait_timeouts_do_not_overflow() {
    let cfg = Config {
        max_wait_secs: u64::MAX,
        ..Config::default()
    };
    let (c, _) = core(cfg);
    let t0 = Instant::now();
    let id = admitted_unclaimed(&c, t0);
    let wait = Request::Wait {
        id,
        timeout_secs: Some(u64::MAX),
    };
    assert_eq!(c.handle(wait, t0), Response::Admitted { id });
}

#[test]
fn units_left_frozen_by_a_failed_pause_are_resumed_next_tick() {
    let (c, ctl) = core(Config::default());
    let t0 = Instant::now();
    let mut m = FakeMeasure::default();
    *ctl.fail_suspend.lock().unwrap() = true;
    let a = one_paused(&c, &mut m, t0);
    assert!(has_decision(&c, &format!("pause #{a} failed")));
    assert!(paused_ids(&c).is_empty());
    m.snap = free(300 * MIB); // still under pressure: only the orphan retry may resume
    c.tick(&mut m, t0 + Duration::from_millis(500));
    assert_eq!(ctl.calls(), vec![("suspend-failed", 100), ("resume", 100)]);
}

#[test]
fn cancel_spares_claimed_jobs_before_and_after_started() {
    let (c, _) = core(Config::default());
    let t0 = Instant::now();
    let mut m = FakeMeasure {
        snap: free(8 * GIB),
        ..Default::default()
    };
    c.tick(&mut m, t0);
    let started = admitted(&acquire(&c, "cargo build", t0));
    let unstarted = admitted(&acquire(&c, "cargo test", t0));
    assert_eq!(
        c.handle(
            Request::Started {
                id: started,
                pid: 100
            },
            t0
        ),
        Response::Ack
    );
    let Response::Error { message } = c.handle(Request::Cancel { id: started }, t0) else {
        panic!("a started job must not be cancelled")
    };
    assert_eq!(
        c.handle(Request::Cancel { id: unstarted }, t0),
        Response::Error {
            message: format!("ticket {unstarted} already admitted; it ends with Finished")
        }
    );
    assert_eq!(
        message,
        format!("ticket {started} already admitted; it ends with Finished")
    );
    let Response::Status(s) = c.handle(Request::Status, t0) else {
        panic!()
    };
    let running: Vec<_> = s.running.iter().map(|r| r.0).collect();
    assert_eq!(running, vec![started, unstarted]);
}

#[test]
fn cancel_releases_an_admission_before_delivery() {
    let (c, _) = core(Config::default());
    let now = Instant::now();
    let Response::Queued { id, .. } = acquire(&c, "cargo build", now) else {
        panic!()
    };
    c.tick(
        &mut FakeMeasure {
            snap: free(8 * GIB),
            ..Default::default()
        },
        now,
    );
    assert_eq!(c.handle(Request::Cancel { id }, now), Response::Ack);
    let Response::Status(s) = c.handle(Request::Status, now) else {
        panic!()
    };
    assert!(s.running.is_empty());
}

fn shutdown_during_finished_resume(at_bound: bool) {
    let dir = temp_dir(if at_bound {
        "inflight-bound"
    } else {
        "inflight-wait"
    });
    let ctl = FakeControl::default();
    let h = crate::run_with(
        Config {
            tick_ms: 60_000,
            ..Config::default()
        },
        &test_socket(if at_bound {
            "inflight-bound"
        } else {
            "inflight-wait"
        }),
        FakeMeasure::default(),
        ctl.clone(),
        Some(dir.clone()),
        Arc::new(crate::OsLauncher::default()),
    )
    .unwrap();
    let c = h.core.clone();
    let bound = Duration::from_millis(300);
    c.set_drain_bound(bound);
    let id = one_paused(&c, &mut FakeMeasure::default(), Instant::now());
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    *ctl.block_resume.lock().unwrap() = Some(ResumeBlock {
        entered: entered_tx,
        release: release_rx,
    });
    let handler = {
        let c = c.clone();
        std::thread::spawn(move || {
            c.handle(
                Request::Finished {
                    id,
                    peak_rss: 0,
                    exit_code: None,
                },
                Instant::now(),
            )
        })
    };
    entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let (stopped_tx, stopped_rx) = std::sync::mpsc::channel();
    let start = Instant::now();
    let shutdown = std::thread::spawn(move || {
        h.shutdown();
        stopped_tx.send(()).unwrap();
    });
    // The bound is injected, so the generous 5 s only fails a shutdown that ignores it.
    let stopped = stopped_rx.recv_timeout(if at_bound {
        Duration::from_secs(5)
    } else {
        Duration::from_millis(150)
    });
    let elapsed = start.elapsed();
    let during = sync_gate_probe::load_paused(&dir.join("paused.json")).unwrap();
    // Always release and join before asserting, including on a regression.
    release_tx.send(()).unwrap();
    // Waiting case: shutdown must return promptly once the blocked resume is released.
    let prompt = at_bound || stopped_rx.recv_timeout(Duration::from_secs(2)).is_ok();
    assert_eq!(handler.join().unwrap(), Response::Ack);
    shutdown.join().unwrap();
    let after = sync_gate_probe::load_paused(&dir.join("paused.json")).unwrap();
    std::fs::remove_dir_all(dir).unwrap();
    assert_eq!(
        during.len(),
        1,
        "the recovery record disappeared during resume"
    );
    // Past the bound the record is final: the instance lock is released with the shutdown, so
    // the late resume must not rewrite it; the next recoverer finds the unit (resumed or not).
    assert_eq!(after.len(), usize::from(at_bound));
    assert!(
        prompt,
        "shutdown did not return after the resume was released"
    );
    if at_bound {
        assert!(stopped.is_ok(), "shutdown ignored its bound");
        assert!(elapsed >= bound, "{elapsed:?}");
    } else {
        assert!(
            stopped.is_err(),
            "shutdown returned before the resume completed"
        );
    }
}

#[test]
fn shutdown_waits_for_finished_resume_and_preserves_its_record() {
    shutdown_during_finished_resume(false);
}

#[test]
fn shutdown_bounds_a_stuck_finished_resume_and_keeps_its_record() {
    shutdown_during_finished_resume(true);
}

#[test]
fn unwinding_resume_preserves_units_for_shutdown_recovery() {
    let dir = temp_dir("inflight-panic");
    let ctl = FakeControl::default();
    let c = Arc::new(Core::new(
        Config::default(),
        CostModel::default(),
        ctl.clone(),
        Some(dir.clone()),
    ));
    let id = one_paused(&c, &mut FakeMeasure::default(), Instant::now());
    ctl.panic_resume
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let handler = {
        let c = c.clone();
        std::thread::spawn(move || {
            c.handle(
                Request::Finished {
                    id,
                    peak_rss: 0,
                    exit_code: None,
                },
                Instant::now(),
            )
        })
    };
    assert!(handler.join().is_err());
    let during = sync_gate_probe::load_paused(&dir.join("paused.json")).unwrap();
    c.resume_all(Instant::now());
    assert!(c.finish_resumes(Instant::now() + Duration::from_secs(5)));
    let after = sync_gate_probe::load_paused(&dir.join("paused.json")).unwrap();
    std::fs::remove_dir_all(dir).unwrap();
    assert_eq!(during.len(), 1);
    assert!(after.is_empty());
    assert_eq!(ctl.calls(), vec![("suspend", 100), ("resume", 100)]);
}

#[test]
fn a_corrupt_paused_file_at_start_is_quarantined_not_overwritten() {
    let dir = temp_dir("corrupt-paused");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("paused.json"), "not json").unwrap();
    let c = Core::new(
        Config::default(),
        CostModel::default(),
        FakeControl::default(),
        Some(dir.clone()),
    );
    c.recover_paused(Instant::now());
    let bad = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.to_string_lossy().contains("paused.json.bad-"))
        .expect("quarantined file");
    let bad = std::fs::read_to_string(bad).unwrap();
    assert_eq!(bad, "not json");
    assert!(!dir.join("paused.json").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- fix round 3 ----

#[test]
fn status_tells_the_cli_who_and_where_the_daemon_is() {
    let dir = temp_dir("identity");
    let c = Core::new(
        Config::default(),
        CostModel::default(),
        FakeControl::default(),
        Some(dir.clone()),
    );
    let Response::Status(s) = c.handle(Request::Status, Instant::now()) else {
        panic!()
    };
    assert_eq!(s.daemon.pid, std::process::id());
    assert_eq!(
        Some(s.daemon.start_time),
        sync_gate_probe::start_time(std::process::id())
    );
    assert!(s.daemon.start_time > 0);
    assert_eq!(s.daemon.data_dir, Some(dir));
    let (c, _) = core(Config::default());
    let Response::Status(s) = c.handle(Request::Status, Instant::now()) else {
        panic!()
    };
    assert_eq!(s.daemon.data_dir, None);
}

fn record_on_disk(dir: &Path) -> sync_gate_probe::PausedRecord {
    sync_gate_probe::load_record(&dir.join("paused.json"))
        .unwrap()
        .unwrap_or_default()
}

#[test]
fn the_intent_is_on_disk_before_suspend_and_replaced_by_the_units_after() {
    let dir = temp_dir("intent");
    let ctl = FakeControl::default();
    *ctl.watch.lock().unwrap() = Some(dir.join("paused.json"));
    let c = Core::new(
        Config::default(),
        CostModel::default(),
        ctl.clone(),
        Some(dir.clone()),
    );
    one_paused(&c, &mut FakeMeasure::default(), Instant::now());
    let seen = ctl.seen_at_suspend.lock().unwrap().clone();
    let at_suspend: Vec<sync_gate_probe::PausedRecord> = seen
        .iter()
        .map(|t| serde_json::from_str(t).unwrap())
        .collect();
    assert_eq!(
        at_suspend,
        vec![sync_gate_probe::PausedRecord {
            units: Vec::new(),
            intents: vec![(100, 1100)],
        }],
        "{seen:?}"
    );
    assert_eq!(
        record_on_disk(&dir),
        sync_gate_probe::PausedRecord {
            units: vec![(100, 0, 1100)],
            intents: Vec::new(),
        }
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_pause_that_cannot_be_recorded_never_suspends() {
    // The data dir is a regular file: no record can be written under it.
    let base = temp_dir("unrecordable");
    std::fs::create_dir_all(&base).unwrap();
    let blocker = base.join("blocker");
    std::fs::write(&blocker, "").unwrap();
    let ctl = FakeControl::default();
    let c = Core::new(
        Config::default(),
        CostModel::default(),
        ctl.clone(),
        Some(blocker.clone()),
    );
    let id = one_paused(&c, &mut FakeMeasure::default(), Instant::now());
    assert!(ctl.calls().is_empty(), "{:?}", ctl.calls());
    assert!(paused_ids(&c).is_empty());
    assert!(
        has_decision(&c, &format!("not pausing #{id}: cannot record the pause (")),
        "{:?}",
        decisions(&c)
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn startup_recovery_runs_the_shared_pass_over_units_and_intents() {
    let dir = temp_dir("shared-pass");
    std::fs::create_dir_all(&dir).unwrap();
    let record = r#"{"units":[[4242,0,111]],"intents":[[5050,555],[6060,666]]}"#;
    std::fs::write(dir.join("paused.json"), record).unwrap();
    let ctl = FakeControl::default();
    // 6060 was reused by another process: its stale intent is dropped untouched.
    ctl.starts
        .lock()
        .unwrap()
        .extend([(4242, 111), (5050, 555), (6060, 999)]);
    let c = Core::new(
        Config::default(),
        CostModel::default(),
        ctl.clone(),
        Some(dir.clone()),
    );
    c.recover_paused(Instant::now());
    assert_eq!(ctl.calls(), vec![("resume", 4242), ("resume-tree", 5050)]);
    assert!(
        has_decision(&c, "resumed 2 units left paused by a previous run"),
        "{:?}",
        decisions(&c)
    );
    assert_eq!(
        record_on_disk(&dir),
        sync_gate_probe::PausedRecord::default()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_failed_intent_from_a_previous_run_stays_recorded_and_is_retried_each_period() {
    let dir = temp_dir("stale-intent");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("paused.json"), r#"{"intents":[[5050,555]]}"#).unwrap();
    let ctl = FakeControl::default();
    ctl.starts.lock().unwrap().insert(5050, 555);
    *ctl.fail_trees.lock().unwrap() = 1;
    let c = Core::new(
        Config::default(),
        CostModel::default(),
        ctl.clone(),
        Some(dir.clone()),
    );
    c.set_leftover_retry(Duration::from_secs(60), Duration::ZERO);
    c.recover_paused(Instant::now());
    assert_eq!(record_on_disk(&dir).intents, vec![(5050, 555)]);
    c.tick(&mut FakeMeasure::default(), Instant::now());
    assert_eq!(
        ctl.calls(),
        vec![("resume-tree-failed", 5050), ("resume-tree", 5050)]
    );
    assert_eq!(
        record_on_disk(&dir),
        sync_gate_probe::PausedRecord::default()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A core with a leftover intent (5050) that never resumes, started at `t0`.
fn core_with_leftover(tag: &str, t0: Instant) -> (Core<FakeControl>, FakeControl, PathBuf) {
    let dir = temp_dir(tag);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("paused.json"), r#"{"intents":[[5050,555]]}"#).unwrap();
    let ctl = FakeControl::default();
    ctl.starts.lock().unwrap().insert(5050, 555);
    *ctl.fail_trees.lock().unwrap() = u32::MAX;
    let c = Core::new(
        Config::default(),
        CostModel::default(),
        ctl.clone(),
        Some(dir.clone()),
    );
    c.set_leftover_retry(Duration::from_secs(3), Duration::from_secs(1));
    c.recover_paused(t0);
    (c, ctl, dir)
}

fn tree_calls(ctl: &FakeControl) -> usize {
    ctl.calls()
        .iter()
        .filter(|c| c.0.starts_with("resume-tree"))
        .count()
}

#[test]
fn leftovers_are_retried_once_a_period_for_the_window_then_they_stay_on_record() {
    let t0 = Instant::now();
    let (c, ctl, dir) = core_with_leftover("leftover-window", t0);
    let mut m = FakeMeasure::default();
    assert_eq!(tree_calls(&ctl), 1, "the start-up pass");
    // Two ticks inside one period: a single retry.
    c.tick(&mut m, t0 + Duration::from_millis(100));
    c.tick(&mut m, t0 + Duration::from_millis(900));
    assert_eq!(tree_calls(&ctl), 1);
    c.tick(&mut m, t0 + Duration::from_secs(1));
    c.tick(&mut m, t0 + Duration::from_secs(2));
    assert_eq!(tree_calls(&ctl), 3);
    // The window (3 s) ends: one line, no more retries, however long the daemon lives.
    for s in 3..60 {
        c.tick(&mut m, t0 + Duration::from_secs(s));
    }
    assert_eq!(tree_calls(&ctl), 3);
    let line = crate::control_loop::leftovers_stay(1);
    let lines = decisions(&c).iter().filter(|d| d.ends_with(&line)).count();
    assert_eq!(lines, 1, "{:?}", decisions(&c));
    assert_eq!(record_on_disk(&dir).intents, vec![(5050, 555)]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn no_leftover_retry_while_this_daemon_holds_a_paused_job_and_the_record_keeps_them() {
    let t0 = Instant::now();
    let (c, ctl, dir) = core_with_leftover("leftover-paused", t0);
    c.set_leftover_retry(Duration::from_secs(60), Duration::from_secs(1));
    let mut m = FakeMeasure::default();
    let a = one_paused(&c, &mut m, t0);
    let before = tree_calls(&ctl);
    // Still under pressure: the job stays paused, and the retry waits.
    m.snap = free(700 * MIB);
    for s in 2..8 {
        c.tick(&mut m, t0 + Duration::from_secs(s));
    }
    assert_eq!(paused_ids(&c), vec![a]);
    assert_eq!(tree_calls(&ctl), before, "a retry while a job is paused");
    // The daemon's own pause record keeps the leftover intent.
    let rec = record_on_disk(&dir);
    assert_eq!(rec.intents, vec![(5050, 555)]);
    assert_eq!(rec.units, vec![(100, 0, 1100)]);
    // The job is resumed: the retry may run again.
    m.snap = free(8 * GIB);
    c.tick(&mut m, t0 + Duration::from_secs(9));
    c.tick(&mut m, t0 + Duration::from_secs(11));
    assert!(tree_calls(&ctl) > before);
    // And after a shutdown the leftover is still on record.
    c.resume_all(t0 + Duration::from_secs(12));
    assert_eq!(c.close(), 0);
    assert_eq!(record_on_disk(&dir).intents, vec![(5050, 555)]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_start_waits_out_a_brief_recovery_pass_but_not_a_live_daemon() {
    let dir = temp_dir("lock-wait");
    std::fs::create_dir_all(&dir).unwrap();
    let hold = |dir: &Path| {
        sync_gate_probe::try_lock(
            std::fs::File::create(dir.join(sync_gate_probe::LOCK_FILE)).unwrap(),
            true,
        )
        .unwrap()
        .expect("free")
    };
    // A brief holder (a recovery pass) releases after 60 ms: the start succeeds.
    let brief = hold(&dir);
    let releaser = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(60));
        drop(brief);
    });
    let started = Instant::now();
    let lock = store::lock_instance_within(&dir, Duration::from_secs(2)).unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
    releaser.join().unwrap();
    // A holder that never lets go (a live daemon): AddrInUse once the window ends.
    let started = Instant::now();
    let second = store::lock_instance_within(&dir, Duration::from_millis(100));
    assert_eq!(
        second.err().map(|e| e.kind()),
        Some(io::ErrorKind::AddrInUse)
    );
    assert!(started.elapsed() >= Duration::from_millis(100));
    drop(lock);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Where shutdown meets a resume that never returns on its own.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Blocked {
    Nothing,
    /// The tick thread is inside a resume when shutdown starts.
    InTick,
    /// The resume started by shutdown's own `resume_all` blocks.
    InResumeAll,
}

fn shutdown_with(blocked: Blocked) {
    let tag = format!("bounded-{blocked:?}");
    let dir = temp_dir(&tag);
    let ctl = FakeControl::default();
    let cfg = Config {
        tick_ms: if blocked == Blocked::InTick {
            20
        } else {
            60_000
        },
        ..Config::default()
    };
    let measure = FakeMeasure {
        snap: free(8 * GIB),
        rss: HashMap::from([(4242, GIB)]),
        starts: HashMap::new(),
    };
    let h = crate::run_with(
        cfg,
        &test_socket(&tag),
        measure,
        ctl.clone(),
        Some(dir.clone()),
        Arc::new(crate::OsLauncher::default()),
    )
    .unwrap();
    let bound = Duration::from_millis(200);
    h.core.set_drain_bound(bound);
    let t0 = Instant::now();
    let id = admitted(&acquire(&h.core, "cargo build", t0));
    h.core.handle(Request::Started { id, pid: 4242 }, t0);
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    if blocked != Blocked::Nothing {
        *ctl.block_resume.lock().unwrap() = Some(ResumeBlock {
            entered: entered_tx,
            release: release_rx,
        });
    }
    h.core.pause_for_test(id, t0);
    if blocked == Blocked::InTick {
        // Memory is back: the next tick resumes the job and blocks inside that resume.
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    }
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let start = Instant::now();
    let shutdown = std::thread::spawn(move || {
        let _ = done_tx.send(h.shutdown_bounded());
    });
    let report = done_rx.recv_timeout(bound + Duration::from_secs(2));
    let elapsed = start.elapsed();
    let during = record_on_disk(&dir);
    // Always release and join before asserting, including on a regression.
    let _ = release_tx.send(());
    shutdown.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    match blocked {
        Blocked::Nothing => {
            assert_eq!(report, Ok(None));
            assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
            assert_eq!(during, sync_gate_probe::PausedRecord::default());
        }
        _ => {
            assert_eq!(report, Ok(Some(1)), "shutdown ignored its bound");
            assert!(elapsed >= bound, "{elapsed:?}");
            assert_eq!(
                during.units,
                vec![(4242, 0, 5242)],
                "the frozen unit is on record"
            );
        }
    }
}

#[test]
fn shutdown_returns_at_its_bound_while_a_tick_is_blocked_in_a_resume() {
    shutdown_with(Blocked::InTick);
}

#[test]
fn shutdown_returns_at_its_bound_while_its_own_resume_is_blocked() {
    shutdown_with(Blocked::InResumeAll);
}

#[test]
fn shutdown_with_nothing_blocked_is_prompt_and_leaves_an_empty_record() {
    shutdown_with(Blocked::Nothing);
}

#[test]
fn the_timeout_line_names_the_frozen_units() {
    assert_eq!(
        crate::shutdown_timed_out(3),
        "sync_gated: shutdown timed out with 3 unit(s) still frozen; they are recorded for recovery"
    );
}

#[test]
fn a_tick_blocked_in_one_resume_does_not_keep_shutdown_from_resuming_the_others() {
    let dir = temp_dir("blocked-tick-others");
    let ctl = FakeControl::default();
    let cfg = Config {
        tick_ms: 20,
        ..Config::default()
    };
    let measure = FakeMeasure {
        snap: free(8 * GIB),
        rss: HashMap::from([(4242, GIB), (4343, GIB)]),
        starts: HashMap::new(),
    };
    let h = crate::run_with(
        cfg,
        &test_socket("blocked-tick-others"),
        measure,
        ctl.clone(),
        Some(dir.clone()),
        Arc::new(crate::OsLauncher::default()),
    )
    .unwrap();
    let bound = Duration::from_millis(300);
    h.core.set_drain_bound(bound);
    let t0 = Instant::now();
    let a = admitted(&acquire(&h.core, "cargo build", t0));
    h.core.handle(Request::Started { id: a, pid: 4242 }, t0);
    let b = admitted(&acquire(&h.core, "cargo test", t0));
    h.core.handle(Request::Started { id: b, pid: 4343 }, t0);
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    *ctl.block_resume.lock().unwrap() = Some(ResumeBlock {
        entered: entered_tx,
        release: release_rx,
    });
    // Memory is back, so the tick resumes A at once and blocks inside that resume; B is
    // paused afterwards and nobody but shutdown will resume it.
    h.core.pause_for_test(a, t0);
    entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    h.core.pause_for_test(b, t0);
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let start = Instant::now();
    let shutdown = std::thread::spawn(move || {
        let _ = done_tx.send(h.shutdown_bounded());
    });
    let report = done_rx.recv_timeout(bound + Duration::from_secs(2));
    let elapsed = start.elapsed();
    let during = record_on_disk(&dir);
    let calls = ctl.calls();
    let _ = release_tx.send(());
    shutdown.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        calls.contains(&("resume", 4343)),
        "B stayed frozen: {calls:?}"
    );
    assert_eq!(report, Ok(Some(1)), "only A is left frozen");
    assert!(elapsed >= bound, "{elapsed:?}");
    assert_eq!(during.units, vec![(4242, 0, 5242)], "A is on record");
}

#[test]
fn the_daemon_does_not_pause_while_its_record_is_unreadable_and_pauses_again_after() {
    let dir = temp_dir("record-unavailable");
    std::fs::create_dir_all(dir.join("paused.json")).unwrap();
    let ctl = FakeControl::default();
    let c = Core::new(
        Config::default(),
        CostModel::default(),
        ctl.clone(),
        Some(dir.clone()),
    );
    let t0 = Instant::now();
    c.recover_paused(t0);
    let mut m = FakeMeasure {
        snap: free(8 * GIB),
        rss: HashMap::from([(100, 500 * MIB)]),
        starts: HashMap::new(),
    };
    c.tick(&mut m, t0);
    let a = admitted(&acquire(&c, "cargo build", t0));
    c.handle(Request::Started { id: a, pid: 100 }, t0);
    c.pause_for_test(a, t0);
    assert!(ctl.calls().is_empty(), "paused without a record");
    assert!(paused_ids(&c).is_empty());
    assert!(
        has_decision(&c, &format!("not pausing #{a}: cannot record the pause (")),
        "{:?}",
        decisions(&c)
    );
    assert!(dir.join("paused.json").is_dir(), "the record was touched");
    // Still unreadable one period later: still no pause, nothing written.
    c.tick(&mut m, t0 + Duration::from_secs(2));
    c.pause_for_test(a, t0 + Duration::from_secs(2));
    assert!(ctl.calls().is_empty());
    // The record becomes readable (here: absent): the next period's retry succeeds.
    std::fs::remove_dir(dir.join("paused.json")).unwrap();
    c.tick(&mut m, t0 + Duration::from_secs(3));
    c.pause_for_test(a, t0 + Duration::from_secs(3));
    assert_eq!(ctl.calls(), vec![("suspend", 100)]);
    assert_eq!(paused_ids(&c), vec![a]);
    assert_eq!(record_on_disk(&dir).units, vec![(100, 0, 1100)]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Runs `f` on its own thread and panics if it does not return within `secs`; a hung shutdown
/// then fails the test instead of hanging the whole run.
fn within(secs: u64, what: String, f: impl FnOnce() + Send + 'static) {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        f();
        let _ = tx.send(());
    });
    if rx.recv_timeout(Duration::from_secs(secs)).is_err() {
        panic!("{what} did not return within {secs}s");
    }
}

#[test]
fn ipc_shutdown_right_after_serve_always_returns() {
    // Shutting down before the accept thread first blocks used to lose the wake-up on Windows.
    for i in 0..100 {
        let server =
            crate::ipc::serve(&test_socket(&format!("loop-{i}")), |_| Response::Ack).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        within(5, format!("ipc shutdown (iteration {i})"), move || {
            let _ = tx.send(server.stop_within(Duration::from_secs(2)));
        });
        assert!(
            rx.recv().unwrap(),
            "ipc shutdown gave up on cycle {i} instead of stopping the accept thread"
        );
    }
}

#[test]
fn daemon_shutdown_and_abort_in_a_loop_always_return() {
    for i in 0..50 {
        let cfg = Config {
            tick_ms: 60_000,
            ..Config::default()
        };
        let h = crate::run_with(
            cfg,
            &test_socket(&format!("dloop-{i}")),
            FakeMeasure::default(),
            FakeControl::default(),
            None,
            Arc::new(crate::OsLauncher::default()),
        )
        .unwrap();
        if i % 2 == 0 {
            within(5, format!("daemon shutdown (iteration {i})"), move || {
                h.shutdown()
            });
        } else {
            within(5, format!("daemon abort (iteration {i})"), move || {
                h.abort()
            });
        }
    }
}

fn mcp_daemon(tag: &str, l: &Arc<FakeLauncher>) -> crate::DaemonHandle<FakeControl> {
    let cfg = Config {
        tick_ms: 60_000,
        ..hub_config()
    };
    crate::run_with(
        cfg,
        &test_socket(tag),
        FakeMeasure::default(),
        FakeControl::default(),
        None,
        l.clone(),
    )
    .unwrap()
}

#[test]
fn shutdown_stops_children_abort_does_not() {
    for abort in [false, true] {
        let l = Arc::new(FakeLauncher::default());
        let h = mcp_daemon(&format!("mcp-stop-{abort}"), &l);
        let a = connect(&h.hub, hello("docs", &[("TOKEN", "a")], "/r"));
        let b = connect(&h.hub, hello("docs", &[("TOKEN", "b")], "/r"));
        assert_eq!((a.reply(), b.reply()), (HubReply::Ok, HubReply::Ok));
        let children = [l.take_child(), l.take_child()];
        let stops = |l: &FakeLauncher| {
            l.calls()
                .into_iter()
                .filter(|c| !c.starts_with("spawn"))
                .collect::<Vec<_>>()
        };
        if abort {
            within(10, "daemon abort".into(), move || h.abort());
            assert!(stops(&l).is_empty(), "{:?}", stops(&l));
            // The children lost their stdin, as they would if the daemon died.
            for c in &children {
                wait_until("stdin EOF", || !l.is_alive_quiet(c.pid));
            }
        } else {
            within(10, "daemon shutdown".into(), move || h.shutdown());
            let calls = stops(&l);
            for c in &children {
                assert!(calls.contains(&format!("reap {}", c.pid)), "{calls:?}");
            }
        }
        assert!(a.closed.load(Ordering::SeqCst) && b.closed.load(Ordering::SeqCst));
    }
}

#[test]
fn status_reports_mcp_servers() {
    let l = Arc::new(FakeLauncher::default());
    let h = mcp_daemon("mcp-status", &l);
    let c = connect(&h.hub, hello("docs", &[], "/r"));
    assert_eq!(c.reply(), HubReply::Ok);
    let child = l.take_child();
    let mut m = FakeMeasure::default();
    m.rss.insert(child.pid, 5 * MIB);
    let now = Instant::now();
    crate::tick(&h.core, &h.hub, &h.services, &mut m, now);
    let Response::Status(s) = crate::respond(&h.core, &h.hub, &h.services, Request::Status, now)
    else {
        panic!("not a status");
    };
    let docs = s.mcp.iter().find(|r| r.server == "docs").expect("docs row");
    assert_eq!(docs.mode, "shared");
    assert_eq!((docs.instances, docs.clients, docs.rss), (1, 1, 5 * MIB));
    let browser = s.mcp.iter().find(|r| r.server == "browser").unwrap();
    assert_eq!(
        (browser.mode.as_str(), browser.instances),
        ("per-session", 0)
    );
    within(10, "daemon shutdown".into(), move || h.shutdown());
}

#[test]
fn hubreload_a_failed_reload_reaches_status_without_file_content() {
    let l = Arc::new(FakeLauncher::default());
    let text = "[mcp.x]\ncommand = \"c\"\nenv = { TOKEN = \"SECRET-VALUE }\n";
    let reload: crate::McpReload = Arc::new(move || {
        Config::from_toml(text)
            .map(|c| c.mcp)
            .map_err(|e| sync_gate_core::ConfigLoadError::parse(text, &e))
    });
    let cfg = Config {
        tick_ms: 60_000,
        ..hub_config()
    };
    let h = crate::run_with_pg(
        cfg,
        &test_socket("mcp-reload-fail"),
        FakeMeasure::default(),
        FakeControl::default(),
        None,
        l.clone(),
        crate::services::Deps {
            mcp_reload: Some(reload),
            ..crate::services::Deps::os()
        },
    )
    .unwrap();
    let c = connect(&h.hub, hello("x", &[], "/r"));
    assert_eq!(c.reply(), HubReply::Unknown);
    let Response::Status(s) = crate::respond(
        &h.core,
        &h.hub,
        &h.services,
        Request::Status,
        Instant::now(),
    ) else {
        panic!("not a status");
    };
    let all = serde_json::to_string(&s).unwrap();
    assert!(!all.contains("SECRET-VALUE"), "{all}");
    let said = s
        .decisions
        .iter()
        .any(|d| d.contains("config did not load"));
    assert!(said, "{:?}", s.decisions);
    within(10, "daemon shutdown".into(), move || h.shutdown());
}

#[test]
fn hub_decisions_reach_the_status_log() {
    let l = Arc::new(FakeLauncher::default());
    let h = mcp_daemon("mcp-log", &l);
    let c = connect(&h.hub, hello("docs", &[], "/r"));
    assert_eq!(c.reply(), HubReply::Ok);
    let mut child = l.take_child();
    let probe = child.next();
    let bad = serde_json::json!({"jsonrpc": "2.0", "id": probe["id"], "result": {"supportedVersions": ["2099-01-01"]}});
    child.send(bad);
    let want = "mcp docs: no supported protocol version; not restarting";
    wait_until("the decision in status", || {
        match crate::respond(
            &h.core,
            &h.hub,
            &h.services,
            Request::Status,
            Instant::now(),
        ) {
            Response::Status(s) => s.decisions.iter().any(|d| d.ends_with(want)),
            _ => false,
        }
    });
    within(10, "daemon shutdown".into(), move || h.shutdown());
}

#[test]
fn memory_for_the_hub_comes_from_the_last_snapshot() {
    let (c, _) = core(Config::default());
    let mut m = FakeMeasure::default();
    c.tick(&mut m, Instant::now());
    assert_eq!(c.memory(), None, "no data: the pool must not grow blind");
    let mut s = snap(16 * GIB, 3 * GIB);
    s.reclaimable = GIB;
    m.snap = Some(s);
    c.tick(&mut m, Instant::now());
    // reserve_fraction 0.10 of 16 GiB; free counts reclaimable cache, like the resume rule.
    let reserve = (16 * GIB) as f64 * 0.10;
    assert_eq!(c.memory(), Some((4 * GIB, reserve as u64)));
}

/// Records, at each leftover check, how many `Control` calls had already happened.
struct OrderLauncher {
    ctl: FakeControl,
    seen: Mutex<Vec<usize>>,
}

impl crate::Launcher for OrderLauncher {
    fn spawn(
        &self,
        _command: &str,
        _args: &[String],
        _env: &std::collections::BTreeMap<String, String>,
        _env_remove: &[String],
        _cwd: Option<&Path>,
    ) -> io::Result<crate::supervisor::Spawned> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn is_alive(&self, _pid: u32, _start_time: u64) -> bool {
        self.seen.lock().unwrap().push(self.ctl.calls().len());
        false
    }
    fn terminate(&self, _pid: u32, _start_time: u64) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn startup_resumes_frozen_jobs_before_touching_mcp_leftovers() {
    let dir = temp_dir("recover-first");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("paused.json"), "[[4242,0,111]]").unwrap();
    crate::supervisor::Registry::load(&dir.join("services.json")).record(
        "docs",
        777,
        5,
        Path::new("/fake/mcp-server"),
    );
    let ctl = FakeControl::default();
    ctl.starts.lock().unwrap().insert(4242, 111);
    let l = Arc::new(OrderLauncher {
        ctl: ctl.clone(),
        seen: Mutex::new(Vec::new()),
    });
    let h = crate::run_with(
        Config {
            tick_ms: 60_000,
            ..Config::default()
        },
        &test_socket("recover-first"),
        FakeMeasure::default(),
        ctl.clone(),
        Some(dir.clone()),
        l.clone(),
    )
    .unwrap();
    assert_eq!(ctl.calls()[0], ("resume", 4242));
    // The leftover was looked at once, after the resume.
    assert_eq!(*l.seen.lock().unwrap(), vec![1]);
    h.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn hub_deadlines_fire_while_the_core_tick_is_blocked() {
    let ctl = FakeControl::default();
    let l = Arc::new(FakeLauncher::default());
    let h = crate::run_with(
        Config {
            tick_ms: 20,
            ..hub_config()
        },
        &test_socket("hub-own-tick"),
        FakeMeasure {
            snap: free(8 * GIB),
            rss: HashMap::from([(4242, GIB)]),
            starts: HashMap::new(),
        },
        ctl.clone(),
        None,
        l.clone(),
    )
    .unwrap();
    let t0 = Instant::now();
    let id = admitted(&acquire(&h.core, "cargo build", t0));
    h.core.handle(Request::Started { id, pid: 4242 }, t0);
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    *ctl.block_resume.lock().unwrap() = Some(ResumeBlock {
        entered: entered_tx,
        release: release_rx,
    });
    // Memory is back: the next core tick resumes the job and blocks inside that resume.
    h.core.pause_for_test(id, t0);
    entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    // A connection that never says hello is still closed after the hello deadline.
    let silent = crate::hub::testkit::raw_conn(h.hub.clone());
    let end = Instant::now() + crate::hub::HELLO_DEADLINE + Duration::from_secs(5);
    while !silent.closed.load(Ordering::SeqCst) && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(20));
    }
    let closed = silent.closed.load(Ordering::SeqCst);
    // Always release before asserting, including on a regression.
    let _ = release_tx.send(());
    within(20, "daemon shutdown".into(), move || h.shutdown());
    assert!(
        closed,
        "the hub's deadlines waited for the blocked core tick"
    );
}

// ---- plan 3-S: guests ----

/// Room for exactly one unknown heavy job (1.5 GiB prior), no pressure ever.
fn one_job() -> (Config, FakeMeasure) {
    let cfg = Config {
        reserve_fraction: 0.0,
        optimism: 1.0,
        tick_ms: 60_000,
        ..Config::default()
    };
    let m = FakeMeasure {
        snap: Some(snap(4096 * MIB, 2048 * MIB)),
        ..Default::default()
    };
    (cfg, m)
}

const GOLDEN: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/testdata/owner-replies.jsonl"
);

/// The owner's replies, one JSON line each, for a fixed script through `respond`; ticket ids
/// and the daemon's identity (they vary per run) become fixed values.
fn owner_script_replies() -> Vec<String> {
    let (cfg, mut m) = one_job();
    let core = Core::new(
        cfg.clone(),
        CostModel::default(),
        FakeControl::default(),
        None,
    );
    let hub = crate::Hub::new(&cfg, Arc::new(FakeLauncher::default()), None, None);
    let services = crate::Services::new(&cfg, None, crate::Deps::os());
    let now = Instant::now();
    core.tick(&mut m, now);
    let ask = |req: Request| crate::respond(&core, &hub, &services, req, now);
    let acquire = |cmd: &str| {
        ask(Request::Acquire {
            argv: cmd.split(' ').map(String::from).collect(),
            cwd: PathBuf::from("/r/site"),
            session: "s1".into(),
            heavy: true,
        })
    };
    let mut replies = vec![acquire("cargo build"), acquire("cargo test")];
    let a = admitted(&replies[0]);
    let Response::Queued { id: b, .. } = replies[1] else {
        panic!("{:?}", replies[1]);
    };
    replies.push(ask(Request::Status));
    replies.push(ask(Request::Started { id: a, pid: 4242 }));
    replies.push(ask(Request::Wait {
        id: b,
        timeout_secs: Some(0),
    }));
    replies.push(ask(Request::Cancel { id: b }));
    replies.push(ask(Request::Finished {
        id: a,
        peak_rss: 700 * MIB,
        exit_code: Some(0),
    }));
    replies.push(ask(Request::Status));
    replies.push(ask(Request::Cancel { id: 42 }));
    replies.push(ask(Request::Lease {
        service: sync_gate_core::SERVICE_POSTGRES.into(),
        project: PathBuf::from("/r/site"),
        holder: sync_gate_core::Holder {
            pid: 4242,
            start: Some(2),
        },
        request: "r1".into(),
        template: None,
        extensions: Vec::new(),
    }));
    replies
        .into_iter()
        .map(|mut r| {
            if let Response::Status(s) = &mut r {
                s.daemon = sync_gate_core::DaemonInfo {
                    pid: 1,
                    start_time: 2,
                    data_dir: None,
                };
            }
            serde_json::to_string(&r)
                .unwrap()
                .replace(&a.to_string(), "1001")
                .replace(&b.to_string(), "1002")
        })
        .collect()
}

#[test]
fn the_owner_replies_are_unchanged_without_guests() {
    let got = owner_script_replies();
    // Only read: the test never changes its own environment.
    if std::env::var_os("SYNC_GATE_UPDATE_GOLDEN").is_some_and(|v| v == "1") {
        std::fs::create_dir_all(Path::new(GOLDEN).parent().unwrap()).unwrap();
        std::fs::write(GOLDEN, got.join("\n") + "\n").unwrap();
    }
    let want = std::fs::read_to_string(GOLDEN).expect("golden file");
    let want: Vec<&str> = want.lines().collect();
    for (i, (g, w)) in got.iter().zip(&want).enumerate() {
        assert_eq!(g, w, "reply {} differs from the golden file", i + 1);
    }
    assert_eq!(got.len(), want.len(), "number of replies");

    // A daemon without guests serves no guest pipe and writes no guest record.
    let dir = temp_dir("golden-daemon");
    let socket = test_socket("golden");
    let (cfg, m) = one_job();
    assert!(cfg.guests.is_empty());
    let h = crate::run_with(
        cfg,
        &socket,
        m,
        FakeControl::default(),
        Some(dir.clone()),
        Arc::new(FakeLauncher::default()),
    )
    .unwrap();
    #[cfg(windows)]
    {
        let pipes: Vec<String> = std::fs::read_dir(r"\\.\pipe\")
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(pipes.contains(&socket), "control: the main pipe is listed");
        let guest = |p: &&String| {
            p.starts_with(&format!("{socket}-guest-")) || p.starts_with(&format!("{socket}-sbx-"))
        };
        assert_eq!(pipes.iter().filter(guest).count(), 0, "{pipes:?}");
    }
    h.shutdown();
    assert!(dir.is_dir(), "control: the daemon used its data dir");
    assert!(!dir.join("paused-guests.json").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- guests: policy (every system, FakeControl and fake identities) ----

/// The owner SID in the fake idents below.
const O: &str = "S-1-5-21-1-2-3-1000";

fn acc(rid: u32) -> String {
    format!("account:S-1-5-21-1-2-3-{rid}")
}

fn ac(c: u32) -> String {
    format!("appcontainer:{O}:S-1-15-2-{c}")
}

fn rs(last: u32) -> String {
    format!("restricted:{O}:S-1-1-0,S-1-5-21-7-7-7-{last},S-1-5-5-0-1")
}

fn as_guest<'a>(index: u8, name: &'a str, client: &'a str) -> Caller<'a> {
    Caller::Guest {
        index,
        name,
        client,
        checked: None,
    }
}

fn guest_ask(
    c: &Core<FakeControl>,
    (index, name, client): (u8, &str, &str),
    req: Request,
    now: Instant,
) -> Response {
    c.handle_as(as_guest(index, name, client), req, now)
}

fn guest_acquire(c: &Core<FakeControl>, who: (u8, &str, &str), now: Instant) -> Response {
    guest_ask(
        c,
        who,
        Request::Acquire {
            argv: vec!["cargo".into(), "test".into()],
            cwd: PathBuf::from("/r/site"),
            session: "s1".into(),
            heavy: true,
        },
        now,
    )
}

fn guest_started(c: &Core<FakeControl>, who: (u8, &str, &str), id: TicketId, pid: u32, start: u64) {
    let (index, name, client) = who;
    let caller = Caller::Guest {
        index,
        name,
        client,
        checked: Some(start),
    };
    assert_eq!(
        c.handle_as(caller, Request::Started { id, pid }, Instant::now()),
        Response::Ack
    );
}

fn ticket(r: &Response) -> TicketId {
    match r {
        Response::Admitted { id } | Response::Queued { id, .. } => *id,
        other => panic!("expected a ticket, got {other:?}"),
    }
}

fn unknown(id: TicketId) -> Response {
    Response::Error {
        message: format!("ticket #{id} was cancelled or is unknown"),
    }
}

fn status_as(c: &Core<FakeControl>, caller: Caller) -> sync_gate_core::StatusReport {
    match c.handle_as(caller, Request::Status, Instant::now()) {
        Response::Status(s) => s,
        other => panic!("{other:?}"),
    }
}

/// A resolved guest whose `ident_of_pid` answers from `pids`.
fn test_guest(index: u8, name: &str, kind: IdentKind, pids: &[(u32, &str, u64)]) -> Guest {
    let pids: HashMap<u32, (String, u64)> = pids
        .iter()
        .map(|&(p, i, s)| (p, (i.to_string(), s)))
        .collect();
    Guest {
        index,
        name: name.into(),
        kind,
        ace_sid: "S-1-5-21-1-2-3-1004".into(),
        ident_of_pid: Box::new(move |pid| pids.get(&pid).cloned()),
    }
}

/// Every request a ticket can take, for the ownership matrix.
fn ticket_requests(id: TicketId) -> [Request; 4] {
    [
        Request::Started { id, pid: 4242 },
        Request::Finished {
            id,
            peak_rss: 1,
            exit_code: Some(0),
        },
        Request::Wait {
            id,
            timeout_secs: Some(0),
        },
        Request::Cancel { id },
    ]
}

#[test]
fn guest_matrix_each_caller_touches_only_its_own() {
    let (one, mut m) = one_job();
    let cfg = Config {
        postgres: Some(Default::default()),
        ..Config {
            mcp: hub_config().mcp,
            ..one
        }
    };
    let ctl = FakeControl::default();
    let c = Core::new(cfg.clone(), CostModel::default(), ctl, None);
    let hub = crate::Hub::new(&cfg, Arc::new(FakeLauncher::default()), None, None);
    let services = crate::Services::new(&cfg, None, crate::Deps::os());
    let now = Instant::now();
    c.tick(&mut m, now);
    let owner_status = || {
        let Response::Status(s) = crate::respond(&c, &hub, &services, Request::Status, now) else {
            panic!("not a status")
        };
        s
    };
    let a = admitted(&acquire(&c, "cargo build", now));
    let b = ticket(&acquire(&c, "cargo test", now));
    c.handle(Request::Started { id: a, pid: 100 }, now);
    c.pause_for_test(a, now);
    let (g0, g1, g1b, g2, g2b) = (acc(1004), ac(1), ac(2), rs(1), rs(2));
    let callers: Vec<(u8, &str, &str)> = vec![
        (0, "tester", g0.as_str()),
        (1, "@appcontainer", g1.as_str()),
        (1, "@appcontainer", g1b.as_str()),
        (2, "@restricted", g2.as_str()),
        (2, "@restricted", g2b.as_str()),
    ];
    let tickets: Vec<TicketId> = callers
        .iter()
        .map(|&who| ticket(&guest_acquire(&c, who, now)))
        .collect();
    let before = serde_json::to_string(&owner_status()).unwrap();
    let st = owner_status();
    assert!(!st.mcp.is_empty() && !st.services.is_empty(), "control");
    assert!(!st.decisions.is_empty() && st.paused == vec![a], "{st:?}");
    // Negative cells first: every guest on every ticket that is not its own (index AND ident).
    let owner_tickets = [a, b];
    for (i, &who) in callers.iter().enumerate() {
        for (j, &t) in tickets.iter().chain(&owner_tickets).enumerate() {
            if i == j {
                continue;
            }
            for req in ticket_requests(t) {
                let what = format!("{who:?} {req:?}");
                assert_eq!(guest_ask(&c, who, req, now), unknown(t), "{what}");
            }
        }
    }
    // The owner on a guest's ticket.
    for &t in &tickets {
        for req in ticket_requests(t) {
            let what = format!("owner {req:?}");
            assert_eq!(c.handle(req, now), unknown(t), "{what}");
        }
    }
    assert_eq!(serde_json::to_string(&owner_status()).unwrap(), before);
    // Each guest's Status, whole.
    let daemon = sync_gate_core::DaemonInfo {
        pid: std::process::id(),
        start_time: sync_gate_probe::start_time(std::process::id()).unwrap_or(0),
        data_dir: None,
    };
    for (pos, (&who, &t)) in callers.iter().zip(&tickets).enumerate() {
        let want = sync_gate_core::StatusReport {
            snapshot: snap(4096 * MIB, 2048 * MIB),
            running: Vec::new(),
            queued: vec![(t, format!("[guest {}] cargo test @ site", who.1), pos)],
            paused: Vec::new(),
            decisions: Vec::new(),
            mcp: Vec::new(),
            daemon: daemon.clone(),
            services: Vec::new(),
        };
        let got = status_as(&c, as_guest(who.0, who.1, who.2));
        assert_eq!(
            serde_json::to_string(&got).unwrap(),
            serde_json::to_string(&want).unwrap(),
            "{who:?}"
        );
    }
    let st = owner_status();
    let queued: Vec<TicketId> = st.queued.iter().map(|q| q.0).collect();
    for t in tickets.iter().chain([&b]) {
        assert!(queued.contains(t), "{st:?}");
    }
    assert_eq!(st.running.iter().map(|r| r.0).collect::<Vec<_>>(), vec![a]);
    // Positive controls, each on its own ticket.
    for (&who, &t) in callers.iter().zip(&tickets) {
        let r = guest_ask(
            &c,
            who,
            Request::Wait {
                id: t,
                timeout_secs: Some(0),
            },
            now,
        );
        assert!(
            matches!(r, Response::Queued { id, .. } if id == t),
            "{who:?} {r:?}"
        );
    }
    let cancel = Request::Cancel { id: tickets[1] };
    assert_eq!(guest_ask(&c, callers[1], cancel, now), Response::Ack);
    assert_eq!(c.handle(Request::Cancel { id: b }, now), Response::Ack);
}

#[test]
fn a_guest_cannot_reach_leases_or_services() {
    let (c, _) = core(Config::default());
    let g = test_guest(
        0,
        "tester",
        IdentKind::Account("S-1-5-21-1-2-3-1004".into()),
        &[],
    );
    let before = decisions(&c);
    let holder = sync_gate_core::Holder {
        pid: 1,
        start: Some(1),
    };
    let leases = [
        Request::Lease {
            service: sync_gate_core::SERVICE_POSTGRES.into(),
            project: PathBuf::from("/r/site"),
            holder,
            request: "r".into(),
            template: None,
            extensions: Vec::new(),
        },
        Request::LeaseHolder {
            lease: "l".into(),
            holder,
        },
        Request::ReleaseLease { lease: "l".into() },
        Request::LeaseGiveUp {
            request: "r".into(),
        },
        Request::TemplateReady {
            lease: "l".into(),
            ok: true,
            interrupted: false,
        },
    ];
    for req in leases {
        let what = format!("{req:?}");
        let r = respond_guest(&c, &g, &acc(1004), req, Instant::now());
        assert_eq!(
            r,
            Response::Error {
                message: "not available to sandboxed callers".into()
            },
            "{what}"
        );
    }
    // respond_guest is never handed the services, so none of them can be called.
    assert_eq!(decisions(&c), before);
}

#[test]
fn a_started_pid_must_share_the_clients_identity() {
    let (c, _) = core(Config::default());
    let now = Instant::now();
    c.tick(
        &mut FakeMeasure {
            snap: free(8 * GIB),
            ..Default::default()
        },
        now,
    );
    let me = acc(1004);
    let kind = IdentKind::Account("S-1-5-21-1-2-3-1004".into());
    let other = acc(1005);
    let g = test_guest(0, "tester", kind, &[(200, &other, 100), (300, &me, 100)]);
    let id = admitted(&respond_guest(
        &c,
        &g,
        &me,
        Request::Acquire {
            argv: vec!["cargo".into(), "test".into()],
            cwd: PathBuf::from("/r/site"),
            session: "s1".into(),
            heavy: true,
        },
        now,
    ));
    let start = |pid| respond_guest(&c, &g, &me, Request::Started { id, pid }, now);
    let refused = |r: Response, pid: u32| {
        assert_eq!(
            r,
            Response::Error {
                message: format!("process {pid} does not run as this caller")
            }
        );
    };
    refused(start(100), 100);
    assert_eq!(c.job_of(id).unwrap().1, None);
    refused(start(200), 200);
    // The same entry kind, another container.
    let ackind = IdentKind::AppContainer(O.into());
    let g1 = test_guest(1, "@appcontainer", ackind, &[(400, &ac(2), 100)]);
    let mine = ac(1);
    let id1 = admitted(&respond_guest(
        &c,
        &g1,
        &mine,
        Request::Acquire {
            argv: vec!["cargo".into(), "test".into()],
            cwd: PathBuf::from("/r/site"),
            session: "s1".into(),
            heavy: true,
        },
        now,
    ));
    refused(
        respond_guest(&c, &g1, &mine, Request::Started { id: id1, pid: 400 }, now),
        400,
    );
    // Control: the client's own identity.
    assert_eq!(start(300), Response::Ack);
    let (guest, pid, job_start) = c.job_of(id).unwrap();
    assert_eq!((pid, job_start), (Some(300), Some(100)));
    assert_eq!(
        guest,
        Some(GuestOf {
            index: 0,
            ident: me.clone()
        })
    );
}

/// Pressure ticks where pid 200 grows fastest (as in `pressure_pauses_then_resumes`).
fn squeeze(c: &Core<FakeControl>, m: &mut FakeMeasure, t0: Instant) {
    for (i, (avail, rss_b)) in [(600, 100), (400, 500), (200, 1000)]
        .into_iter()
        .enumerate()
    {
        m.snap = free(avail * MIB);
        m.rss = HashMap::from([(100, 100 * MIB), (200, rss_b * MIB)]);
        c.tick(m, t0 + Duration::from_millis(500 * i as u64));
    }
}

#[test]
fn a_guest_job_pauses_through_its_ident_and_teaches_no_cost() {
    let me = acc(1004);
    let who = (0, "tester", me.as_str());
    let gsig = sync_gate_core::JobSignature {
        key: "[guest tester] cargo test @ site".into(),
    };
    let dir = temp_dir("guest-cost");
    let ctl = FakeControl::default();
    let c = Core::new(
        Config::default(),
        CostModel::default(),
        ctl.clone(),
        Some(dir.clone()),
    );
    let t0 = Instant::now();
    let mut m = FakeMeasure {
        snap: free(8 * GIB),
        starts: HashMap::from([(200, 100)]),
        ..Default::default()
    };
    c.tick(&mut m, t0);
    let a = admitted(&acquire(&c, "cargo build", t0));
    let g = admitted(&guest_acquire(&c, who, t0));
    c.handle(Request::Started { id: a, pid: 100 }, t0);
    guest_started(&c, who, g, 200, 100);
    squeeze(&c, &mut m, t0);
    assert_eq!(*ctl.as_calls.lock().unwrap(), vec![(200, 100, me.clone())]);
    assert!(
        !ctl.calls().iter().any(|c| c.0 == "suspend"),
        "{:?}",
        ctl.calls()
    );
    assert!(
        has_decision(&c, &format!("paused #{g}")),
        "{:?}",
        decisions(&c)
    );
    // Finished with a huge peak teaches nothing.
    let fin = Request::Finished {
        id: g,
        peak_rss: 40 * GIB,
        exit_code: Some(0),
    };
    assert_eq!(guest_ask(&c, who, fin, t0), Response::Ack);
    assert_eq!(c.estimate(&gsig), PRIOR_HEAVY);
    let cost = std::fs::read_to_string(dir.join("cost.json")).unwrap_or_default();
    assert!(!cost.contains("[guest"), "{cost}");

    // Control: the same squeeze on an owner job suspends it and never calls suspend_as.
    let (c2, ctl2) = core(Config::default());
    let mut m2 = FakeMeasure::default();
    two_running(&c2, &mut m2, t0);
    squeeze(&c2, &mut m2, t0);
    assert_eq!(ctl2.calls(), vec![("suspend", 200)]);
    assert!(ctl2.as_calls.lock().unwrap().is_empty());

    // R13a, process gone: no cost; control: the owner's job learns its peak.
    let (c3, _) = core(Config::default());
    let mut m3 = FakeMeasure {
        snap: free(8 * GIB),
        rss: HashMap::from([(300, 3 * GIB), (400, 3 * GIB)]),
        starts: HashMap::from([(300, 300)]),
    };
    c3.tick(&mut m3, t0);
    let g3 = admitted(&guest_acquire(&c3, who, t0));
    let o3 = admitted(&acquire(&c3, "cargo build", t0));
    guest_started(&c3, who, g3, 300, 300);
    c3.handle(Request::Started { id: o3, pid: 400 }, t0);
    c3.tick(&mut m3, t0);
    m3.rss.clear();
    c3.tick(&mut m3, t0);
    for id in [g3, o3] {
        assert!(
            has_decision(&c3, &format!("released #{id}: process gone")),
            "{:?}",
            decisions(&c3)
        );
    }
    assert_eq!(c3.estimate(&gsig), PRIOR_HEAVY);
    assert_eq!(c3.estimate(&sig("cargo build")), 3 * GIB);

    // R13a, pid reused: the rss stays, the start time moves on.
    let (c4, _) = core(Config::default());
    let mut m4 = FakeMeasure {
        snap: free(8 * GIB),
        rss: HashMap::from([(500, 3 * GIB), (600, 3 * GIB)]),
        starts: HashMap::from([(500, 100), (600, 100)]),
    };
    c4.tick(&mut m4, t0);
    let g4 = admitted(&guest_acquire(&c4, who, t0));
    let o4 = admitted(&acquire(&c4, "cargo build", t0));
    guest_started(&c4, who, g4, 500, 100);
    c4.handle(Request::Started { id: o4, pid: 600 }, t0);
    c4.tick(&mut m4, t0);
    assert!(!has_decision(&c4, "process gone"), "{:?}", decisions(&c4));
    m4.starts = HashMap::from([(500, 101), (600, 101)]);
    c4.tick(&mut m4, t0);
    assert!(
        has_decision(&c4, &format!("released #{g4}: process gone")),
        "{:?}",
        decisions(&c4)
    );
    assert_eq!(c4.estimate(&gsig), PRIOR_HEAVY);
    // Control: the owner's job has no start, so the same Measure leaves it running.
    assert!(
        !has_decision(&c4, &format!("released #{o4}")),
        "{:?}",
        decisions(&c4)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_guest_has_at_most_8_live_tickets() {
    assert_eq!(GUEST_MAX_TICKETS, 8);
    let (c, _) = core(Config::default());
    let now = Instant::now();
    c.tick(
        &mut FakeMeasure {
            snap: free(GIB),
            ..Default::default()
        },
        now,
    );
    let me = acc(1004);
    let who = (0, "tester", me.as_str());
    let ids: Vec<TicketId> = (0..8)
        .map(|_| match guest_acquire(&c, who, now) {
            r @ (Response::Admitted { .. } | Response::Queued { .. }) => ticket(&r),
            other => panic!("{other:?}"),
        })
        .collect();
    let busy = |r: Response| match r {
        Response::Error { message } => assert!(message.contains(ERR_BUSY), "{message}"),
        other => panic!("expected busy, got {other:?}"),
    };
    busy(guest_acquire(&c, who, now));
    // Another entry has its own cap.
    let other = rs(1);
    ticket(&guest_acquire(&c, (2, "@restricted", other.as_str()), now));
    // A dormant ticket still counts (ruling P8).
    let wait = Request::Wait {
        id: ids[0],
        timeout_secs: Some(0),
    };
    assert!(matches!(
        guest_ask(&c, who, wait, now),
        Response::Queued { .. }
    ));
    assert!(!c.has_waiter(ids[0]));
    busy(guest_acquire(&c, who, now));
    // Control: after a Cancel, a new Acquire passes.
    let cancel = Request::Cancel { id: ids[1] };
    assert_eq!(guest_ask(&c, who, cancel, now), Response::Ack);
    ticket(&guest_acquire(&c, who, now));
    busy(guest_acquire(&c, who, now));
}

#[test]
fn a_guest_acquire_never_probes_the_owner_disk_nor_reads_its_history() {
    let base = temp_dir("guest-disk");
    let pkg = base.join("repo").join("pkg");
    std::fs::create_dir_all(base.join("repo").join(".git")).unwrap();
    std::fs::create_dir_all(&pkg).unwrap();
    let pkg2 = base.join("pkg2").join("pkg");
    std::fs::create_dir_all(&pkg2).unwrap();
    let os = |v: &[&str]| v.iter().map(OsString::from).collect::<Vec<_>>();
    let owner_key = signature(&os(&["cargo", "test"]), &pkg).unwrap().key;
    assert_eq!(owner_key, "cargo test @ repo");
    let mut cost = CostModel::default();
    for key in ["cargo test @ repo", "cargo test @ pkg"] {
        let s = sync_gate_core::JobSignature { key: key.into() };
        cost.record(&s, 30 * GIB);
        cost.record(&s, 30 * GIB);
    }
    let ctl = FakeControl::default();
    let c = Core::new(Config::default(), cost, ctl, None);
    let now = Instant::now();
    // No room: tickets stay queued, where their estimate is read; then room to run.
    let mut full = FakeMeasure {
        snap: Some(snap(128 * GIB, 0)),
        ..Default::default()
    };
    let mut room = FakeMeasure {
        snap: Some(snap(128 * GIB, 100 * GIB)),
        ..Default::default()
    };
    c.tick(&mut full, now);
    let ask = |argv: &[&str], cwd: &Path| Request::Acquire {
        argv: argv.iter().map(|s| s.to_string()).collect(),
        cwd: cwd.to_path_buf(),
        session: "s1".into(),
        heavy: true,
    };
    let prior = sync_gate_core::Estimate {
        peak_bytes: 1536 * 1024 * 1024,
        confident: false,
    };
    let key_of = |id: TicketId| -> String {
        let Response::Status(s) = c.handle(Request::Status, now) else {
            panic!()
        };
        s.running
            .iter()
            .map(|r| (r.0, r.1.clone()))
            .chain(s.queued.iter().map(|q| (q.0, q.1.clone())))
            .find(|r| r.0 == id)
            .expect("listed")
            .1
    };
    let o = ticket(&c.handle(ask(&["cargo", "test"], &pkg), now));
    assert_eq!(key_of(o), "cargo test @ repo");
    let seeded = sync_gate_core::Estimate {
        peak_bytes: 30 * GIB,
        confident: true,
    };
    assert_eq!(c.ticket_estimate(o), Some(seeded));
    let me = acc(1004);
    let tester = (0, "tester", me.as_str());
    let g = ticket(&guest_ask(&c, tester, ask(&["cargo", "test"], &pkg), now));
    assert_eq!(key_of(g), "[guest tester] cargo test @ pkg");
    assert_eq!(c.ticket_estimate(g), Some(prior));
    let r = rs(1);
    let restricted = (2, "@restricted", r.as_str());
    let g2 = ticket(&guest_ask(
        &c,
        restricted,
        ask(&["cargo", "test"], &pkg),
        now,
    ));
    assert_eq!(key_of(g2), "[guest @restricted] cargo test @ pkg");
    assert_eq!(c.ticket_estimate(g2), Some(prior));
    // Collision (report 2): the owner teaches the very key a guest's command gets.
    // The forgery travels in the program's name: the key keeps no word with `]` in it.
    let forged = ["[guest tester] cargo test.exe"];
    assert_eq!(
        signature(&os(&["cargo", "test"]), &pkg2).unwrap().key,
        "cargo test @ pkg"
    );
    let learned = signature(&os(&forged), &pkg2).unwrap();
    assert_eq!(
        learned.key, "[guest tester] cargo test @ pkg",
        "control: the keys collide"
    );
    c.tick(&mut room, now);
    for _ in 0..2 {
        let id = admitted(&c.handle(ask(&forged, &pkg2), now));
        assert_eq!(
            c.handle(Request::Started { id, pid: 77 }, now),
            Response::Ack
        );
        let fin = Request::Finished {
            id,
            peak_rss: 40 * GIB,
            exit_code: Some(0),
        };
        assert_eq!(c.handle(fin, now), Response::Ack);
    }
    assert_eq!(
        c.estimate_of(&learned),
        sync_gate_core::Estimate {
            peak_bytes: 40 * GIB,
            confident: true
        }
    );
    c.tick(&mut full, now);
    let g3 = ticket(&guest_ask(&c, tester, ask(&["cargo", "test"], &pkg2), now));
    assert_eq!(key_of(g3), learned.key);
    assert_eq!(c.ticket_estimate(g3), Some(prior));
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_ticket_is_bound_to_the_identity_that_asked_for_it() {
    let (cfg, mut m) = one_job();
    let (c, _) = core(cfg);
    let now = Instant::now();
    c.tick(&mut m, now);
    let finish = |id| Request::Finished {
        id,
        peak_rss: MIB,
        exit_code: Some(0),
    };
    let owner = admitted(&acquire(&c, "cargo build", now));
    c.handle(
        Request::Started {
            id: owner,
            pid: 100,
        },
        now,
    );
    let (a_id, b_id, c_id, d_id) = (ac(1), ac(2), rs(1), rs(2));
    let a = (1, "@appcontainer", a_id.as_str());
    let b = (1, "@appcontainer", b_id.as_str());
    let cc = (2, "@restricted", c_id.as_str());
    let d = (2, "@restricted", d_id.as_str());
    // One pair per entry: the second caller never reaches the first one's ticket.
    let check = |mine: (u8, &str, &str), theirs: (u8, &str, &str)| -> TicketId {
        let t = ticket(&guest_acquire(&c, mine, now));
        let seen = status_as(&c, as_guest(theirs.0, theirs.1, theirs.2));
        assert!(seen.queued.iter().all(|q| q.0 != t), "{seen:?}");
        for req in ticket_requests(t) {
            let what = format!("{req:?}");
            assert_eq!(guest_ask(&c, theirs, req, now), unknown(t), "{what}");
        }
        let still = status_as(&c, as_guest(mine.0, mine.1, mine.2));
        assert_eq!(
            still.queued.iter().map(|q| q.0).collect::<Vec<_>>(),
            vec![t]
        );
        t
    };
    let admitted_to = |who: (u8, &str, &str), t: TicketId| {
        c.tick(
            &mut FakeMeasure {
                snap: m.snap,
                ..Default::default()
            },
            now,
        );
        let wait = Request::Wait {
            id: t,
            timeout_secs: Some(0),
        };
        assert_eq!(guest_ask(&c, who, wait, now), Response::Admitted { id: t });
    };
    let ta = check(a, b);
    assert_eq!(c.handle(finish(owner), now), Response::Ack);
    admitted_to(a, ta);
    let tc = check(cc, d);
    assert_eq!(guest_ask(&c, a, finish(ta), now), Response::Ack);
    admitted_to(cc, tc);
    // Control: another connection of the same identity is the same caller.
    let ta2 = ticket(&guest_acquire(&c, a, now));
    assert_eq!(guest_ask(&c, cc, finish(tc), now), Response::Ack);
    let again = a_id.clone();
    admitted_to((1, "@appcontainer", again.as_str()), ta2);
    // The cap is per entry, whatever the identity (decision 9).
    let fill: Vec<TicketId> = (0..7).map(|_| ticket(&guest_acquire(&c, a, now))).collect();
    assert_eq!(fill.len() + 1, GUEST_MAX_TICKETS);
    match guest_acquire(&c, b, now) {
        Response::Error { message } => assert!(message.contains(ERR_BUSY), "{message}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_guest_pause_never_touches_another_account() {
    let me = acc(1004);
    let who = (0, "tester", me.as_str());
    let dir = temp_dir("guest-pause");
    let ctl = FakeControl::default();
    let c = Core::new(
        Config::default(),
        CostModel::default(),
        ctl.clone(),
        Some(dir.clone()),
    );
    let t0 = Instant::now();
    let mut m = FakeMeasure {
        snap: free(8 * GIB),
        rss: HashMap::from([(200, GIB)]),
        starts: HashMap::from([(200, 100)]),
    };
    c.tick(&mut m, t0);
    let g = admitted(&guest_acquire(&c, who, t0));
    guest_started(&c, who, g, 200, 100);
    // A complete rollback: nothing stays frozen, nothing is on record.
    *ctl.as_script.lock().unwrap() = Some(AsScript {
        plan: vec![gunit(200, 1, &me)],
        left: Some(0),
    });
    c.pause_for_test(g, t0);
    assert!(
        has_decision(&c, &format!("pause #{g} failed")),
        "{:?}",
        decisions(&c)
    );
    assert!(paused_ids(&c).is_empty());
    assert!(!c.job_has_token(g));
    assert_eq!(c.guest_planned_len(), 0);
    assert_eq!(
        record_on_disk(&dir),
        sync_gate_probe::PausedRecord::default()
    );
    assert!(!dir.join("paused-guests.json").exists());
    // Success, then the resume uses that very token.
    c.pause_for_test(g, t0);
    assert_eq!(paused_ids(&c), vec![g]);
    m.snap = free(8 * GIB);
    c.tick(&mut m, t0 + Duration::from_secs(1));
    assert!(ctl.calls().contains(&("resume-as", 2)), "{:?}", ctl.calls());
    // resume_all resumes a guest's pause too.
    c.pause_for_test(g, t0 + Duration::from_secs(120));
    c.resume_all(t0 + Duration::from_secs(121));
    assert!(ctl.calls().contains(&("resume-as", 3)), "{:?}", ctl.calls());
    assert!(!dir.join("paused-guests.json").exists());
    // A guest job with no checked start is never paused.
    let g2 = admitted(&guest_acquire(&c, who, t0));
    let calls = ctl.as_calls.lock().unwrap().len();
    c.pause_pid_for_test(g2, 300, t0);
    assert!(
        has_decision(
            &c,
            &format!("not pausing #{g2}: guest process identity unknown")
        ),
        "{:?}",
        decisions(&c)
    );
    assert_eq!(ctl.as_calls.lock().unwrap().len(), calls);
    // The owner's path only ever calls suspend and resume.
    assert!(
        ctl.calls()
            .iter()
            .all(|c| matches!(c.0, "suspend-as" | "resume-as")),
        "{:?}",
        ctl.calls()
    );
    let (c2, ctl2) = core(Config::default());
    let a = one_paused(&c2, &mut FakeMeasure::default(), t0);
    c2.handle(
        Request::Finished {
            id: a,
            peak_rss: 1,
            exit_code: None,
        },
        t0,
    );
    assert_eq!(ctl2.calls(), vec![("suspend", 100), ("resume", 100)]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[derive(serde::Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
struct OldRecord {
    #[serde(default)]
    units: Vec<(u32, u32, u64)>,
    #[serde(default)]
    intents: Vec<(u32, u64)>,
}

fn guest_record(dir: &Path) -> Option<Vec<GuestUnit>> {
    let text = std::fs::read_to_string(dir.join("paused-guests.json")).ok()?;
    Some(
        serde_json::from_str::<sync_gate_probe::GuestRecord>(&text)
            .unwrap()
            .units,
    )
}

#[test]
fn guest_units_never_reach_paused_json() {
    let me = acc(1004);
    let who = (0, "tester", me.as_str());
    let dir = temp_dir("guest-file");
    let ctl = FakeControl::default();
    let (u, v) = (gunit(200, 1, &me), gunit(200, 2, &me));
    *ctl.guest_watch.lock().unwrap() = Some(dir.join("paused-guests.json"));
    *ctl.as_script.lock().unwrap() = Some(AsScript {
        plan: vec![u.clone(), v.clone()],
        left: None,
    });
    let c = Core::new(
        Config::default(),
        CostModel::default(),
        ctl.clone(),
        Some(dir.clone()),
    );
    let t0 = Instant::now();
    c.tick(
        &mut FakeMeasure {
            snap: free(8 * GIB),
            ..Default::default()
        },
        t0,
    );
    let a = admitted(&acquire(&c, "cargo build", t0));
    c.handle(Request::Started { id: a, pid: 100 }, t0);
    let g = admitted(&guest_acquire(&c, who, t0));
    guest_started(&c, who, g, 200, 100);
    let g2 = admitted(&guest_acquire(&c, who, t0));
    guest_started(&c, who, g2, 300, 100);
    c.pause_for_test(a, t0);
    c.pause_for_test(g, t0);
    let seen = ctl.seen_at_plan.lock().unwrap().clone();
    let at_plan: sync_gate_probe::GuestRecord = serde_json::from_str(&seen[0]).unwrap();
    assert_eq!(
        at_plan.units,
        vec![u.clone(), v.clone()],
        "written before any suspend"
    );
    let old: OldRecord =
        serde_json::from_str(&std::fs::read_to_string(dir.join("paused.json")).unwrap()).unwrap();
    assert_eq!(
        old,
        OldRecord {
            units: vec![(100, 0, 1100)],
            intents: Vec::new()
        }
    );
    assert_eq!(guest_record(&dir), Some(vec![u, v]));
    // The guest's job is resumed: its file goes, the owner's record stays.
    let fin = Request::Finished {
        id: g,
        peak_rss: 1,
        exit_code: None,
    };
    assert_eq!(guest_ask(&c, who, fin, t0), Response::Ack);
    assert_eq!(guest_record(&dir), None);
    assert_eq!(record_on_disk(&dir).units, vec![(100, 0, 1100)]);
    // A suspend_as that plans and then fails leaves no guest file.
    *ctl.as_script.lock().unwrap() = Some(AsScript {
        plan: vec![gunit(300, 1, &me)],
        left: Some(0),
    });
    c.pause_for_test(g2, t0);
    assert_eq!(ctl.seen_at_plan.lock().unwrap().len(), 2);
    assert!(ctl.seen_at_plan.lock().unwrap()[1].contains("\"pid\":300"));
    assert_eq!(guest_record(&dir), None);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_partial_guest_rollback_keeps_the_frozen_units_on_record() {
    let me = acc(1004);
    let who = (0, "tester", me.as_str());
    let (u, v) = (gunit(200, 1, &me), gunit(200, 2, &me));
    // A pause whose rollback leaves U frozen (V never froze).
    let setup = |tag: &str| {
        let dir = temp_dir(tag);
        let ctl = FakeControl::default();
        *ctl.as_script.lock().unwrap() = Some(AsScript {
            plan: vec![u.clone(), v.clone()],
            left: Some(1),
        });
        let c = Core::new(
            Config::default(),
            CostModel::default(),
            ctl.clone(),
            Some(dir.clone()),
        );
        let t0 = Instant::now();
        c.tick(
            &mut FakeMeasure {
                snap: free(8 * GIB),
                ..Default::default()
            },
            t0,
        );
        let g = admitted(&guest_acquire(&c, who, t0));
        guest_started(&c, who, g, 200, 100);
        c.pause_for_test(g, t0);
        assert!(
            has_decision(&c, &format!("pause #{g} failed")),
            "{:?}",
            decisions(&c)
        );
        assert!(!c.job_has_token(g));
        assert_eq!(guest_record(&dir), Some(vec![u.clone()]));
        assert_eq!(c.guest_planned_len(), 0);
        assert_eq!(c.held_units(), 1);
        (c, ctl, dir)
    };
    let (c, ctl, dir) = setup("guest-partial");
    c.tick(&mut FakeMeasure::default(), Instant::now());
    assert!(ctl.calls().contains(&("resume-as", 1)), "{:?}", ctl.calls());
    assert_eq!(guest_record(&dir), None);
    assert_eq!(c.held_units(), 0);
    let _ = std::fs::remove_dir_all(&dir);
    // The resume fails and the daemon dies: the next start hands U to the identity recovery.
    let (c, ctl, dir) = setup("guest-partial-crash");
    ctl.fail_next_resumes(1);
    c.tick(&mut FakeMeasure::default(), Instant::now());
    assert!(
        ctl.calls().contains(&("resume-as-failed", 1)),
        "{:?}",
        ctl.calls()
    );
    assert_eq!(guest_record(&dir), Some(vec![u.clone()]));
    drop(c);
    let ctl2 = FakeControl::default();
    let c2 = Core::new(
        Config::default(),
        CostModel::default(),
        ctl2.clone(),
        Some(dir.clone()),
    );
    c2.recover_paused(Instant::now());
    assert_eq!(*ctl2.recovered.lock().unwrap(), vec![vec![u.clone()]]);
    assert_eq!(guest_record(&dir), None);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Fail closed: a guest record that cannot be read is never replaced, and no guest job is
/// paused until a later pass reads it; the owner's pauses go on.
#[test]
fn an_unreadable_guest_record_is_kept_and_stops_guest_pauses() {
    let me = acc(1004);
    let who = (0, "tester", me.as_str());
    let dir = temp_dir("guest-unreadable");
    // A folder where the file should be: reading it fails (not "not found").
    std::fs::create_dir_all(dir.join("paused-guests.json")).unwrap();
    let ctl = FakeControl::default();
    let c = Core::new(
        Config::default(),
        CostModel::default(),
        ctl.clone(),
        Some(dir.clone()),
    );
    c.recover_paused(Instant::now());
    let t0 = Instant::now();
    let mut m = FakeMeasure {
        snap: free(8 * GIB),
        rss: HashMap::from([(100, GIB), (200, GIB)]),
        starts: HashMap::from([(200, 100)]),
    };
    c.tick(&mut m, t0);
    let a = admitted(&acquire(&c, "cargo build", t0));
    c.handle(Request::Started { id: a, pid: 100 }, t0);
    let g = admitted(&guest_acquire(&c, who, t0));
    guest_started(&c, who, g, 200, 100);
    c.pause_for_test(g, t0);
    assert!(
        has_decision(
            &c,
            &format!("pause #{g} failed: paused-guests.json cannot be read")
        ),
        "{:?}",
        decisions(&c)
    );
    assert!(!c.job_has_token(g));
    assert!(
        dir.join("paused-guests.json").is_dir(),
        "the record was replaced"
    );
    c.pause_for_test(a, t0);
    assert_eq!(
        record_on_disk(&dir).units,
        vec![(100, 0, 1100)],
        "control: the owner pauses"
    );
    c.resume_all(t0);
    // Readable again (gone): the next tick reads it and guest pauses are back.
    std::fs::remove_dir(dir.join("paused-guests.json")).unwrap();
    c.tick(&mut m, t0 + Duration::from_secs(1));
    c.pause_for_test(g, t0 + Duration::from_secs(1));
    assert!(c.job_has_token(g), "{:?}", decisions(&c));
    assert_eq!(guest_record(&dir), Some(vec![gunit(200, 1, &me)]));
    c.resume_all(t0 + Duration::from_secs(2));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn guest_units_recovery_failures_are_retried_and_stay_on_record() {
    let me = acc(1004);
    let dir = temp_dir("guest-leftover");
    std::fs::create_dir_all(&dir).unwrap();
    let u = gunit(200, 1, &me);
    let record = sync_gate_probe::GuestRecord {
        units: vec![u.clone()],
    };
    sync_gate_probe::save_guest_record(&dir, &record).unwrap();
    let ctl = FakeControl::default();
    *ctl.fail_recover.lock().unwrap() = 1;
    let c = Core::new(
        Config::default(),
        CostModel::default(),
        ctl.clone(),
        Some(dir.clone()),
    );
    c.set_leftover_retry(Duration::from_secs(60), Duration::ZERO);
    c.recover_paused(Instant::now());
    assert_eq!(guest_record(&dir), Some(vec![u.clone()]));
    c.tick(&mut FakeMeasure::default(), Instant::now());
    assert_eq!(
        *ctl.recovered.lock().unwrap(),
        vec![vec![u.clone()], vec![u.clone()]]
    );
    assert_eq!(guest_record(&dir), None);
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(windows)]
#[test]
fn a_taken_guest_name_does_not_stop_the_daemon() {
    use interprocess::local_socket::ListenerOptions;
    let socket = test_socket("guest-taken");
    let pipe = sync_gate_core::guest_socket_name(&socket, "tester");
    let _squatter = ListenerOptions::new()
        .name(sync_gate_core::ipc_name::to_name(&pipe).unwrap())
        .create_sync()
        .unwrap();
    let g = test_guest(
        0,
        "tester",
        IdentKind::Account("S-1-5-21-1-2-3-1004".into()),
        &[],
    );
    let h = crate::run_with_guests(
        Config {
            tick_ms: 60_000,
            ..Config::default()
        },
        &socket,
        FakeMeasure::default(),
        FakeControl::default(),
        None,
        Arc::new(FakeLauncher::default()),
        vec![g],
    )
    .unwrap();
    let reply = sync_gate_core::ipc_name::connect(&socket).and_then(|mut s| {
        use std::io::{BufRead, Write};
        s.write_all(b"\"Status\"\n")?;
        let mut line = String::new();
        std::io::BufReader::new(s).read_line(&mut line)?;
        Ok(line)
    });
    h.shutdown();
    let reply = reply.unwrap();
    assert!(
        matches!(serde_json::from_str(&reply), Ok(Response::Status(_))),
        "{reply}"
    );
}

/// Review 4, Important 1: the owner pass of start-up saves `paused.json` (a stale unit is gone)
/// before the guest pass has read `paused-guests.json`; that save must not delete the guest file.
#[test]
fn the_owner_recovery_save_keeps_the_guest_record_for_its_own_pass() {
    let me = acc(1004);
    let dir = temp_dir("guest-record-startup");
    std::fs::create_dir_all(&dir).unwrap();
    // Owner record: a unit whose process is gone (not in `starts`), which makes the pass save.
    std::fs::write(dir.join("paused.json"), "[[4242,0,111]]").unwrap();
    let u = gunit(200, 1, &me);
    sync_gate_probe::save_guest_record(
        &dir,
        &sync_gate_probe::GuestRecord {
            units: vec![u.clone()],
        },
    )
    .unwrap();
    let ctl = FakeControl::default();
    *ctl.fail_recover.lock().unwrap() = 1; // U stays frozen after its resume fails
    let c = Core::new(
        Config::default(),
        CostModel::default(),
        ctl.clone(),
        Some(dir.clone()),
    );
    c.recover_paused(Instant::now());
    assert_eq!(
        *ctl.recovered.lock().unwrap(),
        vec![vec![u.clone()]],
        "the guest unit never reached its recovery"
    );
    assert_eq!(guest_record(&dir), Some(vec![u]), "its record was lost");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A stored command `pending/<id>.json` aged by `age`; the folder is created private.
fn aged_pending(dir: &Path, id: TicketId, age: Duration) -> PathBuf {
    let pending = dir.join("pending");
    sync_gate_probe::create_private_dir(&pending).unwrap();
    let p = pending.join(format!("{id}.json"));
    std::fs::write(&p, "{}").unwrap();
    std::fs::File::options()
        .write(true)
        .open(&p)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - age)
        .unwrap();
    p
}

const DAY_AND_TWO_HOURS: Duration = Duration::from_secs(26 * 3600);
const SWEPT: &str = "removed 1 pending command(s) older than 25 h";

/// T2.1
#[test]
fn live_tickets_are_queued_running_and_just_dormant() {
    use crate::state::{RunningJob, State};
    let t0 = Instant::now();
    let mut st: State<()> = State::new(Config::default(), CostModel::default(), t0);
    let ticket = |id| sync_gate_core::Ticket {
        id,
        sig: sig("cargo build"),
        estimate: CostModel::default().estimate(&sig("cargo build"), true),
        session: "s1".into(),
        enqueued_at: t0,
        guest: None,
    };
    st.enqueue(ticket(1), t0);
    st.running.insert(
        2,
        RunningJob {
            sig: sig("cargo build"),
            reserved: 0,
            pid: Some(100),
            peak: 0,
            admitted_at: t0,
            paused_since: None,
            token: None,
            retry: false,
            resumed_at: None,
            claimed: true,
            guest: None,
            start: None,
        },
    );
    st.dormant
        .insert(3, (ticket(3), t0 + Duration::from_secs(30)));
    st.dormant.insert(4, (ticket(4), t0));
    assert_eq!(
        st.live_tickets(t0 + Duration::from_secs(61), Duration::from_secs(60)),
        std::collections::HashSet::from([1, 2, 3])
    );
}

/// T2.2
#[test]
fn the_tick_sweeps_expired_pending_files_every_ten_minutes() {
    let dir = temp_dir("sweep");
    let c = Core::new(
        Config::default(),
        CostModel::default(),
        FakeControl::default(),
        Some(dir.clone()),
    );
    let one = aged_pending(&dir, 1, DAY_AND_TWO_HOURS);
    let mut m = FakeMeasure::default();
    let t0 = Instant::now();
    c.tick(&mut m, t0);
    assert!(!one.exists(), "the first tick sweeps");
    assert!(has_decision(&c, SWEPT), "{:?}", decisions(&c));
    let two = aged_pending(&dir, 2, DAY_AND_TWO_HOURS);
    c.tick(&mut m, t0 + Duration::from_secs(599));
    assert!(two.exists(), "not yet due");
    c.tick(&mut m, t0 + Duration::from_secs(600));
    assert!(!two.exists(), "due after ten minutes");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A core whose only slot is held by a started job, with a second ticket queued behind it and
/// its stored command 26 h old, never renewed (an older CLI). Later ticks see no data, so
/// nothing is admitted or paused, and the running job's tree stays alive.
fn held_slot(
    tag: &str,
) -> (
    Arc<Core<FakeControl>>,
    FakeMeasure,
    Instant,
    TicketId,
    PathBuf,
    PathBuf,
) {
    let dir = temp_dir(tag);
    let c = Arc::new(Core::new(
        Config::default(),
        CostModel::default(),
        FakeControl::default(),
        Some(dir.clone()),
    ));
    let t0 = Instant::now();
    let mut m = FakeMeasure {
        snap: free(3 * GIB),
        ..Default::default()
    };
    c.tick(&mut m, t0);
    let a = admitted(&acquire(&c, "cargo build", t0));
    assert_eq!(
        c.handle(Request::Started { id: a, pid: 100 }, t0),
        Response::Ack
    );
    let Response::Queued { id: b, .. } = acquire(&c, "cargo build", t0) else {
        panic!("the slot is held")
    };
    m.snap = None;
    m.rss = HashMap::from([(100, 100 * MIB)]);
    let waited = aged_pending(&dir, b, DAY_AND_TWO_HOURS);
    // A control nobody waits on: proves each checked tick really swept.
    let other = aged_pending(&dir, 1, DAY_AND_TWO_HOURS);
    (c, m, t0, b, waited, other)
}

/// T2.3 (E3): a wait in progress keeps its stored command, renewed or not.
#[test]
fn a_live_wait_without_renewal_keeps_its_pending_file() {
    // Case 1: a Wait blocked in the daemon.
    let (c, mut m, t0, b, waited, other) = held_slot("livewait");
    let (tx, rx) = std::sync::mpsc::channel();
    {
        let c = c.clone();
        std::thread::spawn(move || {
            let _ = tx.send(c.handle(
                Request::Wait {
                    id: b,
                    timeout_secs: Some(5),
                },
                Instant::now(),
            ));
        });
    }
    let start = Instant::now();
    while !c.has_waiter(b) {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "waiter never registered"
        );
        std::thread::yield_now();
    }
    let t = t0 + Duration::from_secs(601);
    c.tick(&mut m, t);
    assert!(!other.exists(), "the tick swept");
    assert!(waited.exists(), "a blocked wait lost its stored command");
    let r = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the wait ends");
    assert!(matches!(r, Response::Queued { .. }), "{r:?}");
    c.tick(&mut m, t + Duration::from_secs(600));
    assert!(!waited.exists(), "nobody waits any more: swept");
    assert!(has_decision(&c, SWEPT), "{:?}", decisions(&c));
    let _ = std::fs::remove_dir_all(waited.parent().unwrap().parent().unwrap());

    // Case 2: between two Waits (the ticket just went dormant).
    let (c, mut m, t0, b, waited, other) = held_slot("betweenwaits");
    let t_end = t0 + Duration::from_secs(600);
    let r = c.handle(
        Request::Wait {
            id: b,
            timeout_secs: Some(0),
        },
        t_end,
    );
    assert!(matches!(r, Response::Queued { .. }), "{r:?}");
    c.tick(&mut m, t_end + Duration::from_secs(30));
    assert!(!other.exists(), "the tick swept");
    assert!(waited.exists(), "a wait 30 s ago lost its stored command");
    c.tick(&mut m, t_end + Duration::from_secs(630));
    assert!(!waited.exists(), "nobody waited for 630 s: swept");
    let _ = std::fs::remove_dir_all(waited.parent().unwrap().parent().unwrap());
}

/// An old-format `cost.json` (`history`, keys built from any non-option word).
fn old_cost_file(tag: &str, history: &str) -> PathBuf {
    let dir = temp_dir(tag);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("cost.json");
    std::fs::write(&path, format!("{{\"history\":{{{history}}}}}")).unwrap();
    path
}

/// T4.3 (X2): a cost file in the old key format is dropped and rewritten, never used.
#[test]
fn an_old_format_cost_file_is_discarded_and_rewritten() {
    let path = old_cost_file(
        "oldcost",
        r#""docker build TOKEN=dummy-secret @ site":{"last":1,"ema":1.0,"samples":3}"#,
    );
    let m = store::load(&path);
    let old = sync_gate_core::JobSignature {
        key: "docker build TOKEN=dummy-secret @ site".into(),
    };
    assert_eq!(m.estimate(&old, true), CostModel::prior(true));
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("history_v2"), "{text}");
    assert!(!text.contains("dummy-secret"), "{text}");
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

/// Review M4: an old-format cost file that cannot be rewritten (read-only: the rename onto it
/// fails on Windows) is removed, so its keys do not stay on disk.
#[cfg(windows)]
#[test]
fn an_old_format_cost_file_that_cannot_be_rewritten_is_removed() {
    let path = old_cost_file(
        "oldcost-ro",
        r#""docker build TOKEN=dummy-secret @ site":{"last":1,"ema":1.0,"samples":3}"#,
    );
    let mut perm = std::fs::metadata(&path).unwrap().permissions();
    perm.set_readonly(true);
    std::fs::set_permissions(&path, perm).unwrap();
    store::load(&path);
    let left = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(!left.contains("dummy-secret"), "{left}");
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

/// T4.4 (X2): a changed key never inherits a confident estimate learned for another command.
#[test]
fn a_changed_key_never_inherits_an_old_estimate() {
    let path = old_cost_file(
        "oldkey",
        &format!(
            r#""docker build MODE=large @ site":{{"last":{big},"ema":{big}.0,"samples":3}},"docker build . @ site":{{"last":{small},"ema":{small}.0,"samples":3}}"#,
            big = 8 * GIB,
            small = 256 * MIB
        ),
    );
    let m = store::load(&path);
    assert_eq!(
        m.estimate(&sig("docker build --build-arg MODE=large ."), true),
        CostModel::prior(true)
    );
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

/// T4.5 (X1): a credential in the arguments reaches neither the status nor `cost.json`.
#[test]
fn credentials_never_reach_cost_status_or_mcp() {
    let dir = temp_dir("creds");
    let c = Core::new(
        Config::default(),
        CostModel::default(),
        FakeControl::default(),
        Some(dir.clone()),
    );
    let t0 = Instant::now();
    let mut m = FakeMeasure {
        snap: free(3 * GIB),
        ..Default::default()
    };
    c.tick(&mut m, t0);
    let cmd =
        "docker build --build-arg PUBLIC=1 https://alice:dummy-secret@example.invalid/repo.git";
    let a = admitted(&acquire(&c, cmd, t0));
    let Response::Queued { .. } = acquire(&c, cmd, t0) else {
        panic!("the slot is held")
    };
    let Response::Status(s) = c.handle(Request::Status, t0) else {
        panic!()
    };
    let keys: Vec<&String> = s
        .running
        .iter()
        .map(|r| &r.1)
        .chain(s.queued.iter().map(|q| &q.1))
        .collect();
    assert_eq!(keys.len(), 2);
    assert!(keys.iter().all(|k| !k.contains("dummy-secret")), "{keys:?}");
    assert_eq!(
        c.handle(Request::Started { id: a, pid: 100 }, t0),
        Response::Ack
    );
    let fin = Request::Finished {
        id: a,
        peak_rss: 300 * MIB,
        exit_code: Some(0),
    };
    assert_eq!(c.handle(fin, t0), Response::Ack);
    let text = std::fs::read_to_string(dir.join("cost.json")).unwrap();
    assert!(text.contains("docker build @ site"), "{text}");
    assert!(!text.contains("dummy-secret"), "{text}");
    let _ = std::fs::remove_dir_all(&dir);
}
