//! Request handling and the per-tick control loop.
//!
//! Locking rule: the `State` mutex is held only for bookkeeping. Measuring, suspending,
//! resuming and disk writes happen outside it: decide under the lock, act, then record.

use crate::state::State;
use crate::store;
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use sync_gate_core::{
    Config, CostModel, DaemonInfo, ERR_ADMITTED, ERR_BUSY, ERR_CLAIMED, ERR_UNKNOWN_TICKET,
    GuestOf, JobSample, MAX_WAIT_SECS, MIB, MachineSnapshot, Request, Response, Ticket, TicketId,
    Verdict, analyze, guest_signature, signature, under_pressure,
};
use sync_gate_probe::{FrozenUnit, GuestSuspension, GuestUnit, Probe, Suspension};

/// An admitted ticket with no `Started` after this long is released (R13b).
const START_GRACE: Duration = Duration::from_secs(10);
/// A queued ticket never waited on is cancelled after `max_wait_secs` plus this (R13c).
const ABANDON_GRACE_SECS: u64 = 30;
/// Micro-analysis window: analyze once it spans this long...
const WINDOW_MIN: Duration = Duration::from_secs(1);
/// ...and never look further back than this.
const WINDOW_MAX: Duration = Duration::from_secs(3);
/// A paused job is resumed after this long even under pressure (R16).
const MAX_PAUSE: Duration = Duration::from_secs(300);
/// A dormant ticket nobody waits on again is dropped after this long (R17).
const DORMANT_TTL: Duration = Duration::from_secs(24 * 3600);
/// A job resumed this recently is not an eligible victim, so it cannot cycle pause/resume.
const RESUME_COOLDOWN: Duration = Duration::from_secs(60);
/// Leftovers of a previous daemon are retried at most this often...
const LEFTOVER_PERIOD: Duration = Duration::from_secs(1);
/// ...and only for this long after the start-up pass; then they just stay on record.
const LEFTOVER_WINDOW: Duration = Duration::from_secs(30);
/// Ticket of units a panicking resumer gave no result for (0 is "a previous daemon").
const PANICKED: TicketId = TicketId::MAX;
/// Stored commands older than `PENDING_TTL` are swept this often (and on the first tick).
const PENDING_SWEEP_EVERY: Duration = Duration::from_secs(600);
/// The CLI re-sends `Wait` 200 ms after the daemon's own wait ends: a ticket dormant for less
/// than this may still have a wait on it.
const WAIT_GAP: Duration = Duration::from_secs(60);

/// Pacing of the retry of what the start-up recovery pass could not resume.
struct Retry {
    window: Duration,
    period: Duration,
    /// When the start-up pass finished with leftovers; `None` = nothing to retry.
    start: Option<Instant>,
    last: Option<Instant>,
    /// The window ended: no more retries, the one line was printed.
    over: bool,
}

pub(crate) fn leftovers_stay(n: usize) -> String {
    format!(
        "sync_gated: could not resume {n} recorded unit(s) left by a previous daemon; they stay on record"
    )
}

/// Machine measurement, faked in tests.
pub trait Measure {
    fn snapshot(&mut self) -> MachineSnapshot;
    /// Resident bytes of `pid` and its descendants; 0 when the pid is gone.
    fn tree_rss(&mut self, pid: u32) -> u64;
    /// Start time of a live process (seconds); `None` when gone. Asked only for guest jobs.
    fn start_time(&mut self, pid: u32) -> Option<u64>;
}

impl Measure for Probe {
    fn snapshot(&mut self) -> MachineSnapshot {
        Probe::snapshot(self)
    }
    fn tree_rss(&mut self, pid: u32) -> u64 {
        Probe::tree_rss(self, pid)
    }
    fn start_time(&mut self, pid: u32) -> Option<u64> {
        sync_gate_probe::start_time(pid)
    }
}

/// Live tickets (queued, dormant or running) one guest entry may hold.
pub const GUEST_MAX_TICKETS: usize = 8;

/// Who sent a request.
#[derive(Clone, Copy, Debug)]
pub enum Caller<'a> {
    Owner,
    /// `client`: the token identity of THIS request, read by the guest door from the message (F47).
    /// `checked`: Some only on a Started whose pid has that same identity: the root start (seconds).
    Guest {
        index: u8,
        name: &'a str,
        client: &'a str,
        checked: Option<u64>,
    },
}

/// Pause/resume of a process tree, faked in tests. Never kills.
pub trait Control: Send + Sync + 'static {
    /// What a pause froze; resuming consumes it.
    type Token: Send + 'static;
    /// On failure, hands back a token holding the units its rollback could not resume (usually none).
    fn suspend(&self, pid: u32) -> Result<Self::Token, (Self::Token, io::Error)>;
    /// On a real failure, hands back a token holding only the units still frozen.
    fn resume(&self, token: Self::Token) -> Result<(), (Self::Token, io::Error)>;
    /// The units a token holds, for the paused-set file.
    fn units(&self, token: &Self::Token) -> Vec<FrozenUnit>;
    /// Rebuilds a token from persisted units (startup recovery).
    fn token(&self, units: Vec<FrozenUnit>) -> Self::Token;
    /// Resumes the current tree of `root` (a recorded pause intent); `NotFound` when gone.
    fn resume_tree(&self, root: u32) -> io::Result<()>;
    /// Start time of a live process; `None` when gone.
    fn start_time(&self, pid: u32) -> Option<u64>;
    /// A guest job's pause (sync_gate_probe::suspend_tree_as): `plan` sees each batch first.
    fn suspend_as(
        &self,
        pid: u32,
        start: u64,
        ident: &str,
        plan: &mut dyn FnMut(&[GuestUnit]) -> io::Result<()>,
    ) -> Result<Self::Token, (Self::Token, io::Error)>;
    /// The guest units a token holds (empty for an owner's token); `units` is empty for a guest's.
    fn guest_units(&self, token: &Self::Token) -> Vec<GuestUnit>;
    /// Recovery of recorded guest units by identity; the failed ones come back.
    fn resume_guest_units(&self, units: Vec<GuestUnit>) -> Vec<GuestUnit>;
}

/// What a real pause froze: the owner's units, or a guest's units with their thread handles.
#[derive(Debug)]
pub enum Frozen {
    Owner(Suspension),
    Guest(GuestSuspension),
}

/// Real control: resumes exactly the units it suspended, so orphaned grandchildren are not left frozen.
pub struct OsControl;

impl Control for OsControl {
    type Token = Frozen;
    fn suspend(&self, pid: u32) -> Result<Frozen, (Frozen, io::Error)> {
        sync_gate_probe::suspend_tree_recorded(pid)
            .map(Frozen::Owner)
            .map_err(|(t, e)| (Frozen::Owner(t), e))
    }
    fn resume(&self, token: Frozen) -> Result<(), (Frozen, io::Error)> {
        match token {
            Frozen::Owner(t) => t.resume().map_err(|(t, e)| (Frozen::Owner(t), e)),
            // Only through the handles held since the pause, never by id (D1).
            Frozen::Guest(t) => t.resume().map_err(|(t, e)| (Frozen::Guest(t), e)),
        }
    }
    fn units(&self, token: &Frozen) -> Vec<FrozenUnit> {
        match token {
            Frozen::Owner(t) => t.units().to_vec(),
            Frozen::Guest(_) => Vec::new(),
        }
    }
    fn token(&self, units: Vec<FrozenUnit>) -> Frozen {
        Frozen::Owner(Suspension::from_units(units))
    }
    fn resume_tree(&self, root: u32) -> io::Result<()> {
        sync_gate_probe::resume_tree(root)
    }
    fn start_time(&self, pid: u32) -> Option<u64> {
        sync_gate_probe::start_time(pid)
    }
    fn suspend_as(
        &self,
        pid: u32,
        start: u64,
        ident: &str,
        plan: &mut dyn FnMut(&[GuestUnit]) -> io::Result<()>,
    ) -> Result<Frozen, (Frozen, io::Error)> {
        sync_gate_probe::suspend_tree_as(pid, start, ident, plan)
            .map(Frozen::Guest)
            .map_err(|(t, e)| (Frozen::Guest(t), e))
    }
    fn guest_units(&self, token: &Frozen) -> Vec<GuestUnit> {
        match token {
            Frozen::Owner(_) => Vec::new(),
            Frozen::Guest(t) => t.units().to_vec(),
        }
    }
    fn resume_guest_units(&self, units: Vec<GuestUnit>) -> Vec<GuestUnit> {
        sync_gate_probe::resume_guest_units(units)
    }
}

/// A guest job's ident and its checked root start (None: never checked).
type GuestPause = (String, Option<u64>);

/// Process-control step decided under the lock and performed after releasing it.
enum Act<T> {
    /// The last field: a guest job's (ident, checked root start), decided with the victim, so
    /// a guest's pid never takes the owner's path even if the job ends meanwhile.
    Pause(TicketId, u32, String, Option<GuestPause>),
    /// Resume a paused job; the message is recorded on success.
    Resume(TicketId, T, String),
    /// Retry the leftover units of a job that already ended.
    Orphan(TicketId, T),
}

pub struct Core<C: Control> {
    state: Mutex<State<C::Token>>,
    /// Signalled whenever a ticket is admitted or removed, to wake blocked `Wait`s.
    cv: Condvar,
    resumes_done: Condvar,
    control: C,
    /// Holds `cost.json` and `paused.json`; `None` keeps everything in memory.
    data_dir: Option<PathBuf>,
    /// Serialises file writes (connection threads finish concurrently and share temp files).
    /// Order: taken before the state lock, never while holding it.
    save_lock: Mutex<()>,
    /// Overall bound of a clean shutdown (milliseconds; shortened by tests).
    drain_ms: AtomicU64,
    /// Set by the final save at shutdown: the instance lock is about to be released, so a
    /// thread left behind must never write the record (or record a new pause) again.
    closed: AtomicBool,
    /// Shutdown began: nothing is paused any more, and a pause that raced it is undone.
    draining: AtomicBool,
    /// `paused.json` could not be read at start-up: nothing may be written to it, so nothing is
    /// paused, until a later pass reads it.
    record_unavailable: AtomicBool,
    /// The same for `paused-guests.json`: it is never written, so no guest job is paused.
    guest_record_unavailable: AtomicBool,
    /// Start-up recovery has not loaded `paused-guests.json` yet: the owner pass saves before the
    /// guest pass, and that save must leave the guest file as it is (it holds frozen units).
    guest_record_unloaded: AtomicBool,
    /// Reported in every `Status`, so the CLI recovers from the dir this daemon really uses.
    daemon: DaemonInfo,
    retry: Mutex<Retry>,
    /// When the stored commands were last swept; `None`: never (the first tick sweeps).
    last_sweep: Mutex<Option<Instant>>,
}

/// Keeps a resume's units visible until its result has been recorded, including unwinding.
struct ResumeGuard<'a, C: Control> {
    core: &'a Core<C>,
    key: u64,
}

impl<C: Control> Drop for ResumeGuard<'_, C> {
    fn drop(&mut self) {
        let mut st = self.core.lock();
        let units = st.in_flight.remove(&self.key);
        let guest = st.guest_in_flight.remove(&self.key);
        if std::thread::panicking() {
            // A panicking resumer gave no result: retain every unit for a safe retry.
            if let Some(units) = units.filter(|u| !u.is_empty()) {
                st.orphans.push((PANICKED, self.core.control.token(units)));
            }
            // Their handles went with the token: recovery by identity is what is left.
            st.guest_leftovers.extend(guest.unwrap_or_default());
        }
        drop(st);
        self.core.resumes_done.notify_all();
        self.core.save_paused();
    }
}

impl<C: Control> Core<C> {
    pub fn new(cfg: Config, cost: CostModel, control: C, data_dir: Option<PathBuf>) -> Self {
        let pid = std::process::id();
        let daemon = DaemonInfo {
            pid,
            start_time: sync_gate_probe::start_time(pid).unwrap_or(0),
            data_dir: data_dir.clone(),
        };
        Self {
            daemon,
            state: Mutex::new(State::new(cfg, cost, Instant::now())),
            cv: Condvar::new(),
            resumes_done: Condvar::new(),
            control,
            data_dir,
            save_lock: Mutex::new(()),
            drain_ms: AtomicU64::new(5_000),
            closed: AtomicBool::new(false),
            draining: AtomicBool::new(false),
            record_unavailable: AtomicBool::new(false),
            guest_record_unavailable: AtomicBool::new(false),
            guest_record_unloaded: AtomicBool::new(false),
            retry: Mutex::new(Retry {
                window: LEFTOVER_WINDOW,
                period: LEFTOVER_PERIOD,
                start: None,
                last: None,
                over: false,
            }),
            last_sweep: Mutex::new(None),
        }
    }

    /// A panic while holding the lock must not take the daemon down with it.
    fn lock(&self) -> MutexGuard<'_, State<C::Token>> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Free memory (available plus reclaimable, as the resume rule counts it) and the reserve
    /// (`total * reserve_fraction`) from the last snapshot; `None` while there is no data.
    pub fn memory(&self) -> Option<(u64, u64)> {
        let st = self.lock();
        let s = st.snapshot;
        (s.total > 0).then(|| {
            let reserve = (s.total as f64 * st.cfg.reserve_fraction) as u64;
            (s.available.saturating_add(s.reclaimable), reserve)
        })
    }

    /// Appends decisions made elsewhere (the MCP hub) to the log `status` shows.
    pub fn record_all(&self, now: Instant, msgs: Vec<String>) {
        if msgs.is_empty() {
            return;
        }
        let mut st = self.lock();
        for m in msgs {
            st.record(now, m);
        }
    }

    /// Called under the same lock that removes a token from its job or orphan list.
    fn track_resume(&self, st: &mut State<C::Token>, token: &C::Token) -> ResumeGuard<'_, C> {
        let key = st.next_resume;
        st.next_resume += 1;
        st.in_flight.insert(key, self.control.units(token));
        st.guest_in_flight
            .insert(key, self.control.guest_units(token));
        ResumeGuard { core: self, key }
    }

    /// Every unit a token still holds frozen, the owner's and the guest's: the one test of
    /// "is anything left" (E3).
    fn frozen_units(&self, t: &C::Token) -> usize {
        self.control.units(t).len() + self.control.guest_units(t).len()
    }

    /// Units this daemon holds frozen: paused jobs, orphans and resumes in flight.
    fn held(&self, st: &State<C::Token>) -> usize {
        let jobs = st.running.values().filter_map(|j| j.token.as_ref());
        let held: usize = jobs
            .chain(st.orphans.iter().map(|(_, t)| t))
            .map(|t| self.frozen_units(t))
            .sum();
        held + st.in_flight.values().map(Vec::len).sum::<usize>()
            + st.guest_in_flight.values().map(Vec::len).sum::<usize>()
    }

    pub(crate) fn begin_shutdown(&self) {
        self.draining.store(true, Ordering::SeqCst);
    }

    pub(crate) fn shutdown_bound(&self) -> Duration {
        Duration::from_millis(self.drain_ms.load(Ordering::SeqCst))
    }

    /// Waits until no resume is in flight or `deadline` passes; true when none is left.
    pub(crate) fn finish_resumes(&self, deadline: Instant) -> bool {
        let st = self.lock();
        let left = deadline.saturating_duration_since(Instant::now());
        let (st, _) = self
            .resumes_done
            .wait_timeout_while(st, left, |st| !st.in_flight.is_empty())
            .unwrap_or_else(|e| e.into_inner());
        st.in_flight.is_empty()
    }

    /// Final save at shutdown, then no more: returns how many units are still frozen.
    pub(crate) fn close(&self) -> usize {
        self.save_paused();
        let _saving = self.save_lock.lock().unwrap_or_else(|e| e.into_inner());
        self.closed.store(true, Ordering::SeqCst);
        let st = self.lock();
        self.held(&st)
    }

    /// Saves the current cost model; the copy is taken inside the save lock so the newest always wins.
    pub fn save_cost(&self) {
        let Some(dir) = &self.data_dir else {
            return;
        };
        let _saving = self.save_lock.lock().unwrap_or_else(|e| e.into_inner());
        let cost = self.lock().cost.clone();
        let path = dir.join("cost.json");
        if let Err(e) = store::save(&path, &cost) {
            eprintln!("sync_gated: cannot save {}: {e}", path.display());
        }
    }

    /// Writes every paused, orphaned or in-flight unit and every pause intent to `paused.json`;
    /// a failure is reported and left for the next save.
    fn save_paused(&self) {
        if self.closed.load(Ordering::SeqCst) || self.record_unavailable.load(Ordering::SeqCst) {
            return;
        }
        if let Err(e) = self.try_save_paused() {
            eprintln!("sync_gated: cannot save paused.json: {e}");
        }
    }

    fn try_save_paused(&self) -> io::Result<()> {
        let Some(dir) = &self.data_dir else {
            return Ok(());
        };
        let _saving = self.save_lock.lock().unwrap_or_else(|e| e.into_inner());
        if self.closed.load(Ordering::SeqCst) {
            return Err(io::Error::other("the daemon is shutting down"));
        }
        if self.record_unavailable.load(Ordering::SeqCst) {
            return Err(io::Error::other("paused.json cannot be read"));
        }
        let (mut record, mut guests) = {
            let st = self.lock();
            let jobs = st.running.values().filter_map(|j| j.token.as_ref());
            let record = sync_gate_probe::PausedRecord {
                units: jobs
                    .chain(st.orphans.iter().map(|(_, t)| t))
                    .flat_map(|t| self.control.units(t))
                    .chain(st.in_flight.values().flatten().copied())
                    .map(|u| (u.pid, u.tid, u.start_time))
                    .collect(),
                intents: st
                    .intents
                    .iter()
                    .map(|&(_, pid, start)| (pid, start))
                    .collect(),
            };
            // Everything of a guest goes to its own file, which no older binary touches (D3).
            let tokens = st.running.values().filter_map(|j| j.token.as_ref());
            let guests: Vec<GuestUnit> = tokens
                .chain(st.orphans.iter().map(|(_, t)| t))
                .flat_map(|t| self.control.guest_units(t))
                .chain(st.guest_in_flight.values().flatten().cloned())
                .chain(st.guest_planned.values().flatten().cloned())
                .chain(st.guest_leftovers.iter().cloned())
                .collect();
            (record, guests)
        };
        record.units.sort_unstable();
        record.units.dedup();
        record.intents.sort_unstable();
        record.intents.dedup();
        guests.sort_by(|a, b| {
            (a.pid, a.tid, a.created, &a.ident).cmp(&(b.pid, b.tid, b.created, &b.ident))
        });
        guests.dedup();
        let owner = sync_gate_probe::save_record(&dir.join(sync_gate_probe::PAUSED_FILE), &record);
        // An unreadable guest record is never replaced (that would drop what it holds).
        let guest = if !self.guest_record_unavailable.load(Ordering::SeqCst)
            && !self.guest_record_unloaded.load(Ordering::SeqCst)
        {
            sync_gate_probe::save_guest_record(dir, &sync_gate_probe::GuestRecord { units: guests })
        } else if guests.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other("paused-guests.json cannot be read"))
        };
        owner.and(guest)
    }

    /// R15, at startup before serving and under the instance lock: the same recovery passes a CLI
    /// runs through `recover_as_owner` (the owner's, then the guests'). What fails is kept and
    /// retried every tick.
    pub fn recover_paused(&self, now: Instant) {
        self.guest_record_unloaded.store(true, Ordering::SeqCst);
        self.recover_owner(now);
        self.recover_guests(now);
        // Loaded (its units are retained) or unreadable (`guest_record_unavailable` guards it).
        self.guest_record_unloaded.store(false, Ordering::SeqCst);
    }

    fn recover_owner(&self, now: Instant) {
        let Some(dir) = &self.data_dir else {
            return;
        };
        let pass = match sync_gate_probe::recovery_pass(
            dir,
            &mut ControlRecover::new(&self.control),
        ) {
            Ok(pass) => pass,
            Err(e) => {
                if !self.record_unavailable.swap(true, Ordering::SeqCst) {
                    eprintln!(
                        "sync_gated: cannot read paused.json ({e}); pausing is off until it can be read"
                    );
                }
                return;
            }
        };
        self.record_unavailable.store(false, Ordering::SeqCst);
        if pass.resumed + pass.gone + pass.failed == 0 {
            return;
        }
        let mut st = self.lock();
        if !pass.kept.units.is_empty() {
            let units = pass
                .kept
                .units
                .iter()
                .map(|&(pid, tid, start_time)| FrozenUnit {
                    pid,
                    tid,
                    start_time,
                });
            st.orphans.push((0, self.control.token(units.collect())));
        }
        st.intents.extend(
            pass.kept
                .intents
                .iter()
                .map(|&(pid, start)| (0, pid, start)),
        );
        let mut msg = format!(
            "resumed {} units left paused by a previous run",
            pass.resumed
        );
        if pass.failed > 0 {
            msg.push_str(&format!("; {} failed, retrying", pass.failed));
        }
        st.record(now, msg);
        drop(st);
        {
            let mut r = self.retry.lock().unwrap_or_else(|e| e.into_inner());
            (r.start, r.last) = (Some(now), Some(now));
        }
        self.save_paused();
    }

    /// The guests' pass over `paused-guests.json`: each unit resumed by its checked identity;
    /// the failed ones become `guest_leftovers`, retried like the ticket-0 units. A record that
    /// cannot be read stops guest pauses until a later pass reads it.
    fn recover_guests(&self, now: Instant) {
        let Some(dir) = &self.data_dir else {
            return;
        };
        let mut r = ControlRecover::new(&self.control);
        let result = sync_gate_probe::guest_recovery_pass(dir, &mut r);
        let (pass, kept) = match (result, r.guest_kept) {
            (Ok(pass), kept) => (pass, kept.map(|k| k.1).unwrap_or_default()),
            // At-least-once (R-3S-T3a): the units were handed over but the record could not be
            // settled; the next save rewrites it with exactly what stayed frozen.
            (Err(e), Some((handed, kept))) => {
                let line = format!(
                    "sync_gated: cannot settle {} ({e}); rewriting it",
                    sync_gate_probe::GUEST_PAUSED_FILE
                );
                eprintln!("{line}");
                self.lock().record(now, line);
                let pass = sync_gate_probe::Pass {
                    resumed: handed.saturating_sub(kept.len()),
                    failed: kept.len(),
                    ..Default::default()
                };
                (pass, kept)
            }
            (Err(e), None) => {
                if !self.guest_record_unavailable.swap(true, Ordering::SeqCst) {
                    eprintln!(
                        "sync_gated: cannot read {} ({e}); guest pauses are off until it can be read",
                        sync_gate_probe::GUEST_PAUSED_FILE
                    );
                }
                return;
            }
        };
        self.guest_record_unavailable.store(false, Ordering::SeqCst);
        if pass.resumed + pass.failed == 0 && kept.is_empty() {
            return;
        }
        let mut st = self.lock();
        let mut msg = format!(
            "resumed {} guest units left paused by a previous run",
            pass.resumed
        );
        if !kept.is_empty() {
            msg.push_str(&format!("; {} failed, retrying", kept.len()));
        }
        st.record(now, msg);
        let left = !kept.is_empty();
        st.guest_leftovers.extend(kept);
        drop(st);
        if left {
            let mut r = self.retry.lock().unwrap_or_else(|e| e.into_inner());
            (r.start, r.last) = (Some(now), Some(now));
        }
        self.save_paused();
    }

    /// Once per period, with no end: whether to read the unreadable record again.
    fn record_retry_due(&self, now: Instant) -> bool {
        let mut r = self.retry.lock().unwrap_or_else(|e| e.into_inner());
        let waiting = r
            .last
            .is_some_and(|l| now.saturating_duration_since(l) < r.period);
        if !waiting {
            r.last = Some(now);
        }
        !waiting
    }

    /// Whether this tick may retry what a previous daemon left (units and intents, ticket 0):
    /// at most once per period, for the window after the start-up pass, and never while this
    /// daemon holds a paused job or has a pause or resume in progress (a tree resume could
    /// undo a pause on purpose). When the window ends with entries left, says so once; they
    /// stay on record for the next daemon or a CLI pass.
    fn leftover_retry_due(&self, st: &mut State<C::Token>, now: Instant) -> bool {
        let mut r = self.retry.lock().unwrap_or_else(|e| e.into_inner());
        let Some(start) = r.start.filter(|_| !r.over) else {
            return false;
        };
        let units: usize = st
            .orphans
            .iter()
            .filter(|(id, _)| *id == 0)
            .map(|(_, t)| self.frozen_units(t))
            .sum();
        let left =
            units + st.guest_leftovers.len() + st.intents.iter().filter(|i| i.0 == 0).count();
        if left == 0 {
            return false;
        }
        if now.saturating_duration_since(start) >= r.window {
            r.over = true;
            let line = leftovers_stay(left);
            eprintln!("{line}");
            st.record(now, line);
            return false;
        }
        let busy = st.running.values().any(|j| j.token.is_some())
            || !st.in_flight.is_empty()
            || !st.guest_planned.is_empty()
            || st.intents.iter().any(|i| i.0 != 0);
        let waiting = r
            .last
            .is_some_and(|l| now.saturating_duration_since(l) < r.period);
        if busy || waiting {
            return false;
        }
        r.last = Some(now);
        true
    }

    /// Retries the tree resume of intents a previous run left (identity checked each time);
    /// true when there were any. They stay recorded until resumed or gone.
    fn retry_stale_intents(&self) -> bool {
        let stale: Vec<(u32, u64)> = self
            .lock()
            .intents
            .iter()
            .filter(|i| i.0 == 0)
            .map(|&(_, pid, start)| (pid, start))
            .collect();
        let settled: Vec<(u32, u64)> = stale
            .iter()
            .copied()
            .filter(|&(root, start)| {
                self.control.start_time(root) != Some(start)
                    || match self.control.resume_tree(root) {
                        Ok(()) => true,
                        Err(e) => e.kind() == io::ErrorKind::NotFound,
                    }
            })
            .collect();
        self.lock()
            .intents
            .retain(|&(id, pid, start)| id != 0 || !settled.contains(&(pid, start)));
        !stale.is_empty()
    }

    /// Retries the guest units a recovery pass could not resume, by identity; true when there
    /// were any. They stay recorded until resumed or gone.
    fn retry_guest_leftovers(&self) -> bool {
        let units = self.lock().guest_leftovers.clone();
        if units.is_empty() {
            return false;
        }
        let failed = self.control.resume_guest_units(units.clone());
        self.lock()
            .guest_leftovers
            .retain(|u| !units.contains(u) || failed.contains(u));
        true
    }

    /// Resumes a token of a job that has ended; units that fail stay as an orphan, retried every tick.
    fn resume_ended(&self, id: TicketId, token: Option<C::Token>) {
        let Some(t) = token else {
            return;
        };
        if let Err((rest, e)) = self.control.resume(t) {
            eprintln!("sync_gated: resume of #{id} failed, will retry: {e}");
            self.lock().orphans.push((id, rest));
        }
        self.save_paused();
    }

    pub fn handle(&self, req: Request, now: Instant) -> Response {
        self.handle_as(Caller::Owner, req, now)
    }

    /// A request from `caller`. A guest acts only on the tickets it asked for (entry AND
    /// identity, E2), gets the prior for every command and never teaches the cost model.
    pub fn handle_as(&self, caller: Caller, req: Request, now: Instant) -> Response {
        let me = match caller {
            Caller::Owner => None,
            Caller::Guest { index, client, .. } => Some(GuestOf {
                index,
                ident: client.to_string(),
            }),
        };
        // Checked first: the owner never reaches a guest's ticket, a guest only its own.
        if let Some(id) = ticket_of(&req) {
            let foreign = match self.lock().caller_of(id) {
                Some(of) => of != me.as_ref(),
                None => me.is_some(),
            };
            if foreign {
                return error(format!("ticket #{id} {ERR_UNKNOWN_TICKET}"));
            }
        }
        match req {
            Request::Acquire {
                argv,
                cwd,
                session,
                heavy,
            } => {
                let argv: Vec<OsString> = argv.into_iter().map(OsString::from).collect();
                // A guest's key comes from the text alone: its cwd is never looked at (O1).
                let sig = match caller {
                    Caller::Owner => signature(&argv, &cwd),
                    Caller::Guest { name, .. } => guest_signature(name, &argv, &cwd),
                };
                let sig = match sig {
                    Ok(s) => s,
                    Err(e) => return error(e),
                };
                let mut st = self.lock();
                let (estimate, session) = match &me {
                    None => (st.cost.estimate(&sig, heavy), session),
                    Some(g) if st.live_guest_tickets(g.index) >= GUEST_MAX_TICKETS => {
                        return error(format!(
                            "{ERR_BUSY}: {GUEST_MAX_TICKETS} commands already queued or running"
                        ));
                    }
                    Some(g) => (
                        CostModel::prior(heavy),
                        format!("guest-{}/{session}", g.index),
                    ),
                };
                let id = st.next_id;
                st.next_id += 1;
                let ticket = Ticket {
                    id,
                    sig,
                    estimate,
                    session,
                    enqueued_at: now,
                    guest: me,
                };
                st.enqueue(ticket, now);
                let admitted = st.admit(now);
                let resp = if admitted.contains(&id) {
                    st.running.get_mut(&id).expect("just admitted").claimed = true;
                    Response::Admitted { id }
                } else {
                    Response::Queued {
                        id,
                        position: st.sched.position(id).unwrap_or(0),
                    }
                };
                drop(st);
                if !admitted.is_empty() {
                    self.cv.notify_all();
                }
                resp
            }
            Request::Started { id, pid } => {
                let start = match caller {
                    Caller::Owner => None,
                    Caller::Guest { checked: None, .. } => {
                        return error(format!("process {pid} does not run as this caller"));
                    }
                    Caller::Guest { checked, .. } => checked,
                };
                let mut st = self.lock();
                match st.running.get_mut(&id) {
                    Some(j) if j.pid.is_none() && pid != 0 => {
                        j.pid = Some(pid);
                        j.start = start;
                        Response::Ack
                    }
                    _ => error(format!("ticket #{id} is not admitted or already started")),
                }
            }
            Request::Finished {
                id,
                peak_rss,
                exit_code,
            } => {
                let mut st = self.lock();
                let Some(job) = st.end(id) else {
                    return error(format!("ticket #{id} is not running"));
                };
                let peak = peak_rss.max(job.peak);
                // A guest's command never teaches the owner's cost model.
                if job.guest.is_none() {
                    st.cost.record(&job.sig, peak);
                }
                let exit = exit_code.map_or("none".into(), |c| c.to_string());
                st.record(
                    now,
                    format!("finished #{id}: peak {} MiB, exit {exit}", peak / MIB),
                );
                let in_flight = job.token.as_ref().map(|t| self.track_resume(&mut st, t));
                drop(st);
                self.cv.notify_all();
                self.resume_ended(id, job.token);
                drop(in_flight);
                self.save_cost();
                Response::Ack
            }
            Request::Wait { id, timeout_secs } => self.wait(id, timeout_secs, now),
            Request::Cancel { id } => {
                let mut st = self.lock();
                // Ownership starts when admission is delivered, before the child is spawned.
                if st
                    .running
                    .get(&id)
                    .is_some_and(|j| j.claimed || j.pid.is_some())
                {
                    return error(format!("ticket {id} {ERR_ADMITTED}; it ends with Finished"));
                }
                let token = if st.cancel_queued(id) {
                    st.record(now, format!("cancelled #{id}: by client"));
                    None
                } else if let Some(job) = st.end(id) {
                    st.record(now, format!("released #{id}: cancelled by client"));
                    job.token
                } else {
                    return error(format!("unknown ticket #{id}"));
                };
                let in_flight = token.as_ref().map(|t| self.track_resume(&mut st, t));
                drop(st);
                self.cv.notify_all();
                self.resume_ended(id, token);
                drop(in_flight);
                Response::Ack
            }
            Request::Status => {
                Response::Status(self.lock().status(self.daemon.clone(), me.as_ref()))
            }
            Request::Lease { .. }
            | Request::LeaseHolder { .. }
            | Request::ReleaseLease { .. }
            | Request::LeaseGiveUp { .. }
            | Request::TemplateReady { .. } => error("postgres service not available"),
        }
    }

    /// Blocks until `id` is admitted, dropped, or `min(timeout_secs, max_wait_secs)` passes. On timeout the
    /// reply is `Queued` and, with no other waiter, the ticket goes dormant (R17); a later
    /// `Wait` wakes it with its original age.
    fn wait(&self, id: TicketId, timeout_secs: Option<u64>, now: Instant) -> Response {
        let mut st = self.lock();
        if st.wake(id, now) && !st.admit(now).is_empty() {
            self.cv.notify_all();
        }
        let secs = timeout_secs.map_or(st.cfg.max_wait_secs, |t| t.min(st.cfg.max_wait_secs));
        let deadline = Instant::now() + Duration::from_secs(secs.min(MAX_WAIT_SECS));
        if let Some(q) = st.queued.get_mut(&id) {
            q.waiters += 1;
        }
        let resp = loop {
            if let Some(j) = st.running.get_mut(&id) {
                // C1: exactly one client gets to run an admitted ticket.
                if j.claimed {
                    break error(format!("ticket #{id} {ERR_CLAIMED}"));
                }
                j.claimed = true;
                break Response::Admitted { id };
            }
            if !st.queued.contains_key(&id) {
                break error(format!("ticket #{id} {ERR_UNKNOWN_TICKET}"));
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break Response::Queued {
                    id,
                    position: st.sched.position(id).unwrap_or(0),
                };
            }
            st = self
                .cv
                .wait_timeout(st, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        };
        let end = Instant::now().max(now);
        if let Some(q) = st.queued.get_mut(&id) {
            q.waiters = q.waiters.saturating_sub(1);
            q.last_seen = end;
            if q.waiters == 0 {
                st.make_dormant(id, end);
            }
        }
        resp
    }

    /// One control-loop step: measure, reap, admit, then pause or resume.
    pub fn tick(&self, m: &mut impl Measure, now: Instant) {
        let pids: Vec<(TicketId, u32, Option<u64>)> = self
            .lock()
            .running
            .iter()
            .filter_map(|(&id, j)| j.pid.map(|p| (id, p, j.start)))
            .collect();
        let snap = m.snapshot();
        let rss: Vec<(TicketId, u32, u64)> = pids
            .iter()
            .map(|&(id, pid, _)| (id, pid, m.tree_rss(pid)))
            .collect();
        // A guest job whose root now has another start time is gone: its pid was reused.
        // shortcut (S10): 1 s resolution here; the pause itself checks the 100 ns creation by
        // handle. shortcut (S12): tree_rss counts the whole tree by parentage.
        let moved: Vec<TicketId> = pids
            .iter()
            .filter(|&&(_, pid, start)| start.is_some_and(|s| m.start_time(pid) != Some(s)))
            .map(|p| p.0)
            .collect();

        let owner_record = self.record_unavailable.load(Ordering::SeqCst);
        let guest_record = self.guest_record_unavailable.load(Ordering::SeqCst);
        if (owner_record || guest_record) && self.record_retry_due(now) {
            if owner_record {
                self.recover_owner(now);
            }
            if guest_record {
                self.recover_guests(now);
            }
        }
        let mut st = self.lock();
        st.snapshot = snap;
        let mut changed = false;
        let mut acts = Vec::new();
        let mut save = false;

        // R13a: a started job whose process tree is gone.
        for &(id, pid, r) in &rss {
            let gone = match st.running.get_mut(&id) {
                Some(j) if j.pid == Some(pid) => {
                    j.peak = j.peak.max(r);
                    r == 0 || moved.contains(&id)
                }
                _ => continue,
            };
            if gone {
                let job = st.end(id).expect("present above");
                // A peak never sampled (died within one tick) would teach a 0-byte cost; a
                // guest's job never teaches one.
                if job.peak > 0 && job.guest.is_none() {
                    st.cost.record(&job.sig, job.peak);
                    save = true;
                }
                let msg = format!("released #{id}: process gone, peak {} MiB", job.peak / MIB);
                st.record(now, msg);
                acts.extend(job.token.map(|t| Act::Orphan(id, t)));
                changed = true;
            }
        }
        // R13b: admitted but never started.
        let unstarted: Vec<TicketId> = st
            .running
            .iter()
            .filter(|(_, j)| {
                j.pid.is_none() && now.saturating_duration_since(j.admitted_at) > START_GRACE
            })
            .map(|(&id, _)| id)
            .collect();
        for id in unstarted {
            st.end(id);
            st.record(now, format!("released #{id}: never started"));
            changed = true;
        }
        // R13c: queued, never waited on, for too long.
        let limit = Duration::from_secs(st.cfg.max_wait_secs.saturating_add(ABANDON_GRACE_SECS));
        let abandoned: Vec<TicketId> = st
            .queued
            .iter()
            .filter(|(_, q)| q.waiters == 0 && now.saturating_duration_since(q.last_seen) > limit)
            .map(|(&id, _)| id)
            .collect();
        for id in abandoned {
            st.cancel_queued(id);
            st.record(now, format!("cancelled #{id}: abandoned, nobody waiting"));
            changed = true;
        }
        // R17: dormant tickets expire.
        let expired: Vec<TicketId> = st
            .dormant
            .iter()
            .filter(|(_, (_, since))| now.saturating_duration_since(*since) > DORMANT_TTL)
            .map(|(&id, _)| id)
            .collect();
        for id in expired {
            st.dormant.remove(&id);
            st.record(now, format!("expired #{id}: dormant for 24 h"));
        }
        changed |= !st.admit(now).is_empty();

        // Leftover units of ended jobs, retries of failed resumes, and the max-pause rule
        // run whatever the measurement says: never leave a process frozen.
        let retry_leftovers = self.leftover_retry_due(&mut st, now);
        let (held, orphans): (Vec<_>, Vec<_>) = std::mem::take(&mut st.orphans)
            .into_iter()
            .partition(|(id, _)| *id == 0 && !retry_leftovers);
        st.orphans = held;
        acts.extend(orphans.into_iter().map(|(id, t)| Act::Orphan(id, t)));
        for (&id, j) in st.running.iter_mut() {
            let overdue = j
                .paused_since
                .is_some_and(|t| now.saturating_duration_since(t) >= MAX_PAUSE);
            let msg = if j.retry {
                format!("resumed #{id} on retry")
            } else if overdue {
                format!("resumed #{id} after max pause (300 s)")
            } else {
                continue;
            };
            if let Some(t) = j.token.take() {
                acts.push(Act::Resume(id, t, msg));
            }
        }

        if snap.total == 0 {
            // No data: never pause or resume blind.
            st.window.clear();
        } else if under_pressure(&snap, &st.cfg) {
            acts.extend(self.pressure_step(&mut st, snap, &rss, now));
        } else {
            st.window.clear();
            acts.extend(resume_candidate(&mut st, snap));
        }
        let acts: Vec<_> = acts
            .into_iter()
            .map(|act| {
                let guard = match &act {
                    Act::Resume(_, t, _) | Act::Orphan(_, t) => Some(self.track_resume(&mut st, t)),
                    Act::Pause(..) => None,
                };
                (act, guard)
            })
            .collect();
        drop(st);

        if changed {
            self.cv.notify_all();
        }
        if save {
            self.save_cost();
        }
        // What a previous run left is retried whatever the measurement says (bounded).
        let retried = retry_leftovers && {
            let intents = self.retry_stale_intents();
            self.retry_guest_leftovers() | intents
        };
        let touched = !acts.is_empty() || retried;
        for (act, in_flight) in acts {
            match act {
                Act::Pause(id, pid, reason, guest) => self.pause(id, pid, &reason, guest, now),
                Act::Resume(id, token, msg) => self.resume_job(id, token, &msg, now),
                Act::Orphan(id, token) => {
                    if let Err((rest, e)) = self.control.resume(token) {
                        let mut st = self.lock();
                        if st.should_log_failure(id, now) {
                            eprintln!("sync_gated: resume of ended #{id} failed, retrying: {e}");
                        }
                        st.orphans.push((id, rest));
                    }
                }
            }
            drop(in_flight);
        }
        if touched {
            self.save_paused();
        }
        self.sweep_pending_if_due(now);
    }

    /// Deletes the stored commands (`<data>/pending`) older than `PENDING_TTL`, every ten
    /// minutes, never one of a ticket a wait may still be on. The disk work runs without the
    /// state lock.
    fn sweep_pending_if_due(&self, now: Instant) {
        let Some(dir) = &self.data_dir else {
            return;
        };
        {
            let mut last = self.last_sweep.lock().unwrap_or_else(|e| e.into_inner());
            if last.is_some_and(|t| now.saturating_duration_since(t) < PENDING_SWEEP_EVERY) {
                return;
            }
            *last = Some(now);
        }
        let live = self.lock().live_tickets(now, WAIT_GAP);
        let n = sync_gate_probe::sweep_pending(
            &dir.join("pending"),
            sync_gate_probe::PENDING_TTL,
            |id| live.contains(&id),
        );
        if n > 0 {
            self.lock().record(
                now,
                format!("removed {n} pending command(s) older than 25 h"),
            );
        }
    }

    /// Resumes a paused job; on failure keeps the still-frozen units as its token and retries next tick.
    fn resume_job(&self, id: TicketId, token: C::Token, msg: &str, now: Instant) {
        let result = self.control.resume(token);
        let mut st = self.lock();
        match (result, st.running.get_mut(&id)) {
            (Ok(()), Some(j)) => {
                j.paused_since = None;
                j.retry = false;
                j.resumed_at = Some(now);
                st.record(now, msg);
            }
            (Ok(()), None) => st.record(now, msg),
            (Err((rest, e)), job) => {
                match job {
                    Some(j) => {
                        j.token = Some(rest);
                        j.retry = true;
                    }
                    None => st.orphans.push((id, rest)),
                }
                // Retried every tick, but logged at most once per 30 s.
                if st.should_log_failure(id, now) {
                    st.record(
                        now,
                        format!("resume #{id} failed: {e}; retrying every tick"),
                    );
                }
            }
        }
    }

    /// Adds this tick to the window; once it spans 1 s, runs the micro-analysis.
    fn pressure_step(
        &self,
        st: &mut State<C::Token>,
        snap: MachineSnapshot,
        rss: &[(TicketId, u32, u64)],
        now: Instant,
    ) -> Option<Act<C::Token>> {
        let samples: Vec<JobSample> = rss
            .iter()
            .filter(|(id, _, r)| {
                *r > 0
                    && st.running.get(id).is_some_and(|j| {
                        j.paused_since.is_none()
                            && j.resumed_at
                                .is_none_or(|t| now.saturating_duration_since(t) >= RESUME_COOLDOWN)
                    })
            })
            .map(|&(id, _, r)| JobSample {
                id,
                rss: r,
                // shortcut: no dependency info exists yet, so no job counts as awaited by others;
                // upgrade when the CLI reports which jobs block which.
                awaited_by_others: false,
            })
            .collect();
        st.window.push((now, snap, samples));
        st.window
            .retain(|(t, ..)| now.saturating_duration_since(*t) <= WINDOW_MAX);
        let span = now.saturating_duration_since(st.window[0].0);
        if span < WINDOW_MIN || st.window.len() < 2 {
            return None;
        }
        let window: Vec<_> = st.window.drain(..).map(|(_, s, j)| (s, j)).collect();
        match analyze(&window, &st.cfg) {
            Verdict::Pause { victim, reason } => {
                let j = st.running.get(&victim)?;
                let guest = guest_pause(j);
                Some(Act::Pause(victim, j.pid?, reason, guest))
            }
            Verdict::FalseAlarm { reason } => {
                st.record(now, format!("false alarm: {reason}"));
                None
            }
            Verdict::Ok => None,
        }
    }

    /// Persists the pause intent of `id` before anything is frozen, so a daemon dying in the
    /// middle of a suspend still leaves a record. With no data dir no record is possible.
    fn record_intent(&self, id: TicketId, pid: u32) -> io::Result<()> {
        if self.draining.load(Ordering::SeqCst) {
            return Err(io::Error::other("the daemon is shutting down"));
        }
        if self.data_dir.is_none() {
            return Ok(());
        }
        let start = self
            .control
            .start_time(pid)
            .filter(|&s| s != 0)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "process start time unknown"))?;
        self.lock().intents.push((id, pid, start));
        self.try_save_paused().inspect_err(|_| {
            self.lock().intents.retain(|i| i.0 != id);
        })
    }

    fn pause(&self, id: TicketId, pid: u32, reason: &str, guest: Option<GuestPause>, now: Instant) {
        if let Some((ident, start)) = guest {
            return self.pause_guest(id, pid, &ident, start, reason, now);
        }
        // Ruling: no suspension without a durable record.
        if let Err(e) = self.record_intent(id, pid) {
            let msg = format!("not pausing #{id}: cannot record the pause ({e})");
            self.lock().record(now, msg);
            return;
        }
        // Every branch below replaces the intent under the same lock that stores the units.
        let token = match self.control.suspend(pid) {
            Ok(t) => t,
            Err((left, e)) => {
                let mut st = self.lock();
                st.intents.retain(|i| i.0 != id);
                st.record(now, format!("pause #{id} failed: {e}"));
                // Units the rollback could not resume are still frozen: retry them every tick.
                if !self.control.units(&left).is_empty() {
                    st.orphans.push((id, left));
                }
                drop(st);
                self.save_paused();
                return;
            }
        };
        let mut st = self.lock();
        st.intents.retain(|i| i.0 != id);
        let draining = self.draining.load(Ordering::SeqCst);
        match st
            .running
            .get_mut(&id)
            .filter(|j| j.pid == Some(pid) && !draining)
        {
            Some(j) => {
                j.token = Some(token);
                j.paused_since = Some(now);
                st.record(now, format!("paused #{id}: {reason}"));
                drop(st);
                self.save_paused();
            }
            None => {
                // The job ended (or shutdown began) while we were suspending it: never leave it frozen.
                let in_flight = self.track_resume(&mut st, &token);
                drop(st);
                self.resume_ended(id, Some(token));
                drop(in_flight);
            }
        }
    }

    /// A guest job's pause: only the processes with the job's identity, each batch written to
    /// `paused-guests.json` before it is suspended (write-ahead), never to `paused.json`.
    fn pause_guest(
        &self,
        id: TicketId,
        pid: u32,
        ident: &str,
        start: Option<u64>,
        reason: &str,
        now: Instant,
    ) {
        let Some(start) = start else {
            let msg = format!("not pausing #{id}: guest process identity unknown");
            self.lock().record(now, msg);
            return;
        };
        if self.draining.load(Ordering::SeqCst) {
            let msg =
                format!("not pausing #{id}: cannot record the pause (the daemon is shutting down)");
            self.lock().record(now, msg);
            return;
        }
        let mut plan = |batch: &[GuestUnit]| {
            self.lock()
                .guest_planned
                .entry(id)
                .or_default()
                .extend_from_slice(batch);
            self.try_save_paused()
        };
        let result = self.control.suspend_as(pid, start, ident, &mut plan);
        // Every branch below replaces the planned units under the same lock that stores the token.
        let mut st = self.lock();
        st.guest_planned.remove(&id);
        let token = match result {
            Ok(t) => t,
            Err((left, e)) => {
                st.record(now, format!("pause #{id} failed: {e}"));
                // What the rollback left frozen stays on record and is retried every tick (E3).
                if self.frozen_units(&left) > 0 {
                    st.orphans.push((id, left));
                }
                drop(st);
                self.save_paused();
                return;
            }
        };
        let draining = self.draining.load(Ordering::SeqCst);
        match st
            .running
            .get_mut(&id)
            .filter(|j| j.pid == Some(pid) && !draining)
        {
            Some(j) => {
                j.token = Some(token);
                j.paused_since = Some(now);
                st.record(now, format!("paused #{id}: {reason}"));
                drop(st);
                self.save_paused();
            }
            None => {
                // The job ended (or shutdown began) while we were suspending it: never leave it frozen.
                let in_flight = self.track_resume(&mut st, &token);
                drop(st);
                self.resume_ended(id, Some(token));
                drop(in_flight);
            }
        }
    }

    /// Resumes every paused job and orphan (clean shutdown). Units that fail stay in `paused.json`
    /// for the next start to recover.
    pub fn resume_all(&self, now: Instant) {
        let mut st = self.lock();
        let jobs: Vec<(TicketId, C::Token)> = st
            .running
            .iter_mut()
            .filter_map(|(&id, j)| j.token.take().map(|t| (id, t)))
            .collect();
        let orphans = std::mem::take(&mut st.orphans);
        let jobs: Vec<_> = jobs
            .into_iter()
            .map(|(id, t)| {
                let guard = self.track_resume(&mut st, &t);
                (id, t, guard)
            })
            .collect();
        let orphans: Vec<_> = orphans
            .into_iter()
            .map(|(id, t)| {
                let guard = self.track_resume(&mut st, &t);
                (id, t, guard)
            })
            .collect();
        drop(st);
        for (id, t, in_flight) in jobs {
            self.resume_job(id, t, &format!("resumed #{id}: shutdown"), now);
            drop(in_flight);
        }
        for (id, t, in_flight) in orphans {
            if let Err((rest, e)) = self.control.resume(t) {
                eprintln!("sync_gated: resume of #{id} failed at shutdown: {e}");
                self.lock().orphans.push((id, rest));
            }
            drop(in_flight);
        }
        self.retry_stale_intents();
        self.save_paused();
    }

    #[cfg(test)]
    pub(crate) fn set_leftover_retry(&self, window: Duration, period: Duration) {
        let mut r = self.retry.lock().unwrap_or_else(|e| e.into_inner());
        (r.window, r.period) = (window, period);
    }

    #[cfg(test)]
    pub(crate) fn set_drain_bound(&self, bound: Duration) {
        self.drain_ms
            .store(bound.as_millis() as u64, Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn estimate(&self, sig: &sync_gate_core::JobSignature) -> u64 {
        self.lock().cost.estimate(sig, true).peak_bytes
    }

    #[cfg(test)]
    pub(crate) fn has_waiter(&self, id: TicketId) -> bool {
        self.lock().queued.get(&id).is_some_and(|q| q.waiters > 0)
    }

    #[cfg(test)]
    pub(crate) fn pause_for_test(&self, id: TicketId, now: Instant) {
        let (pid, guest) = {
            let st = self.lock();
            let j = &st.running[&id];
            (j.pid.expect("started"), guest_pause(j))
        };
        self.pause(id, pid, "test", guest, now);
    }

    #[cfg(test)]
    pub(crate) fn pause_pid_for_test(&self, id: TicketId, pid: u32, now: Instant) {
        let guest = guest_pause(&self.lock().running[&id]);
        self.pause(id, pid, "test", guest, now);
    }

    /// (guest, pid, start) of a running job.
    #[cfg(test)]
    pub(crate) fn job_of(
        &self,
        id: TicketId,
    ) -> Option<(Option<GuestOf>, Option<u32>, Option<u64>)> {
        self.lock()
            .running
            .get(&id)
            .map(|j| (j.guest.clone(), j.pid, j.start))
    }

    #[cfg(test)]
    pub(crate) fn job_has_token(&self, id: TicketId) -> bool {
        self.lock()
            .running
            .get(&id)
            .is_some_and(|j| j.token.is_some())
    }

    /// The estimate a queued or dormant ticket carries.
    #[cfg(test)]
    pub(crate) fn ticket_estimate(&self, id: TicketId) -> Option<sync_gate_core::Estimate> {
        let st = self.lock();
        st.queued
            .get(&id)
            .map(|q| q.ticket.estimate)
            .or_else(|| st.dormant.get(&id).map(|(t, _)| t.estimate))
    }

    #[cfg(test)]
    pub(crate) fn estimate_of(
        &self,
        sig: &sync_gate_core::JobSignature,
    ) -> sync_gate_core::Estimate {
        self.lock().cost.estimate(sig, true)
    }

    #[cfg(test)]
    pub(crate) fn guest_planned_len(&self) -> usize {
        self.lock().guest_planned.len()
    }

    /// The count `close` reports, without closing.
    #[cfg(test)]
    pub(crate) fn held_units(&self) -> usize {
        let st = self.lock();
        self.held(&st)
    }
}

/// What a guest job's pause needs; None for the owner's job.
fn guest_pause<T>(j: &crate::state::RunningJob<T>) -> Option<GuestPause> {
    j.guest.as_ref().map(|g| (g.ident.clone(), j.start))
}

/// The ticket a request acts on, if any.
fn ticket_of(req: &Request) -> Option<TicketId> {
    match req {
        Request::Started { id, .. }
        | Request::Finished { id, .. }
        | Request::Wait { id, .. }
        | Request::Cancel { id } => Some(*id),
        _ => None,
    }
}

/// The daemon's `Control` as the shared recovery pass's resumer.
struct ControlRecover<'a, C: Control> {
    control: &'a C,
    /// How many units `guest_units` was handed and the ones it could not resume; `None` = it
    /// was never called (nothing was read).
    guest_kept: Option<(usize, Vec<GuestUnit>)>,
}

impl<'a, C: Control> ControlRecover<'a, C> {
    fn new(control: &'a C) -> Self {
        Self {
            control,
            guest_kept: None,
        }
    }
}

impl<C: Control> sync_gate_probe::Recover for ControlRecover<'_, C> {
    fn start_time(&mut self, pid: u32) -> Option<u64> {
        self.control.start_time(pid)
    }
    fn units(&mut self, units: Vec<FrozenUnit>) -> Vec<FrozenUnit> {
        match self.control.resume(self.control.token(units)) {
            Ok(()) => Vec::new(),
            Err((rest, e)) => {
                eprintln!("sync_gated: resuming units from a previous run failed: {e}");
                self.control.units(&rest)
            }
        }
    }
    fn tree(&mut self, root: u32) -> io::Result<()> {
        self.control.resume_tree(root)
    }
    fn guest_units(&mut self, units: Vec<GuestUnit>) -> Vec<GuestUnit> {
        let handed = units.len();
        let failed = self.control.resume_guest_units(units);
        self.guest_kept = Some((handed, failed.clone()));
        failed
    }
}

/// R16: the oldest paused job, once free plus reclaimable memory is back above the reserve.
/// Its own pages are still resident (not in `available`), so its peak is not subtracted.
fn resume_candidate<T>(st: &mut State<T>, snap: MachineSnapshot) -> Option<Act<T>> {
    let room = snap.available.saturating_add(snap.reclaimable) as f64;
    if room < snap.total as f64 * st.cfg.reserve_fraction {
        return None;
    }
    let (&id, job) = st
        .running
        .iter_mut()
        .filter(|(_, j)| j.token.is_some())
        .min_by_key(|(_, j)| j.paused_since)?;
    job.token
        .take()
        .map(|t| Act::Resume(id, t, format!("resumed #{id}: memory is back")))
}

fn error(e: impl ToString) -> Response {
    Response::Error {
        message: e.to_string(),
    }
}
