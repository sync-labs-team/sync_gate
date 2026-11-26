//! Daemon state behind one `Mutex`: queue, dormant tickets, running jobs, cost model and the
//! decision log. Everything here is pure bookkeeping; no I/O, no process control.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};
use sync_gate_core::{
    Config, CostModel, DaemonInfo, GuestOf, JobSample, JobSignature, MachineSnapshot, Scheduler,
    StatusReport, Ticket, TicketId,
};
use sync_gate_probe::GuestUnit;

const MAX_DECISIONS: usize = 50;

pub struct QueuedJob {
    /// The scheduler's copy, kept so the ticket can go dormant and come back with its age.
    pub ticket: Ticket,
    /// Last time a client showed interest (enqueue or end of a `Wait`).
    pub last_seen: Instant,
    /// `Wait` requests currently blocked on this ticket.
    pub waiters: u32,
}

pub struct RunningJob<T> {
    pub sig: JobSignature,
    /// Estimated peak at admission.
    pub reserved: u64,
    /// `None` until the CLI sends `Started`.
    pub pid: Option<u32>,
    /// Highest tree RSS observed so far.
    pub peak: u64,
    pub admitted_at: Instant,
    /// Set from the pause until a resume fully succeeds.
    pub paused_since: Option<Instant>,
    /// What must still be resumed. Taken out while a resume is in flight.
    pub token: Option<T>,
    /// The last resume failed for some units; retry them on the next tick.
    pub retry: bool,
    /// Last successful resume; starts the cooldown during which it is not a victim.
    pub resumed_at: Option<Instant>,
    /// Handed to a client (Acquire or one `Wait`); later `Wait`s are refused, so it runs once.
    pub claimed: bool,
    /// Copied from the ticket at admission; the pause uses its ident.
    pub guest: Option<GuestOf>,
    /// A guest job's root start (seconds), set by its checked Started.
    pub start: Option<u64>,
}

pub type Window = Vec<(Instant, MachineSnapshot, Vec<JobSample>)>;

pub struct State<T> {
    pub cfg: Config,
    pub sched: Scheduler,
    pub cost: CostModel,
    pub next_id: TicketId,
    pub queued: HashMap<TicketId, QueuedJob>,
    /// Out of the scheduler because nobody waits; never admitted until a `Wait` wakes it.
    pub dormant: HashMap<TicketId, (Ticket, Instant)>,
    pub running: HashMap<TicketId, RunningJob<T>>,
    /// Units of ended jobs whose resume failed, by ticket (0 = a previous run); retried every tick.
    pub orphans: Vec<(TicketId, T)>,
    /// Exact units owned by resume operations outside the state lock.
    pub in_flight: HashMap<u64, Vec<sync_gate_probe::FrozenUnit>>,
    /// Pause intents `(ticket, root_pid, root_start_time)`: written before a suspend, replaced by
    /// the units after it. Ticket 0: left by a previous run, retried every tick.
    pub intents: Vec<(TicketId, u32, u64)>,
    /// Write-ahead of a guest pause in progress: every unit planned so far, by ticket.
    pub guest_planned: HashMap<TicketId, Vec<GuestUnit>>,
    /// The guest units of resume operations outside the state lock (same keys as `in_flight`).
    pub guest_in_flight: HashMap<u64, Vec<GuestUnit>>,
    /// Guest units a recovery pass could not resume; retried like the ticket-0 units.
    pub guest_leftovers: Vec<GuestUnit>,
    pub next_resume: u64,
    /// Last time a resume failure was logged, per ticket.
    fail_logged: HashMap<TicketId, Instant>,
    pub snapshot: MachineSnapshot,
    /// Pressure samples for the micro-analysis; empty when not under pressure.
    pub window: Window,
    /// The "admission held" decision was already logged for the current pause.
    hold_noted: bool,
    decisions: VecDeque<String>,
    started: Instant,
}

impl<T> State<T> {
    pub fn new(cfg: Config, cost: CostModel, started: Instant) -> Self {
        Self {
            sched: Scheduler::new(cfg.clone()),
            cfg,
            cost,
            // R18: ids start at the Unix time in ms, so a stale `pending/N.json` from an
            // earlier daemon run can never match a new ticket.
            next_id: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(1, |d| d.as_millis() as TicketId),
            queued: HashMap::new(),
            dormant: HashMap::new(),
            running: HashMap::new(),
            orphans: Vec::new(),
            in_flight: HashMap::new(),
            intents: Vec::new(),
            guest_planned: HashMap::new(),
            guest_in_flight: HashMap::new(),
            guest_leftovers: Vec::new(),
            next_resume: 0,
            fail_logged: HashMap::new(),
            snapshot: MachineSnapshot {
                total: 0,
                available: 0,
                reclaimable: 0,
                swap_used: 0,
                swap_total: 0,
                vram: None,
            },
            window: Vec::new(),
            hold_noted: false,
            decisions: VecDeque::new(),
            started,
        }
    }

    /// Appends to the decision log, prefixed with seconds since daemon start; keeps the last 50.
    pub fn record(&mut self, now: Instant, msg: impl AsRef<str>) {
        let secs = now.saturating_duration_since(self.started).as_secs();
        if self.decisions.len() == MAX_DECISIONS {
            self.decisions.pop_front();
        }
        self.decisions
            .push_back(format!("[{secs}s] {}", msg.as_ref()));
    }

    /// Not-yet-used part of every running job's reservation (the snapshot already holds the used part).
    pub fn running_reserved(&self) -> u64 {
        self.running
            .values()
            .map(|j| j.reserved.saturating_sub(j.peak))
            .fold(0, u64::saturating_add)
    }

    pub fn enqueue(&mut self, ticket: Ticket, now: Instant) {
        self.sched.enqueue(ticket.clone());
        self.queued.insert(
            ticket.id,
            QueuedJob {
                ticket,
                last_seen: now,
                waiters: 0,
            },
        );
    }

    /// Runs one scheduler round against the last snapshot and moves admitted tickets to `running`.
    pub fn admit(&mut self, now: Instant) -> Vec<TicketId> {
        // R16: while a job is paused, admitting more would starve it of the memory it waits for.
        if let Some(&paused) = self
            .running
            .iter()
            .find(|(_, j)| j.paused_since.is_some())
            .map(|(id, _)| id)
        {
            if !self.hold_noted {
                self.hold_noted = true;
                self.record(now, format!("admission held: #{paused} is paused"));
            }
            return Vec::new();
        }
        self.hold_noted = false;
        // No data (total == 0): an unbounded reservation leaves budget 0, so only
        // zero-estimate tickets pass and the idle oversized-starver rule cannot fire.
        let reserved = if self.snapshot.total == 0 {
            u64::MAX
        } else {
            self.running_reserved()
        };
        let ids = self.sched.admit(&self.snapshot, reserved, now);
        for &id in &ids {
            let Some(q) = self.queued.remove(&id) else {
                // Not ours to run: do not leave it holding a scheduler slot.
                self.sched.release(id);
                continue;
            };
            self.running.insert(
                id,
                RunningJob {
                    sig: q.ticket.sig,
                    reserved: q.ticket.estimate.peak_bytes,
                    pid: None,
                    peak: 0,
                    admitted_at: now,
                    paused_since: None,
                    token: None,
                    retry: false,
                    resumed_at: None,
                    claimed: false,
                    guest: q.ticket.guest,
                    start: None,
                },
            );
            self.record(now, format!("admitted #{id}"));
        }
        ids
    }

    /// True at most once per 30 s per ticket: rate-limits logging of a failure retried every tick.
    pub fn should_log_failure(&mut self, id: TicketId, now: Instant) -> bool {
        const EVERY: std::time::Duration = std::time::Duration::from_secs(30);
        let due = self
            .fail_logged
            .get(&id)
            .is_none_or(|&t| now.saturating_duration_since(t) >= EVERY);
        if due {
            self.fail_logged.insert(id, now);
        }
        due
    }

    /// Ends an admitted job on any exit path: removes it and releases its scheduler slot.
    pub fn end(&mut self, id: TicketId) -> Option<RunningJob<T>> {
        let job = self.running.remove(&id)?;
        self.sched.release(id);
        Some(job)
    }

    /// Drops a queued or dormant ticket (never an admitted one).
    pub fn cancel_queued(&mut self, id: TicketId) -> bool {
        self.sched.cancel(id);
        self.queued.remove(&id).is_some() | self.dormant.remove(&id).is_some()
    }

    /// R17: takes a queued ticket out of the scheduler, keeping its original `enqueued_at`.
    pub fn make_dormant(&mut self, id: TicketId, now: Instant) {
        if let Some(q) = self.queued.remove(&id) {
            self.sched.cancel(id);
            self.dormant.insert(id, (q.ticket, now));
            self.record(now, format!("dormant #{id}: nobody waiting"));
        }
    }

    /// R17: puts a dormant ticket back in the queue with its original age.
    pub fn wake(&mut self, id: TicketId, now: Instant) -> bool {
        let Some((ticket, _)) = self.dormant.remove(&id) else {
            return false;
        };
        self.enqueue(ticket, now);
        self.record(now, format!("woke #{id}: waited on again"));
        true
    }

    /// A guest viewer sees only tickets whose guest == Some(viewer) (index AND ident), plus memory.
    pub fn status(&self, mut daemon: DaemonInfo, viewer: Option<&GuestOf>) -> StatusReport {
        // The owner sees everything; a guest only what it asked for, never the owner's paths.
        let shown = |g: &Option<GuestOf>| viewer.is_none() || g.as_ref() == viewer;
        if viewer.is_some() {
            daemon.data_dir = None;
        }
        let mut running: Vec<_> = self
            .running
            .iter()
            .filter(|(_, j)| shown(&j.guest))
            .map(|(&id, j)| (id, j.sig.key.clone(), j.peak))
            .collect();
        running.sort_by_key(|r| r.0);
        let mut queued: Vec<_> = self
            .queued
            .iter()
            .filter(|(_, q)| shown(&q.ticket.guest))
            .map(|(&id, q)| {
                let pos = self.sched.position(id).unwrap_or(0);
                (id, q.ticket.sig.key.clone(), pos)
            })
            .collect();
        queued.sort_by_key(|q| q.2);
        let mut paused: Vec<_> = self
            .running
            .iter()
            .filter(|(_, j)| j.paused_since.is_some() && shown(&j.guest))
            .map(|(&id, _)| id)
            .collect();
        paused.sort_unstable();
        StatusReport {
            snapshot: self.snapshot,
            running,
            queued,
            paused,
            decisions: match viewer {
                None => self.decisions.iter().cloned().collect(),
                Some(_) => Vec::new(),
            },
            mcp: Vec::new(),
            daemon,
            services: Vec::new(),
        }
    }

    /// Tickets a wait may still be on: queued, admitted, or dormant for less than `gap` (a CLI
    /// sends its next `Wait` 200 ms after the daemon's own wait ended). Their stored commands
    /// are never swept.
    pub fn live_tickets(&self, now: Instant, gap: Duration) -> HashSet<TicketId> {
        let just_dormant = self
            .dormant
            .iter()
            .filter(|(_, (_, since))| now.saturating_duration_since(*since) < gap)
            .map(|(id, _)| id);
        self.queued
            .keys()
            .chain(self.running.keys())
            .chain(just_dormant)
            .copied()
            .collect()
    }

    /// Per entry, whatever the ident (decision 9): queued, dormant and running.
    pub fn live_guest_tickets(&self, g: u8) -> usize {
        let of = |t: &Option<GuestOf>| t.as_ref().is_some_and(|t| t.index == g);
        self.queued.values().filter(|q| of(&q.ticket.guest)).count()
            + self.dormant.values().filter(|(t, _)| of(&t.guest)).count()
            + self.running.values().filter(|j| of(&j.guest)).count()
    }

    /// Who may act on ticket `id`: None = no such ticket; Some(None) = the owner's; Some(Some(g)).
    pub fn caller_of(&self, id: TicketId) -> Option<Option<&GuestOf>> {
        if let Some(j) = self.running.get(&id) {
            return Some(j.guest.as_ref());
        }
        if let Some(q) = self.queued.get(&id) {
            return Some(q.ticket.guest.as_ref());
        }
        self.dormant.get(&id).map(|(t, _)| t.guest.as_ref())
    }
}
