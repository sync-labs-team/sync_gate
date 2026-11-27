//! Admission scheduler: optimistic budget, backfill, aging, per-session fairness and anti-starvation.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use crate::{Config, Estimate, JobSignature, MachineSnapshot};

pub type TicketId = u64;

/// Who asked for a guest ticket: the entry in the daemon's guest list and the token identity of
/// the request that sent the Acquire (ident_of over the message's context, F47). Same ident =
/// same caller (E2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestOf {
    pub index: u8,
    pub ident: String,
}

#[derive(Debug, Clone)]
pub struct Ticket {
    pub id: TicketId,
    pub sig: JobSignature,
    pub estimate: Estimate,
    pub session: String,
    pub enqueued_at: Instant,
    /// None: the owner.
    pub guest: Option<GuestOf>,
}

pub struct Scheduler {
    cfg: Config,
    /// Vector order is arrival order.
    queue: Vec<Ticket>,
    running: HashMap<TicketId, String>,
}

impl Scheduler {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            queue: Vec::new(),
            running: HashMap::new(),
        }
    }

    pub fn enqueue(&mut self, t: Ticket) {
        self.queue.push(t);
    }

    /// Removes queued tickets only; an admitted job is ended with `release`.
    pub fn cancel(&mut self, id: TicketId) {
        self.queue.retain(|t| t.id != id);
    }

    /// The daemon must call this on every exit path of an admitted job, or its session stays penalised.
    pub fn release(&mut self, id: TicketId) {
        self.running.remove(&id);
    }

    /// Position in the current priority order, aged as of the call time.
    pub fn position(&self, id: TicketId) -> Option<usize> {
        self.order(Instant::now())
            .iter()
            .position(|&i| self.queue[i].id == id)
    }

    fn age_secs(t: &Ticket, now: Instant) -> u64 {
        now.saturating_duration_since(t.enqueued_at).as_secs()
    }

    /// Queue indices by priority: older age bucket, then fewer running in session, then arrival.
    fn order(&self, now: Instant) -> Vec<usize> {
        let mut per_session: HashMap<&str, usize> = HashMap::new();
        for s in self.running.values() {
            *per_session.entry(s.as_str()).or_default() += 1;
        }
        let aging = self.cfg.aging_secs.max(1);
        let mut idx: Vec<usize> = (0..self.queue.len()).collect();
        idx.sort_by_key(|&i| {
            let t = &self.queue[i];
            (
                std::cmp::Reverse(Self::age_secs(t, now) / aging),
                per_session.get(t.session.as_str()).copied().unwrap_or(0),
                i,
            )
        });
        idx
    }

    pub fn admit(
        &mut self,
        snap: &MachineSnapshot,
        running_reserved: u64,
        now: Instant,
    ) -> Vec<TicketId> {
        let free = (snap.available as f64 + snap.reclaimable as f64) * self.cfg.optimism
            - snap.total as f64 * self.cfg.reserve_fraction
            - running_reserved as f64;
        // Float-to-int `as` saturates: negative and NaN become 0.
        let mut budget = free as u64;

        let order = self.order(now);
        let starve_after = self.cfg.aging_secs.saturating_mul(4);
        let reserved = order
            .iter()
            .copied()
            .filter(|&i| Self::age_secs(&self.queue[i], now) >= starve_after)
            .min_by_key(|&i| self.queue[i].enqueued_at);

        let mut admitted: Vec<usize> = Vec::new();
        if let Some(r) = reserved {
            let need = self.queue[r].estimate.peak_bytes;
            // R7: with nothing running an oversized reserve would deadlock the queue; admit it anyway.
            let idle = self.running.is_empty() && running_reserved == 0;
            if need > budget && !idle {
                return Vec::new();
            }
            budget = budget.saturating_sub(need);
            admitted.push(r);
        }
        for i in order {
            let need = self.queue[i].estimate.peak_bytes;
            if Some(i) != reserved && need <= budget {
                budget -= need;
                admitted.push(i);
            }
        }

        let ids: Vec<TicketId> = admitted.iter().map(|&i| self.queue[i].id).collect();
        for &i in &admitted {
            let t = &self.queue[i];
            self.running.insert(t.id, t.session.clone());
        }
        let done: HashSet<TicketId> = ids.iter().copied().collect();
        self.queue.retain(|t| !done.contains(&t.id));
        ids
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const GIB: u64 = 1024 * 1024 * 1024;

    fn cfg(reserve: f64, optimism: f64) -> Config {
        Config {
            reserve_fraction: reserve,
            optimism,
            ..Config::default()
        }
    }

    fn snap(available: u64) -> MachineSnapshot {
        MachineSnapshot {
            total: 16 * GIB,
            available,
            reclaimable: 0,
            swap_used: 0,
            swap_total: 0,
            vram: None,
        }
    }

    fn ticket(id: u64, bytes: u64, session: &str, at: Instant) -> Ticket {
        Ticket {
            id,
            sig: JobSignature {
                key: format!("k{id}"),
            },
            estimate: Estimate {
                peak_bytes: bytes,
                confident: true,
            },
            session: session.into(),
            enqueued_at: at,
            guest: None,
        }
    }

    #[test]
    fn fast_path_admits_when_room() {
        let now = Instant::now();
        let mut s = Scheduler::new(Config::default());
        s.enqueue(ticket(1, GIB, "s1", now));
        assert_eq!(s.admit(&snap(8 * GIB), 0, now), vec![1]);
        assert_eq!(s.position(1), None);
    }

    #[test]
    fn big_waits_small_backfills() {
        let now = Instant::now();
        let mut s = Scheduler::new(cfg(0.0, 1.0));
        s.enqueue(ticket(1, 3 * GIB, "s1", now)); // A
        s.enqueue(ticket(2, GIB, "s2", now)); // B
        assert_eq!(s.admit(&snap(2 * GIB), 0, now), vec![2]);
        assert_eq!(s.position(1), Some(0));
    }

    #[test]
    fn starving_ticket_reserves() {
        let t0 = Instant::now();
        let aging = Config::default().aging_secs;
        let now = t0 + Duration::from_secs(4 * aging);
        let mut s = Scheduler::new(cfg(0.0, 1.0));
        s.enqueue(ticket(1, 3 * GIB, "s1", t0)); // A, starving
        s.enqueue(ticket(2, GIB, "s2", now)); // B, fresh
        // 1 GiB already reserved by running jobs, so the round is blocked (not idle)
        assert!(s.admit(&snap(3 * GIB), GIB, now).is_empty());
        assert_eq!(s.admit(&snap(4 * GIB), GIB, now), vec![1]);
    }

    #[test]
    fn fairness_across_sessions() {
        let now = Instant::now();
        let mut s = Scheduler::new(cfg(0.0, 1.0));
        s.enqueue(ticket(10, GIB, "s1", now));
        assert_eq!(s.admit(&snap(8 * GIB), 0, now), vec![10]); // s1 now has 1 running
        s.enqueue(ticket(1, GIB, "s1", now)); // arrives first
        s.enqueue(ticket(2, GIB, "s2", now));
        // room for exactly one: s2 (0 running) wins over s1 (1 running)
        assert_eq!(s.admit(&snap(GIB), 0, now), vec![2]);
    }

    #[test]
    fn budget_never_negative() {
        let now = Instant::now();
        let mut s = Scheduler::new(Config::default());
        s.enqueue(ticket(1, 64, "s1", now));
        assert!(s.admit(&snap(0), u64::MAX, now).is_empty());
    }

    #[test]
    fn optimism_allows_more_than_available() {
        let now = Instant::now();
        let mut s = Scheduler::new(cfg(0.0, 1.25));
        s.enqueue(ticket(1, GIB * 12 / 10, "s1", now));
        assert_eq!(s.admit(&snap(GIB), 0, now), vec![1]);
    }

    #[test]
    fn release_frees_session_slot_for_fairness() {
        let now = Instant::now();
        let mut s = Scheduler::new(cfg(0.0, 1.0));
        s.enqueue(ticket(10, GIB, "s1", now));
        s.admit(&snap(8 * GIB), 0, now);
        s.release(10);
        s.enqueue(ticket(1, GIB, "s1", now));
        s.enqueue(ticket(2, GIB, "s2", now));
        assert_eq!(s.admit(&snap(GIB), 0, now), vec![1]); // tie: arrival order
    }

    #[test]
    fn oversized_starving_ticket_is_admitted_when_nothing_runs() {
        let t0 = Instant::now();
        let now = t0 + Duration::from_secs(4 * Config::default().aging_secs);
        let mut s = Scheduler::new(cfg(0.0, 1.0));
        s.enqueue(ticket(1, 100 * GIB, "s1", t0));
        s.enqueue(ticket(2, GIB, "s2", now));
        assert_eq!(s.admit(&snap(8 * GIB), 0, now), vec![1]);
    }

    #[test]
    fn oversized_starving_ticket_still_blocks_while_a_job_runs() {
        let t0 = Instant::now();
        let now = t0 + Duration::from_secs(4 * Config::default().aging_secs);
        let mut s = Scheduler::new(cfg(0.0, 1.0));
        s.enqueue(ticket(10, GIB, "s1", t0));
        assert_eq!(s.admit(&snap(8 * GIB), 0, t0), vec![10]);
        s.enqueue(ticket(1, 100 * GIB, "s1", t0));
        s.enqueue(ticket(2, GIB, "s2", now));
        assert!(s.admit(&snap(8 * GIB), 0, now).is_empty());
        // external reservation also counts as "something running"
        s.release(10);
        assert!(s.admit(&snap(8 * GIB), GIB, now).is_empty());
    }

    #[test]
    fn estimate_equal_to_the_budget_is_admitted() {
        let t0 = Instant::now();
        // backfill path: need == budget
        let mut s = Scheduler::new(cfg(0.0, 1.0));
        s.enqueue(ticket(1, 2 * GIB, "s1", t0));
        assert_eq!(s.admit(&snap(2 * GIB), 0, t0), vec![1]);
        // reserved (starving) path: need == budget while another job runs
        let now = t0 + Duration::from_secs(4 * Config::default().aging_secs);
        let mut s = Scheduler::new(cfg(0.0, 1.0));
        s.enqueue(ticket(2, 2 * GIB, "s1", t0));
        assert_eq!(s.admit(&snap(3 * GIB), GIB, now), vec![2]);
    }
}
