//! Micro-analysis run before pausing a job: false alarm, or pause one specific victim.

use crate::{Config, MIB, MachineSnapshot, TicketId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobSample {
    pub id: TicketId,
    pub rss: u64,
    pub awaited_by_others: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Ok,
    FalseAlarm { reason: String },
    Pause { victim: TicketId, reason: String },
}

fn threshold(snap: &MachineSnapshot, cfg: &Config) -> f64 {
    snap.total as f64 * cfg.reserve_fraction / 2.0
}

/// True when free plus reclaimable memory is below half the reserve; triggers `analyze`.
pub fn under_pressure(snap: &MachineSnapshot, cfg: &Config) -> bool {
    (snap.available.saturating_add(snap.reclaimable) as f64) < threshold(snap, cfg)
}

fn false_alarm(reason: &str) -> Verdict {
    Verdict::FalseAlarm {
        reason: reason.to_string(),
    }
}

/// Decides, from a 2-6 sample window (about 1-3 s), whether to pause one job.
pub fn analyze(window: &[(MachineSnapshot, Vec<JobSample>)], cfg: &Config) -> Verdict {
    let (Some((first, _)), Some((last, last_jobs))) = (window.first(), window.last()) else {
        return false_alarm("not growing");
    };
    if window.len() < 2 {
        return false_alarm("not growing");
    }
    let t = threshold(last, cfg);
    if (last.available as f64) >= t {
        return false_alarm("transient spike");
    }
    if (last.available.saturating_add(last.reclaimable) as f64) >= t {
        return false_alarm("recovered: reclaimable memory");
    }
    let usage = |s: &MachineSnapshot| s.total.saturating_sub(s.available);
    if usage(last) <= usage(first) {
        return false_alarm("not growing");
    }
    // RSS growth = last sample's rss minus the rss in the first sample where the job appears.
    let growth = |j: &JobSample| {
        let start = window
            .iter()
            .find_map(|(_, jobs)| jobs.iter().find(|x| x.id == j.id))
            .map_or(j.rss, |x| x.rss);
        j.rss.saturating_sub(start)
    };
    last_jobs
        .iter()
        .filter(|j| !j.awaited_by_others)
        .map(|j| (growth(j), j.id))
        // a job that did not grow frees nothing when paused
        .filter(|(g, _)| *g > 0)
        // max growth; on a tie the lowest TicketId wins
        .max_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)))
        .map_or_else(
            || false_alarm("no safe victim"),
            |(g, victim)| Verdict::Pause {
                victim,
                reason: format!("fastest grower: +{} MiB in window", g / MIB),
            },
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * MIB;

    fn snap(available: u64, reclaimable: u64) -> MachineSnapshot {
        MachineSnapshot {
            total: 16 * GIB,
            available,
            reclaimable,
            swap_used: 0,
            swap_total: 0,
            vram: None,
        }
    }

    fn job(id: TicketId, rss_mib: u64, awaited: bool) -> JobSample {
        JobSample {
            id,
            rss: rss_mib * MIB,
            awaited_by_others: awaited,
        }
    }

    // threshold with default config: 16 GiB * 0.10 / 2 = 0.8 GiB
    fn is_false_alarm(v: &Verdict, needle: &str) -> bool {
        matches!(v, Verdict::FalseAlarm { reason } if reason.contains(needle))
    }

    fn growing(a: bool, b: bool) -> Vec<(MachineSnapshot, Vec<JobSample>)> {
        vec![
            (snap(600 * MIB, 0), vec![job(1, 100, a), job(2, 100, b)]),
            (snap(300 * MIB, 0), vec![job(1, 200, a), job(2, 1000, b)]),
        ]
    }

    #[test]
    fn reclaimable_covers_it_is_false_alarm() {
        let w = vec![
            (snap(700 * MIB, 0), vec![job(1, 100, false)]),
            (snap(500 * MIB, 600 * MIB), vec![job(1, 300, false)]),
        ];
        assert!(is_false_alarm(
            &analyze(&w, &Config::default()),
            "reclaimable"
        ));
    }

    #[test]
    fn transient_spike_is_false_alarm() {
        let w = vec![
            (snap(300 * MIB, 0), vec![job(1, 100, false)]),
            (snap(2 * GIB, 0), vec![job(1, 100, false)]),
        ];
        assert!(is_false_alarm(
            &analyze(&w, &Config::default()),
            "transient spike"
        ));
    }

    #[test]
    fn flat_usage_is_false_alarm() {
        let w = vec![
            (snap(300 * MIB, 0), vec![job(1, 100, false)]),
            (snap(300 * MIB, 0), vec![job(1, 100, false)]),
        ];
        assert!(is_false_alarm(
            &analyze(&w, &Config::default()),
            "not growing"
        ));
    }

    #[test]
    fn short_window_is_not_growing() {
        let cfg = Config::default();
        assert!(is_false_alarm(&analyze(&[], &cfg), "not growing"));
        let one = vec![(snap(300 * MIB, 0), vec![job(1, 100, false)])];
        assert!(is_false_alarm(&analyze(&one, &cfg), "not growing"));
    }

    #[test]
    fn growing_pressure_pauses_fastest_grower() {
        let v = analyze(&growing(false, false), &Config::default());
        assert!(matches!(v, Verdict::Pause { victim: 2, .. }), "{v:?}");
    }

    #[test]
    fn never_pauses_awaited_job() {
        let v = analyze(&growing(false, true), &Config::default());
        assert!(matches!(v, Verdict::Pause { victim: 1, .. }), "{v:?}");
    }

    #[test]
    fn no_eligible_victim() {
        let v = analyze(&growing(true, true), &Config::default());
        assert!(is_false_alarm(&v, "no safe victim"), "{v:?}");
    }

    #[test]
    fn under_pressure_threshold() {
        let cfg = Config::default();
        assert!(under_pressure(&snap(300 * MIB, 100 * MIB), &cfg));
        assert!(!under_pressure(&snap(300 * MIB, 600 * MIB), &cfg));
    }

    #[test]
    fn flat_rss_jobs_are_not_victims() {
        let w = vec![
            (
                snap(600 * MIB, 0),
                vec![job(1, 100, false), job(2, 100, false)],
            ),
            (
                snap(300 * MIB, 0),
                vec![job(1, 100, false), job(2, 100, false)],
            ),
        ];
        let v = analyze(&w, &Config::default());
        assert!(is_false_alarm(&v, "no safe victim"), "{v:?}");
    }

    #[test]
    fn healthy_single_sample_is_not_growing() {
        let one = vec![(snap(4 * GIB, 0), vec![job(1, 100, false)])];
        let v = analyze(&one, &Config::default());
        assert!(is_false_alarm(&v, "not growing"), "{v:?}");
    }

    #[test]
    fn tie_picks_lowest_ticket_id() {
        let w = vec![
            (
                snap(600 * MIB, 0),
                vec![job(3, 100, false), job(2, 100, false)],
            ),
            (
                snap(300 * MIB, 0),
                vec![job(3, 500, false), job(2, 500, false)],
            ),
        ];
        let v = analyze(&w, &Config::default());
        assert!(matches!(v, Verdict::Pause { victim: 2, .. }), "{v:?}");
    }
}
