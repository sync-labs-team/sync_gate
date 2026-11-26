//! Pure decisions of the elastic pool: how many children one server key runs and which one
//! takes a request. No I/O, no threads, no clock: the hub measures and feeds the numbers.

use std::time::Duration;

/// The oldest queued request must wait longer than this before the pool grows.
pub const GROW_WAIT: Duration = Duration::from_millis(500);
/// An extra instance with nothing in flight for this long is stopped.
pub const SHRINK_IDLE: Duration = Duration::from_secs(120);

/// One key's pool as the hub sees it. `in_flight` and `idle_for` have one entry per instance.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PoolStats {
    pub instances: u32,
    pub in_flight: Vec<u32>,
    /// Requests waiting in the hub queue that a new instance could serve.
    pub queued: u32,
    pub oldest_wait: Duration,
    pub idle_for: Vec<Duration>,
    /// Largest resident size measured for one instance of this key.
    pub instance_rss: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolAction {
    None,
    Grow,
    Shrink { instance: usize },
}

/// True when the queue has waited too long, every instance is full and the pool may grow.
/// Memory is not considered: with this true and `decide` saying `None`, memory is the limit.
pub fn wants_to_grow(s: &PoolStats, max_instances: u32, max_in_flight: u32) -> bool {
    s.queued > 0
        && s.oldest_wait > GROW_WAIT
        && s.instances < max_instances
        && s.in_flight.iter().all(|&n| n >= max_in_flight)
}

pub fn decide(
    s: &PoolStats,
    max_instances: u32,
    max_in_flight: u32,
    free_bytes: u64,
    reserve_bytes: u64,
) -> PoolAction {
    if wants_to_grow(s, max_instances, max_in_flight) {
        // The new instance must fit without eating into the reserve.
        return if free_bytes.saturating_sub(s.instance_rss) >= reserve_bytes {
            PoolAction::Grow
        } else {
            PoolAction::None
        };
    }
    // Newest first; instance 0 is never shrunk, so the pool keeps at least one.
    (1..s.instances as usize)
        .rev()
        .find(|&i| {
            s.in_flight.get(i) == Some(&0) && s.idle_for.get(i).is_some_and(|d| *d >= SHRINK_IDLE)
        })
        .map_or(PoolAction::None, |instance| PoolAction::Shrink { instance })
}

/// The least loaded instance with room (lowest index on a tie); `None`: the request waits.
pub fn pick_instance(in_flight: &[u32], max_in_flight: u32) -> Option<usize> {
    in_flight
        .iter()
        .enumerate()
        .filter(|(_, n)| **n < max_in_flight)
        .min_by_key(|(_, n)| **n)
        .map(|(i, _)| i)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;

    fn busy(instances: u32, wait_ms: u64) -> PoolStats {
        PoolStats {
            instances,
            in_flight: vec![8; instances as usize],
            queued: 3,
            oldest_wait: Duration::from_millis(wait_ms),
            idle_for: vec![Duration::ZERO; instances as usize],
            instance_rss: 100 * MIB,
        }
    }

    #[test]
    fn grows_when_the_queue_waits_and_memory_allows() {
        let s = PoolStats {
            instances: 1,
            in_flight: vec![8],
            queued: 3,
            oldest_wait: Duration::from_millis(600),
            idle_for: vec![Duration::ZERO],
            instance_rss: 100 * MIB,
        };
        assert!(matches!(
            decide(&s, 3, 8, 2048 * MIB, 512 * MIB),
            PoolAction::Grow
        ));
    }

    #[test]
    fn does_not_grow_past_max_or_into_the_reserve() {
        let s = busy(3, 600);
        assert_eq!(decide(&s, 3, 8, 2048 * MIB, 512 * MIB), PoolAction::None);
        let s = busy(1, 600);
        assert_eq!(decide(&s, 3, 8, 600 * MIB, 512 * MIB), PoolAction::None);
        assert!(wants_to_grow(&s, 3, 8), "memory is the only limit here");
    }

    #[test]
    fn does_not_grow_on_a_short_wait() {
        assert_eq!(
            decide(&busy(1, 400), 3, 8, 2048 * MIB, 512 * MIB),
            PoolAction::None
        );
    }

    #[test]
    fn does_not_grow_while_an_instance_has_room() {
        // A second instance still starting (0 in flight) must not trigger a third.
        let mut s = busy(2, 600);
        s.in_flight[1] = 0;
        assert_eq!(decide(&s, 3, 8, 2048 * MIB, 512 * MIB), PoolAction::None);
    }

    #[test]
    fn shrinks_an_idle_instance_but_never_the_last() {
        let s = PoolStats {
            instances: 2,
            in_flight: vec![3, 0],
            queued: 0,
            oldest_wait: Duration::ZERO,
            idle_for: vec![Duration::ZERO, Duration::from_secs(121)],
            instance_rss: 100 * MIB,
        };
        assert_eq!(
            decide(&s, 3, 8, 2048 * MIB, 512 * MIB),
            PoolAction::Shrink { instance: 1 }
        );
        let s = PoolStats {
            instances: 1,
            in_flight: vec![0],
            queued: 0,
            oldest_wait: Duration::ZERO,
            idle_for: vec![Duration::from_secs(3600)],
            instance_rss: 100 * MIB,
        };
        assert_eq!(decide(&s, 3, 8, 2048 * MIB, 512 * MIB), PoolAction::None);
        // Busy or not idle long enough: kept.
        let s = PoolStats {
            instances: 2,
            in_flight: vec![0, 1],
            queued: 0,
            oldest_wait: Duration::ZERO,
            idle_for: vec![Duration::from_secs(3600), Duration::from_secs(3600)],
            instance_rss: 0,
        };
        assert_eq!(decide(&s, 3, 8, 2048 * MIB, 512 * MIB), PoolAction::None);
    }

    #[test]
    fn pick_instance_prefers_the_least_loaded_with_room() {
        assert_eq!(pick_instance(&[8, 3, 5], 8), Some(1));
        assert_eq!(pick_instance(&[8, 8], 8), None);
        assert_eq!(pick_instance(&[2, 2], 8), Some(0));
    }
}
