//! Learned cost model: remembers the observed memory peak per job signature.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::JobSignature;

pub const MIB: u64 = 1024 * 1024;
pub const PRIOR_HEAVY: u64 = 1536 * MIB;
pub const PRIOR_LIGHT: u64 = 64 * MIB;

const ALPHA: f64 = 0.3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Estimate {
    pub peak_bytes: u64,
    pub confident: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct History {
    last: u64,
    ema: f64,
    samples: u32,
}

/// Keyed by the signature's string key (JSON maps need string keys). Serialized as
/// `history_v2`: keys of the older format (`history`) came from any non-option word and are
/// never read again.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CostModel {
    #[serde(rename = "history_v2", default)]
    history: HashMap<String, History>,
}

impl CostModel {
    /// With history the `heavy` hint is ignored: a "light" job that grew is treated by what it did.
    pub fn estimate(&self, sig: &JobSignature, heavy: bool) -> Estimate {
        match self.history.get(&sig.key) {
            Some(h) => Estimate {
                peak_bytes: h.last.max(h.ema as u64),
                confident: h.samples >= 2,
            },
            None => Self::prior(heavy),
        }
    }

    /// The estimate without history; the only one a guest's job ever gets.
    pub fn prior(heavy: bool) -> Estimate {
        Estimate {
            peak_bytes: if heavy { PRIOR_HEAVY } else { PRIOR_LIGHT },
            confident: false,
        }
    }

    pub fn record(&mut self, sig: &JobSignature, observed_peak: u64) {
        let x = observed_peak as f64;
        self.history
            .entry(sig.key.clone())
            .and_modify(|h| {
                h.ema = ALPHA * x + (1.0 - ALPHA) * h.ema;
                h.last = observed_peak;
                h.samples = h.samples.saturating_add(1);
            })
            .or_insert(History {
                last: observed_peak,
                ema: x,
                samples: 1,
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(s: &str) -> JobSignature {
        JobSignature { key: s.into() }
    }

    #[test]
    fn unknown_heavy_uses_prior() {
        let m = CostModel::default();
        let e = m.estimate(&k("x"), true);
        assert_eq!(e.peak_bytes, PRIOR_HEAVY);
        assert!(!e.confident);
    }

    #[test]
    fn prior_is_the_no_history_estimate() {
        assert_eq!(
            CostModel::prior(true),
            Estimate {
                peak_bytes: 1536 * 1024 * 1024,
                confident: false
            }
        );
        assert_eq!(
            CostModel::prior(false),
            Estimate {
                peak_bytes: 64 * 1024 * 1024,
                confident: false
            }
        );
        for heavy in [true, false] {
            assert_eq!(
                CostModel::default().estimate(&k("x"), heavy),
                CostModel::prior(heavy)
            );
        }
    }

    #[test]
    fn unknown_light_uses_light_prior() {
        assert_eq!(
            CostModel::default().estimate(&k("x"), false).peak_bytes,
            PRIOR_LIGHT
        );
    }

    #[test]
    fn learns_from_records() {
        let mut m = CostModel::default();
        m.record(&k("x"), 800 * MIB);
        assert!(!m.estimate(&k("x"), true).confident);
        m.record(&k("x"), 900 * MIB);
        let e = m.estimate(&k("x"), true);
        assert!(e.peak_bytes >= 900 * MIB);
        assert!(e.confident);
    }

    #[test]
    fn ema_keeps_a_spike_above_the_last_peak() {
        let mut m = CostModel::default();
        m.record(&k("x"), 1000 * MIB);
        m.record(&k("x"), 100 * MIB);
        // ema = 0.3*100 + 0.7*1000 = 730 MiB > last (100 MiB)
        assert_eq!(m.estimate(&k("x"), false).peak_bytes, 730 * MIB);
    }

    #[test]
    fn light_that_grew_is_estimated_by_history() {
        let mut m = CostModel::default();
        m.record(&k("y"), 700 * MIB);
        assert!(m.estimate(&k("y"), false).peak_bytes >= 700 * MIB);
    }

    #[test]
    fn roundtrips_json() {
        let mut m = CostModel::default();
        m.record(&k("x"), 800 * MIB);
        m.record(&k("x"), 900 * MIB);
        let back: CostModel = serde_json::from_str(&serde_json::to_string(&m).unwrap()).unwrap();
        assert_eq!(back.estimate(&k("x"), false), m.estimate(&k("x"), false));
        assert!(back.estimate(&k("x"), false).confident);
    }
}
