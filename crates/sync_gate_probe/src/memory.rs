//! Machine memory snapshot.
use crate::gpu;
use sync_gate_core::MachineSnapshot;
use sysinfo::{MemoryRefreshKind, System};

/// Reusable sampler; keep one alive so refreshes stay cheap.
pub struct Probe {
    // None only if sysinfo does not support this platform; measurements then read as 0.
    pub(crate) sys: Option<System>,
}

impl Default for Probe {
    fn default() -> Self {
        Self::new()
    }
}

impl Probe {
    pub fn new() -> Self {
        Self {
            sys: System::new().ok(),
        }
    }

    pub fn snapshot(&mut self) -> MachineSnapshot {
        let vram = gpu::vram();
        let Some(sys) = self.sys.as_mut() else {
            return MachineSnapshot {
                total: 0,
                available: 0,
                reclaimable: 0,
                swap_used: 0,
                swap_total: 0,
                vram,
            };
        };
        sys.refresh_memory_specifics(MemoryRefreshKind::everything());
        let total = sys.total_memory();
        let available = sys.free_memory().min(total);
        // shortcut: Windows reports free == available, so its standby list is not split out
        // (reclaimable is 0 there); GetPerformanceInfo would be the upgrade.
        let reclaimable = sys.available_memory().min(total).saturating_sub(available);
        MachineSnapshot {
            total,
            available,
            reclaimable,
            swap_used: sys.used_swap(),
            swap_total: sys.total_swap(),
            vram,
        }
    }
}
