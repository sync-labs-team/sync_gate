//! Point-in-time view of machine memory, as sampled by the daemon.

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VramSnapshot {
    pub total: u64,
    pub used: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MachineSnapshot {
    /// Installed physical memory, in bytes.
    pub total: u64,
    /// Immediately free memory, in bytes (excludes reclaimable cache).
    pub available: u64,
    /// Cache/standby memory the OS can hand back on demand, in bytes.
    /// `available + reclaimable <= total`, and the sum is the OS's own "available" figure.
    pub reclaimable: u64,
    pub swap_used: u64,
    pub swap_total: u64,
    pub vram: Option<VramSnapshot>,
}
