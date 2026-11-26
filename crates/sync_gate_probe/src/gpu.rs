//! NVIDIA VRAM via NVML, behind the `nvidia` feature.
use sync_gate_core::VramSnapshot;

#[cfg(not(feature = "nvidia"))]
pub fn vram() -> Option<VramSnapshot> {
    None
}

#[cfg(feature = "nvidia")]
pub fn vram() -> Option<VramSnapshot> {
    use std::sync::OnceLock;
    // Init once (it loads the driver library); a failed init is cached as None too.
    static NVML: OnceLock<Option<nvml_wrapper::Nvml>> = OnceLock::new();
    let nvml = NVML
        .get_or_init(|| nvml_wrapper::Nvml::init().ok())
        .as_ref()?;
    let info = nvml.device_by_index(0).ok()?.memory_info().ok()?;
    Some(VramSnapshot {
        total: info.total,
        used: info.used.min(info.total),
    })
}
