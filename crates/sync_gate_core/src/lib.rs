//! Pure logic for sync_gate: job signatures, cost model, scheduler, pressure analysis and protocol types.

pub mod adopted;
pub mod agent_config;
pub mod config;
pub mod cost;
#[cfg(feature = "ipc")]
pub mod ipc_name;
pub mod jsonrpc;
pub mod pressure;
pub mod private_dir;
pub mod program;
pub mod protocol;
pub mod scheduler;
pub mod signature;
pub mod snapshot;
pub mod template;
pub mod update;
#[cfg(windows)]
mod win_sec;
pub use config::{
    APPCONTAINER_GUEST, Config, ConfigLoadError, MAX_GUESTS, MAX_WAIT_SECS, McpMode, McpServer,
    PgConfig, PgProject, RESTRICTED_GUEST, data_dir, is_extension_name, read_config, shims_dir,
    shims_dir_from,
};
pub use cost::{CostModel, Estimate, MIB, PRIOR_HEAVY, PRIOR_LIGHT};
pub use jsonrpc::{Kind, classify, error_response, result_response};
pub use pressure::{JobSample, Verdict, analyze, under_pressure};
pub use private_dir::{
    DirState, check_private_dir, check_private_file, is_in_use, is_refusal, open_private_file,
    refusal,
};
pub use program::{SHIMS_MANIFEST, find_program, find_ps1, resolve_in_env, resolve_program};
pub use protocol::{
    DaemonInfo, ERR_ADMITTED, ERR_BUSY, ERR_CLAIMED, ERR_UNKNOWN_TICKET, Holder, HubHello,
    HubReply, McpStatus, Request, Response, SERVICE_POSTGRES, Secret, ServiceStatus, StatusReport,
    guest_socket_name, hub_socket_name, sandbox_socket_name, socket_name,
};
pub use scheduler::{GuestOf, Scheduler, Ticket, TicketId};
pub use signature::{
    HEAVY_PROGRAMS, JobSignature, SignatureError, guest_signature, is_heavy, signature,
};
pub use snapshot::{MachineSnapshot, VramSnapshot};
pub use template::{KeyError, is_template_key, template_key};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn workspace_builds() {
        assert_eq!(crate::VERSION, env!("CARGO_PKG_VERSION"));
    }
}
