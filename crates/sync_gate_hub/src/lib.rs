//! MCP hub: shares one MCP server process between many agent sessions.

pub mod mux;
pub use mux::{
    ClientId, Era, MAX_IN_FLIGHT_PER_CLIENT, MAX_MESSAGE_BYTES, MAX_QUEUED_BYTES_PER_CLIENT,
    MAX_QUEUED_PER_CLIENT, MAX_SUBSCRIPTIONS_PER_CLIENT, Mux, Out, PROBE_TIMEOUT,
};
pub mod pool;
pub use pool::{
    GROW_WAIT, PoolAction, PoolStats, SHRINK_IDLE, decide, pick_instance, wants_to_grow,
};
