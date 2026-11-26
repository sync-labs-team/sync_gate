//! `sync_gate mcp list`: configured MCP servers next to what the daemon reports about them.

use crate::client::{ClientError, call_at};
use crate::runner::socket;
use sync_gate_core::{Config, MIB, McpMode, McpStatus, Request, Response};

/// One row per configured server; a server the daemon does not report shows zeros.
pub fn render(cfg: &Config, daemon: Option<&[McpStatus]>) -> String {
    use std::fmt::Write;
    let mut rows = vec![
        [
            "SERVER",
            "MODE",
            "INSTANCES",
            "CLIENTS",
            "IN-FLIGHT",
            "RSS(MiB)",
            "RESTARTS",
        ]
        .map(String::from),
    ];
    for (name, srv) in &cfg.mcp {
        let mode = match srv.mode {
            McpMode::Shared => "shared",
            McpMode::PerSession => "per-session",
        };
        let st = daemon.and_then(|d| d.iter().find(|s| s.server == *name));
        let n = |f: fn(&McpStatus) -> u64| st.map_or(0, f).to_string();
        rows.push([
            name.clone(),
            mode.into(),
            n(|s| s.instances.into()),
            n(|s| s.clients.into()),
            n(|s| s.in_flight.into()),
            n(|s| s.rss / MIB),
            n(|s| s.restarts.into()),
        ]);
    }
    let mut o = String::new();
    if daemon.is_none() {
        o.push_str("daemon not running\n");
    }
    let width: Vec<usize> = (0..7)
        .map(|c| rows.iter().map(|r| r[c].len()).max().unwrap_or(0))
        .collect();
    for r in &rows {
        let line: Vec<String> = r
            .iter()
            .zip(&width)
            .map(|(v, w)| format!("{v:<w$}"))
            .collect();
        let _ = writeln!(o, "{}", line.join("  ").trim_end());
    }
    o
}

pub fn list() -> i32 {
    let cfg = match sync_gate_shim::load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sync_gate: {e}");
            return 1;
        }
    };
    let report = match call_at(&socket(), &Request::Status) {
        Ok(Response::Status(s)) => Some(s.mcp),
        Ok(_) | Err(ClientError::DaemonDown) => None,
        Err(e) => {
            eprintln!("sync_gate: {e}");
            return 1;
        }
    };
    print!("{}", render(&cfg, report.as_deref()));
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_show_zeros_for_unreported_servers_and_the_daemon_note_when_down() {
        let cfg = Config::from_toml(
            "[mcp.docs]\ncommand=\"x\"\nmode=\"shared\"\n[mcp.solo]\ncommand=\"y\"\n",
        )
        .unwrap();
        let st = McpStatus {
            server: "docs".into(),
            mode: "shared".into(),
            instances: 1,
            clients: 2,
            in_flight: 3,
            rss: 5 * MIB,
            restarts: 4,
        };
        let up = render(&cfg, Some(&[st]));
        let rows: Vec<Vec<&str>> = up.lines().map(|l| l.split_whitespace().collect()).collect();
        assert_eq!(rows[0][0], "SERVER");
        assert_eq!(rows[1], ["docs", "shared", "1", "2", "3", "5", "4"]);
        assert_eq!(rows[2], ["solo", "per-session", "0", "0", "0", "0", "0"]);
        let down = render(&cfg, None);
        assert_eq!(down.lines().next(), Some("daemon not running"));
        assert_eq!(down.lines().count(), 4);
    }
}
