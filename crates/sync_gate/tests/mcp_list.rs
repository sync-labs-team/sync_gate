//! `sync_gate mcp list` through the real binary, with and without a daemon.

use std::process::Command;
use std::sync::Arc;
use sync_gate_core::Config;
use sync_gate_probe::Probe;
use sync_gated::{OsControl, OsLauncher};

const TOML: &str =
    "[mcp.docs]\ncommand = \"docs-mcp\"\nmode = \"shared\"\n\n[mcp.solo]\ncommand = \"solo-mcp\"\n";

fn list(socket: &str, config: &std::path::Path) -> (i32, Vec<Vec<String>>) {
    let out = Command::new(env!("CARGO_BIN_EXE_sync_gate"))
        .args(["mcp", "list"])
        .env("SYNC_GATE_SOCKET", socket)
        .env("SYNC_GATE_CONFIG", config)
        .output()
        .unwrap();
    let rows = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.split_whitespace().map(String::from).collect())
        .collect();
    (out.status.code().unwrap(), rows)
}

#[test]
fn mcp_list_shows_servers_with_and_without_daemon() {
    let id = format!("sync_gate_mcplist-{}", std::process::id());
    let dir = std::env::temp_dir().join(&id);
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("config.toml");
    std::fs::write(&config, TOML).unwrap();
    let socket = if cfg!(windows) {
        id.clone()
    } else {
        dir.join("s.sock").to_string_lossy().into_owned()
    };

    // No daemon: the config is listed under a note, exit 0.
    let (code, rows) = list(&socket, &config);
    assert_eq!(code, 0);
    assert_eq!(rows[0], ["daemon", "not", "running"]);
    assert_eq!(rows[1][0], "SERVER");
    assert_eq!(rows[1].len(), 7);
    assert_eq!(rows[2][..2], ["docs", "shared"]);
    assert_eq!(rows[3][..2], ["solo", "per-session"]);

    // With a daemon: no note, same rows (nothing running yet, so zeros).
    let cfg = Config::from_toml(TOML).unwrap();
    let daemon = sync_gated::run_with(
        cfg,
        &socket,
        Probe::new(),
        OsControl,
        Some(dir.join("data")),
        Arc::new(OsLauncher::default()),
    )
    .unwrap();
    let (code, rows) = list(&socket, &config);
    daemon.shutdown();
    assert_eq!(code, 0);
    assert_eq!(rows[0][0], "SERVER");
    assert_eq!(rows[1], ["docs", "shared", "0", "0", "0", "0", "0"]);
    assert_eq!(rows[2], ["solo", "per-session", "0", "0", "0", "0", "0"]);
    let _ = std::fs::remove_dir_all(&dir);
}
