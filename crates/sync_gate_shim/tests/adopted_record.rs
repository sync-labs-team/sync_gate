//! The relay's fallback to the adoption record, through the real `sync_gate_mcp` binary: a
//! record of ours starts the recorded server; one others can change starts nothing.

use std::path::{Path, PathBuf};
use std::process::Command;
use sync_gate_core::adopted::{Adopted, AdoptedEntry, Agent, RECORD};
use sync_gate_core::agent_config::LaunchText;

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("fg-relay-rec-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("data")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for p in [d.clone(), d.join("data")] {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    d
}

/// A record whose only server `srv` creates `marker` when it starts.
fn write_record(data: &Path, marker: &Path) {
    let (command, args) = if cfg!(windows) {
        (
            "cmd".to_owned(),
            vec!["/c".to_owned(), format!("type nul > {}", marker.display())],
        )
    } else {
        (
            "sh".to_owned(),
            vec!["-c".to_owned(), format!("touch '{}'", marker.display())],
        )
    };
    let entry = AdoptedEntry {
        agent: Agent::Codex,
        file: data.join("codex.toml"),
        server: "srv".into(),
        original: LaunchText {
            command: command.clone(),
            args: None,
        },
        original_command: command,
        original_args: Some(args),
        adopted_command: "sync_gate_mcp".into(),
        adopted_args: vec!["srv".into()],
        inserted_args: false,
    };
    let rec = Adopted {
        version: 1,
        entries: vec![entry],
    };
    let p = data.join(RECORD);
    std::fs::write(&p, serde_json::to_vec(&rec).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn open_to_others(p: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o666)).unwrap();
    }
    #[cfg(windows)]
    {
        let out = Command::new("icacls")
            .arg(p)
            .args(["/grant", "*S-1-1-0:(W)"])
            .output()
            .unwrap();
        assert!(out.status.success(), "icacls: {out:?}");
    }
}

/// (exit code, stderr) of `sync_gate_mcp srv` with no config, stdin closed.
fn relay(dir: &Path) -> (Option<i32>, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_sync_gate_mcp"))
        .arg("srv")
        .env("SYNC_GATE_DATA_DIR", dir.join("data"))
        .env("SYNC_GATE_CONFIG", dir.join("absent.toml"))
        .env(
            "SYNC_GATE_SOCKET",
            format!("fg-relay-rec-{}", std::process::id()),
        )
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// C3b: the server named only by the record runs when the record is ours; not when others can
/// change the record.
#[test]
fn the_relay_runs_a_recorded_server_only_from_a_record_of_ours() {
    let ok = scratch("ok");
    let marker = ok.join("started");
    write_record(&ok.join("data"), &marker);
    let (_, err) = relay(&ok);
    assert!(err.contains("from the adoption record"), "{err}");
    assert!(
        marker.exists(),
        "control: the recorded server did not start: {err}"
    );
    let _ = std::fs::remove_dir_all(&ok);

    let bad = scratch("open");
    let marker = bad.join("started");
    write_record(&bad.join("data"), &marker);
    open_to_others(&bad.join("data").join(RECORD));
    let (code, err) = relay(&bad);
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("adoption record refused"), "{err}");
    assert!(err.contains("writable by other users"), "{err}");
    assert!(!marker.exists(), "the recorded server started");
    let _ = std::fs::remove_dir_all(&bad);
}
