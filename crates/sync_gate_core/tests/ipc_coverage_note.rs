//! `cargo test -p sync_gate_core` alone builds without the `ipc` feature, so the IPC tests are
//! compiled out. The run must say so, and must not say so when the feature is on.

use std::process::Command;

const NOTE: &str = "ipc coverage skipped: run with --features ipc";

/// Standard output of the crate's own unit tests named `ipc_coverage`, built by a nested cargo in
/// its own target folder (the outer one is locked by the running `cargo test`).
fn run(features: &[&str]) -> String {
    let out = Command::new(env!("CARGO"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["test", "-p", "sync_gate_core", "--lib", "--locked"])
        .args(features)
        .args(["--", "ipc_coverage"])
        .env(
            "CARGO_TARGET_DIR",
            concat!(env!("CARGO_TARGET_TMPDIR"), "/ipc-coverage-note"),
        )
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    stdout
}

#[test]
fn package_only_run_says_ipc_coverage_is_skipped() {
    let stdout = run(&[]);
    assert!(
        stdout.contains(NOTE),
        "no note without the feature:\n{stdout}"
    );
}

#[test]
fn run_with_ipc_has_no_note() {
    let stdout = run(&["--features", "ipc"]);
    assert!(
        !stdout.contains(NOTE),
        "note with the feature on:\n{stdout}"
    );
}
