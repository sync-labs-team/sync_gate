//! `cargo test -p sync_gate_core` alone builds without the `ipc` feature, so the IPC tests are
//! compiled out. The run must say so, and must not say so when the feature is on.

use std::process::Command;

const NOTE: &str = "ipc coverage skipped: run with --features ipc";

/// Standard output and error of the crate's own unit tests, built by a nested cargo in its own
/// target folder (the outer one is locked by the running `cargo test`).
fn run(cargo_args: &[&str], test_args: &[&str]) -> String {
    let out = Command::new(env!("CARGO"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["test", "-p", "sync_gate_core", "--lib", "--locked"])
        .args(cargo_args)
        .arg("--")
        .args(test_args)
        .env(
            "CARGO_TARGET_DIR",
            concat!(env!("CARGO_TARGET_TMPDIR"), "/ipc-coverage-note"),
        )
        .output()
        .unwrap();
    let all = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{all}");
    all
}

#[test]
fn package_only_run_says_ipc_coverage_is_skipped_even_quiet() {
    // cargo's `--quiet` also hands `--quiet` to libtest.
    let all = run(&["--quiet"], &["ipc_coverage"]);
    assert!(all.contains(NOTE), "no note without the feature:\n{all}");
}

#[test]
fn run_with_ipc_has_the_ipc_tests_and_no_note() {
    let all = run(&["--features", "ipc"], &["--list"]);
    assert!(
        all.contains("ipc_name::tests::"),
        "no ipc test with the feature on:\n{all}"
    );
    assert!(
        !all.contains("ipc_coverage"),
        "note with the feature on:\n{all}"
    );
}
