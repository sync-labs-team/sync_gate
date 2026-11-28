//! `sync_gate paths` through the real binary (no daemon, no pipe touched), and the CLI against a
//! daemon on a `SYNC_GATE_SOCKET` of its own.

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::Arc;
use sync_gate_core::Config;
use sync_gate_probe::Probe;
use sync_gated::{OsControl, OsLauncher};

struct Env {
    dir: PathBuf,
}

impl Env {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("sync_gate-t1p-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Env { dir }
    }
    fn data(&self) -> PathBuf {
        self.dir.join("data")
    }
    fn config(&self) -> PathBuf {
        self.dir.join("config.toml")
    }
    fn cmd(&self, args: &[&str], socket: Option<&str>) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_sync_gate"));
        c.args(args)
            .env("SYNC_GATE_DATA_DIR", self.data())
            .env("SYNC_GATE_CONFIG", self.config())
            .env_remove("SYNC_GATE_SOCKET");
        if let Some(s) = socket {
            c.env("SYNC_GATE_SOCKET", s);
        }
        c
    }
    fn paths(&self, socket: Option<&str>) -> Output {
        self.cmd(&["paths"], socket).output().unwrap()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn lines(out: &Output) -> Vec<(String, String)> {
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout.clone())
        .unwrap()
        .lines()
        .map(|l| {
            let (k, v) = l.split_once('=').unwrap();
            (k.to_owned(), v.to_owned())
        })
        .collect()
}

fn get<'a>(l: &'a [(String, String)], key: &str) -> &'a str {
    &l.iter().find(|(k, _)| k == key).unwrap().1
}

#[test]
fn paths_reports_the_temporary_locations_and_the_socket_override() {
    let e = Env::new("a");
    let l = lines(&e.paths(Some("x")));
    let keys: Vec<_> = l.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        keys,
        ["config", "data", "shims", "adopted", "socket", "hub"]
    );
    assert_eq!(get(&l, "config"), e.config().to_str().unwrap());
    assert_eq!(get(&l, "data"), e.data().to_str().unwrap());
    assert_eq!(get(&l, "shims"), e.data().join("shims").to_str().unwrap());
    assert_eq!(
        get(&l, "adopted"),
        e.data().join("mcp-adopted.json").to_str().unwrap()
    );
    assert_eq!(get(&l, "socket"), "x");
    assert_eq!(get(&l, "hub"), "x-mcp");
}

#[test]
fn empty_socket_override_falls_back_to_the_default_names() {
    let e = Env::new("b");
    let default = lines(&e.paths(None));
    let empty = lines(&e.paths(Some("")));
    for k in ["socket", "hub"] {
        assert_eq!(get(&empty, k), get(&default, k), "{k}");
        assert!(!get(&empty, k).is_empty(), "{k}");
    }
    assert_ne!(get(&empty, "hub"), "-mcp");
}

#[test]
fn cli_reaches_a_daemon_named_by_sync_gate_socket() {
    let e = Env::new("c");
    let account = format!("fgt1x{}", std::process::id());
    let sock = if cfg!(windows) {
        format!("sync_gate-t1p-{}", std::process::id())
    } else {
        e.dir.join("s.sock").to_string_lossy().into_owned()
    };
    let daemon = sync_gated::run_with(
        Config::default(),
        &sock,
        Probe::new(),
        OsControl,
        Some(e.data()),
        Arc::new(OsLauncher::default()),
    )
    .unwrap();
    let outs: Vec<_> = [vec!["status"], vec!["mcp", "list"]]
        .iter()
        .map(|a| {
            let mut c = e.cmd(a, Some(&sock));
            // The daemon's account is fake: only the override can lead the CLI to it.
            c.env(if cfg!(windows) { "USERNAME" } else { "USER" }, &account);
            c.output().unwrap()
        })
        .collect();
    daemon.shutdown();
    for out in outs {
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!String::from_utf8_lossy(&out.stdout).contains("not running"));
    }
}

#[test]
fn the_default_folders_are_under_the_sync_labs_vendor_folder() {
    let e = Env::new("v");
    let mut c = e.cmd(&["paths"], Some("x"));
    c.env_remove("SYNC_GATE_DATA_DIR")
        .env_remove("SYNC_GATE_CONFIG");
    let l = lines(&c.output().unwrap());
    let (config, data) = (get(&l, "config").to_owned(), get(&l, "data").to_owned());
    // The vendor folder exists on Windows (`sync_labs\sync_gate`) and macOS (`dev.sync_labs.sync_gate`) only.
    if cfg!(any(windows, target_os = "macos")) {
        assert!(
            config.contains("sync_labs") && data.contains("sync_labs"),
            "{config} {data}"
        );
    }
    assert!(
        !config.contains("synclabs") && !data.contains("synclabs"),
        "{config} {data}"
    );
}

/// D3: `paths --check` judges files and folders the way sync_gate judges its own (the installer
/// uses it): one of ours passes, absent passes, one others can change is refused with the reason.
#[test]
fn paths_check_judges_files_and_folders() {
    let e = Env::new("check");
    let f = e.dir.join("launcher.cmd");
    std::fs::write(&f, "@echo off\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&e.dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let absent = e.dir.join("absent.json");
    let check = |paths: &[&PathBuf]| {
        let mut c = e.cmd(&["paths", "--check"], None);
        c.args(paths);
        c.output().unwrap()
    };
    let ok = check(&[&e.dir, &f, &absent]);
    assert_eq!(
        ok.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o666)).unwrap();
    }
    #[cfg(windows)]
    {
        let out = Command::new("icacls")
            .arg(&f)
            .args(["/grant", "*S-1-1-0:(W)"])
            .output()
            .unwrap();
        assert!(out.status.success(), "icacls: {out:?}");
    }
    let bad = check(&[&e.dir, &f]);
    let err = String::from_utf8_lossy(&bad.stderr);
    let _ = std::fs::remove_dir_all(&e.dir);
    assert_eq!(bad.status.code(), Some(1), "{err}");
    assert!(err.contains("writable by other users"), "{err}");
    assert!(err.contains("launcher.cmd"), "{err}");
}

/// C-03, Windows: a file another program holds open for writing when it is checked is refused
/// (a handle opened before its permissions were fixed would keep that access); closed, it passes.
#[cfg(windows)]
#[test]
fn paths_check_refuses_a_file_open_for_writing() {
    let e = Env::new("check-held");
    let f = e.dir.join("install-state.json");
    std::fs::write(&f, "{}").unwrap();
    let check = || {
        let o = e.cmd(&["paths", "--check"], None).arg(&f).output().unwrap();
        (
            o.status.code(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        )
    };
    let held = std::fs::OpenOptions::new().write(true).open(&f).unwrap();
    let (code, err) = check();
    drop(held);
    assert_eq!(code, Some(1), "{err}");
    assert!(err.contains("sharing violation"), "{err}");
    let (code, err) = check();
    let _ = std::fs::remove_dir_all(&e.dir);
    assert_eq!(code, Some(0), "{err}");
}

/// C-02: an absent path passes only when what gets created there would: the nearest folder above
/// it that exists passes the folder rule (what is created inherits from it); and its name passes
/// the file rule (Windows: no stream, final dot or space).
#[test]
fn paths_check_judges_where_an_absent_path_would_be_created() {
    let e = Env::new("check-absent");
    let open = e.dir.join("open");
    std::fs::create_dir(&open).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&e.dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
    }
    #[cfg(windows)]
    {
        let out = Command::new("icacls")
            .arg(&open)
            .args(["/grant", "*S-1-1-0:(OI)(CI)(M)"])
            .output()
            .unwrap();
        assert!(out.status.success(), "icacls: {out:?}");
    }
    let check = |paths: &[PathBuf]| {
        let mut c = e.cmd(&["paths", "--check"], None);
        c.args(paths);
        let o = c.output().unwrap();
        (
            o.status.code(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        )
    };
    // Under a folder of ours: absent passes, a missing folder of a missing folder too.
    let (code, err) = check(&[e.dir.join("new.json"), e.dir.join("a").join("b").join("c")]);
    assert_eq!(code, Some(0), "{err}");
    // Under a folder others can change: refused, for a file and for a whole missing tree.
    for p in [
        open.join("install-state.json"),
        open.join("root").join("bin"),
    ] {
        let (code, err) = check(std::slice::from_ref(&p));
        assert_eq!(code, Some(1), "{}: {err}", p.display());
        assert!(err.contains("writable by other users"), "{err}");
    }
    #[cfg(windows)]
    for name in ["state.json.", "state.json:x"] {
        let (code, err) = check(&[e.dir.join(name)]);
        assert_eq!(code, Some(1), "{name}: {err}");
    }
    let _ = std::fs::remove_dir_all(&e.dir);
}
