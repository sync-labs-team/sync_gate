//! The `sync_gated` binary: `--help` and `--version` answer without starting a daemon,
//! `SYNC_GATE_SOCKET` names the control socket and the hub, and every child here runs against a
//! throwaway socket, data folder, config and fake account name, so a binary that ignores
//! `SYNC_GATE_SOCKET` creates `sync_gate-<fake account>` and never the real pipe.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};
use sync_gate_core::{Request, Response};

const BIN: &str = env!("CARGO_BIN_EXE_sync_gated");
const LIMIT: Duration = Duration::from_secs(5);

/// A throwaway environment for one child. Dropping it removes the folder.
struct Sandbox {
    dir: PathBuf,
    /// Socket name (Windows) or path (Unix) given as `SYNC_GATE_SOCKET`.
    sock: String,
    account: String,
}

impl Sandbox {
    fn new(tag: &str) -> Self {
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("sync_gate-t1-{tag}-{pid}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let sock = if cfg!(windows) {
            format!("sync_gate-t1-{tag}-{pid}")
        } else {
            dir.join("s.sock").to_string_lossy().into_owned()
        };
        let sb = Sandbox {
            dir,
            sock,
            account: format!("fgt1x{pid}"),
        };
        sb.guard();
        sb
    }

    /// 1.0: a binary that ignores `SYNC_GATE_SOCKET` would bind the name below; it must not be
    /// the one the real account uses.
    fn guard(&self) {
        let real = sync_gate_core::socket_name();
        let (fake, real) = if cfg!(windows) {
            (format!("sync_gate-{}", self.account), real)
        } else {
            let file = PathBuf::from(real)
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned();
            (format!("sync_gate-{}.sock", self.account), file)
        };
        assert_ne!(
            fake, real,
            "fake account name must not reach the real socket"
        );
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(BIN);
        c.args(args)
            .env("SYNC_GATE_SOCKET", &self.sock)
            .env("SYNC_GATE_DATA_DIR", self.dir.join("data"))
            .env("SYNC_GATE_CONFIG", self.dir.join("config.toml"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if cfg!(windows) {
            c.env("USERNAME", &self.account);
        } else {
            c.env("USER", &self.account)
                .env("XDG_RUNTIME_DIR", &self.dir);
        }
        c
    }

    /// Runs to completion within `LIMIT`; a child still alive then is killed and the test fails.
    fn run(&self, args: &[&str]) -> Output {
        let mut child = self.command(args).spawn().unwrap();
        let start = Instant::now();
        while child.try_wait().unwrap().is_none() {
            if start.elapsed() > LIMIT {
                let _ = child.kill();
                let _ = child.wait();
                panic!("sync_gated {args:?} did not exit within {LIMIT:?}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        child.wait_with_output().unwrap()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[test]
fn help_exits_zero_and_prints_usage() {
    let sb = Sandbox::new("help");
    for flag in ["--help", "-h"] {
        let out = sb.run(&[flag]);
        assert_eq!(out.status.code(), Some(0), "{flag}");
        assert!(text(&out.stdout).starts_with("usage: sync_gated"), "{flag}");
    }
}

#[test]
fn version_prints_the_product_line() {
    let sb = Sandbox::new("ver");
    let want = format!("sync_gated {}", env!("CARGO_PKG_VERSION"));
    for flag in ["--version", "-V"] {
        let out = sb.run(&[flag]);
        assert_eq!(out.status.code(), Some(0), "{flag}");
        assert_eq!(text(&out.stdout).trim_end(), want, "{flag}");
    }
}

#[test]
fn unexpected_arguments_exit_two() {
    let sb = Sandbox::new("bad");
    for (args, arg) in [
        (vec!["--bogus"], "--bogus"),
        (vec!["--help", "extra"], "extra"),
    ] {
        let out = sb.run(&args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
        let err = text(&out.stderr);
        assert!(
            err.contains(&format!("unexpected argument `{arg}`")),
            "{args:?}: {err}"
        );
    }
}

/// Waits for the daemon to answer `Status` on the control socket (up to `LIMIT`), as the CLI does.
fn status(sock: &str) -> Option<Response> {
    let start = Instant::now();
    while start.elapsed() < LIMIT {
        if let Ok(stream) = sync_gate_core::ipc_name::connect(sock) {
            let mut conn = BufReader::new(stream);
            let mut line = serde_json::to_vec(&Request::Status).unwrap();
            line.push(b'\n');
            conn.get_mut().write_all(&line).unwrap();
            conn.get_mut().flush().unwrap();
            let mut reply = String::new();
            if conn.read_line(&mut reply).is_ok() && !reply.is_empty() {
                return serde_json::from_str(&reply).ok();
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    None
}

fn stop(mut child: Child) {
    #[cfg(unix)]
    {
        use nix::sys::signal::{Signal, kill};
        kill(
            nix::unistd::Pid::from_raw(child.id() as i32),
            Signal::SIGTERM,
        )
        .unwrap();
        let start = Instant::now();
        while child.try_wait().unwrap().is_none() {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "no exit after SIGTERM"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(child.wait().unwrap().success());
    }
    #[cfg(windows)]
    {
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[test]
fn daemon_serves_control_socket_and_hub_on_sync_gate_socket() {
    let sb = Sandbox::new("run");
    let child = sb.command(&[]).spawn().unwrap();
    let pid = child.id();
    let reply = status(&sb.sock);
    let hub = sync_gate_core::ipc_name::connect(&format!("{}-mcp", sb.sock));
    stop(child);
    match reply {
        Some(Response::Status(r)) => assert_eq!(r.daemon.pid, pid),
        other => panic!("no Status reply on {}: {other:?}", sb.sock),
    }
    assert!(hub.is_ok(), "hub: {:?}", hub.err());
}
