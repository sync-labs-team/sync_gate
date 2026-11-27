//! `sync_gated`: loads config, runs the daemon until Ctrl+C or a termination signal, then shuts down cleanly.
//!
//! Test or advanced override read from the environment (not part of the public interface):
//! `SYNC_GATE_CONFIG` (path of the `config.toml` to use instead of the per-user one),
//! `SYNC_GATE_DATA_DIR`, `SYNC_GATE_SOCKET`.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, mpsc};
use sync_gate_core::{Config, ConfigLoadError, socket_name};

/// `$SYNC_GATE_CONFIG`, else `config.toml` in the per-user config dir; missing means defaults,
/// invalid is an error: the full text for this console, and a version safe for a note.
fn load_config() -> Result<Config, (String, ConfigLoadError)> {
    let path = match std::env::var_os("SYNC_GATE_CONFIG") {
        Some(p) => PathBuf::from(p),
        None => match directories::ProjectDirs::from("dev", "sync_labs", "sync_gate") {
            Some(dirs) => dirs.config_dir().join("config.toml"),
            None => return Ok(Config::default()),
        },
    };
    match sync_gate_core::read_config(&path) {
        Ok(text) => Config::from_toml(&text).map_err(|e| {
            let detail = format!("invalid {}: {e}", path.display());
            (detail, ConfigLoadError::parse(&text, &e))
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(e) => Err((
            format!("cannot read {}: {e}", path.display()),
            ConfigLoadError::unreadable(),
        )),
    }
}

const USAGE: &str = "usage: sync_gated [--help | --version]

The sync_gate daemon. The installer starts it with your session (Task Scheduler, launchd or
systemd --user); you do not need to run it by hand.

Environment: SYNC_GATE_CONFIG, SYNC_GATE_DATA_DIR, SYNC_GATE_SOCKET, SYNC_GATE_UPDATE_CHECK=0
(no weekly look at the latest release).";

#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Run,
    Help,
    Version,
    Bad(String),
}

/// No arguments runs the daemon; exactly one of `-h`/`--help`/`-V`/`--version` answers and exits;
/// anything else is `Bad` with the first argument that does not belong.
fn mode(args: &[OsString]) -> Mode {
    let Some(first) = args.first() else {
        return Mode::Run;
    };
    let known = match first.to_str() {
        Some("-h" | "--help") => Mode::Help,
        Some("-V" | "--version") => Mode::Version,
        _ => return Mode::Bad(first.to_string_lossy().into_owned()),
    };
    match args.get(1) {
        None => known,
        Some(extra) => Mode::Bad(extra.to_string_lossy().into_owned()),
    }
}

fn main() -> ExitCode {
    // Decided before anything else: asking for help must never start a daemon.
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match mode(&args) {
        Mode::Run => {}
        Mode::Help => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Mode::Version => {
            println!("sync_gated {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Mode::Bad(arg) => {
            eprintln!("sync_gated: unexpected argument `{arg}`\n\n{USAGE}");
            return ExitCode::from(2);
        }
    }
    let cfg = match load_config() {
        Ok(c) => c,
        Err((e, _)) => {
            eprintln!("sync_gated: {e}");
            return ExitCode::from(2);
        }
    };
    // Installed before `run`, so a signal during startup still ends in a clean shutdown.
    // The handler only signals; resuming happens in `shutdown`. Windows may kill the process
    // right after a console close; the next start recovers from paused.json in that case.
    let (tx, rx) = mpsc::channel();
    if let Err(e) = ctrlc::set_handler(move || {
        let _ = tx.send(());
    }) {
        eprintln!("sync_gated: cannot install signal handler: {e}");
        return ExitCode::FAILURE;
    }
    // The hub rereads `[mcp]` from the same file when a session names a server it does not know.
    let reload: sync_gated::McpReload =
        Arc::new(|| load_config().map(|c| c.mcp).map_err(|(_, safe)| safe));
    let handle = match sync_gated::run(cfg, &socket_name(), Some(reload)) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("sync_gated: cannot start: {e}");
            return ExitCode::FAILURE;
        }
    };
    // The weekly look at the latest release; reads `update_check_days` again at every wake-up.
    if let Some(dir) = sync_gated::store::default_dir() {
        sync_gated::update_check::spawn(dir, || sync_gate_core::update::days_of(load_config()));
    }
    let _ = rx.recv();
    handle.shutdown();
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(a: &[&str]) -> Mode {
        mode(&a.iter().map(OsString::from).collect::<Vec<_>>())
    }

    #[test]
    fn mode_table() {
        assert_eq!(m(&[]), Mode::Run);
        for h in ["-h", "--help"] {
            assert_eq!(m(&[h]), Mode::Help);
        }
        for v in ["-V", "--version"] {
            assert_eq!(m(&[v]), Mode::Version);
        }
        assert_eq!(m(&["--bogus"]), Mode::Bad("--bogus".into()));
        assert_eq!(m(&["--help", "extra"]), Mode::Bad("extra".into()));
        assert_eq!(m(&["extra", "--help"]), Mode::Bad("extra".into()));
    }
}
