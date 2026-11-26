//! Starting the real MCP server from the relay.

use std::process::{Child, Command, ExitStatus, Stdio};
use sync_gate_core::McpServer;

/// The configured command with its `env` added to ours; `cwd` unset or `"inherit"` keeps ours.
/// `program` is the file [`resolve`] found once at relay start: a bare command is started from
/// it and from nothing else (no second search, never the bare name, which the OS would search
/// in folders we skip). The error is the relay's exit code (127 not found, 126 otherwise) and
/// its stderr message.
pub(crate) fn spawn(
    name: &str,
    srv: &McpServer,
    program: Option<&std::path::Path>,
    stdin: Stdio,
    stdout: Stdio,
) -> Result<Child, (i32, String)> {
    let mut c = match program {
        Some(p) => Command::new(p),
        None if is_bare(&srv.command) => return Err((127, no_safe_message(name, srv))),
        None => Command::new(&srv.command),
    };
    c.args(&srv.args).envs(&srv.env).stdin(stdin).stdout(stdout);
    if let Some(dir) = srv.cwd.as_deref().filter(|d| *d != "inherit") {
        c.current_dir(dir);
    }
    c.spawn().map_err(|e| {
        let code = if e.kind() == std::io::ErrorKind::NotFound {
            127
        } else {
            126
        };
        (code, format!("sync_gate_mcp: cannot start '{name}': {e}"))
    })
}

fn no_safe_message(name: &str, srv: &McpServer) -> String {
    format!(
        "sync_gate_mcp: cannot start '{name}': '{}' is on no safe folder of PATH",
        srv.command
    )
}

/// What the relay resolves once: the file for a bare command (`Err` with the message when no
/// safe folder has it), `None` for a command with a folder part, which runs as given.
pub(crate) fn resolve(name: &str, srv: &McpServer) -> Result<Option<std::path::PathBuf>, String> {
    match program_of(srv) {
        Some(p) => Ok(Some(p)),
        None if is_bare(&srv.command) => Err(no_safe_message(name, srv)),
        None => Ok(None),
    }
}

fn is_bare(command: &str) -> bool {
    !command
        .chars()
        .any(|c| std::path::is_separator(c) || (cfg!(windows) && c == ':'))
}

/// A bare command as the agent would find it: the server's `PATH` (any case on Windows), else
/// ours, shim folders skipped; a relative `PATH` entry is taken from the folder the server runs
/// in (its fixed `cwd`, else ours). `None` for a command with a folder part, or found nowhere.
pub(crate) fn program_of(srv: &McpServer) -> Option<std::path::PathBuf> {
    if !is_bare(&srv.command) {
        return None;
    }
    let path = srv
        .env
        .iter()
        .find(|(k, _)| k.as_str() == "PATH" || (cfg!(windows) && k.eq_ignore_ascii_case("PATH")))
        .map(|(_, v)| std::ffi::OsString::from(v))
        .or_else(|| std::env::var_os("PATH"));
    sync_gate_core::find_program(
        std::ffi::OsStr::new(&srv.command),
        path.as_deref(),
        std::env::var_os("PATHEXT").as_deref(),
        &server_dir(srv),
    )
}

/// Where the server runs: its fixed `cwd` (a relative one from ours), else ours.
fn server_dir(srv: &McpServer) -> std::path::PathBuf {
    let ours = std::env::current_dir().unwrap_or_default();
    match srv.cwd.as_deref().filter(|d| *d != "inherit") {
        Some(d) => ours.join(d),
        None => ours,
    }
}

/// A signal on Unix becomes 128 + the signal, like a shell reports it.
pub(crate) fn exit_code(s: ExitStatus) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = s.signal() {
            return 128 + sig;
        }
    }
    s.code().unwrap_or(1)
}
