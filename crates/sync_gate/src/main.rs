//! `sync_gate run | wait | status`: ask `sync_gated` for admission before heavy commands.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use sync_gate::adopt::{self, AgentArg};
use sync_gate::runner;

#[derive(Parser)]
#[command(
    version = env!("CARGO_PKG_VERSION"),
    about = "sync_gate: lets several coding agents share one machine without freezing it."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a command, waiting for the daemon's admission first. Whatever follows `--` queues, heavy or not.
    Run {
        /// Session name; default `$SYNC_GATE_SESSION`, else "default".
        #[arg(long)]
        session: Option<String>,
        /// Seconds to wait in the queue before exiting 75; default from the config.
        #[arg(long)]
        max_wait: Option<u64>,
        /// The command and its arguments, after `--`.
        #[arg(last = true, required = true, num_args = 1..)]
        cmd: Vec<String>,
    },
    /// Resume the wait of a queued ticket and run its stored command. sync_gated deletes the stored command (arguments and folder) 25 h after it was saved or its last wait began, unless a wait on it is in progress; in the `elevated` Codex sandbox, the sandbox's next queued command deletes it instead (no time limit if none comes). A deleted ticket exits 2: run the original command again.
    Wait {
        id: u64,
        #[arg(long)]
        max_wait: Option<u64>,
    },
    /// Show memory, running jobs, the queue and recent decisions.
    Status,
    /// MCP servers shared through the daemon's hub.
    Mcp {
        #[command(subcommand)]
        cmd: McpCmd,
    },
    /// Shims that send heavy programs through the queue.
    Shims {
        #[command(subcommand)]
        cmd: ShimsCmd,
    },
    /// Print the paths and socket names this sync_gate uses, one `key=value` per line.
    Paths {
        /// Instead, judge each PATH as sync_gate judges what it trusts (a folder only you can
        /// change; a file nobody else can change, not a link); absent paths pass. One line per
        /// refusal; exit 1 when any is refused. The installer uses it.
        #[arg(long, num_args = 1.., value_name = "PATH")]
        check: Vec<PathBuf>,
    },
    /// Agent hook entry points (Claude Code, Codex).
    Hook {
        #[command(subcommand)]
        event: HookEvent,
    },
}

#[derive(Subcommand)]
enum HookEvent {
    /// SessionStart: shims on the Claude session's Bash PATH, and a short context.
    SessionStart,
}

#[derive(Subcommand)]
enum ShimsCmd {
    /// Create or refresh the shims; prints the folder and how to put it on PATH.
    Install,
    /// Remove the shims sync_gate made (nothing else in the folder).
    Remove,
}

#[derive(Subcommand)]
enum McpCmd {
    /// Act as the MCP server `<server>` on stdio (what an agent's config launches).
    Connect { server: String },
    /// List the configured servers with what the daemon reports about them.
    List,
    /// sync_gate's own read-only MCP server on stdio: machine state and the queue.
    Serve,
    /// Point MCP servers of Claude Code and Codex at the hub; without names, list the candidates.
    Adopt {
        #[arg(long, value_enum, default_value = "all")]
        agent: AgentArg,
        /// Show what would change; write nothing.
        #[arg(long)]
        dry_run: bool,
        /// The server does not depend on the session's folder: one instance serves every project.
        #[arg(long)]
        any_folder: bool,
        /// Claude Code's config (default: ~/.claude.json).
        #[arg(long)]
        claude_config: Option<PathBuf>,
        /// Codex's config (default: $CODEX_HOME/config.toml, else ~/.codex/config.toml).
        #[arg(long)]
        codex_config: Option<PathBuf>,
        servers: Vec<String>,
    },
    /// Put back the launch values `adopt` replaced; without names, every recorded server.
    Restore {
        #[arg(long, value_enum, default_value = "all")]
        agent: AgentArg,
        #[arg(long)]
        claude_config: Option<PathBuf>,
        #[arg(long)]
        codex_config: Option<PathBuf>,
        /// Exit 3 while a selected entry is still adopted after the restore.
        #[arg(long)]
        strict: bool,
        servers: Vec<String>,
    },
}

/// `paths --check`: folders by `check_private_dir`, anything else by `check_private_file`.
fn check_paths(paths: &[PathBuf]) -> i32 {
    let mut refused = 0;
    for p in paths {
        let r = match std::fs::symlink_metadata(p) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Ok(m) if m.is_dir() => sync_gate_core::check_private_dir(p).map(drop),
            _ => match sync_gate_core::check_private_file(p) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                r => r,
            },
        };
        if let Err(e) = r {
            eprintln!("sync_gate: refused: {e}");
            refused += 1;
        }
    }
    i32::from(refused > 0)
}

/// `key=value` lines, values as they are; a value that is missing, not UTF-8 or multi-line fails.
fn paths() -> i32 {
    let data = sync_gate_core::data_dir();
    let rows: [(&str, Option<PathBuf>); 6] = [
        ("config", sync_gate_shim::config_path()),
        ("data", data.clone()),
        ("shims", sync_gate_core::shims_dir()),
        (
            "adopted",
            data.map(|d| d.join(sync_gate_core::adopted::RECORD)),
        ),
        ("socket", Some(runner::socket().into())),
        ("hub", Some(sync_gate_shim::hub_name().into())),
    ];
    let mut out = String::new();
    for (key, value) in rows {
        let why = match value.as_deref().map(std::path::Path::to_str) {
            None => "not available",
            Some(None) => "not valid UTF-8",
            Some(Some(v)) if v.contains(['\n', '\r']) => "contains a newline",
            Some(Some(v)) => {
                out.push_str(&format!("{key}={v}\n"));
                continue;
            }
        };
        eprintln!("sync_gate: paths: {key}: {why}");
        return 1;
    }
    print!("{out}");
    0
}

fn main() {
    // A shim is this binary under the name of a heavy program.
    if let Some(name) = sync_gate::shims::invoked_as() {
        std::process::exit(sync_gate::shims::run_as(&name));
    }
    let cli = Cli::parse();
    // `mcp connect` has its own signal handling; the Ctrl+C undo logic is for `run` / `wait`.
    if !matches!(cli.cmd, Cmd::Mcp { .. }) {
        runner::install_ctrlc();
    }
    let code = match cli.cmd {
        Cmd::Run {
            session,
            max_wait,
            cmd,
        } => {
            let session = session
                .or_else(|| std::env::var("SYNC_GATE_SESSION").ok())
                .unwrap_or_else(|| "default".into());
            runner::run(session, max_wait, cmd, true)
        }
        Cmd::Wait { id, max_wait } => runner::wait(id, max_wait),
        Cmd::Status => runner::status(),
        Cmd::Mcp {
            cmd: McpCmd::Connect { server },
        } => {
            sync_gate_shim::exit_on_signal();
            sync_gate_shim::run_process(&server)
        }
        Cmd::Mcp { cmd: McpCmd::List } => sync_gate::mcp::list(),
        Cmd::Mcp { cmd: McpCmd::Serve } => sync_gate::mcp_server::serve(),
        Cmd::Mcp {
            cmd:
                McpCmd::Adopt {
                    agent,
                    dry_run,
                    any_folder,
                    claude_config,
                    codex_config,
                    servers,
                },
        } => adopt::adopt(&adopt::AdoptOptions {
            agent,
            dry_run,
            any_folder,
            claude_config,
            codex_config,
            servers,
            sync_gate_config: None,
            data_dir: None,
        }),
        Cmd::Mcp {
            cmd:
                McpCmd::Restore {
                    agent,
                    claude_config,
                    codex_config,
                    strict,
                    servers,
                },
        } => adopt::restore(&adopt::RestoreOptions {
            agent,
            claude_config,
            codex_config,
            servers,
            strict,
            data_dir: None,
        }),
        Cmd::Shims {
            cmd: ShimsCmd::Install,
        } => sync_gate::shims::cli_install(),
        Cmd::Shims {
            cmd: ShimsCmd::Remove,
        } => sync_gate::shims::cli_remove(),
        Cmd::Paths { check } if check.is_empty() => paths(),
        Cmd::Paths { check } => check_paths(&check),
        Cmd::Hook {
            event: HookEvent::SessionStart,
        } => sync_gate::hook::session_start(),
    };
    std::process::exit(code);
}
