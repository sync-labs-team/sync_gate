# Install guide

The installer never asks for administrator rights and writes only to folders and settings of your
own account. Files come from the GitHub release (on Linux, when there is no ready binary, the installer builds with `cargo install`), over HTTPS, and are checked against `SHA256SUMS`
before anything is changed.

| System | Install or update | Uninstall |
|---|---|---|
| Windows | `irm https://gate.synclabs.team/install.ps1 \| iex` | `& ([scriptblock]::Create((irm https://gate.synclabs.team/install.ps1))) -Uninstall` |
| macOS, Linux | `curl -fsSL https://gate.synclabs.team/install.sh \| sh` | `curl -fsSL https://gate.synclabs.team/install.sh \| sh -s -- --uninstall` |

To skip the domain, use the GitHub addresses of the same files:

- `https://github.com/Sync-Labs-team/sync_gate/releases/latest/download/install.ps1`
- `https://github.com/Sync-Labs-team/sync_gate/releases/latest/download/install.sh`

Pin a version with `-Version 0.1.0` (Windows, in the scriptblock form above) or
`sh -s -- --version 0.1.0` (macOS, Linux). Running the install command again updates.

Windows ARM64 is not part of 0.1.

## What the installer changes

### Windows

| What | Where |
|---|---|
| Programs (`sync_gate.exe`, `sync_gated.exe`, `sync_gate_mcp.exe`) | `%LOCALAPPDATA%\sync_labs\sync_gate\bin` |
| Launcher, state, daemon log | `launcher.cmd`, `install-state.json`, `daemon.log` in `%LOCALAPPDATA%\sync_labs\sync_gate` |
| Daemon | a scheduled task named `sync_gate`, of your own account, started at logon |
| `PATH` | your user `PATH` (`HKCU\Environment`): the shortcuts folder and the programs folder go in front |
| Your own values | user variables in `HKCU\Environment` (see [Own values](#own-values)) |
| PowerShell profiles | a marked block (`# >>> sync_gate >>>` ... `# <<< sync_gate <<<`) at the end of the user profiles of Windows PowerShell and PowerShell 7, only when the execution policy runs profile scripts (`RemoteSigned`, `Unrestricted`, `Bypass`) |
| Data and config | not created by the installer; `sync_gate paths` prints them |

The programs in use are never overwritten: the old one is renamed to `<name>.old-<run-id>`
and deleted on a later run.

### macOS and Linux

| What | Where |
|---|---|
| Programs (`sync_gate`, `sync_gated`, `sync_gate_mcp`) | `~/.local/bin` |
| State | `${XDG_STATE_HOME:-~/.local/state}/sync_gate`: `install-state`, `env`, `rollback/` |
| Daemon, Linux | `systemd --user` unit `~/.config/systemd/user/sync_gated.service` |
| Daemon, macOS | LaunchAgent `~/Library/LaunchAgents/dev.sync_labs.sync_gated.plist` |
| `PATH` | the file `env` puts the shortcuts folder and the programs folder in front |
| Shell files | a marked block (`# >>> sync_gate >>>` ... `# <<< sync_gate <<<`) at the end of `~/.profile` and `~/.bashrc`, plus `~/.bash_profile` if it exists, plus `~/.zprofile` and `~/.zshrc` on macOS or when `zsh` is installed |

The daemon is only started by the service manager, never by the installer itself. In both
installers, a file of yours is edited only inside the marked block, at its end; the rest stays
byte for byte as it was.

Install and uninstall are serialized per home directory with the lock file `~/.sync_gate-install.lock`.
The installer needs `flock` or Perl with `flock` support to acquire it. The file stays in place between
runs. The operating system releases the lock once the installer and its active commands exit.

A Linux machine with no prebuilt file for its architecture builds the release with `cargo`
(it needs Rust); the installer says so before it starts.

## Update

Run the install command again. Your own values (below) are kept. The installer stops the daemon,
swaps the programs, refreshes the shortcuts, starts the daemon and waits for `sync_gate status` to
answer in a new environment. Only then it discards the saved previous state.

## Uninstall

Run the uninstall command. It begins with `sync_gate mcp restore --strict`, which gives back every
MCP server you adopted, and then searches the Claude Code and Codex configs for the path of the
installed programs. **If any reference is left (adopted or written by hand), it removes nothing**
and lists the files and lines: a config that points to a program that is gone would break the
agent. Remove those lines, or run `sync_gate mcp restore`, and run the uninstall again.

It then stops the daemon, removes the shortcuts, undoes what it added (the `PATH` entries, user
variables, profile or shell-file blocks, the task, the unit or the plist) and deletes the programs.
Only the entries this installation added are removed; the same text that was already there before
stays. Your configuration and data folders are kept: the installer says where. The agent plugin is
not removed; do it with `claude plugin uninstall sync-gate@sync_gate` and
`codex plugin remove sync-gate@sync_gate`.

## Recover

Every change has an undo, and the previous state is kept in a `rollback` folder (Windows:
`%LOCALAPPDATA%\sync_labs\sync_gate\rollback`; macOS and Linux: `rollback` inside the state folder)
until the new daemon answers.

- A run that failed undoes itself and prints `previous version restored`.
- A run that was cut off (closed window, power loss) is undone by the next run, before anything
  else: it prints `a previous run stopped at <step>; restoring it first`. Run the install or the
  uninstall command again.
- If the message says `could not restore ...; files kept in <rollback folder>`, something could
  not be put back (a file in use or a replaced program, for example). On Windows, a binary
  conflict during uninstall recovery blocks shim recreation and scheduled task startup.
  Close the program it names and run the command again. If it fails again, the folder holds
  the old programs, the old launcher, unit or plist,
  the old `PATH` text and the old profile or shell files: copy back by hand what is missing, then
  run the install command. Report it at https://github.com/Sync-Labs-team/sync_gate/issues without
  pasting paths of your machine.

## Own values

Four values can be set before the install command. The installer stores them and keeps them on
updates, so you set them once.

| Variable | Meaning |
|---|---|
| `SYNC_GATE_INSTALL_DIR` | install folder (Windows: the folder that holds `bin`; macOS and Linux: the programs folder) |
| `SYNC_GATE_DATA_DIR` | data folder of the daemon |
| `SYNC_GATE_SOCKET` | name of the pipe or path of the socket |
| `SYNC_GATE_CONFIG` | path of `config.toml` |

On Windows they are written as user variables, so every program of your account sees them. On
macOS and Linux they go into the `env` file, the unit or the plist. A value that changes between
runs prints `override changed: <NAME>`.

To forget them, run the install command with `-ClearOverrides` (Windows, scriptblock form) or
`--clear-overrides` (macOS, Linux). Programs already installed in a custom `SYNC_GATE_INSTALL_DIR`
are not moved or removed.

**Folders.** A folder that goes on the `PATH` cannot contain `;` (Windows) or `:` (macOS, Linux):
the installer refuses and changes nothing. On Windows it also refuses `%` when your `PATH` is an
expanding value. On Linux, `systemd` refuses `'`, `"` and `\` in the path of the program, and the installer refuses `$`, `%` and `\` in a value of your own that goes into the unit: set
`SYNC_GATE_INSTALL_DIR` to another folder.

**If you use sandbox guests.** On Windows, `SYNC_GATE_DATA_DIR` and `SYNC_GATE_SOCKET` as user
variables reach every process of your account, including the `elevated` guest of Codex's sandbox.
The `sync_gate` command gives `SYNC_GATE_DATA_DIR` priority over the guest's own folder, so the guest would try
to write its pending commands in your data folder, where it can only read. Whoever uses guests
([sandbox.md](sandbox.md)) should not set a `SYNC_GATE_DATA_DIR` of their own.

## For testing

Used by the installer's own tests, never needed in daily use. They point the installer at
throwaway names, so a test cannot touch your real setup.

- Windows: `SYNC_GATE_TASK_NAME`, `SYNC_GATE_ENV_KEY`, `SYNC_GATE_PROFILE_PATHS`,
  `SYNC_GATE_CLAUDE_CONFIG`, `SYNC_GATE_CODEX_CONFIG`, `SYNC_GATE_TEST_POLICY`,
  `SYNC_GATE_INSTALL_FROM`, `SYNC_GATE_INSTALL_FAIL_AT`, `SYNC_GATE_INSTALL_NO_MAIN`.
- macOS and Linux: `SYNC_GATE_SERVICE_NAME`, `SYNC_GATE_CLAUDE_CONFIG`, `SYNC_GATE_CODEX_CONFIG`,
  `SYNC_GATE_INSTALL_FROM`, `SYNC_GATE_INSTALL_FAIL_AT`.

## Install by hand

1. Download the archive for your system from the
   [release](https://github.com/Sync-Labs-team/sync_gate/releases) and check it against
   `SHA256SUMS`.
2. Put `sync_gate`, `sync_gated` and `sync_gate_mcp` in one folder and add it to your `PATH`.
3. Run `sync_gate shims install`. It creates the shortcuts folder and prints it; put that folder
   in front of the folder with the programs on your `PATH`.
4. Start `sync_gated` under your service manager (a scheduled task at logon, a `systemd --user`
   unit or a LaunchAgent). Starting it from a shell works for a try, but a daemon started that way
   is not seen by Codex's sandbox.

## Where things are

`sync_gate paths` prints the real folders, one `name=value` per line: `config`, `data`, `shims`,
`adopted`, `socket` and `hub`.

The daemon log: on Windows, `daemon.log` in the install folder; on macOS,
`~/Library/Logs/sync_gate/daemon.log`; on Linux, `journalctl --user -u sync_gated`.

## Limits

- **Windows `PATH` order.** The machine `PATH` comes before the user `PATH`. A program installed
  for all users (Node.js and Go, for example) is found before the shortcuts, so it goes through
  the queue only in PowerShell with the profile block, which puts the shortcuts first. Elsewhere,
  wrap the command: `sync_gate run -- <command>`.
- **`cmd.exe` has no shortcuts.** Use `sync_gate run -- <command>`.
- **No profile with a restrictive policy.** If the execution policy does not run profile scripts,
  the installer does not create the profile block.
- **`.ps1` programs.** The shortcut folder does not hide what exists only as a `.ps1` at the time
  of `sync_gate shims install`. One that appears later exits 127 with an instruction until the
  next `sync_gate shims install`.
- **`fish` and macOS graphical apps** get no shortcuts.
- **WSL and containers** without `systemd --user` do not start the daemon by themselves; the
  installer starts nothing there and says how to start `sync_gated`.
- **Windows ARM64** is not part of 0.1.

## TLS on older Windows PowerShell

If `irm` fails with an error about the secure channel, ask for TLS 1.2 first:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
irm https://gate.synclabs.team/install.ps1 | iex
```

Older builds of Windows 10 were not verified.
