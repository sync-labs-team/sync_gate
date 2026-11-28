<!-- q1: 1 -->
# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |

## Report a vulnerability

Report it in private: on the repository page, open **Security**, then **Report a vulnerability**
(https://github.com/sync-labs-team/sync_gate/security/advisories/new). Do not open a public issue
for a vulnerability. Include the version (`sync_gate --version`), the operating system, what you ran
and what happened.

## What sync_gate trusts

- **The user who runs it.** The daemon and the CLI act for one operating-system account. Anything
  that account can do, sync_gate can do.
- **The pipe or socket**, after it is checked. The daemon serves its own named pipe (Windows) or Unix
  socket, and it refuses a peer that is not that account.
- **Guests, only when you list them.** A sandbox (Codex's, for example) reaches the queue through
  its own narrow pipe, and only if you name it in the configuration. See
  [`docs/sandbox.md`](docs/sandbox.md).
- **Files in its data and config folders, only when owned by you (or SYSTEM, Administrators or
  TrustedInstaller on Windows) and no account outside those can change them.** That covers `config.toml`, the adoption record, the
  shims, the stored commands of queued tickets, the daemon's records and the PostgreSQL cluster
  sync_gate runs. On Windows the owner and the permissions of each file are checked, and a file
  that is a link, or any other reparse point Windows reports, is refused. On
  Linux and macOS the file must be yours, not writable by group or others, and have one link. A
  file another account (root included) owns is refused, so a `config.toml` under `/etc`, or in a
  folder your group can write, is not read. The same holds for a sandbox that runs as another
  account: it never reads your files and uses its own config or the defaults.
- **The installer's files, when it runs.** Before it reads or changes anything, the installer
  checks with the same rule its folder, `bin\`, `launcher.cmd`, `install-state.json` and the
  rollback copies (Windows), and for one that does not exist yet the folder it would be created
  in. It stops if another account can change them or a program has one open for writing.

## Declared limits

- **The update check calls GitHub.** Once every `update_check_days` (default 7), the daemon runs
  `curl` for `releases/latest` of this repository: one anonymous GET over HTTPS, with no
  token, cookie or data of yours. Your DNS resolver sees the name `api.github.com`, and GitHub sees your IP address, the time and
  the `curl` version, in a TLS connection. On failure the daemon does not retry before the next interval. The
  answer is kept only as a plain `X.Y.Z` in `update-check.json` in the data folder. Off with
  `update_check_days = 0` in `config.toml` or `SYNC_GATE_UPDATE_CHECK=0` in the daemon's environment;
  off means no call and the file is removed.
- **Pending command files are readable by other accounts on Windows.** The folder
  `<data>\pending` inherits the permissions of the user profile, and the setup of Codex's sandbox
  gives the group `CodexSandboxUsers` read access to the profile. Those accounts can read the files
  of pending commands (measured with Codex 0.169 in `elevated` mode). Do not put a secret on the
  command line. The shell history keeps it too.
- **How long a pending command stays on disk.** Until it runs, or for up to 25 hours. The daemon
  sweeps every 10 minutes. A guest in `elevated` mode that does not enqueue stays without a time
  limit, and so does an orphan marker.
- **The cost key leaves the machine.** sync_gate keeps a key for each command it queued in
  `cost.json` and shows it in `sync_gate status` and over MCP. That text enters the agent's context,
  and from there it reaches the provider of the agent's model. The key is the program, up to two
  short lowercase words right after it (`cargo test hunter2` enters) and the folder name. A
  credential in a URL, an `X=Y` pair, an option value or a long or upper-case token does not enter.
  Only a queued command gets a key: every command typed after `sync_gate run`, whatever the
  program, a heavy command reached through a shim, and any program with `SYNC_GATE_FORCE_HEAVY=1`.
  A light command reached through a shim gets none. The old history was reset.
- **A refused file is not repaired.** sync_gate reports it and leaves it as it is, and the
  command that needed it stops or uses defaults. Fixing the permissions does not make the
  content trustworthy: another account may already have changed it. What to do depends on the
  file. A stored command (`pending`), `services.json`, `cost.json`, a program or `launcher.cmd` of
  the installer: delete it; sync_gate or the installer writes a new one. The shims: delete the
  shims folder, then run `sync_gate shims install`. `config.toml` and the adoption record: read
  them before you trust them again, then fix their permissions or write new ones. Files that
  record what to undo (`paused.json`, `paused-guests.json`, the installer's
  `install-state.json` and `rollback\`): keep them, check their content, then fix their
  permissions; deleting them gives up resuming the paused processes, or undoing what the
  installer changed. The PostgreSQL cluster: check it, or remove the cluster and let sync_gate
  create a new one.
- **What is checked is the state when it is read.** A program that opened a file for writing
  before its permissions were fixed keeps that access, and Windows cannot take it back: delete the
  file and sign out. Files that Windows or PostgreSQL run or read later (the shims, the cluster)
  are checked when sync_gate puts them on `PATH` or starts the server.
- **The program files and the logon task are checked by the installer only.** Task Scheduler and
  your shell run `launcher.cmd` and the programs before any code of sync_gate does.
- **The installer checks at one instant.** It checks its files once, before it starts, and
  then reads and copies them by path (PowerShell keeps no handle open across the run). In between
  only an account inside the boundary, or a program that opened a file for writing earlier and
  closed it by then, could change one. The check refuses a file open for writing when it runs.
- **An uninstall trusts the installed `sync_gate.exe` to check.** No other copy is at hand, so a
  `sync_gate.exe` another account already replaced is not caught by the uninstall; it would run
  anyway, as it does every time your shell runs `sync_gate`. An install or update checks with the
  downloaded binary, verified against `SHA256SUMS`. A version before 0.1.5 cannot check: the
  installer says so and goes on only when you uninstall it or pin it with `-Version`.
- **A shims folder already on your `PATH`.** The session hook never adds a refused shims folder,
  but it cannot remove one you (or `sync_gate shims install`'s suggestion) put on your user
  `PATH`: Windows keeps running what it finds there. Delete the shims folder, then run
  `sync_gate shims install`.
- **Unsigned binaries.** The release binaries are not code-signed. Check them against `SHA256SUMS`.
  The installer changes only what belongs to the user. The list is in
  [`docs/install.md`](docs/install.md).
