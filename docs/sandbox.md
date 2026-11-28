# Using the queue from Codex's sandbox

Codex runs commands in a sandbox. By default the sandboxed `sync_gate` cannot reach your daemon, so
its commands run directly and print one line saying why. You can let a sandbox use your queue
through a narrow pipe of its own. Nothing is open unless you list it.

## Windows

In the sync_gate configuration file (`SYNC_GATE_CONFIG`, or `config.toml` in the per-user
sync_gate configuration folder), then restart `sync_gated`:

```toml
guests = ["CodexSandboxOffline", "@restricted", "@appcontainer"]
```

Up to 8 entries. Each entry is one kind of sandbox:

| Entry | Codex mode (`windows.sandbox`) | Who runs the command |
|---|---|---|
| a local account name, such as `CodexSandboxOffline` | `elevated` | another local account (a name with letters, digits, `_`, `.`, `-`) |
| `@restricted` | `unelevated` | your own account with a write-restricted token |
| `@appcontainer` | `mxc` | your own account inside an AppContainer |

Only local accounts count; a domain account or an unknown name is ignored.

A guest gets its own pipe next to yours (`<name>-guest-<account>`, `<name>-sbx-restricted`,
`<name>-sbx-appcontainer`). Your pipe, its name and its access list do not change. The guest's
pipe lets a client read and write and nothing else (no create, no change of permissions), and the
daemon reads the identity of the caller from each message, never from a process id.

What a guest can do:

- ask for a slot for its own command, wait for it and report that it finished (at most 8 commands
  at a time per guest);
- see the machine's memory and its own tickets in `sync_gate status`;
- be paused while it runs, like your own jobs, but only the processes that have the same identity
  as the job (never one of yours that a sandboxed process happens to be the parent of).

What it cannot do: see or touch your tickets or your commands, ask for a database lease, report
a process that is not its own, or teach the cost model (a guest's command is always costed as an
unknown heavy command).

`@restricted` covers every process of yours with a restricted token in the same logon session, and
`@appcontainer` every AppContainer of yours with the `registryRead` capability. Each identity only
asks for a slot, sees and is paused on what is its own: every `mxc` run is its own identity, and
`unelevated` runs from the same folder are one.

In the `mxc` and `unelevated` modes sync_gate deliberately keeps the ticket in the daemon's
process and stores no pending command for the sandbox. A command that waited longer than
`--max-wait` therefore exits with 75 and gives its ticket back. There is no `sync_gate wait` for
it: **run the command again**. The `elevated` mode keeps the pending command in the guest's own
profile and `sync_gate wait N` works as usual. Your daemon cannot read that profile, so it never
expires those files: the sandbox deletes its own stored commands older than 25 h each time it
queues another command. **If the sandbox never queues anything again, they stay without a time
limit** (see "What sync_gate keeps on disk" below).

If the account is not listed, the sandboxed `sync_gate` prints
`this account may not use the owner's sync_gate queue` once and runs the command directly.

### Declared limits

- If the daemon crashes in the middle of a guest's pause, recovery may resume one of that guest's
  own threads once more than needed (at-least-once replay). It only ever touches that guest's own
  processes, never yours.
- After a crash with a guest paused, an older `sync_gated` (one built before this feature) keeps
  `paused-guests.json` but cannot resume it: the guest's processes stay frozen until a newer
  `sync_gated` starts, because recovery runs at its start. If that happens, start the current
  `sync_gated`; it resumes them and removes the file.
- A guest client that takes more than 10 s to send its request or to read the reply is dropped
  and its command runs directly.
- To save time, a sync_gate command checks the daemon once and then trusts the same daemon process
  for the rest of that command. The check assumes that no full-token process of yours hands its end
  of the daemon's pipe to a sandboxed process; with the cache, that assumption covers the whole
  command instead of each connection.
- On the machine this was developed on, the `@restricted` and `@appcontainer` entries are off.
- A guest reads a `config.toml` only from a folder and file its own account owns that nobody else
  can change. `unelevated` (`@restricted`) is your own account, so it reads yours. An `elevated`
  account reads its own config (in its own profile), never yours. `mxc` runs inside an
  AppContainer: a standard install grants it nothing it could read and that the sandbox could not
  also change, so it runs with the defaults and prints `ignoring the config`.

## What sync_gate keeps on disk

`<data>` is the per-user sync_gate data folder (Windows: `%APPDATA%\sync_labs\sync_gate\data`).
On Windows, the `elevated` sandbox accounts (`CodexSandboxUsers`) can read the files under your
`AppData` and next to your agents' configs through permissions Codex sets on your profile. On
Unix the files sync_gate writes in `<data>` are readable only by you (and root): mode 0600 in a
0700 folder. The `adopt` backups and temporary files keep the permissions of the agent config they
copy (a Codex `config.toml` is often 0644, readable by every local user), and `CLAUDE_ENV_FILE`'s
permissions are Claude Code's, not sync_gate's.

| What | What it holds | When it goes | How to delete it by hand |
|---|---|---|---|
| `<data>/pending/<id>.json`, the stored command of a queued ticket | the command's arguments, its folder and the session name; never the environment | `sync_gated` deletes it on its first sweep (every 10 min, and at start) after 25 h since it was saved or its last `sync_gate wait` began, unless a wait on it is in progress: at most 25 h 10 min with this version. Daemon stopped: at its next start. Kept: a file dated in the future (wrong clock) until the clock reaches it | delete the file; `sync_gate wait <id>` then exits 2 with `sync_gate: ticket <id> expired or is gone` and runs nothing: run the original command again |
| the same, in the `elevated` sandbox's own profile | the sandbox's own commands | only when that sandbox queues another command and the file is 25 h old; **no time limit** if it never does | as that account, or as an administrator |
| `<data>/pending/<id>.claim`, `<id>.claim.reclaim` | a process id, or nothing | removed by the claim, renewal or expiry that made it. One left by a live process, an empty one, or an orphan `.claim.reclaim` keeps `<id>.json` until removed: `sync_gate wait` prints their paths | delete them when no `sync_gate` is running |
| `<data>/cost.json` | the learned cost model: one key per queued command (heavy, or typed after `sync_gate run`), `<program> <up to two subcommand words> @ <folder>` | never pruned; reset once when the key format changed | delete it (estimates start over) |
| `sync_gate status` and the MCP tool `sync_gate_status` | the same keys, for running and queued jobs | the text goes into the agent's context and from there to the model provider | — |
| `<data>/cost.json.bad` | the keys of a `cost.json` that could not be read | never | delete it |
| `<data>/mcp-adopted.json` | `command` and `args` of each MCP server adopted by `sync_gate mcp adopt` | `sync_gate mcp restore <name>` removes its entry | `restore`, or delete the file after restoring everything |
| `[mcp.<name>]` tables in sync_gate's `config.toml` | `command`, `args`, names of environment variables (`env_from`) and a literal `cwd` | never: `restore` does not remove them | edit `config.toml` |
| `<agent config>.sync_gate-<seconds>-<pid>.bak`, next to `.claude.json` or Codex's `config.toml` | a full copy of the agent's config, **including literal `env` values** of every server | never | delete them once the adoption works; `adopt` prints each path |
| `<agent config>.sync_gate-tmp-<pid>-<n>` | the new config text, while `adopt` writes it | on error; left only if the process dies mid-write | delete it |
| `<name>.tmp-<pid>-<n>` in `<data>` | a copy of `cost.json` or of a pause record while it is written | on error; left only if the daemon dies mid-write | delete it |
| `CLAUDE_ENV_FILE` (Claude Code's `session-env` folder) | the `PATH` the session hook saw and `SYNC_GATE_SESSION` | when Claude Code deletes it (not ruled by sync_gate; observed: weeks) | delete old session folders |

The cost key keeps only words shaped like a subcommand (1 to 24 characters of `a-z`, `0-9`, `.`,
`_`, `-`, starting with a letter) from the start of the arguments, and stops at the first other
word, so an option, a `KEY=value`, a URL, a path or a long or upper-case token never enters it.
Up to two short lower-case words right after the program still do (`vitest hunter2`,
`cargo test hunter2`), and any command typed after `sync_gate run` (or run with `SYNC_GATE_FORCE_HEAVY=1`) gets a
key: a key exists only for a command sync_gate queued. The key also holds two names that can be personal: the program
name (the file name of the command's first word, whatever it is) and a folder name (the
repository's root folder, or the current folder outside a repository: a command run in your home
folder gives `... @ <your user name>`). Backups of these files (roaming profile, Time Machine, other
backup tools) do not expire with them.

## macOS and Linux

Nothing to list. The sandbox shares your user, but it may not be able to reach the daemon's socket:

- macOS: Unix sockets are denied by default; set `network.allow_unix_sockets` in Codex's
  configuration to allow the daemon's socket.
- Linux: with the network off the sandbox cannot `connect` to a local socket, so the queue is not
  reachable there.

In both cases the command runs directly and sync_gate prints one line saying so. These two were read
in Codex's source, not measured.

## Proof

`crates/sync_gate/tests/xuser_windows.rs` and `crates/sync_gate_probe/tests/xuser_pause_windows.rs`
drive the real `codex sandbox` in the three
modes. They are `#[ignore]` and run only on request:

```
set SYNC_GATE_TEST_CODEX_SANDBOX=1
cargo test -p sync_gate --test xuser_windows --locked -- --ignored --test-threads=1 --nocapture
cargo test -p sync_gate_probe --test xuser_pause_windows --locked -- --ignored --test-threads=1 --nocapture
```

Declared limit: start `sync_gated` from the scheduled task (how the installer runs it), PowerShell
or cmd. A daemon started from an MSYS/Git Bash shell has no ACE for the owner's logon SID in its
process permissions, so the `elevated` sandbox (a restricted token) cannot verify it: elevated
guests run their commands directly, and sync_gate prints one line saying so. It never trusts a
daemon it cannot verify. The `elevated` tests check this first and fail, with that explanation,
when run from an MSYS/Git Bash shell: run them from PowerShell or cmd.

The `elevated` and `unelevated` setups of Codex re-apply permissions on your profile and add the
test folder to Codex's list of writable folders (once, for the fixed folder
`%TEMP%\trabalho\sync_gate\xw`). The tests change no permission themselves.
