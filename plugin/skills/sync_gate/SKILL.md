---
name: sync_gate
description: Use when running builds, tests, installs or docker build (npm, pnpm, cargo, pytest, make...), when a command prints "queued: ticket", or when a command exits with code 75. Explains the sync_gate queue and how to resume.
---

# sync_gate

sync_gate queues heavy commands (builds, tests, installs, `docker build`) so several
agents on one machine do not exhaust its memory. Heavy commands go through the queue
automatically, through shims on the `PATH`. Light commands (`ls`, `git status`) never wait.

## Exit codes

- **75**: still queued after the maximum wait. The command did NOT run. The output has
  `queued: ticket N`. Resume with `sync_gate wait N`: it
  takes the slot AND runs the stored command, so never run the original command again. The stored
  command runs with the environment of the shell that calls it, not the one it was first run in:
  call `wait` from a shell that has the same variables. If
  `wait` exits 75 again, resume with the ticket it prints. The stored command is deleted 25 h
  after it was saved or its last `sync_gate wait` began, unless a wait on it is in progress;
  after that, `wait N` exits 2 with `sync_gate: ticket N expired or is gone` and nothing runs:
  run the original command again (unless an earlier `sync_gate wait N` of yours already ran it).
- **126**: the program could not be started (on Windows, for example, a `.cmd` or `.bat`
  given an argument that contains a line break). Nothing ran; use the tool's own executable.
- **127**: the program was not found (on Windows this includes a tool that exists only as a
  `.ps1`: sync_gate never forwards a `.ps1`).
- **130**: interrupted (Ctrl+C); the ticket is released.

## What to do

- Check the queue: `sync_gate status`, or the `sync_gate_status` MCP tool.
- Waiting for a ticket: `sync_gate wait N` (it runs the stored command). Do not poll in a
  loop and do not start the command again, before or after.
- Never work around the queue: no absolute path to the real binary, no editing `PATH`,
  no killing the processes of other agents, no running the same build twice.
- Where the shims are not on the `PATH` (the Claude `PowerShell` tool, a shell without
  the session hook), wrap the command: `sync_gate run -- <cmd>`. PowerShell limits: the wrapper does not
  forward a program that exists only as a `.ps1` (exit 127), and a `.cmd`/`.bat` cannot take
  an argument with a line break (exit 126).
- When the daemon is unreachable or refuses, the command runs directly and prints a warning.
  That is expected, not an error. On Windows inside the Codex sandbox the queue works only when
  the owner lists that sandbox in `guests` (see docs/sandbox.md); otherwise the command runs
  directly and one line says so. In the `mxc` and `unelevated` modes a command that waited too
  long exits 75 and nothing is kept: there is no `sync_gate wait`, so run the same command again.
- Shims are installed once with `sync_gate shims install`.
