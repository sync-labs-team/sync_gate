# sync_gate

English | [Português](README.pt-BR.md) | [Español](README.es.md)

The gatekeeper of your machine: heavy commands of several coding agents wait their turn, so the memory does not run out.

![Memory with and without sync_gate](docs/benchmark.svg)

<!-- bench -->
proxy: heavy commands of 4 agents + 10 MCP sessions; agent processes not included

Candidate d503b62, crates tree 7a3d4ce1ca80.
median of 3 runs, range in parentheses (minimum-maximum).

| Measure | Without sync_gate | With sync_gate |
| --- | --- | --- |
| Jobs lost to memory (confirmed) | 0 (0-0) | 0 (0-0) |
| Jobs lost, memory suspected or unexplained | 0 (0-0) | 0 (0-0) |
| Jobs completed | 4 (4-4) | 4 (4-4) |
| Peak RAM | 98% (93%-99%) | 90% (88%-90%) |
| Paging file growth | 4957 MB (3750 MB-5037 MB) | 2549 MB (2521 MB-3039 MB) |
| MCP processes | 40 (40-40) | 4 (4-4) |
| MCP memory | 2323 MB (2295 MB-2366 MB) | 233 MB (232 MB-236 MB) |
| sync_gate daemon memory | - | 12 MB (12 MB-13 MB) |
| Total time | 1m16s (1m15s-1m18s) | 1m50s (1m35s-2m05s) |
| Cost per command | 13 ms (12 ms-13 ms) | 132 ms (129 ms-132 ms) |
| Complete phases | 3 of 3 | 3 of 3 |
<!-- /bench -->

Windows 11, 16 GB RAM, 8 cores (16 logical CPUs), Docker Engine 27.5.1 via the Docker API. All six phases used the same signed, read-only local APT mirror and the same synthetic localhost configuration for the second Next.js build. Docker ran APT offline and installed packages in every phase with `--no-cache`. The timings exclude the earlier Internet downloads for APT. BuildKit could reuse context blobs. Other agent sessions open; their RAM was not excluded. No agents launched. Installed daemon active; guard clean. Daemon memory refers to the isolated benchmark daemon. MB = MiB.

<!-- s:install -->
## Install

Windows (PowerShell):

```powershell
irm https://gate.synclabs.team/install.ps1 | iex
```

macOS and Linux:

```sh
curl -fsSL https://gate.synclabs.team/install.sh | sh
```

No administrator rights. It only writes to your folders. Update, uninstall and recovery: [docs/install.md](docs/install.md).

<!-- s:highlights -->
## Highlights

- Builds, tests, installs and `docker build` wait in a queue until memory allows. Light commands never wait. Exit code 75 means "still queued": `sync_gate wait N` runs it with your shell's environment, not the queuing one's.
- A shared MCP server you adopted runs up to 3 instances for all your sessions, not one per session.
- Each command of a declared project can get its own PostgreSQL database, dropped when the command ends: [docs/postgres.md](docs/postgres.md).
- Codex's sandbox uses your queue only if you list it in `guests`: [docs/sandbox.md](docs/sandbox.md).
- A proxy benchmark, with how to run it: [docs/benchmark.md](docs/benchmark.md).

<!-- s:quickstart -->
## Quickstart

```sh
claude plugin marketplace add sync-labs-team/sync_gate
claude plugin install sync-gate@sync_gate
sync_gate mcp adopt
```

`sync_gate mcp adopt` lists your MCP servers. Adopting is by name (`sync_gate mcp adopt <name>`); nothing is adopted.

<!-- s:agents -->
## Agents

| Agent | What it gets |
|---|---|
| Claude Code | plugin with a session hook, a skill and the MCP server |
| Codex | plugin with context at `SessionStart`, a skill and the MCP server |
| Others | shortcuts on the `PATH`, `sync_gate run -- <command>`, `sync_gate mcp serve` |

<!-- s:limits -->
## Limits

- On Windows, the files of pending commands can be read by the accounts of Codex's sandbox group. A pending command stays on disk until it runs, or for up to 25 hours. A guest in `elevated` mode that does not enqueue stays with no time limit, and so does an orphan marker. Do not put a secret on a command line. More in [SECURITY.md](SECURITY.md).
- The cost key (program, up to two short words, folder name) appears in `sync_gate status`, so it enters the agent's context and reaches the provider of the agent's model.
- Sandbox commands join the queue only after the account is in `guests`; before that they run directly.
- On Windows, the shortcut does not hide a program that exists only as a `.ps1` when you run `sync_gate shims install`. If one appears later, it exits 127 with an instruction until the next install.

<!-- s:docs -->
## Documentation

- [Install guide](docs/install.md)
- [Codex sandbox](docs/sandbox.md)
- [Shared PostgreSQL](docs/postgres.md)
- [Benchmark](docs/benchmark.md)
- [Security policy](SECURITY.md)

<!-- s:license -->
## License

MIT or Apache-2.0, at your option: [LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE).
