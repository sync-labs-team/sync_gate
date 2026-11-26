# sync_gate plugin

sync_gate for Claude Code and Codex: a SessionStart hook
(`sync_gate hook session-start`), the `sync_gate` skill and the `sync_gate mcp serve` MCP server.
Needs the `sync_gate` binary on the `PATH`; install the queue shims with `sync_gate shims install`.

## Claude Code

```
claude plugin marketplace add Sync-Labs-team/sync_gate
claude plugin install sync-gate@sync_gate
```

## Codex

```
codex plugin marketplace add Sync-Labs-team/sync_gate
codex plugin add sync-gate@sync_gate
```

Then open Codex once and trust the hook in `/hooks`.
