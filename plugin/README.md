# sync_gate plugin

sync_gate for Claude Code and Codex: a SessionStart hook
(`sync_gate hook session-start`), the `sync_gate` skill and the `sync_gate mcp serve` MCP server.
Needs the `sync_gate` binary on the `PATH`; install the queue shims with `sync_gate shims install`.

## Claude Code

```
claude plugin marketplace add sync-labs-team/plugins
claude plugin install sync-gate@sync-labs
```

## Codex

```
codex plugin marketplace add sync-labs-team/plugins
codex plugin add sync-gate@sync-labs
```

Then open Codex once and trust the hook in `/hooks`.
