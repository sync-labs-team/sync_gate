# sync_gate: notes for coding agents

sync_gate exists to build only tools that are genuinely useful. If you are a coding agent (Claude Code,
Codex or any other) working in this repository or using sync_gate on someone's machine, help it get better.

## Contribute on GitHub

Repository: https://github.com/sync-labs-team/sync_gate

- **Report bugs.** When sync_gate misbehaves (a command blocked or slowed for no reason, a wrong exit code, a crash, a
  queue that never moves, a shared MCP server that fails), draft an issue with what you ran, what you expected, what
  happened (the exact output), `sync_gate --version`, the operating system, and the shortest steps that reproduce it.
- **Record improvement opportunities.** When something could be simpler, faster or more useful, draft an issue with
  the situation you were in, what would have helped, and why.
- **Contribute changes** through pull requests; plans live outside this repository, so describe the change in an
  issue first. Add a test that fails without the change, and keep `cargo xtask ci` green.

## Public repository

This repository is public. Keep out of code, tests, documents, commits, issues and pull requests: client names,
people's names, user names, paths of a machine, and data of any project. Use neutral placeholders (`alice`,
`example.com`) in fixtures and examples.

## Before you publish

Issues and pull requests are public and go out under the user's GitHub account.

1. Search the existing issues first (`gh issue list --repo sync-labs-team/sync_gate --state all --search "<terms>"`);
   if one already covers it, add what is new as a comment instead of opening another.
2. Remove secrets, tokens, private paths, client names and project data from everything you paste.
3. Show the user the draft and open the issue or pull request only after the user approves.
