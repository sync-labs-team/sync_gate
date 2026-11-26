# Benchmark: the proof scenario

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

## Published run

Windows 11, 16 GB RAM, 8 cores (16 logical CPUs), Docker Engine 27.5.1 via the Docker API.

All six Docker builds used the same signed APT mirror, mounted read-only. APT ran with networking
disabled. `--no-cache` forced the package installations to run in every phase. The Docker lane
includes local context handling, package installation and image export. The APT packages were
downloaded from the Internet before the timed runs. BuildKit could reuse context blobs across
builds. The second Next.js build used the same synthetic localhost configuration in all six phases.

The run was done with other agent sessions open and the sync_gate daemon active (no pause), with the
contamination guard on (`contaminated: false`), on the same base image as the previous round.
The daemon memory row is the benchmark's own isolated daemon, not the one installed on the machine.
MB in the tables means MiB (2^20 bytes).

`cargo xtask bench` runs the same heavy work twice on one machine, once without sync_gate and once
with it, and reports what each run cost.

**What it is.** A proxy: `proxy: heavy commands of 4 agents + 10 MCP sessions; agent processes not
included`. It runs the heavy commands four coding agents would run at the same time (two Next.js
builds, a release build of this repository, a `docker build --no-cache`) next to 10 idle MCP
sessions. The label "agent processes not included" means the benchmark launches no agent
processes. Other agent sessions were open during the published run; their memory was not isolated
from the system-wide RAM measurements.

## How to run it

1. Build the three binaries of the candidate commit and put them in one folder: `sync_gate`,
   `sync_gated` and `sync_gate_mcp` (the binary of the `sync_gate_shim` package).
2. `cargo xtask bench setup --work <folder> --rev <sha>`. Needs a clean working tree and the
   commit in this repository. It clones the repository at `<sha>`, clones each outside project at
   the commit fixed in `tools/bench/workloads.toml`, and runs their preparation once (install,
   `cargo fetch`, base image). It is the main step that uses the network,
   not the only one: `npx -y` fetches the MCP server on first use and the image build can download
   packages, and `setup` does not warm either (a cold cache slows the first phase).
3. Close everything you can. The phase without sync_gate is meant to push the machine to its limit
   and can freeze it or kill processes. `cargo xtask bench run --work <folder> --bin <bin folder>
   --phase both --repeat 3 --out result.json`: 3 pairs, each one a `without` phase and then a
   `with` phase. A pair takes up to an hour per phase (`--phase-deadline`, in seconds).
4. `cargo xtask bench report result.json --svg docs/benchmark.svg` prints the table in Markdown and
   writes the chart.

`tools/bench/smoke.toml` is a short version of the same machinery (two light lanes, sync_gate's
own MCP server, under 3 minutes): `bench setup ... --workloads tools/bench/smoke.toml`. It checks
the orchestration, not the heavy work.

## What keeps it fair

- Both phases start from the same state: build outputs erased, `docker build --no-cache`, the base
  image already pulled, memory settled (3 samples within 2%, at most 120 s).
- Every child runs in a controlled environment: no inherited `SYNC_GATE_*` variable, no folder with
  a shim manifest on `PATH`, programs resolved to absolute paths (a program that resolves to a
  sync_gate binary stops the run). In the phase without sync_gate the socket name points at nobody,
  so a shortcut that escaped would fail open instead of reaching your real daemon.
- The phase with sync_gate uses its own daemon: its own socket, data folder and config in the work
  folder, with the MCP server in `[mcp]` as `shared`. The 10 sessions are `sync_gate mcp connect`.
  The four lanes run as `SYNC_GATE_FORCE_HEAVY=1 sync_gate run --session <lane> ...`.
- Your real daemon (pid and start time), the `pending` folder and the hashes of `cost.json`,
  `services.json` and `mcp-adopted.json` are photographed at `setup` and compared at the end of
  `run`. Any difference sets `contaminated: true`, and `report` refuses that file.
- A lane that exits 75 (still queued) is resumed with `sync_gate wait N` until it ends or the phase
  deadline passes. Only a lane that exits 0 **and** shows its proof (`done` in the workloads file:
  a file newer than the start of the lane, or a command that exits 0) counts as completed.

## What each number means

| Row | Meaning |
| --- | --- |
| Jobs lost to memory (confirmed) | Lanes whose error output shows memory ran out **and** the system confirms it in the lane's time window (Windows: event 2004 of the Resource-Exhaustion-Detector; Linux: `Out of memory: Killed process <pid>` for a process of the lane's tree). Target: zero. |
| Jobs lost, memory suspected or unexplained | Only one of the two signs, or killed with no sign at all. "JavaScript heap out of memory" counts as a sign and never as confirmation: it is the V8 limit, not the machine's. |
| Jobs completed | Lanes that finished with their proof. Target: all four. |
| Peak RAM | Highest share of RAM in use in a sample (every 500 ms) during the phase. |
| Paging file growth | Peak minus the start of the swap or paging file in use. |
| MCP processes | Peak number of MCP server processes started by the 10 sessions (without) or by the daemon (with); a process that already existed does not count. It counts every process of the tree (`cmd`, `npx`, `node`), not servers: with `npx` expect 3-4 per server, never read it as "1 per server". |
| MCP memory | Peak working set of those processes. |
| sync_gate daemon memory | Peak working set of the benchmark's daemon. |
| Total time | From the start of the four lanes to the end of the last one, queue included. |
| Cost per command | Median of 20 runs of a trivial command directly, against 20 through `sync_gate run --` (asks the daemon for a slot), on an idle daemon. |
| Complete phases | A phase is complete when all 10 sessions came up and no lane ended `failed`, `killed_unexplained`, `spawn_failed` or `queued_timeout`. A lane that hit its time limit or stayed queued (exit 75) counts as `queued_timeout`. |

With one pair the report says "single run, no repeatability measured". With three or more, each
number is the median and the range is minimum-maximum.

## Fields of the JSON that qualify the result

- `complete`: false when any phase is incomplete (rule above) or the run stopped early;
  `incomplete_reason` says why. The JSON is saved after every phase (with `complete: false` until
  the end), so a crash keeps what was measured. It is written to `<file>.tmp` and renamed, so a
  kill mid-write leaves the previous file intact.
- `ram_start_pct` (per phase): share of RAM in use when the phase began, after waiting for the
  machine to settle. `settle_timeout`: the machine did not settle in time; `suspect` (top level)
  is true when any phase has it. `report` prints a WARNING for incomplete or suspect results.
- `knobs`: the test knobs of the queue and of the isolated daemon the run used, so a result
  made with non-default knobs is recognizable.
- Lane state `spawn_failed`: the command could not be started (distinct from a kill).

## Identity of what was measured

The JSON holds `candidate` (the commit), `crates_tree` (`git rev-parse <sha>:crates`) and the blob
hashes of `Cargo.toml` and `Cargo.lock`. A repository published from another commit can still cite
the result when `v0.1.0:crates`, `Cargo.toml` and `Cargo.lock` give the same hashes. The JSON has
no absolute path, machine name or user name (`run` and `report` refuse to write one).

## Limits

- It is a proxy: no agent runs, only the heavy commands of agents.
- macOS has no confirmation source, so nothing is ever `oom_confirmed` there.
- On Windows the event 2004 lists processes by name and ID, but the benchmark matches it by time
  window only: a 2004 caused by another program in the lane's window counts.
- Lanes that run longer than the phase deadline are not killed; the deadline only bounds the wait
  in the queue.
- Pressing Ctrl+C can leave the isolated daemon and the lanes' processes running; they are the
  ones with `sync_gate-bench-<pid>` in their environment.
- The numbers are one machine and one day. Compare them with a run of your own.
