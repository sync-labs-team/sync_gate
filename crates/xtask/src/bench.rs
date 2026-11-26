//! `cargo xtask bench`: the proof scenario (heavy commands of 4 agents plus 10 idle MCP sessions)
//! run without and with sync_gate, on this machine, and turned into a table and a chart.
//!
//! Every child runs in a controlled environment (see [`controlled_env`]): no inherited
//! `SYNC_GATE_*`, no shim folder on `PATH`, and a socket name that is either the isolated daemon of
//! the benchmark or one nobody serves. The user's own daemon, data folder and agent configs are
//! never touched; `setup` and `run` photograph them (see [`RealSnapshot`]) and flag any change.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Mutex, mpsc};
use std::time::{Duration, Instant, SystemTime};
use sync_gate_core::{SHIMS_MANIFEST, find_program};
use sysinfo::{MemoryRefreshKind, Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

pub const LABEL: &str =
    "proxy: heavy commands of 4 agents + 10 MCP sessions; agent processes not included";
const SESSIONS: usize = 10;
const OVERHEAD_RUNS: usize = 20;
const STATE_FILE: &str = "bench-state.json";
const WORKLOADS_COPY: &str = "workloads.toml";
const DEFAULT_WORKLOADS: &str = "tools/bench/workloads.toml";
const SAMPLE_EVERY: Duration = Duration::from_millis(500);
const DEFAULT_PHASE_DEADLINE: u64 = 3600;
const BENCH_MCP: &str = "bench";
const INITIALIZE: &str = concat!(
    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","#,
    r#""capabilities":{},"clientInfo":{"name":"sync_gate-bench","version":"0"}}}"#,
    "\n",
    r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    "\n"
);

// ---------------------------------------------------------------------------------------------
// Pure parts (tested without running anything)
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workloads {
    pub server: Server,
    pub lane: Vec<Lane>,
}

/// The MCP server the 10 sessions start. `{bin}` is the folder with the sync_gate binaries.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Server {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
}

/// One of the four parallel tracks. Without `repo` it runs in the clone of the candidate.
/// Placeholders in `command`, `env`, `clean`, `clean_commands` and `done`: `{dir}` (the lane's
/// folder), `{target}` (a build folder of its own), `{bin}`, `{exe}` (`.exe` on Windows).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lane {
    pub name: String,
    pub repo: Option<String>,
    pub rev: Option<String>,
    pub license: Option<String>,
    /// Commands `setup` runs once in the lane's folder (dependencies, fetch, base image).
    #[serde(default)]
    pub prepare: Vec<Vec<String>>,
    pub command: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Paths (relative to `{dir}`) erased before every phase.
    #[serde(default)]
    pub clean: Vec<String>,
    /// Commands run before every phase, failures ignored (`docker rmi -f` of an absent image).
    #[serde(default)]
    pub clean_commands: Vec<Vec<String>>,
    pub done: Done,
}

/// The proof that the work ended: a file newer than the start of the lane, or a command that
/// exits 0. Exactly one of the two.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Done {
    pub file: Option<String>,
    pub command: Option<Vec<String>>,
}

impl Workloads {
    pub fn parse(text: &str) -> Result<Workloads, String> {
        let w: Workloads = toml::from_str(text).map_err(|e| format!("workloads: {e}"))?;
        if w.server.command.trim().is_empty() {
            return Err("workloads: server.command is empty".into());
        }
        if w.lane.is_empty() {
            return Err("workloads: no [[lane]]".into());
        }
        let mut seen = HashSet::new();
        for l in &w.lane {
            let ok_name = !l.name.is_empty()
                && l.name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
            if !ok_name || !seen.insert(l.name.as_str()) {
                return Err(format!(
                    "workloads: lane name `{}` is empty, not [a-z0-9-] or repeated",
                    l.name
                ));
            }
            if l.command.is_empty() {
                return Err(format!("workloads: lane {} has no command", l.name));
            }
            if l.done.file.is_some() == l.done.command.is_some() {
                return Err(format!(
                    "workloads: lane {} needs exactly one `done` proof (file or command)",
                    l.name
                ));
            }
            if l.repo.is_some() && !(l.rev.as_deref().is_some_and(is_sha) && l.license.is_some()) {
                return Err(format!(
                    "workloads: lane {} has a repo, so it needs a 40-hex rev and a license",
                    l.name
                ));
            }
        }
        Ok(w)
    }
}

fn is_sha(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneState {
    Done,
    Failed,
    QueuedTimeout,
    OomConfirmed,
    OomSuspected,
    KilledUnexplained,
    /// The program could not even be started (not a kill, not memory).
    SpawnFailed,
}

/// A sign in the error output that memory ran out. "JavaScript heap out of memory" is one: it
/// is a hint, never a confirmation (it is the V8 limit, not the machine's).
pub fn oom_hint(stderr: &str) -> bool {
    let low = stderr.to_ascii_lowercase();
    [
        "out of memory",
        "cannot allocate",
        "enomem",
        "0xc0000017",
        "paging file is too small",
    ]
    .iter()
    .any(|needle| low.contains(needle))
}

/// `exit`: the exit code (`None`: ended by a signal). 75 never comes here (it is a queue state).
pub fn classify(exit: Option<i32>, hint: bool, confirmed: bool, done_ok: bool) -> LaneState {
    if exit == Some(0) {
        return if done_ok {
            LaneState::Done
        } else {
            LaneState::Failed
        };
    }
    match (hint, confirmed) {
        (true, true) => LaneState::OomConfirmed,
        (true, false) | (false, true) => LaneState::OomSuspected,
        // A signal, or a Windows NTSTATUS-style code, with nothing that says why.
        (false, false) if exit.is_none_or(|c| c as u32 >= 0xC000_0000) => {
            LaneState::KilledUnexplained
        }
        (false, false) => LaneState::Failed,
    }
}

/// The ticket of `...resume with: sync_gate wait N` (the three texts of `runner.rs`).
pub fn parse_ticket(stderr: &str) -> Option<u64> {
    const KEY: &str = "resume with: sync_gate wait ";
    let rest = &stderr[stderr.rfind(KEY)? + KEY.len()..];
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// Pids of `Out of memory: Killed process <pid>` lines (Linux kernel log).
pub fn kernel_killed_pids(log: &str) -> Vec<u32> {
    const KEY: &str = "Out of memory: Killed process ";
    log.lines()
        .filter_map(|line| {
            let rest = &line[line.find(KEY)? + KEY.len()..];
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            digits.parse().ok()
        })
        .collect()
}

pub fn median(values: &[f64]) -> Option<f64> {
    let mut v = values.to_vec();
    v.sort_by(f64::total_cmp);
    let mid = v.len() / 2;
    match v.len() {
        0 => None,
        n if n % 2 == 1 => Some(v[mid]),
        _ => Some((v[mid - 1] + v[mid]) / 2.0),
    }
}

pub fn range(values: &[f64]) -> Option<(f64, f64)> {
    let min = values.iter().copied().min_by(f64::total_cmp)?;
    let max = values.iter().copied().max_by(f64::total_cmp)?;
    Some((min, max))
}

/// Memory has settled when the last 3 samples are within 2% of each other.
pub fn settled(samples: &[f64]) -> bool {
    let Some(last) = samples.last_chunk::<3>() else {
        return false;
    };
    let (min, max) = range(last).unwrap_or_default();
    max <= min * 1.02
}

/// The environment of every child: nothing `SYNC_GATE_*` inherited, no folder with a shim
/// manifest on `PATH`, and `SYNC_GATE_SOCKET` set to `socket`.
pub fn controlled_env(
    base: impl IntoIterator<Item = (OsString, OsString)>,
    socket: &str,
    has_manifest: impl Fn(&Path) -> bool,
) -> Vec<(OsString, OsString)> {
    let mut out = Vec::new();
    for (key, value) in base {
        let name = key.to_string_lossy().to_ascii_uppercase();
        if name.starts_with("SYNC_GATE_") {
            continue;
        }
        if name == "PATH" {
            let dirs = std::env::split_paths(&value).filter(|d| !has_manifest(d));
            let cleaned = std::env::join_paths(dirs).unwrap_or(value);
            out.push((key, cleaned));
        } else {
            out.push((key, value));
        }
    }
    out.push(("SYNC_GATE_SOCKET".into(), socket.into()));
    out
}

/// `parents`: pid -> parent pid. `roots` and everything below them.
pub fn descendants(parents: &HashMap<u32, u32>, roots: &[u32]) -> HashSet<u32> {
    let mut found: HashSet<u32> = roots.iter().copied().collect();
    loop {
        let before = found.len();
        for (pid, parent) in parents {
            if found.contains(parent) {
                found.insert(*pid);
            }
        }
        if found.len() == before {
            return found;
        }
    }
}

/// Something in the text that must not go public: this user's name or an absolute path.
pub fn leak(text: &str, user: Option<&str>) -> Option<String> {
    if let Some(u) = user.filter(|u| u.len() > 2)
        && text.to_lowercase().contains(&u.to_lowercase())
    {
        return Some("the user name".into());
    }
    let b = text.as_bytes();
    let drive = (0..b.len().saturating_sub(2)).any(|i| {
        b[i].is_ascii_alphabetic()
            && b[i + 1] == b':'
            && matches!(b[i + 2], b'\\' | b'/')
            && (i == 0 || !b[i - 1].is_ascii_alphanumeric())
    });
    if drive {
        return Some("an absolute path (drive letter)".into());
    }
    ["/Users/", "/home/", "\\Users\\"]
        .iter()
        .find(|bad| text.contains(**bad))
        .map(|bad| format!("an absolute path (`{bad}`)"))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bench {
    pub candidate: String,
    pub crates_tree: String,
    pub cargo_toml: String,
    pub cargo_lock: String,
    pub contaminated: bool,
    pub label: String,
    pub machine: Machine,
    /// `false` while the run is unfinished, after an error, or with a phase that is not complete.
    #[serde(default)]
    pub complete: bool,
    #[serde(default)]
    pub incomplete_reason: Option<String>,
    /// A phase started with memory that had not settled.
    #[serde(default)]
    pub suspect: bool,
    #[serde(default)]
    pub knobs: Knobs,
    pub runs: Vec<Run>,
}

/// The test knobs of the queue and of the isolated daemon: a measure with them set is not a normal one.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Knobs {
    pub reserve_fraction: Option<f64>,
    pub aging_secs: Option<u64>,
    pub first_max_wait: Option<u64>,
    pub phase_deadline: u64,
}

impl Knobs {
    fn of(o: &RunOpts) -> Knobs {
        Knobs {
            reserve_fraction: o.reserve_fraction,
            aging_secs: o.aging_secs,
            first_max_wait: o.first_max_wait,
            phase_deadline: o.phase_deadline,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Machine {
    pub system: String,
    pub ram_total_mb: u64,
    pub cpus: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Run {
    pub phases: Phases,
    pub overhead_ms: Option<Overhead>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Phases {
    pub without: Option<PhaseOut>,
    pub with: Option<PhaseOut>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhaseOut {
    pub complete: bool,
    pub wall_secs: f64,
    pub lanes: Vec<LaneOut>,
    pub peak_ram_pct: f64,
    pub swap_start: u64,
    pub swap_peak: u64,
    pub mcp_procs_peak: u32,
    pub mcp_rss_peak: u64,
    pub daemon_rss_peak: u64,
    pub sessions_ready: u32,
    /// Memory in use when the phase started, after the wait for it to settle.
    #[serde(default)]
    pub ram_start_pct: f64,
    /// The wait ran out before 3 samples agreed.
    #[serde(default)]
    pub settle_timeout: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LaneOut {
    pub name: String,
    pub state: LaneState,
    pub exit: Option<i32>,
    pub secs: f64,
    pub waits: u32,
}

/// Medians of the per-command cost, in milliseconds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Overhead {
    pub direct: f64,
    pub sync_gate: f64,
}

const MB: f64 = 1024.0 * 1024.0;

fn count(phase: &PhaseOut, states: &[LaneState]) -> f64 {
    phase
        .lanes
        .iter()
        .filter(|l| states.contains(&l.state))
        .count() as f64
}

/// One row: how each phase's number is read from a phase.
type Pick = fn(&PhaseOut) -> f64;
type Show = fn(f64) -> String;

fn show_count(v: f64) -> String {
    format!("{v:.0}")
}
fn show_pct(v: f64) -> String {
    format!("{v:.0}%")
}
fn show_mb(v: f64) -> String {
    format!("{v:.0} MB")
}
fn show_ms(v: f64) -> String {
    format!("{v:.0} ms")
}
fn show_time(v: f64) -> String {
    let s = v.round() as u64;
    format!("{}m{:02}s", s / 60, s % 60)
}

fn cell(values: &[f64], show: Show) -> String {
    match (median(values), range(values)) {
        (Some(m), Some((lo, hi))) if values.len() > 1 => {
            format!("{} ({}-{})", show(m), show(lo), show(hi))
        }
        (Some(m), _) => show(m),
        _ => "-".into(),
    }
}

impl Bench {
    fn phase_values(&self, with: bool, pick: Pick) -> Vec<f64> {
        self.runs
            .iter()
            .filter_map(|r| {
                if with {
                    &r.phases.with
                } else {
                    &r.phases.without
                }
                .as_ref()
            })
            .map(pick)
            .collect()
    }
}

/// The report: the label, what was measured, and the table in Markdown.
pub fn render_table(b: &Bench) -> String {
    let n = b.runs.len();
    let how = if n == 1 {
        "single run, no repeatability measured".to_owned()
    } else {
        format!("median of {n} runs, range in parentheses (minimum-maximum)")
    };
    let rows: [(&str, Pick, Show); 9] = [
        (
            "Jobs lost to memory (confirmed)",
            |p| count(p, &[LaneState::OomConfirmed]),
            show_count,
        ),
        (
            "Jobs lost, memory suspected or unexplained",
            |p| count(p, &[LaneState::OomSuspected, LaneState::KilledUnexplained]),
            show_count,
        ),
        (
            "Jobs completed",
            |p| count(p, &[LaneState::Done]),
            show_count,
        ),
        ("Peak RAM", |p| p.peak_ram_pct, show_pct),
        (
            "Paging file growth",
            |p| p.swap_peak.saturating_sub(p.swap_start) as f64 / MB,
            show_mb,
        ),
        ("MCP processes", |p| f64::from(p.mcp_procs_peak), show_count),
        ("MCP memory", |p| p.mcp_rss_peak as f64 / MB, show_mb),
        (
            "sync_gate daemon memory",
            |p| p.daemon_rss_peak as f64 / MB,
            show_mb,
        ),
        ("Total time", |p| p.wall_secs, show_time),
    ];
    let mut warnings = String::new();
    if let Some(why) = &b.incomplete_reason {
        warnings.push_str(&format!("WARNING: incomplete: {why}.\n"));
    }
    if b.suspect {
        warnings.push_str("WARNING: memory had not settled before a phase started; other programs may have skewed it.\n");
    }
    if !warnings.is_empty() {
        warnings.push('\n');
    }
    let mut out = format!(
        "{warnings}{LABEL}\n\nCandidate {}, crates tree {}.\n{how}.\n\n",
        b.candidate.get(..7).unwrap_or(&b.candidate),
        b.crates_tree.get(..12).unwrap_or(&b.crates_tree),
    );
    out.push_str("| Measure | Without sync_gate | With sync_gate |\n| --- | --- | --- |\n");
    for (name, pick, show) in rows {
        let without = b.phase_values(false, pick);
        let mut with = b.phase_values(true, pick);
        // The daemon exists only in the second phase.
        let daemon_row = name == "sync_gate daemon memory";
        let without_cell = if daemon_row {
            "-".into()
        } else {
            cell(&without, show)
        };
        if daemon_row && with.is_empty() {
            with.clear();
        }
        out.push_str(&format!(
            "| {name} | {without_cell} | {} |\n",
            cell(&with, show)
        ));
    }
    let direct: Vec<f64> = b
        .runs
        .iter()
        .filter_map(|r| r.overhead_ms.as_ref())
        .map(|o| o.direct)
        .collect();
    let queued: Vec<f64> = b
        .runs
        .iter()
        .filter_map(|r| r.overhead_ms.as_ref())
        .map(|o| o.sync_gate)
        .collect();
    out.push_str(&format!(
        "| Cost per command | {} | {} |\n",
        cell(&direct, show_ms),
        cell(&queued, show_ms)
    ));
    let complete = |with: bool| {
        let phases: Vec<&PhaseOut> = b
            .runs
            .iter()
            .filter_map(|r| {
                if with {
                    &r.phases.with
                } else {
                    &r.phases.without
                }
                .as_ref()
            })
            .collect();
        format!(
            "{} of {}",
            phases.iter().filter(|p| p.complete).count(),
            phases.len()
        )
    };
    out.push_str(&format!(
        "| Complete phases | {} | {} |\n",
        complete(false),
        complete(true)
    ));
    out
}

/// Three pairs of bars (medians): jobs lost to memory (confirmed), peak RAM, MCP processes.
pub fn render_svg(b: &Bench) -> String {
    let groups: [(&str, &str, Pick, f64); 3] = [
        (
            "lost",
            "Jobs lost to memory",
            |p| count(p, &[LaneState::OomConfirmed]),
            4.0,
        ),
        ("ram", "Peak RAM (%)", |p| p.peak_ram_pct, 100.0),
        (
            "mcp",
            "MCP processes",
            |p| f64::from(p.mcp_procs_peak),
            10.0,
        ),
    ];
    let mut body = String::new();
    for (i, (id, title, pick, floor)) in groups.iter().enumerate() {
        let x = 20 + i * 200;
        let values = [
            median(&b.phase_values(false, *pick)),
            median(&b.phase_values(true, *pick)),
        ];
        let scale = values.iter().flatten().copied().fold(*floor, f64::max);
        body.push_str(&format!(
            "<g id=\"{id}\"><text x=\"{x}\" y=\"28\">{title}</text>\n"
        ));
        for (j, (class, label)) in [("without", "Without"), ("with", "With")]
            .iter()
            .enumerate()
        {
            let y = 48 + j * 80;
            body.push_str(&format!("<text x=\"{x}\" y=\"{}\">{label}</text>", y + 12));
            // No bar for a phase that did not run: a "0" would read as a measurement.
            let Some(v) = values[j] else {
                body.push_str(&format!("<text x=\"{x}\" y=\"{}\">-</text>\n", y + 38));
                continue;
            };
            let w = (v / scale * 150.0).round();
            body.push_str(&format!(
                "<rect class=\"{class}\" x=\"{x}\" y=\"{}\" width=\"{w}\" height=\"24\"/>\
                 <text x=\"{}\" y=\"{}\">{v:.0}</text>\n",
                y + 20,
                x as f64 + w + 6.0,
                y + 38
            ));
        }
        body.push_str("</g>\n");
    }
    format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 620 230\" role=\"img\" \
         aria-labelledby=\"t d\">\n<title id=\"t\">sync_gate benchmark</title>\
         <desc id=\"d\">{LABEL}</desc>\n<style>\n\
         :root{{--bg:#ffffff;--fg:#1f2328;--without:#c0392b;--with:#1a7f4b}}\n\
         @media (prefers-color-scheme: dark){{:root{{--bg:#0d1117;--fg:#e6edf3;--without:#ff7b72;--with:#56d364}}}}\n\
         text{{fill:var(--fg);font:12px sans-serif}}\n\
         .bg{{fill:var(--bg)}}.without{{fill:var(--without)}}.with{{fill:var(--with)}}\n\
         </style>\n<rect class=\"bg\" width=\"620\" height=\"230\"/>\n{body}</svg>\n"
    )
}

// ---------------------------------------------------------------------------------------------
// Command line
// ---------------------------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub enum Which {
    Without,
    With,
    Both,
}

#[derive(Debug, PartialEq)]
pub struct SetupOpts {
    pub work: PathBuf,
    pub rev: String,
    pub workloads: Option<PathBuf>,
}

#[derive(Debug, PartialEq)]
pub struct RunOpts {
    pub work: PathBuf,
    pub bin: PathBuf,
    pub phase: Which,
    pub repeat: u32,
    pub out: PathBuf,
    /// Test knobs of the isolated daemon's config and of the queue.
    pub reserve_fraction: Option<f64>,
    pub aging_secs: Option<u64>,
    pub first_max_wait: Option<u64>,
    pub phase_deadline: u64,
}

#[derive(Debug, PartialEq)]
pub struct ReportOpts {
    pub json: PathBuf,
    pub svg: Option<PathBuf>,
}

#[derive(Debug, PartialEq)]
pub enum BenchCmd {
    Setup(SetupOpts),
    Run(RunOpts),
    Report(ReportOpts),
}

pub fn parse(args: &[String]) -> Result<BenchCmd, String> {
    let Some((sub, flags)) = args.split_first() else {
        return Err("bench needs setup, run or report".into());
    };
    let mut it = flags.iter();
    let mut map: HashMap<&str, String> = HashMap::new();
    let mut free: Vec<&String> = Vec::new();
    let known: &[&str] = match sub.as_str() {
        "setup" => &["--work", "--rev", "--workloads"],
        "run" => &[
            "--work",
            "--bin",
            "--phase",
            "--repeat",
            "--out",
            "--reserve-fraction",
            "--aging-secs",
            "--first-max-wait",
            "--phase-deadline",
        ],
        "report" => &["--svg"],
        other => return Err(format!("unknown bench command `{other}`")),
    };
    while let Some(flag) = it.next() {
        if let Some(name) = known.iter().find(|k| **k == flag.as_str()) {
            let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
            map.insert(name, value.clone());
        } else if flag.starts_with("--") {
            return Err(format!("unknown option `{flag}`"));
        } else {
            free.push(flag);
        }
    }
    let need = |name: &str| {
        map.get(name)
            .cloned()
            .ok_or_else(|| format!("bench {sub} needs {name}"))
    };
    let num = |name: &str| -> Result<Option<u64>, String> {
        map.get(name)
            .map(|v| v.parse().map_err(|_| format!("{name} needs a number")))
            .transpose()
    };
    match sub.as_str() {
        "setup" => Ok(BenchCmd::Setup(SetupOpts {
            work: need("--work")?.into(),
            rev: need("--rev")?,
            workloads: map.get("--workloads").map(PathBuf::from),
        })),
        "run" => {
            let phase = match map.get("--phase").map(String::as_str) {
                None | Some("both") => Which::Both,
                Some("without") => Which::Without,
                Some("with") => Which::With,
                Some(other) => {
                    return Err(format!("--phase is without, with or both, not `{other}`"));
                }
            };
            let repeat = num("--repeat")?.unwrap_or(1);
            if repeat == 0 {
                return Err("--repeat needs at least 1".into());
            }
            let reserve_fraction = map
                .get("--reserve-fraction")
                .map(|v| {
                    v.parse()
                        .map_err(|_| "--reserve-fraction needs a number".to_owned())
                })
                .transpose()?;
            Ok(BenchCmd::Run(RunOpts {
                work: need("--work")?.into(),
                bin: need("--bin")?.into(),
                phase,
                repeat: repeat as u32,
                out: need("--out")?.into(),
                reserve_fraction,
                aging_secs: num("--aging-secs")?,
                first_max_wait: num("--first-max-wait")?,
                phase_deadline: num("--phase-deadline")?.unwrap_or(DEFAULT_PHASE_DEADLINE),
            }))
        }
        _ => match free.as_slice() {
            [json] => Ok(BenchCmd::Report(ReportOpts {
                json: PathBuf::from(json),
                svg: map.get("--svg").map(PathBuf::from),
            })),
            _ => Err("bench report needs the JSON file".into()),
        },
    }
}

// ---------------------------------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------------------------------

/// Everything a child gets: the controlled environment, and how to resolve a program name.
struct Env {
    original_path: Option<OsString>,
    pathext: Option<OsString>,
    base: Vec<(OsString, OsString)>,
    none_socket: String,
}

fn has_manifest(dir: &Path) -> bool {
    dir.join(SHIMS_MANIFEST).exists()
}

impl Env {
    fn new() -> Env {
        Env {
            original_path: std::env::var_os("PATH"),
            pathext: std::env::var_os("PATHEXT"),
            base: std::env::vars_os().collect(),
            none_socket: format!("sync_gate-bench-none-{}", std::process::id()),
        }
    }

    fn vars(&self, socket: &str) -> Vec<(OsString, OsString)> {
        controlled_env(self.base.clone(), socket, has_manifest)
    }

    fn clean_path(&self) -> Option<OsString> {
        let vars = self.vars(&self.none_socket);
        vars.into_iter()
            .find(|(k, _)| k.to_string_lossy().eq_ignore_ascii_case("PATH"))
            .map(|(_, v)| v)
    }

    /// A bare name is found on the cleaned `PATH`; one with a folder part is taken as written.
    fn resolve(&self, name: &str, forbidden: &[PathBuf]) -> Result<PathBuf, String> {
        if name.contains(['/', '\\']) {
            return Ok(PathBuf::from(name));
        }
        let cwd = std::env::current_dir().unwrap_or_default();
        let found = find_program(
            OsStr::new(name),
            self.clean_path().as_deref(),
            self.pathext.as_deref(),
            &cwd,
        )
        .ok_or_else(|| format!("`{name}` is not on the PATH (without the shim folders)"))?;
        if forbidden.iter().any(|f| same_file(f, &found)) {
            return Err(format!(
                "`{name}` resolves to a sync_gate binary: refusing to benchmark"
            ));
        }
        Ok(found)
    }

    /// The `sync_gate`, `sync_gated` and `sync_gate_mcp` binaries a lane must never resolve to.
    fn forbidden(&self, bin: Option<&Path>) -> Vec<PathBuf> {
        let cwd = std::env::current_dir().unwrap_or_default();
        let mut list = Vec::new();
        for name in ["sync_gate", "sync_gated", "sync_gate_mcp", "sync_gate_shim"] {
            if let Some(p) = find_program(
                OsStr::new(name),
                self.original_path.as_deref(),
                self.pathext.as_deref(),
                &cwd,
            ) {
                list.push(p);
            }
            if let Some(dir) = bin
                && let Some(p) = find_program(
                    OsStr::new(name),
                    Some(dir.as_os_str()),
                    self.pathext.as_deref(),
                    &cwd,
                )
            {
                list.push(p);
            }
        }
        list
    }
}

/// The same file: the same path once resolved, or a copy or hard link with the same bytes.
fn same_file(a: &Path, b: &Path) -> bool {
    if let (Ok(x), Ok(y)) = (std::fs::canonicalize(a), std::fs::canonicalize(b))
        && x == y
    {
        return true;
    }
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(x), Ok(y)) if x.len() == y.len() && x.is_file() => {
            matches!((std::fs::read(a), std::fs::read(b)), (Ok(p), Ok(q)) if p == q)
        }
        _ => false,
    }
}

struct Expand<'a> {
    dir: &'a Path,
    target: &'a Path,
    bin: &'a Path,
}

impl Expand<'_> {
    fn text(&self, s: &str) -> String {
        s.replace("{dir}", &self.dir.to_string_lossy())
            .replace("{target}", &self.target.to_string_lossy())
            .replace("{bin}", &self.bin.to_string_lossy())
            .replace("{exe}", if cfg!(windows) { ".exe" } else { "" })
    }
    fn list(&self, v: &[String]) -> Vec<String> {
        v.iter().map(|s| self.text(s)).collect()
    }
}

fn lane_dir(work: &Path, lane: &Lane) -> PathBuf {
    work.join(if lane.repo.is_some() {
        &lane.name
    } else {
        "candidate"
    })
}

fn lane_target(work: &Path, lane: &Lane) -> PathBuf {
    work.join(format!("target-{}", lane.name))
}

fn git(dir: &Path, args: &[&str]) -> Result<String, String> {
    crate::output(dir, "git", args)
}

/// The absolute path of `p` without the verbatim prefix Windows adds (git and others refuse it).
fn plain(p: &Path) -> std::io::Result<PathBuf> {
    let full = std::fs::canonicalize(p)?;
    let text = full.to_string_lossy();
    Ok(match text.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => PathBuf::from(rest),
        _ => full,
    })
}

/// The Windows console hosts that appear under a child that has a console.
pub fn is_console_helper(name: &str) -> bool {
    ["conhost.exe", "openconsole.exe"].contains(&name.to_ascii_lowercase().as_str())
}

fn fnv(bytes: &[u8]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h = (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3);
    }
    format!("{h:016x}")
}

/// What the user's real daemon and data folder look like. A benchmark leaves it as it was.
#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
struct RealSnapshot {
    /// (pid, start time) of the `sync_gated` of the installed path.
    daemon: Vec<(u32, u64)>,
    data_known: bool,
    pending: Vec<String>,
    files: BTreeMap<String, Option<String>>,
}

fn real_snapshot(env: &Env) -> RealSnapshot {
    let cwd = std::env::current_dir().unwrap_or_default();
    let find = |name: &str| {
        find_program(
            OsStr::new(name),
            env.original_path.as_deref(),
            env.pathext.as_deref(),
            &cwd,
        )
    };
    let mut snap = RealSnapshot::default();
    if let Some(installed) = find("sync_gated").and_then(|p| std::fs::canonicalize(p).ok()) {
        let mut sys = System::new().ok();
        if let Some(sys) = sys.as_mut() {
            sys.refresh_processes_specifics(
                ProcessesToUpdate::All,
                true,
                ProcessRefreshKind::nothing().with_exe(UpdateKind::Always),
            );
            for (pid, p) in sys.processes() {
                if p.exe()
                    .and_then(|e| std::fs::canonicalize(e).ok())
                    .as_deref()
                    == Some(&installed)
                {
                    snap.daemon.push((pid.as_u32(), p.start_time()));
                }
            }
            snap.daemon.sort_unstable();
        }
    }
    let data = find("sync_gate").and_then(|sg| {
        let out = Command::new(sg)
            .arg("paths")
            .env_clear()
            .envs(env.vars(&env.none_socket))
            .output()
            .ok()?;
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .find_map(|l| l.strip_prefix("data=").map(PathBuf::from))
    });
    if let Some(data) = data {
        snap.data_known = true;
        if let Ok(rd) = std::fs::read_dir(data.join("pending")) {
            snap.pending = rd
                .filter_map(|e| e.ok()?.file_name().into_string().ok())
                .collect();
            snap.pending.sort();
        }
        for name in ["cost.json", "services.json", "mcp-adopted.json"] {
            snap.files.insert(
                name.into(),
                std::fs::read(data.join(name)).ok().map(|b| fnv(&b)),
            );
        }
    }
    snap
}

#[derive(Serialize, Deserialize)]
struct State {
    candidate: String,
    crates_tree: String,
    cargo_toml: String,
    cargo_lock: String,
    real: RealSnapshot,
}

fn run_checked(
    env: &Env,
    forbidden: &[PathBuf],
    cwd: &Path,
    argv: &[String],
    extra: &[(OsString, OsString)],
) -> Result<(), String> {
    let (program, args) = argv.split_first().ok_or("empty command")?;
    let exe = env.resolve(program, forbidden)?;
    let status = Command::new(&exe)
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .envs(env.vars(&env.none_socket))
        .envs(extra.iter().cloned())
        .stdout(Stdio::null())
        .status()
        .map_err(|e| format!("could not start `{program}`: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("`{}` failed ({status})", argv.join(" ")))
    }
}

fn setup(root: &Path, o: &SetupOpts) -> Result<bool, String> {
    let status = ["status", "--porcelain", "--untracked-files=all"];
    if !git(root, &status)?.is_empty() {
        return Err("bench setup needs a clean working tree: commit or stash first".into());
    }
    let sha = git(
        root,
        &["rev-parse", "--verify", &format!("{}^{{commit}}", o.rev)],
    )?;
    let workloads_path = o
        .workloads
        .clone()
        .unwrap_or_else(|| root.join(DEFAULT_WORKLOADS));
    let text = std::fs::read_to_string(&workloads_path)
        .map_err(|e| format!("cannot read the workloads file: {e}"))?;
    let w = Workloads::parse(&text)?;
    if o.work.join("candidate").exists() {
        return Err("--work is already set up: use a new folder".into());
    }
    std::fs::create_dir_all(&o.work).map_err(|e| format!("cannot create --work: {e}"))?;
    let work = plain(&o.work).map_err(|e| e.to_string())?;
    let env = Env::new();
    let forbidden = env.forbidden(None);
    let state = State {
        crates_tree: git(root, &["rev-parse", &format!("{sha}:crates")])?,
        cargo_toml: git(root, &["rev-parse", &format!("{sha}:Cargo.toml")])?,
        cargo_lock: git(root, &["rev-parse", &format!("{sha}:Cargo.lock")])?,
        candidate: sha.clone(),
        real: real_snapshot(&env),
    };
    std::fs::write(work.join(WORKLOADS_COPY), &text).map_err(|e| e.to_string())?;

    let clone = |from: &str, to: &Path, rev: &str| -> Result<(), String> {
        let to_s = to.to_string_lossy().into_owned();
        run_checked(
            &env,
            &forbidden,
            &work,
            &argv(&["git", "clone", "--no-checkout", from, &to_s]),
            &[],
        )?;
        run_checked(
            &env,
            &forbidden,
            to,
            &argv(&["git", "checkout", "--detach", rev]),
            &[],
        )
    };
    clone(&root.to_string_lossy(), &work.join("candidate"), &sha)?;
    let bin = work.join("bin-unused");
    for lane in &w.lane {
        let dir = lane_dir(&work, lane);
        if let (Some(repo), Some(rev)) = (&lane.repo, &lane.rev) {
            clone(repo, &dir, rev)?;
        }
        let target = lane_target(&work, lane);
        let x = Expand {
            dir: &dir,
            target: &target,
            bin: &bin,
        };
        for cmd in &lane.prepare {
            println!("setup {}: {}", lane.name, cmd.join(" "));
            run_checked(&env, &forbidden, &dir, &x.list(cmd), &[])?;
        }
    }
    std::fs::write(
        work.join(STATE_FILE),
        serde_json::to_string_pretty(&state).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    println!("setup done for {}", &sha[..7]);
    Ok(true)
}

fn argv(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| (*s).to_owned()).collect()
}

/// Reads a child's error output; keeps the tail (the last 128 KiB) as text.
fn read_tail(mut r: impl Read) -> String {
    const KEEP: usize = 128 * 1024;
    let (mut buf, mut chunk) = (Vec::new(), [0u8; 8192]);
    while let Ok(n) = r.read(&mut chunk) {
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > KEEP {
            buf.drain(..buf.len() - KEEP);
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

fn kill_tree(pids: &[u32]) {
    let Ok(mut sys) = System::new() else { return };
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing());
    let parents = parent_table(&sys);
    for pid in descendants(&parents, pids) {
        if let Some(p) = sys.process(Pid::from_u32(pid)) {
            p.kill();
        }
    }
}

fn parent_table(sys: &System) -> HashMap<u32, u32> {
    sys.processes()
        .iter()
        .map(|(pid, p)| (pid.as_u32(), p.parent().map_or(u32::MAX, Pid::as_u32)))
        .collect()
}

/// Whether the system itself says memory ran out in the last `window` for one of `pids`.
/// Windows: event 2004 of the Resource-Exhaustion-Detector in the window (the event does list
/// the processes by name and ID, but we do not match them: any 2004 in the window counts). Linux: `Out of memory: Killed process <pid>` of a pid in the lane's tree. macOS: no
/// source is read, so nothing is ever confirmed there.
fn system_confirms(window: Duration, pids: &HashSet<u32>) -> bool {
    if cfg!(windows) {
        let ms = window.as_millis() + 5000;
        let query = format!(
            "*[System[Provider[@Name='Microsoft-Windows-Resource-Exhaustion-Detector'] and \
             (EventID=2004) and TimeCreated[timediff(@SystemTime) <= {ms}]]]"
        );
        Command::new("wevtutil")
            .args(["qe", "System", &format!("/q:{query}"), "/c:1", "/f:text"])
            .output()
            .is_ok_and(|o| !o.stdout.iter().all(u8::is_ascii_whitespace))
    } else if cfg!(target_os = "linux") {
        let since = format!("-{}s", window.as_secs() + 5);
        let log = Command::new("journalctl")
            .args(["-k", "--no-pager", "--since", &since])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .or_else(|| Command::new("dmesg").output().ok())
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        kernel_killed_pids(&log).iter().any(|p| pids.contains(p))
    } else {
        false
    }
}

enum Proof {
    File(PathBuf),
    Command(Vec<String>),
}

struct LaneJob {
    name: String,
    program: PathBuf,
    args: Vec<String>,
    cwd: PathBuf,
    env: Vec<(OsString, OsString)>,
    proof: Proof,
    clean: Vec<PathBuf>,
    clean_commands: Vec<Vec<String>>,
}

struct Shared {
    deadline: Instant,
    /// The `sync_gate` binary and the environment of the isolated daemon (the phase "with").
    queued: Option<(PathBuf, Vec<(OsString, OsString)>)>,
    first_max_wait: Option<u64>,
    roots: Mutex<HashMap<String, u32>>,
    tree: Mutex<HashMap<String, HashSet<u32>>>,
}

fn spawn_captured(
    cmd: &mut Command,
    shared: &Shared,
    lane: &str,
) -> Result<(Child, std::thread::JoinHandle<String>), String> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| {
        format!(
            "could not start {}: {e}",
            cmd.get_program().to_string_lossy()
        )
    })?;
    shared
        .roots
        .lock()
        .unwrap()
        .insert(lane.to_owned(), child.id());
    let stderr = child.stderr.take().ok_or("no stderr pipe")?;
    Ok((child, std::thread::spawn(move || read_tail(stderr))))
}

fn proof_ok(job: &LaneJob, env: &Env, started: SystemTime) -> bool {
    match &job.proof {
        Proof::File(path) => std::fs::metadata(path)
            .and_then(|m| m.modified())
            .is_ok_and(|t| t >= started - Duration::from_secs(2)),
        Proof::Command(argv) => run_checked(env, &[], &job.cwd, argv, &[]).is_ok(),
    }
}

fn run_lane(job: &LaneJob, env: &Env, shared: &Shared) -> LaneOut {
    let (started, started_at) = (Instant::now(), SystemTime::now());
    let mut waits = 0;
    let mut ticket: Option<u64> = None;
    let mut stderr_all = String::new();
    let mut timed_out = false;
    let exit = loop {
        let mut cmd;
        match &shared.queued {
            None => {
                cmd = Command::new(&job.program);
                cmd.args(&job.args)
                    .env_clear()
                    .envs(job.env.iter().cloned());
            }
            Some((sync_gate, with_env)) => {
                let left = shared
                    .deadline
                    .saturating_duration_since(Instant::now())
                    .as_secs();
                cmd = Command::new(sync_gate);
                match ticket {
                    None => {
                        let first = shared.first_max_wait.map_or(left, |f| f.min(left));
                        cmd.args(["run", "--session", &job.name, "--max-wait"])
                            .arg(first.max(1).to_string())
                            .arg("--")
                            .arg(&job.program)
                            .args(&job.args);
                    }
                    Some(n) => {
                        if left == 0 {
                            timed_out = true;
                            break None;
                        }
                        waits += 1;
                        cmd.args(["wait", &n.to_string(), "--max-wait", &left.to_string()]);
                    }
                }
                cmd.env_clear()
                    .envs(with_env.iter().cloned())
                    .envs(job.env.iter().cloned())
                    .env("SYNC_GATE_FORCE_HEAVY", "1");
            }
        }
        cmd.current_dir(&job.cwd);
        let (mut child, reader) = match spawn_captured(&mut cmd, shared, &job.name) {
            Ok(x) => x,
            Err(_) => {
                return LaneOut {
                    name: job.name.clone(),
                    state: LaneState::SpawnFailed,
                    exit: None,
                    secs: started.elapsed().as_secs_f64(),
                    waits,
                };
            }
        };
        let code = child.wait().ok().and_then(|s| s.code());
        stderr_all.push_str(&reader.join().unwrap_or_default());
        shared.roots.lock().unwrap().remove(&job.name);
        if shared.queued.is_some() && code == Some(75) {
            // shortcut: a 75 without a ticket in the text ends the lane as failed,
            // when the text of runner.rs changes the parser must follow (test 6.8).
            match parse_ticket(&stderr_all).or(ticket) {
                Some(n) => ticket = Some(n),
                None => break Some(75),
            }
            continue;
        }
        break code;
    };
    let secs = started.elapsed().as_secs_f64();
    if timed_out || (shared.queued.is_some() && exit == Some(75) && ticket.is_some()) {
        return LaneOut {
            name: job.name.clone(),
            state: LaneState::QueuedTimeout,
            exit: Some(75),
            secs,
            waits,
        };
    }
    let hint = oom_hint(&stderr_all);
    let abnormal = exit.is_none_or(|c| c as u32 >= 0xC000_0000);
    let confirmed = exit != Some(0) && (hint || abnormal) && {
        let pids = shared
            .tree
            .lock()
            .unwrap()
            .get(&job.name)
            .cloned()
            .unwrap_or_default();
        system_confirms(started.elapsed(), &pids)
    };
    let done_ok = exit == Some(0) && proof_ok(job, env, started_at);
    LaneOut {
        name: job.name.clone(),
        state: classify(exit, hint, confirmed, done_ok),
        exit,
        secs,
        waits,
    }
}

#[derive(Default)]
struct Tally {
    peak_ram_pct: f64,
    swap_peak: u64,
    mcp_procs_peak: u32,
    mcp_rss_peak: u64,
    daemon_rss_peak: u64,
}

/// One sample of the machine and of the processes the benchmark started.
fn sample(sys: &mut System, t: &mut Tally, daemon: Option<u32>, sessions: &[u32], shared: &Shared) {
    sys.refresh_memory_specifics(MemoryRefreshKind::everything());
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_memory(),
    );
    let total = sys.total_memory().max(1);
    t.peak_ram_pct = t
        .peak_ram_pct
        .max(sys.used_memory() as f64 / total as f64 * 100.0);
    t.swap_peak = t.swap_peak.max(sys.used_swap());
    let parents = parent_table(sys);
    // With the daemon: the servers it started. Without: the sessions themselves and what they start.
    let mut mcp: HashSet<u32> = match daemon {
        Some(d) => {
            let mut set = descendants(&parents, &[d]);
            set.remove(&d);
            set
        }
        None => descendants(&parents, sessions),
    };
    // Gone, or a console host Windows adds under a console child: not an MCP process.
    mcp.retain(|p| {
        sys.process(Pid::from_u32(*p))
            .is_some_and(|pr| !is_console_helper(&pr.name().to_string_lossy()))
    });
    let rss = |pid: u32| {
        sys.process(Pid::from_u32(pid))
            .map_or(0, sysinfo::Process::memory)
    };
    t.mcp_procs_peak = t.mcp_procs_peak.max(mcp.len() as u32);
    t.mcp_rss_peak = t.mcp_rss_peak.max(mcp.iter().map(|p| rss(*p)).sum());
    if let Some(d) = daemon {
        t.daemon_rss_peak = t.daemon_rss_peak.max(rss(d));
    }
    let roots: Vec<(String, u32)> = shared
        .roots
        .lock()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), *v))
        .collect();
    let mut tree = shared.tree.lock().unwrap();
    for (lane, root) in roots {
        tree.entry(lane)
            .or_default()
            .extend(descendants(&parents, &[root]));
    }
}

struct Sessions {
    children: Vec<Child>,
    _stdins: Vec<ChildStdin>,
    ready: u32,
}

/// Starts `n` MCP sessions (open stdin, `initialize` sent) and waits for each one's first reply.
fn start_sessions(n: usize, mut make: impl FnMut() -> Command) -> Result<Sessions, String> {
    let (tx, rx) = mpsc::channel();
    let mut s = Sessions {
        children: Vec::new(),
        _stdins: Vec::new(),
        ready: 0,
    };
    for _ in 0..n {
        let mut cmd = make();
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("could not start an MCP session: {e}"))?;
        let mut stdin = child.stdin.take().ok_or("no stdin pipe")?;
        stdin
            .write_all(INITIALIZE.as_bytes())
            .and_then(|()| stdin.flush())
            .map_err(|e| format!("could not talk to an MCP session: {e}"))?;
        let out = child.stdout.take().ok_or("no stdout pipe")?;
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut lines = BufReader::new(out).lines();
            if lines.next().is_some() {
                let _ = tx.send(());
            }
            for _ in lines {}
        });
        s.children.push(child);
        s._stdins.push(stdin);
    }
    drop(tx);
    let until = Instant::now() + Duration::from_secs(90);
    while (s.ready as usize) < n {
        let left = until.saturating_duration_since(Instant::now());
        if rx.recv_timeout(left).is_err() {
            break;
        }
        s.ready += 1;
    }
    Ok(s)
}

fn used_pct(sys: &mut System) -> f64 {
    sys.refresh_memory_specifics(MemoryRefreshKind::everything());
    sys.used_memory() as f64 / sys.total_memory().max(1) as f64 * 100.0
}

/// Waits for memory to settle (3 samples within 2%, 120 s at most). Returns whether it settled
/// and the last memory reading.
fn settle() -> (bool, f64) {
    let Ok(mut sys) = System::new() else {
        return (false, 0.0);
    };
    let (mut seen, until) = (Vec::new(), Instant::now() + Duration::from_secs(120));
    while Instant::now() < until {
        seen.push(used_pct(&mut sys));
        if settled(&seen) {
            return (true, seen[seen.len() - 1]);
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    (false, seen.last().copied().unwrap_or(0.0))
}

fn median_ms(mut f: impl FnMut() -> Result<(), String>) -> Result<f64, String> {
    let mut times = Vec::new();
    for _ in 0..OVERHEAD_RUNS {
        let t = Instant::now();
        f()?;
        times.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    median(&times).ok_or_else(|| "no samples".into())
}

struct Ctx {
    work: PathBuf,
    bin: PathBuf,
    workloads: Workloads,
    env: Env,
    forbidden: Vec<PathBuf>,
}

fn bin_path(bin: &Path, name: &str) -> PathBuf {
    bin.join(format!("{name}{}", if cfg!(windows) { ".exe" } else { "" }))
}

fn make_jobs(c: &Ctx, env_of_lane: &[(OsString, OsString)]) -> Result<Vec<LaneJob>, String> {
    let mut jobs = Vec::new();
    for lane in &c.workloads.lane {
        let (dir, target) = (lane_dir(&c.work, lane), lane_target(&c.work, lane));
        let x = Expand {
            dir: &dir,
            target: &target,
            bin: &c.bin,
        };
        let cmd = x.list(&lane.command);
        let program = c.env.resolve(&cmd[0], &c.forbidden)?;
        let mut env = env_of_lane.to_vec();
        env.extend(lane.env.iter().map(|(k, v)| (k.into(), x.text(v).into())));
        let proof = match (&lane.done.file, &lane.done.command) {
            (Some(f), _) => Proof::File(dir.join(x.text(f))),
            (_, Some(argv)) => Proof::Command(x.list(argv)),
            _ => return Err(format!("lane {} has no done proof", lane.name)),
        };
        let mut clean: Vec<PathBuf> = lane.clean.iter().map(|p| dir.join(x.text(p))).collect();
        clean.push(target.clone());
        jobs.push(LaneJob {
            name: lane.name.clone(),
            program,
            args: cmd[1..].to_vec(),
            cwd: dir.clone(),
            env,
            proof,
            clean,
            clean_commands: lane.clean_commands.iter().map(|c| x.list(c)).collect(),
        });
    }
    Ok(jobs)
}

fn erase(path: &Path) -> Result<(), String> {
    let r = if path.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    };
    match r {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            Err(format!("cannot erase {}: {e}", path.display()))
        }
        _ => Ok(()),
    }
}

fn server_command(c: &Ctx) -> Result<(PathBuf, Vec<String>), String> {
    let x = Expand {
        dir: &c.work,
        target: &c.work,
        bin: &c.bin,
    };
    let program = c
        .env
        .resolve(&x.text(&c.workloads.server.command), &c.forbidden)?;
    Ok((program, x.list(&c.workloads.server.args)))
}

struct IsolatedDaemon {
    child: Child,
    data: PathBuf,
}

impl IsolatedDaemon {
    fn stop(mut self) {
        kill_tree(&[self.child.id()]);
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.data);
    }
}

fn run_phase(c: &Ctx, o: &RunOpts, with: bool) -> Result<(PhaseOut, Option<Overhead>), String> {
    let pid = std::process::id();
    let socket = format!("sync_gate-bench-{pid}");
    let data = c.work.join("daemon-data");
    let config = c.work.join("daemon-config.toml");
    let sg = bin_path(&c.bin, "sync_gate");
    let env_with = |socket: &str| {
        let mut v = c.env.vars(socket);
        v.push(("SYNC_GATE_DATA_DIR".into(), data.clone().into()));
        v.push(("SYNC_GATE_CONFIG".into(), config.clone().into()));
        v
    };
    let phase_env = if with {
        env_with(&socket)
    } else {
        c.env.vars(&c.env.none_socket)
    };
    let jobs = make_jobs(c, &phase_env)?;
    for job in &jobs {
        for p in &job.clean {
            erase(p)?;
        }
        for cmd in &job.clean_commands {
            let _ = run_checked(&c.env, &c.forbidden, &job.cwd, cmd, &[]);
        }
    }
    let (settled_ok, ram_start_pct) = settle();
    let mut sys = System::new().map_err(|e| e.to_string())?;
    sys.refresh_memory_specifics(MemoryRefreshKind::everything());
    let swap_start = sys.used_swap();

    let (server, server_args) = server_command(c)?;
    let (mut daemon, mut overhead) = (None, None);
    if with {
        let _ = std::fs::remove_dir_all(&data);
        std::fs::create_dir_all(&data).map_err(|e| e.to_string())?;
        let mut cfg = toml::Table::new();
        if let Some(r) = o.reserve_fraction {
            cfg.insert("reserve_fraction".into(), r.into());
        }
        if let Some(a) = o.aging_secs {
            cfg.insert(
                "aging_secs".into(),
                i64::try_from(a).map_err(|e| e.to_string())?.into(),
            );
        }
        let mut mcp = toml::Table::new();
        mcp.insert(
            "command".into(),
            server.to_string_lossy().into_owned().into(),
        );
        mcp.insert("args".into(), server_args.clone().into());
        mcp.insert("mode".into(), "shared".into());
        cfg.insert(
            "mcp".into(),
            toml::Table::from_iter([(BENCH_MCP.to_owned(), mcp.into())]).into(),
        );
        std::fs::write(&config, toml::to_string(&cfg).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        let log = std::fs::File::create(c.work.join("daemon.log")).map_err(|e| e.to_string())?;
        let child = Command::new(bin_path(&c.bin, "sync_gated"))
            .env_clear()
            .envs(env_with(&socket))
            .stdin(Stdio::null())
            .stdout(log.try_clone().map_err(|e| e.to_string())?)
            .stderr(log)
            .spawn()
            .map_err(|e| format!("could not start the isolated sync_gated: {e}"))?;
        daemon = Some(IsolatedDaemon {
            child,
            data: data.clone(),
        });
        let up = Instant::now() + Duration::from_secs(30);
        loop {
            let ready = Command::new(&sg)
                .arg("status")
                .env_clear()
                .envs(env_with(&socket))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success());
            if ready {
                break;
            }
            if Instant::now() > up {
                return Err("the isolated sync_gated did not answer in 30 s".into());
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        // The cost of asking for a slot, on an idle daemon. Not measured with the queue knobs
        // (a daemon told to hold everything would make each of the 40 runs wait).
        if o.reserve_fraction.is_none() && o.aging_secs.is_none() {
            let trivial = |cmd: &mut Command| -> Result<(), String> {
                let s = cmd
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .map_err(|e| e.to_string())?;
                s.success()
                    .then_some(())
                    .ok_or_else(|| "the trivial command failed".to_owned())
            };
            let direct = median_ms(|| {
                trivial(
                    Command::new(&sg)
                        .arg("--version")
                        .env_clear()
                        .envs(c.env.vars(&c.env.none_socket)),
                )
            })?;
            let queued = median_ms(|| {
                trivial(
                    Command::new(&sg)
                        .args(["run", "--"])
                        .arg(&sg)
                        .arg("--version")
                        .env_clear()
                        .envs(env_with(&socket))
                        .env("SYNC_GATE_FORCE_HEAVY", "1"),
                )
            })?;
            overhead = Some(Overhead {
                direct,
                sync_gate: queued,
            });
        }
    }

    let sessions = start_sessions(SESSIONS, || {
        let mut cmd;
        if with {
            cmd = Command::new(&sg);
            cmd.args(["mcp", "connect", BENCH_MCP])
                .env_clear()
                .envs(env_with(&socket));
        } else {
            cmd = Command::new(&server);
            cmd.args(&server_args)
                .env_clear()
                .envs(c.env.vars(&c.env.none_socket));
        }
        cmd
    });
    let mut sessions = match sessions {
        Ok(s) => s,
        Err(e) => {
            if let Some(d) = daemon.take() {
                d.stop();
            }
            return Err(e);
        }
    };
    let session_pids: Vec<u32> = sessions.children.iter().map(Child::id).collect();

    let shared = Shared {
        deadline: Instant::now() + Duration::from_secs(o.phase_deadline),
        queued: with.then(|| (sg.clone(), env_with(&socket))),
        first_max_wait: o.first_max_wait,
        roots: Mutex::new(HashMap::new()),
        tree: Mutex::new(HashMap::new()),
    };
    let daemon_pid = daemon.as_ref().map(|d| d.child.id());
    let mut tally = Tally::default();
    let started = Instant::now();
    let lanes: Vec<LaneOut> = std::thread::scope(|scope| {
        let handles: Vec<_> = jobs
            .iter()
            .map(|job| scope.spawn(|| run_lane(job, &c.env, &shared)))
            .collect();
        while !handles.iter().all(|h| h.is_finished()) {
            sample(&mut sys, &mut tally, daemon_pid, &session_pids, &shared);
            std::thread::sleep(SAMPLE_EVERY);
        }
        sample(&mut sys, &mut tally, daemon_pid, &session_pids, &shared);
        handles
            .into_iter()
            .map(|h| h.join().expect("a lane thread panicked"))
            .collect()
    });
    let wall_secs = started.elapsed().as_secs_f64();

    sessions._stdins.clear();
    kill_tree(&session_pids);
    for child in &mut sessions.children {
        let _ = child.wait();
    }
    if let Some(d) = daemon {
        d.stop();
    }
    let complete = phase_complete(&lanes, sessions.ready);
    let out = PhaseOut {
        complete,
        wall_secs,
        lanes,
        peak_ram_pct: tally.peak_ram_pct,
        swap_start,
        swap_peak: tally.swap_peak.max(swap_start),
        mcp_procs_peak: tally.mcp_procs_peak,
        mcp_rss_peak: tally.mcp_rss_peak,
        daemon_rss_peak: tally.daemon_rss_peak,
        sessions_ready: sessions.ready,
        ram_start_pct,
        settle_timeout: !settled_ok,
    };
    Ok((out, overhead))
}

/// A phase counts only when every lane ended soundly (lost to memory is a result; a failed,
/// unexplained, unstartable or still-queued lane is not) and every MCP session answered.
fn phase_complete(lanes: &[LaneOut], sessions_ready: u32) -> bool {
    sessions_ready as usize >= SESSIONS
        && lanes.iter().all(|l| {
            !matches!(
                l.state,
                LaneState::Failed
                    | LaneState::KilledUnexplained
                    | LaneState::SpawnFailed
                    | LaneState::QueuedTimeout
            )
        })
}

/// Writes next to the target and renames, so a kill mid-write never truncates the previous
/// good result.
fn write_atomic(path: &Path, text: &str) -> std::io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path) // replaces an existing file on Windows too (MoveFileEx)
}

fn phases_of(runs: &[Run]) -> impl Iterator<Item = &PhaseOut> {
    runs.iter()
        .flat_map(|r| [&r.phases.without, &r.phases.with])
        .flatten()
}

fn suspect(runs: &[Run]) -> bool {
    phases_of(runs).any(|p| p.settle_timeout)
}

/// Runs the pairs, saving after every phase (unfinished) and at the end. Returns what was
/// measured and the error that stopped the run, if any.
fn run_pairs(
    repeat: u32,
    which: &Which,
    mut phase: impl FnMut(bool) -> Result<(PhaseOut, Option<Overhead>), String>,
    mut save: impl FnMut(&[Run], Option<String>) -> Result<(), String>,
) -> (Vec<Run>, Option<String>) {
    const UNFINISHED: &str = "the run did not finish (interrupted or still running)";
    let mut runs: Vec<Run> = Vec::new();
    let mut failure = None;
    'pairs: for n in 1..=repeat {
        println!("pair {n} of {repeat}");
        runs.push(Run {
            phases: Phases {
                without: None,
                with: None,
            },
            overhead_ms: None,
        });
        for with in [false, true] {
            if (with && *which == Which::Without) || (!with && *which == Which::With) {
                continue;
            }
            match phase(with) {
                Ok((p, overhead)) => {
                    let r = runs.last_mut().expect("just pushed");
                    if with {
                        r.phases.with = Some(p);
                        r.overhead_ms = overhead;
                    } else {
                        r.phases.without = Some(p);
                    }
                    if let Err(e) = save(&runs, Some(UNFINISHED.into())) {
                        failure = Some(e);
                        break 'pairs;
                    }
                }
                Err(e) => {
                    failure = Some(e);
                    break 'pairs;
                }
            }
        }
    }
    if runs
        .last()
        .is_some_and(|r| r.phases.without.is_none() && r.phases.with.is_none())
    {
        runs.pop();
    }
    let reason = failure.clone().or_else(|| {
        (!phases_of(&runs).all(|p| p.complete)).then(|| {
            "a phase is not complete (failed lane, queue timeout or MCP sessions not ready)".into()
        })
    });
    if let Err(e) = save(&runs, reason) {
        failure.get_or_insert(e);
    }
    (runs, failure)
}
fn user_name() -> Option<String> {
    std::env::var(if cfg!(windows) { "USERNAME" } else { "USER" }).ok()
}

fn run(o: &RunOpts) -> Result<bool, String> {
    let work = plain(&o.work).map_err(|e| format!("--work: {e}"))?;
    let bin = plain(&o.bin).map_err(|e| format!("--bin: {e}"))?;
    for name in ["sync_gate", "sync_gated"] {
        if !bin_path(&bin, name).is_file() {
            return Err(format!("--bin has no {name}"));
        }
    }
    let state: State = serde_json::from_str(
        &std::fs::read_to_string(work.join(STATE_FILE))
            .map_err(|e| format!("not set up (run `bench setup` first): {e}"))?,
    )
    .map_err(|e| e.to_string())?;
    let workloads = Workloads::parse(
        &std::fs::read_to_string(work.join(WORKLOADS_COPY)).map_err(|e| e.to_string())?,
    )?;
    let env = Env::new();
    let forbidden = env.forbidden(Some(&bin));
    let c = Ctx {
        work,
        bin,
        workloads,
        env,
        forbidden,
    };
    let last = std::cell::Cell::new((false, false, false));
    let save = |runs: &[Run], reason: Option<String>| -> Result<(), String> {
        let contaminated = real_snapshot(&c.env) != state.real;
        let mut sys = System::new().ok();
        if let Some(s) = sys.as_mut() {
            s.refresh_memory_specifics(MemoryRefreshKind::everything());
        }
        let bench = Bench {
            candidate: state.candidate.clone(),
            crates_tree: state.crates_tree.clone(),
            cargo_toml: state.cargo_toml.clone(),
            cargo_lock: state.cargo_lock.clone(),
            contaminated,
            label: LABEL.into(),
            machine: Machine {
                system: format!(
                    "{} {}",
                    System::name().unwrap_or_default(),
                    System::os_version().unwrap_or_default()
                ),
                ram_total_mb: sys.map_or(0, |s| s.total_memory() / (1024 * 1024)),
                cpus: std::thread::available_parallelism().map_or(0, |n| n.get() as u64),
            },
            complete: reason.is_none(),
            incomplete_reason: reason,
            suspect: suspect(runs),
            knobs: Knobs::of(o),
            runs: runs.to_vec(),
        };
        let text = serde_json::to_string_pretty(&bench).map_err(|e| e.to_string())?;
        if let Some(what) = leak(&text, user_name().as_deref()) {
            return Err(format!("the result holds {what}: not written"));
        }
        write_atomic(&o.out, &text).map_err(|e| format!("--out: {e}"))?;
        last.set((contaminated, bench.complete, bench.suspect));
        Ok(())
    };
    let (_, failure) = run_pairs(o.repeat, &o.phase, |with| run_phase(&c, o, with), save);
    if let Some(e) = failure {
        return Err(format!("{e} (what was measured so far is in --out)"));
    }
    let (contaminated, complete, suspect) = last.get();
    println!("contaminated: {contaminated}, complete: {complete}, suspect: {suspect}");
    Ok(!contaminated && complete)
}

fn report(o: &ReportOpts) -> Result<bool, String> {
    let bench: Bench = serde_json::from_str(
        &std::fs::read_to_string(&o.json).map_err(|e| format!("cannot read the JSON: {e}"))?,
    )
    .map_err(|e| format!("not a bench result: {e}"))?;
    if bench.contaminated {
        return Err(
            "the result is contaminated (the real daemon or data folder changed): run again".into(),
        );
    }
    if bench.runs.is_empty() {
        return Err("the result has no runs".into());
    }
    let table = render_table(&bench);
    let svg = render_svg(&bench);
    for text in [&table, &svg] {
        if let Some(what) = leak(text, user_name().as_deref()) {
            return Err(format!("the report holds {what}: not written"));
        }
    }
    if let Some(path) = &o.svg {
        std::fs::write(path, svg).map_err(|e| format!("--svg: {e}"))?;
    }
    print!("{table}");
    Ok(true)
}

pub fn bench(root: &Path, cmd: &BenchCmd) -> Result<bool, String> {
    match cmd {
        BenchCmd::Setup(o) => setup(root, o),
        BenchCmd::Run(o) => run(o),
        BenchCmd::Report(o) => report(o),
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn write_atomic_keeps_the_old_file_when_the_write_fails() {
        let dir = std::env::temp_dir().join(format!("sgbench-atomic-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("out.json");
        write_atomic(&out, "old").unwrap();
        write_atomic(&out, "new").unwrap();
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "new");
        assert!(!dir.join("out.json.tmp").exists());
        // a directory squatting on the temp name makes the write fail midway
        std::fs::create_dir(dir.join("out.json.tmp")).unwrap();
        assert!(write_atomic(&out, "newer").is_err());
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "new");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    use super::*;

    const GOOD: &str = r#"
[server]
command = "{bin}/sync_gate"
args = ["mcp", "serve"]

[[lane]]
name = "cargo"
command = ["cargo", "build"]
done = { file = "{target}/release/sync_gated{exe}" }
"#;

    // 6.1
    #[test]
    fn workloads_are_read_and_the_bad_ones_refused() {
        let w = Workloads::parse(GOOD).unwrap();
        assert_eq!(w.lane[0].name, "cargo");
        assert_eq!(w.server.args, ["mcp", "serve"]);
        let unknown = GOOD.replace("name = \"cargo\"", "name = \"cargo\"\nbogus = 1");
        assert!(Workloads::parse(&unknown).is_err());
        let no_done = GOOD.replace("done = { file = \"{target}/release/sync_gated{exe}\" }", "");
        assert!(Workloads::parse(&no_done).unwrap_err().contains("done"));
        let empty_done = GOOD.replace("{ file = \"{target}/release/sync_gated{exe}\" }", "{}");
        assert!(Workloads::parse(&empty_done).is_err());
        // an external repo needs a fixed commit and a license
        let loose = format!(
            "{GOOD}\n[[lane]]\nname = \"n\"\nrepo = \"https://x\"\ncommand = [\"a\"]\ndone = {{ file = \"f\" }}\n"
        );
        assert!(Workloads::parse(&loose).unwrap_err().contains("rev"));
    }

    #[test]
    fn the_shipped_workload_files_parse() {
        let real = Workloads::parse(include_str!("../../../tools/bench/workloads.toml")).unwrap();
        let names: Vec<&str> = real.lane.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(names, ["next-a", "next-b", "cargo", "docker"]);
        Workloads::parse(include_str!("../../../tools/bench/smoke.toml")).unwrap();
    }

    #[test]
    fn absolute_paths_carry_no_verbatim_prefix() {
        let p = plain(&std::env::temp_dir()).unwrap();
        assert!(!p.to_string_lossy().starts_with(r"\\?\"));
        assert!(p.is_dir());
    }

    // 6.2
    #[test]
    fn classifier_tells_the_deaths_apart() {
        let heap =
            "FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory";
        assert!(oom_hint(heap) && oom_hint("ENOMEM") && !oom_hint("all fine"));
        assert_eq!(
            classify(Some(1), true, true, false),
            LaneState::OomConfirmed
        );
        assert_eq!(
            classify(Some(134), oom_hint(heap), false, false),
            LaneState::OomSuspected
        );
        assert_eq!(
            classify(None, false, false, false),
            LaneState::KilledUnexplained
        );
        assert_eq!(classify(Some(1), false, false, false), LaneState::Failed);
        assert_eq!(classify(Some(0), false, false, false), LaneState::Failed);
        assert_eq!(classify(Some(0), false, false, true), LaneState::Done);
    }

    // 6.4
    #[test]
    fn median_and_range() {
        assert_eq!(median(&[1.0, 3.0]), Some(2.0));
        assert_eq!(median(&[3.0, 1.0, 2.0]), Some(2.0));
        assert_eq!(median(&[5.0]), Some(5.0));
        assert_eq!(median(&[]), None);
        assert_eq!(range(&[3.0, 1.0, 2.0]), Some((1.0, 3.0)));
        assert!(settled(&[50.0, 40.0, 40.5, 40.2]) && !settled(&[40.0, 45.0, 40.0]));
    }

    // 6.6
    #[test]
    fn child_environment_is_controlled() {
        let shims = std::env::temp_dir().join(format!("sgbench-shims-{}", std::process::id()));
        std::fs::create_dir_all(&shims).unwrap();
        std::fs::write(shims.join(SHIMS_MANIFEST), "{}").unwrap();
        let keep = std::env::temp_dir();
        let path = std::env::join_paths([&shims, &keep]).unwrap();
        let base = vec![
            ("SYNC_GATE_JOB".into(), "7".into()),
            ("SYNC_GATE_SOCKET".into(), "x".into()),
            ("PATH".into(), path),
            ("KEEP".into(), "1".into()),
        ];
        let env = controlled_env(base, "phase-socket", has_manifest);
        let get = |k: &str| {
            env.iter()
                .rev()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(get("SYNC_GATE_JOB"), None);
        assert_eq!(get("SYNC_GATE_SOCKET"), Some("phase-socket".into()));
        assert_eq!(
            env.iter().filter(|(n, _)| n == "SYNC_GATE_SOCKET").count(),
            1
        );
        assert_eq!(get("KEEP"), Some("1".into()));
        let dirs: Vec<PathBuf> = std::env::split_paths(&get("PATH").unwrap()).collect();
        assert_eq!(dirs, [keep]);
        std::fs::remove_dir_all(&shims).unwrap();
    }

    // 6.8
    #[test]
    fn ticket_is_read_from_the_three_texts() {
        assert_eq!(
            parse_ticket("queued: ticket 7 \u{2014} resume with: sync_gate wait 7"),
            Some(7)
        );
        assert_eq!(
            parse_ticket(
                "sync_gate: cannot queue ticket 12 again (Busy); resume with: sync_gate wait 12"
            ),
            Some(12)
        );
        assert_eq!(
            parse_ticket("sync_gate: the daemon went away; resume with: sync_gate wait 345\n"),
            Some(345)
        );
        assert_eq!(parse_ticket("nothing here"), None);
    }

    #[test]
    fn tree_and_kernel_log_helpers() {
        assert!(is_console_helper("conhost.exe") && is_console_helper("OpenConsole.exe"));
        assert!(!is_console_helper("sync_gate.exe"));
        let parents = HashMap::from([(2, 1), (3, 2), (4, 9), (5, 3)]);
        assert_eq!(descendants(&parents, &[1]), HashSet::from([1, 2, 3, 5]));
        let log = "x Out of memory: Killed process 4242 (node) total-vm\nOut of memory: Killed process 7 (a)";
        assert_eq!(kernel_killed_pids(log), [4242, 7]);
    }

    fn phase(lost: usize, done: usize, ram: f64, mcp: u32, secs: f64, daemon: u64) -> PhaseOut {
        let mut lanes = Vec::new();
        for i in 0..4 {
            let state = if i < lost {
                LaneState::OomConfirmed
            } else if i < lost + done {
                LaneState::Done
            } else {
                LaneState::Failed
            };
            lanes.push(LaneOut {
                name: format!("l{i}"),
                state,
                exit: Some(0),
                secs: 1.0,
                waits: 0,
            });
        }
        PhaseOut {
            complete: true,
            wall_secs: secs,
            lanes,
            peak_ram_pct: ram,
            swap_start: 1 << 30,
            swap_peak: 3 << 30,
            mcp_procs_peak: mcp,
            mcp_rss_peak: 500 << 20,
            daemon_rss_peak: daemon,
            sessions_ready: 10,
            ram_start_pct: 40.0,
            settle_timeout: false,
        }
    }

    fn bench_of(pairs: &[(f64, f64)]) -> Bench {
        Bench {
            candidate: "abcdef0123456789abcdef0123456789abcdef01".into(),
            crates_tree: "0123456789abcdef0123456789abcdef01234567".into(),
            cargo_toml: "a".into(),
            cargo_lock: "b".into(),
            complete: true,
            incomplete_reason: None,
            suspect: false,
            knobs: Knobs::default(),
            contaminated: false,
            label: LABEL.into(),
            machine: Machine {
                system: "Test 1".into(),
                ram_total_mb: 16000,
                cpus: 8,
            },
            runs: pairs
                .iter()
                .map(|(without_ram, with_ram)| Run {
                    phases: Phases {
                        without: Some(phase(1, 3, *without_ram, 10, 600.0, 0)),
                        with: Some(phase(0, 4, *with_ram, 1, 660.0, 20 << 20)),
                    },
                    overhead_ms: Some(Overhead {
                        direct: 8.0,
                        sync_gate: 70.0,
                    }),
                })
                .collect(),
        }
    }

    // 6.3
    #[test]
    fn report_prints_the_exact_table_for_one_pair() {
        let table = render_table(&bench_of(&[(97.0, 81.0)]));
        let expected = "\
proxy: heavy commands of 4 agents + 10 MCP sessions; agent processes not included

Candidate abcdef0, crates tree 0123456789ab.
single run, no repeatability measured.

| Measure | Without sync_gate | With sync_gate |
| --- | --- | --- |
| Jobs lost to memory (confirmed) | 1 | 0 |
| Jobs lost, memory suspected or unexplained | 0 | 0 |
| Jobs completed | 3 | 4 |
| Peak RAM | 97% | 81% |
| Paging file growth | 2048 MB | 2048 MB |
| MCP processes | 10 | 1 |
| MCP memory | 500 MB | 500 MB |
| sync_gate daemon memory | - | 20 MB |
| Total time | 10m00s | 11m00s |
| Cost per command | 8 ms | 70 ms |
| Complete phases | 1 of 1 | 1 of 1 |
";
        assert_eq!(table, expected);
    }

    #[test]
    fn report_of_three_pairs_gives_median_and_range_and_a_chart() {
        let b = bench_of(&[(90.0, 70.0), (97.0, 81.0), (95.0, 75.0)]);
        let table = render_table(&b);
        assert!(table.contains("median of 3 runs"));
        assert!(table.contains("| Peak RAM | 95% (90%-97%) | 75% (70%-81%) |"));
        let svg = render_svg(&b);
        for id in ["id=\"lost\"", "id=\"ram\"", "id=\"mcp\""] {
            assert!(svg.contains(id), "{id}");
        }
        assert!(
            svg.contains("prefers-color-scheme: dark")
                && svg.contains("#ffffff")
                && svg.contains("#0d1117")
        );
        let user =
            std::env::var(if cfg!(windows) { "USERNAME" } else { "USER" }).unwrap_or_default();
        for text in [&table, &svg] {
            assert_eq!(leak(text, Some(&user)), None);
        }
        assert!(leak("see C:\\Users\\x", None).is_some() && leak("/home/a", None).is_some());
    }

    #[test]
    fn report_refuses_a_contaminated_result() {
        let dir = std::env::temp_dir().join(format!("sgbench-rep-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("r.json");
        let mut b = bench_of(&[(90.0, 70.0)]);
        std::fs::write(&file, serde_json::to_string(&b).unwrap()).unwrap();
        let ok = ReportOpts {
            json: file.clone(),
            svg: Some(dir.join("o.svg")),
        };
        assert!(report(&ok).unwrap());
        assert!(dir.join("o.svg").is_file());
        b.contaminated = true;
        std::fs::write(&file, serde_json::to_string(&b).unwrap()).unwrap();
        let bad = ReportOpts {
            json: file,
            svg: None,
        };
        assert!(report(&bad).unwrap_err().contains("contaminated"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn bench_flags_are_read_and_the_rest_refused() {
        let a = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let run = parse(&a(&[
            "run", "--work", "w", "--bin", "b", "--out", "o", "--repeat", "3", "--phase", "with",
        ]));
        let Ok(BenchCmd::Run(r)) = run else {
            panic!("run did not parse")
        };
        assert_eq!(
            (r.repeat, r.phase, r.phase_deadline),
            (3, Which::With, 3600)
        );
        assert!(parse(&a(&["run", "--work", "w", "--bin", "b"])).is_err());
        let bogus = a(&[
            "run", "--work", "w", "--bin", "b", "--out", "o", "--bogus", "1",
        ]);
        assert!(parse(&bogus).is_err());
        assert!(parse(&a(&["setup", "--work", "w"])).is_err());
        let rep = parse(&a(&["report", "r.json", "--svg", "o.svg"]));
        assert!(matches!(rep, Ok(BenchCmd::Report(_))));
        assert!(parse(&a(&["bench"])).is_err());
    }

    fn lane(state: LaneState) -> LaneOut {
        LaneOut {
            name: "l".into(),
            state,
            exit: Some(0),
            secs: 1.0,
            waits: 0,
        }
    }

    // R1 I2: a failed lane or sessions that never came up make the phase incomplete.
    #[test]
    fn a_phase_is_complete_only_with_every_lane_sound_and_every_session_ready() {
        let ok = [lane(LaneState::Done), lane(LaneState::OomConfirmed)];
        assert!(phase_complete(&ok, SESSIONS as u32));
        for bad in [
            LaneState::Failed,
            LaneState::KilledUnexplained,
            LaneState::SpawnFailed,
            LaneState::QueuedTimeout,
        ] {
            let lanes = [lane(LaneState::Done), lane(bad)];
            assert!(!phase_complete(&lanes, SESSIONS as u32), "{bad:?}");
        }
        assert!(!phase_complete(&ok, SESSIONS as u32 - 1));
    }

    // R1 I1: what was measured is saved after every phase and on the error path.
    #[test]
    fn run_pairs_saves_each_phase_and_the_partial_result_on_error() {
        let mut calls = 0;
        let mut saved: Vec<(usize, Option<String>)> = Vec::new();
        let (runs, failure) = run_pairs(
            2,
            &Which::Without,
            |_| {
                calls += 1;
                if calls == 2 {
                    return Err("sessions did not come up".into());
                }
                Ok((phase(0, 4, 50.0, 10, 1.0, 0), None))
            },
            |runs, reason| {
                saved.push((runs.len(), reason));
                Ok(())
            },
        );
        assert_eq!(failure.as_deref(), Some("sessions did not come up"));
        assert_eq!(
            runs.len(),
            1,
            "pair 1 survives, the empty pair 2 is dropped"
        );
        assert!(runs[0].phases.without.is_some());
        let (n, reason) = saved.last().unwrap();
        assert_eq!(*n, 1);
        let reason = reason.as_deref().unwrap();
        assert!(reason.contains("sessions did not come up"));
        // after the first phase the file already held the pair, marked unfinished
        assert_eq!(saved[0].0, 1);
        assert!(saved[0].1.is_some());
    }

    #[test]
    fn run_pairs_ends_complete_only_when_every_phase_is() {
        let mut last = None;
        let (_, failure) = run_pairs(
            1,
            &Which::Both,
            |_| Ok((phase(0, 4, 50.0, 10, 1.0, 0), None)),
            |_, reason| {
                last = Some(reason);
                Ok(())
            },
        );
        assert!(failure.is_none());
        assert_eq!(last, Some(None));
        let mut bad = phase(0, 4, 50.0, 10, 1.0, 0);
        bad.complete = false;
        let mut last = None;
        run_pairs(
            1,
            &Which::Without,
            |_| Ok((bad.clone(), None)),
            |_, reason| {
                last = Some(reason);
                Ok(())
            },
        );
        assert!(last.unwrap().is_some());
    }

    // R1 I3: a settle that ran out of time marks the result suspect and the report says so.
    #[test]
    fn a_settle_timeout_makes_the_result_suspect() {
        let mut b = bench_of(&[(90.0, 80.0)]);
        assert!(!suspect(&b.runs));
        assert!(!render_table(&b).contains("WARNING"));
        b.runs[0].phases.with.as_mut().unwrap().settle_timeout = true;
        b.suspect = suspect(&b.runs);
        assert!(b.suspect);
        assert!(render_table(&b).contains("WARNING: memory had not settled"));
        b.suspect = false;
        b.incomplete_reason = Some("boom".into());
        assert!(render_table(&b).contains("WARNING: incomplete: boom"));
    }

    // R1 minor (a)
    #[test]
    fn the_queue_knobs_go_to_the_json() {
        let o = RunOpts {
            work: "w".into(),
            bin: "b".into(),
            phase: Which::With,
            repeat: 1,
            out: "o".into(),
            reserve_fraction: Some(0.99),
            aging_secs: Some(30),
            first_max_wait: Some(2),
            phase_deadline: 5,
        };
        let mut b = bench_of(&[(90.0, 80.0)]);
        b.knobs = Knobs::of(&o);
        let json = serde_json::to_string(&b).unwrap();
        for part in [
            "\"reserve_fraction\":0.99",
            "\"aging_secs\":30",
            "\"first_max_wait\":2",
            "\"phase_deadline\":5",
        ] {
            assert!(json.contains(part), "{part}");
        }
    }

    // R1 minor (b)
    #[test]
    fn a_spawn_failure_is_not_a_kill() {
        let dir = std::env::temp_dir();
        let job = LaneJob {
            name: "ghost".into(),
            program: dir.join("sync_gate-bench-no-such-program"),
            args: vec![],
            cwd: dir,
            env: vec![],
            proof: Proof::Command(vec![]),
            clean: vec![],
            clean_commands: vec![],
        };
        let shared = Shared {
            deadline: Instant::now() + Duration::from_secs(5),
            queued: None,
            first_max_wait: None,
            roots: Mutex::new(HashMap::new()),
            tree: Mutex::new(HashMap::new()),
        };
        let out = run_lane(&job, &Env::new(), &shared);
        assert_eq!(out.state, LaneState::SpawnFailed);
    }

    // R1 minor (c)
    #[test]
    fn the_svg_draws_no_bar_for_an_absent_phase() {
        let mut b = bench_of(&[(90.0, 80.0)]);
        b.runs[0].phases.with = None;
        let svg = render_svg(&b);
        assert!(!svg.contains("<rect class=\"with\""));
        assert!(svg.contains("<rect class=\"without\""));
    }
}
