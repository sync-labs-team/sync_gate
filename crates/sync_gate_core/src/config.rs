//! Scheduler tunables; every field is optional in TOML and falls back to its default.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};

/// Uses the same override and per-user directory in every executable.
pub fn data_dir() -> Option<PathBuf> {
    std::env::var_os("SYNC_GATE_DATA_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            directories::ProjectDirs::from("dev", "sync_labs", "sync_gate")
                .map(|d| d.data_dir().to_owned())
        })
}

/// Folder of the PATH shims: `<SYNC_GATE_DATA_DIR>/shims`, else `shims` in the per-user local data folder.
pub fn shims_dir() -> Option<PathBuf> {
    shims_dir_from(
        std::env::var_os("SYNC_GATE_DATA_DIR"),
        directories::ProjectDirs::from("dev", "sync_labs", "sync_gate")
            .map(|d| d.data_local_dir().to_owned()),
    )
}

pub fn shims_dir_from(data_override: Option<OsString>, local: Option<PathBuf>) -> Option<PathBuf> {
    data_override
        .map(PathBuf::from)
        .or(local)
        .map(|d| d.join("shims"))
}

/// Upper bound for any queue wait (config or `--max-wait`): one day. Keeps `Instant` additions finite.
pub const MAX_WAIT_SECS: u64 = 86_400;

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default)]
pub struct Config {
    pub reserve_fraction: f64,
    pub optimism: f64,
    pub max_wait_secs: u64,
    pub aging_secs: u64,
    pub tick_ms: u64,
    /// MCP servers, from `[mcp.<name>]` tables.
    pub mcp: BTreeMap<String, McpServer>,
    /// Shared PostgreSQL service, from `[postgres]` and `[[postgres.project]]`; `None` = not configured.
    pub postgres: Option<PgConfig>,
    /// Windows: who else may queue commands here. A local account name (the Codex `elevated`
    /// sandbox accounts), "@appcontainer" (your own account in an AppContainer: Codex `mxc`), or
    /// "@restricted" (your own account with a write-restricted token: Codex `unelevated`).
    /// Empty: nobody but you. Ignored elsewhere.
    pub guests: Vec<String>,
    /// Days between looks at the latest release on GitHub (one anonymous GET); 0 = never.
    pub update_check_days: u64,
}

/// The shared PostgreSQL server the daemon owns: one database and role per `sync_gate run` lease.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PgConfig {
    /// Absolute path of the PostgreSQL `bin` directory.
    pub bin_dir: PathBuf,
    pub port: u16,
    pub max_leases: u32,
    pub connections_per_lease: u32,
    pub idle_stop_secs: u64,
    /// How long the CLI waits at most for a lease (server ready, queue and grant steps together).
    pub lease_wait_secs: u64,
    pub project: Vec<PgProject>,
}

impl Default for PgConfig {
    fn default() -> Self {
        Self {
            bin_dir: PathBuf::new(),
            port: 28543,
            max_leases: 8,
            connections_per_lease: 25,
            idle_stop_secs: 600,
            lease_wait_secs: 30,
            project: Vec::new(),
        }
    }
}

/// A project directory whose matching commands get a database of their own.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PgProject {
    pub dir: PathBuf,
    /// Command prefixes (`npm test`); empty matches any command.
    #[serde(default)]
    pub commands: Vec<String>,
    /// Environment variables that receive the connection URL.
    #[serde(default = "default_url_vars")]
    pub url_vars: Vec<String>,
    /// Migration command (argv, no shell) run once per template; needs `watch`.
    #[serde(default)]
    pub migrate: Vec<String>,
    /// Files or folders, relative to `dir`, whose contents key the template database.
    #[serde(default)]
    pub watch: Vec<String>,
    #[serde(default = "default_migrate_timeout")]
    pub migrate_timeout_secs: u64,
    /// PostgreSQL extensions created in every database lent to this project.
    #[serde(default)]
    pub extensions: Vec<String>,
}

/// A name for `project.extensions`: `[a-z_][a-z0-9_-]{0,62}`.
pub fn is_extension_name(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=63).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'-'))
}

fn default_migrate_timeout() -> u64 {
    300
}

fn default_url_vars() -> Vec<String> {
    vec!["DATABASE_URL".into()]
}

/// Path components for ancestry checks (no lossy conversion: distinct bytes stay distinct).
fn components(p: &Path) -> Vec<OsString> {
    p.components()
        .filter(|c| !matches!(c, Component::CurDir))
        .map(|c| c.as_os_str().to_os_string())
        .collect()
}

/// Unix compares bytes. Windows folds ASCII case, but only when both sides are valid Unicode.
fn component_eq(a: &OsStr, b: &OsStr) -> bool {
    match (cfg!(windows), a.to_str(), b.to_str()) {
        (true, Some(x), Some(y)) => x.eq_ignore_ascii_case(y),
        _ => a == b,
    }
}

/// The extensions of `PATHEXT` (dot included, as written); `.COM;.EXE;.BAT;.CMD` when unset or empty.
pub fn pathext_list(pathext: Option<&OsStr>) -> Vec<String> {
    let list: Vec<String> = pathext
        .and_then(OsStr::to_str)
        .unwrap_or_default()
        .split(';')
        .filter(|e| e.len() > 1 && e.starts_with('.'))
        .map(String::from)
        .collect();
    if list.is_empty() {
        return [".COM", ".EXE", ".BAT", ".CMD"].map(String::from).into();
    }
    list
}

/// Windows only: a program name without its `PATHEXT` extension and folded to lower case, so
/// `npm`, `npm.cmd` and `NPM.CMD` are one command.
pub fn program_key(word: &str, exts: &[String]) -> String {
    let stem = match word.rfind('.') {
        Some(dot) if dot > 0 && exts.iter().any(|e| e.eq_ignore_ascii_case(&word[dot..])) => {
            &word[..dot]
        }
        _ => word,
    };
    stem.to_ascii_lowercase()
}

/// Whether `argv` starts with the configured command `c`, ending on a word boundary: `npm test`
/// matches `npm test -u` but not `npm testx`. The first word of `c` is the program: a bare name is
/// `argv[0]`'s file name (the shims and `sync_gate run` hand over the resolved path), a word with a
/// folder part is the whole `argv[0]`. On Windows the program ignores case and a `PATHEXT`
/// extension; the rest compares as written.
fn command_matches(c: &str, argv: &[String], exts: &[String]) -> bool {
    let Some(program) = argv.first() else {
        return false;
    };
    let (word, tail) = c.split_at(c.find(' ').unwrap_or(c.len()));
    let seps: &[char] = if cfg!(windows) {
        &['/', '\\', ':']
    } else {
        &['/']
    };
    let program = if word.contains(seps) {
        program.as_str()
    } else {
        program.rsplit(seps).next().unwrap_or(program)
    };
    let same = if cfg!(windows) {
        program_key(program, exts) == program_key(word, exts)
    } else {
        program == word
    };
    let args = argv[1..].iter().fold(String::new(), |a, x| a + " " + x);
    same && args
        .strip_prefix(tail)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with(' '))
}

fn same_components(a: &[OsString], b: &[OsString]) -> bool {
    a.len() == b.len() && is_ancestor(a, b)
}

/// `dir` is `cwd` or one of its ancestors.
fn is_ancestor(dir: &[OsString], cwd: &[OsString]) -> bool {
    dir.len() <= cwd.len() && dir.iter().zip(cwd).all(|(d, c)| component_eq(d, c))
}

impl PgConfig {
    /// The project whose `dir` is the deepest ancestor of `cwd` and whose `commands` match `argv`.
    pub fn project_for(&self, cwd: &Path, argv: &[String]) -> Option<&PgProject> {
        let cwd = components(cwd);
        let exts = pathext_list(std::env::var_os("PATHEXT").as_deref());
        self.project
            .iter()
            .filter(|p| {
                let dir = components(&p.dir);
                is_ancestor(&dir, &cwd)
                    && (p.commands.is_empty()
                        || p.commands.iter().any(|c| command_matches(c, argv, &exts)))
            })
            .max_by_key(|p| components(&p.dir).len())
    }

    /// Server `max_connections`: every lease's share plus headroom for the administrator.
    pub fn max_connections(&self) -> u32 {
        self.max_leases * self.connections_per_lease + 5
    }
}

/// At most this many `guests`.
pub const MAX_GUESTS: usize = 8;
/// The reserved `guests` entry for this account inside an AppContainer (Codex `mxc`).
pub const APPCONTAINER_GUEST: &str = "@appcontainer";
/// The reserved `guests` entry for this account with a write-restricted token (Codex `unelevated`).
pub const RESTRICTED_GUEST: &str = "@restricted";

fn guests_error(guests: &[String]) -> Option<String> {
    if guests.len() > MAX_GUESTS {
        return Some(format!("[guests] at most {MAX_GUESTS} entries"));
    }
    let mut seen: Vec<String> = Vec::new();
    for g in guests {
        let key = if g == APPCONTAINER_GUEST || g == RESTRICTED_GUEST {
            g.clone()
        } else if g.is_empty()
            || g.len() > 64
            || !g
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        {
            return Some(
                "[guests] each entry is a local account name ([A-Za-z0-9_.-], 1 to 64 characters), \"@appcontainer\" or \"@restricted\""
                    .into(),
            );
        } else {
            crate::protocol::sanitize_user(g).to_lowercase()
        };
        if key.is_empty() || seen.contains(&key) {
            return Some(format!(
                "[guests] \"{g}\" is empty or repeats another entry"
            ));
        }
        seen.push(key);
    }
    None
}

fn pg_error(pg: &PgConfig) -> Option<String> {
    let msg = if pg.bin_dir.as_os_str().is_empty() || !pg.bin_dir.is_absolute() {
        "bin_dir must be an absolute path"
    } else if pg.port < 1024 {
        "port must be >= 1024"
    } else if !(1..=64).contains(&pg.max_leases) {
        "max_leases must be in 1..=64"
    } else if !(1..=1000).contains(&pg.connections_per_lease) {
        "connections_per_lease must be in 1..=1000"
    } else if pg.idle_stop_secs > MAX_WAIT_SECS {
        "idle_stop_secs must be <= 86400"
    } else if !(1..=300).contains(&pg.lease_wait_secs) {
        "lease_wait_secs must be in 1..=300"
    } else {
        return pg_project_error(&pg.project).map(|m| format!("[postgres] {m}"));
    };
    Some(format!("[postgres] {msg}"))
}

fn pg_project_error(projects: &[PgProject]) -> Option<&'static str> {
    for (i, p) in projects.iter().enumerate() {
        if p.dir.as_os_str().is_empty() || !p.dir.is_absolute() {
            return Some("project.dir must be an absolute path");
        }
        if projects[..i]
            .iter()
            .any(|q| same_components(&components(&q.dir), &components(&p.dir)))
        {
            return Some("two projects have the same dir");
        }
        if p.commands.iter().any(|c| c.trim().is_empty()) {
            return Some("project.commands must not contain an empty entry");
        }
        if !p.url_vars.iter().all(|v| valid_env_name(v)) {
            return Some(
                "project.url_vars must match [A-Za-z_][A-Za-z0-9_]{0,63} and not start with PG",
            );
        }
        if p.migrate.is_empty() != p.watch.is_empty() {
            return Some("project.migrate and project.watch must be set together");
        }
        if p.migrate.first().is_some_and(|a| a.trim().is_empty()) {
            return Some("project.migrate must start with a program name");
        }
        if p.watch.iter().any(|w| !valid_watch_path(w)) {
            return Some("project.watch must be relative paths without empty, . or .. parts");
        }
        if p.watch.len() > 64 {
            return Some("project.watch must have at most 64 entries");
        }
        if !(1..=3600).contains(&p.migrate_timeout_secs) {
            return Some("project.migrate_timeout_secs must be in 1..=3600");
        }
        if !p.extensions.iter().all(|e| is_extension_name(e)) {
            return Some("project.extensions must be names matching [a-z_][a-z0-9_-]{0,62}");
        }
        if p.extensions.len() > 16 {
            return Some("project.extensions must have at most 16 entries");
        }
        if p.extensions
            .iter()
            .enumerate()
            .any(|(i, e)| p.extensions[..i].contains(e))
        {
            return Some("project.extensions must not repeat a name");
        }
    }
    None
}

/// Relative, `/` or `\` separated, no empty/`.`/`..` part, no `:` (drive letters).
fn valid_watch_path(w: &str) -> bool {
    !w.contains(':') && w.split(['/', '\\']).all(|c| !matches!(c, "" | "." | ".."))
}

fn valid_env_name(v: &str) -> bool {
    let b = v.as_bytes();
    (1..=64).contains(&b.len())
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
        && !v.get(..2).is_some_and(|p| p.eq_ignore_ascii_case("pg"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
pub enum McpMode {
    #[serde(rename = "shared")]
    Shared,
    #[default]
    #[serde(rename = "per-session")]
    PerSession,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct McpServer {
    pub command: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    /// Names of variables copied from the client's environment.
    pub env_from: Vec<String>,
    /// Working directory; the literal `"inherit"` means the client's.
    pub cwd: Option<String>,
    pub mode: McpMode,
    pub max_instances: u32,
    pub max_in_flight: u32,
    pub request_timeout_secs: u64,
    pub idle_stop_secs: u64,
}

impl Default for McpServer {
    fn default() -> Self {
        Self {
            command: String::new(),
            args: Vec::new(),
            env: BTreeMap::new(),
            env_from: Vec::new(),
            cwd: None,
            mode: McpMode::default(),
            max_instances: 3,
            max_in_flight: 8,
            request_timeout_secs: 300,
            idle_stop_secs: 600,
        }
    }
}

impl McpServer {
    pub fn inherits_cwd(&self) -> bool {
        self.cwd.as_deref() == Some("inherit")
    }
}

/// The names a `[mcp.<name>]` section accepts.
pub fn is_mcp_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn mcp_error(name: &str, s: &McpServer) -> Option<String> {
    // One precedence for hub and direct mode: a name is either fixed or forwarded, never both.
    if let Some(var) = s.env_from.iter().find(|v| s.env.contains_key(*v)) {
        return Some(format!("mcp.{name}: {var} is in both env and env_from"));
    }
    let msg = if !is_mcp_name(name) {
        Some("name must match [A-Za-z0-9_-]{1,64}")
    } else if s.command.trim().is_empty() {
        Some("command must not be empty")
    } else if !(1..=16).contains(&s.max_instances) {
        Some("max_instances must be in 1..=16")
    } else if !(1..=1024).contains(&s.max_in_flight) {
        Some("max_in_flight must be in 1..=1024")
    } else if !(1..=MAX_WAIT_SECS).contains(&s.request_timeout_secs) {
        Some("request_timeout_secs must be in 1..=86400")
    } else if s.idle_stop_secs > MAX_WAIT_SECS {
        Some("idle_stop_secs must be <= 86400")
    } else {
        None
    };
    msg.map(|m| format!("[mcp.{name}] {m}"))
}

impl Default for Config {
    fn default() -> Self {
        Self {
            reserve_fraction: 0.10,
            optimism: 1.25,
            max_wait_secs: 90,
            aging_secs: 20,
            tick_ms: 500,
            mcp: BTreeMap::new(),
            postgres: None,
            guests: Vec::new(),
            update_check_days: crate::update::DEFAULT_DAYS,
        }
    }
}

/// Why a config did not load, in words that carry nothing of the file or of the parser's own
/// text (both can hold a secret): a category and, when the parser gives one, a line and column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigLoadError {
    category: &'static str,
    at: Option<(usize, usize)>,
}

impl ConfigLoadError {
    /// From a failed [`Config::from_toml`] of `text`.
    pub fn parse(text: &str, e: &toml::de::Error) -> Self {
        let at = e.span().and_then(|s| {
            let before = text.get(..s.start)?;
            let line = before.matches('\n').count() + 1;
            let col = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
            Some((line, col))
        });
        let category = if at.is_some() {
            "syntax or type error"
        } else {
            "invalid setting"
        };
        Self { category, at }
    }

    /// The file exists but could not be read.
    pub fn unreadable() -> Self {
        Self {
            category: "file cannot be read",
            at: None,
        }
    }
}

impl std::fmt::Display for ConfigLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.at {
            Some((l, c)) => write!(
                f,
                "config did not load: {} at line {l}, column {c}",
                self.category
            ),
            None => write!(f, "config did not load ({})", self.category),
        }
    }
}

impl Config {
    pub fn from_toml(s: &str) -> Result<Config, toml::de::Error> {
        let c: Config = match toml::from_str(s) {
            Ok(c) => c,
            Err(e) => {
                // A malformed `[postgres]` value reads like a validation error; `[mcp]` type errors stay raw TOML.
                if let Ok(doc) = toml::from_str::<toml::Table>(s)
                    && let Some(pg) = doc.get("postgres")
                    && let Err(pe) = pg.clone().try_into::<PgConfig>()
                {
                    return Err(<toml::de::Error as serde::de::Error>::custom(format!(
                        "[postgres] {pe}"
                    )));
                }
                return Err(e);
            }
        };
        let bad: Option<String> = if c.aging_secs == 0 {
            Some("aging_secs must be > 0".into())
        } else if c.tick_ms == 0 {
            Some("tick_ms must be > 0".into())
        } else if !c.optimism.is_finite() || c.optimism <= 0.0 {
            Some("optimism must be finite and > 0".into())
        } else if !(0.0..1.0).contains(&c.reserve_fraction) {
            Some("reserve_fraction must be in [0, 1)".into())
        } else if c.max_wait_secs > MAX_WAIT_SECS {
            Some("max_wait_secs must be <= 86400".into())
        } else if let Some(m) = guests_error(&c.guests) {
            Some(m)
        } else {
            c.mcp
                .iter()
                .find_map(|(n, s)| mcp_error(n, s))
                .or_else(|| c.postgres.as_ref().and_then(pg_error))
        };
        match bad {
            Some(m) => Err(<toml::de::Error as serde::de::Error>::custom(m)),
            None => Ok(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_check_days_defaults_to_a_week_and_zero_turns_it_off() {
        assert_eq!(Config::default().update_check_days, 7);
        assert_eq!(Config::from_toml("").unwrap().update_check_days, 7);
        assert_eq!(
            Config::from_toml("update_check_days = 0")
                .unwrap()
                .update_check_days,
            0
        );
    }
    use std::path::PathBuf;

    fn guests_toml(list: &[&str]) -> String {
        let items: Vec<String> = list.iter().map(|g| format!("{g:?}")).collect();
        format!("guests = [{}]", items.join(", "))
    }

    #[test]
    fn guests_take_local_account_names_and_the_two_kinds() {
        let ok = [
            "CodexSandboxOffline",
            "CodexSandboxOnline",
            "@appcontainer",
            "@restricted",
        ];
        let c = Config::from_toml(&guests_toml(&ok)).unwrap();
        assert_eq!(c.guests, ok);
        let long = "a".repeat(65);
        let nine: Vec<String> = (0..9).map(|i| format!("u{i}")).collect();
        let nine: Vec<&str> = nine.iter().map(String::as_str).collect();
        let bad: Vec<Vec<&str>> = vec![
            vec![""],
            vec!["ACMEPC\\x"],
            vec!["a b"],
            vec![long.as_str()],
            nine,
            vec!["a", "A"],
            vec!["a.b", "ab"],
            vec!["@other"],
            vec!["@"],
            vec!["@restricted", "@restricted"],
        ];
        for b in bad {
            let e = Config::from_toml(&guests_toml(&b)).unwrap_err().to_string();
            assert!(e.contains("[guests]"), "{b:?}: {e}");
        }
        // Controls: the limits themselves are accepted.
        let sixty_four = "a".repeat(64);
        assert!(Config::from_toml(&guests_toml(&[sixty_four.as_str()])).is_ok());
        let eight = ["u0", "u1", "u2", "u3", "u4", "u5", "u6", "u7"];
        assert!(Config::from_toml(&guests_toml(&eight)).is_ok());
        assert!(Config::default().guests.is_empty());
        assert_eq!(Config::from_toml("").unwrap(), Config::default());
    }

    #[test]
    fn shims_dir_uses_the_override_then_local_data() {
        let local = Some(PathBuf::from("local"));
        assert_eq!(
            shims_dir_from(Some("over".into()), local.clone()),
            Some(PathBuf::from("over").join("shims"))
        );
        assert_eq!(
            shims_dir_from(None, local),
            Some(PathBuf::from("local").join("shims"))
        );
        assert_eq!(shims_dir_from(None, None), None);
    }

    #[test]
    fn missing_fields_take_defaults() {
        let c = Config::from_toml("optimism = 2.0").unwrap();
        assert_eq!(c.optimism, 2.0);
        assert_eq!(c.aging_secs, 20);
        assert_eq!(Config::from_toml("").unwrap(), Config::default());
    }

    #[test]
    fn bad_input_is_an_error_not_a_panic() {
        assert!(Config::from_toml("optimism = \"x\"").is_err());
        assert!(Config::from_toml("not toml [[").is_err());
    }

    #[test]
    fn rejects_values_that_disable_the_scheduler() {
        for bad in [
            "aging_secs = 0",
            "optimism = 0.0",
            "optimism = -1.0",
            "optimism = nan",
            "optimism = inf",
            "reserve_fraction = -0.1",
            "reserve_fraction = 1.0",
            "reserve_fraction = nan",
            "tick_ms = 0",
            "max_wait_secs = 86401",
        ] {
            assert!(Config::from_toml(bad).is_err(), "{bad} should be rejected");
        }
        assert!(Config::from_toml("reserve_fraction = 0.0").is_ok());
        assert!(Config::from_toml("max_wait_secs = 86400").is_ok());
    }

    #[test]
    fn parses_mcp_servers_with_defaults() {
        let c = Config::from_toml(
            "[mcp.docs]
command = \"npx\"
args = [\"-y\", \"docs-mcp\"]
mode = \"shared\"
env_from = [\"DOCS_TOKEN\"]

[mcp.browser]
command = \"browser-mcp\"
",
        )
        .unwrap();
        assert_eq!(c.mcp["docs"].mode, McpMode::Shared);
        assert_eq!(c.mcp["docs"].max_instances, 3);
        assert_eq!(c.mcp["docs"].max_in_flight, 8);
        assert_eq!(c.mcp["docs"].request_timeout_secs, 300);
        assert_eq!(c.mcp["docs"].idle_stop_secs, 600);
        assert_eq!(c.mcp["browser"].mode, McpMode::PerSession);
        assert!(!c.mcp["browser"].inherits_cwd());
    }

    #[test]
    fn mcp_cwd_inherit() {
        let c = Config::from_toml(
            "[mcp.a]
command=\"x\"
cwd=\"inherit\"",
        )
        .unwrap();
        assert!(c.mcp["a"].inherits_cwd());
    }

    #[test]
    fn no_mcp_table_is_empty() {
        assert!(Config::from_toml("").unwrap().mcp.is_empty());
    }

    #[test]
    fn rejects_bad_mcp_values() {
        let long = format!(
            "[mcp.{}]
command=\"x\"",
            "a".repeat(65)
        );
        for bad in [
            "[mcp.\"a b\"]
command=\"x\"",
            "[mcp.a]
command=\"\"",
            "[mcp.a]
command=\"x\"
max_instances=0",
            "[mcp.a]
command=\"x\"
max_instances=17",
            "[mcp.a]
command=\"x\"
max_in_flight=0",
            "[mcp.a]
command=\"x\"
max_in_flight=1025",
            "[mcp.a]
command=\"x\"
request_timeout_secs=0",
            "[mcp.a]
command=\"x\"
request_timeout_secs=86401",
            "[mcp.a]
command=\"x\"
idle_stop_secs=86401",
            long.as_str(),
        ] {
            assert!(Config::from_toml(bad).is_err(), "{bad}");
        }
        assert!(
            Config::from_toml(
                "[mcp.a-b_1]
command=\"x\"
idle_stop_secs=0"
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_unknown_mcp_keys_but_not_top_level_ones() {
        for typo in ["env_form", "max_instance", "modee"] {
            let t = format!(
                "[mcp.a]
command=\"x\"
{typo} = \"shared\""
            );
            assert!(Config::from_toml(&t).is_err(), "{typo}");
        }
        assert!(Config::from_toml("future_key = 1").is_ok());
    }

    #[test]
    fn mcp_errors_name_the_server() {
        let e = Config::from_toml(
            "[mcp.docs]
command=\"\"",
        )
        .unwrap_err();
        assert!(
            e.to_string()
                .contains("[mcp.docs] command must not be empty"),
            "{e}"
        );
    }

    #[test]
    fn a_name_in_both_env_and_env_from_is_rejected() {
        let e = Config::from_toml(
            "[mcp.docs]
command=\"x\"
env={DOCS_TOKEN=\"fixed\"}
env_from=[\"DOCS_TOKEN\"]",
        )
        .unwrap_err();
        assert!(
            e.to_string()
                .contains("mcp.docs: DOCS_TOKEN is in both env and env_from"),
            "{e}"
        );
    }

    /// Fixtures must be absolute on every platform: `/x` is relative on Windows.
    fn abs(rest: &str) -> String {
        format!("{}{rest}", if cfg!(windows) { "C:" } else { "" })
    }

    fn pg_toml(extra: &str) -> String {
        format!(
            "[postgres]\nbin_dir = \"{}\"\n{extra}\n[[postgres.project]]\ndir = \"{}\"\ncommands = [\"npm test\"]\n",
            abs("/opt/pg/17/bin"),
            abs("/r/api")
        )
    }

    #[test]
    fn parses_postgres_with_defaults() {
        let c = Config::from_toml(&pg_toml("")).unwrap();
        let pg = c.postgres.unwrap();
        assert_eq!(
            (
                pg.port,
                pg.max_leases,
                pg.connections_per_lease,
                pg.idle_stop_secs,
                pg.lease_wait_secs
            ),
            (28543, 8, 25, 600, 30)
        );
        assert_eq!(pg.project[0].url_vars, vec!["DATABASE_URL"]);
        assert_eq!(pg.max_connections(), 205);
    }

    #[test]
    fn migrate_defaults() {
        let c = Config::from_toml(&pg_toml("")).unwrap().postgres.unwrap();
        let p = &c.project[0];
        assert!(p.migrate.is_empty() && p.watch.is_empty());
        assert_eq!(p.migrate_timeout_secs, 300);
    }

    #[test]
    fn no_postgres_table_is_none() {
        assert!(Config::from_toml("").unwrap().postgres.is_none());
    }

    #[test]
    fn rejects_bad_postgres_values() {
        let bin = abs("/opt/pg/17/bin");
        let dir = abs("/r/api");
        let head = format!("[postgres]\nbin_dir = \"{bin}\"\n");
        let proj = format!("[[postgres.project]]\ndir = \"{dir}\"\n");
        let cases = [
            "[postgres]\nbin_dir = \"\"\n".to_string(),
            "[postgres]\nbin_dir = \"rel/bin\"\n".to_string(),
            "[postgres]\n".to_string(),
            format!("{head}port = 1023\n"),
            format!("{head}max_leases = 0\n"),
            format!("{head}max_leases = 65\n"),
            format!("{head}connections_per_lease = 0\n"),
            format!("{head}connections_per_lease = 1001\n"),
            format!("{head}idle_stop_secs = 86401\n"),
            format!("{head}lease_wait_secs = 0\n"),
            format!("{head}lease_wait_secs = 301\n"),
            format!("{head}[[postgres.project]]\ndir = \"\"\n"),
            format!("{head}[[postgres.project]]\ndir = \"r/api\"\n"),
            format!("{head}{proj}{proj}"),
            format!("{head}{proj}commands = [\"npm test\", \" \"]\n"),
            format!("{head}{proj}url_vars = [\"1BAD\"]\n"),
            format!("{head}{proj}url_vars = [\"A-B\"]\n"),
            format!("{head}{proj}url_vars = [\"\"]\n"),
            format!("{head}{proj}url_vars = [\"{}\"]\n", "A".repeat(65)),
            format!("{head}{proj}url_vars = [\"PGPASSWORD\"]\n"),
            format!("{head}{proj}url_vars = [\"pgpassword\"]\n"),
            format!("{head}{proj}url_vars = [\"PgPassword\"]\n"),
            format!("{head}{proj}url_vars = [\"Pghost\"]\n"),
            format!("{head}port = -1\n"),
            format!("{head}max_leases = -1\n"),
            format!("{head}connections_per_lease = -1\n"),
            format!("{head}lease_wait_secs = -1\n"),
            format!("{head}port = \"x\"\n"),
            format!("{head}{proj}commands = \"npm test\"\n"),
            format!("{head}{proj}derived = [\"test_{{db}}\"]\n"),
            format!("{head}{proj}parallel = 2\n"),
            format!("{head}{proj}migrate = [\"x\"]\n"),
            format!("{head}{proj}watch = [\"db\"]\n"),
            format!("{head}{proj}migrate = [\"\"]\nwatch = [\"db\"]\n"),
            format!("{head}{proj}migrate = [\"x\"]\nwatch = [\"../db\"]\n"),
            format!("{head}{proj}migrate = [\"x\"]\nwatch = [\"/abs\"]\n"),
            format!("{head}{proj}migrate = [\"x\"]\nwatch = [\"C:/abs\"]\n"),
            format!("{head}{proj}migrate = [\"x\"]\nwatch = [\"a//b\"]\n"),
            format!("{head}{proj}migrate = [\"x\"]\nwatch = [\"\"]\n"),
            format!("{head}{proj}migrate = [\"x\"]\nwatch = [\"a/./b\"]\n"),
            format!("{head}{proj}migrate_timeout_secs = 0\n"),
            format!("{head}{proj}migrate_timeout_secs = 3601\n"),
            format!(
                "{head}{proj}migrate = [\"x\"]\nwatch = [{}]\n",
                (0..65)
                    .map(|i| format!("\"w{i}\""))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            format!("{head}what = 1\n"),
        ];
        for bad in &cases {
            let e = Config::from_toml(bad).expect_err(bad).to_string();
            assert!(
                e.contains("[postgres]") || e.contains("unknown field"),
                "{bad}: {e}"
            );
        }
        for ok in [
            "lease_wait_secs = 1",
            "lease_wait_secs = 300",
            "port = 1024",
            "port = 65535",
            "max_leases = 1",
            "max_leases = 64",
            "connections_per_lease = 1",
            "connections_per_lease = 1000",
            "idle_stop_secs = 0",
            "idle_stop_secs = 86400",
        ] {
            assert!(Config::from_toml(&pg_toml(ok)).is_ok(), "{ok}");
        }
        for extra in [
            "migrate_timeout_secs = 3600",
            "migrate = [\"npm\",\"run\",\"migrate\"]\nwatch = [\"db/migrations\",\"schema.sql\"]",
            "migrate = [\"npm\",\"run\",\"migrate\"]\nwatch = [\"db\\\\migrations\"]",
        ] {
            let t = format!("{head}{proj}{extra}\n");
            assert!(Config::from_toml(&t).is_ok(), "{extra}");
        }
        let long = format!("A{}", "b".repeat(63));
        for names in [
            "\"_X1\", \"DB_URL\"",
            "\"MY_PG_URL\"",
            &format!("\"{long}\""),
        ] {
            let url_ok = format!("{head}{proj}url_vars = [{names}]\n");
            assert!(Config::from_toml(&url_ok).is_ok(), "{names}");
        }
    }

    #[test]
    fn extensions_are_parsed_and_validated() {
        let t = |list: &str| format!("{}extensions = [{list}]\n", pg_toml(""));
        let pg = Config::from_toml(&t("\"pg_trgm\", \"uuid-ossp\", \"_x9\""))
            .unwrap()
            .postgres
            .unwrap();
        assert_eq!(pg.project[0].extensions, ["pg_trgm", "uuid-ossp", "_x9"]);
        let none = Config::from_toml(&pg_toml("")).unwrap().postgres.unwrap();
        assert!(none.project[0].extensions.is_empty());
        let longest = format!("\"a{}\"", "b".repeat(62));
        let sixteen = (0..16).map(|i| format!("\"e{i}\"")).collect::<Vec<_>>();
        for ok in [longest.as_str(), &sixteen.join(","), ""] {
            assert!(Config::from_toml(&t(ok)).is_ok(), "{ok}");
        }
        let names = "[postgres] project.extensions must be names matching [a-z_][a-z0-9_-]{0,62}";
        let too_long = format!("\"a{}\"", "b".repeat(63));
        for bad in [
            "\"\"",
            "\"PG_TRGM\"",
            "\"1x\"",
            "\"-x\"",
            "\"pg trgm\"",
            "\"a\\\"b\"",
            "\"a;b\"",
            "\"\u{e9}\"",
            too_long.as_str(),
        ] {
            let e = Config::from_toml(&t(bad)).expect_err(bad).to_string();
            assert!(e.contains(names), "{bad}: {e}");
        }
        let seventeen = (0..17).map(|i| format!("\"e{i}\"")).collect::<Vec<_>>();
        let e = Config::from_toml(&t(&seventeen.join(",")))
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("[postgres] project.extensions must have at most 16 entries"),
            "{e}"
        );
        let e = Config::from_toml(&t("\"pg_trgm\", \"citext\", \"pg_trgm\""))
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("[postgres] project.extensions must not repeat a name"),
            "{e}"
        );
    }

    fn two_projects() -> PgConfig {
        let t = format!(
            "[postgres]\nbin_dir = \"{}\"\n\
             [[postgres.project]]\ndir = \"{}\"\ncommands = [\"npm test\"]\n\
             [[postgres.project]]\ndir = \"{}\"\n",
            abs("/opt/pg/17/bin"),
            abs("/r/api"),
            abs("/r")
        );
        Config::from_toml(&t).unwrap().postgres.unwrap()
    }

    fn argv(s: &str) -> Vec<String> {
        s.split(' ').map(String::from).collect()
    }

    #[test]
    fn project_for_picks_the_deepest_dir_and_matches_command_prefixes() {
        let pg = two_projects();
        let deep = PathBuf::from(abs("/r/api/src"));
        let found = pg.project_for(&deep, &argv("npm test -- -u")).unwrap();
        assert_eq!(found.dir, PathBuf::from(abs("/r/api")));
        let exact = pg.project_for(&deep, &argv("npm test")).unwrap();
        assert_eq!(exact.dir, PathBuf::from(abs("/r/api")));
        // "npm testx" is not "npm test": the deep project does not match, the shallow one (any command) does.
        let other = pg.project_for(&deep, &argv("npm testx")).unwrap();
        assert_eq!(other.dir, PathBuf::from(abs("/r")));
        // a sibling of /r/api falls to /r, whose empty `commands` matches anything
        let sib = PathBuf::from(abs("/r/web"));
        assert_eq!(
            pg.project_for(&sib, &argv("anything at all")).unwrap().dir,
            PathBuf::from(abs("/r"))
        );
        // "/rx" shares a string prefix with "/r" but is not under it
        assert!(
            pg.project_for(&PathBuf::from(abs("/rx")), &argv("npm test"))
                .is_none()
        );
        assert!(
            pg.project_for(&PathBuf::from(abs("/x")), &argv("npm test"))
                .is_none()
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_prefixes_ignore_the_extension_and_case() {
        let t = format!(
            "[postgres]\nbin_dir = \"{}\"\n\
             [[postgres.project]]\ndir = \"{}\"\ncommands = [\"npm run test:e2e\"]\n",
            abs("/opt/pg/17/bin"),
            abs("/r")
        );
        let pg = Config::from_toml(&t).unwrap().postgres.unwrap();
        let cwd = PathBuf::from(abs("/r"));
        for line in [
            "npm run test:e2e",
            "npm.cmd run test:e2e",
            "NPM.CMD run test:e2e",
        ] {
            assert!(pg.project_for(&cwd, &argv(line)).is_some(), "{line}");
        }
        assert!(
            pg.project_for(&cwd, &argv("npm run test:e2e:full"))
                .is_none()
        );
        assert!(pg.project_for(&cwd, &argv("npm.cmd run test")).is_none());
        assert!(pg.project_for(&cwd, &argv("npmx run test:e2e")).is_none());
        // `argv[0]` is one program name, even with a space in it: not `npm` plus an argument.
        let spaced: Vec<String> = ["npm.cmd run", "test:e2e"].map(String::from).into();
        assert!(pg.project_for(&cwd, &spaced).is_none());
    }

    #[test]
    fn a_bare_filter_matches_the_resolved_program_by_its_file_name() {
        // The shims and `sync_gate run` hand over `argv[0]` as the resolved path of the program.
        let exts = pathext_list(None);
        let m = |c: &str, a: &[&str]| {
            command_matches(
                c,
                &a.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                &exts,
            )
        };
        #[cfg(unix)]
        {
            assert!(m("npm test", &["/usr/bin/npm", "test", "-u"]));
            assert!(m("npm", &["/usr/bin/npm"]));
            assert!(m("npm test", &["npm", "test"]));
            assert!(!m("npm test", &["/usr/bin/npmx", "test"]));
            assert!(!m("npm test", &["/usr/bin/npm", "testx"]));
            // A filter that names a path means that file only.
            assert!(m("/usr/bin/npm test", &["/usr/bin/npm", "test"]));
            assert!(!m("/opt/npm test", &["/usr/bin/npm", "test"]));
            assert!(!m("bin/npm", &["/usr/bin/npm"]));
        }
        #[cfg(windows)]
        {
            let npm = r"C:\Program Files\nodejs\NPM.CMD";
            assert!(m("npm test", &[npm, "test", "-u"]));
            assert!(m("pytest", &[r"C:\x\pytest.exe"]));
            assert!(m("npm test", &["C:/x/npm.cmd", "test"]));
            assert!(!m("npm test", &[r"C:\x\npmx.cmd", "test"]));
            assert!(!m("npm test", &[npm, "testx"]));
            // A filter that names a path means that file only (case and extension aside).
            assert!(m(r"C:\x\npm test", &[r"c:\X\npm.cmd", "test"]));
            assert!(!m(r"C:\y\npm test", &[r"C:\x\npm.cmd", "test"]));
        }
    }

    fn bare_project(dir: PathBuf) -> PgConfig {
        PgConfig {
            project: vec![PgProject {
                dir,
                commands: Vec::new(),
                url_vars: default_url_vars(),
                migrate: Vec::new(),
                watch: Vec::new(),
                migrate_timeout_secs: default_migrate_timeout(),
                extensions: Vec::new(),
            }],
            ..PgConfig::default()
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_path_components_are_not_conflated_with_replacement_chars() {
        use std::os::unix::ffi::OsStringExt;
        let pg = bare_project(PathBuf::from("/r/ap\u{FFFD}"));
        let mut bytes = b"/r/ap".to_vec();
        bytes.push(0xff);
        let cwd = PathBuf::from(std::ffi::OsString::from_vec(bytes));
        assert!(pg.project_for(&cwd, &argv("x")).is_none());
        assert!(
            pg.project_for(Path::new("/r/ap\u{FFFD}/s"), &argv("x"))
                .is_some()
        );
    }

    #[cfg(windows)]
    #[test]
    fn non_unicode_path_components_are_not_conflated_on_windows() {
        use std::os::windows::ffi::OsStringExt;
        let pg = bare_project(PathBuf::from("C:\\r\\ap\u{FFFD}"));
        let wide: Vec<u16> = "C:\\r\\ap".encode_utf16().chain([0xD800]).collect();
        let cwd = PathBuf::from(std::ffi::OsString::from_wide(&wide));
        assert!(pg.project_for(&cwd, &argv("x")).is_none());
        assert!(
            pg.project_for(Path::new("C:\\R\\AP\u{FFFD}\\s"), &argv("x"))
                .is_some()
        );
    }

    #[cfg(windows)]
    #[test]
    fn project_dir_matches_case_insensitively_on_windows() {
        let t = "[postgres]\nbin_dir = 'C:\\pg\\bin'\n[[postgres.project]]\ndir = 'C:\\R\\Api'\n";
        let pg = Config::from_toml(t).unwrap().postgres.unwrap();
        assert!(
            pg.project_for(Path::new("c:\\r\\api"), &argv("x"))
                .is_some()
        );
    }

    #[test]
    fn whitespace_only_command_is_rejected() {
        assert!(
            Config::from_toml(
                "[mcp.a]
command=\"  \t\""
            )
            .is_err()
        );
    }
}
