//! Shared support for tests that drive a real PostgreSQL: where the binaries are, one cluster
//! test at a time, free ports, scratch folders, a guard that stops what a test started, and a
//! "user's own" server that sync_gate must never touch.

use super::pg_sql::{
    ADMIN_ROLE, LEASE_COMMENT, OWNER_COMMENT, SAFE_PATH, bootstrap_sql, candidate_oids,
    clone_adopt, create_database, create_database_from, create_extensions, create_role,
    db_activity, db_by_oid, drop_database, drop_role, drop_template_role, lease_roles,
    missing_extensions, name_taken, owned_databases, template_check, template_db,
    template_names_free, template_own, template_owner, template_rename_db, template_rename_role,
    template_seal, template_state,
};
use super::pg_tools::{
    ClusterPaths, PgTools, ServerId, canonical, running_postmaster, tool_command,
};
use crate::supervisor::{ToolOutput, run_starter, run_tool};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// The `bin` folder of a real PostgreSQL, from `SYNC_GATE_TEST_PG_BIN`. Without it the test is
/// skipped, except under CI, where that is a failure.
pub fn pg_bin() -> Option<PathBuf> {
    let Some(bin) = std::env::var_os("SYNC_GATE_TEST_PG_BIN") else {
        assert!(
            std::env::var_os("CI").is_none(),
            "CI must set SYNC_GATE_TEST_PG_BIN"
        );
        println!("skipped: set SYNC_GATE_TEST_PG_BIN");
        return None;
    };
    Some(PathBuf::from(bin))
}

/// Real-cluster tests run one at a time inside a test binary.
pub fn serial() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// A free loopback port, never the ones this machine or sync_gate already use.
pub fn free_port() -> u16 {
    loop {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        if port != 54329 && port != 28543 {
            return port;
        }
    }
}

/// A fresh, canonical, absolute scratch folder whose name has a space; removed on drop.
/// Under `/tmp` on Unix so socket paths stay short (macOS's temp folder is long).
pub struct Scratch(PathBuf);

impl Scratch {
    pub fn new(tag: &str) -> Scratch {
        let base = if cfg!(unix) {
            PathBuf::from("/tmp")
        } else {
            std::env::temp_dir()
        };
        // A leftover folder that still holds a `postmaster.pid` may belong to a live server.
        let dir = (0..)
            .map(|n| {
                let suffix = if n == 0 {
                    String::new()
                } else {
                    format!("-{n}")
                };
                base.join(format!(
                    "sync_gate pg test-{tag}-{}{suffix}",
                    std::process::id()
                ))
            })
            .find(|d| !has_pidfile(d))
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let dir = canonical(&dir).unwrap();
        assert!(dir.is_absolute());
        Scratch(dir)
    }
}

impl std::ops::Deref for Scratch {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

/// How deep below a scratch folder `has_pidfile` looks before it gives up and keeps the folder.
pub const SCRATCH_DEPTH: usize = 16;

/// True when a `postmaster.pid` exists anywhere under `dir` (links are not followed) or when that
/// cannot be ruled out: a folder that cannot be read, an entry that fails to enumerate or whose
/// type cannot be read, or a tree deeper than `SCRATCH_DEPTH`. A missing folder holds nothing.
fn has_pidfile(dir: &Path) -> bool {
    fn walk(dir: &Path, depth: usize) -> bool {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => return e.kind() != std::io::ErrorKind::NotFound,
        };
        for entry in entries {
            let Ok(e) = entry else { return true };
            if e.file_name() == "postmaster.pid" {
                return true;
            }
            match e.file_type() {
                Ok(t) if t.is_dir() => {
                    if depth == 0 || walk(&e.path(), depth - 1) {
                        return true;
                    }
                }
                Ok(_) => {}
                Err(_) => return true,
            }
        }
        false
    }
    walk(dir, SCRATCH_DEPTH)
}

/// Prints from a destructor without waiting: a detached writer that blocks forever on a dead
/// stderr is left behind and cannot hold up the test.
fn note(msg: String) {
    let _ = std::thread::Builder::new().spawn(move || {
        let _ = writeln!(std::io::stderr(), "{msg}");
    });
}

/// A server possibly left running is a test failure; while a panic already unwinds, only a note.
fn server_left(msg: String) {
    if std::thread::panicking() {
        note(msg);
    } else {
        panic!("{msg}");
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if has_pidfile(&self.0) {
            server_left(format!(
                "scratch folder kept, a server may still run: {}",
                self.0.display()
            ));
        } else if let Err(e) = std::fs::remove_dir_all(&self.0) {
            // A leftover temporary folder is not a correctness problem (Windows locks files briefly).
            note(format!(
                "scratch folder not removed: {}: {e}",
                self.0.display()
            ));
        }
    }
}

/// Stops, with `pg_ctl stop -m immediate` on its own data folder, a server a test started.
/// Installed before the server can exist. It acts only while `postmaster.pid` in that folder
/// names a live `postgres` of `bin` with the recorded start time and data folder, so it never
/// stops anything else, and it has nothing to do once a stop has succeeded.
pub struct ServerGuard {
    bin: PathBuf,
    data: PathBuf,
}

impl ServerGuard {
    pub fn new(bin: &Path, data: &Path) -> ServerGuard {
        ServerGuard {
            bin: bin.to_path_buf(),
            data: data.to_path_buf(),
        }
    }
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let left = |why: String| {
            server_left(format!(
                "server in {} not stopped: {why}",
                self.data.display()
            ))
        };
        match running_postmaster(&self.data, &self.bin) {
            Ok(None) => {}
            Err(why) => left(why),
            Ok(Some(_)) => {
                let mut c = tool_command(&self.bin, "pg_ctl");
                c.arg("stop").arg("-D").arg(&self.data);
                c.args(["-m", "immediate", "-w", "-t", "30"]);
                match run_tool(c, None, Duration::from_secs(40)) {
                    Ok(o) if o.code == Some(0) => {}
                    Ok(o) => left(format!("pg_ctl stop exited {:?}", o.code)),
                    Err(e) => left(e.to_string()),
                }
            }
        }
    }
}

/// A server that stands for the user's own: `initdb` and `pg_ctl` run by the test, superuser
/// `postgres` with trust, TCP on 127.0.0.1:`port` only. Returns its guard.
pub fn user_server(bin: &Path, dir: &Path, port: u16) -> ServerGuard {
    user_server_at(bin, dir, port, "postgres", None)
}

/// `user_server` with the superuser's name and, optionally, a Unix socket folder for it.
pub fn user_server_at(
    bin: &Path,
    dir: &Path,
    port: u16,
    superuser: &str,
    sock: Option<&Path>,
) -> ServerGuard {
    let data = dir.join("data");
    let mut init = tool_command(bin, "initdb");
    init.arg("-D").arg(&data);
    init.args(["-U", superuser, "-A", "trust", "-E", "UTF8", "--no-locale"]);
    init.arg("--no-sync");
    let out = run_tool(init, None, Duration::from_secs(125)).unwrap();
    assert_eq!(out.code, Some(0), "{}", out.stderr);
    let conf = data.join("postgresql.conf");
    let mut text = std::fs::read_to_string(&conf).unwrap();
    let sock = sock.map_or(String::new(), |p| p.to_string_lossy().replace('\\', "/"));
    text.push_str(&format!(
        "\nport = {port}\nlisten_addresses = '127.0.0.1'\nunix_socket_directories = '{sock}'\n"
    ));
    std::fs::write(&conf, text).unwrap();
    let guard = ServerGuard::new(bin, &data);
    let mut start = tool_command(bin, "pg_ctl");
    start.arg("start").arg("-D").arg(&data);
    start.arg("-l").arg(dir.join("user.log"));
    start.args(["-w", "-t", "60"]);
    assert_eq!(
        run_starter(start, Duration::from_secs(75)).unwrap(),
        Some(0)
    );
    guard
}

/// One `psql -c` over TCP to 127.0.0.1:`port`, never prompting for a password.
pub fn psql_tcp(bin: &Path, port: u16, user: &str, db: &str, sql: &str) -> ToolOutput {
    let mut q = tool_command(bin, "psql");
    q.args([
        "-X",
        "-A",
        "-t",
        "-w",
        "-h",
        "127.0.0.1",
        "-p",
        &port.to_string(),
    ]);
    q.args(["-U", user, "-d", db, "-c", sql]);
    psql_run(q)
}

/// Runs a test `psql`; stdout with LF line ends (Windows prints CRLF).
pub fn psql_run(q: std::process::Command) -> ToolOutput {
    let mut out = run_tool(q, None, Duration::from_secs(35)).unwrap();
    out.stdout = out.stdout.replace("\r\n", "\n");
    out
}

/// The one fake of [`PgTools`] (ruling PF11): records every call as text (`major`, `init`,
/// `start`, `server`, `stop`, `config_current`, `sql <kind> <args>`, where `kind` is the
/// `pg_sql` builder's name and `args` its arguments but the password), announces each call on
/// the channels from [`FakePg::subscribe`], can hold the next call of a step until the test
/// releases it or fail a step, and keeps a fake catalogue of roles (OID, comment, login) and
/// databases (OID, owner, connections allowed, extension names) that the scripts update. A script is applied
/// only when it is exactly what its `pg_sql` builder returns for the values it carries; any
/// other is refused and recorded as `unrecognised: ...`.
pub struct FakePg {
    st: Mutex<FakeState>,
    cv: Condvar,
}

struct FakeRole {
    oid: u32,
    comment: Option<String>,
    login: bool,
}

impl FakeRole {
    /// The creation token of a lease mark.
    fn token(&self) -> Option<&str> {
        self.comment.as_deref()?.strip_prefix(LEASE_COMMENT)
    }
}

struct FakeDb {
    oid: u32,
    owner: String,
    allow_conn: bool,
    /// Extension names; a copy starts with its template's.
    exts: BTreeSet<String>,
}

struct FakeState {
    calls: Vec<String>,
    subscribers: Vec<Sender<String>>,
    /// step -> entered; the entry is removed when the test releases it.
    blocks: HashMap<String, bool>,
    /// step -> (calls left that fail, message; `{password}` is replaced by the script's).
    fails: HashMap<String, (u32, String)>,
    major: u32,
    server: Result<Option<ServerId>, String>,
    next_pid: u32,
    config_current: bool,
    lie_name_taken: bool,
    activity: Result<String, String>,
    /// What `template_check` prints (`Ok`) or fails with (`Err`) once the candidate exists.
    check: Result<String, String>,
    /// Whether `template_seal` ended every other session.
    terminated: bool,
    next_oid: u32,
    roles: BTreeMap<String, FakeRole>,
    dbs: BTreeMap<String, FakeDb>,
}

impl FakeState {
    fn oid(&mut self) -> u32 {
        self.next_oid += 1;
        self.next_oid
    }

    fn add_role(&mut self, name: &str, comment: Option<String>) {
        let oid = self.oid();
        let role = FakeRole {
            oid,
            comment,
            login: true,
        };
        self.roles.insert(name.into(), role);
    }

    fn add_db(&mut self, name: &str, owner: &str) {
        let oid = self.oid();
        let db = FakeDb {
            oid,
            owner: owner.into(),
            allow_conn: true,
            exts: BTreeSet::new(),
        };
        self.dbs.insert(name.into(), db);
    }

    /// The role `name` carries the lease mark of `token`.
    fn marked(&self, name: &str, token: &str) -> bool {
        self.roles.get(name).and_then(FakeRole::token) == Some(token)
    }

    fn role_by_oid(&self, oid: u32) -> Option<&str> {
        let mut named = self.roles.iter().filter(|(_, r)| r.oid == oid);
        named.next().map(|(n, _)| n.as_str())
    }

    /// Like `DROP ROLE`: refused while the role owns a database.
    fn drop_role(&mut self, name: &str) -> io::Result<()> {
        if self.dbs.values().any(|d| d.owner == name) {
            return Err(io::Error::other(format!(
                "ERROR:  role \"{name}\" cannot be dropped because some objects depend on it"
            )));
        }
        self.roles.remove(name);
        Ok(())
    }
}

/// Calls of a step that fail forever.
pub const ALWAYS: u32 = u32::MAX;
/// The longest a blocked step waits for the test; past it the step fails, so a test whose
/// blocker is never released fails instead of hanging.
pub const BLOCK_LIMIT: Duration = Duration::from_secs(60);

/// A blocked step; released when dropped, also while a failing test unwinds.
#[must_use = "the step is released when this guard drops"]
pub struct Blocked {
    fake: Arc<FakePg>,
    step: String,
}

impl Drop for Blocked {
    fn drop(&mut self) {
        self.fake.release(&self.step);
    }
}

impl Default for FakePg {
    fn default() -> Self {
        FakePg {
            st: Mutex::new(FakeState {
                calls: Vec::new(),
                subscribers: Vec::new(),
                blocks: HashMap::new(),
                fails: HashMap::new(),
                major: 17,
                server: Ok(None),
                next_pid: 900,
                config_current: true,
                lie_name_taken: false,
                activity: Ok("0|0".into()),
                check: Ok("t".into()),
                terminated: true,
                // Below it the OIDs of a real cluster's own objects.
                next_oid: 16383,
                roles: BTreeMap::new(),
                dbs: BTreeMap::new(),
            }),
            cv: Condvar::new(),
        }
    }
}

/// The text between `from` and the next `to` after it.
fn between<'a>(s: &'a str, from: &str, to: char) -> &'a str {
    s.split_once(from)
        .and_then(|(_, rest)| rest.split(to).next())
        .unwrap_or("")
}

/// The hex digits right after `from`.
fn hex_after(s: &str, from: &str) -> String {
    let rest = s.split_once(from).map_or("", |(_, rest)| rest);
    rest.chars().take_while(char::is_ascii_hexdigit).collect()
}

/// The identifier after `from`, up to the first `"` not followed by another; `""` becomes `"`.
fn quoted_ident(s: &str, from: &str) -> String {
    let Some((_, rest)) = s.split_once(from) else {
        return String::new();
    };
    let mut out = String::new();
    let mut chars = rest.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '"' {
            if chars.peek() != Some(&'"') {
                break;
            }
            chars.next();
        }
        out.push(c);
    }
    out
}

impl FakePg {
    fn lock(&self) -> MutexGuard<'_, FakeState> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn calls(&self) -> Vec<String> {
        self.lock().calls.clone()
    }

    /// Calls whose step (first word, or the kind of an `sql` call) is `step`.
    pub fn count(&self, step: &str) -> usize {
        self.lock()
            .calls
            .iter()
            .filter(|c| step_of(c) == step)
            .count()
    }

    pub fn subscribe(&self) -> Receiver<String> {
        let (tx, rx) = std::sync::mpsc::channel();
        self.lock().subscribers.push(tx);
        rx
    }

    /// The next call of `step` waits, after it is recorded, until the guard drops (or
    /// [`BLOCK_LIMIT`] passes, and then it fails).
    pub fn block(self: &Arc<Self>, step: &str) -> Blocked {
        self.lock().blocks.insert(step.into(), false);
        Blocked {
            fake: self.clone(),
            step: step.into(),
        }
    }

    /// True once a call of the blocked `step` is waiting; false at `timeout`.
    pub fn wait_entered(&self, step: &str, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        let mut st = self.lock();
        loop {
            if st.blocks.get(step) == Some(&true) {
                return true;
            }
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return false;
            }
            st = self
                .cv
                .wait_timeout(st, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    pub fn release(&self, step: &str) {
        self.lock().blocks.remove(step);
        self.cv.notify_all();
    }

    /// The next `times` calls of `step` fail with `msg` ([`ALWAYS`]: every call).
    pub fn fail(&self, step: &str, times: u32, msg: &str) {
        self.lock().fails.insert(step.into(), (times, msg.into()));
    }

    pub fn set_major(&self, major: u32) {
        self.lock().major = major;
    }

    pub fn set_server(&self, server: Result<Option<ServerId>, String>) {
        self.lock().server = server;
    }

    pub fn server_id(&self) -> Option<ServerId> {
        self.lock().server.clone().ok().flatten()
    }

    pub fn set_config_current(&self, current: bool) {
        self.lock().config_current = current;
    }

    /// `name_taken` answers `f` even for a name in the catalogue.
    pub fn lie_name_taken(&self) {
        self.lock().lie_name_taken = true;
    }

    /// What every `db_activity` prints (`Ok`) or fails with (`Err`).
    pub fn set_activity(&self, out: Result<&str, &str>) {
        self.lock().activity = out.map(Into::into).map_err(Into::into);
    }

    /// What `template_check` prints (`Ok`) or fails with (`Err`) for an existing candidate.
    pub fn set_template_check(&self, out: Result<&str, &str>) {
        self.lock().check = out.map(Into::into).map_err(Into::into);
    }

    /// Whether `template_seal` ends every other session (`false`: it prints `f`).
    pub fn set_terminated(&self, terminated: bool) {
        self.lock().terminated = terminated;
    }

    /// A role that logs in, with the lease mark of `token` (or no comment).
    pub fn add_role(&self, name: &str, token: Option<&str>) {
        let comment = token.map(|t| format!("{LEASE_COMMENT}{t}"));
        self.lock().add_role(name, comment);
    }

    pub fn add_db(&self, name: &str, owner: &str) {
        self.lock().add_db(name, owner);
    }

    /// Role -> creation token of its lease mark.
    pub fn roles(&self) -> BTreeMap<String, Option<String>> {
        let st = self.lock();
        let token = |r: &FakeRole| r.token().map(Into::into);
        st.roles
            .iter()
            .map(|(n, r)| (n.clone(), token(r)))
            .collect()
    }

    /// Database -> owner.
    pub fn dbs(&self) -> BTreeMap<String, String> {
        let st = self.lock();
        st.dbs
            .iter()
            .map(|(n, d)| (n.clone(), d.owner.clone()))
            .collect()
    }

    pub fn oid_of_role(&self, name: &str) -> Option<u32> {
        self.lock().roles.get(name).map(|r| r.oid)
    }

    pub fn oid_of_db(&self, name: &str) -> Option<u32> {
        self.lock().dbs.get(name).map(|d| d.oid)
    }

    /// Role -> key, for every role carrying an owner mark.
    pub fn owner_roles(&self) -> BTreeMap<String, String> {
        let st = self.lock();
        let key = |r: &FakeRole| Some(r.comment.as_deref()?.strip_prefix(OWNER_COMMENT)?.into());
        let marked = st
            .roles
            .iter()
            .filter_map(|(n, r)| Some((n.clone(), key(r)?)));
        marked.collect()
    }

    pub fn db_owner(&self, name: &str) -> Option<String> {
        self.lock().dbs.get(name).map(|d| d.owner.clone())
    }

    /// Records and announces the call, waits while it is blocked, then applies a planned
    /// failure. `password` fills `{password}` in a failure message.
    fn enter(&self, call: String, password: &str) -> Result<MutexGuard<'_, FakeState>, String> {
        let step = step_of(&call).to_string();
        let mut st = self.lock();
        st.calls.push(call.clone());
        st.subscribers.retain(|s| s.send(call.clone()).is_ok());
        if st.blocks.get(&step) == Some(&false) {
            st.blocks.insert(step.clone(), true);
            self.cv.notify_all();
            let deadline = Instant::now() + BLOCK_LIMIT;
            while st.blocks.contains_key(&step) {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err("test blocker timed out".into());
                }
                st = self
                    .cv
                    .wait_timeout(st, left)
                    .unwrap_or_else(|e| e.into_inner())
                    .0;
            }
        }
        if let Some((left, msg)) = st.fails.get_mut(&step) {
            if *left > 0 {
                if *left != ALWAYS {
                    *left -= 1;
                }
                return Err(msg.replace("{password}", password));
            }
        }
        Ok(st)
    }
}

/// The call text and the password of a script that is byte for byte what its `pg_sql` builder
/// returns for the values it carries (ruling F1); `Err(kind)` for any other script.
fn recognise(script: &str) -> Result<(String, String), &'static str> {
    let lit = |from: &str| between(script, from, '\'').to_string();
    let ident = |from: &str| quoted_ident(script, from);
    let token = lit(LEASE_COMMENT);
    let none = String::new();
    let (kind, call, expected, password) = if script.starts_with("REVOKE CONNECT") {
        (
            "bootstrap",
            "sql bootstrap".into(),
            Ok(bootstrap_sql()),
            none,
        )
    } else if script.starts_with("SELECT EXISTS") {
        let n = lit("rolname = '");
        (
            "name_taken",
            format!("sql name_taken {n}"),
            name_taken(&n),
            none,
        )
    } else if script.starts_with("BEGIN; CREATE ROLE") {
        let (n, pw) = (ident("ROLE \""), lit("PASSWORD '"));
        let limit = between(script, "CONNECTION LIMIT ", ' ').parse::<u32>();
        let expected = match limit {
            Ok(l) => create_role(&n, &token, &pw, l),
            Err(_) => return Err("create_role"),
        };
        let call = format!("sql create_role {n} {token}");
        ("create_role", call, expected, pw)
    } else if script.starts_with("CREATE DATABASE") {
        let n = ident("DATABASE \"");
        let call = format!("sql create_database {n}");
        ("create_database", call, create_database(&n), none)
    } else if script.starts_with("SELECT d.datname") {
        let n = lit("rolname = '");
        let call = format!("sql owned_databases {n} {token}");
        ("owned_databases", call, owned_databases(&n, &token), none)
    } else if script.starts_with("ALTER DATABASE") {
        let n = ident("DATABASE \"");
        let call = format!("sql drop_database {n}");
        ("drop_database", call, drop_database(&n), none)
    } else if script.starts_with("DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles r") {
        let n = lit("rolname = '");
        let call = format!("sql drop_role {n} {token}");
        ("drop_role", call, drop_role(&n, &token), none)
    } else if script.starts_with("SELECT rolname") {
        (
            "lease_roles",
            "sql lease_roles".into(),
            Ok(lease_roles()),
            none,
        )
    } else if script.starts_with("SELECT (SELECT count(*)") {
        let n = lit("datname = '");
        (
            "db_activity",
            format!("sql db_activity {n}"),
            db_activity(&n),
            none,
        )
    } else if let Some(rest) = script.strip_prefix(SAFE_PATH) {
        let key = |from: &str| hex_after(script, from);
        // 0 when unreadable: the builder then refuses it, so the script is not recognised.
        let oid = |from: &str| between(script, from, '\'').parse::<u32>().unwrap_or(0);
        let n = lit("rolname = '");
        if rest.starts_with("SELECT r.oid") {
            let call = format!("sql candidate_oids {n} {token}");
            ("candidate_oids", call, candidate_oids(&n, &token), none)
        } else if rest.starts_with("SELECT NOT EXISTS") {
            let k = key("fg_t_");
            let call = format!("sql template_names_free {k}");
            ("template_names_free", call, template_names_free(&k), none)
        } else if rest.starts_with("DO $$ BEGIN IF NOT EXISTS") {
            let call = format!("sql template_seal {n} {token}");
            ("template_seal", call, template_seal(&n, &token), none)
        } else if rest.starts_with("BEGIN;") {
            let k = key(OWNER_COMMENT);
            let call = format!("sql template_rename_role {n} {token} {k}");
            let expected = template_rename_role(&n, &token, &k);
            ("template_rename_role", call, expected, none)
        } else if rest.starts_with("ALTER DATABASE") && rest.contains(" RENAME TO ") {
            let (n, k) = (ident("DATABASE \""), key("fg_t_"));
            let call = format!("sql template_rename_db {n} {k}");
            ("template_rename_db", call, template_rename_db(&n, &k), none)
        } else if rest.starts_with("ALTER DATABASE") {
            let n = ident("DATABASE \"");
            let call = format!("sql template_own {n}");
            ("template_own", call, template_own(&n), none)
        } else if rest.starts_with("SELECT EXISTS") {
            let (k, d, r) = (key("fg_t_"), oid("d.oid = '"), oid("r.oid = '"));
            let call = format!("sql template_state {k} {d} {r}");
            ("template_state", call, template_state(&k, d, r), none)
        } else if rest.starts_with("SELECT d.datname") {
            let (d, r) = (oid("d.oid = '"), oid("d.datdba = '"));
            let (n, k) = (lit("IN ('"), key("fg_t_"));
            let call = format!("sql db_by_oid {d} {r} {n} {k}");
            ("db_by_oid", call, db_by_oid(d, r, &n, &k), none)
        } else if rest.starts_with("DO $$ BEGIN IF EXISTS") {
            let (r, k) = (oid("r.oid = '"), key(OWNER_COMMENT));
            let call = format!("sql drop_template_role {r} {n} {token} {k}");
            let expected = drop_template_role(r, &n, &token, &k);
            ("drop_template_role", call, expected, none)
        } else if rest.starts_with("CREATE DATABASE") {
            let (n, k) = (ident("DATABASE \""), key("fg_t_"));
            let call = format!("sql create_database_from {n} {k}");
            (
                "create_database_from",
                call,
                create_database_from(&n, &k),
                none,
            )
        } else {
            return Err("unknown");
        }
    } else if script.starts_with("\\connect") {
        let n = ident("\\connect \"");
        if script.contains("REASSIGN OWNED BY") {
            let k = hex_after(script, "fg_o_");
            let call = format!("sql clone_adopt {n} {k}");
            ("clone_adopt", call, clone_adopt(&n, &k), none)
        } else if script.contains("SET ROLE") {
            let exts: Vec<String> = script
                .split("CREATE EXTENSION IF NOT EXISTS ")
                .skip(1)
                .map(|r| quoted_ident(r, "\""))
                .collect();
            let call = exts
                .iter()
                .fold(format!("sql create_extensions {n}"), |c, e| c + " " + e);
            (
                "create_extensions",
                call,
                create_extensions(&n, &exts),
                none,
            )
        } else if script.contains("pg_catalog.pg_extension") {
            // Validated names: no quote inside a literal.
            let list = between(script, "ARRAY[", ']');
            let exts: Vec<String> = list
                .split(", ")
                .map(|l| l.trim_matches('\'').to_string())
                .collect();
            let call = exts
                .iter()
                .fold(format!("sql missing_extensions {n}"), |c, e| c + " " + e);
            (
                "missing_extensions",
                call,
                missing_extensions(&n, &exts),
                none,
            )
        } else {
            let call = format!("sql template_check {n}");
            ("template_check", call, template_check(&n), none)
        }
    } else {
        return Err("unknown");
    };
    match expected {
        Ok(e) if e == script => Ok((call, password)),
        _ => Err(kind),
    }
}

fn step_of(call: &str) -> &str {
    let mut words = call.split(' ');
    match words.next() {
        Some("sql") => words.next().unwrap_or(""),
        Some(w) => w,
        None => "",
    }
}

impl PgTools for FakePg {
    fn major_version(&self, _bin: &Path) -> io::Result<u32> {
        let st = self.enter("major".into(), "").map_err(io::Error::other)?;
        Ok(st.major)
    }

    fn init(&self, c: &ClusterPaths, _max_connections: u32) -> io::Result<()> {
        let mut st = self.enter("init".into(), "").map_err(io::Error::other)?;
        // Like the real one: a new cluster gets its record and an empty lease registry.
        if !c.record.exists() {
            std::fs::create_dir_all(&c.root)?;
            std::fs::write(&c.record, "{}")?;
            std::fs::write(
                &c.leases,
                r#"{"version":1,"unknown_before":false,"leases":[]}"#,
            )?;
            std::fs::write(&c.templates, super::pg_tools::TEMPLATES_EMPTY)?;
        }
        st.config_current = true;
        Ok(())
    }

    fn start(&self, _c: &ClusterPaths) -> io::Result<ServerId> {
        let mut st = self.enter("start".into(), "").map_err(io::Error::other)?;
        if !matches!(st.server, Ok(None)) {
            return Err(io::Error::other("the server is already running"));
        }
        let id = ServerId {
            pid: st.next_pid,
            start: 1,
        };
        st.next_pid += 1;
        st.server = Ok(Some(id));
        Ok(id)
    }

    fn server(&self, _c: &ClusterPaths) -> Result<Option<ServerId>, String> {
        self.enter("server".into(), "")?.server.clone()
    }

    fn stop(&self, _c: &ClusterPaths, id: ServerId) -> io::Result<()> {
        let mut st = self.enter("stop".into(), "").map_err(io::Error::other)?;
        if st.server != Ok(Some(id)) {
            return Err(io::Error::other(
                "the server is not the one identified; not stopping",
            ));
        }
        st.server = Ok(None);
        Ok(())
    }

    fn sql(&self, _c: &ClusterPaths, script: &str, _secrets: &[&str]) -> io::Result<String> {
        let (call, password) = match recognise(script) {
            Ok(c) => c,
            Err(kind) => {
                // Recorded, never applied: a test sees which script no builder wrote.
                let call = format!("unrecognised: sql {kind}");
                let mut st = self.lock();
                st.calls.push(call.clone());
                st.subscribers.retain(|s| s.send(call.clone()).is_ok());
                return Err(io::Error::other("FakePg: unrecognised script"));
            }
        };
        let mut st = self
            .enter(call.clone(), &password)
            .map_err(io::Error::other)?;
        if !matches!(st.server, Ok(Some(_))) {
            return Err(io::Error::other("postgres is not running"));
        }
        let words: Vec<&str> = call.split(' ').collect();
        let arg = |i: usize| words.get(i).copied().unwrap_or("");
        let num = |i: usize| arg(i).parse::<u32>().unwrap_or(0);
        let (name, token) = (arg(2), arg(3));
        let tdb = |key: &str| template_db(key).unwrap_or_default();
        let town = |key: &str| template_owner(key).unwrap_or_default();
        let owner_mark = |key: &str| Some(format!("{OWNER_COMMENT}{key}"));
        let fail = |what: &str, n: &str, why: &str| {
            Err(io::Error::other(format!("ERROR:  {what} \"{n}\" {why}")))
        };
        let tf = |b: bool| if b { "t\n" } else { "f\n" }.to_string();
        let none = Ok(String::new());
        match words[1] {
            "name_taken" => {
                let taken = st.roles.contains_key(name) || st.dbs.contains_key(name);
                Ok(tf(taken && !st.lie_name_taken))
            }
            "create_role" if st.roles.contains_key(name) => fail("role", name, "already exists"),
            "create_role" => {
                st.add_role(name, Some(format!("{LEASE_COMMENT}{token}")));
                none
            }
            "create_database" if st.dbs.contains_key(name) => {
                fail("database", name, "already exists")
            }
            "create_database" => {
                st.add_db(name, name);
                none
            }
            "owned_databases" if st.marked(name, token) => {
                let owned = st.dbs.iter().filter(|(_, d)| d.owner == name);
                Ok(owned.map(|(d, _)| format!("{d}\n")).collect())
            }
            "drop_database" => {
                st.dbs.remove(name);
                none
            }
            "drop_role" if st.marked(name, token) => st.drop_role(name).map(|()| String::new()),
            "lease_roles" => {
                let marked = st.roles.iter().filter_map(|(r, x)| Some((r, x.token()?)));
                Ok(marked.map(|(r, t)| format!("{r}|{t}\n")).collect())
            }
            "db_activity" => st.activity.clone().map_err(io::Error::other),
            "candidate_oids" => {
                let db = st.dbs.get(name).filter(|d| d.owner == name);
                Ok(match (st.marked(name, token), st.roles.get(name), db) {
                    (true, Some(r), Some(d)) => format!("{}|{}\n", r.oid, d.oid),
                    _ => String::new(),
                })
            }
            "template_names_free" => Ok(tf(
                !st.dbs.contains_key(&tdb(name)) && !st.roles.contains_key(&town(name))
            )),
            "template_seal" | "template_rename_role" if !st.marked(name, token) => Err(
                io::Error::other("ERROR:  the lease role does not carry its mark"),
            ),
            "template_seal" if !st.dbs.contains_key(name) => {
                fail("database", name, "does not exist")
            }
            "template_seal" => {
                if let Some(r) = st.roles.get_mut(name) {
                    r.login = false;
                }
                Ok(tf(st.terminated))
            }
            // `\connect` fails without the database; the check needs the candidate role.
            "template_check" if !st.dbs.contains_key(name) => {
                fail("database", name, "does not exist")
            }
            "template_check" if !st.roles.contains_key(name) => Ok(tf(false)),
            "template_check" => st
                .check
                .clone()
                .map(|o| format!("{o}\n"))
                .map_err(io::Error::other),
            "template_own" => match st.dbs.get_mut(name) {
                Some(d) => {
                    d.owner = ADMIN_ROLE.into();
                    d.allow_conn = false;
                    none
                }
                None => fail("database", name, "does not exist"),
            },
            "template_rename_role" => {
                let (key, owner) = (arg(4), town(arg(4)));
                if st.roles.contains_key(&owner) {
                    return fail("role", &owner, "already exists");
                }
                if let Some(mut r) = st.roles.remove(name) {
                    r.comment = owner_mark(key);
                    st.roles.insert(owner.clone(), r);
                }
                // An owner is an OID: its databases follow the new name.
                for d in st.dbs.values_mut().filter(|d| d.owner == name) {
                    d.owner = owner.clone();
                }
                none
            }
            "template_rename_db" => {
                let to = tdb(token);
                if st.dbs.contains_key(&to) {
                    return fail("database", &to, "already exists");
                }
                match st.dbs.remove(name) {
                    Some(d) => {
                        st.dbs.insert(to, d);
                        none
                    }
                    None => fail("database", name, "does not exist"),
                }
            }
            "template_state" => {
                let (key, db, role) = (name, num(3), num(4));
                let db_ok = st
                    .dbs
                    .get(&tdb(key))
                    .is_some_and(|d| d.oid == db && d.owner == ADMIN_ROLE && !d.allow_conn);
                let role_ok = st
                    .roles
                    .get(&town(key))
                    .is_some_and(|r| r.oid == role && !r.login && r.comment == owner_mark(key));
                Ok(tf(db_ok && role_ok))
            }
            "db_by_oid" => {
                let (db, role, lease, key) = (num(2), num(3), arg(4), arg(5));
                let owner = st.role_by_oid(role).unwrap_or("").to_string();
                let found = st.dbs.iter().find(|(n, d)| {
                    d.oid == db
                        && (n.as_str() == lease || **n == tdb(key))
                        && (d.owner == owner || d.owner == ADMIN_ROLE)
                });
                Ok(found.map_or(String::new(), |(n, _)| format!("{n}\n")))
            }
            "drop_template_role" => {
                let (role, lease, token, key) = (num(2), arg(3), arg(4), arg(5));
                let owner = town(key);
                let target = match st.role_by_oid(role) {
                    Some(n) if n == lease && st.marked(lease, token) => Some(lease.to_string()),
                    Some(n) if n == owner && st.roles[n].comment == owner_mark(key) => Some(owner),
                    _ => None,
                };
                match target {
                    Some(n) => st.drop_role(&n).map(|()| String::new()),
                    None => none,
                }
            }
            "create_database_from" if !st.dbs.contains_key(&tdb(token)) => {
                fail("database", &tdb(token), "does not exist")
            }
            "create_database_from" if st.dbs.contains_key(name) => {
                fail("database", name, "already exists")
            }
            "create_database_from" => {
                let exts = st.dbs[&tdb(token)].exts.clone();
                st.add_db(name, name);
                if let Some(d) = st.dbs.get_mut(name) {
                    d.exts = exts;
                }
                none
            }
            "clone_adopt" | "create_extensions" | "missing_extensions"
                if !st.dbs.contains_key(name) =>
            {
                fail("database", name, "does not exist")
            }
            "create_extensions" => {
                if let Some(d) = st.dbs.get_mut(name) {
                    d.exts.extend(words[3..].iter().map(|e| e.to_string()));
                }
                none
            }
            "missing_extensions" => {
                let have = &st.dbs[name].exts;
                let missing = words[3..].iter().filter(|e| !have.contains(**e));
                Ok(missing.map(|e| format!("{e}\n")).collect())
            }
            _ => none,
        }
    }

    fn config_current(&self, _c: &ClusterPaths, _max_connections: u32) -> bool {
        self.enter("config_current".into(), "")
            .is_ok_and(|st| st.config_current)
    }
}
