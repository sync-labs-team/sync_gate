//! The CLI's side of a database lease: ask for it right before the command starts, register the
//! command as the holder, give it back when the command ends. Every failure runs the command
//! with its own environment and says so once on stderr; no lease variable is ever printed.

use crate::client::{ClientError, call_at, call_with_deadline};
use crate::runner::{Phase, exit_code, interrupted, lock_phase, socket};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use sync_gate_core::{
    Config, Holder, PgConfig, PgProject, Request, Response, SERVICE_POSTGRES, Secret, template_key,
};
use sync_gate_probe::start_time;

/// Variables of the user's own PostgreSQL setup that would override the injected ones.
const DROPPED_VARS: [&str; 5] = [
    "PGSERVICE",
    "PGSERVICEFILE",
    "PGPASSFILE",
    "PGHOSTADDR",
    "PGOPTIONS",
];

/// How often the holder registration is repeated until the daemon answers.
const HAND_OVER_EVERY: Duration = Duration::from_secs(1);

/// How often a running `migrate` is checked for its exit.
const MIGRATE_POLL: Duration = Duration::from_millis(50);

/// The longest one try to register a `migrate` waits for its answer, and the least time
/// between two tries.
const REGISTER_TRY: Duration = Duration::from_millis(500);

/// A granted lease. Its variables live only here, in memory, until they reach the command.
pub struct Lease {
    id: String,
    env: BTreeMap<String, Secret>,
    given_back: bool,
}

impl std::fmt::Debug for Lease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lease")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// The give-up of a request whose patience ran out; joined before the CLI exits.
static GIVE_UP: Mutex<Option<JoinHandle<()>>> = Mutex::new(None);

fn warn(why: &str) {
    eprintln!("sync_gate: no shared database ({why}); running with the project's own settings");
}

/// Unique per attempt, `[0-9a-f-]{1,64}`, not a secret.
fn new_request() -> String {
    static N: AtomicU32 = AtomicU32::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!(
        "{:x}-{nanos:x}-{:x}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    )
}

fn me() -> Holder {
    let pid = std::process::id();
    Holder {
        pid,
        start: start_time(pid),
    }
}

/// Asks for the database of the project matching `cwd` and `argv`. `None` when no project
/// matches (silently) or when none could be had (one line on stderr): the command then runs
/// as if sync_gate were not there. A project with `migrate` gets a copy of its template or
/// nothing, never an empty database.
pub fn acquire(cfg: &Config, cwd: &Path, argv: &[String]) -> Option<Lease> {
    let pg = cfg.postgres.as_ref()?;
    let project = pg.project_for(cwd, argv)?;
    let got = if project.migrate.is_empty() {
        ask(pg, project, None).lease(pg)
    } else {
        from_template(pg, project)
    };
    got.inspect_err(|why| warn(why)).ok()
}

/// What a reply to a lease request gives the CLI.
#[derive(Debug)]
enum Reply {
    /// The database to run the command on.
    Leased(Lease),
    /// A candidate to run the project's `migrate` on.
    Prepare(Lease),
    /// Nothing to use, and why; `Some` is a lease to give back.
    Refused(Option<Lease>, String),
}

impl Reply {
    fn refused(why: impl Into<String>) -> Reply {
        Reply::Refused(None, why.into())
    }

    /// The database to run on; any other lease is given back within the patience.
    fn lease(self, pg: &PgConfig) -> Result<Lease, String> {
        let (back, why) = match self {
            Reply::Leased(l) => return Ok(l),
            Reply::Prepare(l) => (Some(l), "unexpected reply".to_string()),
            Reply::Refused(back, why) => (back, why),
        };
        if let Some(l) = back {
            l.release_by(patience_from_now(pg));
        }
        Err(why)
    }
}

/// Judges a reply to a request asked with template `key` and the project's `extensions`: a
/// database copied from anything else, or made with another extension list (an older daemon
/// that ignored them), is not trusted. A project without extensions accepts any echo.
fn interpret(reply: Response, key: Option<&str>, extensions: &[String]) -> Reply {
    let older = || "the daemon is older than this command".to_string();
    let stale = |echo: &[String]| !extensions.is_empty() && echo != extensions;
    match reply {
        Response::Leased {
            lease,
            env,
            template,
            extensions: echo,
        } => {
            let l = Lease {
                id: lease,
                env,
                given_back: false,
            };
            if (key.is_some() && template.as_deref() != key) || stale(&echo) {
                Reply::Refused(Some(l), older())
            } else {
                Reply::Leased(l)
            }
        }
        Response::Prepare {
            lease,
            env,
            extensions: echo,
        } => {
            let l = Lease {
                id: lease,
                env,
                given_back: false,
            };
            if stale(&echo) {
                Reply::Refused(Some(l), older())
            } else {
                Reply::Prepare(l)
            }
        }
        Response::Error { message } => Reply::refused(message),
        _ => Reply::refused("unexpected reply"),
    }
}

/// One lease request for `project` with template `key`, within `lease_wait_secs`; a request
/// that runs out of patience is given up.
fn ask(pg: &PgConfig, project: &PgProject, key: Option<&str>) -> Reply {
    let request = new_request();
    let ask = Request::Lease {
        service: SERVICE_POSTGRES.into(),
        project: project.dir.clone(),
        holder: me(),
        request: request.clone(),
        template: key.map(String::from),
        extensions: project.extensions.clone(),
    };
    let patience = Duration::from_secs(pg.lease_wait_secs);
    match call_with_deadline(&socket(), &ask, patience) {
        Ok(reply) => interpret(reply, key, &project.extensions),
        Err(ClientError::DaemonDown) => Reply::refused("daemon not running"),
        Err(ClientError::Timeout) => {
            give_up(request);
            Reply::refused(format!("timed out after {} s", pg.lease_wait_secs))
        }
        Err(e) => Reply::refused(e.to_string()),
    }
}

/// A copy of the template of the project's watched files; when the files are new, the template
/// is made first by the project's `migrate` on a candidate, then asked for once more.
fn from_template(pg: &PgConfig, project: &PgProject) -> Result<Lease, String> {
    let key = project_key(project).map_err(|e| e.to_string())?;
    let copy = match ask(pg, project, Some(&key)) {
        Reply::Prepare(candidate) => {
            migrate(pg, project, &key, candidate)?;
            ask(pg, project, Some(&key)).lease(pg)?
        }
        reply => reply.lease(pg)?,
    };
    // C7: the files may have changed while the copy was being made.
    if same_key(project, &key) {
        Ok(copy)
    } else {
        copy.release_by(patience_from_now(pg));
        Err("the watched files changed while the database was being made".into())
    }
}

/// The end of one `lease_wait_secs` from now: what the CLI may still spend talking to the daemon
/// before the command starts.
fn patience_from_now(pg: &PgConfig) -> Instant {
    Instant::now() + Duration::from_secs(pg.lease_wait_secs)
}

fn left(by: Instant) -> Duration {
    by.saturating_duration_since(Instant::now())
}

/// Whether the watched files still hash to `key` (unreadable: no).
fn same_key(project: &PgProject, key: &str) -> bool {
    project_key(project).is_ok_and(|k| k == key)
}

fn project_key(p: &PgProject) -> Result<String, sync_gate_core::KeyError> {
    template_key(&p.dir, &p.migrate, &p.watch, &p.extensions)
}

/// Runs the project's `migrate` on `candidate` and reports how it ended; `Ok` once the daemon
/// made the template. Its output goes to our stderr: the command's stdout stays its own. It is
/// never ended here: past its deadline it keeps the candidate, whose holder it is, and the
/// daemon drops the candidate once it exits.
fn migrate(pg: &PgConfig, project: &PgProject, key: &str, candidate: Lease) -> Result<(), String> {
    let mut before = None;
    let done = migrate_on(pg, project, key, candidate, &mut before);
    // Only now, with the report sent and the candidate dealt with, may a Ctrl+C that is still
    // on its way to the phase lock end the process.
    if let Some(p) = before {
        *lock_phase() = p;
    }
    done
}

/// [`migrate`]; `before` gets the caller's phase if this function replaced it.
fn migrate_on(
    pg: &PgConfig,
    project: &PgProject,
    key: &str,
    candidate: Lease,
    before: &mut Option<Phase>,
) -> Result<(), String> {
    let mut c = Command::new(crate::program::resolve_in_env(&project.migrate[0]));
    c.args(&project.migrate[1..])
        .current_dir(&project.dir)
        .stdin(Stdio::null())
        .stdout(std::io::stderr())
        .stderr(std::io::stderr());
    candidate.apply(&mut c);
    // As for the command in `run_admitted`: an interrupt waits from the spawn until the
    // registration is settled, so the CLI never ends leaving a live `migrate` that holds nothing.
    let mut phase = lock_phase();
    // The admission context: a shim inside the `migrate` runs its program with the candidate's
    // variables and asks for no slot (it would wait behind this very job) and no database.
    // Outside an admission (a light or fail-open command) any non-empty value does the same.
    c.env(
        "SYNC_GATE_JOB",
        match *phase {
            Phase::Admitted(id) => id.to_string(),
            _ => "migrate".to_string(),
        },
    );
    let Ok(mut child) = c.spawn() else {
        drop(phase);
        return candidate.no_template(
            "the migration could not start".into(),
            patience_from_now(pg),
            false,
        );
    };
    // Read while the child is unreaped: a pid freed later could be a stranger's.
    let pid = child.id();
    let holder = Holder {
        pid,
        start: start_time(pid),
    };
    let start = Instant::now();
    // A `try_wait` error cannot tell: taken as still running, so nothing is given back under it.
    let mut status = None;
    let mut exited = || {
        status = status.or_else(|| child.try_wait().ok().flatten());
        status.is_some()
    };
    let limit = Duration::from_secs(project.migrate_timeout_secs);
    // A registration that is no use any more (the `migrate` ended) stops, and one still trying
    // at the deadline is left to the way out, which has its own patience.
    let register_by = patience_from_now(pg).min(start + limit);
    let registered = candidate.register(holder, register_by, &mut exited);
    // Running, so a Ctrl+C during the wait only raises the flag: this function tells the daemon
    // the key is free; the caller's phase comes back once it is done.
    *before = Some(std::mem::replace(&mut *phase, Phase::Running));
    drop(phase);
    while !exited() && start.elapsed() < limit && !interrupted() {
        thread::sleep(MIGRATE_POLL);
    }
    // Everything from here to the command shares one patience.
    let by = patience_from_now(pg);
    let Some(status) = status else {
        // Still running: it must hold the candidate before the CLI leaves it.
        let registered = registered || candidate.register(holder, by, || false);
        let stopped = interrupted();
        candidate.template_failed(by, stopped);
        candidate.leave();
        let n = project.migrate_timeout_secs;
        return Err(if stopped {
            "the migration was interrupted".into()
        } else if registered {
            format!("the migration is still running after {n} s")
        } else {
            format!(
                "the migration is still running after {n} s and could not be registered as the \
                 holder of its database, which may be dropped under it"
            )
        });
    };
    if !status.success() {
        let stopped = interrupted();
        let why = if stopped {
            "the migration was interrupted".into()
        } else {
            format!("the migration failed (exit {})", exit_code(status))
        };
        return candidate.no_template(why, by, stopped);
    }
    if !same_key(project, key) {
        let why = "the watched files changed during the migration".into();
        return candidate.no_template(why, by, false);
    }
    let ready = Request::TemplateReady {
        lease: candidate.id.clone(),
        ok: true,
        interrupted: false,
    };
    let patience = Duration::from_secs(pg.lease_wait_secs);
    let made = call_with_deadline(&socket(), &ready, patience);
    // From the report on, the promotion decides: it keeps the candidate or gives it back.
    candidate.leave();
    match made {
        Ok(Response::Ack) => Ok(()),
        Ok(Response::Error { message }) => {
            Err(format!("the template could not be made: {message}"))
        }
        Ok(_) => Err("the template could not be made: unexpected reply".into()),
        Err(e) => Err(format!("the template could not be made: {e}")),
    }
}

/// Tells the daemon once that nobody waits for `request` any more, off the command's way.
fn give_up(request: String) {
    let send = thread::Builder::new().spawn(move || {
        let _ = call_at(&socket(), &Request::LeaseGiveUp { request });
    });
    // A thread that cannot start loses the message: the daemon's owner rules clean up.
    if let Ok(h) = send {
        *GIVE_UP.lock().unwrap_or_else(|e| e.into_inner()) = Some(h);
    }
}

/// Waits for the give-up send, if any (bounded by the client's own deadline); call before exiting.
pub fn settle() {
    let h = GIVE_UP.lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Some(h) = h {
        let _ = h.join();
    }
}

impl Lease {
    /// Gives `command` the lease's variables, without the user's own PostgreSQL settings that
    /// would override them.
    pub fn apply(&self, command: &mut Command) {
        for name in DROPPED_VARS {
            command.env_remove(name);
        }
        command.envs(self.env.iter().map(|(k, v)| (k, v.expose())));
    }

    /// Registers `holder` as the process of this lease, trying again after any answer but `Ack`
    /// until `by` or until `gone()`; whether the daemon confirmed it. One try waits at most
    /// [`REGISTER_TRY`], so an exit is seen soon; a late answer only repeats the registration.
    fn register(&self, holder: Holder, by: Instant, mut gone: impl FnMut() -> bool) -> bool {
        let req = Request::LeaseHolder {
            lease: self.id.clone(),
            holder,
        };
        while !left(by).is_zero() && !gone() {
            let tried = Instant::now();
            let wait = left(by).min(REGISTER_TRY);
            if matches!(call_with_deadline(&socket(), &req, wait), Ok(Response::Ack)) {
                return true;
            }
            // A refusal comes back at once: tries stay `REGISTER_TRY` apart.
            thread::sleep(REGISTER_TRY.saturating_sub(tried.elapsed()).min(left(by)));
        }
        false
    }

    /// Tells the daemon the `migrate` on this candidate made no template, waiting for the
    /// answer (ignored) at most until `by`; with no time left it is still sent, unwaited.
    fn template_failed(&self, by: Instant, interrupted: bool) {
        let ready = Request::TemplateReady {
            lease: self.id.clone(),
            ok: false,
            interrupted,
        };
        let _ = call_with_deadline(&socket(), &ready, left(by));
    }

    /// A `migrate` that ended without a template: the key fails, the candidate goes back, both
    /// within `by`.
    fn no_template(self, why: String, by: Instant, interrupted: bool) -> Result<(), String> {
        self.template_failed(by, interrupted);
        self.release_by(by);
        Err(why)
    }

    /// [`Lease::release`], waiting for the answer at most until `by`.
    fn release_by(mut self, by: Instant) {
        self.given_back = true;
        let req = Request::ReleaseLease {
            lease: self.id.clone(),
        };
        let _ = call_with_deadline(&socket(), &req, left(by));
    }

    /// Leaves the lease to the daemon, without giving it back.
    fn leave(mut self) {
        self.given_back = true;
    }

    /// Tells the daemon which process now owns the lease; repeats every second until it answers.
    pub fn hand_over(&self, child_pid: u32) -> HandOver {
        self.hand_over_to(socket(), child_pid)
    }

    /// [`Lease::hand_over`] to the daemon on `name`. The command's identity is read here, in the
    /// caller's thread, while the caller still holds the unreaped child: a thread could run after
    /// the pid was freed. An unreadable start time stays `None`, which the daemon judges as unknown.
    fn hand_over_to(&self, name: String, child_pid: u32) -> HandOver {
        let (stop, stopped) = mpsc::channel::<()>();
        let lease = self.id.clone();
        let holder = Holder {
            pid: child_pid,
            start: start_time(child_pid),
        };
        let thread = thread::Builder::new()
            .spawn(move || {
                loop {
                    let req = Request::LeaseHolder {
                        lease: lease.clone(),
                        holder,
                    };
                    if matches!(
                        call_at(&name, &req),
                        Ok(Response::Ack | Response::Error { .. })
                    ) {
                        return;
                    }
                    // A message or a closed channel means the command is over.
                    if !matches!(
                        stopped.recv_timeout(HAND_OVER_EVERY),
                        Err(mpsc::RecvTimeoutError::Timeout)
                    ) {
                        return;
                    }
                }
            })
            .ok();
        HandOver {
            stop,
            thread,
            holder,
        }
    }

    /// Gives the lease back; the daemon drops the database.
    pub fn release(mut self) {
        self.give_back();
    }

    fn give_back(&mut self) {
        if !std::mem::replace(&mut self.given_back, true) {
            let _ = call_at(
                &socket(),
                &Request::ReleaseLease {
                    lease: self.id.clone(),
                },
            );
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.give_back();
    }
}

/// The registration of the command as holder, running on its own thread.
pub struct HandOver {
    stop: mpsc::Sender<()>,
    thread: Option<JoinHandle<()>>,
    /// What was registered; read by the unit test.
    #[cfg_attr(not(test), allow(dead_code))]
    holder: Holder,
}

impl HandOver {
    /// Stops retrying and joins the thread (an exchange in flight ends within the client's deadline).
    pub fn finish(self) {
        let _ = self.stop.send(());
        if let Some(t) = self.thread {
            let _ = t.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Child, Command};
    use std::time::Instant;

    /// How long a killed child may take to be reaped.
    const REAP: Duration = Duration::from_secs(10);

    /// Kills the child (result ignored) and polls for its exit, never blocking in `wait`;
    /// whether it was reaped within `limit`.
    fn reap(child: &mut Child, limit: Duration) -> bool {
        let _ = child.kill();
        let start = Instant::now();
        loop {
            if let Ok(Some(_)) = child.try_wait() {
                return true;
            }
            if start.elapsed() >= limit {
                return false;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Prints without waiting: a detached writer that blocks forever on a dead stderr is left
    /// behind and cannot hold up the test.
    fn note(msg: String) {
        let _ = thread::Builder::new().spawn(move || {
            use std::io::Write;
            let _ = writeln!(std::io::stderr(), "{msg}");
        });
    }

    /// Kills and reaps the child on every path, a failed assertion included (the test holds
    /// the handle, so the pid cannot have been reused).
    struct Reap(Child);

    impl Drop for Reap {
        fn drop(&mut self) {
            if !reap(&mut self.0, REAP) {
                note(format!(
                    "lease test: the child was not reaped within {REAP:?}; leaving it"
                ));
            }
        }
    }

    /// The holder is read in the caller's thread: a command that ends right after `hand_over`
    /// (killed here, then reaped) must still be registered under its own start time.
    #[test]
    fn the_holder_is_read_before_the_command_can_be_reaped() {
        let _own = crate::client::SPAWN_VS_PIPES
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut c = if cfg!(windows) {
            let mut c = Command::new("ping");
            c.args(["-n", "30", "127.0.0.1"]);
            c
        } else {
            let mut c = Command::new("sleep");
            c.arg("30");
            c
        };
        let mut child = Reap(c.stdout(std::process::Stdio::null()).spawn().unwrap());
        let pid = child.0.id();
        let expected = Holder {
            pid,
            start: start_time(pid),
        };
        assert!(expected.start.is_some(), "the start time of a live child");
        let lease = Lease {
            id: "x".into(),
            env: BTreeMap::new(),
            given_back: true,
        };
        // No daemon listens on this name; only the holder matters.
        let h = lease.hand_over_to("sync_gate-lease-unit-no-daemon".into(), pid);
        assert!(
            reap(&mut child.0, REAP),
            "the child was not reaped within {REAP:?}"
        );
        assert!(
            h.holder == expected,
            "the holder is not the child's own identity"
        );
        h.finish();
    }

    #[test]
    fn an_old_daemon_that_ignores_the_key_is_not_trusted() {
        let key = "0123456789abcdef";
        let leased = |template: Option<&str>| Response::Leased {
            lease: "x".into(),
            env: BTreeMap::new(),
            template: template.map(String::from),
            extensions: Vec::new(),
        };
        // No key in the reply (an older daemon), or another one: given back.
        for template in [None, Some("fedcba9876543210")] {
            match interpret(leased(template), Some(key), &[]) {
                Reply::Refused(Some(mut l), why) => {
                    assert_eq!(l.id, "x");
                    assert_eq!(why, "the daemon is older than this command");
                    // The caller gives it back; no daemon listens in this test.
                    l.given_back = true;
                }
                other => panic!("{template:?}: {other:?}"),
            }
        }
        // The key it was asked with, or a request without one: used.
        for (template, asked) in [(Some(key), Some(key)), (None, None)] {
            match interpret(leased(template), asked, &[]) {
                Reply::Leased(mut l) => l.given_back = true,
                other => panic!("{template:?}: {other:?}"),
            }
        }
    }

    #[test]
    fn a_daemon_that_does_not_echo_the_extensions_is_not_trusted() {
        let key = "0123456789abcdef";
        let ext = |l: &[&str]| l.iter().map(|e| e.to_string()).collect::<Vec<_>>();
        let leased = |echo: Vec<String>| Response::Leased {
            lease: "x".into(),
            env: BTreeMap::new(),
            template: Some(key.into()),
            extensions: echo,
        };
        let prepare = |echo: Vec<String>| Response::Prepare {
            lease: "x".into(),
            env: BTreeMap::new(),
            extensions: echo,
        };
        let cli = ext(&["citext"]);
        // No echo (an older daemon) or another list: given back, migrate never runs.
        for reply in [
            prepare(vec![]),
            prepare(ext(&["pg_trgm"])),
            leased(vec![]),
            leased(ext(&["citext", "pg_trgm"])),
        ] {
            match interpret(reply, Some(key), &cli) {
                Reply::Refused(Some(mut l), why) => {
                    assert_eq!(l.id, "x");
                    assert_eq!(why, "the daemon is older than this command");
                    l.given_back = true;
                }
                other => panic!("{other:?}"),
            }
        }
        // The same list: used.
        match interpret(leased(cli.clone()), Some(key), &cli) {
            Reply::Leased(mut l) => l.given_back = true,
            other => panic!("{other:?}"),
        }
        match interpret(prepare(cli.clone()), Some(key), &cli) {
            Reply::Prepare(mut l) => l.given_back = true,
            other => panic!("{other:?}"),
        }
        // No extensions in the project: any echo is accepted.
        match interpret(prepare(vec![]), Some(key), &[]) {
            Reply::Prepare(mut l) => l.given_back = true,
            other => panic!("{other:?}"),
        }
        match interpret(leased(ext(&["x"])), Some(key), &[]) {
            Reply::Leased(mut l) => l.given_back = true,
            other => panic!("{other:?}"),
        }
    }
}
