//! Library half of the `sync_gated` daemon: state, control loop, MCP hub, persistence and IPC.

pub mod control_loop;
// Guests are Windows-only; the policy half also builds in every system's tests.
#[cfg(any(windows, test))]
mod guest;
pub mod hub;
pub mod ipc;
pub mod services;
pub mod state;
pub mod store;
pub mod supervisor;
pub mod update_check;

pub use control_loop::{Control, Core, Measure, OsControl};
pub use hub::{Hub, McpReload};
pub use services::{Deps, Services};
pub use supervisor::{Launcher, OsLauncher};

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use sync_gate_core::{Config, Request, Response, SERVICE_POSTGRES};
use sync_gate_probe::Probe;

/// Longest wait for the hub's tick thread at shutdown or abort; a stopped hub ignores a late tick.
const HUB_TICKER_WAIT: Duration = Duration::from_secs(1);

/// A running daemon: the IPC servers (control and MCP hub) plus the two tick threads.
pub struct DaemonHandle<C: Control = OsControl> {
    core: Arc<Core<C>>,
    hub: Arc<Hub>,
    /// The shared PostgreSQL service (inert without `[postgres]`).
    services: Arc<Services>,
    /// Dropping the sender stops the tick thread.
    stop: mpsc::Sender<()>,
    ticker: JoinHandle<()>,
    /// The hub's own tick thread (its deadlines must not wait for a blocked core tick).
    hub_stop: mpsc::Sender<()>,
    hub_ticker: JoinHandle<()>,
    server: ipc::ServerHandle,
    /// One per listed guest that could be served (Windows).
    guests: Vec<ipc::ServerHandle>,
    hub_server: ipc::ServerHandle,
    /// Held for the daemon's lifetime; dropped last, after the clean shutdown work.
    _instance: Option<store::InstanceLock>,
}

impl<C: Control> DaemonHandle<C> {
    /// Clean exit: stop ticking, resume every paused job (before the IPC teardown, which may
    /// wait on connections) and record what is still frozen, all within one bound (5 s); then
    /// stop the MCP hub (no new connections, clients closed, own children stopped; bounded by
    /// the accept wake deadline plus the hub's stop grace, then at most `HUB_TICKER_WAIT` for
    /// the hub's tick thread), stop serving, save the cost model.
    pub fn shutdown(self) {
        if let Some(n) = self.shutdown_bounded() {
            eprintln!("{}", shutdown_timed_out(n));
        }
    }

    /// [`Self::shutdown`]; `Some(units still frozen)` when the bound was hit. A tick or resume
    /// blocked in an OS call is left behind: its units are in flight, so they stay on record.
    pub(crate) fn shutdown_bounded(self) -> Option<usize> {
        let deadline = Instant::now() + self.core.shutdown_bound();
        // A late tick must not pause anything from here on.
        self.core.begin_shutdown();
        drop(self.stop);
        // resume_all first: a tick blocked in an OS call must not eat the bound before the
        // other paused jobs are resumed. Everything below waits against the same deadline.
        let (tx, rx) = mpsc::channel();
        let core = self.core.clone();
        thread::spawn(move || {
            core.resume_all(Instant::now());
            let _ = tx.send(());
        });
        let mut done = rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .is_ok();
        done &= wait_until(deadline, || self.ticker.is_finished());
        done &= self.core.finish_resumes(deadline);
        // Always: whatever is still frozen is on record before the instance lock is released.
        let frozen = self.core.close();
        // The hub after the jobs: its stop must not delay a resume. Both calls have their own
        // bounds. A stopped hub spawns nothing new; a spawn already under way when the stop
        // arrives is stopped right after it by that thread, which shutdown does not wait for:
        // its child is in the registry first, so the next start reaps it if the daemon exits
        // before the stop completes.
        drop(self.hub_stop);
        self.hub_server.shutdown();
        self.hub.shutdown();
        wait_until(Instant::now() + HUB_TICKER_WAIT, || {
            self.hub_ticker.is_finished()
        });
        self.server.shutdown();
        self.guests
            .into_iter()
            .for_each(ipc::ServerHandle::shutdown);
        self.core.save_cost();
        // Last, with its own bound (ruling PF15): it never delays a resume, and with live
        // leases the server is left running for the next daemon.
        self.services.shutdown();
        for note in self.services.take_notes() {
            eprintln!("sync_gated: {note}");
        }
        (!done).then_some(frozen)
    }

    /// Stops the threads without resuming, stopping MCP children or saving; simulates a crash
    /// in tests (the children see their stdin close, as they would if the daemon died).
    pub fn abort(self) {
        drop(self.stop);
        drop(self.hub_stop);
        let _ = self.ticker.join();
        self.hub_server.shutdown();
        self.hub.abort();
        wait_until(Instant::now() + HUB_TICKER_WAIT, || {
            self.hub_ticker.is_finished()
        });
        self.server.shutdown();
        self.guests
            .into_iter()
            .for_each(ipc::ServerHandle::shutdown);
    }
}

/// Starts the real daemon on `socket_name` (the hub on `<socket_name>-mcp`), with its files
/// in the per-user data dir. `reload` rereads the config's `[mcp]`, so the hub can serve a
/// server added after the start.
pub fn run(cfg: Config, socket_name: &str, reload: Option<McpReload>) -> io::Result<DaemonHandle> {
    run_with_pg(
        cfg,
        socket_name,
        Probe::new(),
        OsControl,
        store::default_dir(),
        Arc::new(OsLauncher::default()),
        Deps {
            mcp_reload: reload,
            ..Deps::os()
        },
    )
}

/// [`run`] with injectable measurement, process control, data dir (`None` = in memory) and
/// launcher of the MCP hub's servers.
pub fn run_with<M, C>(
    cfg: Config,
    socket_name: &str,
    measure: M,
    control: C,
    data_dir: Option<PathBuf>,
    launcher: Arc<dyn Launcher>,
) -> io::Result<DaemonHandle<C>>
where
    M: Measure + Send + 'static,
    C: Control,
{
    run_with_pg(
        cfg,
        socket_name,
        measure,
        control,
        data_dir,
        launcher,
        Deps::os(),
    )
}

/// [`run_with`] with the shared PostgreSQL service's dependencies injected.
pub fn run_with_pg<M, C>(
    cfg: Config,
    socket_name: &str,
    measure: M,
    control: C,
    data_dir: Option<PathBuf>,
    launcher: Arc<dyn Launcher>,
    deps: Deps,
) -> io::Result<DaemonHandle<C>>
where
    M: Measure + Send + 'static,
    C: Control,
{
    let names = cfg.guests.clone();
    start_daemon(
        cfg,
        socket_name,
        measure,
        control,
        data_dir,
        launcher,
        store::LOCK_WAIT,
        deps,
        move |core, socket| serve_listed(&names, socket, core),
    )
}

/// [`run_with`] with the instance-lock wait (shortened by tests).
#[cfg(test)]
pub(crate) fn run_with_lock_wait<M, C>(
    cfg: Config,
    socket_name: &str,
    measure: M,
    control: C,
    data_dir: Option<PathBuf>,
    launcher: Arc<dyn Launcher>,
    lock_wait: Duration,
) -> io::Result<DaemonHandle<C>>
where
    M: Measure + Send + 'static,
    C: Control,
{
    let names = cfg.guests.clone();
    start_daemon(
        cfg,
        socket_name,
        measure,
        control,
        data_dir,
        launcher,
        lock_wait,
        Deps::os(),
        move |core, socket| serve_listed(&names, socket, core),
    )
}

/// [`run_with`] with the guests already resolved (test hook: no LSA, no config).
#[cfg(all(test, windows))]
pub(crate) fn run_with_guests<M, C>(
    cfg: Config,
    socket_name: &str,
    measure: M,
    control: C,
    data_dir: Option<PathBuf>,
    launcher: Arc<dyn Launcher>,
    guests: Vec<guest::Guest>,
) -> io::Result<DaemonHandle<C>>
where
    M: Measure + Send + 'static,
    C: Control,
{
    start_daemon(
        cfg,
        socket_name,
        measure,
        control,
        data_dir,
        launcher,
        store::LOCK_WAIT,
        Deps::os(),
        move |core, socket| serve_guests(guests, socket, core),
    )
}

/// Resolves the listed guests and serves one pipe for each; none listed = nothing at all
/// (no LSA call, no pipe). A guest that cannot be served is said and skipped.
#[cfg(windows)]
fn serve_listed<C: Control>(
    names: &[String],
    socket: &str,
    core: &Arc<Core<C>>,
) -> Vec<ipc::ServerHandle> {
    use sync_gate_core::{APPCONTAINER_GUEST, RESTRICTED_GUEST};
    if names.is_empty() {
        return Vec::new();
    }
    let reserved = |n: &&String| *n == APPCONTAINER_GUEST || *n == RESTRICTED_GUEST;
    let domain = guest::local_account_domain();
    let names: Vec<String> = match &domain {
        Some(_) => names.to_vec(),
        None => {
            if names.iter().any(|n| !reserved(&n)) {
                eprintln!("sync_gated: cannot read this machine's account domain; guests ignored");
            }
            names.iter().filter(reserved).cloned().collect()
        }
    };
    let own = match ipc::user_sid() {
        Ok(sid) => sid,
        Err(e) => {
            eprintln!("sync_gated: cannot read this account's SID ({e}); guests ignored");
            return Vec::new();
        }
    };
    let (dom_name, dom_sid) = domain.unwrap_or_default();
    let logon = guest::logon_sid();
    let (kept, notes) = guest::resolve(
        &names,
        |n| guest::lookup_account(&dom_name, n),
        &own,
        &dom_sid,
        logon.as_deref(),
    );
    for note in notes {
        eprintln!("sync_gated: guest {note}; ignored");
    }
    let guests = kept
        .into_iter()
        .map(|(index, name, kind, ace_sid)| guest::Guest {
            index,
            name,
            ident_of_pid: guest::os_ident_of_pid(kind.clone()),
            kind,
            ace_sid,
        })
        .collect();
    serve_guests(guests, socket, core)
}

#[cfg(not(windows))]
fn serve_listed<C: Control>(
    names: &[String],
    _socket: &str,
    _core: &Arc<Core<C>>,
) -> Vec<ipc::ServerHandle> {
    if !names.is_empty() {
        eprintln!(
            "sync_gated: guests are Windows-only (the Codex sandbox runs as your user on macOS and Linux); ignored"
        );
    }
    Vec::new()
}

/// One pipe per guest: `<socket>-guest-<account>` or `<socket>-sbx-<kind>`, each request
/// judged by the identity of its own message.
#[cfg(windows)]
fn serve_guests<C: Control>(
    guests: Vec<guest::Guest>,
    socket: &str,
    core: &Arc<Core<C>>,
) -> Vec<ipc::ServerHandle> {
    use sync_gate_core::{guest_socket_name, sandbox_socket_name};
    guests
        .into_iter()
        .filter_map(|g| {
            let pipe = if g.name.starts_with('@') {
                sandbox_socket_name(socket, &g.name)
            } else {
                guest_socket_name(socket, &g.name)
            };
            let (name, kind, ace) = (g.name.clone(), g.kind.clone(), g.ace_sid.clone());
            let core = core.clone();
            let served = ipc::serve_guest(
                &pipe,
                &name,
                &ace,
                move |view| sync_gate_probe::ident_of(&kind, view),
                move |client, req| guest::respond_guest(&core, &g, client, req, Instant::now()),
            );
            match served {
                Ok(server) => {
                    eprintln!("sync_gated: guest {name} may queue commands on {pipe}");
                    Some(server)
                }
                Err(e) => {
                    eprintln!(
                        "sync_gated: cannot serve guest {name}: {e}; its commands run without queue"
                    );
                    None
                }
            }
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn start_daemon<M, C>(
    cfg: Config,
    socket_name: &str,
    mut measure: M,
    control: C,
    data_dir: Option<PathBuf>,
    launcher: Arc<dyn Launcher>,
    lock_wait: Duration,
    mut deps: Deps,
    serve_guests: impl FnOnce(&Arc<Core<C>>, &str) -> Vec<ipc::ServerHandle>,
) -> io::Result<DaemonHandle<C>>
where
    M: Measure + Send + 'static,
    C: Control,
{
    // Single instance first: a second daemon must fail before it reads or rewrites the live
    // daemon's paused set (recovery) or measures anything.
    let instance = data_dir
        .as_deref()
        .map(|d| store::lock_instance_within(d, lock_wait))
        .transpose()?;
    // The daemon never reads `pending` (it only sweeps expired files from it, every ten minutes
    // from the first tick below), but the CLI trusts it: tighten it if it exists.
    if let Some(d) = data_dir
        .as_deref()
        .map(|d| d.join("pending"))
        .filter(|d| d.exists())
        && let Err(e) = sync_gate_probe::create_private_dir(&d)
    {
        eprintln!("sync_gated: pending folder {}: {e}", d.display());
    }
    let cost = data_dir
        .as_deref()
        .map(|d| store::load(&d.join("cost.json")))
        .unwrap_or_default();
    let period = Duration::from_millis(cfg.tick_ms);
    let hub_cfg = cfg.clone();
    let core = Arc::new(Core::new(cfg, cost, control, data_dir.clone()));
    // R15: a previous run killed without a clean shutdown may have left processes frozen. The
    // same pass a CLI runs through `recover_as_owner`, under the instance lock taken above.
    // First: frozen user jobs must not wait for the (possibly slow) leftover cleanup below.
    core.recover_paused(Instant::now());
    // Processes this daemon started in a previous run are stopped before anything new is spawned.
    if let Some(d) = data_dir.as_deref() {
        let mut reg = supervisor::Registry::load(&d.join("services.json"));
        supervisor::reap_leftovers(&*launcher, &mut reg);
    }
    let hub = Arc::new(Hub::new(
        &hub_cfg,
        launcher,
        data_dir.as_deref(),
        deps.mcp_reload.take(),
    ));
    // Not in `services.json`: the cluster is adopted by its proven identity, never reaped.
    let services = Arc::new(Services::new(&hub_cfg, data_dir.as_deref(), deps));
    // One snapshot before serving, so the first Acquire can be admitted at once.
    tick(&core, &hub, &services, &mut measure, Instant::now());
    let server = {
        let (core, hub, services) = (core.clone(), hub.clone(), services.clone());
        ipc::serve(socket_name, move |req| {
            respond(&core, &hub, &services, req, Instant::now())
        })?
    };
    let guests = serve_guests(&core, socket_name);
    let hub_server = {
        let hub = hub.clone();
        let served = ipc::serve_stream(&format!("{socket_name}-mcp"), move |r, w, close| {
            hub.serve_conn(r, w, close)
        });
        match served {
            Ok(s) => s,
            Err(e) => {
                server.shutdown();
                guests.into_iter().for_each(ipc::ServerHandle::shutdown);
                return Err(e);
            }
        }
    };
    let (hub_stop, hub_rx) = mpsc::channel::<()>();
    let hub_ticker = {
        let hub = hub.clone();
        thread::Builder::new()
            .name("sync_gated-hub-tick".into())
            .spawn(move || {
                while let Err(RecvTimeoutError::Timeout) = hub_rx.recv_timeout(period) {
                    hub.tick(Instant::now());
                }
            })
    };
    let hub_ticker = match hub_ticker {
        Ok(t) => t,
        Err(e) => {
            hub_server.shutdown();
            hub.abort();
            server.shutdown();
            guests.into_iter().for_each(ipc::ServerHandle::shutdown);
            return Err(e);
        }
    };
    let (stop, rx) = mpsc::channel::<()>();
    let ticker = {
        let (core, hub, services) = (core.clone(), hub.clone(), services.clone());
        // The tick thread owns the probe (a sysinfo System).
        thread::spawn(move || {
            while let Err(RecvTimeoutError::Timeout) = rx.recv_timeout(period) {
                tick(&core, &hub, &services, &mut measure, Instant::now());
            }
        })
    };
    Ok(DaemonHandle {
        core,
        hub,
        services,
        stop,
        ticker,
        hub_stop,
        hub_ticker,
        server,
        guests,
        hub_server,
        _instance: instance,
    })
}

/// One daemon tick: the hub's unmeasured children into the core's admission, the control loop,
/// then the hub's memory input, the RSS of its children,
/// the shared services (which only queue work), and their decisions into the shared log. No
/// core lock is held while the hub or the services run. The hub's deadlines and pool decisions
/// (`Hub::tick`) run on the hub's own tick thread.
fn tick<C: Control>(
    core: &Core<C>,
    hub: &Hub,
    services: &Services,
    m: &mut impl Measure,
    now: Instant,
) {
    core.set_hub_reserved(hub.unmeasured());
    core.tick(m, now);
    if let Some((free, reserve)) = core.memory() {
        hub.set_memory(free, reserve);
    }
    hub.measure(|pid| m.tree_rss(pid));
    services.tick(now);
    services.measure(|pid| m.tree_rss(pid));
    core.record_all(now, hub.take_notes());
    core.record_all(now, services.take_notes());
}

/// A control request: lease messages go to the services first (ruling PF3: an unknown
/// service is refused here); `Status` also reports the hub's servers and the services.
fn respond<C: Control>(
    core: &Core<C>,
    hub: &Hub,
    services: &Services,
    req: Request,
    now: Instant,
) -> Response {
    core.record_all(now, hub.take_notes());
    core.record_all(now, services.take_notes());
    match req {
        Request::Lease { service, .. } if service != SERVICE_POSTGRES => Response::Error {
            message: "unknown service".into(),
        },
        Request::Lease {
            project,
            holder,
            request,
            template,
            extensions,
            ..
        } => services.lease(&project, holder, &request, template.as_deref(), &extensions),
        Request::TemplateReady {
            lease,
            ok,
            interrupted,
        } => services.template_ready(&lease, ok, interrupted),
        Request::LeaseHolder { lease, holder } => services.set_holder(&lease, holder),
        Request::ReleaseLease { lease } => services.release(&lease),
        Request::LeaseGiveUp { request } => services.give_up(&request),
        req => {
            let mut resp = core.handle(req, now);
            if let Response::Status(s) = &mut resp {
                s.mcp = hub.report();
                s.services = services.report();
            }
            resp
        }
    }
}

pub(crate) fn shutdown_timed_out(n: usize) -> String {
    format!(
        "sync_gated: shutdown timed out with {n} unit(s) still frozen; they are recorded for recovery"
    )
}

/// Polls `done` until it holds or `deadline` passes; true when it held.
fn wait_until(deadline: Instant, done: impl Fn() -> bool) -> bool {
    loop {
        if done() {
            return true;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return false;
        }
        thread::sleep(left.min(Duration::from_millis(5)));
    }
}

#[cfg(test)]
mod tests;
