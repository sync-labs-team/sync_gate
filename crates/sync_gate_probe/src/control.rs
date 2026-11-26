//! Suspend and resume a whole process tree. sync_gate never kills: the only
//! operations are thread suspend/resume (Windows) and SIGSTOP/SIGCONT (Unix).
use crate::tree::{descendants, ppid_table, walk};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io;
#[cfg(windows)]
use std::os::windows::io::OwnedHandle;

/// One suspendable unit as `(pid, tid)`: a thread on Windows, a whole process (tid 0) on Unix.
pub(crate) type Unit = (u32, u32);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Action {
    Suspend,
    Resume,
}

/// Maximum number of tree scans per `suspend_tree` call.
const MAX_PASSES: usize = 3;

/// Freeze `root_pid` and all its descendants, parents first so nothing can fork behind us.
///
/// Thin wrapper over [`suspend_tree_recorded`] for callers that resume by a fresh scan.
/// Calls must be paired by the caller: on Windows suspend counts nest, so two
/// `suspend_tree` calls need two `resume_tree` calls.
pub fn suspend_tree(root_pid: u32) -> io::Result<()> {
    suspend_tree_recorded(root_pid)
        .map(|_| ())
        .map_err(|(left, e)| {
            // Best effort: one more try at whatever the rollback could not resume.
            let _ = left.resume();
            e
        })
}

/// One frozen unit with its process start time, so a later run can tell a reused pid apart.
/// `tid` is 0 on Unix (the whole process is the unit). `start_time` 0 means unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrozenUnit {
    pub pid: u32,
    pub tid: u32,
    pub start_time: u64,
}

/// The exact units one [`suspend_tree_recorded`] call froze, in suspend order.
/// Resuming these (not a fresh scan) also reaches grandchildren orphaned while frozen.
#[derive(Debug)]
#[must_use = "a dropped Suspension leaves the tree frozen; call resume()"]
pub struct Suspension {
    units: Vec<FrozenUnit>,
}

impl Suspension {
    /// Rebuilds a suspension from persisted units (crash recovery). The caller checks start times first.
    pub fn from_units(units: Vec<FrozenUnit>) -> Self {
        Self { units }
    }

    pub fn units(&self) -> &[FrozenUnit] {
        &self.units
    }

    /// Resumes exactly the recorded units, newest first. Vanished units are dropped; every
    /// unit is attempted. On a real error, returns the units that failed (to retry) and the first error.
    pub fn resume(self) -> Result<(), (Suspension, io::Error)> {
        let raw: Vec<Unit> = self.units.iter().map(|u| (u.pid, u.tid)).collect();
        resume_units(&raw, &mut platform_act).map_err(|(failed, e)| {
            let units = self
                .units
                .into_iter()
                .filter(|u| failed.contains(&(u.pid, u.tid)))
                .collect();
            (Suspension { units }, e)
        })
    }
}

/// Freeze `root_pid` and all its descendants, recording what was frozen.
///
/// Coverage: the tree is scanned up to 3 times, suspending anything not yet suspended by
/// this call, and stops early when a scan finds nothing new. A thread or child created
/// by a still-running thread between scans is caught by the next scan; one created in the
/// final window after the last scan can still escape (best effort, not atomic).
/// On `Err` a failure other than "already gone", or a root that was never reached, resumes
/// (in reverse order) whatever this call suspended; the returned `Suspension` holds the units
/// that rollback could not resume (usually none), for the caller to retry.
/// Refuses pid 0 and our own pid or ancestors (`InvalidInput`); an unknown or unreached
/// root is `NotFound`.
pub fn suspend_tree_recorded(root_pid: u32) -> Result<Suspension, (Suspension, io::Error)> {
    check_root(root_pid).map_err(|e| (Suspension { units: Vec::new() }, e))?;
    suspend_with_rollback(
        root_pid,
        &mut || scan(root_pid),
        &mut |_| Ok(()),
        &mut platform_act,
    )
    .map(recorded)
    .map_err(|(left, e)| (recorded(left), e))
}

/// Units with their start times, so a later run can tell a reused pid apart.
fn recorded(done: Vec<Unit>) -> Suspension {
    let pids: Vec<u32> = done.iter().map(|u| u.0).collect();
    let starts = start_times(&pids);
    let units = done
        .into_iter()
        .map(|(pid, tid)| FrozenUnit {
            pid,
            tid,
            start_time: starts.get(&pid).copied().unwrap_or(0),
        })
        .collect();
    Suspension { units }
}

/// Start time (seconds since the epoch) of each live pid in `pids`; dead pids are absent.
fn start_times(pids: &[u32]) -> std::collections::HashMap<u32, u64> {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
    let Ok(mut sys) = System::new() else {
        return Default::default();
    };
    let wanted: Vec<Pid> = pids.iter().map(|&p| Pid::from_u32(p)).collect();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&wanted),
        true,
        ProcessRefreshKind::nothing(),
    );
    pids.iter()
        .filter_map(|&p| sys.process(Pid::from_u32(p)).map(|x| (p, x.start_time())))
        .collect()
}

/// Start time of a live process, `None` if it is gone.
pub fn start_time(pid: u32) -> Option<u64> {
    start_times(&[pid]).get(&pid).copied()
}

/// Undo [`suspend_tree`] on the current tree, children first. Best effort: every unit is
/// attempted, vanished ones are ignored, the first other error is returned.
pub fn resume_tree(root_pid: u32) -> io::Result<()> {
    check_root(root_pid)?;
    let mut units = scan(root_pid)?;
    units.reverse();
    let (mut first_err, mut reached) = (None, false);
    for u in units {
        match platform_act(u, Action::Resume) {
            Ok(()) => reached |= u.0 == root_pid,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                first_err.get_or_insert(e);
            }
        }
    }
    match (first_err, reached) {
        (Some(e), _) => Err(e),
        (None, true) => Ok(()),
        (None, false) => Err(io::ErrorKind::NotFound.into()),
    }
}

/// Pure resume loop (the testable seam): `units` in reverse, `NotFound` dropped. On a real
/// error returns the units that failed, in their original order, and the first error.
pub(crate) fn resume_units(
    units: &[Unit],
    act: &mut impl FnMut(Unit, Action) -> io::Result<()>,
) -> Result<(), (Vec<Unit>, io::Error)> {
    let (mut failed, mut first_err) = (Vec::new(), None);
    for &u in units.iter().rev() {
        match act(u, Action::Resume) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                failed.push(u);
                first_err.get_or_insert(e);
            }
        }
    }
    failed.reverse();
    first_err.map_or(Ok(()), |e| Err((failed, e)))
}

fn check_root(root: u32) -> io::Result<()> {
    if root == 0 || root == std::process::id() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to touch pid 0 or ourselves",
        ));
    }
    Ok(())
}

/// Current units of the tree rooted at `root`, parents before children.
fn scan(root: u32) -> io::Result<Vec<Unit>> {
    let order = descendants(root, &ppid_table()?);
    if order.is_empty() {
        return Err(io::ErrorKind::NotFound.into());
    }
    if order.contains(&std::process::id()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "target tree contains this process",
        ));
    }
    units_of(&order)
}

/// Pure suspend loop (the testable seam). `scan` lists the tree's units; `act` performs one
/// action, where `ErrorKind::NotFound` means "already gone" and is ignored.
/// `plan` is called with each batch of units BEFORE any of them is suspended (write-ahead, D2);
/// an error stops the call: that batch is not touched, earlier ones are resumed. The owner's
/// path passes `|_| Ok(())` (behaviour unchanged).
/// Returns the units this call suspended, in order. On failure, returns the units the
/// rollback could not resume (still frozen) with the original error.
pub(crate) fn suspend_with_rollback(
    root: u32,
    scan: &mut impl FnMut() -> io::Result<Vec<Unit>>,
    plan: &mut impl FnMut(&[Unit]) -> io::Result<()>,
    act: &mut impl FnMut(Unit, Action) -> io::Result<()>,
) -> Result<Vec<Unit>, (Vec<Unit>, io::Error)> {
    let (mut done, mut seen): (Vec<Unit>, HashSet<Unit>) = (Vec::new(), HashSet::new());
    let mut failure = None;
    'passes: for pass in 0..MAX_PASSES {
        let units = match scan() {
            Ok(u) => u,
            Err(e) if pass > 0 && e.kind() == io::ErrorKind::NotFound => break,
            Err(e) => {
                failure = Some(e);
                break;
            }
        };
        let fresh: Vec<Unit> = units.into_iter().filter(|u| seen.insert(*u)).collect();
        if fresh.is_empty() {
            break;
        }
        if let Err(e) = plan(&fresh) {
            failure = Some(e);
            break;
        }
        for u in fresh {
            match act(u, Action::Suspend) {
                Ok(()) => done.push(u),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => {
                    failure = Some(e);
                    break 'passes;
                }
            }
        }
    }
    if failure.is_none() && !done.iter().any(|u| u.0 == root) {
        failure = Some(io::ErrorKind::NotFound.into());
    }
    match failure {
        None => Ok(done),
        Some(e) => {
            let still_frozen = resume_units(&done, act)
                .err()
                .map_or_else(Vec::new, |f| f.0);
            Err((still_frozen, e))
        }
    }
}

/// What identifies a process's token for the queue (strings are S-1-... SIDs).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TokenView {
    pub user: String,
    pub restricted: Vec<String>,
    pub app_container: Option<String>,
}

/// The kind a guest entry stands for, with the SIDs it needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentKind {
    /// The account's SID.
    Account(String),
    /// The owner's SID.
    AppContainer(String),
    /// The owner's SID.
    Restricted(String),
}

/// The identity of a token for guests of `kind`, None when the token is not of that kind.
/// SIDs are compared ignoring case.
/// - `Account(s)`: user == s -> `account:{s}`;
/// - `AppContainer(o)`: user == o, in an AppContainer `c` -> `appcontainer:{o}:{c}`;
/// - `Restricted(o)`: user == o, restricting SIDs, no AppContainer ->
///   `restricted:{o}:{restricting SIDs, sorted, joined by ','}`.
///
/// The `elevated` sandbox token (user = the sandbox account, restricted, F36) is never
/// `Restricted(owner)`.
pub fn ident_of(kind: &IdentKind, t: &TokenView) -> Option<String> {
    let user_is = |sid: &str| t.user.eq_ignore_ascii_case(sid);
    match kind {
        IdentKind::Account(s) if user_is(s) => Some(format!("account:{s}")),
        IdentKind::AppContainer(o) if user_is(o) => t
            .app_container
            .as_ref()
            .map(|c| format!("appcontainer:{o}:{c}")),
        IdentKind::Restricted(o)
            if user_is(o) && !t.restricted.is_empty() && t.app_container.is_none() =>
        {
            let mut sids = t.restricted.clone();
            sids.sort();
            Some(format!("restricted:{o}:{}", sids.join(",")))
        }
        _ => None,
    }
}

/// The kind an ident was made for (its prefix and owner or account SID); None if malformed.
pub fn ident_kind(ident: &str) -> Option<IdentKind> {
    let (prefix, rest) = ident.split_once(':')?;
    let (sid, tail) = rest
        .split_once(':')
        .map_or((rest, None), |(s, t)| (s, Some(t)));
    if sid.is_empty() || tail.is_some_and(str::is_empty) {
        return None;
    }
    let sid = sid.to_string();
    match (prefix, tail.is_some()) {
        ("account", false) => Some(IdentKind::Account(sid)),
        ("appcontainer", true) => Some(IdentKind::AppContainer(sid)),
        ("restricted", true) => Some(IdentKind::Restricted(sid)),
        _ => None,
    }
}

/// The guest's part of a tree, parents first: `info(pid)` = Some((matches the ident, created));
/// a process is kept only when it matches and was created at or after the root; never walks
/// below a process that is not kept; the root must pass, else empty.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn guest_order(
    root: u32,
    ppids: &HashMap<u32, u32>,
    mut info: impl FnMut(u32) -> Option<(bool, u64)>,
) -> Vec<u32> {
    // A guest's pause never trusts parentage alone: a process is frozen only when its token has
    // the job's identity and it was created after the root (K3).
    let Some((true, start)) = info(root) else {
        return Vec::new();
    };
    walk(root, ppids, |pid| {
        pid == root || matches!(info(pid), Some((true, created)) if created >= start)
    })
}

/// One frozen thread of a guest's job, as recorded (write-ahead) and recovered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestUnit {
    pub pid: u32,
    pub tid: u32,
    /// Process creation, FILETIME 100 ns.
    pub created: u64,
    pub ident: String,
}

/// What one [`suspend_tree_as`] froze: the units and, on Windows, the open handle of each
/// suspended thread. Resuming acts ONLY through those handles, never through an id (D1).
/// Dropping it without `resume()` leaves the threads frozen (as a crash would) and closes the
/// handles.
#[derive(Debug)]
#[must_use = "a dropped GuestSuspension leaves the guest's threads frozen; call resume()"]
pub struct GuestSuspension {
    units: Vec<GuestUnit>,
    /// The handle of each suspended thread, in the order of `units`.
    #[cfg(windows)]
    threads: Vec<OwnedHandle>,
}

impl GuestSuspension {
    fn empty() -> Self {
        Self {
            units: Vec::new(),
            #[cfg(windows)]
            threads: Vec::new(),
        }
    }

    /// A suspension made of these units and handles, whatever they really name (test 36).
    #[cfg(all(test, windows))]
    fn from_parts(units: Vec<GuestUnit>, threads: Vec<OwnedHandle>) -> Self {
        Self { units, threads }
    }

    pub fn units(&self) -> &[GuestUnit] {
        &self.units
    }

    /// `ResumeThread` on each held handle, newest first. A thread that ended (S17) counts as
    /// resumed. On a real error: the failed units with their handles, and the first error.
    pub fn resume(self) -> Result<(), (GuestSuspension, io::Error)> {
        #[cfg(windows)]
        {
            // Only the handles taken at suspension: an id may name another process by now (D1).
            let (mut left, mut first) = (Self::empty(), None);
            for (unit, thread) in self.units.into_iter().zip(self.threads).rev() {
                match win::act_on_guest(&thread, Action::Resume) {
                    Err(e) if e.kind() != io::ErrorKind::NotFound => {
                        left.units.push(unit);
                        left.threads.push(thread);
                        first.get_or_insert(e);
                    }
                    _ => {}
                }
            }
            left.units.reverse();
            left.threads.reverse();
            first.map_or(Ok(()), |e| Err((left, e)))
        }
        #[cfg(not(windows))]
        {
            if self.units.is_empty() {
                Ok(())
            } else {
                Err((self, io::ErrorKind::Unsupported.into()))
            }
        }
    }
}

/// Keeps the units `open` accepts. `NotFound` from `open` means the unit is genuinely gone (the
/// thread id no longer exists, or names another process's thread) and is skipped; every other
/// error is returned, so the caller's earlier suspensions roll back and the pause fails.
#[cfg(any(windows, test))]
pub(crate) fn retain_openable(
    units: Vec<Unit>,
    open: &mut impl FnMut(Unit) -> io::Result<()>,
) -> io::Result<Vec<Unit>> {
    let mut kept = Vec::new();
    for u in units {
        match open(u) {
            Ok(()) => kept.push(u),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(kept)
}

/// Whether the process a recorded unit names still is the one recorded. `query(kind)` is the
/// process's `(ident, created)`: `Ok(None)` when it is gone or its token is not of the kind,
/// `Err` when it could not be checked. `Ok` = verified; `NotFound` = gone or another process
/// (drop the unit); any other error = not verified (keep the unit, try again later).
#[cfg(any(windows, test))]
pub(crate) fn check_recorded(
    u: &GuestUnit,
    query: impl FnOnce(&IdentKind) -> io::Result<Option<(String, u64)>>,
) -> io::Result<()> {
    let gone = || io::Error::from(io::ErrorKind::NotFound);
    let kind = ident_kind(&u.ident).ok_or_else(gone)?;
    match query(&kind)? {
        Some((ident, created)) if ident == u.ident && created == u.created => Ok(()),
        _ => Err(gone()),
    }
}

/// The units `resume` could not settle, oldest first: gone ones (`NotFound`) are dropped, any
/// other failure keeps the unit for the next pass.
#[cfg(any(windows, test))]
pub(crate) fn unsettled(
    units: Vec<GuestUnit>,
    mut resume: impl FnMut(&GuestUnit) -> io::Result<()>,
) -> Vec<GuestUnit> {
    let mut failed: Vec<GuestUnit> = units
        .into_iter()
        .rev()
        .filter(|u| resume(u).is_err_and(|e| e.kind() != io::ErrorKind::NotFound))
        .collect();
    failed.reverse();
    failed
}

/// Freezes the part of `root`'s tree whose tokens have identity `ident` (Windows).
///
/// Before anything: the root is opened and must have `ident` (else `PermissionDenied`) and the
/// start time `root_start` while that handle is open (else `NotFound`); nothing is frozen in
/// either case. Then, per pass (at most 3): the current tree, `guest_order` with one process
/// handle per pid kept open for the whole call; each fresh unit's thread opened and checked to
/// belong to its process; `plan(batch)` with the batch; only then each thread suspended through
/// its handle. A failure resumes what this call froze, through the same handles; what could not
/// be resumed comes back in the error's `GuestSuspension`. Elsewhere: `Unsupported`.
pub fn suspend_tree_as(
    root: u32,
    root_start: u64,
    ident: &str,
    plan: &mut dyn FnMut(&[GuestUnit]) -> io::Result<()>,
) -> Result<GuestSuspension, (GuestSuspension, io::Error)> {
    #[cfg(windows)]
    return win::suspend_tree_as(root, root_start, ident, plan);
    #[cfg(not(windows))]
    {
        let _ = (root, root_start, ident, plan);
        Err((GuestSuspension::empty(), io::ErrorKind::Unsupported.into()))
    }
}

/// Recovery, when no handle survived (a crash). Per unit: open the process, check its creation
/// time and that its token still has the unit's `ident` WHILE that handle is open, open the
/// thread, check it belongs to the process, resume it. A mismatch or a missing process or
/// thread is gone (dropped, never touched); a process that could not be verified (token or
/// process query failed) is kept, to be retried. Returns the units that were not settled.
/// Elsewhere: all gone.
pub fn resume_guest_units(units: Vec<GuestUnit>) -> Vec<GuestUnit> {
    #[cfg(windows)]
    {
        unsettled(units, win::resume_recorded)
    }
    #[cfg(not(windows))]
    {
        let _ = units;
        Vec::new()
    }
}

#[cfg(windows)]
mod win {
    use super::{
        Action, GuestSuspension, GuestUnit, IdentKind, TokenView, Unit, check_recorded, check_root,
        guest_order, ident_kind, ident_of, retain_openable, start_time, suspend_with_rollback,
    };
    use crate::tree::ppid_table;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::io;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_INVALID_PARAMETER, FILETIME, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
        STILL_ACTIVE,
    };
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{
        GetTokenInformation, PSID, SID_AND_ATTRIBUTES, TOKEN_APPCONTAINER_INFORMATION,
        TOKEN_GROUPS, TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TOKEN_USER, TokenAppContainerSid,
        TokenRestrictedSids, TokenUser,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::Threading::{
        GetExitCodeThread, GetProcessIdOfThread, GetProcessTimes, OpenProcess, OpenProcessToken,
        OpenThread, PROCESS_QUERY_LIMITED_INFORMATION, ResumeThread, SuspendThread,
        THREAD_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
    };

    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    #[test]
    fn foreign_thread_is_never_suspended_or_resumed() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, Ordering},
        };
        use std::time::{Duration, Instant};
        let running = Arc::new(AtomicBool::new(true));
        let counter = Arc::new(AtomicU64::new(0));
        let (tx, rx) = std::sync::mpsc::channel();
        let (flag, ticks) = (running.clone(), counter.clone());
        let helper = std::thread::spawn(move || {
            tx.send(unsafe { windows_sys::Win32::System::Threading::GetCurrentThreadId() })
                .unwrap();
            while flag.load(Ordering::SeqCst) {
                ticks.fetch_add(1, Ordering::SeqCst);
                std::thread::yield_now();
            }
        });
        let tid = rx.recv().unwrap();
        let suspended = act((u32::MAX, tid), Action::Suspend);
        let resumed = act((u32::MAX, tid), Action::Resume);
        let before = counter.load(Ordering::SeqCst);
        let deadline = Instant::now() + Duration::from_secs(1);
        while counter.load(Ordering::SeqCst) == before && Instant::now() < deadline {
            std::thread::yield_now();
        }
        let progressed = counter.load(Ordering::SeqCst) > before;
        // A partial regression must not leave the helper frozen when the assertion fails.
        if suspended.is_ok() {
            let _ = act((std::process::id(), tid), Action::Resume);
        }
        running.store(false, Ordering::SeqCst);
        helper.join().unwrap();
        assert_eq!(suspended.unwrap_err().kind(), io::ErrorKind::NotFound);
        assert_eq!(resumed.unwrap_err().kind(), io::ErrorKind::NotFound);
        assert!(progressed);
    }

    /// Threads owned by the pids in `order`, grouped in `order` (parents first).
    pub(super) fn units_of(order: &[u32]) -> io::Result<Vec<Unit>> {
        let mut threads = Vec::new();
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snap == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let snap = Handle(snap);
        let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        let mut more = unsafe { Thread32First(snap.0, &mut entry) } != 0;
        while more {
            threads.push((entry.th32OwnerProcessID, entry.th32ThreadID));
            more = unsafe { Thread32Next(snap.0, &mut entry) } != 0;
        }
        Ok(order
            .iter()
            .flat_map(|&pid| threads.iter().filter(move |t| t.0 == pid).copied())
            .collect())
    }

    pub(super) fn act(unit: Unit, action: Action) -> io::Result<()> {
        // A new thread reusing this TID in the same process passes; it is still inside the job.
        // Resuming a thread that is not suspended is harmless.
        act_on(&open_thread(unit)?, action)
    }

    /// Thread `tid`, opened to suspend, resume and query it; `NotFound` when it is gone or does
    /// not belong to `pid`.
    fn open_thread((pid, tid): Unit) -> io::Result<OwnedHandle> {
        // SAFETY: no pointers; a non-null result is a new handle we own.
        let raw = unsafe {
            OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
                0,
                tid,
            )
        };
        if raw.is_null() {
            let err = io::Error::last_os_error();
            // Invalid parameter = the thread is already gone.
            return Err(
                if err.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
                    io::ErrorKind::NotFound.into()
                } else {
                    err
                },
            );
        }
        // SAFETY: a fresh handle nobody else owns, closed once on drop.
        let thread = unsafe { OwnedHandle::from_raw_handle(raw) };
        // SAFETY: an open thread handle with THREAD_QUERY_LIMITED_INFORMATION.
        if unsafe { GetProcessIdOfThread(thread.as_raw_handle()) } != pid {
            return Err(io::ErrorKind::NotFound.into());
        }
        Ok(thread)
    }

    /// Suspends or resumes the thread behind `thread`; any failure is an error. This is the
    /// owner's semantics, exactly as before 3-S.
    pub(super) fn act_on(thread: &OwnedHandle, action: Action) -> io::Result<()> {
        let h = thread.as_raw_handle();
        // SAFETY: an open thread handle with THREAD_SUSPEND_RESUME.
        let prev = unsafe {
            match action {
                Action::Suspend => SuspendThread(h),
                Action::Resume => ResumeThread(h),
            }
        };
        if prev == u32::MAX {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// [`act_on`] for a guest's thread: one that has ended is `NotFound` (S17), not an error.
    pub(super) fn act_on_guest(thread: &OwnedHandle, action: Action) -> io::Result<()> {
        let err = match act_on(thread, action) {
            Err(e) => e,
            ok => return ok,
        };
        let h = thread.as_raw_handle();
        let mut code = 0u32;
        // SAFETY: the same handle, with THREAD_QUERY_LIMITED_INFORMATION; `code` is an out pointer.
        if unsafe { GetExitCodeThread(h, &mut code) } != 0 && code != STILL_ACTIVE as u32 {
            return Err(io::ErrorKind::NotFound.into());
        }
        Err(err)
    }

    /// The information of `class` of an open `token` in a buffer aligned for any TOKEN_* struct,
    /// with the bytes written; None on failure or when fewer than `min` bytes came back.
    fn info_of(
        token: HANDLE,
        class: TOKEN_INFORMATION_CLASS,
        min: usize,
    ) -> Option<(Vec<u64>, usize)> {
        let mut len = 0u32;
        // SAFETY: size query: null buffer of length 0, `len` is a valid out pointer.
        unsafe { GetTokenInformation(token, class, std::ptr::null_mut(), 0, &mut len) };
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        // SAFETY: `buf` holds at least `len` writable bytes.
        let ok =
            unsafe { GetTokenInformation(token, class, buf.as_mut_ptr().cast(), len, &mut len) };
        (ok != 0 && len as usize >= min).then_some((buf, len as usize))
    }

    /// The `S-1-...` form of a SID.
    ///
    /// # Safety
    /// `sid` must point to a valid SID for the whole call.
    unsafe fn sid_string(sid: PSID) -> Option<String> {
        let mut wide: *mut u16 = std::ptr::null_mut();
        // SAFETY: `sid` is valid (caller); `wide` is a valid out pointer.
        if unsafe { ConvertSidToStringSidW(sid, &mut wide) } == 0 {
            return None;
        }
        // SAFETY: on success `wide` is a NUL-terminated string the system allocated; it is read up
        // to the NUL and freed with LocalFree, exactly once.
        unsafe {
            let n = (0..).take_while(|&i| *wide.add(i) != 0).count();
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(wide, n));
            LocalFree(wide.cast());
            Some(s)
        }
    }

    /// The [`TokenView`] of an open token (TOKEN_QUERY): TokenUser, TokenRestrictedSids,
    /// TokenAppContainerSid. None on any failure (a bad handle only makes the queries fail).
    pub fn token_view(token: HANDLE) -> Option<TokenView> {
        let (user, _) = info_of(token, TokenUser, size_of::<TOKEN_USER>())?;
        let (groups, len) = info_of(token, TokenRestrictedSids, size_of::<u32>())?;
        let (container, _) = info_of(
            token,
            TokenAppContainerSid,
            size_of::<TOKEN_APPCONTAINER_INFORMATION>(),
        )?;
        // SAFETY: each buffer holds what `info_of` checked it holds (a whole TOKEN_USER and
        // TOKEN_APPCONTAINER_INFORMATION, a GroupCount whose entries are bounds-checked against
        // the bytes written below); every SID points inside its own buffer, alive until the end.
        unsafe {
            let n = *groups.as_ptr().cast::<u32>() as usize;
            let first = std::mem::offset_of!(TOKEN_GROUPS, Groups);
            let restricted = if n == 0 {
                Vec::new()
            } else {
                if n > len.saturating_sub(first) / size_of::<SID_AND_ATTRIBUTES>() {
                    return None;
                }
                let entries = groups
                    .as_ptr()
                    .cast::<u8>()
                    .add(first)
                    .cast::<SID_AND_ATTRIBUTES>();
                std::slice::from_raw_parts(entries, n)
                    .iter()
                    .map(|g| sid_string(g.Sid))
                    .collect::<Option<_>>()?
            };
            let c =
                (*container.as_ptr().cast::<TOKEN_APPCONTAINER_INFORMATION>()).TokenAppContainer;
            Some(TokenView {
                user: sid_string((*user.as_ptr().cast::<TOKEN_USER>()).User.Sid)?,
                restricted,
                app_container: if c.is_null() {
                    None
                } else {
                    Some(sid_string(c)?)
                },
            })
        }
    }

    /// [`ident_of`] over the token of `pid`, plus its creation time (FILETIME, 100 ns), both
    /// read through ONE process handle, returned open so the caller keeps the pid pinned (F46).
    /// None on any failure.
    pub fn process_ident(pid: u32, kind: &IdentKind) -> Option<(String, u64, OwnedHandle)> {
        process_ident_checked(pid, kind).ok().flatten()
    }

    /// [`process_ident`] telling "no such process, or its token is not of `kind`" (`Ok(None)`)
    /// from "could not check" (`Err`: access denied, token or time query failed).
    fn process_ident_checked(
        pid: u32,
        kind: &IdentKind,
    ) -> io::Result<Option<(String, u64, OwnedHandle)>> {
        // SAFETY: no pointers; a non-null result is a new handle we own.
        let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if raw.is_null() {
            let err = io::Error::last_os_error();
            // Invalid parameter = no process has this id.
            return if err.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
                Ok(None)
            } else {
                Err(err)
            };
        }
        // SAFETY: a fresh handle nobody else owns, closed once on drop.
        let process = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: `raw` is open (owned by `process`); `token` is a valid out pointer.
        if unsafe { OpenProcessToken(raw, TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a fresh handle nobody else owns, closed once on drop.
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let view = token_view(token.as_raw_handle())
            .ok_or_else(|| io::Error::other("cannot read the token"))?;
        let Some(ident) = ident_of(kind, &view) else {
            return Ok(None);
        };
        // SAFETY: plain C structs, all-zero is valid.
        let mut t: [FILETIME; 4] = unsafe { std::mem::zeroed() };
        let [c, e, k, u] = &mut t;
        // SAFETY: `raw` is open with PROCESS_QUERY_LIMITED_INFORMATION; four valid out pointers.
        if unsafe { GetProcessTimes(raw, c, e, k, u) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let created = (u64::from(t[0].dwHighDateTime) << 32) | u64::from(t[0].dwLowDateTime);
        Ok(Some((ident, created, process)))
    }

    /// See [`super::suspend_tree_as`].
    pub(super) fn suspend_tree_as(
        root: u32,
        root_start: u64,
        ident: &str,
        plan: &mut dyn FnMut(&[GuestUnit]) -> io::Result<()>,
    ) -> Result<GuestSuspension, (GuestSuspension, io::Error)> {
        let refuse = |kind: io::ErrorKind| (GuestSuspension::empty(), io::Error::from(kind));
        check_root(root).map_err(|e| (GuestSuspension::empty(), e))?;
        let kind = ident_kind(ident).ok_or_else(|| refuse(io::ErrorKind::PermissionDenied))?;
        let (_, root_created, root_handle) = process_ident(root, &kind)
            .filter(|(i, ..)| i == ident)
            .ok_or_else(|| refuse(io::ErrorKind::PermissionDenied))?;
        if start_time(root) != Some(root_start) {
            return Err(refuse(io::ErrorKind::NotFound));
        }
        // Every process whose identity was read stays open until the end: none of their pids
        // can name another process meanwhile (F46).
        let mut pinned: HashMap<u32, (bool, u64, OwnedHandle)> =
            HashMap::from([(root, (true, root_created, root_handle))]);
        // Each unit's thread handle and its process's creation, opened before it is planned.
        let threads: RefCell<HashMap<Unit, (u64, OwnedHandle)>> = RefCell::default();
        let result = suspend_with_rollback(
            root,
            &mut || {
                let ppids = ppid_table()?;
                let order = guest_order(root, &ppids, |pid| {
                    if let Some((matches, created, _)) = pinned.get(&pid) {
                        return Some((*matches, *created));
                    }
                    let (id, created, handle) = process_ident(pid, &kind)?;
                    let matches = id == ident;
                    pinned.insert(pid, (matches, created, handle));
                    Some((matches, created))
                });
                if order.is_empty() {
                    return Err(io::ErrorKind::NotFound.into());
                }
                if order.contains(&std::process::id()) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "target tree contains this process",
                    ));
                }
                let mut open = threads.borrow_mut();
                retain_openable(units_of(&order)?, &mut |u| {
                    if open.contains_key(&u) {
                        return Ok(());
                    }
                    // Only a process pinned with the job's ident, whatever the walk returned.
                    let Some((true, created, _)) = pinned.get(&u.0) else {
                        return Err(io::ErrorKind::NotFound.into());
                    };
                    open.insert(u, (*created, open_thread(u)?));
                    Ok(())
                })
            },
            &mut |batch| {
                let open = threads.borrow();
                let units: Vec<GuestUnit> = batch
                    .iter()
                    .map(|&(pid, tid)| GuestUnit {
                        pid,
                        tid,
                        created: open[&(pid, tid)].0,
                        ident: ident.to_string(),
                    })
                    .collect();
                plan(&units)
            },
            &mut |unit, action| act_on_guest(&threads.borrow()[&unit].1, action),
        );
        let mut open = threads.into_inner();
        let mut held = |done: Vec<Unit>| {
            let mut s = GuestSuspension::empty();
            for (pid, tid) in done {
                if let Some((created, thread)) = open.remove(&(pid, tid)) {
                    s.units.push(GuestUnit {
                        pid,
                        tid,
                        created,
                        ident: ident.to_string(),
                    });
                    s.threads.push(thread);
                }
            }
            s
        };
        match result {
            Ok(done) => Ok(held(done)),
            Err((left, e)) => Err((held(left), e)),
        }
    }

    /// Resumes one recorded unit after a crash, only if its process still has the recorded
    /// creation time and identity, read with that process's handle open. `NotFound` = gone.
    pub(super) fn resume_recorded(u: &GuestUnit) -> io::Result<()> {
        // `_process` stays open until the thread is resumed: the pid stays this process's (F46).
        let mut _process = None;
        check_recorded(u, |kind| {
            Ok(
                process_ident_checked(u.pid, kind)?.map(|(ident, created, p)| {
                    _process = Some(p);
                    (ident, created)
                }),
            )
        })?;
        act_on_guest(&open_thread((u.pid, u.tid))?, Action::Resume)
    }
}
#[cfg(windows)]
use win::{act as platform_act, units_of};
#[cfg(windows)]
pub use win::{process_ident, token_view};

#[cfg(unix)]
fn units_of(order: &[u32]) -> io::Result<Vec<Unit>> {
    Ok(order.iter().map(|&pid| (pid, 0)).collect())
}

#[cfg(unix)]
fn platform_act((pid, _): Unit, action: Action) -> io::Result<()> {
    use nix::errno::Errno;
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    let signal = match action {
        Action::Suspend => Signal::SIGSTOP,
        Action::Resume => Signal::SIGCONT,
    };
    // A pid above i32::MAX would wrap negative and address a process group.
    let Ok(raw) = i32::try_from(pid) else {
        return Err(io::ErrorKind::NotFound.into());
    };
    match kill(Pid::from_raw(raw), signal) {
        Ok(()) => Ok(()),
        Err(Errno::ESRCH) => Err(io::ErrorKind::NotFound.into()),
        Err(e) => Err(io::Error::from(e)),
    }
}

/// `Some(false)` only when the process table was read and `pid` is not in it; `None` when the
/// probe could not tell (callers must then treat the process as alive).
pub fn process_alive(pid: u32) -> Option<bool> {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
    let mut sys = System::new().ok()?;
    let p = Pid::from_u32(pid);
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[p]),
        true,
        ProcessRefreshKind::nothing(),
    );
    Some(sys.process(p).is_some())
}

/// Guest pauses against real processes. Every process here is a `PING` this test created, ended
/// through its own handle when the test is done (or fails); a restricted one that has to stay
/// alive is created suspended (F45).
#[cfg(all(test, windows))]
mod guest_tests {
    use super::*;
    use crate::{
        GUEST_PAUSED_FILE, GuestRecord, OsRecover, guest_recovery_pass, save_guest_record,
    };
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::{HANDLE, LocalFree, WAIT_OBJECT_0};
    use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
    use windows_sys::Win32::Security::{
        CreateRestrictedToken, DuplicateTokenEx, GetTokenInformation, PSID, SID_AND_ATTRIBUTES,
        SecurityImpersonation, TOKEN_ALL_ACCESS, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE,
        TOKEN_GROUPS, TOKEN_QUERY, TokenLogonSid, TokenPrimary, WRITE_RESTRICTED,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_SUSPENDED, CreateProcessAsUserW, CreateProcessW, DETACHED_PROCESS,
        DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
        InitializeProcThreadAttributeList, OpenProcessToken, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        PROCESS_INFORMATION, ResumeThread, STARTUPINFOEXW, STARTUPINFOW, SuspendThread,
        TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
    };

    /// A process this test created, ended through its handle on drop.
    struct Proc {
        process: OwnedHandle,
        thread: OwnedHandle,
        pid: u32,
        tid: u32,
    }

    impl Proc {
        /// Ends the process and proves it: TerminateProcess succeeded (or the process was already
        /// over) and bounded waits saw the process AND its first thread signalled. The process
        /// is signalled before that thread has run down (measured: right after, it still reads
        /// STILL_ACTIVE and SuspendThread is denied), so tests whose premise is an ended thread
        /// need the second wait. Fails the test loudly otherwise.
        fn end(&self) {
            let h = self.process.as_raw_handle();
            // SAFETY: our own open process and thread handles.
            let (terminated, waited, thread) = unsafe {
                (
                    TerminateProcess(h, 1),
                    WaitForSingleObject(h, 5000),
                    WaitForSingleObject(self.thread.as_raw_handle(), 5000),
                )
            };
            let err = io::Error::last_os_error();
            assert_eq!(
                (waited, thread),
                (WAIT_OBJECT_0, WAIT_OBJECT_0),
                "pid {} did not end (TerminateProcess={terminated}, wait={waited}, thread={thread}, {err})",
                self.pid
            );
        }

        /// Best-effort end for drop: never panics.
        fn cleanup(&self) {
            // SAFETY: our own open process handle; a process that already ended just fails here.
            unsafe {
                TerminateProcess(self.process.as_raw_handle(), 1);
                WaitForSingleObject(self.process.as_raw_handle(), 5000);
            }
        }
    }

    impl Drop for Proc {
        fn drop(&mut self) {
            self.cleanup();
        }
    }

    fn own(h: HANDLE) -> OwnedHandle {
        assert!(!h.is_null(), "{}", io::Error::last_os_error());
        // SAFETY: a fresh handle nobody else owns.
        unsafe { OwnedHandle::from_raw_handle(h) }
    }

    fn own_token() -> OwnedHandle {
        let mut t: HANDLE = std::ptr::null_mut();
        // SAFETY: pseudo handle; `t` is a valid out pointer.
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
                &mut t,
            )
        };
        own(t)
    }

    /// The test's own token, unrestricted, as a new primary token.
    fn full_token() -> OwnedHandle {
        let mut t: HANDLE = std::ptr::null_mut();
        // SAFETY: an open token; `t` is a valid out pointer.
        unsafe {
            DuplicateTokenEx(
                own_token().as_raw_handle(),
                TOKEN_ALL_ACCESS,
                std::ptr::null(),
                SecurityImpersonation,
                TokenPrimary,
                &mut t,
            )
        };
        own(t)
    }

    /// The test's own token, write-restricted to Everyone and the logon SID (as F45 measured).
    fn restricted_token() -> OwnedHandle {
        let token = own_token();
        let mut len = 0u32;
        let mut logon = vec![0u64; 64];
        let mut everyone: PSID = std::ptr::null_mut();
        let everyone_text: Vec<u16> = "S-1-1-0\0".encode_utf16().collect();
        let mut restricted: HANDLE = std::ptr::null_mut();
        // SAFETY: `logon` holds 512 writable bytes; the TOKEN_GROUPS read back points inside it;
        // `everyone` is freed once with LocalFree after the call that uses it.
        unsafe {
            assert_ne!(
                GetTokenInformation(
                    token.as_raw_handle(),
                    TokenLogonSid,
                    logon.as_mut_ptr().cast(),
                    512,
                    &mut len
                ),
                0
            );
            assert_ne!(
                ConvertStringSidToSidW(everyone_text.as_ptr(), &mut everyone),
                0
            );
            let sids = [
                SID_AND_ATTRIBUTES {
                    Sid: everyone,
                    Attributes: 0,
                },
                SID_AND_ATTRIBUTES {
                    Sid: (*logon.as_ptr().cast::<TOKEN_GROUPS>()).Groups[0].Sid,
                    Attributes: 0,
                },
            ];
            CreateRestrictedToken(
                token.as_raw_handle(),
                WRITE_RESTRICTED,
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                2,
                sids.as_ptr(),
                &mut restricted,
            );
            LocalFree(everyone.cast());
        }
        own(restricted)
    }

    /// `PING -n 30 127.0.0.1` with `token` (else this process's) under `parent` (else this
    /// process), with no console (no conhost child), suspended or running.
    fn ping(token: Option<&OwnedHandle>, parent: Option<&OwnedHandle>, suspended: bool) -> Proc {
        let mut cmd: Vec<u16> = "PING.EXE -n 30 127.0.0.1\0".encode_utf16().collect();
        // SAFETY: plain C structs, all-zero is valid.
        let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        let mut flags = DETACHED_PROCESS | if suspended { CREATE_SUSPENDED } else { 0 };
        si.StartupInfo.cb = size_of::<STARTUPINFOW>() as u32;
        let mut list = vec![0u64; 16];
        let parent_raw = parent.map(|p| p.as_raw_handle());
        // SAFETY: `list` (128 bytes) holds a one-attribute list; `parent_raw` and `list` outlive
        // the CreateProcess call that reads them; `cmd` is a writable NUL-terminated buffer.
        unsafe {
            if let Some(p) = &parent_raw {
                let mut size = 128usize;
                assert_ne!(
                    InitializeProcThreadAttributeList(list.as_mut_ptr().cast(), 1, 0, &mut size),
                    0
                );
                assert_ne!(
                    UpdateProcThreadAttribute(
                        list.as_mut_ptr().cast(),
                        0,
                        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize,
                        (p as *const HANDLE).cast(),
                        size_of::<HANDLE>(),
                        std::ptr::null_mut(),
                        std::ptr::null(),
                    ),
                    0
                );
                si.lpAttributeList = list.as_mut_ptr().cast();
                si.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
                flags |= EXTENDED_STARTUPINFO_PRESENT;
            }
            let ok = match token {
                Some(t) => CreateProcessAsUserW(
                    t.as_raw_handle(),
                    std::ptr::null(),
                    cmd.as_mut_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                    flags,
                    std::ptr::null(),
                    std::ptr::null(),
                    &si.StartupInfo,
                    &mut pi,
                ),
                None => CreateProcessW(
                    std::ptr::null(),
                    cmd.as_mut_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                    flags,
                    std::ptr::null(),
                    std::ptr::null(),
                    &si.StartupInfo,
                    &mut pi,
                ),
            };
            let err = io::Error::last_os_error();
            if parent_raw.is_some() {
                DeleteProcThreadAttributeList(list.as_mut_ptr().cast());
            }
            assert_ne!(ok, 0, "{err}");
        }
        Proc {
            process: own(pi.hProcess),
            thread: own(pi.hThread),
            pid: pi.dwProcessId,
            tid: pi.dwThreadId,
        }
    }

    /// The suspend count of a thread, read through the handle CreateProcess gave.
    fn count(thread: &OwnedHandle) -> u32 {
        // SAFETY: our own thread handle with THREAD_ALL_ACCESS.
        unsafe {
            let prev = SuspendThread(thread.as_raw_handle());
            assert_ne!(prev, u32::MAX, "{}", io::Error::last_os_error());
            ResumeThread(thread.as_raw_handle());
            prev
        }
    }

    fn own_view() -> TokenView {
        token_view(own_token().as_raw_handle()).expect("own token")
    }

    fn view_of(p: &Proc) -> TokenView {
        let mut t: HANDLE = std::ptr::null_mut();
        // SAFETY: our own process handle; `t` is a valid out pointer.
        unsafe { OpenProcessToken(p.process.as_raw_handle(), TOKEN_QUERY, &mut t) };
        token_view(own(t).as_raw_handle()).expect("token of a test process")
    }

    /// Test 28 (F33, F45): R is restricted; Q is a full-token process of the owner hanging below R;
    /// C below R inherits R's token. Pausing R's ident freezes R and C, never Q.
    #[test]
    fn suspend_tree_as_freezes_only_the_same_ident() {
        let me = own_view();
        let r = ping(Some(&restricted_token()), None, true);
        let q = ping(Some(&full_token()), Some(&r.process), false);
        let c = ping(None, Some(&r.process), true);
        // The case is built only if Q really hangs below R with the owner's full token.
        assert_eq!(crate::tree::ppid_table().unwrap().get(&q.pid), Some(&r.pid));
        let qv = view_of(&q);
        assert!(qv.user == me.user && qv.restricted.is_empty(), "{qv:?}");
        let kind = IdentKind::Restricted(me.user.clone());
        let ident = process_ident(r.pid, &kind).expect("R is restricted").0;
        assert_eq!(
            process_ident(c.pid, &kind).map(|x| x.0),
            Some(ident.clone())
        );
        let counts = || [count(&r.thread), count(&q.thread), count(&c.thread)];
        assert_eq!(counts(), [1, 0, 1]);
        let start = start_time(r.pid).unwrap();

        let (left, e) =
            suspend_tree_as(r.pid, start, "account:S-1-5-18", &mut |_| Ok(())).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        assert!(left.units().is_empty());
        assert_eq!(counts(), [1, 0, 1]);
        let (left, e) = suspend_tree_as(r.pid, start + 1, &ident, &mut |_| Ok(())).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
        assert!(left.units().is_empty());
        assert_eq!(counts(), [1, 0, 1]);

        let mut batches: Vec<Vec<GuestUnit>> = Vec::new();
        let frozen = suspend_tree_as(r.pid, start, &ident, &mut |b| {
            batches.push(b.to_vec());
            Ok(())
        })
        .unwrap();
        assert_eq!(counts(), [2, 0, 2]);
        let planned: HashSet<u32> = batches.iter().flatten().map(|u| u.pid).collect();
        assert_eq!(planned, HashSet::from([r.pid, c.pid]));
        assert!(batches.iter().flatten().all(|u| u.ident == ident));
        frozen.resume().unwrap();
        assert_eq!(counts(), [1, 0, 1]);
    }

    /// Test 36 (D1): resuming acts on the handles held, never on the ids recorded.
    #[test]
    fn a_guest_resume_acts_only_through_its_handles() {
        let me = own_view();
        let ident = format!("account:{}", me.user);
        let o = ping(None, None, true);
        let ended = ping(None, None, true);
        ended.end();
        let created = process_ident(o.pid, &IdentKind::Account(me.user.clone()))
            .unwrap()
            .1;
        let swapped = GuestSuspension::from_parts(
            vec![GuestUnit {
                pid: o.pid,
                tid: o.tid,
                created,
                ident: ident.clone(),
            }],
            vec![ended.thread.try_clone().unwrap()],
        );
        swapped.resume().unwrap();
        assert_eq!(
            count(&o.thread),
            1,
            "the unit's ids were used instead of its handle"
        );

        // Control: a thread that ended counts as resumed (S17); a live one goes back to 0.
        let live = ping(None, None, false);
        let frozen = suspend_tree_as(live.pid, start_time(live.pid).unwrap(), &ident, &mut |_| {
            Ok(())
        })
        .unwrap();
        live.end();
        frozen.resume().unwrap();
        let other = ping(None, None, false);
        let frozen = suspend_tree_as(
            other.pid,
            start_time(other.pid).unwrap(),
            &ident,
            &mut |_| Ok(()),
        )
        .unwrap();
        assert_eq!(count(&other.thread), 1);
        frozen.resume().unwrap();
        assert_eq!(count(&other.thread), 0);
    }

    /// Test 37 (D1): recovery resumes only when identity and creation match, read with the
    /// process handle open.
    #[test]
    fn guest_recovery_checks_identity_with_the_handle_open() {
        let me = own_view();
        let o = ping(None, None, true);
        let created = process_ident(o.pid, &IdentKind::Account(me.user.clone()))
            .unwrap()
            .1;
        let unit = |ident: &str, created| GuestUnit {
            pid: o.pid,
            tid: o.tid,
            created,
            ident: ident.to_string(),
        };
        let ident = format!("account:{}", me.user);
        assert!(resume_guest_units(vec![unit("account:S-1-5-21-1-2-3-1004", created)]).is_empty());
        assert_eq!(count(&o.thread), 1);
        assert!(resume_guest_units(vec![unit(&ident, created + 1)]).is_empty());
        assert_eq!(count(&o.thread), 1);
        assert!(resume_guest_units(vec![unit(&ident, created)]).is_empty());
        assert_eq!(count(&o.thread), 0);
    }

    /// Test 38 (D2): a crash after suspending; recovery reads only the units, no tree.
    #[test]
    fn guest_recovery_does_not_need_the_tree() {
        let me = own_view();
        let ident = format!("account:{}", me.user);
        let dir =
            std::env::temp_dir().join(format!("sync_gate-guest-crash-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let r = ping(None, None, false);
        let a = ping(None, Some(&r.process), false);
        let b = ping(None, Some(&a.process), false);
        let mut recorded = Vec::new();
        let frozen = suspend_tree_as(r.pid, start_time(r.pid).unwrap(), &ident, &mut |batch| {
            recorded.extend_from_slice(batch);
            save_guest_record(
                &dir,
                &GuestRecord {
                    units: recorded.clone(),
                },
            )
        })
        .unwrap();
        assert!(frozen.units().iter().any(|u| u.pid == b.pid));
        drop(frozen); // the crash: the handles go, the threads stay frozen
        r.end();
        a.end();
        assert_eq!(count(&b.thread), 1);
        let pass = guest_recovery_pass(&dir, &mut OsRecover).unwrap();
        assert_eq!(count(&b.thread), 0);
        assert!(pass.resumed >= 1, "{pass:?}");
        assert!(!dir.join(GUEST_PAUSED_FILE).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fix round 1, Important 1: through the same handle of an ended thread the owner action is
    /// an error (as before 3-S) and only the guest action calls it gone (S17).
    #[test]
    fn only_a_guest_action_treats_an_ended_thread_as_gone() {
        let p = ping(None, None, false);
        p.end();
        let owner = win::act_on(&p.thread, Action::Suspend).unwrap_err();
        assert_ne!(owner.kind(), io::ErrorKind::NotFound, "{owner}");
        let guest = win::act_on_guest(&p.thread, Action::Suspend).unwrap_err();
        assert_eq!(guest.kind(), io::ErrorKind::NotFound, "{guest}");
    }

    /// This session's logon SID as a string, read from the test's own token.
    fn logon_sid() -> String {
        use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
        let token = own_token();
        let (mut buf, mut len) = (vec![0u64; 64], 0u32);
        let mut wide: *mut u16 = std::ptr::null_mut();
        // SAFETY: `buf` holds 512 writable bytes; the TOKEN_GROUPS read back points inside it;
        // `wide` is read up to its NUL and freed once with LocalFree.
        unsafe {
            assert_ne!(
                GetTokenInformation(
                    token.as_raw_handle(),
                    TokenLogonSid,
                    buf.as_mut_ptr().cast(),
                    512,
                    &mut len
                ),
                0
            );
            let sid = (*buf.as_ptr().cast::<TOKEN_GROUPS>()).Groups[0].Sid;
            assert_ne!(ConvertSidToStringSidW(sid, &mut wide), 0);
            let n = (0..).take_while(|&i| *wide.add(i) != 0).count();
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(wide, n));
            LocalFree(wide.cast());
            s
        }
    }

    /// Test 15: the identity of a process by kind, read through one handle.
    #[test]
    fn process_ident_rules() {
        let me = own_view().user;
        let ident = |pid, kind: &IdentKind| process_ident(pid, kind).map(|(i, ..)| i);
        let full = ping(None, None, false);
        assert_eq!(
            ident(full.pid, &IdentKind::Account(me.clone())),
            Some(format!("account:{me}"))
        );
        assert_eq!(ident(full.pid, &IdentKind::Restricted(me.clone())), None);
        // A live restricted process is created suspended (F45).
        let r = ping(Some(&restricted_token()), None, true);
        let mut sids = vec!["S-1-1-0".to_string(), logon_sid()];
        sids.sort();
        assert!(sids[1].starts_with("S-1-5-5-"), "{sids:?}");
        assert_eq!(
            ident(r.pid, &IdentKind::Restricted(me.clone())),
            Some(format!("restricted:{me}:{}", sids.join(",")))
        );
        assert_eq!(ident(4, &IdentKind::Account(me.clone())), None);
        // Ended, and its handles closed: no process has that id any more. Another holder of a
        // handle to it (csrss, a scanner) keeps the ended process openable, with the same
        // identity and creation time, for a moment after ours close (measured), so poll; a pid
        // reused meanwhile names another process, with a later creation time.
        let pid = full.pid;
        let (_, created, _) = process_ident(pid, &IdentKind::Account(me.clone())).unwrap();
        full.end();
        drop(full);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while let Some((_, c, _)) = process_ident(pid, &IdentKind::Account(me.clone())) {
            if c != created {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "pid {pid} still names the ended process after 10 s"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        r.end();
    }
}
