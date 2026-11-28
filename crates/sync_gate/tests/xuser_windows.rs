//! The guest queue proven with the REAL `codex sandbox` in its three Windows modes (plan 3-S,
//! Task 6): X1 to X6 and X12 (`elevated`), X9 (`unelevated`, F27), X10 (`mxc`), X11 (`unelevated`).
//! X7, X8 and the pause parts of X10 and X11 live in `sync_gate_probe/tests`.
//!
//! All `#[ignore]`: they run only on request, with `SYNC_GATE_TEST_CODEX_SANDBOX=1` and `codex` on the
//! `PATH` (else they print `skipped: ...` and pass):
//!
//! ```text
//! cargo test -p sync_gate --test xuser_windows --locked -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! What they change outside this process (authorised by the owner, K1): the Codex `elevated` and
//! `unelevated` setups re-apply ACLs on the profile and add the fixed folder `<tmp>` (below) to
//! `cap_sid`, once. The tests grant no permission themselves and run no `icacls`. `--nocapture`
//! matters only for X11g, which reads the daemon's own stderr line.
//!
//! Every test uses its own pipe names (`sync_gate-xw-<pid>`) and temporary data folders, never the
//! owner's real daemon, its pipe or its data folder.
#![cfg(windows)]

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use sync_gate_core::{Config, MIB, MachineSnapshot, Request, Response, StatusReport};
use sync_gate_probe::Probe;
use sync_gated::{DaemonHandle, Measure, OsControl, OsLauncher};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// The deadline of one process execution: from its spawn to the last byte of its output.
const BOUND: Duration = Duration::from_secs(180);
/// The same for a process that lives through a whole scenario (the owner's job).
const LONG_BOUND: Duration = Duration::from_secs(300);
/// The same for the short helpers (powershell, `codex --version`).
const SHORT_BOUND: Duration = Duration::from_secs(60);

const RERUN_LINE: &str = "sync_gate: still queued; this sandbox cannot resume a ticket later, so it was given back: run the command again";

/// Where the pending commands of the `elevated` guest live (the real use's own folder).
const GUEST_PENDING: &str =
    r"C:\Users\CodexSandboxOffline\AppData\Roaming\sync_labs\sync_gate\data\pending";

// ---------------------------------------------------------------------------------------------
// The daemon: in this process, as the owner.
// ---------------------------------------------------------------------------------------------

/// Real tree RSS, but a fixed machine: room for exactly one unknown heavy job (1.5 GiB prior).
struct FixedMachine {
    probe: Probe,
}

impl Measure for FixedMachine {
    fn snapshot(&mut self) -> MachineSnapshot {
        MachineSnapshot {
            total: 4096 * MIB,
            available: 2048 * MIB,
            reclaimable: 0,
            swap_used: 0,
            swap_total: 0,
            vram: None,
        }
    }
    fn tree_rss(&mut self, pid: u32) -> u64 {
        self.probe.tree_rss(pid)
    }
    fn start_time(&mut self, pid: u32) -> Option<u64> {
        sync_gate_probe::start_time(pid)
    }
}

// ---------------------------------------------------------------------------------------------
// ACL guard (N2): read-only, bounded, it does NOT prove that no new grant was made.
// ---------------------------------------------------------------------------------------------

/// The ACEs of the three Codex sandbox accounts on six paths: `path|account|type|rights|inherit`.
/// Not seen: a grant made by the warm-up itself, a path outside the six, an ACE for a capability
/// SID (`S-1-5-21-...` of `cap_sid`, F23).
const ACL_SCRIPT: &str = r#"
$u = $env:USERPROFILE
$paths = @($u, "$u\.claude.json", "$u\.codex", $env:APPDATA, "$env:APPDATA\sync_labs\sync_gate", $env:LOCALAPPDATA)
foreach ($p in $paths) {
  try { $a = Get-Acl -LiteralPath $p -ErrorAction Stop } catch { "$p|unreadable"; continue }
  foreach ($r in $a.Access) {
    if ($r.IdentityReference.Value -match '(?i)\\CodexSandbox(Users|Offline|Online)$') {
      "$p|$($r.IdentityReference.Value)|$($r.AccessControlType)|$($r.FileSystemRights)|$($r.InheritanceFlags)|$($r.PropagationFlags)"
    }
  }
}
"#;

fn acl_capture() -> BTreeSet<String> {
    let mut c = Command::new("powershell");
    c.args(["-NoProfile", "-NonInteractive", "-Command", ACL_SCRIPT]);
    run_for(c, SHORT_BOUND)
        .out
        .lines()
        .map(|l| l.trim().to_owned())
        .filter(|l| !l.is_empty())
        .collect()
}

fn print_capture(label: &str, set: &BTreeSet<String>) {
    println!("ACL guard {label}: {} entries", set.len());
    for e in set {
        println!("    {e}");
    }
}

fn print_diff(label: &str, from: &BTreeSet<String>, to: &BTreeSet<String>) {
    let (added, removed): (Vec<_>, Vec<_>) =
        (to.difference(from).collect(), from.difference(to).collect());
    println!("ACL guard {label}: +{} -{}", added.len(), removed.len());
    for e in added {
        println!("    + {e}");
    }
    for e in removed {
        println!("    - {e}");
    }
}

// ---------------------------------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------------------------------

struct Res {
    code: i32,
    out: String,
    err: String,
}

/// A spawned process with its output collected under ONE deadline (spawn to the last byte);
/// dropping it before `finish` kills it by its handle (it is a process this test created).
struct Live {
    child: Option<Child>,
    out: Option<Reader>,
    err: Option<Reader>,
    deadline: Instant,
}

/// The bytes of one pipe, as far as they came.
struct Reader {
    buf: Arc<Mutex<Vec<u8>>>,
    thread: JoinHandle<()>,
}

/// The Codex `elevated` token is restricted (restricting SIDs: the owner's logon SID, not AU), so
/// its guest CLI can open the daemon process only through an ACE for the logon SID. A process
/// started from MSYS/Git Bash has none (docs/sandbox.md). Fails, never skips: the guest would
/// fall open and the scenario would prove nothing.
fn require_logon_sid_ace() {
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
        GetKernelObjectSecurity, GetSecurityDescriptorDacl, GetTokenInformation, TOKEN_GROUPS,
        TOKEN_QUERY, TokenLogonSid,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    /// Closes the token on every way out of the function, a failed assert included.
    struct Owned(HANDLE);
    impl Drop for Owned {
        fn drop(&mut self) {
            // SAFETY: the handle came from OpenProcessToken and is closed once, here.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
        }
    }
    let mut raw: HANDLE = std::ptr::null_mut();
    // SAFETY: valid out pointer; the pseudo handle needs no closing.
    assert!(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } != 0);
    let owned = Owned(raw);
    let token = owned.0;
    let mut len = 0u32;
    // SAFETY: size query, then a buffer of that many u64 (aligned for TOKEN_GROUPS).
    unsafe { GetTokenInformation(token, TokenLogonSid, std::ptr::null_mut(), 0, &mut len) };
    let mut groups = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `groups` holds at least `len` writable bytes.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenLogonSid,
            groups.as_mut_ptr().cast(),
            len,
            &mut len,
        )
    };
    assert!(ok != 0, "{}", std::io::Error::last_os_error());
    // SAFETY: on success the buffer is a TOKEN_GROUPS with one entry (the logon SID).
    let logon = unsafe { (*groups.as_ptr().cast::<TOKEN_GROUPS>()).Groups[0].Sid };
    let mut len = 0u32;
    // SAFETY: size query on this process's own pseudo handle.
    unsafe {
        GetKernelObjectSecurity(
            GetCurrentProcess(),
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            0,
            &mut len,
        )
    };
    let mut sd = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `sd` holds at least `len` writable bytes.
    let ok = unsafe {
        GetKernelObjectSecurity(
            GetCurrentProcess(),
            DACL_SECURITY_INFORMATION,
            sd.as_mut_ptr().cast(),
            len,
            &mut len,
        )
    };
    assert!(ok != 0, "{}", std::io::Error::last_os_error());
    let (mut present, mut defaulted) = (0i32, 0i32);
    let mut acl: *mut ACL = std::ptr::null_mut();
    // SAFETY: `sd` is the valid self-relative descriptor just read; the out pointers are valid.
    let ok = unsafe {
        GetSecurityDescriptorDacl(
            sd.as_ptr().cast_mut().cast(),
            &mut present,
            &mut acl,
            &mut defaulted,
        )
    };
    let mut found = false;
    if ok != 0 && present != 0 && !acl.is_null() {
        // SAFETY: `acl` points into `sd`, alive here.
        for i in 0..u32::from(unsafe { (*acl).AceCount }) {
            let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
            // SAFETY: `i` is below AceCount.
            if unsafe { GetAce(acl, i, &mut ace) } == 0 {
                continue;
            }
            let a = ace.cast::<ACCESS_ALLOWED_ACE>();
            // SAFETY: the ACE is inside `sd`; for type 0 (ACCESS_ALLOWED) SidStart is its SID.
            let hit = unsafe {
                (*a).Header.AceType == 0
                    && (*a).Mask & 0x1000 != 0
                    && EqualSid(std::ptr::addr_of_mut!((*a).SidStart).cast(), logon) != 0
            };
            found |= hit;
        }
    }
    assert!(
        found,
        "this test process has no ACCESS_ALLOWED ACE (mask with 0x1000) for the logon SID in its \
         process DACL: run these tests from PowerShell or cmd; a process started from an \
         MSYS/Git Bash shell has no logon-SID ACE, so the Codex elevated sandbox cannot verify \
         the daemon (docs/sandbox.md)"
    );
}

fn collect(pipe: Option<impl Read + Send + 'static>) -> Reader {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let into = Arc::clone(&buf);
    let thread = std::thread::spawn(move || {
        let Some(mut p) = pipe else { return };
        let mut chunk = [0u8; 8192];
        while let Ok(n) = p.read(&mut chunk) {
            if n == 0 {
                break;
            }
            into.lock().unwrap().extend_from_slice(&chunk[..n]);
        }
    });
    Reader { buf, thread }
}

impl Reader {
    /// Everything read until the pipe closed or `until` passed (a grandchild may hold the pipe
    /// open: then what came so far, and the reader thread is left to end with the process).
    fn take(self, until: Instant) -> (String, bool) {
        while !self.thread.is_finished() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(10));
        }
        let text = String::from_utf8_lossy(&self.buf.lock().unwrap()).into_owned();
        (text, self.thread.is_finished())
    }
}

impl Live {
    fn spawn(c: Command) -> Live {
        Live::spawn_for(c, BOUND)
    }

    fn spawn_for(c: Command, bound: Duration) -> Live {
        Live::try_spawn(c, bound).expect("spawn")
    }

    fn try_spawn(mut c: Command, bound: Duration) -> std::io::Result<Live> {
        c.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = c.spawn()?;
        let out = collect(child.stdout.take());
        let err = collect(child.stderr.take());
        Ok(Live {
            child: Some(child),
            out: Some(out),
            err: Some(err),
            deadline: Instant::now() + bound,
        })
    }

    fn done(&mut self) -> bool {
        self.child
            .as_mut()
            .is_some_and(|c| c.try_wait().ok().flatten().is_some())
    }

    fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    /// Waits for the exit and the output until the deadline of the whole execution; past it the
    /// child is killed through its handle, what it printed is collected and the test fails.
    fn finish(mut self) -> Res {
        let mut child = self.child.take().unwrap();
        let status = loop {
            if let Some(s) = child.try_wait().expect("try_wait") {
                break Some(s);
            }
            if self.expired() {
                if let Err(e) = kill_confirmed(&mut child, Duration::from_secs(10)) {
                    panic!(
                        "a process did not exit before its deadline and may still be running: {e}"
                    );
                }
                break None;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        // After a kill the pipes close with the child; a held-open one gets a short grace.
        let until = if status.is_some() {
            self.deadline.max(Instant::now() + Duration::from_secs(5))
        } else {
            Instant::now() + Duration::from_secs(5)
        };
        let (out, out_closed) = self.out.take().unwrap().take(until);
        let (err, err_closed) = self.err.take().unwrap().take(until);
        let Some(status) = status else {
            panic!(
                "a process did not exit before its deadline (killed it); stdout:\n{out}\nstderr:\n{err}"
            );
        };
        assert!(
            out_closed && err_closed,
            "the process exited but its output stayed open past the deadline; stdout:\n{out}\nstderr:\n{err}"
        );
        Res {
            code: status.code().unwrap_or(-1),
            out,
            err,
        }
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take()
            && let Err(e) = kill_confirmed(&mut c, Duration::from_secs(10))
        {
            let _ = writeln!(
                std::io::stderr(),
                "WARNING: a test process may still be running: {e}"
            );
        }
    }
}

/// Kills the child through its own handle and waits (bounded) until it is really gone.
fn kill_confirmed(child: &mut Child, bound: Duration) -> Result<(), String> {
    if let Ok(Some(_)) = child.try_wait() {
        return Ok(());
    }
    let killed = child.kill();
    let end = Instant::now() + bound;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) if Instant::now() < end => std::thread::sleep(Duration::from_millis(20)),
            other => {
                return Err(format!(
                    "pid {} not confirmed ended within {bound:?} (kill: {killed:?}, wait: {other:?})",
                    child.id()
                ));
            }
        }
    }
}

fn run(c: Command) -> Res {
    run_for(c, BOUND)
}

fn run_for(c: Command, bound: Duration) -> Res {
    Live::spawn_for(c, bound).finish()
}

fn wait_for(what: &str, secs: u64, mut ok: impl FnMut() -> bool) {
    let start = Instant::now();
    while !ok() {
        assert!(
            start.elapsed() < Duration::from_secs(secs),
            "timed out: {what}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The value of the probe's `label = value` line.
fn probe_line<'a>(out: &'a str, label: &str) -> &'a str {
    let key = format!("{label} = ");
    out.lines()
        .find_map(|l| l.strip_prefix(&key))
        .unwrap_or_else(|| panic!("no `{label} = ` line in:\n{out}"))
}

fn jsons(dirs: &[&Path]) -> BTreeSet<PathBuf> {
    fn walk(d: &Path, into: &mut BTreeSet<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(d) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, into);
            } else if p
                .extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("json"))
            {
                into.insert(p);
            }
        }
    }
    let mut s = BTreeSet::new();
    for d in dirs {
        walk(d, &mut s);
    }
    s
}

fn guest_pending_count() -> String {
    std::fs::read_dir(GUEST_PENDING)
        .map(|d| d.count().to_string())
        .unwrap_or_else(|e| format!("unreadable ({e})"))
}

// ---------------------------------------------------------------------------------------------
// One scenario's world
// ---------------------------------------------------------------------------------------------

struct Ctx {
    mode: &'static str,
    /// The fixed folder the sandbox can write (one `cap_sid` entry for it, K1).
    tmp: PathBuf,
    /// The owner's folder for this test: data dir, a project with a `.git`, the owner's job.
    work: PathBuf,
    socket: String,
    /// The local part of the account that runs commands in the sandbox, lower case.
    account: String,
    acl_warm: BTreeSet<String>,
}

fn reset_dir(p: &Path) {
    remove_dir(p);
    std::fs::create_dir_all(p).unwrap();
}

/// Removes a folder, retrying for 15 s at most (a sandbox process may still hold a file); the
/// reason when it stays.
fn try_remove_dir(p: &Path) -> Result<(), String> {
    let start = Instant::now();
    loop {
        match std::fs::remove_dir_all(p) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) if start.elapsed() > Duration::from_secs(15) => {
                return Err(format!("cannot remove {}: {e}", p.display()));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(250)),
        }
    }
}

fn remove_dir(p: &Path) {
    if let Err(e) = try_remove_dir(p) {
        panic!("{e}");
    }
}

fn tmp_dir() -> PathBuf {
    std::env::temp_dir()
        .join("trabalho")
        .join("sync_gate")
        .join("xw")
}

impl Ctx {
    /// Guards, ACL capture, the fixed folder with the copied binary and the probe, the warm-up.
    /// `None` after printing `skipped: ...`.
    fn begin(mode: &'static str) -> Option<Ctx> {
        if std::env::var("SYNC_GATE_TEST_CODEX_SANDBOX").as_deref() != Ok("1") {
            println!("skipped: SYNC_GATE_TEST_CODEX_SANDBOX=1 is not set");
            return None;
        }
        let mut version = Command::new("codex");
        version.arg("--version");
        match Live::try_spawn(version, SHORT_BOUND) {
            Err(_) => {
                println!("skipped: codex is not on the PATH");
                return None;
            }
            Ok(l) => {
                l.finish();
            }
        }
        if mode == "elevated" {
            require_logon_sid_ace();
        }
        let acl_before = acl_capture();
        let pid = std::process::id();
        // The folder guard first: whatever fails below, `Drop` removes both folders (bounded,
        // and a folder that stays is reported).
        let mut c = Ctx {
            mode,
            tmp: tmp_dir(),
            // Not under the temporary folder: the sandbox is allowed to change that one, so the
            // daemon refuses a data folder there.
            work: PathBuf::from(std::env::var_os("LOCALAPPDATA").expect("LOCALAPPDATA"))
                .join("sync_gate-xw")
                .join(format!("data-{pid}")),
            socket: format!(
                "sync_gate-xw-{pid}-{}",
                COUNTER.fetch_add(1, Ordering::SeqCst)
            ),
            account: String::new(),
            acl_warm: BTreeSet::new(),
        };
        reset_dir(&c.tmp);
        reset_dir(&c.work.join("data"));
        std::fs::create_dir_all(c.work.join("proj").join(".git")).unwrap();
        std::fs::create_dir_all(c.work.join("proj").join("sub")).unwrap();
        std::fs::write(c.work.join("config.toml"), "").unwrap();
        std::fs::copy(env!("CARGO_BIN_EXE_sync_gate"), c.tmp.join("sync_gate.exe")).unwrap();
        std::fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/xuser/guest-probe.ps1"),
            c.tmp.join("guest-probe.ps1"),
        )
        .unwrap();
        // Warm-up: the account that runs commands in this mode.
        // The system `whoami`, not the first one on the PATH (Git's cygwin one dies in a sandbox).
        let whoami = format!(
            r"{}\System32\whoami.exe",
            std::env::var("SystemRoot").unwrap()
        );
        let r = run(c.sbx(&[&whoami]));
        assert_eq!(
            r.code, 0,
            "the {mode} warm-up failed:\n{}\n{}",
            r.out, r.err
        );
        let who = r.out.trim().to_lowercase();
        let local = who.rsplit('\\').next().unwrap().to_owned();
        let own = std::env::var("USERNAME").unwrap().to_lowercase();
        println!("{mode} warm-up whoami = {who}");
        if mode == "elevated" && local == own {
            println!("skipped: the elevated sandbox ran as the owner ({who})");
            c.cleanup();
            return None;
        }
        if mode != "elevated" && local != own {
            c.cleanup();
            panic!("the {mode} sandbox is expected to run as the owner, got {who}");
        }
        c.account = local;
        let acl_warm = acl_capture();
        print_capture(&format!("[{mode}] before the warm-up"), &acl_before);
        print_capture(&format!("[{mode}] after the warm-up"), &acl_warm);
        print_diff(
            &format!("[{mode}] warm-up (authorised, only printed)"),
            &acl_before,
            &acl_warm,
        );
        c.acl_warm = acl_warm;
        Some(c)
    }

    fn cleanup(&self) {
        remove_dir(&self.tmp);
        remove_dir(&self.work);
    }

    /// Last capture, the guard, the folders gone.
    fn end(self) {
        let acl_end = acl_capture();
        print_capture(&format!("[{}] at the end", self.mode), &acl_end);
        print_diff(
            &format!("[{}] after the warm-up -> end", self.mode),
            &self.acl_warm,
            &acl_end,
        );
        let new: Vec<_> = acl_end.difference(&self.acl_warm).collect();
        self.cleanup();
        assert!(!self.tmp.exists(), "{} still exists", self.tmp.display());
        assert!(
            new.is_empty(),
            "ACEs of the sandbox accounts that the proof commands added: {new:?}"
        );
    }

    fn data(&self) -> PathBuf {
        self.work.join("data")
    }

    /// `codex -c windows.sandbox=<mode> sandbox -P :workspace -C <tmp> -- <argv>`.
    fn sbx(&self, argv: &[&str]) -> Command {
        let mut c = Command::new("codex");
        c.args(["-c", &format!("windows.sandbox={}", self.mode)])
            .args(["sandbox", "-P", ":workspace", "-C"])
            .arg(&self.tmp)
            .arg("--")
            .args(argv)
            .env("SYNC_GATE_SOCKET", &self.socket)
            // In a folder that does not exist: the defaults, with nothing to check. At the drive
            // root: under `tmp` the sandbox can change the parent (refused), and under the
            // profile the sandbox account cannot even open it (`Access is denied`).
            .env("SYNC_GATE_CONFIG", r"C:\sync_gate-xw-none\config.toml")
            .env("SYNC_GATE_FORCE_HEAVY", "1")
            .env_remove("SYNC_GATE_DATA_DIR")
            .env_remove("SYNC_GATE_JOB")
            .env_remove("SYNC_GATE_SHIM_TARGET");
        c
    }

    /// The copied `sync_gate.exe` in the sandbox.
    fn sbx_fg(&self, args: &[&str]) -> Command {
        let exe = self.tmp.join("sync_gate.exe");
        let mut argv = vec![exe.to_str().unwrap()];
        argv.extend_from_slice(args);
        self.sbx(&argv)
    }

    /// `guest-probe.ps1` in the sandbox, with `extra` arguments.
    fn sbx_probe(&self, extra: &[&str]) -> Command {
        let script = self.tmp.join("guest-probe.ps1");
        let mut argv = vec![
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            script.to_str().unwrap(),
        ];
        argv.extend_from_slice(extra);
        self.sbx(&argv)
    }

    /// The owner's own `sync_gate <args>`, outside any sandbox.
    fn owner_fg(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_sync_gate"));
        c.args(args)
            .env("SYNC_GATE_SOCKET", &self.socket)
            .env("SYNC_GATE_DATA_DIR", self.data())
            .env("SYNC_GATE_CONFIG", self.work.join("config.toml"))
            .env("SYNC_GATE_FORCE_HEAVY", "1")
            .env_remove("SYNC_GATE_JOB")
            .env_remove("SYNC_GATE_SHIM_TARGET");
        c
    }

    fn start(&self, guests: &[&str]) -> Daemon {
        let cfg = Config {
            reserve_fraction: 0.0,
            optimism: 1.0,
            tick_ms: 100,
            guests: guests.iter().map(|g| (*g).to_owned()).collect(),
            ..Config::default()
        };
        let m = FixedMachine {
            probe: Probe::new(),
        };
        Daemon(Some(
            sync_gated::run_with(
                cfg,
                &self.socket,
                m,
                OsControl,
                Some(self.data()),
                Arc::new(OsLauncher::default()),
            )
            .unwrap(),
        ))
    }

    fn status(&self) -> StatusReport {
        status_at(&self.socket)
    }

    fn guest_pipe(&self) -> String {
        format!("{}-guest-{}", self.socket, self.account)
    }

    fn sbx_pipe(&self, kind: &str) -> String {
        format!("{}-sbx-{kind}", self.socket)
    }

    /// The owner's job: holds the only slot until released. Its key carries `fg-owner-<pid>`.
    fn owner_job(&self) -> OwnerJob {
        let marker = format!("fg-owner-{}", std::process::id());
        let script = self.work.join(format!("{marker}.ps1"));
        let stop = self.work.join("owner.stop");
        let _ = std::fs::remove_file(&stop);
        std::fs::write(
            &script,
            "param([string]$Stop)\nwhile (-not (Test-Path $Stop)) { Start-Sleep -Milliseconds 100 }\n",
        )
        .unwrap();
        // The key is the program and the folder it runs in (the script after `-File` is not
        // part of it): a folder named after the marker puts the marker in the key.
        let cwd = self.work.join(&marker);
        std::fs::create_dir_all(&cwd).unwrap();
        let mut c = self.owner_fg(&["run", "--"]);
        c.args(["powershell", "-NoProfile", "-File"])
            .arg(&script)
            .arg(&stop)
            .current_dir(&cwd);
        let job = OwnerJob {
            live: Some(Live::spawn_for(c, LONG_BOUND)),
            stop,
            marker,
        };
        wait_for("the owner's job running", 30, || {
            self.status()
                .running
                .iter()
                .any(|(_, key, _)| key.contains(&job.marker))
        });
        job
    }
}

impl Drop for Ctx {
    fn drop(&mut self) {
        // A failed test: leave nothing of ours behind (a no-op after `end`). A folder that stays
        // is reported; it fails the test only when the test had not already failed.
        for p in [&self.tmp, &self.work] {
            if let Err(e) = try_remove_dir(p) {
                let _ = writeln!(std::io::stderr(), "CLEANUP FAILED: {e}");
                assert!(std::thread::panicking(), "CLEANUP FAILED: {e}");
            }
        }
    }
}

/// The in-process daemon; a failed test still stops it, so the next test finds its pipe free.
struct Daemon(Option<DaemonHandle<OsControl>>);

impl Daemon {
    fn shutdown(mut self) {
        if let Some(d) = self.0.take() {
            d.shutdown();
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(d) = self.0.take() {
            d.shutdown();
        }
    }
}

fn status_at(socket: &str) -> StatusReport {
    match sync_gate::client::call_at(socket, &Request::Status).expect("the daemon answers Status") {
        Response::Status(s) => s,
        other => panic!("{other:?}"),
    }
}

struct OwnerJob {
    live: Option<Live>,
    stop: PathBuf,
    pub marker: String,
}

impl OwnerJob {
    /// Lets the job end; its exit code.
    fn release(mut self) -> i32 {
        std::fs::write(&self.stop, "").unwrap();
        self.live.take().unwrap().finish().code
    }
}

impl Drop for OwnerJob {
    fn drop(&mut self) {
        let _ = std::fs::write(&self.stop, "");
    }
}

/// `sync_gate run ...` in the sandbox while the owner's `Status` is polled for a row that has
/// `label` (the key of a guest's command is `[guest <name>] ...`, S25). `(result, seen)`.
fn run_and_watch(c: &Ctx, cmd: Command, label: &str) -> (Res, bool) {
    let mut live = Live::spawn(cmd);
    let mut seen = false;
    while !live.done() && !live.expired() {
        let s = c.status();
        seen |= s
            .running
            .iter()
            .map(|r| &r.1)
            .chain(s.queued.iter().map(|q| &q.1))
            .any(|k| k.to_lowercase().contains(label));
        std::thread::sleep(Duration::from_millis(150));
    }
    (live.finish(), seen)
}

/// The N of the one decision that has `<word>N` (e.g. `dormant #N`).
fn decision_id(s: &StatusReport, word: &str) -> u64 {
    let ids: Vec<u64> = s
        .decisions
        .iter()
        .filter_map(|d| d.split(word).nth(1))
        .filter_map(|rest| {
            let n: String = rest.chars().take_while(char::is_ascii_digit).collect();
            n.parse().ok()
        })
        .collect();
    assert_eq!(
        ids.len(),
        1,
        "want one `{word}N` decision in {:?}",
        s.decisions
    );
    ids[0]
}

fn count_decisions(s: &StatusReport, word: &str) -> usize {
    s.decisions.iter().filter(|d| d.contains(word)).count()
}

/// Commands that ended: the CLI's `Finished`, or the daemon's own tick that saw the process gone
/// first (a command as short as `echo ok` can end between two ticks either way).
fn count_ended(s: &StatusReport) -> usize {
    count_decisions(s, "finished #") + count_decisions(s, ": process gone")
}

// ---------------------------------------------------------------------------------------------
// X1 to X6: the `elevated` sandbox (a local account of its own)
// ---------------------------------------------------------------------------------------------

/// The sync_gate diagnostic lines of a stderr (the guest's own output has none).
fn sync_gate_lines(err: &str) -> usize {
    err.lines().filter(|l| l.starts_with("sync_gate:")).count()
}

/// X1. The account is not listed: one line says so, the command runs, nothing is admitted.
#[test]
#[ignore]
fn x01_not_listed_runs_directly() {
    let Some(c) = Ctx::begin("elevated") else {
        return;
    };
    let d = c.start(&[]);
    let r = run(c.sbx_fg(&["run", "--", "cmd", "/d", "/c", "echo", "ok"]));
    let s = c.status();
    d.shutdown();
    println!(
        "X1 exit={} stdout={:?} stderr={:?}",
        r.code,
        r.out.trim(),
        r.err.trim()
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(r.out.contains("ok"), "{}", r.out);
    assert!(
        r.err.contains("may not use the owner's sync_gate queue"),
        "{}",
        r.err
    );
    assert_eq!(
        sync_gate_lines(&r.err),
        1,
        "exactly one sync_gate line: {}",
        r.err
    );
    assert_eq!(count_decisions(&s, "admitted"), 0, "{:?}", s.decisions);
    c.end();
}

/// X2. Listed, slot free: admitted and finished by the daemon (S23: the elevated CLI reads the
/// holders of the pipe; S25: the key of the guest's command names the guest, from the message).
#[test]
#[ignore]
fn x02_listed_free_slot_is_queued() {
    let Some(c) = Ctx::begin("elevated") else {
        return;
    };
    let acct = c.account.clone();
    let d = c.start(&[&acct]);
    let r = run(c.sbx_fg(&["run", "--", "cmd", "/d", "/c", "echo", "ok"]));
    let s = c.status();
    println!(
        "X2 exit={} stdout={:?} stderr={:?}",
        r.code,
        r.out.trim(),
        r.err.trim()
    );
    println!("X2 decisions: {:?}", s.decisions);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(r.out.contains("ok"), "{}", r.out);
    assert!(!r.err.contains("continuing without queue"), "{}", r.err);
    assert_eq!(count_decisions(&s, "admitted #"), 1, "{:?}", s.decisions);
    assert_eq!(count_ended(&s), 1, "{:?}", s.decisions);
    // The same, long enough to see the row the daemon holds for it.
    let label = format!("[guest {acct}]");
    let (r2, seen) = run_and_watch(
        &c,
        c.sbx_fg(&[
            "run",
            "--",
            "powershell.exe",
            "-NoProfile",
            "-Command",
            "Start-Sleep -Seconds 5",
        ]),
        &label,
    );
    d.shutdown();
    println!(
        "X2 second run exit={} stderr={:?} seen {label} in the owner's Status: {seen}",
        r2.code,
        r2.err.trim()
    );
    assert_eq!(r2.code, 0, "{}", r2.err);
    // The child lived for 5 s: the daemon must have accepted its `Started`.
    assert!(!r2.err.contains("unexpected reply"), "{}", r2.err);
    assert!(seen, "the owner's Status never showed a row `{label}`");
    c.end();
}

/// X3. Queued behind the owner, with a pending command in the guest's own profile.
#[test]
#[ignore]
fn x03_queued_with_a_pending_file_then_wait() {
    let Some(c) = Ctx::begin("elevated") else {
        return;
    };
    let acct = c.account.clone();
    let d = c.start(&[&acct]);
    let job = c.owner_job();
    let pending_before = guest_pending_count();
    let r = run(c.sbx_fg(&[
        "run",
        "--max-wait",
        "0",
        "--",
        "cmd",
        "/d",
        "/c",
        "echo",
        "late",
    ]));
    let pending_queued = guest_pending_count();
    println!(
        "X3 exit={} stderr={:?} guest pending files: {pending_before} -> {pending_queued}",
        r.code,
        r.err.trim()
    );
    assert_eq!(r.code, 75, "{}", r.err);
    let id: u64 = r
        .err
        .lines()
        .find_map(|l| l.trim().strip_prefix("queued: ticket "))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("no `queued: ticket N` in {}", r.err));
    let s = c.status();
    // `--max-wait 0` leaves nobody waiting: the ticket is dormant (R17), not in `queued`
    // (same as e2e max_wait_0_still_leaves_the_ticket_dormant); its owner is proven by `wait`.
    assert!(s.queued.is_empty(), "{:?}", s.queued);
    assert_eq!(
        count_decisions(&s, &format!("dormant #{id}")),
        1,
        "{:?}",
        s.decisions
    );
    assert_eq!(job.release(), 0);
    let w = run(c.sbx_fg(&["wait", &id.to_string()]));
    let pending_after = guest_pending_count();
    d.shutdown();
    println!(
        "X3 wait exit={} stdout={:?} stderr={:?} guest pending files after: {pending_after}",
        w.code,
        w.out.trim(),
        w.err.trim()
    );
    assert_eq!(w.code, 0, "{}", w.err);
    assert!(w.out.contains("late"), "{}", w.out);
    c.end();
}

/// X4. The guest sees the machine, not the owner's work.
#[test]
#[ignore]
fn x04_status_hides_the_owners_work() {
    let Some(c) = Ctx::begin("elevated") else {
        return;
    };
    let acct = c.account.clone();
    let d = c.start(&[&acct]);
    let job = c.owner_job();
    // Control: the owner's own Status does show the job.
    let own = run(c.owner_fg(&["status"]));
    assert!(own.out.contains(&job.marker), "{}", own.out);
    let r = run(c.sbx_fg(&["status"]));
    println!("X4 exit={}\n{}", r.code, r.out);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(r.out.contains("memory:"), "{}", r.out);
    assert!(!r.out.contains(&job.marker), "{}", r.out);
    let decisions = r
        .out
        .split("decisions:")
        .nth(1)
        .expect("a decisions: section");
    assert!(decisions.trim().is_empty(), "decisions: {decisions:?}");
    job.release();
    d.shutdown();
    c.end();
}

/// X5. What the guest pipe refuses, by the raw protocol.
#[test]
#[ignore]
fn x05_raw_protocol_refusals() {
    let Some(c) = Ctx::begin("elevated") else {
        return;
    };
    let acct = c.account.clone();
    let d = c.start(&[&acct]);
    let job = c.owner_job();
    let owner_id = c
        .status()
        .running
        .iter()
        .find(|r| r.1.contains(&job.marker))
        .unwrap()
        .0;
    let owner_sid = {
        let mut o = Command::new("powershell");
        o.args([
            "-NoProfile",
            "-Command",
            "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
        ]);
        run_for(o, SHORT_BOUND).out.trim().to_owned()
    };
    let cwd = c.work.join("proj").join("sub");
    let sync = c.tmp.join("sync");
    let (main, guest) = (c.socket.clone(), c.guest_pipe());
    let (id_s, pid_s) = (owner_id.to_string(), std::process::id().to_string());
    let probe = c.sbx_probe(&[
        "-Main",
        &main,
        "-Guest",
        &guest,
        "-OwnerTicket",
        &id_s,
        "-ForgedPid",
        &pid_s,
        "-Cwd",
        cwd.to_str().unwrap(),
        "-Sync",
        sync.to_str().unwrap(),
    ]);
    let mut live = Live::spawn(probe);
    let acquired = PathBuf::from(format!("{}.acquired", sync.display()));
    wait_for("the probe's Acquire", 60, || {
        acquired.exists() || live.done()
    });
    if !acquired.exists() {
        let r = live.finish();
        panic!(
            "the probe ended before its Acquire: exit {}
{}{}",
            r.code, r.out, r.err
        );
    }
    // The probe's own ticket is queued behind the owner's: its key was made from the text of the
    // cwd alone, so it ends in `@ sub` and the daemon never looked for the `.git` above it.
    let s = c.status();
    let mine: Vec<_> = s
        .queued
        .iter()
        .filter(|q| q.1.to_lowercase().contains(&format!("[guest {acct}]")))
        .collect();
    println!(
        "X5 owner's Status while the probe waits: queued {:?}",
        s.queued
    );
    assert!(
        mine.iter().any(|q| q.1.ends_with("@ sub")),
        "queued: {:?}",
        s.queued
    );
    assert!(
        !mine.iter().any(|q| q.1.contains("@ proj")),
        "queued: {:?}",
        s.queued
    );
    std::fs::write(format!("{}.go", sync.display()), "").unwrap();
    let r = live.finish();
    println!("X5 probe exit={}\n{}{}", r.code, r.out, r.err);
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(probe_line(&r.out, "main GR|GW"), "DENIED");
    assert_eq!(probe_line(&r.out, "guest GR|GW"), "DENIED");
    assert_eq!(probe_line(&r.out, "guest narrow"), "OK");
    assert_eq!(probe_line(&r.out, "owner"), owner_sid);
    assert!(
        probe_line(&r.out, "Cancel owner").contains("was cancelled or is unknown"),
        "{}",
        r.out
    );
    assert!(
        probe_line(&r.out, "Lease").contains("not available to sandboxed callers"),
        "{}",
        r.out
    );
    let forged = probe_line(&r.out, "Started forged");
    assert!(
        forged.contains("Error") && forged.contains("does not run as this caller"),
        "{forged}"
    );
    assert_eq!(probe_line(&r.out, "create instance main"), "DENIED");
    assert_eq!(probe_line(&r.out, "create instance guest"), "DENIED");
    // The owner's ticket is still there.
    let after = c.status();
    assert!(
        after.running.iter().any(|r| r.0 == owner_id),
        "{:?}",
        after.running
    );
    assert!(
        !after.queued.iter().any(|q| q.1.contains("[guest")),
        "the probe cancelled its ticket: {:?}",
        after.queued
    );
    job.release();
    d.shutdown();
    c.end();
}

/// X6. The owner is unchanged.
#[test]
#[ignore]
fn x06_the_owner_is_unchanged() {
    let Some(c) = Ctx::begin("elevated") else {
        return;
    };
    let acct = c.account.clone();
    let d = c.start(&[&acct]);
    let r = run(c.owner_fg(&["run", "--", "cmd", "/d", "/c", "echo", "ok"]));
    let s = c.status();
    d.shutdown();
    println!(
        "X6 exit={} stderr={:?} decisions={:?}",
        r.code,
        r.err.trim(),
        s.decisions
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(count_decisions(&s, "admitted #"), 1, "{:?}", s.decisions);
    assert_eq!(count_ended(&s), 1, "{:?}", s.decisions);
    assert!(!r.err.contains("continuing without queue"), "{}", r.err);
    c.end();
}

/// X12. The shims folder as the installer leaves it, outside the sandbox's own folders, with what
/// the sandbox may read inherited from the profile: a heavy command run in the sandbox with the
/// shims first on the PATH finds the shim and goes through the queue.
#[test]
#[ignore]
fn x12_shims_on_the_path_go_through_the_queue() {
    let Some(c) = Ctx::begin("elevated") else {
        return;
    };
    let acct = c.account.clone();
    let r = run(c.owner_fg(&["shims", "install"]));
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    let shims = c.data().join("shims");
    // A stand-in for the real `go`, after the shims on the PATH: prints the account it runs as.
    let sys = PathBuf::from(std::env::var("SystemRoot").unwrap()).join("System32");
    let bin = c.work.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::copy(sys.join("whoami.exe"), bin.join("go.exe")).unwrap();
    let path = std::env::join_paths([&shims, &bin, &sys]).unwrap();
    let d = c.start(&[&acct]);
    let cmd = sys.join("cmd.exe");
    let mut sbx = c.sbx(&[cmd.to_str().unwrap(), "/d", "/c", "go"]);
    sbx.env("PATH", &path);
    let r = run(sbx);
    let s = c.status();
    d.shutdown();
    println!(
        "X12 exit={} stdout={:?} stderr={:?} decisions={:?}",
        r.code,
        r.out.trim(),
        r.err.trim(),
        s.decisions
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(r.out.to_lowercase().contains(&acct), "{}", r.out);
    assert!(!r.err.contains("continuing without queue"), "{}", r.err);
    assert_eq!(count_decisions(&s, "admitted #"), 1, "{:?}", s.decisions);
    c.end();
}

// ---------------------------------------------------------------------------------------------
// X9: F27 for real (`unelevated`)
// ---------------------------------------------------------------------------------------------

/// X9. A sandboxed process holds the name of the owner's pipe and nobody serves it: the owner's
/// CLI refuses to write to it, and the occupant receives nothing.
#[test]
#[ignore]
fn x09_f27_a_pipe_held_by_a_restricted_process() {
    let Some(c) = Ctx::begin("unelevated") else {
        return;
    };
    let name = format!("sync_gate-xw-f27-{}", std::process::id());
    let out = c.tmp.join("f27");
    let occupant = Live::spawn(c.sbx_probe(&["-Serve", &name, "-Out", out.to_str().unwrap()]));
    let ready = PathBuf::from(format!("{}.ready", out.display()));
    wait_for("the occupant's pipe", 60, || ready.exists());
    let mut cli = c.owner_fg(&["status"]);
    cli.env("SYNC_GATE_SOCKET", &name);
    let r = run(cli);
    let o = occupant.finish();
    let report = std::fs::read_to_string(&out).unwrap_or_default();
    println!(
        "X9 owner's status exit={} stderr={:?}; occupant: {report:?} ({})",
        r.code,
        r.err.trim(),
        o.out.trim()
    );
    assert!(
        r.err.contains("daemon pipe is not owned by this user"),
        "{}",
        r.err
    );
    assert!(
        report.contains("bytes=0"),
        "the occupant received something: {report}"
    );
    // Control: with a daemon of the owner up (another name) the same `status` answers.
    let d = c.start(&[]);
    let ok = run(c.owner_fg(&["status"]));
    d.shutdown();
    assert_eq!(ok.code, 0, "{}", ok.err);
    assert!(ok.out.contains("memory:"), "{}", ok.out);
    c.end();
}

// ---------------------------------------------------------------------------------------------
// X10 (`mxc`, "@appcontainer") and X11 (`unelevated`, "@restricted"): a to d and f
// ---------------------------------------------------------------------------------------------

/// What differs between the two own-account sandboxes.
struct Kind {
    mode: &'static str,
    entry: &'static str,
    /// Lower-cased start of the key the daemon gives their commands.
    label: &'static str,
    /// `<socket>-sbx-<this>`.
    pipe: &'static str,
}

const MXC: Kind = Kind {
    mode: "mxc",
    entry: "@appcontainer",
    label: "[guest @appcontainer]",
    pipe: "appcontainer",
};
const UNELEVATED: Kind = Kind {
    mode: "unelevated",
    entry: "@restricted",
    label: "[guest @restricted]",
    pipe: "restricted",
};

fn kind_a(k: &Kind) {
    let Some(c) = Ctx::begin(k.mode) else { return };
    let d = c.start(&[k.entry]);
    let r = run(c.sbx_fg(&["run", "--", "cmd", "/d", "/c", "echo", "ok"]));
    let s = c.status();
    println!(
        "{} a exit={} stdout={:?} stderr={:?} decisions={:?}",
        k.mode,
        r.code,
        r.out.trim(),
        r.err.trim(),
        s.decisions
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(r.out.contains("ok"), "{}", r.out);
    assert!(!r.err.contains("continuing without queue"), "{}", r.err);
    assert_eq!(count_decisions(&s, "admitted #"), 1, "{:?}", s.decisions);
    assert_eq!(count_ended(&s), 1, "{:?}", s.decisions);
    let (r2, seen) = run_and_watch(
        &c,
        c.sbx_fg(&[
            "run",
            "--",
            "powershell.exe",
            "-NoProfile",
            "-Command",
            "Start-Sleep -Seconds 5",
        ]),
        k.label,
    );
    d.shutdown();
    println!(
        "{} a second run exit={} stderr={:?} seen {} in the owner's Status: {seen}",
        k.mode,
        r2.code,
        r2.err.trim(),
        k.label
    );
    assert_eq!(r2.code, 0, "{}", r2.err);
    // The child lived for 5 s: the daemon must have accepted its `Started`.
    assert!(!r2.err.contains("unexpected reply"), "{}", r2.err);
    assert!(seen, "the owner's Status never showed a row `{}`", k.label);
    c.end();
}

fn kind_b(k: &Kind) {
    let Some(c) = Ctx::begin(k.mode) else { return };
    let d = c.start(&[]);
    let r = run(c.sbx_fg(&["run", "--", "cmd", "/d", "/c", "echo", "ok"]));
    d.shutdown();
    println!(
        "{} b exit={} stdout={:?} stderr={:?}",
        k.mode,
        r.code,
        r.out.trim(),
        r.err.trim()
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(r.out.contains("ok"), "{}", r.out);
    assert!(
        r.err.contains("may not use the owner's sync_gate queue"),
        "{}",
        r.err
    );
    assert_eq!(
        sync_gate_lines(&r.err),
        1,
        "exactly one sync_gate line: {}",
        r.err
    );
    c.end();
}

fn kind_c(k: &Kind) {
    let Some(c) = Ctx::begin(k.mode) else { return };
    let d = c.start(&[k.entry]);
    let job = c.owner_job();
    let before = jsons(&[&c.tmp, &c.data()]);
    let r = run(c.sbx_fg(&[
        "run",
        "--max-wait",
        "0",
        "--",
        "cmd",
        "/d",
        "/c",
        "echo",
        "late",
    ]));
    let s = c.status();
    let after = jsons(&[&c.tmp, &c.data()]);
    println!("{} c exit={} stderr={:?}", k.mode, r.code, r.err.trim());
    assert_eq!(r.code, 75, "{}", r.err);
    assert!(r.err.contains(RERUN_LINE), "{}", r.err);
    assert!(!r.err.contains("sync_gate wait"), "{}", r.err);
    assert!(!r.out.contains("sync_gate wait"), "{}", r.out);
    assert!(
        !s.queued
            .iter()
            .any(|q| q.1.to_lowercase().contains(k.label)),
        "the guest's ticket is still queued: {:?}",
        s.queued
    );
    // The timeout's Cancel: `--max-wait 0` leaves the guest's ticket dormant (not in `queued`), so
    // identify it by its one `dormant #N` decision and prove it is gone: the daemon recorded
    // `cancelled #N: by client` and the owner's own Cancel finds no such ticket.
    let id = decision_id(&s, "dormant #");
    assert_eq!(
        count_decisions(&s, &format!("cancelled #{id}: by client")),
        1,
        "the guest's ticket #{id} was not cancelled after the exit 75: {:?}",
        s.decisions
    );
    match sync_gate::client::call_at(&c.socket, &Request::Cancel { id }) {
        Ok(Response::Error { message }) => assert!(
            message.contains("unknown ticket"),
            "a Cancel of #{id} answered: {message}"
        ),
        other => panic!("ticket #{id} is still alive after the exit 75: {other:?}"),
    }
    assert_eq!(
        before, after,
        "a .json appeared in <tmp> or the data folder"
    );
    job.release();
    d.shutdown();
    c.end();
}

fn kind_d(k: &Kind) {
    let Some(c) = Ctx::begin(k.mode) else { return };
    let d = c.start(&[k.entry]);
    let job = c.owner_job();
    let r = run(c.sbx_fg(&["status"]));
    println!("{} d exit={}\n{}", k.mode, r.code, r.out);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(r.out.contains("memory:"), "{}", r.out);
    assert!(!r.out.contains(&job.marker), "{}", r.out);
    job.release();
    d.shutdown();
    c.end();
}

fn kind_f(k: &Kind) {
    let Some(c) = Ctx::begin(k.mode) else { return };
    let d = c.start(&[k.entry]);
    let (main, guest, pid) = (
        c.socket.clone(),
        c.sbx_pipe(k.pipe),
        std::process::id().to_string(),
    );
    let cwd = c.work.join("proj").join("sub");
    let r = run(c.sbx_probe(&[
        "-Main",
        &main,
        "-Guest",
        &guest,
        "-ForgedPid",
        &pid,
        "-Cwd",
        cwd.to_str().unwrap(),
    ]));
    d.shutdown();
    println!("{} f exit={}\n{}{}", k.mode, r.code, r.out, r.err);
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(probe_line(&r.out, "guest narrow"), "OK", "{}", r.out);
    let forged = probe_line(&r.out, "Started forged");
    assert!(
        forged.contains("Error") && forged.contains("does not run as this caller"),
        "{forged}"
    );
    c.end();
}

#[test]
#[ignore]
fn x10a_mxc_runs_through_the_queue() {
    kind_a(&MXC)
}
#[test]
#[ignore]
fn x10b_mxc_not_listed_runs_directly() {
    kind_b(&MXC)
}
#[test]
#[ignore]
fn x10c_mxc_waited_too_long_says_rerun() {
    kind_c(&MXC)
}
#[test]
#[ignore]
fn x10d_mxc_status_hides_the_owners_work() {
    kind_d(&MXC)
}
#[test]
#[ignore]
fn x10f_mxc_forged_started_is_refused() {
    kind_f(&MXC)
}

#[test]
#[ignore]
fn x11a_unelevated_runs_through_the_queue() {
    kind_a(&UNELEVATED)
}
#[test]
#[ignore]
fn x11b_unelevated_not_listed_runs_directly() {
    kind_b(&UNELEVATED)
}
#[test]
#[ignore]
fn x11c_unelevated_waited_too_long_says_rerun() {
    kind_c(&UNELEVATED)
}
#[test]
#[ignore]
fn x11d_unelevated_status_hides_the_owners_work() {
    kind_d(&UNELEVATED)
}
#[test]
#[ignore]
fn x11f_unelevated_forged_started_is_refused() {
    kind_f(&UNELEVATED)
}

// ---------------------------------------------------------------------------------------------
// X11g: a client of another kind on the `@restricted` pipe
// ---------------------------------------------------------------------------------------------

/// The daemon's own stderr in a file for the life of this value (`SetStdHandle`; `eprintln!` reads
/// the handle on every write, so it works only with `--nocapture`).
struct StderrToFile {
    saved: windows_sys::Win32::Foundation::HANDLE,
    path: PathBuf,
    _file: std::fs::File,
}

impl StderrToFile {
    fn new(path: PathBuf) -> Self {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE, SetStdHandle};
        let file = std::fs::File::create(&path).unwrap();
        // SAFETY: plain calls; `file` stays open for as long as it is the standard error handle.
        let saved = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
        let ok = unsafe { SetStdHandle(STD_ERROR_HANDLE, file.as_raw_handle().cast()) };
        assert_ne!(ok, 0, "SetStdHandle failed");
        Self {
            saved,
            path,
            _file: file,
        }
    }

    fn text(&self) -> String {
        std::fs::read_to_string(&self.path).unwrap_or_default()
    }
}

impl Drop for StderrToFile {
    fn drop(&mut self) {
        use windows_sys::Win32::System::Console::{STD_ERROR_HANDLE, SetStdHandle};
        // SAFETY: puts back the handle taken in `new`.
        unsafe { SetStdHandle(STD_ERROR_HANDLE, self.saved) };
    }
}

/// X11g. `guests = [<elevated account>, "@restricted"]`: the `elevated` client opens the
/// `-sbx-restricted` pipe (its ACE for the logon SID lets it, F36) and is dropped without a reply.
#[test]
#[ignore]
fn x11g_a_client_of_another_kind_is_dropped() {
    let Some(c) = Ctx::begin("elevated") else {
        return;
    };
    let acct = c.account.clone();
    let log = StderrToFile::new(c.work.join("daemon-stderr.txt"));
    let d = c.start(&[&acct, "@restricted"]);
    let (main, guest) = (c.socket.clone(), c.sbx_pipe("restricted"));
    let cwd = c.work.join("proj").join("sub");
    let r = run(c.sbx_probe(&[
        "-Main",
        &main,
        "-Guest",
        &guest,
        "-Cwd",
        cwd.to_str().unwrap(),
    ]));
    d.shutdown();
    let daemon_said = log.text();
    drop(log);
    println!(
        "X11g probe exit={}\n{}{}\ndaemon stderr: {daemon_said:?}",
        r.code, r.out, r.err
    );
    assert_eq!(r.code, 0, "{}", r.err);
    // The probe really got in (the pipe's ACE lets the elevated client connect, F36) ...
    assert_eq!(probe_line(&r.out, "guest narrow"), "OK", "{}", r.out);
    // ... and was dropped without a reply after connecting: EOF or a broken pipe. A refused
    // access, a failed connection or any other write/read error is `FAILED(..)`: not this proof.
    let acquire = probe_line(&r.out, "Acquire");
    assert_eq!(
        acquire, "CLOSED-WITHOUT-REPLY",
        "the client of another kind was not dropped without a reply: {acquire}"
    );
    assert!(
        daemon_said.contains("refused a client of another kind"),
        "the daemon's stderr (needs --nocapture): {daemon_said:?}"
    );
    c.end();
}
