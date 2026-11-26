//! The pause of a guest's job proven with the REAL `codex sandbox` (plan 3-S, Task 6): X7
//! (`elevated`, two accounts, the launcher of F33), X10e (`mxc`) and X11e (`unelevated`).
//!
//! `#[ignore]`: only on request, with `SYNC_GATE_TEST_CODEX_SANDBOX=1` and `codex` on the `PATH`
//! (else `skipped: ...`):
//!
//! ```text
//! cargo test -p sync_gate_probe --test xuser_pause_windows --locked -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! Same footprint as `crates/sync_gate/tests/xuser_windows.rs` (the Codex setup of the `elevated` and
//! `unelevated` modes re-applies ACLs and lists the fixed folder `<tmp>` in `cap_sid`, authorised
//! by the owner; the tests grant nothing themselves). The only processes the tests end are the one
//! they created, by its handle; the sandbox command ends by itself.
#![cfg(windows)]

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};
use sync_gate_probe::{
    GuestUnit, IdentKind, TokenView, process_ident, start_time, suspend_tree_as, token_view,
};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::Security::{
    DuplicateTokenEx, SecurityImpersonation, TOKEN_ALL_ACCESS, TOKEN_QUERY, TokenPrimary,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CreateProcessAsUserW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, InitializeProcThreadAttributeList,
    OpenProcess, OpenProcessToken, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, PROCESS_CREATE_PROCESS,
    PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, STARTUPINFOEXW, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject,
};

/// The deadline of one process execution: from its spawn to the last byte of its output.
const BOUND: Duration = Duration::from_secs(180);
/// The same for the short helpers (powershell, `codex --version`).
const SHORT_BOUND: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------------------------
// Guards and the fixed folder (the same as xuser_windows.rs)
// ---------------------------------------------------------------------------------------------

/// ACEs of the three Codex sandbox accounts on six paths. Not seen: a grant made by the warm-up
/// itself, a path outside the six, an ACE for a capability SID (F23). Read-only.
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
    let added: Vec<_> = to.difference(from).collect();
    let removed: Vec<_> = from.difference(to).collect();
    println!("ACL guard {label}: +{} -{}", added.len(), removed.len());
    for e in added {
        println!("    + {e}");
    }
    for e in removed {
        println!("    - {e}");
    }
}

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

    /// Waits for the exit and the output until the deadline of the whole execution; past it the
    /// child is killed through its handle, what it printed is collected and the test fails.
    fn finish(mut self) -> Res {
        let mut child = self.child.take().unwrap();
        let status = loop {
            if let Some(s) = child.try_wait().expect("try_wait") {
                break Some(s);
            }
            if Instant::now() >= self.deadline {
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
        if let Some(mut c) = self.child.take() {
            if let Err(e) = kill_confirmed(&mut c, Duration::from_secs(10)) {
                let _ = writeln!(
                    std::io::stderr(),
                    "WARNING: a test process may still be running: {e}"
                );
            }
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
        std::thread::sleep(Duration::from_millis(50));
    }
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

struct Ctx {
    mode: &'static str,
    /// `%TEMP%\trabalho\sync_gate\xw`: the one folder the sandbox can write (K1).
    tmp: PathBuf,
    /// The owner's folder for this test (the owner process's beat).
    work: PathBuf,
    acl_warm: BTreeSet<String>,
}

impl Ctx {
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
        let acl_before = acl_capture();
        let base = std::env::temp_dir().join("trabalho").join("sync_gate");
        // The folder guard first: whatever fails below, `Drop` removes both folders (bounded, and
        // a folder that stays is reported).
        let mut c = Ctx {
            mode,
            tmp: base.join("xw"),
            work: base.join(format!("xw-pause-{}", std::process::id())),
            acl_warm: BTreeSet::new(),
        };
        remove_dir(&c.tmp);
        std::fs::create_dir_all(&c.tmp).unwrap();
        remove_dir(&c.work);
        std::fs::create_dir_all(&c.work).unwrap();
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
        let own = std::env::var("USERNAME").unwrap().to_lowercase();
        println!("{mode} warm-up whoami = {who}");
        let local = who.rsplit('\\').next().unwrap();
        if mode == "elevated" && local == own {
            println!("skipped: the elevated sandbox ran as the owner ({who})");
            return None;
        }
        assert!(
            mode == "elevated" || local == own,
            "the {mode} sandbox is expected to run as the owner, got {who}"
        );
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

    fn end(self) {
        let acl_end = acl_capture();
        print_capture(&format!("[{}] at the end", self.mode), &acl_end);
        print_diff(
            &format!("[{}] after the warm-up -> end", self.mode),
            &self.acl_warm,
            &acl_end,
        );
        let new: Vec<_> = acl_end.difference(&self.acl_warm).collect();
        remove_dir(&self.tmp);
        remove_dir(&self.work);
        assert!(!self.tmp.exists(), "{} still exists", self.tmp.display());
        assert!(
            new.is_empty(),
            "ACEs of the sandbox accounts that the proof commands added: {new:?}"
        );
    }

    /// `codex -c windows.sandbox=<mode> sandbox -P :workspace -C <tmp> -- <argv>`.
    fn sbx(&self, argv: &[&str]) -> Command {
        let mut c = Command::new("codex");
        c.args(["-c", &format!("windows.sandbox={}", self.mode)])
            .args(["sandbox", "-P", ":workspace", "-C"])
            .arg(&self.tmp)
            .arg("--")
            .args(argv);
        c
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

// ---------------------------------------------------------------------------------------------
// Beats: a file rewritten every 100 ms by a process; its modification time says whether it runs.
// ---------------------------------------------------------------------------------------------

fn mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

/// The beat moved within `within`.
fn advances(p: &Path, within: Duration) -> bool {
    let m0 = mtime(p);
    let start = Instant::now();
    while start.elapsed() < within {
        std::thread::sleep(Duration::from_millis(40));
        if mtime(p) != m0 {
            return true;
        }
    }
    false
}

/// Written by the sandbox's command: its own pid, a beat of its own and a child with a beat.
const GUEST_SCRIPT: &str = r#"param([string]$Ws)
Set-Content -Encoding ascii "$Ws\guest.pid.tmp" $PID
Move-Item -Force "$Ws\guest.pid.tmp" "$Ws\guest.pid"
$cmd = "for (`$i = 0; `$i -lt 200; `$i++) { Set-Content -Encoding ascii '$Ws\child.beat' `$i; Start-Sleep -Milliseconds 100 }"
$child = Start-Process powershell.exe -PassThru -WindowStyle Hidden -ArgumentList '-NoProfile', '-Command', $cmd
for ($i = 0; $i -lt 200; $i++) { Set-Content -Encoding ascii "$Ws\guest.beat" $i; Start-Sleep -Milliseconds 100 }
"#;

/// Written by the owner's process that hangs below the guest: a beat of its own.
fn owner_script(beat: &Path) -> String {
    format!(
        "while ($true) {{ Set-Content -Encoding ascii '{}' 1; Start-Sleep -Milliseconds 100 }}\n",
        beat.display()
    )
}

// ---------------------------------------------------------------------------------------------
// Processes and tokens
// ---------------------------------------------------------------------------------------------

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn view_of_token(token: HANDLE) -> Option<TokenView> {
    token_view(token)
}

fn own_view() -> TokenView {
    let mut t: HANDLE = std::ptr::null_mut();
    // SAFETY: our own process; `t` is a valid out pointer; closed below.
    unsafe {
        assert_ne!(
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut t),
            0
        );
        let v = view_of_token(t).expect("own token");
        CloseHandle(t);
        v
    }
}

/// The token of `pid` as the owner can read it.
fn view_of_pid(pid: u32) -> Option<TokenView> {
    // SAFETY: handles are opened and closed here; out pointers are valid.
    unsafe {
        let p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if p.is_null() {
            return None;
        }
        let mut t: HANDLE = std::ptr::null_mut();
        let ok = OpenProcessToken(p, TOKEN_QUERY, &mut t) != 0;
        CloseHandle(p);
        if !ok {
            return None;
        }
        let v = view_of_token(t);
        CloseHandle(t);
        v
    }
}

/// ToolHelp: the parent pid of `pid`.
fn parent_of(pid: u32) -> Option<u32> {
    // SAFETY: a snapshot handle closed below; `e` is a properly sized PROCESSENTRY32W.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap.is_null() || snap as isize == -1 {
            return None;
        }
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut found = None;
        let mut ok = Process32FirstW(snap, &mut e) != 0;
        while ok {
            if e.th32ProcessID == pid {
                found = Some(e.th32ParentProcessID);
                break;
            }
            ok = Process32NextW(snap, &mut e) != 0;
        }
        CloseHandle(snap);
        found
    }
}

/// The owner's process hanging below a guest's process (F33): `CreateProcessAsUserW` with a
/// duplicate of the test's own token and `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` = the guest.
struct OwnerProc {
    process: HANDLE,
    pid: u32,
}

impl OwnerProc {
    /// `Err(win32 error)` when the guest process cannot be opened with `PROCESS_CREATE_PROCESS`.
    fn launch(parent_pid: u32, script: &Path) -> Result<OwnerProc, u32> {
        // SAFETY: plain Win32 calls with buffers that live through each call; every handle opened
        // here is closed here except the new process's, which `OwnerProc` ends.
        unsafe {
            let parent = OpenProcess(
                PROCESS_CREATE_PROCESS | PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                parent_pid,
            );
            if parent.is_null() {
                return Err(GetLastError());
            }
            let mut me: HANDLE = std::ptr::null_mut();
            assert_ne!(
                OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut me),
                0,
                "own token"
            );
            let mut dup: HANDLE = std::ptr::null_mut();
            let ok = DuplicateTokenEx(
                me,
                0x0200_0000,
                std::ptr::null(),
                SecurityImpersonation,
                TokenPrimary,
                &mut dup,
            );
            CloseHandle(me);
            assert_ne!(ok, 0, "DuplicateTokenEx: {}", GetLastError());

            let mut size = 0usize;
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size);
            let mut list = vec![0u8; size];
            let list_ptr = list.as_mut_ptr().cast();
            assert_ne!(
                InitializeProcThreadAttributeList(list_ptr, 1, 0, &mut size),
                0
            );
            let mut value = parent;
            assert_ne!(
                UpdateProcThreadAttribute(
                    list_ptr,
                    0,
                    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize,
                    (&mut value as *mut HANDLE).cast(),
                    size_of::<HANDLE>(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                ),
                0
            );
            let mut si: STARTUPINFOEXW = std::mem::zeroed();
            si.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
            si.lpAttributeList = list_ptr;
            let ps = format!(
                r"{}\System32\WindowsPowerShell\v1.0\powershell.exe",
                std::env::var("SystemRoot").unwrap()
            );
            let mut cmd = wide(&format!(
                "\"{ps}\" -NoProfile -ExecutionPolicy Bypass -File \"{}\"",
                script.display()
            ));
            let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
            let created = CreateProcessAsUserW(
                dup,
                std::ptr::null(),
                cmd.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                std::ptr::null(),
                std::ptr::null(),
                (&si as *const STARTUPINFOEXW).cast(),
                &mut pi,
            );
            let err = GetLastError();
            DeleteProcThreadAttributeList(list_ptr);
            CloseHandle(dup);
            CloseHandle(parent);
            if created == 0 {
                panic!("CreateProcessAsUserW with the guest as parent failed: error {err}");
            }
            CloseHandle(pi.hThread);
            Ok(OwnerProc {
                process: pi.hProcess,
                pid: pi.dwProcessId,
            })
        }
    }

    /// Ends the process this test created, by its handle, and waits (bounded) until it is gone.
    fn terminate(&self, wait_ms: u32) -> bool {
        // SAFETY: the handle is ours and still open (it is closed only by `Drop`).
        unsafe {
            TerminateProcess(self.process, 1);
            WaitForSingleObject(self.process, wait_ms) == WAIT_OBJECT_0
        }
    }

    /// The end the test checks: the process is really gone.
    fn end(self) {
        assert!(
            self.terminate(10_000),
            "the owner's process {} did not end within 10 s of TerminateProcess",
            self.pid
        );
    }
}

/// Installed with the handle: a panic anywhere after the launch still ends the process (its
/// script loops forever) and closes the handle.
impl Drop for OwnerProc {
    fn drop(&mut self) {
        if !self.terminate(5_000) {
            let _ = writeln!(
                std::io::stderr(),
                "WARNING: the owner's process {} may still be running (not confirmed ended)",
                self.pid
            );
        }
        // SAFETY: the handle is ours; closed once, here.
        unsafe { CloseHandle(self.process) };
    }
}

// ---------------------------------------------------------------------------------------------
// The scenario, shared by X7, X10e and X11e
// ---------------------------------------------------------------------------------------------

/// How the guest of a mode is named for the pause.
struct Mode {
    sandbox: &'static str,
    /// What `process_ident` must start with.
    prefix: &'static str,
    /// An ident that is a real kind but not this job's: the pause must refuse it, freezing nothing.
    wrong: fn(&TokenView) -> String,
    kind: fn(&TokenView, &TokenView) -> IdentKind,
}

/// X7: another local account (the sandbox account), `account:<its SID>`.
const ELEVATED: Mode = Mode {
    sandbox: "elevated",
    prefix: "account:",
    // The owner's account: never a guest's identity, whatever the tree below.
    wrong: |own| format!("account:{}", own.user),
    kind: |guest, _own| IdentKind::Account(guest.user.clone()),
};

/// X10e: the owner's own account inside an AppContainer.
const MXC: Mode = Mode {
    sandbox: "mxc",
    prefix: "appcontainer:",
    wrong: |own| format!("appcontainer:{}:S-1-15-2-1-1-1-1-1-1-1", own.user),
    kind: |_guest, own| IdentKind::AppContainer(own.user.clone()),
};

/// X11e: the owner's own account with a write-restricted token.
const UNELEVATED: Mode = Mode {
    sandbox: "unelevated",
    prefix: "restricted:",
    wrong: |own| format!("restricted:{}:S-1-1-0", own.user),
    kind: |_guest, own| IdentKind::Restricted(own.user.clone()),
};

fn pause_scenario(m: &Mode, label: &str) {
    let Some(c) = Ctx::begin(m.sandbox) else {
        return;
    };
    let own = own_view();
    std::fs::write(c.tmp.join("guest.ps1"), GUEST_SCRIPT).unwrap();
    let guest_beat = c.tmp.join("guest.beat");
    let child_beat = c.tmp.join("child.beat");
    let owner_beat = c.work.join("owner.beat");
    std::fs::write(c.work.join("owner.ps1"), owner_script(&owner_beat)).unwrap();

    let script = c.tmp.join("guest.ps1");
    let ws = c.tmp.to_str().unwrap().to_owned();
    let sandbox = Live::spawn(c.sbx(&[
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        script.to_str().unwrap(),
        "-Ws",
        &ws,
    ]));
    let pid_file = c.tmp.join("guest.pid");
    wait_for("guest.pid", 60, || {
        std::fs::read_to_string(&pid_file).is_ok_and(|s| s.trim().parse::<u32>().is_ok())
    });
    let guest: u32 = std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    wait_for("both guest beats", 30, || {
        guest_beat.exists() && child_beat.exists()
    });
    assert!(
        advances(&guest_beat, Duration::from_secs(1)),
        "guest.beat does not run"
    );
    assert!(
        advances(&child_beat, Duration::from_secs(1)),
        "child.beat does not run"
    );

    // The guest's identity, read as the owner reads it.
    let gview = view_of_pid(guest)
        .unwrap_or_else(|| panic!("the owner cannot read the token of the guest process {guest}"));
    println!("{label}: guest pid {guest}, token {gview:?}");
    let kind = (m.kind)(&gview, &own);
    let (ident, _created, _pin) = process_ident(guest, &kind)
        .unwrap_or_else(|| panic!("process_ident({guest}, {kind:?}) is None; token {gview:?}"));
    println!("{label}: ident = {ident}");
    assert!(ident.starts_with(m.prefix), "{ident}");
    if m.sandbox == "elevated" {
        // The SID of the account, asked of Windows by name, not read from the token.
        let mut o = Command::new("powershell");
        o.args(["-NoProfile", "-Command", "(New-Object Security.Principal.NTAccount('CodexSandboxOffline')).Translate([Security.Principal.SecurityIdentifier]).Value"]);
        assert_eq!(run_for(o, SHORT_BOUND).out.trim(), gview.user);
    }

    // The owner's process hanging below the guest's (the launcher of F33), when it can be made.
    let launched = OwnerProc::launch(guest, &c.work.join("owner.ps1"));
    let owner_proc = match launched {
        Ok(p) => {
            // Obligatory check before pausing: the process really is the owner's, unrestricted,
            // and really hangs below the guest.
            let v = view_of_pid(p.pid);
            let parent = parent_of(p.pid);
            println!(
                "{label}: owner process {} parent {parent:?} token {v:?}",
                p.pid
            );
            let good = v.as_ref().is_some_and(|v| {
                v.user == own.user && v.restricted.is_empty() && v.app_container.is_none()
            }) && parent == Some(guest);
            if !good {
                panic!(
                    "the owner's process is not what the test needs: parent {parent:?} (guest {guest}), token {v:?}, owner {own:?}"
                );
            }
            wait_for("owner.beat", 30, || owner_beat.exists());
            Some(p)
        }
        Err(code) => {
            assert_ne!(
                m.sandbox, "elevated",
                "X7: OpenProcess(PROCESS_CREATE_PROCESS) on the guest failed: error {code}"
            );
            println!(
                "launcher: denied (S21) (OpenProcess error {code}); continuing without the owner's process"
            );
            None
        }
    };

    // Pause.
    let start = start_time(guest).expect("the guest's start time");
    let mut planned: Vec<GuestUnit> = Vec::new();
    let frozen = suspend_tree_as(guest, start, &ident, &mut |batch| {
        planned.extend_from_slice(batch);
        Ok(())
    })
    .unwrap_or_else(|(_, e)| panic!("suspend_tree_as failed: {e}"));
    let pids: BTreeSet<u32> = planned.iter().map(|u| u.pid).collect();
    println!(
        "{label}: planned pids {pids:?}, {} units frozen",
        frozen.units().len()
    );
    assert!(
        pids.contains(&guest),
        "the guest's root is not in the plan: {pids:?}"
    );
    assert!(
        pids.len() >= 2,
        "the guest's child is not in the plan: {pids:?}"
    );
    for u in &planned {
        assert_eq!(u.ident, ident, "unit {u:?}");
        let v = view_of_pid(u.pid)
            .unwrap_or_else(|| panic!("cannot read the token of planned pid {}", u.pid));
        // Every planned process has the guest's token, none the owner's full one.
        assert!(
            process_ident(u.pid, &kind).is_some_and(|(i, ..)| i == ident),
            "planned pid {} has token {v:?}, not the guest's identity",
            u.pid
        );
    }
    if let Some(p) = &owner_proc {
        assert!(
            !pids.contains(&p.pid),
            "the owner's process {} is in the plan",
            p.pid
        );
    }
    // In at most 1 s the guest's beats stop, for at least 1 s; the owner's keeps going.
    std::thread::sleep(Duration::from_millis(1000));
    let (g0, c0) = (mtime(&guest_beat), mtime(&child_beat));
    std::thread::sleep(Duration::from_millis(1000));
    let (g1, c1) = (mtime(&guest_beat), mtime(&child_beat));
    println!(
        "{label}: while paused guest.beat {} child.beat {}",
        if g0 == g1 { "stopped" } else { "RAN" },
        if c0 == c1 { "stopped" } else { "RAN" }
    );
    assert_eq!(g0, g1, "guest.beat kept beating while paused");
    assert_eq!(c0, c1, "child.beat kept beating while paused");
    if owner_proc.is_some() {
        assert!(
            advances(&owner_beat, Duration::from_secs(1)),
            "owner.beat stopped: the owner's process was frozen"
        );
    }

    // The wrong identity freezes nothing (a negative with the positive above).
    let wrong = (m.wrong)(&own);
    // The beats are frozen right now: first resume, then try the wrong identity on a running tree.
    frozen
        .resume()
        .unwrap_or_else(|(_, e)| panic!("resume failed: {e}"));
    assert!(
        advances(&guest_beat, Duration::from_millis(1500)),
        "guest.beat did not come back"
    );
    assert!(
        advances(&child_beat, Duration::from_millis(1500)),
        "child.beat did not come back"
    );
    if m.sandbox == "elevated" {
        match suspend_tree_as(guest, start, &wrong, &mut |_| Ok(())) {
            Err((left, e)) => {
                assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{e}");
                assert!(left.units().is_empty());
            }
            Ok(_) => panic!("suspend_tree_as accepted the owner's account for a guest's tree"),
        }
        assert!(
            advances(&guest_beat, Duration::from_secs(1)),
            "the refused pause stopped guest.beat"
        );
        assert!(
            advances(&child_beat, Duration::from_secs(1)),
            "the refused pause stopped child.beat"
        );
    } else {
        // The same-account kinds: a real kind that is not this job's identity is refused too.
        let r = suspend_tree_as(guest, start, &wrong, &mut |_| Ok(()));
        match r {
            Err((left, e)) => {
                assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{e}");
                assert!(left.units().is_empty());
            }
            Ok(_) => panic!("suspend_tree_as accepted {wrong} for this guest"),
        }
        assert!(
            advances(&guest_beat, Duration::from_secs(1)),
            "the refused pause stopped guest.beat"
        );
    }

    if let Some(p) = owner_proc {
        p.end();
    }
    // The sandbox command ends by itself (at most 20 s after it began).
    let r = sandbox.finish();
    println!(
        "{label}: sandbox command exit={} {}{}",
        r.code,
        r.out.trim(),
        r.err.trim()
    );
    c.end();
}

/// X7. Two accounts: the `elevated` sandbox account's job with one of the owner's processes
/// hanging below it. The pause freezes the guest's processes only.
#[test]
#[ignore]
fn x07_pause_a_guest_job_with_an_owner_process_hanging() {
    pause_scenario(&ELEVATED, "X7");
}

/// X10e. `mxc`: the owner's account inside an AppContainer.
#[test]
#[ignore]
fn x10e_pause_in_the_appcontainer() {
    pause_scenario(&MXC, "X10e");
}

/// X11e. `unelevated`: the owner's account with a write-restricted token.
#[test]
#[ignore]
fn x11e_pause_with_the_restricted_token() {
    pause_scenario(&UNELEVATED, "X11e");
}
