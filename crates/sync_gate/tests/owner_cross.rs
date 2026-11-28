//! F11 (item 6), Windows: a file created by an elevated process of this user (owner:
//! Administrators) is trusted by a normal process of this user, and the other way round. The
//! child runs with a token made from this process's own: Administrators disabled, every privilege
//! but one dropped, integrity Medium. What each side really was is printed (elevation, integrity,
//! owner of each file); without elevation the cross-owner half does not apply and is said so.
#![cfg(windows)]

use std::ffi::OsString;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSidToSidW, GetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, GetTokenInformation, OWNER_SECURITY_INFORMATION,
    PSID, SID_AND_ATTRIBUTES, SetTokenInformation, TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY,
    TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TokenElevation,
    TokenIntegrityLevel,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, GetCurrentProcess,
    GetExitCodeProcess, INFINITE, OpenProcessToken, PROCESS_INFORMATION, STARTUPINFOW,
    WaitForSingleObject,
};

fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain([0]).collect()
}

fn sid_text(s: PSID) -> String {
    let mut t = std::ptr::null_mut();
    // SAFETY: a valid SID; `t` is freed below.
    unsafe {
        if ConvertSidToStringSidW(s, &mut t) == 0 {
            return "?".into();
        }
        let n = (0..).take_while(|&i| *t.add(i) != 0).count();
        let out = String::from_utf16_lossy(std::slice::from_raw_parts(t, n));
        LocalFree(t.cast());
        out
    }
}

fn sid(text: &str) -> PSID {
    let mut p = std::ptr::null_mut();
    let w: Vec<u16> = text.encode_utf16().chain([0]).collect();
    // SAFETY: a NUL-terminated string; the SID is leaked on purpose (a test).
    assert_ne!(unsafe { ConvertStringSidToSidW(w.as_ptr(), &mut p) }, 0);
    p
}

fn owner_of(p: &Path) -> String {
    let f = std::fs::File::open(p).unwrap();
    let (mut owner, mut sd) = (std::ptr::null_mut(), std::ptr::null_mut());
    // SAFETY: a valid handle; `owner` points into `sd`, freed below.
    unsafe {
        let e = GetSecurityInfo(
            f.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        );
        assert_eq!(e, 0);
        let t = sid_text(owner);
        LocalFree(sd);
        t
    }
}

/// (elevated, integrity RID) of a token.
fn describe(token: HANDLE) -> (bool, u32) {
    let mut e = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut len = 0;
    let mut buf = vec![0u64; 16];
    // SAFETY: buffers of the sizes passed.
    unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&raw mut e).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        );
        GetTokenInformation(
            token,
            TokenIntegrityLevel,
            buf.as_mut_ptr().cast(),
            (buf.len() * 8) as u32,
            &mut len,
        );
        let label = &*buf.as_ptr().cast::<TOKEN_MANDATORY_LABEL>();
        let text = sid_text(label.Label.Sid);
        let rid = text.rsplit('-').next().unwrap().parse().unwrap_or(0);
        (e.TokenIsElevated != 0, rid)
    }
}

fn own_token() -> HANDLE {
    let mut t = std::ptr::null_mut();
    let access = TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT;
    // SAFETY: a pseudo handle and a valid out pointer.
    assert_ne!(
        unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut t) },
        0
    );
    t
}

/// This process's token with Administrators disabled, privileges dropped and integrity Medium.
fn normal_token() -> HANDLE {
    let me = own_token();
    let ba = SID_AND_ATTRIBUTES {
        Sid: sid("S-1-5-32-544"),
        Attributes: 0,
    };
    let mut r = std::ptr::null_mut();
    // SAFETY: valid handles and arrays of the counts passed.
    unsafe {
        let ok = CreateRestrictedToken(
            me,
            DISABLE_MAX_PRIVILEGE,
            1,
            &ba,
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            &mut r,
        );
        assert_ne!(ok, 0, "{}", std::io::Error::last_os_error());
        let label = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: sid("S-1-16-8192"),
                Attributes: 0x20, // SE_GROUP_INTEGRITY
            },
        };
        let ok = SetTokenInformation(
            r,
            TokenIntegrityLevel,
            (&raw const label).cast(),
            size_of::<TOKEN_MANDATORY_LABEL>() as u32,
        );
        assert_ne!(ok, 0, "{}", std::io::Error::last_os_error());
        CloseHandle(me);
    }
    r
}

/// Runs `cmd /d /c <line>` with `token` and `env` added; the exit code and what the child token was.
fn run_as(token: HANDLE, line: &str, env: &[(&str, &Path)]) -> (u32, bool, u32) {
    let mut block: Vec<u16> = Vec::new();
    for (k, v) in std::env::vars_os() {
        if env.iter().any(|(n, _)| k == *n) {
            continue;
        }
        let mut kv = k.clone();
        kv.push("=");
        kv.push(v);
        block.extend(kv.encode_wide().chain([0]));
    }
    for (k, v) in env {
        let mut kv = OsString::from(k);
        kv.push("=");
        kv.push(v.as_os_str());
        block.extend(kv.encode_wide().chain([0]));
    }
    block.push(0);
    let mut cmd = wide(&OsString::from(format!("cmd.exe /d /c \"{line}\"")));
    let si = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        ..unsafe { std::mem::zeroed() }
    };
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: valid buffers; the handles returned are closed below.
    unsafe {
        let ok = CreateProcessAsUserW(
            token,
            std::ptr::null(),
            cmd.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            block.as_ptr().cast(),
            std::ptr::null(),
            &si,
            &mut pi,
        );
        assert_ne!(
            ok,
            0,
            "CreateProcessAsUserW: {}",
            std::io::Error::last_os_error()
        );
        let mut t = std::ptr::null_mut();
        let seen = if OpenProcessToken(pi.hProcess, TOKEN_QUERY, &mut t) != 0 {
            let d = describe(t);
            CloseHandle(t);
            d
        } else {
            (false, 0)
        };
        WaitForSingleObject(pi.hProcess, INFINITE);
        let mut code = 0;
        GetExitCodeProcess(pi.hProcess, &mut code);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        (code, seen.0, seen.1)
    }
}

fn scratch() -> PathBuf {
    let d = std::env::temp_dir().join(format!("fg-f11-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn files_cross_between_an_elevated_and_a_normal_process_of_this_user() {
    let me = own_token();
    let (elevated, il) = describe(me);
    // SAFETY: opened above.
    unsafe { CloseHandle(me) };
    println!("F11 parent: elevated={elevated} integrity=0x{il:x}");
    let d = scratch();
    let exe = PathBuf::from(env!("CARGO_BIN_EXE_sync_gate"));
    // Parent -> child: the parent's config, read by `mcp list` in the child.
    let cfg = d.join("config.toml");
    std::fs::write(&cfg, "[mcp.docs]\ncommand = \"docs-mcp\"\n").unwrap();
    println!("F11 config written by the parent: owner {}", owner_of(&cfg));
    let token = normal_token();
    let out = d.join("list.txt");
    let line = format!(
        "\"{}\" mcp list > \"{}\" 2>&1",
        exe.display(),
        out.display()
    );
    let sock = PathBuf::from(format!("fg-f11-{}", std::process::id()));
    let (code, child_elevated, child_il) = run_as(
        token,
        &line,
        &[("SYNC_GATE_CONFIG", &cfg), ("SYNC_GATE_SOCKET", &sock)],
    );
    let listed = std::fs::read_to_string(&out).unwrap_or_default();
    println!(
        "F11 child: elevated={child_elevated} integrity=0x{child_il:x}; mcp list exit={code}: {listed:?}"
    );
    // Child -> parent: a file the child creates, read as a config by the parent.
    let back = d.join("back.toml");
    let (code2, ..) = run_as(
        token,
        &format!("echo max_wait_secs = 5 > \"{}\"", back.display()),
        &[],
    );
    // SAFETY: made by `normal_token`.
    unsafe { CloseHandle(token) };
    println!(
        "F11 file written by the child (exit {code2}): owner {}",
        owner_of(&back)
    );
    let read = sync_gate_core::read_config(&back);
    println!("F11 parent reads it: {read:?}");
    let _ = std::fs::remove_dir_all(&d);
    assert_eq!(code, 0, "{listed}");
    assert!(listed.contains("docs"), "{listed}");
    assert!(
        read.as_deref().is_ok_and(|t| t.contains("max_wait_secs")),
        "{read:?}"
    );
    if !elevated {
        println!(
            "partial: not elevated, both files are owned by this user; the cross-owner case needs an elevated run"
        );
    } else if child_elevated || child_il > 0x2000 {
        println!(
            "partial: the child was not a normal process (elevated={child_elevated}, integrity=0x{child_il:x})"
        );
    }
}
