//! `sync_gate hook session-start`: puts the shims folder on the PATH of a Claude Code session
//! (through `CLAUDE_ENV_FILE`, plain assignments only) and prints a short context.
//! Always exits 0 and prints valid JSON; it never talks to the daemon.

use std::ffi::OsStr;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use sync_gate_core::{SHIMS_MANIFEST, shims_dir};

/// Most the hook reads from stdin or from the environment file.
const LIMIT: u64 = 64 * 1024;
const STDIN_DEADLINE: std::time::Duration = std::time::Duration::from_secs(2);

const WINDOWS_NOTE: &str = " Inside Codex's Windows sandbox the queue works only when the owner lists the sandbox in \"guests\" (see docs/sandbox.md); otherwise commands run directly and sync_gate prints one line saying so.";
const BASH: &str = "sync_gate (local job queue): at session start no folder ahead of the shims folder on PATH for Bash had a command the shims cover (inherited, or set by the session env file); Bash's effective PATH is not re-checked later. Heavy commands (npm/pnpm/yarn/bun install|ci|test|build, cargo build|test|clippy|xtask, docker build, next build, go build|test, pytest, vitest, jest, tsc, gradle, mvn) should wait for a slot automatically. In the PowerShell tool, or if unsure a heavy command goes through the shims, run it as \"sync_gate run -- <command>\". Exit code 75 with \"queued: ticket N\" means the machine is busy and nothing ran: do other work, then run \"sync_gate wait N\" (it runs the stored command with the environment of the shell that calls it, not the original one, so call it from a shell with the same variables). Do not re-run the command another way to skip the queue. \"sync_gate status\" shows memory, running jobs and the queue.";
const ON: &str = "sync_gate (local job queue): at session start no folder ahead of the shims folder on PATH for Bash had a command the shims cover (inherited, or set by the session env file); Bash's effective PATH is not re-checked later. Heavy commands (npm/pnpm/yarn/bun install|ci|test|build, cargo build|test|clippy|xtask, docker build, next build, go build|test, pytest, vitest, jest, tsc, gradle, mvn) should wait for a slot automatically. If unsure a heavy command goes through the shims, run it as \"sync_gate run -- <command>\". Exit code 75 with \"queued: ticket N\" means the machine is busy and nothing ran: do other work, then run \"sync_gate wait N\" (it runs the stored command with the environment of the shell that calls it, not the original one, so call it from a shell with the same variables). Do not re-run the command another way to skip the queue. \"sync_gate status\" shows memory, running jobs and the queue.";
const PREFIX: &str = "sync_gate (local job queue) is installed. Run heavy commands (builds, test suites, installs, docker build) as \"sync_gate run -- <command>\". Exit code 75 with \"queued: ticket N\" means the machine is busy and nothing ran: do other work, then run \"sync_gate wait N\" (it runs the stored command with the environment of the shell that calls it, not the original one, so call it from a shell with the same variables). \"sync_gate status\" shows memory, running jobs and the queue.";

pub struct HookInput<'a> {
    pub stdin: Option<&'a str>,
    pub env_file: Option<&'a Path>,
    pub shims: Option<&'a Path>,
    pub path: Option<&'a OsStr>,
    pub session_set: bool,
}

pub fn session_start() -> i32 {
    let stdin = read_stdin();
    let env_file = std::env::var_os("CLAUDE_ENV_FILE").map(PathBuf::from);
    let shims = shims_dir();
    let path = std::env::var_os("PATH");
    let mut input = HookInput {
        stdin: Some(&stdin),
        env_file: env_file.as_deref(),
        shims: shims.as_deref(),
        path: path.as_deref(),
        session_set: std::env::var_os("SYNC_GATE_SESSION").is_some(),
    };
    let (mut out, lines) = session_start_with(&input);
    if let Some(f) = input.env_file
        && !lines.is_empty()
        && append(f, &lines).is_err()
    {
        // Nothing reached the file: say what is true, not what we meant to do.
        input.env_file = None;
        out = session_start_with(&input).0;
    }
    println!("{out}");
    0
}

/// Stdin as text (at most `LIMIT` bytes), or empty if it is a terminal or does not end within
/// `STDIN_DEADLINE` (a writer that keeps the pipe open must not hold the session start).
fn read_stdin() -> String {
    if std::io::stdin().is_terminal() {
        return String::new();
    }
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut s = String::new();
        let _ = std::io::stdin().take(LIMIT).read_to_string(&mut s);
        let _ = tx.send(s);
    });
    rx.recv_timeout(STDIN_DEADLINE).unwrap_or_default()
}

/// Appends whole lines; never truncates. Looks only at the file's size and last byte (never the
/// whole file): if they cannot be checked, or the file is over `LIMIT`, nothing is written. A
/// missing file (Claude Code does not create it before the hook) is created, empty, in its
/// existing folder.
fn append(file: &Path, lines: &[String]) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind, Seek, SeekFrom};
    // One handle reads the last byte and appends: an append-mode write always lands at the end.
    let mut r = std::fs::OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(file)?;
    let len = r.metadata()?.len();
    if len > LIMIT {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "env file too big to inspect",
        ));
    }
    let mut text = String::new();
    if len > 0 {
        let mut last = [0u8];
        r.seek(SeekFrom::Start(len - 1))?;
        r.read_exact(&mut last)?;
        if last[0] != b'\n' {
            text.push('\n');
        }
    }
    for l in lines {
        text.push_str(l);
        text.push('\n');
    }
    r.write_all(text.as_bytes())
}

/// The env file's text; `None` when it cannot be known to be whole (so no PATH line is written).
fn read_env_file(file: &Path) -> Option<String> {
    let mut buf = Vec::new();
    match std::fs::File::open(file) {
        Ok(f) => f.take(LIMIT + 1).read_to_end(&mut buf).ok()?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(_) => return None,
    };
    if buf.len() as u64 > LIMIT {
        return None;
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

fn shims_active(dir: &Path) -> bool {
    #[cfg(unix)]
    if !matches!(
        sync_gate_core::check_private_dir(dir),
        Ok(sync_gate_core::DirState::Private | sync_gate_core::DirState::OthersCanRead)
    ) {
        return false;
    }
    dir.join(SHIMS_MANIFEST).is_file()
}

/// (stdout JSON, lines to append to the env file)
pub fn session_start_with(i: &HookInput) -> (String, Vec<String>) {
    let mut lines = Vec::new();
    let active = i.shims.filter(|d| shims_active(d));
    // A PATH the env file sets (or may set: unreadable) replaces the inherited one in Bash.
    let shims_ahead = active.is_some_and(|d| i.path.is_some_and(|p| shims_ahead(d, p)))
        && i.env_file
            .is_none_or(|f| read_env_file(f).is_some_and(|t| !mentions_path(&t)));
    let mut bash = shims_ahead && i.env_file.is_some();
    if let (Some(dir), Some(file), false) = (active, i.env_file, shims_ahead)
        && let Some(line) = path_for(dir, file, i.path)
    {
        lines.push(line);
        bash = true;
    }
    if let Some(line) = (!i.session_set && i.env_file.is_some())
        .then(|| i.stdin.and_then(session_id))
        .flatten()
        .and_then(|id| session_line(&id))
    {
        lines.push(line);
    }
    lines.retain(|l| is_plain_assignment(l));
    let text = match (bash, shims_ahead) {
        (true, _) => BASH,
        (false, true) => ON,
        _ => PREFIX,
    };
    let ctx = if cfg!(windows) {
        format!("{text}{WINDOWS_NOTE}")
    } else {
        text.to_owned()
    };
    let json = serde_json::json!({"hookSpecificOutput": {
        "hookEventName": "SessionStart", "additionalContext": ctx}});
    (json.to_string(), lines)
}

/// True when `dir` is on `path` and no folder before it holds a command its shims cover (same
/// file name; Windows: ignoring case and `PATHEXT` extensions). A folder before it that is missing
/// is harmless; one that exists but cannot be listed, or a relative one (Bash resolves it later,
/// from its own directory), counts as holding one.
fn shims_ahead(dir: &Path, path: &OsStr) -> bool {
    use std::collections::HashSet;
    let exts = sync_gate_core::config::pathext_list(std::env::var_os("PATHEXT").as_deref());
    let key = |name: &OsStr| {
        let name = name.to_string_lossy();
        if cfg!(windows) {
            sync_gate_core::config::program_key(&name, &exts)
        } else {
            name.into_owned()
        }
    };
    let Ok(listing) = std::fs::read_dir(dir) else {
        return false;
    };
    let Ok(mut shims) = listing
        .map(|e| e.map(|e| key(&e.file_name())))
        .collect::<std::io::Result<HashSet<_>>>()
    else {
        return false;
    };
    shims.remove(&key(OsStr::new(SHIMS_MANIFEST)));
    let clashes = |d: &Path| -> std::io::Result<bool> {
        for e in std::fs::read_dir(d)? {
            if shims.contains(&key(&e?.file_name())) {
                return Ok(true);
            }
        }
        Ok(false)
    };
    for e in std::env::split_paths(path) {
        // Skipped as `path_for` skips it.
        if cfg!(windows) && e.as_os_str().is_empty() {
            continue;
        }
        if same_shims_dir(&e, dir) {
            return true;
        }
        if !e.is_absolute() {
            return false;
        }
        match clashes(&e) {
            Ok(false) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            _ => return false,
        }
    }
    false
}

fn session_id(stdin: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(stdin).ok()?;
    Some(v.get("session_id")?.as_str()?.to_owned())
}

fn same_shims_dir(a: &Path, b: &Path) -> bool {
    if a.as_os_str() == b.as_os_str() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;

        let identity = |p: &Path| {
            std::fs::OpenOptions::new()
                .access_mode(0)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                .open(p)
                .ok()
                .and_then(|f| crate::adopt::identity(&f))
        };
        if let Some(same) = identity(a)
            .zip(identity(b))
            .and_then(|(a, b)| same_shims_identity(a, b))
        {
            return same;
        }
    }
    std::fs::canonicalize(a)
        .ok()
        .zip(std::fs::canonicalize(b).ok())
        .is_some_and(|(a, b)| a.as_os_str() == b.as_os_str())
}

#[cfg(windows)]
fn same_shims_identity(a: (u64, [u8; 16]), b: (u64, [u8; 16])) -> Option<bool> {
    // FILE_ID_128 reserves all zeroes and all ones for an unavailable ID.
    let available = |id| id != [0; 16] && id != [0xff; 16];
    (available(a.1) && available(b.1)).then_some(a == b)
}

/// The PATH line, unless the env file mentions PATH at all (we cannot read what it did) or a
/// part cannot be written as a plain literal.
fn path_for(dir: &Path, file: &Path, path: Option<&OsStr>) -> Option<String> {
    if mentions_path(&read_env_file(file)?) {
        return None;
    }
    let path = path?;
    // Keep the inherited PATH if it cannot be written as Unicode without loss.
    path.to_str()?;
    let conv = |p: &Path| {
        if cfg!(windows) {
            msys_path(p)
        } else {
            p.to_str().map(str::to_owned)
        }
    };
    let first = conv(dir)?;
    let mut rest = Vec::new();
    for e in std::env::split_paths(path) {
        if (cfg!(windows) && e.as_os_str().is_empty()) || same_shims_dir(&e, dir) {
            continue;
        }
        rest.push(conv(&e)?);
    }
    path_line(&first, &rest)
}

/// `C:\a b\x` -> `/c/a b/x`; `\\srv\s\x` -> `//srv/s/x`; `\\?\...` and `\\.\...` -> None.
pub fn msys_path(p: &Path) -> Option<String> {
    let s = p.to_str()?;
    if s.starts_with(r"\\?\") || s.starts_with(r"\\.\") || s.starts_with("//?/") {
        return None;
    }
    let b = s.as_bytes();
    if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
        let rest = s[2..].replace('\\', "/");
        let sep = if rest.is_empty() || rest.starts_with('/') {
            ""
        } else {
            "/" // `C:x` is relative to the drive's folder; keep it distinct from `C:\x`
        };
        return Some(format!("/{}{sep}{rest}", s[..1].to_ascii_lowercase()));
    }
    Some(s.replace('\\', "/"))
}

/// `export PATH='<first>:<rest...>'`, or None if any part has `'` or a control character.
pub fn path_line(first: &str, rest: &[String]) -> Option<String> {
    let all: Vec<&str> = std::iter::once(first)
        .chain(rest.iter().map(String::as_str))
        .collect();
    if all
        .iter()
        .any(|p| p.chars().any(|c| c == '\'' || c.is_control()))
    {
        return None;
    }
    Some(format!("export PATH='{}'", all.join(":")))
}

/// `export SYNC_GATE_SESSION=claude-<up to 8 of [A-Za-z0-9] from the id>`, None without any.
pub fn session_line(session_id: &str) -> Option<String> {
    let id: String = session_id
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(8)
        .collect();
    (!id.is_empty()).then(|| format!("export SYNC_GATE_SESSION=claude-{id}"))
}

/// The plain-assignment grammar of F21: blank, `# comment`, or
/// `[export |declare -x |typeset -x ]NAME=value` where the value is one bare word of safe
/// characters, one `'...'`, or one `"..."` whose only `$`, `` ` `` and `\` are escaped.
pub fn is_plain_assignment(line: &str) -> bool {
    if line.trim().is_empty() || line.starts_with('#') {
        return true;
    }
    let body = ["export ", "declare -x ", "typeset -x "]
        .iter()
        .find_map(|p| line.strip_prefix(p))
        .unwrap_or(line);
    let Some((name, value)) = body.split_once('=') else {
        return false;
    };
    let mut n = name.chars();
    if !n
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        || !n.all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return false;
    }
    if let Some(q) = value.strip_prefix('\'') {
        return q.strip_suffix('\'').is_some_and(|q| !q.contains('\''));
    }
    if let Some(q) = value.strip_prefix('"') {
        let Some(q) = q.strip_suffix('"') else {
            return false;
        };
        let mut it = q.chars();
        while let Some(c) = it.next() {
            match c {
                '"' | '$' | '`' => return false,
                '\\' if !matches!(it.next(), Some('\\' | '"' | '$' | '`')) => return false,
                _ => {}
            }
        }
        return true;
    }
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c))
}

/// True if the word `PATH` (`\bPATH\b`, case-sensitive) appears anywhere, comments included.
/// Over-detects on purpose: a false positive costs the shims, never someone else's PATH.
pub fn mentions_path(env_file_text: &str) -> bool {
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    env_file_text.match_indices("PATH").any(|(i, m)| {
        !env_file_text[..i].chars().next_back().is_some_and(word)
            && !env_file_text[i + m.len()..]
                .chars()
                .next()
                .is_some_and(word)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In ON and BASH, never in PREFIX.
    const MARKER: &str = "ahead of the shims folder on PATH for Bash";

    /// The hook's context (no env file) for PATH = `ahead`, then the shims folder, which holds an
    /// `npm` shim; `make` prepares `ahead` (or leaves it missing).
    fn context_with_ahead(tag: &str, make: impl FnOnce(&Path)) -> String {
        context_with_path(tag, |ahead, shims| {
            make(ahead);
            std::env::join_paths([ahead, shims]).unwrap()
        })
    }

    /// Like `context_with_ahead`, with the PATH that `path(ahead, shims)` returns.
    fn context_with_path(
        tag: &str,
        path: impl FnOnce(&Path, &Path) -> std::ffi::OsString,
    ) -> String {
        let root =
            std::env::temp_dir().join(format!("sync-gate-hook-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (shims, ahead) = (root.join("shims"), root.join("ahead"));
        std::fs::create_dir_all(&shims).unwrap();
        std::fs::write(shims.join(SHIMS_MANIFEST), "{}").unwrap();
        std::fs::write(
            shims.join(if cfg!(windows) { "npm.exe" } else { "npm" }),
            "",
        )
        .unwrap();
        let path = path(&ahead, &shims);
        let (out, lines) = session_start_with(&HookInput {
            stdin: None,
            env_file: None,
            shims: Some(&shims),
            path: Some(&path),
            session_set: true,
        });
        // A folder left unreadable is removed by its test.
        let _ = std::fs::remove_dir_all(&root);
        assert!(lines.is_empty(), "{lines:?}");
        out
    }

    #[test]
    fn hook_shims_are_not_ahead_of_a_relative_folder() {
        let ctx = context_with_path("relative", |_, shims| {
            std::env::join_paths([Path::new("relative"), shims]).unwrap()
        });
        assert!(!ctx.contains(MARKER), "{ctx}");
    }

    #[test]
    fn hook_empty_path_entry_ahead_is_skipped_on_windows_and_the_current_folder_elsewhere() {
        let ctx = context_with_path("empty", |_, shims| {
            std::env::join_paths([Path::new(""), shims]).unwrap()
        });
        assert_eq!(ctx.contains(MARKER), cfg!(windows), "{ctx}");
    }

    #[test]
    fn hook_shims_are_not_ahead_when_their_folder_is_not_on_path() {
        let rg = if cfg!(windows) { "rg.exe" } else { "rg" };
        let ctx = context_with_path("absent", |ahead, _| {
            folder_with(ahead, rg);
            std::env::join_paths([ahead]).unwrap()
        });
        assert!(!ctx.contains(MARKER), "{ctx}");
    }

    fn folder_with(dir: &Path, file: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(file), "").unwrap();
    }

    #[test]
    fn hook_shims_count_as_ahead_behind_a_folder_without_their_commands() {
        let rg = if cfg!(windows) { "rg.exe" } else { "rg" };
        let ctx = context_with_ahead("harmless", |d| folder_with(d, rg));
        assert!(ctx.contains(MARKER), "{ctx}");
    }

    #[test]
    fn hook_shims_are_not_ahead_of_a_folder_with_one_of_their_commands() {
        // Windows: another case and another PATHEXT extension are still the same command.
        let npm = if cfg!(windows) { "NPM.cmd" } else { "npm" };
        let ctx = context_with_ahead("conflict", |d| folder_with(d, npm));
        assert!(!ctx.contains(MARKER), "{ctx}");
        assert!(ctx.contains("sync_gate run --"), "{ctx}");
    }

    #[test]
    fn hook_shims_count_as_ahead_behind_a_missing_folder() {
        let ctx = context_with_ahead("missing", |_| {});
        assert!(ctx.contains(MARKER), "{ctx}");
    }

    #[test]
    fn hook_shims_are_not_ahead_of_a_folder_that_cannot_be_listed() {
        let mut locked = None;
        let ctx = context_with_ahead("unreadable", |d| {
            folder_with(d, "rg");
            locked = Some(d.to_owned());
            deny_listing(d, true);
        });
        let d = locked.unwrap();
        let listed = std::fs::read_dir(&d).map(|_| ()).map_err(|e| e.kind());
        deny_listing(&d, false);
        std::fs::remove_dir_all(d.parent().unwrap()).unwrap();
        if listed.is_ok() {
            println!("skipped: this user can list any folder");
            return;
        }
        assert_ne!(listed, Err(std::io::ErrorKind::NotFound));
        assert!(!ctx.contains(MARKER), "{ctx}");
    }

    #[cfg(unix)]
    fn deny_listing(dir: &Path, deny: bool) {
        use std::os::unix::fs::PermissionsExt;
        let mode = if deny { 0o000 } else { 0o700 };
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(windows)]
    fn deny_listing(dir: &Path, deny: bool) {
        let user = std::env::var("USERNAME").unwrap();
        let rule = if deny {
            ["/deny".to_owned(), format!("{user}:(RD)")]
        } else {
            ["/remove:d".to_owned(), user]
        };
        let ok = std::process::Command::new("icacls")
            .arg(dir)
            .args(rule)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap()
            .success();
        assert!(ok, "icacls {}", dir.display());
    }

    #[test]
    fn msys_path_converts_drive_and_unc_paths_only() {
        let m = |s: &str| msys_path(Path::new(s));
        assert_eq!(m(r"C:\a b\x").as_deref(), Some("/c/a b/x"));
        assert_eq!(m(r"d:\").as_deref(), Some("/d/"));
        assert_eq!(m(r"\\srv\s\x").as_deref(), Some("//srv/s/x"));
        assert_eq!(m(r"\\?\C:\x"), None);
        assert_eq!(m(r"\\.\pipe\x"), None);
    }

    #[test]
    fn path_line_is_a_plain_assignment_or_nothing() {
        let l = path_line("/s", &["/a b".into(), "/c".into()]).unwrap();
        assert_eq!(l, "export PATH='/s:/a b:/c'");
        assert!(is_plain_assignment(&l));
        assert_eq!(path_line("/s", &["/it's".into()]), None);
        assert_eq!(path_line("/s", &["/a\nb".into()]), None);
    }

    #[test]
    fn session_line_is_plain_and_short() {
        let l = session_line("abc-123_def456").unwrap();
        assert_eq!(l, "export SYNC_GATE_SESSION=claude-abc123de");
        assert!(is_plain_assignment(&l));
        assert_eq!(session_line("--__"), None);
    }

    #[test]
    fn is_plain_assignment_follows_the_documented_grammar() {
        for ok in ["export A=x", "declare -x A='x y'", r#"A="a\$b""#, "", "# c"] {
            assert!(is_plain_assignment(ok), "{ok}");
        }
        for bad in [
            r#"export PATH="$PATH:x""#,
            "source x",
            "A=$'x'",
            "A=$(x)",
            "A='x'y",
        ] {
            assert!(!is_plain_assignment(bad), "{bad}");
        }
    }

    #[test]
    fn windows_path_line_keeps_every_entry_in_order() {
        let rest: Vec<String> = [
            r"C:\Windows\System32",
            r"C:\Program Files\Git\cmd",
            r"\\srv\s",
        ]
        .iter()
        .map(|s| msys_path(Path::new(s)).unwrap())
        .collect();
        assert_eq!(
            path_line("/c/fg/shims", &rest).unwrap(),
            "export PATH='/c/fg/shims:/c/Windows/System32:/c/Program Files/Git/cmd://srv/s'"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_shims_identity_ignores_unavailable_file_ids() {
        let valid = (7, [1; 16]);
        for unavailable in [(7, [0; 16]), (7, [0xff; 16])] {
            assert_eq!(same_shims_identity(unavailable, unavailable), None);
            assert_eq!(same_shims_identity(unavailable, valid), None);
            assert_eq!(same_shims_identity(valid, unavailable), None);
        }
        assert_eq!(same_shims_identity(valid, valid), Some(true));
        assert_eq!(same_shims_identity(valid, (7, [2; 16])), Some(false));
        assert_eq!(same_shims_identity(valid, (8, [1; 16])), Some(false));
    }

    #[cfg(windows)]
    #[test]
    fn windows_path_preserves_distinct_directories_and_leaves_invalid_utf16_unedited() {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;

        let root = std::env::temp_dir().join(format!("sync-gate-hook-path-{}", std::process::id()));
        let file = root.join("env.sh");
        let machine = root.join("machine");
        let [
            (shims, other, ctx, lines),
            (_, _, invalid_ctx, invalid_lines),
        ] = [
            ("u-\u{130}", OsString::from("u-i\u{307}")),
            ("\u{fffd}", OsString::from_wide(&[0xd800])),
        ]
        .map(|(official, other)| {
            let shims = root.join(official).join("shims");
            let other = root.join(other).join("shims");
            std::fs::create_dir_all(&shims).unwrap();
            std::fs::create_dir_all(&other).unwrap();
            std::fs::write(shims.join(SHIMS_MANIFEST), "{}").unwrap();
            // `other` holds a command the shims cover, so the shims are not ahead of it.
            std::fs::write(shims.join("npm.exe"), "").unwrap();
            std::fs::write(other.join("npm.cmd"), "").unwrap();
            let path = std::env::join_paths([&machine, &other, &shims]).unwrap();
            let (ctx, lines) = session_start_with(&HookInput {
                stdin: Some(r#"{"session_id":"abc123def456"}"#),
                env_file: Some(&file),
                shims: Some(&shims),
                path: Some(&path),
                session_set: false,
            });
            (shims, other, ctx, lines)
        });
        std::fs::remove_dir_all(&root).unwrap();

        assert!(ctx.contains(MARKER), "{ctx}");
        assert_eq!(
            lines[0],
            format!(
                "export PATH='{}:{}:{}'",
                msys_path(&shims).unwrap(),
                msys_path(&machine).unwrap(),
                msys_path(&other).unwrap()
            ),
        );
        assert!(!invalid_ctx.contains(MARKER), "{invalid_ctx}");
        assert_eq!(invalid_lines, ["export SYNC_GATE_SESSION=claude-abc123de"]);
    }

    #[test]
    fn mentions_path_sees_the_word_in_any_form() {
        for yes in [
            "PATH=x",
            "export PATH=x",
            "declare -x PATH='x'",
            "  PATH+=:x",
            "A=1; PATH=x",
            "export \"PATH=/v\"",
            "PATH[0]=x",
            "echo $PATH",
            "# PATH",
        ] {
            assert!(mentions_path(yes), "{yes}");
        }
        for no in ["MYPATH=x", "export PATHX=1", "path=x", "echo _PATH_", ""] {
            assert!(!mentions_path(no), "{no}");
        }
    }
}
