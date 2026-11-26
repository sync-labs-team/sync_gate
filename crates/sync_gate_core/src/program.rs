//! Finding the program of a command the way `cmd.exe` (Windows) or `execvp` (elsewhere) does.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// File that marks a folder of sync_gate shims; such a folder is never searched for a real program.
pub const SHIMS_MANIFEST: &str = "sync_gate_shims.json";

fn is_shims_dir(dir: &Path) -> bool {
    dir.join(SHIMS_MANIFEST).exists()
}

/// `name` (no separator) through `path`, skipping every folder that holds [`SHIMS_MANIFEST`].
/// Windows: absolute entries only, in `PATHEXT` order (a name that already has one of its
/// extensions is searched as it is). Unix: every entry, an empty or relative one
/// taken from `cwd` (as `execvp` does; no implicit "."), a regular file the effective user can
/// execute (one it cannot is skipped, as `execvp` does after `EACCES`). `path` of `None` searches
/// [`UNIX_DEFAULT_PATH`]; `Some("")` stays "the current directory only".
/// The result is absolute.
/// What `execvp` searches when `PATH` is not set at all (`confstr(_CS_PATH)`; `nix` has no
/// `confstr`, so a constant per libc: glibc `/bin:/usr/bin`, Apple `_PATH_DEFPATH` `/usr/bin:/bin`).
/// shortcut: another Unix with a different default is not covered.
#[cfg(all(unix, not(target_vendor = "apple")))]
const UNIX_DEFAULT_PATH: &str = "/bin:/usr/bin";
#[cfg(target_vendor = "apple")]
const UNIX_DEFAULT_PATH: &str = "/usr/bin:/bin";

/// Effective uid/gid may execute `file` (`faccessat` + `AT_EACCESS`): owner, group, ACLs, `noexec`.
#[cfg(unix)]
fn can_execute(file: &Path) -> bool {
    use nix::fcntl::{AT_FDCWD, AtFlags};
    use nix::unistd::{AccessFlags, faccessat};
    faccessat(AT_FDCWD, file, AccessFlags::X_OK, AtFlags::AT_EACCESS).is_ok()
}

pub fn find_program(
    name: &OsStr,
    path: Option<&OsStr>,
    pathext: Option<&OsStr>,
    cwd: &Path,
) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        let _ = cwd;
        // A `.ps1` is never an executable target, whatever PATHEXT says: CreateProcess cannot run it.
        let exts: Vec<String> = crate::config::pathext_list(pathext)
            .into_iter()
            .filter(|e| !e.eq_ignore_ascii_case(".ps1"))
            .collect();
        // A name that already ends in a PATHEXT extension is that exact file (as `cmd.exe` and
        // CreateProcess do): `tool.exe` is never `tool.exe.cmd`.
        let has_ext = Path::new(name)
            .extension()
            .and_then(OsStr::to_str)
            .is_some_and(|x| exts.iter().any(|e| e[1..].eq_ignore_ascii_case(x)));
        for dir in absolute_dirs(path) {
            if has_ext {
                let file = dir.join(name);
                if file.is_file() {
                    return Some(file);
                }
                continue;
            }
            for ext in &exts {
                let mut file_name = name.to_os_string();
                file_name.push(ext);
                let file = dir.join(file_name);
                if file.is_file() {
                    return Some(file);
                }
            }
        }
        None
    }
    #[cfg(unix)]
    {
        let _ = pathext;
        let path = path.unwrap_or(OsStr::new(UNIX_DEFAULT_PATH));
        for dir in std::env::split_paths(path) {
            let dir = if dir.as_os_str().is_empty() {
                cwd.to_path_buf()
            } else {
                cwd.join(dir) // an absolute entry replaces the cwd
            };
            if is_shims_dir(&dir) {
                continue;
            }
            let file = dir.join(name);
            if file.metadata().is_ok_and(|m| m.is_file()) && can_execute(&file) {
                return Some(file);
            }
        }
        None
    }
}

/// The absolute, non-shim entries of `path`. A relative entry (empty, `.`, `C:foo`) would run a
/// file planted in the cwd.
fn absolute_dirs(path: Option<&OsStr>) -> impl Iterator<Item = PathBuf> {
    std::env::split_paths(path.unwrap_or_default()).filter(|d| d.is_absolute() && !is_shims_dir(d))
}

/// Windows: `<name>.ps1` in the first absolute entry that has it (manifest folders skipped).
pub fn find_ps1(name: &OsStr, path: Option<&OsStr>) -> Option<PathBuf> {
    let mut file_name = name.to_os_string();
    file_name.push(".ps1");
    absolute_dirs(path)
        .map(|d| d.join(&file_name))
        .find(|f| f.is_file())
}

/// Windows: `name` looked up through `PATH` and `PATHEXT` (the current directory is not
/// searched), so `npm` finds `npm.cmd`, which `Command` alone cannot. A name with a separator, a
/// drive or an extension of `PATHEXT`, and a name found nowhere, come back unchanged. Elsewhere
/// the name always does. Folders of sync_gate shims are skipped.
pub fn resolve_program(name: &str, path: Option<&OsStr>, pathext: Option<&OsStr>) -> PathBuf {
    #[cfg(windows)]
    {
        let exts = crate::config::pathext_list(pathext);
        let has_ext = Path::new(name)
            .extension()
            .and_then(OsStr::to_str)
            .is_some_and(|x| exts.iter().any(|e| e[1..].eq_ignore_ascii_case(x)));
        if !(has_ext || name.contains(['/', '\\', ':'])) {
            if let Some(file) = find_program(OsStr::new(name), path, pathext, Path::new("")) {
                return file;
            }
        }
    }
    #[cfg(not(windows))]
    let _ = (path, pathext);
    PathBuf::from(name)
}

/// [`resolve_program`] with this process's own `PATH` and `PATHEXT`, which the child inherits.
pub fn resolve_in_env(name: &str) -> PathBuf {
    resolve_program(
        name,
        std::env::var_os("PATH").as_deref(),
        std::env::var_os("PATHEXT").as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sync_gate-prog-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The extension keeps the case `PATHEXT` wrote; the file system does not care.
    #[cfg(windows)]
    fn same(a: PathBuf, b: PathBuf) {
        assert_eq!(
            a.to_string_lossy().to_lowercase(),
            b.to_string_lossy().to_lowercase()
        );
    }

    fn os(s: &str) -> OsString {
        s.into()
    }

    #[cfg(windows)]
    #[test]
    fn finds_a_cmd_shim_through_pathext() {
        let d = dir("shim");
        std::fs::write(d.join("npmx.cmd"), "").unwrap();
        let got = resolve_program(
            "npmx",
            Some(d.as_os_str()),
            Some(&os(".COM;.EXE;.BAT;.CMD")),
        );
        same(got, d.join("npmx.cmd"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(windows)]
    #[test]
    fn a_name_with_a_pathext_extension_is_searched_exactly() {
        let d = dir("exact");
        std::fs::write(d.join("tool.exe"), "").unwrap();
        std::fs::write(d.join("tool.exe.cmd"), "").unwrap();
        let ext = os(".COM;.EXE;.BAT;.CMD");
        for name in ["tool.exe", "TOOL.EXE"] {
            let got = find_program(&os(name), Some(d.as_os_str()), Some(&ext), &d);
            same(got.unwrap(), d.join("tool.exe"));
        }
        // Only the longer file exists: the name asked for is not there.
        std::fs::remove_file(d.join("tool.exe")).unwrap();
        assert_eq!(
            find_program(&os("tool.exe"), Some(d.as_os_str()), Some(&ext), &d),
            None
        );
        // No extension of PATHEXT: still extended (`tool.v2` is a name, not an extension).
        std::fs::write(d.join("tool.v2.cmd"), "").unwrap();
        let got = find_program(&os("tool.v2"), Some(d.as_os_str()), Some(&ext), &d);
        same(got.unwrap(), d.join("tool.v2.cmd"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(windows)]
    #[test]
    fn pathext_order_wins() {
        let d = dir("order");
        std::fs::write(d.join("x.bat"), "").unwrap();
        std::fs::write(d.join("x.cmd"), "").unwrap();
        let got = resolve_program("x", Some(d.as_os_str()), Some(&os(".CMD;.BAT")));
        same(got, d.join("x.cmd"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(windows)]
    #[test]
    fn a_name_with_a_path_or_extension_is_unchanged() {
        // Each name has a candidate that would be found if its guard were removed.
        let d = dir("same");
        std::fs::create_dir_all(d.join("sub")).unwrap();
        for f in ["sub\\x.cmd", "x.CMD.CMD", "x.exe.cmd"] {
            std::fs::write(d.join(f), "").unwrap();
        }
        // "C:x" has no candidate: a Windows file name cannot contain `:`, so its guard cannot be proven.
        for name in ["sub\\x", "sub/x", "C:x", "x.CMD", "x.exe"] {
            let got = resolve_program(name, Some(d.as_os_str()), Some(&os(".CMD;.EXE")));
            assert_eq!(got, PathBuf::from(name), "{name}");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Removes only what the test created: the planted files, then the (empty) folder.
    #[cfg(windows)]
    struct Planted(Vec<PathBuf>, PathBuf);

    #[cfg(windows)]
    impl Drop for Planted {
        fn drop(&mut self) {
            for f in &self.0 {
                let _ = std::fs::remove_file(f);
            }
            let _ = std::fs::remove_dir(&self.1);
        }
    }

    #[cfg(windows)]
    #[test]
    fn relative_path_entries_are_skipped() {
        let base = dir("rel");
        let trusted = base.join("trusted");
        std::fs::create_dir_all(&trusted).unwrap();
        // Planted where a relative entry points: the cwd, a subfolder of it, a drive-relative
        // path. Names unique to this run, created with `create_new`, so nothing of anyone's
        // is overwritten or removed.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let id = format!("{}{nanos}", std::process::id());
        let (name, folder) = (format!("fgz{id}"), format!("fgrel-{id}"));
        std::fs::write(trusted.join(format!("{name}.cmd")), "").unwrap();
        let cwd = std::env::current_dir().unwrap();
        let sub = cwd.join(&folder);
        std::fs::create_dir(&sub).unwrap();
        let mut planted = Planted(Vec::new(), sub.clone());
        for f in [
            cwd.join(format!("{name}.cmd")),
            sub.join(format!("{name}.cmd")),
        ] {
            let mut open = std::fs::OpenOptions::new();
            open.write(true).create_new(true).open(&f).unwrap();
            planted.0.push(f);
        }
        let drive_rel = format!("{}{folder}", &cwd.to_string_lossy()[..2]);
        for rel in ["", ".", folder.as_str(), drive_rel.as_str()] {
            let path = std::env::join_paths([os(rel), trusted.clone().into()]).unwrap();
            let got = resolve_program(&name, Some(&path), Some(&os(".CMD")));
            same(got, trusted.join(format!("{name}.cmd")));
        }
        drop(planted);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(windows)]
    #[test]
    fn nothing_found_returns_the_name() {
        let d = dir("none");
        let got = resolve_program("nope", Some(d.as_os_str()), None);
        assert_eq!(got, PathBuf::from("nope"));
        assert_eq!(resolve_program("nope", None, None), PathBuf::from("nope"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(windows)]
    #[test]
    fn default_pathext_when_unset() {
        let d = dir("default");
        std::fs::write(d.join("y.cmd"), "").unwrap();
        for unset in [None, Some(os(""))] {
            let got = resolve_program("y", Some(d.as_os_str()), unset.as_deref());
            same(got, d.join("y.cmd"));
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(windows)]
    #[test]
    fn find_program_skips_a_folder_with_the_shims_manifest() {
        let d = dir("skipman");
        let (shims, real) = (d.join("shims"), d.join("real"));
        std::fs::create_dir_all(&shims).unwrap();
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(shims.join("x.exe"), "").unwrap();
        std::fs::write(shims.join(SHIMS_MANIFEST), "{}").unwrap();
        std::fs::write(real.join("x.cmd"), "").unwrap();
        let path = std::env::join_paths([&shims, &real]).unwrap();
        let got = find_program(&os("x"), Some(&path), Some(&os(".EXE;.CMD")), &d);
        same(got.unwrap(), real.join("x.cmd"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(windows)]
    #[test]
    fn find_program_is_none_when_only_a_ps1_exists_and_find_ps1_finds_it() {
        let d = dir("ps1");
        std::fs::write(d.join("tool.ps1"), "").unwrap();
        let none = find_program(&os("tool"), Some(d.as_os_str()), None, &d);
        assert_eq!(none, None);
        same(
            find_ps1(&os("tool"), Some(d.as_os_str())).unwrap(),
            d.join("tool.ps1"),
        );
        assert_eq!(find_ps1(&os("other"), Some(d.as_os_str())), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(windows)]
    #[test]
    fn find_program_never_returns_a_ps1_even_if_pathext_lists_it() {
        let d = dir("ps1ext");
        let ext = os(".PS1;.EXE;.CMD;.BAT");
        std::fs::write(d.join("tool.ps1"), "").unwrap();
        assert_eq!(
            find_program(&os("tool"), Some(d.as_os_str()), Some(&ext), &d),
            None
        );
        std::fs::write(d.join("tool.cmd"), "").unwrap();
        let got = find_program(&os("tool"), Some(d.as_os_str()), Some(&ext), &d).unwrap();
        same(got, d.join("tool.cmd"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(windows)]
    #[test]
    fn resolve_program_skips_a_shims_folder_too() {
        let d = dir("resskip");
        let (shims, real) = (d.join("shims"), d.join("real"));
        std::fs::create_dir_all(&shims).unwrap();
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(shims.join("x.cmd"), "").unwrap();
        std::fs::write(shims.join(SHIMS_MANIFEST), "{}").unwrap();
        std::fs::write(real.join("x.bat"), "").unwrap();
        let path = std::env::join_paths([&shims, &real]).unwrap();
        let got = resolve_program("x", Some(&path), Some(&os(".CMD;.BAT")));
        same(got, real.join("x.bat"));
        let only = resolve_program("x", Some(shims.as_os_str()), Some(&os(".CMD")));
        assert_eq!(only, PathBuf::from("x"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    fn exe(path: &std::path::Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, "").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn find_program_unix_relative_and_empty_entries_come_from_cwd() {
        let d = dir("unixrel");
        std::fs::create_dir_all(d.join("node_modules/.bin")).unwrap();
        exe(&d.join("node_modules/.bin/viabin"), 0o755);
        exe(&d.join("viacwd"), 0o755);
        let path = os("node_modules/.bin::/usr/bin");
        let got = find_program(&os("viabin"), Some(&path), None, &d);
        assert_eq!(got, Some(d.join("node_modules/.bin/viabin")));
        let got = find_program(&os("viacwd"), Some(&path), None, &d);
        assert_eq!(got, Some(d.join("viacwd")));
        assert!(got.unwrap().is_absolute());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn find_program_unix_skips_non_executables_and_manifest_folders() {
        let d = dir("unixskip");
        let (plain, shims, real) = (d.join("plain"), d.join("shims"), d.join("real"));
        for f in [&plain, &shims, &real] {
            std::fs::create_dir_all(f).unwrap();
        }
        exe(&plain.join("x"), 0o644);
        std::fs::create_dir_all(d.join("dirfirst/x")).unwrap();
        exe(&shims.join("x"), 0o755);
        exe(&shims.join(SHIMS_MANIFEST), 0o644);
        exe(&real.join("x"), 0o755);
        let path = std::env::join_paths([d.join("dirfirst"), plain, shims, real.clone()]).unwrap();
        let got = find_program(&os("x"), Some(&path), None, &d);
        assert_eq!(got, Some(real.join("x")));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn find_program_unix_none_without_a_candidate() {
        let d = dir("unixnone");
        assert_eq!(
            find_program(&os("nope"), Some(d.as_os_str()), None, &d),
            None
        );
        assert_eq!(find_program(&os("nope"), None, None, &d), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn find_program_unix_unset_path_uses_the_default_but_empty_path_does_not() {
        let d = dir("unixdefault");
        let got = find_program(&os("sh"), None, None, &d).unwrap();
        assert!(got.is_absolute() && got.ends_with("sh"), "{got:?}");
        assert_eq!(find_program(&os("sh"), Some(&os("")), None, &d), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn find_program_unix_skips_a_candidate_the_user_cannot_execute() {
        let d = dir("unixeacces");
        let (a, b) = (d.join("a"), d.join("b"));
        for f in [&a, &b] {
            std::fs::create_dir_all(f).unwrap();
        }
        exe(&a.join("x"), 0o610); // exec bit for the group only; the owner (us) is denied
        exe(&b.join("x"), 0o755);
        let path = std::env::join_paths([a, b.clone()]).unwrap();
        // run as non-root: root ignores permission bits
        assert_eq!(
            find_program(&os("x"), Some(&path), None, &d),
            Some(b.join("x"))
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
