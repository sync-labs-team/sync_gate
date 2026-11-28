//! Private-folder checks: who owns a folder, who can write to it and to its ancestors.
//! Unix: only the owner (or root) can swap an entry of a folder they alone can write to, so a
//! folder that passes `check_private_dir` cannot be replaced by another user (`inode(7)`,
//! `rename(3p)`). Windows: the same rules in owners and DACLs (`private_dir/win.rs`), for folders
//! and for each file read.
#[cfg(unix)]
use nix::unistd::{getegid, geteuid};
#[cfg(unix)]
use std::collections::VecDeque;
#[cfg(unix)]
use std::fs::Metadata;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::Path;
#[cfg(unix)]
use std::path::{Component, PathBuf};

#[cfg(windows)]
mod win;
#[cfg(windows)]
pub use win::{check_private_dir, check_private_file, create_private_dir, open_private_file};

#[cfg(unix)]
const STICKY: u32 = 0o1000;

/// What `check_private_dir` found, when the folder is safe to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirState {
    Missing,
    Private,
    /// Ours and only we can write, but group or others can still read or list it.
    OthersCanRead,
}

/// A refusal by the rules of this module, told apart from an error of the system by `is_refusal`
/// (it has no OS error code and the kind alone does not say it).
#[derive(Debug)]
struct Refused(String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

/// An error that `is_refusal` recognises.
pub fn refusal(kind: io::ErrorKind, msg: String) -> io::Error {
    io::Error::new(kind, Refused(msg))
}

/// True for what a rule refused (link, kind, owner, who can write, path), false for an error of
/// the system (a file in use, a failed read), which may pass on a retry.
pub fn is_refusal(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|i| i.is::<Refused>())
}

fn deny(path: &Path, why: &str) -> io::Error {
    refusal(
        io::ErrorKind::PermissionDenied,
        format!("{} {why}", path.display()),
    )
}

/// `IsReparseTagNameSurrogate`: the tag's bit 0x20000000 (symlink, mount point/junction...).
pub fn is_name_surrogate(tag: u32) -> bool {
    tag & 0x2000_0000 != 0
}

/// Windows: (attributes, reparse tag) of an open handle.
#[cfg(windows)]
pub fn tag_info(f: &std::fs::File) -> Option<(u32, u32)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_TAG_INFO, FileAttributeTagInfo, GetFileInformationByHandleEx,
    };
    let mut i = FILE_ATTRIBUTE_TAG_INFO {
        FileAttributes: 0,
        ReparseTag: 0,
    };
    // SAFETY: a valid handle and a buffer of the size passed.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            f.as_raw_handle() as _,
            FileAttributeTagInfo,
            (&raw mut i).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    };
    (ok != 0).then_some((i.FileAttributes, i.ReparseTag))
}

/// An ancestor must not let another user replace what is under it.
#[cfg(unix)]
fn ancestor_ok(m: &Metadata) -> bool {
    let (euid, egid) = (geteuid().as_raw(), getegid().as_raw());
    let (mode, sticky) = (m.mode(), m.mode() & STICKY != 0);
    (m.uid() == 0 || m.uid() == euid)
        && !(m.is_dir() && mode & 0o002 != 0 && !sticky)
        && !(m.is_dir() && mode & 0o020 != 0 && !sticky && m.gid() != egid)
}

/// Walks `dir` component by component the way the kernel does, checking every folder or link
/// entry it goes through (each link expansion included) except the last one, which is returned
/// unfollowed (`None` when it does not exist). A trailing slash cannot make us follow a final link.
#[cfg(unix)]
fn walk(dir: &Path) -> io::Result<Option<Metadata>> {
    let mut queue = VecDeque::new();
    for c in dir.components() {
        match c {
            Component::Normal(n) => queue.push_back((n.to_owned(), false)),
            Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{} has a parent-folder component", dir.display()),
                ));
            }
            _ => {}
        }
    }
    let Some(last) = queue.back_mut() else {
        return Path::new("/").symlink_metadata().map(Some);
    };
    last.1 = true;
    let (mut cur, mut hops) = (PathBuf::from("/"), 0);
    while let Some((name, is_last)) = queue.pop_front() {
        if name == ".." {
            cur.pop();
            continue;
        }
        let next = cur.join(&name);
        let m = match next.symlink_metadata() {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        if is_last {
            return Ok(Some(m));
        }
        if !ancestor_ok(&m) {
            return Err(deny(
                dir,
                &format!(
                    "sits in a folder other users can change: {}",
                    next.display()
                ),
            ));
        }
        if m.file_type().is_symlink() {
            hops += 1;
            if hops > 40 {
                return Err(deny(dir, "has too many links"));
            }
            let target = std::fs::read_link(&next)?;
            if target.is_absolute() {
                cur = PathBuf::from("/");
            }
            let parts: Vec<_> = target
                .components()
                .filter(|c| matches!(c, Component::Normal(_) | Component::ParentDir))
                .collect();
            for c in parts.into_iter().rev() {
                queue.push_front((c.as_os_str().to_owned(), false));
            }
        } else {
            cur = next;
        }
    }
    Ok(None)
}

/// Checks that `dir` (absolute) is a folder only this user can change, with ancestors nobody
/// else can change either. `Missing` is not an error: the caller creates it.
#[cfg(unix)]
pub fn check_private_dir(dir: &Path) -> io::Result<DirState> {
    if !dir.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not an absolute path", dir.display()),
        ));
    }
    let Some(m) = walk(dir)? else {
        return Ok(DirState::Missing);
    };
    if m.file_type().is_symlink() {
        return Err(deny(dir, "is a link"));
    }
    if !m.is_dir() {
        return Err(deny(dir, "is not a folder"));
    }
    if m.uid() != geteuid().as_raw() {
        return Err(deny(dir, "is owned by another user"));
    }
    if m.mode() & 0o022 != 0 {
        return Err(deny(
            dir,
            "is writable by other users (check its files, then chmod 700 it)",
        ));
    }
    Ok(if m.mode() & 0o077 != 0 {
        DirState::OthersCanRead
    } else {
        DirState::Private
    })
}

/// Checks a regular file of ours that nobody else can write or re-link. Its folder is the
/// caller's job (it already passed `check_private_dir`).
#[cfg(unix)]
pub fn check_private_file(path: &Path) -> io::Result<()> {
    let m = path.symlink_metadata()?;
    if m.file_type().is_symlink() {
        return Err(deny(path, "is a link"));
    }
    if !m.is_file() {
        return Err(deny(path, "is not a file"));
    }
    if m.uid() != geteuid().as_raw() {
        return Err(deny(path, "is owned by another user"));
    }
    if m.mode() & 0o022 != 0 {
        return Err(deny(path, "is writable by other users (chmod 600 it)"));
    }
    if m.nlink() != 1 {
        return Err(deny(path, "has more than one link"));
    }
    Ok(())
}

/// Opens a regular file of ours that nobody else can write or re-link, without following a final
/// link, and checks it on the opened descriptor: what is read is what was checked, whatever
/// happens to the path afterwards. `NotFound` when absent. The folder is the caller's job.
#[cfg(unix)]
pub fn open_private_file(path: &Path) -> io::Result<std::fs::File> {
    use nix::fcntl::{OFlag, open};
    // O_NONBLOCK: opening a FIFO must not wait for a writer; a regular file reads the same.
    let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK;
    let fd = open(path, flags, nix::sys::stat::Mode::empty()).map_err(|e| match e {
        nix::errno::Errno::ELOOP => deny(path, "is a link"),
        e => io::Error::from(e),
    })?;
    let file = std::fs::File::from(fd);
    let m = file.metadata()?;
    if !m.is_file() {
        return Err(deny(path, "is not a file"));
    }
    if m.uid() != geteuid().as_raw() {
        return Err(deny(path, "is owned by another user"));
    }
    if m.mode() & 0o022 != 0 {
        return Err(deny(path, "is writable by other users (chmod 600 it)"));
    }
    if m.nlink() != 1 {
        return Err(deny(path, "has more than one link"));
    }
    Ok(file)
}

/// A scratch folder for tests, removed on drop.
#[cfg(all(test, unix))]
pub(crate) struct Scratch(pub PathBuf);

#[cfg(all(test, unix))]
impl Scratch {
    pub fn new(tag: &str) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("fg-pd-{}-{tag}-{n}", std::process::id()));
        std::fs::create_dir(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self(p.canonicalize().unwrap())
    }
    /// A new folder under the scratch one with exactly `mode`.
    pub fn dir(&self, name: &str, mode: u32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = self.0.join(name);
        std::fs::create_dir(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    }
}

#[cfg(all(test, unix))]
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn err_text(r: io::Result<DirState>) -> String {
        let e = r.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        e.to_string()
    }

    fn chmod(p: &Path, mode: u32) {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn private_dir_rules() {
        let s = Scratch::new("rules");
        assert_eq!(
            check_private_dir(&s.dir("a", 0o700)).unwrap(),
            DirState::Private
        );
        assert_eq!(
            check_private_dir(&s.dir("b", 0o755)).unwrap(),
            DirState::OthersCanRead
        );
        assert_eq!(
            check_private_dir(&s.0.join("nope")).unwrap(),
            DirState::Missing
        );
        for (n, m) in [("c", 0o770), ("d", 0o775), ("e", 0o777)] {
            let t = err_text(check_private_dir(&s.dir(n, m)));
            assert!(t.contains("writable by other users"), "{t}");
        }
        let target = s.dir("t", 0o700);
        symlink(&target, s.0.join("lnk")).unwrap();
        let t = err_text(check_private_dir(&s.0.join("lnk")));
        assert!(t.contains("is a link"), "{t}");
        std::fs::write(s.0.join("f"), b"x").unwrap();
        let t = err_text(check_private_dir(&s.0.join("f")));
        assert!(t.contains("is not a folder"), "{t}");
        let e = check_private_dir(Path::new("rel")).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn private_dir_ancestors() {
        let s = Scratch::new("anc");
        let open = s.dir("open", 0o777);
        let child = open.join("c");
        std::fs::create_dir(&child).unwrap();
        chmod(&child, 0o700);
        let t = err_text(check_private_dir(&child));
        assert!(t.contains("other users can change"), "{t}");
        // Same for a path that does not exist yet.
        let t = err_text(check_private_dir(&open.join("later")));
        assert!(t.contains("other users can change"), "{t}");

        for (name, mode) in [("sticky", 0o1777), ("group", 0o770)] {
            let base = s.dir(name, mode);
            let child = base.join("c");
            std::fs::create_dir(&child).unwrap();
            chmod(&child, 0o700);
            assert_eq!(
                check_private_dir(&child).unwrap(),
                DirState::Private,
                "{name}"
            );
        }

        // A link into an unsafe folder is checked where it really lives.
        symlink(&open, s.0.join("via")).unwrap();
        let t = err_text(check_private_dir(&s.0.join("via").join("c")));
        assert!(t.contains("other users can change"), "{t}");
    }

    #[test]
    fn private_dir_checks_every_link_expansion() {
        let s = Scratch::new("hop");
        let open = s.dir("open", 0o777);
        let safe = s.dir("safe", 0o700);
        std::fs::create_dir(safe.join("c")).unwrap();
        chmod(&safe.join("c"), 0o700);
        // lnk -> open/bridge -> safe: only the hops show that `open` can be changed by others.
        symlink(&safe, open.join("bridge")).unwrap();
        symlink(open.join("bridge"), s.0.join("lnk")).unwrap();
        let t = err_text(check_private_dir(&s.0.join("lnk").join("c")));
        assert!(t.contains("other users can change"), "{t}");
        // Control: a chain of links through safe folders is fine.
        symlink(&safe, s.0.join("ok")).unwrap();
        symlink(s.0.join("ok"), s.0.join("ok2")).unwrap();
        assert_eq!(
            check_private_dir(&s.0.join("ok2").join("c")).unwrap(),
            DirState::Private
        );
    }

    #[test]
    fn a_final_link_is_refused_with_or_without_a_trailing_slash() {
        let s = Scratch::new("slash");
        let safe = s.dir("safe", 0o700);
        symlink(&safe, s.0.join("lnk")).unwrap();
        let lnk = s.0.join("lnk");
        for p in [lnk.clone(), PathBuf::from(format!("{}/", lnk.display()))] {
            let t = err_text(check_private_dir(&p));
            assert!(t.contains("is a link"), "{p:?}: {t}");
        }
        let with_slash = PathBuf::from(format!("{}/", safe.display()));
        assert_eq!(check_private_dir(&with_slash).unwrap(), DirState::Private);
    }

    #[test]
    fn open_private_file_rules() {
        use std::io::Read;
        let s = Scratch::new("openfile");
        let f = s.0.join("f");
        std::fs::write(&f, b"x").unwrap();
        chmod(&f, 0o600);
        let mut t = String::new();
        open_private_file(&f)
            .unwrap()
            .read_to_string(&mut t)
            .unwrap();
        assert_eq!(t, "x");
        assert_eq!(
            open_private_file(&s.0.join("absent")).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        let text = |p: &Path| err_text(open_private_file(p).map(|_| DirState::Private));
        symlink(&f, s.0.join("l")).unwrap();
        assert!(text(&s.0.join("l")).contains("is a link"));
        assert!(text(&s.0).contains("is not a file"));
        let fifo = nix::sys::stat::Mode::from_bits_truncate(0o600);
        nix::unistd::mkfifo(&s.0.join("p"), fifo).unwrap();
        assert!(text(&s.0.join("p")).contains("is not a file"));
        std::fs::hard_link(&f, s.0.join("g")).unwrap();
        assert!(text(&f).contains("more than one link"));
        std::fs::remove_file(s.0.join("g")).unwrap();
        chmod(&f, 0o620);
        assert!(text(&f).contains("writable"));
    }

    #[test]
    fn private_file_rules() {
        let s = Scratch::new("file");
        let f = s.0.join("f");
        std::fs::write(&f, b"x").unwrap();
        chmod(&f, 0o600);
        check_private_file(&f).unwrap();
        chmod(&f, 0o666);
        assert!(
            check_private_file(&f)
                .unwrap_err()
                .to_string()
                .contains("writable")
        );
        chmod(&f, 0o600);
        std::fs::hard_link(&f, s.0.join("g")).unwrap();
        let t = check_private_file(&f).unwrap_err().to_string();
        assert!(t.contains("more than one link"), "{t}");
        symlink(&f, s.0.join("l")).unwrap();
        let t = check_private_file(&s.0.join("l")).unwrap_err().to_string();
        assert!(t.contains("is a link"), "{t}");
        let t = check_private_file(&s.0).unwrap_err().to_string();
        assert!(t.contains("is not a file"), "{t}");
    }

    /// Needs root: `cargo test -p sync_gate_core -- --ignored xuser`.
    #[test]
    #[cfg(target_os = "linux")]
    #[ignore = "needs root"]
    fn xuser_private_dir_rules() {
        use std::os::unix::fs::{chown, lchown};
        assert_eq!(geteuid().as_raw(), 0, "run as root");
        let s = Scratch::new("xuser");
        let d = s.dir("d", 0o700);
        chown(&d, Some(65534), None).unwrap();
        assert!(err_text(check_private_dir(&d)).contains("owned by another user"));
        let f = s.0.join("f");
        std::fs::write(&f, b"x").unwrap();
        chmod(&f, 0o600);
        chown(&f, Some(65534), None).unwrap();
        let t = check_private_file(&f).unwrap_err().to_string();
        assert!(t.contains("owned by another user"), "{t}");

        let g = s.dir("g", 0o770);
        chown(&g, None, Some(65534)).unwrap();
        let child = g.join("c");
        std::fs::create_dir(&child).unwrap();
        chmod(&child, 0o700);
        assert!(err_text(check_private_dir(&child)).contains("other users can change"));

        let sticky = s.dir("sticky", 0o1777);
        let real = s.dir("real", 0o700);
        std::fs::create_dir(real.join("c")).unwrap();
        chmod(&real.join("c"), 0o700);
        let lnk = sticky.join("lnk");
        symlink(&real, &lnk).unwrap();
        // Positive control: the same link, still ours, is fine.
        assert_eq!(
            check_private_dir(&lnk.join("c")).unwrap(),
            DirState::Private
        );
        lchown(&lnk, Some(65534), None).unwrap();
        assert!(err_text(check_private_dir(&lnk.join("c"))).contains("other users can change"));
    }

    /// A record another user wrote (mode 0600, so only the owner check can refuse it) is
    /// untrusted. Needs root: `cargo test -p sync_gate_core -- --ignored xuser`.
    #[test]
    #[cfg(target_os = "linux")]
    #[ignore = "needs root"]
    fn xuser_a_file_of_another_user_is_untrusted() {
        use std::os::unix::fs::chown;
        assert_eq!(geteuid().as_raw(), 0, "run as root");
        let s = Scratch::new("xuser-file");
        let f = s.0.join("services.json");
        std::fs::write(&f, b"[]").unwrap();
        chmod(&f, 0o600);
        check_private_file(&f).unwrap();
        chown(&f, Some(65534), None).unwrap();
        let e = check_private_file(&f).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        assert!(e.to_string().contains("owned by another user"), "{e}");
    }
}
