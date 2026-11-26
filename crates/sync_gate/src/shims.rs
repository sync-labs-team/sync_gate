//! `sync_gate shims install|remove`: a private folder of PATH shims for the heavy programs.
//!
//! The folder holds code that runs from `PATH`, so sync_gate touches only what its manifest
//! lists and only while that file is still what sync_gate made (Windows: size and FNV-1a of the
//! content; Unix: a link to the recorded target). Anything else is left alone and reported.
//! Windows: one copy of the binary (`BASE`) plus a hard link per name. Unix: a symlink per name.

use serde::{Deserialize, Serialize};
use std::ffi::{OsStr, OsString};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use sync_gate_core::{HEAVY_PROGRAMS, SHIMS_MANIFEST, shims_dir};
use sync_gate_probe::{create_private_dir, write_atomic};

/// Windows: the one copy of the binary the hard links share (`sync_gate_shim.exe`).
pub const BASE: &str = "sync_gate_shim";

const CHANGED: &str = "changed by another program since sync_gate made it; kept";
const FOREIGN: &str = "exists and sync_gate did not create it";

pub struct Installed {
    pub dir: PathBuf,
    pub created: Vec<String>,
    pub skipped: Vec<(String, String)>,
}

/// Size and FNV-1a (64 bit) of a file's content.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
struct Fp {
    size: u64,
    fnv64: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct Aside {
    name: String,
    #[serde(flatten)]
    fp: Fp,
}

#[cfg(windows)]
type Entry = String;

#[cfg(unix)]
#[derive(Serialize, Deserialize, Clone)]
struct Entry {
    name: String,
    target: String,
    /// Targets of an update in progress: a link to one of them is ours too.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pending: Vec<String>,
}

/// Two-phase record. Before an update publishes any name the manifest lists the new content as
/// pending (Windows: `pending`; Unix: `Entry::pending`) next to the old; a file matching the old
/// OR a pending entry is ours. If the update is interrupted and cannot be put back, the next
/// `install` finishes it and `remove` removes both; a file matching neither is never touched.
/// The final write drops `pending` and leaves the new content only.
#[derive(Serialize, Deserialize, Clone)]
struct Manifest {
    version: u32,
    exe: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    base: Option<Fp>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pending: Vec<Fp>,
    files: Vec<Entry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    aside: Vec<Aside>,
}

/// shortcut: FNV is not cryptographic. It guards against another tool replacing a file, not
/// against someone crafting a collision (whoever can write this folder already runs code as the
/// user; on Unix it is private). Move to SHA-256 if the folder ever becomes shared.
#[cfg_attr(unix, allow(dead_code))]
fn fingerprint(path: &Path) -> io::Result<(u64, u64)> {
    let mut f = std::fs::File::open(path)?;
    let (mut size, mut h) = (0u64, 0xcbf2_9ce4_8422_2325u64);
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            return Ok((size, h));
        }
        size += n as u64;
        for b in &buf[..n] {
            h = (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3);
        }
    }
}

#[cfg_attr(unix, allow(dead_code))]
fn fp_of(path: &Path) -> io::Result<Fp> {
    let (size, h) = fingerprint(path)?;
    Ok(Fp {
        size,
        fnv64: format!("{h:016x}"),
    })
}

#[cfg(windows)]
fn shim_name(program: &str) -> String {
    format!("{program}.exe")
}

fn exists(path: &Path) -> io::Result<bool> {
    match path.symlink_metadata() {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// Windows: is this file's content the recorded base or a pending one?
#[cfg(windows)]
fn ours(m: &Manifest, p: &Path) -> bool {
    fp_of(p)
        .ok()
        .is_some_and(|f| m.base.as_ref() == Some(&f) || m.pending.contains(&f))
}

fn load(dir: &Path) -> io::Result<Option<Manifest>> {
    let p = dir.join(SHIMS_MANIFEST);
    if !exists(&p)? {
        return Ok(None);
    }
    let bad = |why: String| {
        io::Error::other(format!(
            "cannot read {}: {why}; remove the folder by hand",
            p.display()
        ))
    };
    #[cfg(unix)]
    sync_gate_core::check_private_file(&p).map_err(|e| bad(e.to_string()))?;
    let m: Manifest =
        serde_json::from_slice(&std::fs::read(&p)?).map_err(|e| bad(e.to_string()))?;
    if m.version != 2 {
        return Err(bad(format!("unknown version {}", m.version)));
    }
    Ok(Some(m))
}

fn save(dir: &Path, m: &Manifest) -> io::Result<()> {
    write_atomic(
        &dir.join(SHIMS_MANIFEST),
        &serde_json::to_vec_pretty(m).map_err(io::Error::other)?,
    )
}

/// Creates or refreshes the shims; idempotent. Files not in the manifest are never touched.
pub fn install(dir: &Path, exe: &Path) -> io::Result<Installed> {
    create_private_dir(dir)?;
    let old = load(dir)?;
    install_os(dir, exe, old)
}

/// Debug builds only (a test seam; release builds have no such switch): `SYNC_GATE_TEST_FAIL=<point>`
/// makes the named steps (comma separated) fail so the tests can prove the folder ends consistent.
fn injected(point: &str) -> bool {
    cfg!(debug_assertions)
        && std::env::var("SYNC_GATE_TEST_FAIL").is_ok_and(|v| v.split(',').any(|p| p == point))
}

/// Test seam `foreign-after-name`: another program replaces `path` right after it was published.
fn plant_foreign(path: &Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::write(path, b"foreign");
}

#[cfg(windows)]
const NO_LINKS: &str = "the shims folder needs a file system with hard links (NTFS)";

fn inject(point: &str) -> io::Result<()> {
    if injected(point) {
        return Err(io::Error::other(format!("injected failure at {point}")));
    }
    Ok(())
}

/// The pid in temporary names; debug builds let a test fix it (`SYNC_GATE_TEST_PID`) to plant
/// foreign files at the names a run would pick.
fn pid() -> String {
    std::env::var("SYNC_GATE_TEST_PID")
        .ok()
        .filter(|_| cfg!(debug_assertions))
        .unwrap_or_else(|| std::process::id().to_string())
}

/// Runs `f` on the first free `<dir>/<name>.<tag>-<pid>-<n>`. `f` must create the target
/// exclusively (it fails with `AlreadyExists` instead of replacing); on that error the next `n`
/// is tried, so a file another tool left at one of these names is never touched.
fn exclusive<T>(
    dir: &Path,
    name: &str,
    tag: &str,
    mut f: impl FnMut(&Path) -> io::Result<T>,
) -> io::Result<(PathBuf, T)> {
    for n in 0..10_000 {
        let p = dir.join(format!("{name}.{tag}-{}-{n}", pid()));
        match f(&p) {
            Ok(v) => return Ok((p, v)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other("no free temporary name"))
}

/// The error of a failed install, with what the rollback could not put back (if anything).
fn failed(e: &io::Error, left: &[String]) -> io::Error {
    let tail = if left.is_empty() {
        "; the folder was left as it was".to_owned()
    } else {
        format!("; could not put back: {}", left.join(", "))
    };
    io::Error::new(e.kind(), format!("{e}{tail}"))
}

/// Moves `from` to `to` but never replaces an existing `to` (`AlreadyExists`): a hard link
/// refuses an existing target, then the old name goes. Without hard links there is no safe
/// move, so it fails (`install` checks that first and changes nothing).
#[cfg(windows)]
fn move_new(from: &Path, to: &Path) -> io::Result<()> {
    std::fs::hard_link(from, to)?;
    std::fs::remove_file(from).inspect_err(|_| {
        let _ = std::fs::remove_file(to); // the link this call just made
    })
}

/// Copies `from` to a new file `to` (exclusive). A half-written copy is removed.
#[cfg(windows)]
fn copy_new(from: &Path, to: &Path) -> io::Result<()> {
    let mut dst = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(to)?;
    let done = io::copy(&mut std::fs::File::open(from)?, &mut dst).and_then(|_| dst.sync_all());
    drop(dst);
    if done.is_err() {
        let _ = std::fs::remove_file(to); // created by this call
    }
    done
}

/// What this run changed in the folder, to put it back if a later step fails. Each step carries
/// the content fingerprint it expects to find again: anything else is not ours and stays.
#[cfg(windows)]
enum Undo {
    /// `from` was moved to `to` (kept aside); `to` held `fp`.
    Aside { from: PathBuf, to: PathBuf, fp: Fp },
    /// A new name was published with content `fp`.
    Placed(PathBuf, Fp),
}

#[cfg(windows)]
#[derive(Default)]
struct Journal(Vec<Undo>);

#[cfg(windows)]
impl Journal {
    /// Moves `name` to a free `.old-` name, but only if it still holds the base or a pending
    /// content (anything else is foreign: left in place, reported). The planned aside name and the
    /// expected content are saved in `m` BEFORE the move, so a crash leaves a record that
    /// `install` and `remove` check by fingerprint (a missing file is dropped).
    fn aside(&mut self, dir: &Path, name: &str, m: &mut Manifest) -> io::Result<()> {
        let from = dir.join(name);
        if injected("foreign-before-aside") {
            plant_foreign(&from);
        }
        // One read: the fingerprint checked against base/pending is the one recorded and compared
        // after the move, so a file swapped in between can never be recorded as ours.
        let fp = fp_of(&from)
            .ok()
            .filter(|f| m.base.as_ref() == Some(f) || m.pending.contains(f))
            .ok_or_else(|| io::Error::other(format!("{name}: changed by another program; kept")))?;
        let (to, ()) = exclusive(dir, name, "old", |p| {
            if exists(p)? {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
            m.aside.push(Aside {
                name: p.file_name().unwrap().to_string_lossy().into_owned(),
                fp: fp.clone(),
            });
            let r = save(dir, m).and_then(|()| {
                if injected("exit-after-aside-record") {
                    std::process::exit(86); // a crash between the record and the move
                }
                if injected("foreign-before-move") {
                    plant_foreign(&from);
                }
                move_new(&from, p)
            });
            if r.is_err() {
                m.aside.pop();
            }
            r
        })?;
        if fp_of(&to).ok().as_ref() != Some(&fp) {
            // Swapped between the check and the move: put it back, never keep it as ours.
            let back = move_new(&to, &from);
            m.aside.pop();
            let _ = save(dir, m);
            return Err(io::Error::other(format!(
                "{name}: changed by another program; {}",
                if back.is_ok() { "kept" } else { "left aside" }
            )));
        }
        self.0.push(Undo::Aside { from, to, fp });
        Ok(())
    }

    fn place(&mut self, from: &Path, to: &Path, fp: &Fp) -> io::Result<()> {
        move_new(from, to)?;
        self.0.push(Undo::Placed(to.to_owned(), fp.clone()));
        Ok(())
    }

    /// Undoes everything in reverse, but touches a name only while it still holds what this run
    /// put there; returns what could not be put back (and why).
    fn rollback(self) -> Vec<String> {
        let mut left = vec![];
        for u in self.0.into_iter().rev() {
            let (at, expect) = match &u {
                Undo::Placed(p, fp) => (p, fp),
                Undo::Aside { to, fp, .. } => (to, fp),
            };
            let r = if fp_of(at).ok().as_ref() != Some(expect) {
                Err(io::Error::other("changed by another program; kept"))
            } else {
                match &u {
                    Undo::Placed(p, _) => {
                        inject("rollback-remove").and_then(|()| std::fs::remove_file(p))
                    }
                    Undo::Aside { from, to, .. } => move_new(to, from),
                }
            };
            if let Err(e) = r {
                let name = match &u {
                    Undo::Placed(p, _) => p,
                    Undo::Aside { from, .. } => from,
                };
                left.push(format!("{} ({e})", name.display()));
            }
        }
        left
    }
}

/// Windows update. Every new file is staged completely (the new base plus one hard link per name)
/// under an exclusive temporary name; then the manifest is written with the new content pending
/// (the recovery record), the old files go aside, the staged ones are published, and the manifest
/// is written final. Any failure puts back what this run moved, each step only while the file is
/// still what this run left there; if that cannot all be done, the pending manifest stays and the
/// next `install` or `remove` finishes or undoes the update by the rule on `Manifest`.
/// A shim that cannot be deleted because it is running stays in `aside` and is cleaned later,
/// only while the manifest still proves it ours. `done` counts the staged files published.
#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
fn publish(
    dir: &Path,
    new: &Path,
    refresh: &[String],
    retire: &[String],
    staged: &[PathBuf],
    j: &mut Journal,
    done: &mut usize,
    m: &mut Manifest,
) -> io::Result<()> {
    let base_name = format!("{BASE}.exe");
    let base_path = dir.join(&base_name);
    let new_fp = fp_of(new)?;
    if !m.pending.contains(&new_fp) {
        m.pending.push(new_fp.clone());
    }
    for n in refresh {
        if !m.files.contains(n) {
            m.files.push(n.clone());
        }
    }
    save(dir, m)?; // phase one: from here on the new content is recognised as ours
    if exists(&base_path)? {
        j.aside(dir, &base_name, m)?;
    }
    j.place(new, &base_path, &new_fp)?;
    inject("after-base")?;
    for (name, tmp) in refresh.iter().zip(staged) {
        if exists(&dir.join(name))? {
            j.aside(dir, name, m)?;
        }
        j.place(tmp, &dir.join(name), &new_fp)?;
        *done += 1;
        if injected("foreign-after-name") {
            plant_foreign(&dir.join(name));
            return Err(io::Error::other("injected failure at foreign-after-name"));
        }
        inject("after-name")?;
    }
    // Names that now only exist as a PowerShell script: our shim goes aside (undone with the rest
    // if a later step fails) and leaves the manifest.
    for name in retire {
        j.aside(dir, name, m)?;
    }
    m.files.retain(|f| !retire.contains(f));
    m.base = Some(new_fp);
    m.pending.clear();
    save(dir, m) // phase two
}

/// `PATH` of this process without the shims folder `dir` (the lookup a shim does at run time never
/// sees that folder: it holds our manifest).
#[cfg(windows)]
fn path_without(dir: &Path) -> Option<OsString> {
    let path = std::env::var_os("PATH")?;
    let kept: Vec<PathBuf> = std::env::split_paths(&path)
        .filter(|d| !same_file(d, dir))
        .collect();
    std::env::join_paths(kept).ok()
}

/// The `<program>.ps1` that a shim for `shim_file` (`<program>.exe`) would hide: no executable
/// target on `path` (the search `run_as` does) and a `.ps1` found. `None` for any other name.
#[cfg(windows)]
fn ps1_only(shim_file: &str, path: Option<&OsStr>) -> Option<PathBuf> {
    let program = shim_file.strip_suffix(".exe")?;
    if !HEAVY_PROGRAMS.contains(&program) {
        return None;
    }
    let name = OsStr::new(program);
    let cwd = std::env::current_dir().unwrap_or_default();
    let pathext = std::env::var_os("PATHEXT");
    if sync_gate_core::program::find_program(name, path, pathext.as_deref(), &cwd).is_some() {
        return None;
    }
    sync_gate_core::program::find_ps1(name, path)
}

#[cfg(windows)]
fn install_os(dir: &Path, exe: &Path, old: Option<Manifest>) -> io::Result<Installed> {
    use std::fs;
    let mut out = Installed {
        dir: dir.to_owned(),
        created: vec![],
        skipped: vec![],
    };
    let base_name = format!("{BASE}.exe");
    let base_path = dir.join(&base_name);
    let mut m = old.clone().unwrap_or(Manifest {
        version: 2,
        exe: String::new(),
        base: None,
        pending: vec![],
        files: vec![],
        aside: vec![],
    });
    // A base we did not make, or one replaced since, stops the whole update.
    if exists(&base_path)? && !ours(&m, &base_path) {
        let why = if m.base.is_some() { CHANGED } else { FOREIGN };
        out.skipped.push((base_name, why.into()));
        return Ok(out);
    }
    // Decide every name before touching anything.
    let mut names: Vec<String> = HEAVY_PROGRAMS.iter().map(|p| shim_name(p)).collect();
    let listed_only: Vec<String> = m
        .files
        .iter()
        .filter(|f| !names.contains(f))
        .cloned()
        .collect();
    names.extend(listed_only);
    let search_path = path_without(dir);
    let (mut refresh, mut retire) = (vec![], vec![]);
    for name in names {
        let path = dir.join(&name);
        let ps1 = ps1_only(&name, search_path.as_deref());
        let hidden = |ps1: &Path| {
            format!(
                "only a PowerShell script exists ({}); a shim would hide it",
                ps1.display()
            )
        };
        if !exists(&path)? {
            match ps1 {
                Some(p) => out.skipped.push((name, hidden(&p))),
                None => refresh.push(name),
            }
        } else if !m.files.contains(&name) {
            out.skipped.push((name, FOREIGN.into()));
        } else if ours(&m, &path) {
            match ps1 {
                Some(p) => {
                    out.skipped.push((name.clone(), hidden(&p)));
                    retire.push(name);
                }
                None => refresh.push(name),
            }
        } else {
            out.skipped.push((name, CHANGED.into()));
        }
    }
    // Stage the new base, then one hard link per name to refresh. Only what this run created
    // (exclusive names) is ever removed. Without hard links nothing is changed.
    let (new, ()) = exclusive(dir, &base_name, "new", |p| copy_new(exe, p))?;
    let mut staged = vec![];
    for name in &refresh {
        let r = inject("stage-copy").and_then(|()| {
            exclusive(dir, name, "new", |p| {
                if injected("no-links") {
                    return Err(io::Error::other(NO_LINKS));
                }
                fs::hard_link(&new, p).map_err(|e| {
                    if e.kind() == io::ErrorKind::AlreadyExists {
                        e
                    } else {
                        io::Error::other(NO_LINKS)
                    }
                })
            })
        });
        match r {
            Ok((p, ())) => staged.push(p),
            Err(e) => {
                for p in staged.iter().chain([&new]) {
                    let _ = fs::remove_file(p);
                }
                return Err(e);
            }
        }
    }
    m.exe = exe.display().to_string();
    let (mut j, mut done) = (Journal::default(), 0);
    if let Err(e) = publish(
        dir, &new, &refresh, &retire, &staged, &mut j, &mut done, &mut m,
    ) {
        let mut left = j.rollback();
        for p in staged[done..].iter().chain([&new]) {
            let _ = fs::remove_file(p); // never published: still ours to delete
        }
        if left.is_empty() {
            // Everything is back: so is the manifest. Otherwise the pending one stays.
            let back = match &old {
                Some(o) => save(dir, o),
                None => fs::remove_file(dir.join(SHIMS_MANIFEST)).or_else(|e| {
                    if e.kind() == io::ErrorKind::NotFound {
                        Ok(())
                    } else {
                        Err(e)
                    }
                }),
            };
            if let Err(e) = back {
                left.push(format!("the manifest ({e})"));
            }
        }
        return Err(failed(&e, &left));
    }
    // Delete the moved files only while they are still what we moved; in use stays for next time.
    m.aside.retain(|a| {
        let p = dir.join(&a.name);
        match fp_of(&p) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            Ok(f) if f == a.fp => fs::remove_file(&p).is_err(),
            _ => {
                out.skipped.push((a.name.clone(), CHANGED.into()));
                false
            }
        }
    });
    save(dir, &m)?;
    out.created = refresh;
    Ok(out)
}

#[cfg(unix)]
fn is_link_to(path: &Path, target: &str) -> bool {
    std::fs::read_link(path).is_ok_and(|t| t == Path::new(target))
        && path
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink())
}

/// A link to the entry's target or to one of its pending targets.
#[cfg(unix)]
fn is_ours(path: &Path, e: &Entry) -> bool {
    is_link_to(path, &e.target) || e.pending.iter().any(|t| is_link_to(path, t))
}

/// A link staged under an exclusive temporary name, waiting to be published over `name`.
#[cfg(unix)]
struct Staged {
    name: &'static str,
    listed: Option<usize>,
    tmp: PathBuf,
    /// The target of the link of ours that it replaces; `None` when the name was absent.
    was: Option<String>,
}

/// Unix update: every temporary link is created (exclusively) before any name is touched, then
/// each is renamed over its name; the manifest is last. A failure puts back what this run
/// published (the old target of a replaced link; removal of a new one, only while it is still
/// our link), so the folder is the old install or the new one.
#[cfg(unix)]
fn install_os(dir: &Path, exe: &Path, old: Option<Manifest>) -> io::Result<Installed> {
    use std::fs;
    let target = fs::canonicalize(exe)?
        .to_str()
        .ok_or_else(|| io::Error::other("the sync_gate path is not valid UTF-8"))?
        .to_owned();
    let mut out = Installed {
        dir: dir.to_owned(),
        created: vec![],
        skipped: vec![],
    };
    let mut files = old.as_ref().map_or(vec![], |m| m.files.clone());
    let mut staged: Vec<Staged> = vec![];
    for (i, p) in HEAVY_PROGRAMS.iter().enumerate() {
        let path = dir.join(p);
        let listed = files.iter().position(|e| e.name == *p);
        // shortcut: the link may be swapped between this check and the rename below (microseconds,
        // in a private folder); the worst case is overwriting a swap made in that instant.
        let mut was = None;
        if exists(&path)? {
            if !listed.is_some_and(|i| is_ours(&path, &files[i])) {
                let why = if listed.is_some() { CHANGED } else { FOREIGN };
                out.skipped.push(((*p).into(), why.into()));
                continue;
            }
            // The target this link has now (the recorded one or a pending one).
            was = fs::read_link(&path)
                .ok()
                .map(|t| t.to_string_lossy().into_owned());
        }
        let r = (if i == 1 { inject("stage-copy") } else { Ok(()) })
            .and_then(|()| exclusive(dir, p, "tmp", |t| std::os::unix::fs::symlink(&target, t)));
        match r {
            Ok((tmp, ())) => staged.push(Staged {
                name: p,
                listed,
                tmp,
                was,
            }),
            Err(e) => {
                for s in &staged {
                    let _ = fs::remove_file(&s.tmp); // created by this run
                }
                return Err(e);
            }
        }
    }
    let mut published = 0;
    let r = (|| {
        // Phase one: the new target is recorded as pending before any name changes.
        let mut pend = files.clone();
        for s in &staged {
            match s.listed {
                Some(i) => {
                    let e = &mut pend[i];
                    if e.target != target && !e.pending.contains(&target) {
                        e.pending.push(target.clone());
                    }
                }
                None => pend.push(Entry {
                    name: s.name.into(),
                    target: target.clone(),
                    pending: vec![],
                }),
            }
        }
        let manifest = |files| Manifest {
            version: 2,
            exe: exe.display().to_string(),
            base: None,
            pending: vec![],
            files,
            aside: vec![],
        };
        save(dir, &manifest(pend))?;
        for s in &staged {
            fs::rename(&s.tmp, dir.join(s.name))?;
            published += 1;
            if injected("foreign-after-name") {
                plant_foreign(&dir.join(s.name));
                return Err(io::Error::other("injected failure at foreign-after-name"));
            }
            inject("after-name")?;
        }
        // Phase two: the new target alone.
        for s in &staged {
            match s.listed {
                Some(i) => {
                    files[i].target.clone_from(&target);
                    files[i].pending.clear();
                }
                None => files.push(Entry {
                    name: s.name.into(),
                    target: target.clone(),
                    pending: vec![],
                }),
            }
        }
        save(dir, &manifest(files.clone()))
    })();
    if let Err(e) = r {
        let mut left = vec![];
        for s in staged[..published].iter().rev() {
            let path = dir.join(s.name);
            let back = if !is_link_to(&path, &target) {
                Err(io::Error::other("changed by another program; kept"))
            } else {
                inject("rollback-remove").and_then(|()| match &s.was {
                    None => fs::remove_file(&path),
                    Some(old) => {
                        exclusive(dir, s.name, "tmp", |t| std::os::unix::fs::symlink(old, t))
                            .and_then(|(t, ())| {
                                fs::rename(&t, &path).inspect_err(|_| {
                                    let _ = fs::remove_file(&t);
                                })
                            })
                    }
                })
            };
            if let Err(e) = back {
                left.push(format!("{} ({e})", path.display()));
            }
        }
        for s in &staged[published..] {
            let _ = fs::remove_file(&s.tmp); // never published: still ours to delete
        }
        if left.is_empty() {
            // Everything is back: so is the manifest. Otherwise the pending one stays.
            let back = match &old {
                Some(o) => save(dir, o),
                None => fs::remove_file(dir.join(SHIMS_MANIFEST)).or_else(|e| {
                    if e.kind() == io::ErrorKind::NotFound {
                        Ok(())
                    } else {
                        Err(e)
                    }
                }),
            };
            if let Err(e) = back {
                left.push(format!("the manifest ({e})"));
            }
        }
        return Err(failed(&e, &left));
    }
    out.created = staged.iter().map(|s| s.name.to_owned()).collect();
    Ok(out)
}

/// Removes only what the manifest lists and that is still what sync_gate made; the rest is kept
/// and named on stderr. Returns how many files were deleted. A file of ours that could not be
/// deleted keeps the manifest (it is what makes the folder skipped when a real program is
/// looked up) and makes this an error naming what is left.
pub fn remove(dir: &Path) -> io::Result<usize> {
    let Some(m) = load(dir)? else {
        return Ok(0);
    };
    let (mut n, mut left) = (0, Vec::new());
    let mut take = |name: &str, ours: &dyn Fn(&Path) -> bool| {
        let p = dir.join(name);
        if !exists(&p).unwrap_or(false) {
            return;
        }
        if !ours(&p) {
            eprintln!("kept: {name}: changed by another program");
        } else if let Err(e) = std::fs::remove_file(&p) {
            eprintln!("kept: {name}: {e}");
            left.push(name.to_owned());
        } else {
            n += 1;
        }
    };
    #[cfg(windows)]
    {
        let same = |want: &Fp| {
            let want = want.clone();
            move |p: &Path| fp_of(p).ok().as_ref() == Some(&want)
        };
        let mine = |p: &Path| ours(&m, p);
        for name in &m.files {
            take(name, &mine);
        }
        take(&format!("{BASE}.exe"), &mine);
        for a in &m.aside {
            take(&a.name, &same(&a.fp));
        }
    }
    #[cfg(unix)]
    for e in &m.files {
        take(&e.name, &|p| is_ours(p, e));
    }
    if !left.is_empty() {
        return Err(io::Error::other(format!(
            "removed {n} file(s) but not {}; the manifest stays so this folder is still skipped: run it again once nothing holds them",
            left.join(", ")
        )));
    }
    std::fs::remove_file(dir.join(SHIMS_MANIFEST))?;
    let _ = std::fs::remove_dir(dir); // only when empty
    Ok(n)
}

fn folder() -> Result<std::path::PathBuf, String> {
    shims_dir().ok_or_else(|| "no per-user data folder for the shims".to_owned())
}

pub fn cli_install() -> i32 {
    let done = folder().and_then(|dir| {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        install(&dir, &exe).map_err(|e| e.to_string())
    });
    let i = match done {
        Ok(i) => i,
        Err(e) => {
            eprintln!("sync_gate: shims install failed: {e}");
            return 1;
        }
    };
    let d = i.dir.display();
    println!("Shims folder: {d}");
    println!("Created: {}", i.created.join(", "));
    for (name, why) in &i.skipped {
        println!("Skipped: {name}: {why}");
    }
    println!("Put the folder first on PATH:");
    if cfg!(windows) {
        println!(
            "  [Environment]::SetEnvironmentVariable('Path', '{d};' + [Environment]::GetEnvironmentVariable('Path','User'), 'User')"
        );
    } else {
        println!("  export PATH=\"{d}:$PATH\"   (in your shell profile)");
    }
    println!("Claude Code sessions get it from the sync_gate plugin.");
    0
}

pub fn cli_remove() -> i32 {
    match folder().map_err(io::Error::other).and_then(|d| remove(&d)) {
        Ok(n) => {
            println!("Removed {n} file(s).");
            0
        }
        Err(e) => {
            eprintln!("sync_gate: shims remove failed: {e}");
            1
        }
    }
}

/// Stem of argv[0], lower case, without `.exe`, when it is one of `HEAVY_PROGRAMS`
/// (never `sync_gate` nor `BASE`).
pub fn invoked_as() -> Option<String> {
    invoked_as_from(std::env::args_os().next()?.as_os_str())
}

pub fn invoked_as_from(argv0: &OsStr) -> Option<String> {
    // Split by hand: `C:\x\NPM.EXE` must work on Unix too.
    // Lossy on purpose: only the file name matters, and a bad byte in a folder must not hide it.
    let file = argv0
        .to_string_lossy()
        .rsplit(['/', '\\'])
        .next()?
        .to_lowercase();
    let stem = file.strip_suffix(".exe").unwrap_or(&file);
    HEAVY_PROGRAMS.contains(&stem).then(|| stem.to_owned())
}

/// The same file, by canonical path (Windows: without case).
pub(crate) fn same_file(a: &Path, b: &Path) -> bool {
    let canon = |p: &Path| {
        let s = std::fs::canonicalize(p)
            .unwrap_or_else(|_| p.to_path_buf())
            .to_string_lossy()
            .into_owned();
        if cfg!(windows) { s.to_lowercase() } else { s }
    };
    canon(a) == canon(b)
}

/// `Some` only when every element is valid Unicode.
pub fn argv_as_strings(argv: Vec<OsString>) -> Option<Vec<String>> {
    argv.into_iter().map(|a| a.into_string().ok()).collect()
}

/// Shim mode: finds the real program outside the shims folders and runs it through the queue.
pub fn run_as(name: &str) -> i32 {
    crate::runner::install_ctrlc();
    let cwd = std::env::current_dir().unwrap_or_default();
    let path = std::env::var_os("PATH");
    let Some(real) = sync_gate_core::program::find_program(
        OsStr::new(name),
        path.as_deref(),
        std::env::var_os("PATHEXT").as_deref(),
        &cwd,
    ) else {
        match cfg!(windows)
            .then(|| sync_gate_core::program::find_ps1(OsStr::new(name), path.as_deref()))
            .flatten()
        {
            Some(ps1) => eprintln!("{}", crate::runner::ps1_only_message(name, &ps1)),
            None => eprintln!("sync_gate: {name}: not found outside the sync_gate shims folders"),
        }
        return 127;
    };
    // Reached through a shim on purpose (`sync_gate run -- <shim>`) is fine; a real that is this
    // very file is a loop.
    if std::env::current_exe().is_ok_and(|me| same_file(&real, &me)) {
        eprintln!(
            "sync_gate: {name} resolves to a sync_gate shim at {} (a copy outside the shims folder?); remove it from PATH",
            real.display()
        );
        return 127;
    }
    let mut argv = vec![real.into_os_string()];
    argv.extend(std::env::args_os().skip(1));
    match argv_as_strings(argv.clone()) {
        Some(v) => {
            let session = std::env::var("SYNC_GATE_SESSION").unwrap_or_else(|_| "default".into());
            crate::runner::run(session, None, v)
        }
        None => {
            eprintln!(
                "sync_gate: {name}: an argument is not valid Unicode; running it directly (no queue)"
            );
            crate::runner::run_os_direct(argv)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_differs_for_same_size_different_content() {
        let dir = std::env::temp_dir().join(format!("fg-shims-fp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (a, b, c) = (dir.join("a"), dir.join("b"), dir.join("c"));
        std::fs::write(&a, b"abcd").unwrap();
        std::fs::write(&b, b"abce").unwrap();
        std::fs::write(&c, b"abcd").unwrap();
        let (fa, fb, fc) = (
            fingerprint(&a).unwrap(),
            fingerprint(&b).unwrap(),
            fingerprint(&c).unwrap(),
        );
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(fa.0, fb.0);
        assert_ne!(fa, fb);
        assert_eq!(fa, fc);
    }

    #[test]
    fn invoked_as_reads_the_program_name() {
        for (arg0, want) in [
            ("npm", Some("npm")),
            (r"C:\x\NPM.EXE", Some("npm")),
            ("/a/cargo", Some("cargo")),
            ("sync_gate", None),
            ("sync_gate.exe", None),
            ("sync_gate_shim.exe", None),
            ("unknown", None),
        ] {
            let got = invoked_as_from(OsStr::new(arg0));
            assert_eq!(got.as_deref(), want, "{arg0}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn a_lone_surrogate_is_not_unicode() {
        use std::os::windows::ffi::OsStringExt;
        let bad = OsString::from_wide(&[0xD800]);
        assert!(argv_as_strings(vec![OsString::from("a"), bad]).is_none());
        assert!(argv_as_strings(vec![OsString::from("a")]).is_some());
    }
}
