//! Windows: the rules of the Unix check in owners and DACLs. A folder passes when its owner is
//! trusted (this user, the default owner, Administrators, SYSTEM), no other SID may change it or
//! anything in it, and no ancestor lets another SID replace what is under it. Every component is
//! opened on its own without following it; a link (symlink, junction, mount point) anywhere in
//! the path is refused, while other reparse points (cloud files, such as OneDrive) are folders.
//! Network shares and drives that are not fixed are refused: their ACLs are not ours to judge.
//! SUBST drives are not resolved: their target is judged as the drive the path names.
use super::{DirState, deny, is_name_surrogate, tag_info};
use crate::win_sec::{sid, token_info};
use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf, Prefix};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetSecurityInfo, SE_FILE_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, AddAce, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
    INHERIT_ONLY_ACE, INHERITED_ACE, InitializeAcl, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_OWNER, TOKEN_USER,
    TokenOwner, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK,
    GetDriveTypeW, GetFileType, READ_CONTROL,
};

// Access rights ("File Access Rights Constants", "Generic Access Rights").
const ADD_FILE: u32 = 0x2;
const ADD_SUBDIRECTORY: u32 = 0x4;
const WRITE_EA: u32 = 0x10;
const DELETE_CHILD: u32 = 0x40;
const WRITE_ATTRIBUTES: u32 = 0x100;
const DELETE: u32 = 0x1_0000;
const WRITE_DAC: u32 = 0x4_0000;
const WRITE_OWNER: u32 = 0x8_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_EXECUTE: u32 = 0x2000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_READ: u32 = 0x8000_0000;

/// On an entry: lets the holder replace that entry.
const REPLACE_SELF: u32 = DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL;
/// On a folder: lets the holder replace any entry in it.
const REPLACE_CHILD: u32 = DELETE_CHILD | WRITE_DAC | WRITE_OWNER | GENERIC_ALL;
/// On a folder: lets the holder add an entry. Refused on the parent of an entry of this user.
const ADD_CHILD: u32 = ADD_FILE | ADD_SUBDIRECTORY | GENERIC_WRITE | GENERIC_ALL;
/// On the final folder: any change to it or to what is in it.
const WRITE_DIR: u32 = ADD_CHILD | WRITE_EA | DELETE_CHILD | WRITE_ATTRIBUTES | REPLACE_SELF;
// The same bits on a file: FILE_WRITE_DATA and FILE_APPEND_DATA.
const WRITE_DATA: u32 = ADD_FILE;
const APPEND_DATA: u32 = ADD_SUBDIRECTORY;
/// On a file: any change to its content, attributes, descriptor, or the file itself.
const WRITE_FILE: u32 =
    WRITE_DATA | APPEND_DATA | WRITE_EA | WRITE_ATTRIBUTES | REPLACE_SELF | GENERIC_WRITE;

const DRIVE_FIXED: u32 = 3;

/// What a DACL grants the SIDs it does not trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Others {
    Nothing,
    Read,
    Change,
}

/// Calls `f(sid, mask)` for each grant of `dacl` to a SID `trusted` rejects; `sid` is None for a
/// grant whose SID or condition is not read here (object, callback, compound). Deny entries only
/// take away and are skipped. Inherit-only entries count only with `io` (they apply to what is
/// created inside), except those for CREATOR OWNER (the creator). False if an entry is unreadable.
///
/// # Safety
/// `dacl` must point to a valid ACL for the whole call.
unsafe fn foreign(
    dacl: *const ACL,
    trusted: &dyn Fn(PSID) -> bool,
    io: bool,
    f: &mut dyn FnMut(Option<PSID>, u32),
) -> bool {
    let creator = sid(3, &[0]);
    // SAFETY: `dacl` is a valid ACL (caller).
    for i in 0..u32::from(unsafe { (*dacl).AceCount }) {
        let mut ace = std::ptr::null_mut();
        // SAFETY: `i` is below the ACE count; `ace` is a valid out pointer.
        if unsafe { GetAce(dacl, i, &mut ace) } == 0 {
            return false;
        }
        // SAFETY: GetAce points `ace` at an entry inside the ACL; every entry starts with a
        // header followed by its access mask.
        let (head, mask) = unsafe {
            let a = ace.cast::<ACCESS_ALLOWED_ACE>();
            ((*a).Header, (*a).Mask)
        };
        let inherit_only = u32::from(head.AceFlags) & INHERIT_ONLY_ACE != 0;
        if inherit_only && !io {
            continue;
        }
        match head.AceType {
            // ACCESS_DENIED, _OBJECT, _CALLBACK, _CALLBACK_OBJECT.
            1 | 6 | 10 | 12 => {}
            0 => {
                // SAFETY: an ACCESS_ALLOWED_ACE: its SID starts at `SidStart`, inside the entry.
                let sid: PSID = unsafe { &raw const (*ace.cast::<ACCESS_ALLOWED_ACE>()).SidStart }
                    .cast_mut()
                    .cast();
                // SAFETY: both SIDs are valid.
                let is_creator = inherit_only
                    && unsafe { EqualSid(sid, creator.as_ptr().cast_mut().cast()) } != 0;
                if !trusted(sid) && !is_creator {
                    f(Some(sid), mask);
                }
            }
            _ => f(None, mask),
        }
    }
    true
}

/// What `dacl` grants SIDs that `trusted` rejects: `Change` for any of `bits`, also for no DACL
/// at all (everyone has everything) or an unreadable one; `Read` for any other right.
///
/// # Safety
/// `dacl` must be null or point to a valid ACL for the whole call.
unsafe fn others(dacl: *const ACL, trusted: &dyn Fn(PSID) -> bool, bits: u32, io: bool) -> Others {
    if dacl.is_null() {
        return Others::Change;
    }
    let mut seen = Others::Nothing;
    let mut f = |_: Option<PSID>, mask: u32| {
        if mask & bits != 0 {
            seen = Others::Change;
        } else if mask != 0 && seen == Others::Nothing {
            seen = Others::Read;
        }
    };
    // SAFETY: a valid ACL (caller).
    if !unsafe { foreign(dacl, trusted, io, &mut f) } {
        return Others::Change;
    }
    seen
}

/// The SIDs, as text, that `dacl` grants any of `bits` to and `trusted` rejects; None when one
/// of those grants cannot be named (no DACL, an unreadable entry, an object or callback one).
///
/// # Safety
/// `dacl` must be null or point to a valid ACL for the whole call.
unsafe fn writers(
    dacl: *const ACL,
    trusted: &dyn Fn(PSID) -> bool,
    bits: u32,
    io: bool,
) -> Option<Vec<String>> {
    if dacl.is_null() {
        return None;
    }
    let (mut out, mut named) = (Vec::new(), true);
    let mut f = |s: Option<PSID>, mask: u32| {
        if mask & bits == 0 {
            return;
        }
        match s.and_then(sid_text) {
            Some(t) if !out.contains(&t) => out.push(t),
            Some(_) => {}
            None => named = false,
        }
    };
    // SAFETY: a valid ACL (caller).
    let read = unsafe { foreign(dacl, trusted, io, &mut f) };
    (read && named).then_some(out)
}

/// `S-1-...` for a valid SID.
fn sid_text(s: PSID) -> Option<String> {
    let mut text = std::ptr::null_mut();
    // SAFETY: a valid SID; `text` is freed below.
    if unsafe { ConvertSidToStringSidW(s, &mut text) } == 0 {
        return None;
    }
    // SAFETY: `text` is a NUL-terminated string allocated by the call above, freed once.
    Some(unsafe {
        let len = (0..).take_while(|&i| *text.add(i) != 0).count();
        let t = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text.cast());
        t
    })
}

/// This process's user and default owner, plus the SIDs trusted like them: Administrators,
/// SYSTEM, TrustedInstaller (owner of system folders) and OWNER RIGHTS (in entries).
struct Trust {
    _bufs: [Vec<u64>; 6],
    user: PSID,
    owner: PSID,
    all: [PSID; 6],
}

impl Trust {
    fn get() -> io::Result<Self> {
        let (Some(u), Some(o)) = (
            token_info::<TOKEN_USER>(TokenUser),
            token_info::<TOKEN_OWNER>(TokenOwner),
        ) else {
            return Err(io::Error::other("cannot read this process's token"));
        };
        // SAFETY: `token_info` checked each buffer holds a whole struct; the SIDs point inside
        // buffers that move into `_bufs` (a Vec's heap block does not move with it).
        let (user, owner) = unsafe {
            (
                (*u.as_ptr().cast::<TOKEN_USER>()).User.Sid,
                (*o.as_ptr().cast::<TOKEN_OWNER>()).Owner,
            )
        };
        let bufs = [
            u,
            o,
            sid(5, &[32, 544]),
            sid(5, &[18]),
            sid(
                5,
                &[
                    80, 956008885, 3418522649, 1831038044, 1853292631, 2271478464,
                ],
            ),
            sid(3, &[4]),
        ];
        let p = |b: &Vec<u64>| b.as_ptr().cast_mut().cast();
        let all = [
            user,
            owner,
            p(&bufs[2]),
            p(&bufs[3]),
            p(&bufs[4]),
            p(&bufs[5]),
        ];
        Ok(Self {
            _bufs: bufs,
            user,
            owner,
            all,
        })
    }

    fn trusted(&self, sid: PSID) -> bool {
        // SAFETY: every SID here is valid while `self` lives; `sid` is checked non-null.
        !sid.is_null() && self.all.iter().any(|&t| unsafe { EqualSid(t, sid) } != 0)
    }

    /// May own a file sync_gate trusts: this user, Administrators, SYSTEM, TrustedInstaller.
    /// The token's default owner only when it is one of those; OWNER RIGHTS never (it only means
    /// something in an entry).
    fn owner_ok(&self, sid: PSID) -> bool {
        let file_owners = [self.all[0], self.all[2], self.all[3], self.all[4]];
        // SAFETY: as in `trusted`.
        !sid.is_null()
            && file_owners
                .iter()
                .any(|&t| unsafe { EqualSid(t, sid) } != 0)
    }

    /// May be granted changes in a file's DACL: a possible owner, or OWNER RIGHTS.
    fn ace_ok(&self, sid: PSID) -> bool {
        // SAFETY: as in `trusted`.
        self.owner_ok(sid) || (!sid.is_null() && unsafe { EqualSid(self.all[5], sid) } != 0)
    }

    /// The entry is ours to delete: owned by this user (or default owner), or its DACL grants
    /// this user DELETE. Then its parent must not let others add entries.
    fn mine(&self, e: &Entry) -> bool {
        let is = |a: PSID, b: PSID| !a.is_null() && unsafe { EqualSid(a, b) } != 0;
        let not_user = |s: PSID| !is(s, self.user);
        is(e.owner, self.user)
            || is(e.owner, self.owner)
            // SAFETY: the entry's DACL is valid while it lives.
            || unsafe { others(e.dacl, &not_user, DELETE | GENERIC_ALL, false) } == Others::Change
    }
}

/// One path component, opened without following it: its owner, DACL and kind.
struct Entry {
    sd: PSECURITY_DESCRIPTOR,
    owner: PSID,
    dacl: *const ACL,
    dir: bool,
    link: bool,
    /// The reparse tag, when it is a reparse point of any kind.
    reparse: Option<u32>,
}

impl Drop for Entry {
    fn drop(&mut self) {
        // SAFETY: allocated by GetSecurityInfo for this entry; freed once.
        unsafe { LocalFree(self.sd) };
    }
}

/// Shared with everyone (the default of `OpenOptions`).
const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

fn open(path: &Path) -> io::Result<Entry> {
    open_with(path, 0, SHARE_ALL).map(|(e, _)| e)
}

/// `open`, opened with `extra` access too and sharing `share`, with its handle.
fn open_with(path: &Path, extra: u32, share: u32) -> io::Result<(Entry, std::fs::File)> {
    let f = std::fs::OpenOptions::new()
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES | extra)
        .share_mode(share)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let (attrs, tag) = tag_info(&f).ok_or_else(io::Error::last_os_error)?;
    let (mut owner, mut dacl, mut sd) = (
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    );
    // SAFETY: a valid handle opened with READ_CONTROL; the out pointers are valid; on success
    // `owner` and `dacl` point into `sd`, which the entry frees.
    let err = unsafe {
        GetSecurityInfo(
            f.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if err != 0 {
        return Err(io::Error::from_raw_os_error(err as i32));
    }
    let e = Entry {
        sd,
        owner,
        dacl,
        dir: attrs & 0x10 != 0,
        link: attrs & 0x400 != 0 && is_name_surrogate(tag),
        reparse: (attrs & 0x400 != 0).then_some(tag),
    };
    Ok((e, f))
}

/// The drive root (`C:\`) and the names under it; a path on a share is refused.
fn split(dir: &Path) -> io::Result<(PathBuf, Vec<OsString>)> {
    let invalid = |why: &str| {
        super::refusal(
            io::ErrorKind::InvalidInput,
            format!("{} {why}", dir.display()),
        )
    };
    if !dir.is_absolute() {
        return Err(invalid("is not an absolute path"));
    }
    let mut parts = dir.components();
    let root = match parts.next() {
        Some(Component::Prefix(p)) => match p.kind() {
            Prefix::Disk(d) | Prefix::VerbatimDisk(d) => PathBuf::from(format!("{}:\\", d as char)),
            _ => {
                return Err(deny(
                    dir,
                    "is not on a local drive (network paths are refused)",
                ));
            }
        },
        _ => return Err(invalid("is not an absolute path")),
    };
    let mut names = Vec::new();
    for c in parts {
        match c {
            Component::Normal(n) => names.push(n.to_owned()),
            Component::ParentDir => return Err(invalid("has a parent-folder component")),
            _ => {}
        }
    }
    Ok((root, names))
}

fn wide(p: &Path) -> Vec<u16> {
    p.as_os_str().encode_wide().chain([0]).collect()
}

/// What the messages tell to do about `p`: with every writer named (`sids`), the command that
/// removes their entries (inherited ones are made its own first), which makes `p` pass; else no
/// command, since none built from names would: the entries are to be removed by hand.
fn fix(p: &Path, sids: Option<Vec<String>>) -> String {
    let Some(sids) = sids else {
        return format!(
            r#"remove by hand every entry that lets another user change it; `icacls "{}"` lists them, and some cannot be named here"#,
            p.display()
        );
    };
    let list: Vec<String> = sids.iter().map(|s| format!("*{s}")).collect();
    format!(
        r#"run: icacls "{}" /inheritance:d /remove:g {}"#,
        p.display(),
        list.join(" ")
    )
}

/// `p` is on the fixed local drive `root`.
fn fixed_drive(root: &Path, p: &Path) -> io::Result<()> {
    // SAFETY: a NUL-terminated path.
    if unsafe { GetDriveTypeW(wide(root).as_ptr()) } != DRIVE_FIXED {
        return Err(deny(
            p,
            "is not on a fixed local drive (network and removable drives are refused)",
        ));
    }
    Ok(())
}

/// Why a file is not trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    Owner,
    Writable,
}

/// The one rule for a file sync_gate trusts: owned by someone `owner_ok` accepts, and no grant
/// of any change to anyone `ace_ok` rejects. No link-count rule: a hard link has no descriptor of
/// its own (the file's is the only one), and the shims are hard links by design.
///
/// # Safety
/// `owner` must be null or a valid SID, and `dacl` null or a valid ACL, for the whole call.
unsafe fn file_refusal(
    owner: PSID,
    dacl: *const ACL,
    owner_ok: &dyn Fn(PSID) -> bool,
    ace_ok: &dyn Fn(PSID) -> bool,
) -> Option<Refusal> {
    if owner.is_null() || !owner_ok(owner) {
        return Some(Refusal::Owner);
    }
    // SAFETY: as the caller guarantees.
    (unsafe { others(dacl, ace_ok, WRITE_FILE, false) } == Others::Change)
        .then_some(Refusal::Writable)
}

/// Opens `path` without following it and judges the opened file with `file_refusal`. `read`:
/// opened to read its data and without sharing writes, so what is read is what was judged and no
/// new opening for writing its data gets in while the handle lives; a file already open for that
/// is refused (sharing violation). Else only its descriptor is read, whoever has it open.
/// Refuses (14.5) a name the Win32 layer would change or read as something else: a final dot or
/// space (dropped by Win32, kept by a verbatim path, so a folder walk and an open could see two
/// objects), a stream (`:`) or a device (`NUL`, `COM1`...). Before any `absolute`, which drops them.
pub(crate) fn check_names(path: &Path) -> io::Result<()> {
    const DEVICES: [&str; 6] = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"];
    let device = |n: &str| {
        let stem = n.split('.').next().unwrap_or(n).trim_end();
        // Bytes, not `str` slices: a name may hold any character.
        let b = stem.as_bytes();
        DEVICES.iter().any(|d| stem.eq_ignore_ascii_case(d))
            || (b.len() == 4
                && [b"COM", b"LPT"]
                    .iter()
                    .any(|p| b[..3].eq_ignore_ascii_case(*p))
                && b[3].is_ascii_digit())
    };
    let plain = path.components().all(|c| match c {
        Component::Normal(n) => {
            let n = n.to_string_lossy();
            !n.contains(':') && !n.ends_with('.') && !n.ends_with(' ') && !device(&n)
        }
        _ => true,
    });
    if plain {
        return Ok(());
    }
    Err(super::refusal(
        io::ErrorKind::InvalidInput,
        format!(
            "{} names a stream, a device or a drive that is not local and fixed",
            path.display()
        ),
    ))
}

fn open_file(path: &Path, read: bool) -> io::Result<std::fs::File> {
    let (root, _) = split(path)?;
    check_names(path)?;
    fixed_drive(&root, path)?;
    let (access, share) = if read {
        (FILE_GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE)
    } else {
        (0, SHARE_ALL)
    };
    let (e, f) = open_with(path, access, share).map_err(|e| {
        if e.raw_os_error() == Some(32) {
            io::Error::new(
                e.kind(),
                format!(
                    "{} is in use by another program in a way that conflicts with a safe read (sharing violation); close it and retry",
                    path.display()
                ),
            )
        } else {
            e
        }
    })?;
    // SAFETY: a valid handle.
    let disk = unsafe { GetFileType(f.as_raw_handle()) } == FILE_TYPE_DISK;
    if e.link {
        return Err(deny(path, "is a link"));
    }
    if let Some(tag) = e.reparse {
        return Err(deny(
            path,
            &format!("is a reparse point (tag {tag:#x}), not a plain file"),
        ));
    }
    if e.dir || !disk {
        return Err(deny(path, "is not a file"));
    }
    let t = Trust::get()?;
    let (owner_ok, ace_ok) = (|s: PSID| t.owner_ok(s), |s: PSID| t.ace_ok(s));
    // SAFETY: the entry's owner and DACL are valid while it lives (all three calls).
    match unsafe { file_refusal(e.owner, e.dacl, &owner_ok, &ace_ok) } {
        None => Ok(f),
        Some(Refusal::Owner) => {
            let who = (!e.owner.is_null())
                .then(|| sid_text(e.owner))
                .flatten()
                .unwrap_or_else(|| "none".into());
            Err(deny(path, &format!("is owned by another user ({who})")))
        }
        Some(Refusal::Writable) => {
            let sids = unsafe { writers(e.dacl, &ace_ok, WRITE_FILE, false) };
            let who = sids
                .as_ref()
                .map_or_else(|| "some cannot be named".into(), |v| v.join(", "));
            Err(deny(
                path,
                &format!(
                    "is writable by other users ({who}): its content may have been changed (check it before you trust it again, then {})",
                    fix(path, sids)
                ),
            ))
        }
    }
}

/// Judges a file of ours by its owner and DACL, without following a final link and without
/// reading its data (it passes while another program has it open). Nothing about what it holds
/// afterwards. Its folder and ancestors are the caller's job (`check_private_dir` first).
/// `NotFound` when absent.
pub fn check_private_file(path: &Path) -> io::Result<()> {
    open_file(path, false).map(drop)
}

/// Opens a file of ours for reading, without following a final link, and judges the opened file:
/// what is read from the handle is what was judged, and no new opening for writing its data gets
/// in while it lives. A file already open for writing is refused. Its folder and ancestors are
/// the caller's job (`check_private_dir` first). `NotFound` when absent.
pub fn open_private_file(path: &Path) -> io::Result<std::fs::File> {
    open_file(path, true)
}

/// Checks that `dir` (absolute, on a fixed local drive) is a folder only this user can change,
/// with ancestors nobody else can change either. `Missing` is not an error: the caller creates it.
pub fn check_private_dir(dir: &Path) -> io::Result<DirState> {
    let (root, names) = split(dir)?;
    fixed_drive(&root, dir)?;
    let t = Trust::get()?;
    let trusted = |s: PSID| t.trusted(s);
    let changeable = |p: &Path, sids: Option<Vec<String>>| {
        deny(
            dir,
            &format!(
                "sits in a folder other users can change: {} (check it, then {})",
                p.display(),
                fix(p, sids)
            ),
        )
    };
    let mut path = root;
    let mut parent: Option<Entry> = None;
    for i in 0..=names.len() {
        if i > 0 {
            path.push(&names[i - 1]);
        }
        let last = i == names.len();
        let e = match open(&path) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(DirState::Missing),
            Err(e) => return Err(e),
        };
        if e.link {
            return Err(if last {
                deny(dir, "is a link")
            } else {
                deny(
                    dir,
                    &format!(
                        "goes through a link: {} (use the real path)",
                        path.display()
                    ),
                )
            });
        }
        if last && !e.dir {
            return Err(deny(dir, "is not a folder"));
        }
        if !t.trusted(e.owner) {
            return Err(if last {
                deny(dir, "is owned by another user")
            } else {
                deny(
                    dir,
                    &format!("sits in a folder owned by another user: {}", path.display()),
                )
            });
        }
        if let Some(p) = &parent {
            let bits = if t.mine(&e) {
                REPLACE_CHILD | ADD_CHILD
            } else {
                REPLACE_CHILD
            };
            // SAFETY: the parent's DACL is valid while it lives (both calls).
            if unsafe { others(p.dacl, &trusted, bits, false) } == Others::Change {
                let sids = unsafe { writers(p.dacl, &trusted, bits, false) };
                return Err(changeable(path.parent().unwrap_or(&path), sids));
            }
        }
        // Inherit-only entries count on the last folder: they reach what is created in it.
        let bits = if last { WRITE_DIR } else { REPLACE_SELF };
        // SAFETY: the entry's DACL is valid while it lives (both calls).
        let grant = unsafe { others(e.dacl, &trusted, bits, last) };
        let sids = || unsafe { writers(e.dacl, &trusted, bits, last) };
        if last {
            return match grant {
                Others::Change => Err(deny(
                    dir,
                    &format!(
                        "is writable by other users (check its files, then {})",
                        fix(dir, sids())
                    ),
                )),
                Others::Read => Ok(DirState::OthersCanRead),
                Others::Nothing => Ok(DirState::Private),
            };
        }
        if grant == Others::Change {
            return Err(changeable(&path, sids()));
        }
        parent = Some(e);
    }
    unreachable!("the last component returns")
}

/// Takes write access away from the SIDs `t` does not trust in the DACL of `dir`, a folder just
/// created, and keeps what they may read: the DACL becomes its own (protected), with the same
/// entries less those rights. Nothing changes when they have none.
fn drop_writes(dir: &Path, t: &Trust) -> io::Result<()> {
    let (e, f) = open_with(dir, WRITE_DAC, SHARE_ALL)?;
    let trusted = |s: PSID| t.trusted(s);
    // SAFETY: the entry's DACL is valid while it lives (also below).
    if e.dacl.is_null() || unsafe { others(e.dacl, &trusted, WRITE_DIR, true) } != Others::Change {
        return Ok(());
    }
    // SAFETY: as above.
    let (rev, size, count) = unsafe {
        (
            u32::from((*e.dacl).AclRevision),
            usize::from((*e.dacl).AclSize),
            u32::from((*e.dacl).AceCount),
        )
    };
    let mut buf = vec![0u64; size.div_ceil(8)];
    let acl = buf.as_mut_ptr().cast::<ACL>();
    // SAFETY: `buf` holds `size` bytes, aligned for an ACL.
    if unsafe { InitializeAcl(acl, size as u32, rev) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let creator = sid(3, &[0]);
    for i in 0..count {
        let mut ace = std::ptr::null_mut();
        // SAFETY: `i` is below the ACE count; the entry is copied out whole, by its own size.
        let mut bytes = unsafe {
            if GetAce(e.dacl, i, &mut ace) == 0 {
                return Err(io::Error::last_os_error());
            }
            let len = usize::from((*ace.cast::<ACE_HEADER>()).AceSize);
            std::slice::from_raw_parts(ace.cast::<u8>(), len).to_vec()
        };
        let (kind, flags) = (bytes[0], u32::from(bytes[1]));
        let mask = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let theirs = match kind {
            1 | 6 | 10 | 12 => false,
            0 => {
                let s: PSID = bytes[8..].as_ptr().cast_mut().cast();
                // SAFETY: an ACCESS_ALLOWED_ACE: its SID follows the mask, inside the copy.
                let is_creator = flags & INHERIT_ONLY_ACE != 0
                    && unsafe { EqualSid(s, creator.as_ptr().cast_mut().cast()) } != 0;
                !t.trusted(s) && !is_creator
            }
            // A grant whose SID is not read here: dropped if it lets anyone write.
            _ if mask & WRITE_DIR != 0 => continue,
            _ => false,
        };
        if theirs {
            let read = if mask & GENERIC_ALL != 0 {
                GENERIC_READ | GENERIC_EXECUTE
            } else {
                0
            };
            let left = (mask | read) & !WRITE_DIR;
            if left == 0 {
                continue;
            }
            bytes[4..8].copy_from_slice(&left.to_le_bytes());
        }
        bytes[1] &= !(INHERITED_ACE as u8);
        // SAFETY: a whole entry of `bytes.len()` bytes; the ACL has room (it only shrinks).
        if unsafe {
            AddAce(
                acl,
                rev,
                u32::MAX,
                bytes.as_ptr().cast(),
                bytes.len() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    // SAFETY: a handle opened with WRITE_DAC and the valid ACL built above.
    let err = unsafe {
        SetSecurityInfo(
            f.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            acl,
            std::ptr::null(),
        )
    };
    if err != 0 {
        return Err(io::Error::from_raw_os_error(err as i32));
    }
    Ok(())
}

/// Like the Unix `create_private_dir`, except that what others may only read is never taken
/// away: an existing folder that passes the check is left as it is (one others can change, a link
/// or another owner's is an error and is left as found). A missing one, and each missing parent,
/// is created with what it inherits, less any write access for others (`drop_writes`). Then the
/// folder is checked again; on failure the folders created here are removed, and any that
/// cannot be is named in the error.
pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    if check_private_dir(dir)? != DirState::Missing {
        return Ok(());
    }
    let t = Trust::get()?;
    let missing: Vec<&Path> = dir
        .ancestors()
        .take_while(|d| std::fs::symlink_metadata(d).is_err())
        .collect();
    let mut made = Vec::new();
    let mut go = || {
        for d in missing.iter().rev() {
            match std::fs::create_dir(d) {
                Ok(()) => made.push(*d),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
            drop_writes(d, &t)?;
        }
        match check_private_dir(dir)? {
            DirState::Missing => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} was removed while being created", dir.display()),
            )),
            _ => Ok(()),
        }
    };
    let Err(e) = go() else {
        return Ok(());
    };
    // A folder made here that cannot be removed is named, not left behind in silence.
    let left: Vec<String> = made
        .iter()
        .rev()
        .filter_map(|d| {
            let r = std::fs::remove_dir(d);
            r.err().map(|x| format!("{} ({x})", d.display()))
        })
        .collect();
    if left.is_empty() {
        return Err(e);
    }
    Err(io::Error::new(
        e.kind(),
        format!("{e}; created here and not removed: {}", left.join(", ")),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn psid(b: &[u64]) -> PSID {
        b.as_ptr().cast_mut().cast()
    }

    /// An ACL built by hand from (type, flags, mask, SID) entries, in a buffer aligned for it.
    fn acl(aces: &[(u8, u8, u32, &[u64])]) -> Vec<u64> {
        let mut body = Vec::new();
        for (kind, flags, mask, sid) in aces {
            // SAFETY: a valid hand-built SID.
            let len = unsafe { windows_sys::Win32::Security::GetLengthSid(psid(sid)) } as usize;
            let bytes = unsafe { std::slice::from_raw_parts(sid.as_ptr().cast::<u8>(), len) };
            body.extend([*kind, *flags]);
            body.extend(((8 + len) as u16).to_le_bytes());
            body.extend(mask.to_le_bytes());
            body.extend(bytes);
        }
        let mut b = vec![2u8, 0];
        b.extend(((8 + body.len()) as u16).to_le_bytes());
        b.extend((aces.len() as u16).to_le_bytes());
        b.extend([0, 0]);
        b.extend(body);
        b.resize(b.len().div_ceil(8) * 8, 0);
        b.chunks(8)
            .map(|c| u64::from_ne_bytes(c.try_into().unwrap()))
            .collect()
    }

    /// T1: the DACL decision on hand-built SIDs and entries.
    #[test]
    fn the_dacl_decision() {
        let (me, other) = (sid(5, &[21, 1, 2, 3, 1001]), sid(5, &[21, 1, 2, 3, 1002]));
        let me2 = me.clone();
        let trusted = |s: PSID| unsafe { EqualSid(s, psid(&me2)) } != 0;
        let judge_io = |aces: &[(u8, u8, u32, &[u64])], bits, io| {
            let a = acl(aces);
            // SAFETY: a valid hand-built ACL.
            unsafe { others(a.as_ptr().cast(), &trusted, bits, io) }
        };
        let judge = |aces: &[(u8, u8, u32, &[u64])], bits| judge_io(aces, bits, false);
        const FULL: u32 = 0x1F_01FF;
        const READ: u32 = 0x12_00A9;
        assert_eq!(judge(&[], WRITE_DIR), Others::Nothing);
        assert_eq!(judge(&[(0, 0, FULL, &me)], WRITE_DIR), Others::Nothing);
        assert_eq!(judge(&[(0, 0, READ, &other)], WRITE_DIR), Others::Read);
        for bit in [
            ADD_FILE,
            ADD_SUBDIRECTORY,
            WRITE_EA,
            DELETE_CHILD,
            WRITE_ATTRIBUTES,
            DELETE,
            WRITE_DAC,
            WRITE_OWNER,
            GENERIC_ALL,
            GENERIC_WRITE,
        ] {
            let aces: [(u8, u8, u32, &[u64]); 2] = [(0, 0, FULL, &me), (0, 0, bit, &other)];
            assert_eq!(judge(&aces, WRITE_DIR), Others::Change, "{bit:#x}");
        }
        // Inherit-only: not for this object, but for what is created in it (`io`), unless it is
        // for CREATOR OWNER. Deny: only takes away.
        assert_eq!(
            judge(&[(0, 0x08, GENERIC_ALL, &other)], WRITE_DIR),
            Others::Nothing
        );
        assert_eq!(
            judge_io(&[(0, 0x09, GENERIC_WRITE, &other)], WRITE_DIR, true),
            Others::Change
        );
        assert_eq!(
            judge_io(&[(0, 0x09, READ, &other)], WRITE_DIR, true),
            Others::Read
        );
        let creator = sid(3, &[0]);
        assert_eq!(
            judge_io(&[(0, 0x0B, GENERIC_ALL, &creator)], WRITE_DIR, true),
            Others::Nothing
        );
        assert_eq!(
            judge(&[(1, 0, GENERIC_ALL, &other)], WRITE_DIR),
            Others::Nothing
        );
        // A grant whose SID and condition are not read here (callback): judged as for others.
        assert_eq!(judge(&[(9, 0, DELETE, &me)], WRITE_DIR), Others::Change);
        assert_eq!(judge(&[(9, 0, READ, &me)], WRITE_DIR), Others::Read);
        // An ancestor: only what replaces it counts; adding entries alone does not.
        assert_eq!(
            judge(&[(0, 0, ADD_FILE, &other)], REPLACE_SELF),
            Others::Read
        );
        assert_eq!(
            judge(&[(0, 0, DELETE, &other)], REPLACE_SELF),
            Others::Change
        );
        assert_eq!(
            judge(&[(0, 0, DELETE_CHILD, &other)], REPLACE_CHILD),
            Others::Change
        );
        assert_eq!(
            judge(&[(0, 0, ADD_SUBDIRECTORY, &other)], ADD_CHILD),
            Others::Change
        );
        // No DACL: everyone has everything.
        // SAFETY: null is allowed.
        assert_eq!(
            unsafe { others(std::ptr::null(), &trusted, WRITE_DIR, false) },
            Others::Change
        );
    }

    /// A fresh folder under the temporary one (which must itself pass: run the suite with TMP in
    /// the user profile, as `cargo xtask ci` does).
    fn base(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fg-pdw-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        create_private_dir(&d).unwrap();
        d
    }

    fn icacls(p: &Path, args: &[&str]) {
        let out = Command::new("icacls").arg(p).args(args).output().unwrap();
        assert!(out.status.success(), "icacls: {out:?}");
    }

    /// Passes: private, or others may only read (what the temporary folder lets them, if any).
    fn passes(p: &Path) {
        let st = check_private_dir(p).unwrap();
        assert_ne!(st, DirState::Missing, "{}", p.display());
    }

    fn err_text(r: io::Result<DirState>) -> String {
        let e = r.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
        e.to_string()
    }

    #[test]
    fn private_dir_rules() {
        let b = base("rules");
        passes(&b);
        assert_eq!(
            check_private_dir(&b.join("nope")).unwrap(),
            DirState::Missing
        );
        // T6: the final folder.
        let r = b.join("readable");
        create_private_dir(&r).unwrap();
        icacls(&r, &["/grant", "*S-1-5-11:(OI)(CI)(RX)"]);
        assert_eq!(check_private_dir(&r).unwrap(), DirState::OthersCanRead);
        let w = b.join("writable");
        create_private_dir(&w).unwrap();
        icacls(&w, &["/grant", "*S-1-5-11:(OI)(CI)(M)"]);
        let t = err_text(check_private_dir(&w));
        assert!(
            t.contains("writable by other users") && t.contains("icacls"),
            "{t}"
        );
        std::fs::write(b.join("f"), b"x").unwrap();
        assert!(err_text(check_private_dir(&b.join("f"))).contains("is not a folder"));
        // T8: the path itself.
        // A2: a refused path is a refusal by the rules (`is_refusal`), like every other one.
        let kind = |p: &Path| {
            let e = check_private_dir(p).unwrap_err();
            assert!(super::super::is_refusal(&e), "{}: {e}", p.display());
            e.kind()
        };
        assert_eq!(kind(Path::new("rel")), io::ErrorKind::InvalidInput);
        assert_eq!(kind(Path::new(r"\no-drive")), io::ErrorKind::InvalidInput);
        let dots = b.join("readable").join("..").join("writable");
        assert_eq!(kind(&dots), io::ErrorKind::InvalidInput);
        let t = err_text(check_private_dir(Path::new(r"\\server\share\data")));
        assert!(t.contains("network"), "{t}");
        let _ = std::fs::remove_dir_all(&b);
    }

    /// T7: what a parent lets others do.
    #[test]
    fn private_dir_ancestors() {
        let b = base("anc");
        // Others may replace any entry of the parent (DELETE_CHILD).
        let dc = b.join("dc");
        create_private_dir(&dc).unwrap();
        icacls(&dc, &["/grant", "*S-1-1-0:(DC)"]);
        let t = create_private_dir(&dc.join("c")).unwrap_err().to_string();
        assert!(t.contains("other users can change"), "{t}");
        std::fs::create_dir(dc.join("c")).unwrap();
        let t = err_text(check_private_dir(&dc.join("c")));
        assert!(t.contains("other users can change"), "{t}");
        // Others may only add entries to the parent: still refused (see T19),
        // for an existing folder and for one about to be created.
        let add = b.join("add");
        create_private_dir(&add).unwrap();
        icacls(&add, &["/grant", "*S-1-1-0:(AD)"]);
        let t = create_private_dir(&add.join("c")).unwrap_err().to_string();
        assert!(t.contains("other users can change"), "{t}");
        assert!(
            !add.join("c").exists(),
            "a refused folder is not left behind"
        );
        create_private_dir(&add.join("x").join("y")).unwrap_err();
        assert!(!add.join("x").exists(), "nor its new parents");
        // Others may change the parent itself.
        let m = b.join("m");
        create_private_dir(&m).unwrap();
        icacls(&m, &["/grant", "*S-1-1-0:(OI)(CI)(M)"]);
        let t = err_text(check_private_dir(&m.join("later")));
        assert!(t.contains("other users can change"), "{t}");
        // Control: others may only read the parent.
        let rx = b.join("rx");
        create_private_dir(&rx).unwrap();
        icacls(&rx, &["/grant", "*S-1-1-0:(OI)(CI)(RX)"]);
        create_private_dir(&rx.join("c")).unwrap();
        passes(&rx.join("c"));
        let _ = std::fs::remove_dir_all(&b);
    }

    /// An entry that applies only to what is created inside still counts for the folder.
    #[test]
    fn an_entry_for_new_files_counts() {
        let b = base("io");
        let w = b.join("w");
        create_private_dir(&w).unwrap();
        icacls(&w, &["/grant", "*S-1-1-0:(OI)(IO)(M)"]);
        let t = err_text(check_private_dir(&w));
        assert!(t.contains("writable by other users"), "{t}");
        // Control: one that only lets others read what is created inside.
        let r = b.join("r");
        create_private_dir(&r).unwrap();
        icacls(&r, &["/grant", "*S-1-1-0:(OI)(IO)(RX)"]);
        check_private_dir(&r).unwrap();
        let _ = std::fs::remove_dir_all(&b);
    }

    /// The command a refusal suggests makes the check pass.
    #[test]
    fn the_suggested_command_fixes_the_folder() {
        let b = base("fix");
        let run = |t: &str| {
            let cmd = &t[t.find("run: ").expect(t) + 5..t.rfind(')').unwrap()];
            use std::os::windows::process::CommandExt;
            let out = Command::new("cmd").arg("/C").raw_arg(cmd).output().unwrap();
            assert!(out.status.success(), "{cmd}: {out:?}");
        };
        let w = b.join("w");
        create_private_dir(&w).unwrap();
        icacls(&w, &["/grant", "*S-1-1-0:(OI)(CI)(M)"]);
        icacls(&w, &["/grant", "*S-1-5-11:(OI)(IO)(M)"]);
        run(&err_text(check_private_dir(&w)));
        check_private_dir(&w).unwrap();
        let p = b.join("p");
        create_private_dir(&p).unwrap();
        icacls(&p, &["/grant", "*S-1-1-0:(DC)"]);
        std::fs::create_dir(p.join("c")).unwrap();
        run(&err_text(check_private_dir(&p.join("c"))));
        check_private_dir(&p.join("c")).unwrap();
        let _ = std::fs::remove_dir_all(&b);
    }

    /// Sets the descriptor of `p` from SDDL.
    fn set_sddl(p: &Path, sddl: &str) {
        use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
        use windows_sys::Win32::Security::SetFileSecurityW;
        let text: Vec<u16> = sddl.encode_utf16().chain([0]).collect();
        let mut sd = std::ptr::null_mut();
        // SAFETY: NUL-terminated strings; `sd` is freed below.
        unsafe {
            let ok = ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                1,
                &mut sd,
                std::ptr::null_mut(),
            );
            assert_ne!(ok, 0, "{sddl}: {}", io::Error::last_os_error());
            let ok = SetFileSecurityW(wide(p).as_ptr(), DACL_SECURITY_INFORMATION, sd);
            let err = io::Error::last_os_error();
            LocalFree(sd);
            assert_ne!(ok, 0, "{}: {err}", p.display());
        }
    }

    /// A grant the check cannot name (a conditional entry for Everyone): no command is offered,
    /// since one that names SIDs would leave it; any command offered must make the check pass.
    #[test]
    fn an_entry_that_cannot_be_named_gets_no_command() {
        let b = base("unnamed");
        let w = b.join("w");
        create_private_dir(&w).unwrap();
        set_sddl(
            &w,
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)\
             (XA;OICI;0x1301bf;;;WD;(Member_of {SID(WD)}))",
        );
        let t = err_text(check_private_dir(&w));
        if let Some(i) = t.find("run: ") {
            use std::os::windows::process::CommandExt;
            let cmd = &t[i + 5..t.rfind(')').unwrap()];
            let out = Command::new("cmd").arg("/C").raw_arg(cmd).output().unwrap();
            assert!(out.status.success(), "{cmd}: {out:?}");
            let after = check_private_dir(&w);
            assert!(
                after.is_ok(),
                "the suggested command left it refused: {after:?}"
            );
        }
        assert!(t.contains("by hand"), "{t}");
        let _ = std::fs::remove_dir_all(&b);
    }

    /// A folder created here that cannot be removed after the refusal is named in the error.
    #[test]
    fn a_created_folder_left_behind_is_reported() {
        let b = base("left");
        let p = b.join("p");
        create_private_dir(&p).unwrap();
        // Others may add entries (refused), and this user may not delete what is created inside.
        icacls(&p, &["/grant", "*S-1-1-0:(AD)"]);
        let me = token_info::<TOKEN_USER>(TokenUser)
            // SAFETY: `token_info` checked the buffer holds a whole TOKEN_USER.
            .and_then(|u| sid_text(unsafe { (*u.as_ptr().cast::<TOKEN_USER>()).User.Sid }))
            .unwrap();
        icacls(&p, &["/deny", &format!("*{me}:(OI)(CI)(IO)(DE,DC)")]);
        let t = create_private_dir(&p.join("x").join("y"))
            .unwrap_err()
            .to_string();
        assert!(t.contains("other users can change"), "{t}");
        assert!(p.join("x").join("y").exists(), "premise: the folder stayed");
        assert!(t.contains("not removed") && t.contains("y"), "{t}");
        icacls(&b, &["/reset", "/T"]);
        let _ = std::fs::remove_dir_all(&b);
    }

    /// T5: a junction as the folder or as an ancestor is refused, wherever it points.
    #[test]
    fn a_junction_anywhere_in_the_path_is_refused() {
        let b = base("junction");
        let real = b.join("real");
        create_private_dir(&real.join("c")).unwrap();
        let j = b.join("j");
        let out = Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&j)
            .arg(&real)
            .output()
            .unwrap();
        assert!(out.status.success(), "mklink: {out:?}");
        assert!(err_text(check_private_dir(&j)).contains("is a link"));
        let t = err_text(check_private_dir(&j.join("c")));
        assert!(t.contains("goes through a link"), "{t}");
        assert!(create_private_dir(&j.join("new")).is_err());
        assert!(!real.join("new").exists());
        // Control: the real path passes.
        passes(&real.join("c"));
        std::fs::remove_dir(&j).unwrap();
        let _ = std::fs::remove_dir_all(&b);
    }

    /// Runs `f` on this thread as this same user through a write-restricted token (restricting
    /// SID Everyone).
    fn as_restricted<T>(f: impl FnOnce() -> T) -> T {
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::Security::{
            CreateRestrictedToken, DuplicateTokenEx, ImpersonateLoggedOnUser, RevertToSelf,
            SID_AND_ATTRIBUTES, SecurityImpersonation, TOKEN_ALL_ACCESS, TOKEN_ASSIGN_PRIMARY,
            TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY, TokenImpersonation, WRITE_RESTRICTED,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        let everyone = sid(1, &[0]);
        let restrict = SID_AND_ATTRIBUTES {
            Sid: psid(&everyone),
            Attributes: 0,
        };
        let (mut tok, mut rt, mut imp): (HANDLE, HANDLE, HANDLE) = (
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        let access = TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE;
        // SAFETY: valid out pointers; every handle opened here is closed below.
        unsafe {
            assert_ne!(OpenProcessToken(GetCurrentProcess(), access, &mut tok), 0);
            let ok = CreateRestrictedToken(
                tok,
                WRITE_RESTRICTED,
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                1,
                &restrict,
                &mut rt,
            );
            assert_ne!(ok, 0, "CreateRestrictedToken");
            let ok = DuplicateTokenEx(
                rt,
                TOKEN_ALL_ACCESS,
                std::ptr::null(),
                SecurityImpersonation,
                TokenImpersonation,
                &mut imp,
            );
            assert_ne!(ok, 0, "DuplicateTokenEx");
            assert_ne!(ImpersonateLoggedOnUser(imp), 0, "ImpersonateLoggedOnUser");
        }
        let out = f();
        // SAFETY: undoes the impersonation above and closes the three handles once.
        unsafe {
            RevertToSelf();
            CloseHandle(imp);
            CloseHandle(rt);
            CloseHandle(tok);
        }
        out
    }

    /// T19: a parent that lets others add entries is refused, also for a restricted token of this
    /// same user; with a parent that gives it nothing, the folder stays where it is.
    #[test]
    fn a_parent_that_lets_others_add_is_refused() {
        let b = base("t19");
        let safe = b.join("safe");
        create_private_dir(&safe.join("data")).unwrap();
        passes(&safe.join("data"));
        let moved = as_restricted(|| std::fs::rename(safe.join("data"), safe.join("moved")));
        assert!(moved.is_err(), "a folder the check passes was moved");
        assert!(safe.join("data").is_dir());

        let open = b.join("open");
        create_private_dir(&open).unwrap();
        icacls(&open, &["/grant", "*S-1-1-0:(AD)"]);
        std::fs::create_dir(open.join("data")).unwrap();
        let t = err_text(check_private_dir(&open.join("data")));
        assert!(t.contains("other users can change"), "{t}");
        let moved = as_restricted(|| std::fs::rename(open.join("data"), open.join("moved")));
        assert!(moved.is_ok(), "premise: {moved:?}");
        let _ = std::fs::remove_dir_all(&b);
    }

    /// Step 12, read only: the real data and shims folders of this machine, as they are, and every
    /// file of theirs that sync_gate trusts, opened and read to the end (only the size is printed).
    /// Writes nothing. `cargo test -p sync_gate_core -- --ignored real_folders`.
    #[test]
    #[ignore = "reads this machine's real folders"]
    fn real_folders() {
        use std::io::Read;
        let mut bad = 0;
        let dirs: Vec<PathBuf> = [crate::data_dir(), crate::shims_dir()]
            .into_iter()
            .flatten()
            .collect();
        // A folder that is missing proves nothing about this installation: it fails too.
        for d in &dirs {
            let r = check_private_dir(d);
            println!("{}: {r:?}", d.display());
            if !matches!(r, Ok(DirState::Private | DirState::OthersCanRead)) {
                bad += 1;
            }
        }
        let mut files = Vec::new();
        // Every entry of `d` but folders; `d` absent is no entry, any other error counts.
        let mut list = |d: &Path, files: &mut Vec<PathBuf>| match std::fs::read_dir(d) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => println!("no folder {}", d.display()),
            Err(e) => {
                bad += 1;
                println!("ERROR listing {}: {e}", d.display());
            }
            Ok(rd) => {
                for e in rd {
                    match e.and_then(|e| Ok((e.file_type()?, e.path()))) {
                        Ok((t, p)) if !t.is_dir() => files.push(p),
                        Ok(_) => {}
                        Err(e) => {
                            bad += 1;
                            println!("ERROR listing {}: {e}", d.display());
                        }
                    }
                }
            }
        };
        if let Some(d) = crate::data_dir() {
            for n in [
                "mcp-adopted.json",
                "services.json",
                "cost.json",
                "paused.json",
                "paused-guests.json",
            ] {
                files.push(d.join(n));
            }
            list(&d.join("pending"), &mut files);
        }
        if let Some(d) = crate::shims_dir() {
            list(&d, &mut files);
        }
        match std::env::var_os("SYNC_GATE_CONFIG") {
            Some(c) => files.push(PathBuf::from(c)),
            None => files.extend(
                directories::ProjectDirs::from("dev", "sync_labs", "sync_gate")
                    .map(|c| c.config_dir().join("config.toml")),
            ),
        }
        for f in files {
            let r = open_private_file(&f).and_then(|mut h| {
                let mut n = Vec::new();
                h.read_to_end(&mut n).map(|_| n.len())
            });
            match r {
                Ok(n) => println!("ok {n} {}", f.display()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    println!("missing {}", f.display())
                }
                Err(e) => {
                    bad += 1;
                    println!("ERROR {}: {e}", f.display());
                }
            }
        }
        assert_eq!(bad, 0);
    }

    fn me() -> String {
        token_info::<TOKEN_USER>(TokenUser)
            // SAFETY: `token_info` checked the buffer holds a whole TOKEN_USER.
            .and_then(|u| sid_text(unsafe { (*u.as_ptr().cast::<TOKEN_USER>()).User.Sid }))
            .unwrap()
    }

    fn file_err(r: io::Result<impl Sized>) -> io::Error {
        match r {
            Ok(_) => panic!("accepted"),
            Err(e) => e,
        }
    }

    fn refused_with(r: io::Result<impl Sized>, what: &str) -> String {
        let e = file_err(r);
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
        let t = e.to_string();
        assert!(t.contains(what), "{t}");
        t
    }

    fn read_all(p: &Path) -> io::Result<String> {
        use std::io::Read;
        let mut s = String::new();
        open_private_file(p)?.read_to_string(&mut s)?;
        Ok(s)
    }

    /// F1: the file decision on hand-built SIDs and entries.
    #[test]
    fn the_file_decision() {
        let (me, other) = (sid(5, &[21, 1, 2, 3, 1001]), sid(5, &[21, 1, 2, 3, 1002]));
        let (ba, sy, ow) = (sid(5, &[32, 544]), sid(5, &[18]), sid(3, &[4]));
        let ti = sid(
            5,
            &[
                80, 956008885, 3418522649, 1831038044, 1853292631, 2271478464,
            ],
        );
        let eq = |a: PSID, b: &[u64]| unsafe { EqualSid(a, psid(b)) } != 0;
        let owner_ok = |s: PSID| [&me, &ba, &sy, &ti].iter().any(|t| eq(s, t));
        let ace_ok = |s: PSID| owner_ok(s) || eq(s, &ow);
        let judge = |owner: &[u64], aces: &[(u8, u8, u32, &[u64])]| {
            let a = acl(aces);
            // SAFETY: a valid hand-built SID and ACL.
            unsafe { file_refusal(psid(owner), a.as_ptr().cast(), &owner_ok, &ace_ok) }
        };
        const FULL: u32 = 0x1F_01FF;
        const RX: u32 = 0x12_00A9;
        for o in [&me, &ba, &sy, &ti] {
            assert_eq!(judge(o, &[(0, 0, FULL, &me)]), None);
        }
        assert_eq!(judge(&ow, &[]), Some(Refusal::Owner));
        assert_eq!(judge(&other, &[(0, 0, FULL, &me)]), Some(Refusal::Owner));
        for bit in [
            WRITE_DATA,
            APPEND_DATA,
            WRITE_EA,
            WRITE_ATTRIBUTES,
            DELETE,
            WRITE_DAC,
            WRITE_OWNER,
            GENERIC_WRITE,
            GENERIC_ALL,
        ] {
            assert_eq!(
                judge(&me, &[(0, 0, FULL, &me), (0, 0, bit, &other)]),
                Some(Refusal::Writable),
                "{bit:#x}"
            );
        }
        assert_eq!(judge(&me, &[(0, 0, FULL, &ow)]), None);
        assert_eq!(judge(&me, &[(0, 0, RX, &other)]), None);
        assert_eq!(judge(&me, &[(0, 0x08, GENERIC_ALL, &other)]), None);
        assert_eq!(judge(&me, &[(1, 0, GENERIC_ALL, &other)]), None);
        assert_eq!(
            judge(&me, &[(9, 0, WRITE_DATA, &me)]),
            Some(Refusal::Writable)
        );
        // No DACL: everyone has everything.
        // SAFETY: null is allowed for the DACL.
        let nul = unsafe { file_refusal(psid(&me), std::ptr::null(), &owner_ok, &ace_ok) };
        assert_eq!(nul, Some(Refusal::Writable));
        // This process's own rule: Administrators may own a file, OWNER RIGHTS and others may not.
        let t = Trust::get().unwrap();
        assert!(t.owner_ok(psid(&ba)) && t.owner_ok(psid(&sy)) && t.owner_ok(psid(&ti)));
        assert!(t.owner_ok(t.user));
        assert!(!t.owner_ok(psid(&ow)) && !t.owner_ok(psid(&other)));
        assert!(t.ace_ok(psid(&ow)) && !t.ace_ok(psid(&other)));
    }

    /// F2-F4: a file of ours passes and is read; one others can write is refused, and the
    /// command the refusal offers makes it pass.
    #[test]
    fn private_file_rules() {
        let b = base("file");
        let f = b.join("config.toml");
        std::fs::write(&f, "x").unwrap();
        assert_eq!(read_all(&f).unwrap(), "x");
        check_private_file(&f).unwrap();
        // F3: an explicit grant to Everyone.
        icacls(&f, &["/grant", "*S-1-1-0:(W)"]);
        let t = refused_with(read_all(&f), "is writable by other users (S-1-1-0)");
        refused_with(check_private_file(&f), "writable");
        let cmd = &t[t.find("run: ").expect(&t) + 5..t.rfind(')').unwrap()];
        use std::os::windows::process::CommandExt;
        let out = Command::new("cmd").arg("/C").raw_arg(cmd).output().unwrap();
        assert!(out.status.success(), "{cmd}: {out:?}");
        assert_eq!(read_all(&f).unwrap(), "x");
        // F4: a protected DACL that grants only Everyone (M).
        let g = b.join("g");
        std::fs::write(&g, "x").unwrap();
        icacls(&g, &["/inheritance:r", "/grant", "*S-1-1-0:(M)"]);
        refused_with(read_all(&g), "writable by other users");
        // Others may read and run it: still ours.
        let r = b.join("r");
        std::fs::write(&r, "x").unwrap();
        icacls(&r, &["/grant", "*S-1-5-32-545:(RX)"]);
        assert_eq!(read_all(&r).unwrap(), "x");
        icacls(&b, &["/reset", "/T"]);
        let _ = std::fs::remove_dir_all(&b);
    }

    /// F4b: what a file inherits from its folder counts.
    #[test]
    fn an_inherited_grant_counts() {
        let b = base("inh");
        let d = b.join("d");
        create_private_dir(&d).unwrap();
        icacls(&d, &["/grant", "*S-1-5-32-545:(OI)(RX)"]);
        let f = d.join("f");
        std::fs::write(&f, "x").unwrap();
        assert_eq!(read_all(&f).unwrap(), "x");
        // Granted on the folder after the file exists: propagated to it as inherited (M).
        icacls(&d, &["/grant", "*S-1-5-32-545:(OI)(M)"]);
        refused_with(read_all(&f), "writable by other users (S-1-5-32-545)");
        let _ = std::fs::remove_dir_all(&b);
    }

    /// F5: not a file, absent, a junction, a file link.
    #[test]
    fn a_file_that_is_not_plain_is_refused() {
        let b = base("kind");
        refused_with(read_all(&b), "is not a file");
        refused_with(check_private_file(&b), "is not a file");
        assert_eq!(
            file_err(read_all(&b.join("absent"))).kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            file_err(check_private_file(&b.join("absent"))).kind(),
            io::ErrorKind::NotFound
        );
        let real = b.join("real");
        std::fs::create_dir(&real).unwrap();
        let j = b.join("j");
        let out = Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&j)
            .arg(&real)
            .output()
            .unwrap();
        assert!(out.status.success(), "mklink: {out:?}");
        refused_with(read_all(&j), "is a link");
        let f = b.join("f");
        std::fs::write(&f, "x").unwrap();
        let l = b.join("l");
        match std::os::windows::fs::symlink_file(&f, &l) {
            Ok(()) => {
                refused_with(read_all(&l), "is a link");
                refused_with(check_private_file(&l), "is a link");
            }
            Err(e) => println!("skipped: file symlink ({e})"),
        }
        std::fs::remove_dir(&j).unwrap();
        let _ = std::fs::remove_dir_all(&b);
    }

    /// F6: a hard link shares the file's descriptor: both names pass, and a grant made through
    /// one name is refused through both.
    #[test]
    fn a_hard_link_has_the_file_s_descriptor() {
        let b = base("hard");
        let f = b.join("f");
        std::fs::write(&f, "x").unwrap();
        let g = b.join("g");
        std::fs::hard_link(&f, &g).unwrap();
        assert_eq!(read_all(&f).unwrap(), "x");
        assert_eq!(read_all(&g).unwrap(), "x");
        icacls(&g, &["/grant", "*S-1-1-0:(W)"]);
        refused_with(read_all(&f), "writable");
        refused_with(read_all(&g), "writable");
        let _ = std::fs::remove_dir_all(&b);
    }

    /// F7: a file open for writing elsewhere is not read; the inspection alone passes; a
    /// replacement by rename while our handle lives leaves what the handle reads whole.
    #[test]
    fn a_file_open_for_writing_is_not_read() {
        use std::io::Read;
        let b = base("share");
        let f = b.join("f");
        std::fs::write(&f, "old").unwrap();
        let w = std::fs::OpenOptions::new().write(true).open(&f).unwrap();
        let t = file_err(read_all(&f)).to_string();
        assert!(t.contains("sharing violation"), "{t}");
        check_private_file(&f).unwrap();
        drop(w);
        let mut h = open_private_file(&f).unwrap();
        let tmp = b.join("f.tmp");
        std::fs::write(&tmp, "new").unwrap();
        std::fs::rename(&tmp, &f).unwrap();
        let mut s = String::new();
        h.read_to_string(&mut s).unwrap();
        assert_eq!(s, "old");
        drop(h);
        assert_eq!(read_all(&f).unwrap(), "new");
        let _ = std::fs::remove_dir_all(&b);
    }

    /// F7b: a program that is running can be judged (opened for reading).
    #[test]
    fn a_running_program_can_be_judged() {
        let b = base("run");
        let exe = b.join("p.exe");
        let sys = std::env::var_os("SystemRoot").unwrap();
        std::fs::copy(Path::new(&sys).join(r"System32\PING.EXE"), &exe).unwrap();
        let mut child = Command::new(&exe)
            .args(["-n", "5", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
        let r = open_private_file(&exe).map(drop);
        let _ = child.kill();
        let _ = child.wait();
        r.unwrap();
        let _ = std::fs::remove_dir_all(&b);
    }

    /// F8: a write-restricted token of this same user reads a file of this user.
    #[test]
    fn a_restricted_token_of_this_user_reads_its_file() {
        let b = base("restr");
        let f = b.join("config.toml");
        std::fs::write(&f, "x").unwrap();
        assert_eq!(as_restricted(|| read_all(&f)).unwrap(), "x");
        let _ = std::fs::remove_dir_all(&b);
    }

    /// F9: streams, devices, shares, and names the Win32 layer would change are refused; a
    /// verbatim path to a plain file is read as the same file.
    #[test]
    fn a_path_that_is_not_a_plain_local_file_is_refused() {
        let b = base("path");
        let f = b.join("config.toml");
        std::fs::write(&f, "x").unwrap();
        // A refusal by the rules (`is_refusal`), never an error of the system that a retry or
        // another spelling could get past.
        let bad = |p: &str| {
            for e in [
                file_err(read_all(Path::new(p))),
                file_err(check_private_file(Path::new(p))),
            ] {
                assert!(super::super::is_refusal(&e), "{p}: {e} ({:?})", e.kind());
            }
        };
        let s = f.display().to_string();
        bad(&format!("{s}:alt"));
        bad(&format!("{s}::$DATA"));
        bad(&format!("{s}."));
        bad(&format!("{s} "));
        bad(&format!(r"\\?\{s}."));
        bad(&format!(r"\\?\{s} "));
        bad(r"\\?\GLOBALROOT\Device\HarddiskVolume1\x");
        bad(r"\\server\share\f");
        bad(r"\\.\NUL");
        bad(&format!(r"{}\NUL", b.display()));
        bad(&format!(r"{}\com1.txt", b.display()));
        bad("config.toml");
        let dotted = b.join("d.").join("f");
        bad(&dotted.display().to_string());
        assert_eq!(read_all(Path::new(&format!(r"\\?\{s}"))).unwrap(), "x");
        // Names that only look like a device are plain files: a non-ASCII 4-byte name included
        // (the device check must not cut a character in two).
        for n in ["abİ", "COMx", "console"] {
            let g = b.join(n);
            std::fs::write(&g, "y").unwrap();
            assert_eq!(read_all(&g).unwrap(), "y", "{n}");
        }
        let _ = std::fs::remove_dir_all(&b);
    }

    /// F10: a reparse point that is not a link is refused too. WOF compression here leaves no
    /// reparse point (step S5: attributes 0x20), so the test sets one itself: a third-party tag
    /// (neither the Microsoft bit nor the name-surrogate bit), which a user may set on a file of
    /// theirs.
    #[test]
    fn a_reparse_point_that_is_not_a_link_is_refused() {
        use windows_sys::Win32::System::IO::DeviceIoControl;
        const FSCTL_SET_REPARSE_POINT: u32 = 0x0009_00A4;
        const TAG: u32 = 0x0000_1234;
        let b = base("rp");
        let f = b.join("f");
        std::fs::write(&f, "x").unwrap();
        assert_eq!(read_all(&f).unwrap(), "x");
        // REPARSE_GUID_DATA_BUFFER: tag, data length, reserved, GUID, data.
        let mut buf = Vec::new();
        buf.extend(TAG.to_le_bytes());
        buf.extend(4u16.to_le_bytes());
        buf.extend(0u16.to_le_bytes());
        buf.extend([0x5a_u8; 16]);
        buf.extend([1u8, 2, 3, 4]);
        let h = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&f)
            .unwrap();
        let mut n = 0;
        // SAFETY: a valid handle and an input buffer of the length passed.
        let ok = unsafe {
            DeviceIoControl(
                h.as_raw_handle(),
                FSCTL_SET_REPARSE_POINT,
                buf.as_ptr().cast(),
                buf.len() as u32,
                std::ptr::null_mut(),
                0,
                &mut n,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(ok, 0, "set reparse point: {}", io::Error::last_os_error());
        drop(h);
        refused_with(
            read_all(&f),
            "is a reparse point (tag 0x1234), not a plain file",
        );
        refused_with(check_private_file(&f), "is a reparse point (tag 0x1234)");
        let _ = std::fs::remove_dir_all(&b);
    }

    /// The owner of a file is judged: one owned by a SID outside the boundary is refused even
    /// with a clean DACL. Setting another owner needs SeRestorePrivilege, so this runs only when
    /// asked for (elevated): `cargo test -p sync_gate_core -- --ignored another_owner`. It fails,
    /// never passes, when it cannot set the owner. Without it the rule is proven by `the_file_decision`.
    #[test]
    #[ignore = "needs SeRestorePrivilege: run elevated"]
    fn a_file_of_another_owner_is_refused() {
        let b = base("own");
        let f = b.join("f");
        std::fs::write(&f, "x").unwrap();
        let out = Command::new("icacls")
            .arg(&f)
            .args(["/setowner", "*S-1-5-32-545"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "cannot set another owner ({}): {out:?}",
            me()
        );
        refused_with(read_all(&f), "is owned by another user (S-1-5-32-545)");
        let _ = std::fs::remove_dir_all(&b);
    }
}
