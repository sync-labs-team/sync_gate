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
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, GetDriveTypeW,
    READ_CONTROL,
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
}

impl Drop for Entry {
    fn drop(&mut self) {
        // SAFETY: allocated by GetSecurityInfo for this entry; freed once.
        unsafe { LocalFree(self.sd) };
    }
}

fn open(path: &Path) -> io::Result<Entry> {
    open_with(path, 0).map(|(e, _)| e)
}

/// `open`, opened with `extra` access too, with its handle.
fn open_with(path: &Path, extra: u32) -> io::Result<(Entry, std::fs::File)> {
    let f = std::fs::OpenOptions::new()
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES | extra)
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
    };
    Ok((e, f))
}

/// The drive root (`C:\`) and the names under it; a path on a share is refused.
fn split(dir: &Path) -> io::Result<(PathBuf, Vec<OsString>)> {
    let invalid = |why: &str| {
        io::Error::new(
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

/// Checks that `dir` (absolute, on a fixed local drive) is a folder only this user can change,
/// with ancestors nobody else can change either. `Missing` is not an error: the caller creates it.
pub fn check_private_dir(dir: &Path) -> io::Result<DirState> {
    let (root, names) = split(dir)?;
    // SAFETY: a NUL-terminated path.
    if unsafe { GetDriveTypeW(wide(&root).as_ptr()) } != DRIVE_FIXED {
        return Err(deny(
            dir,
            "is not on a fixed local drive (network and removable drives are refused)",
        ));
    }
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
    let (e, f) = open_with(dir, WRITE_DAC)?;
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
        let kind = |p: &str| check_private_dir(Path::new(p)).unwrap_err().kind();
        assert_eq!(kind("rel"), io::ErrorKind::InvalidInput);
        assert_eq!(kind(r"\no-drive"), io::ErrorKind::InvalidInput);
        let dots = b.join("readable").join("..").join("writable");
        assert_eq!(
            check_private_dir(&dots).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
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

    /// Step 12, read only: the real data and shims folders of this machine, as they are. Prints
    /// the state; writes nothing. `cargo test -p sync_gate_core -- --ignored real_folders`.
    #[test]
    #[ignore = "reads this machine's real folders"]
    fn real_folders() {
        for d in [crate::data_dir(), crate::shims_dir()]
            .into_iter()
            .flatten()
        {
            println!("{}: {:?}", d.display(), check_private_dir(&d));
            assert!(check_private_dir(&d).is_ok());
        }
    }
}
