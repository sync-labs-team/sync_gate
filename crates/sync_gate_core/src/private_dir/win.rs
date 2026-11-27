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
use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
    GetSecurityDescriptorDacl, INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    TOKEN_OWNER, TOKEN_USER, TokenOwner, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_READ_ATTRIBUTES, GetDriveTypeW, READ_CONTROL,
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
const GENERIC_WRITE: u32 = 0x4000_0000;

/// On an entry: lets the holder replace that entry.
const REPLACE_SELF: u32 = DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL;
/// On a folder: lets the holder replace any entry in it.
const REPLACE_CHILD: u32 = DELETE_CHILD | WRITE_DAC | WRITE_OWNER | GENERIC_ALL;
/// On a folder: lets the holder add an entry. A restricted token of this same user (a sandbox)
/// gets DELETE on our own entries from our own grant, so with these on the parent it can rename
/// our folder away and create its own under the name.
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

/// What `dacl` grants SIDs that `trusted` rejects: `Change` for any of `bits`, also for a grant
/// whose SID or condition is not read here (object, callback, compound) and for no DACL at all
/// (everyone has everything); `Read` for any other right. Inherit-only entries do not apply to
/// the object and deny entries only take away: both are skipped.
///
/// # Safety
/// `dacl` must be null or point to a valid ACL for the whole call.
unsafe fn others(dacl: *const ACL, trusted: &dyn Fn(PSID) -> bool, bits: u32) -> Others {
    if dacl.is_null() {
        return Others::Change;
    }
    let mut seen = Others::Nothing;
    // SAFETY: `dacl` is a valid ACL (caller).
    for i in 0..u32::from(unsafe { (*dacl).AceCount }) {
        let mut ace = std::ptr::null_mut();
        // SAFETY: `i` is below the ACE count; `ace` is a valid out pointer.
        if unsafe { GetAce(dacl, i, &mut ace) } == 0 {
            return Others::Change;
        }
        // SAFETY: GetAce points `ace` at an entry inside the ACL; every entry starts with a
        // header followed by its access mask.
        let (head, mask) = unsafe {
            let a = ace.cast::<ACCESS_ALLOWED_ACE>();
            ((*a).Header, (*a).Mask)
        };
        if u32::from(head.AceFlags) & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        match head.AceType {
            // ACCESS_DENIED, _OBJECT, _CALLBACK, _CALLBACK_OBJECT.
            1 | 6 | 10 | 12 => continue,
            0 => {
                // SAFETY: an ACCESS_ALLOWED_ACE: its SID starts at `SidStart`, inside the entry.
                let sid = unsafe { (&raw const (*ace.cast::<ACCESS_ALLOWED_ACE>()).SidStart) };
                if trusted(sid.cast_mut().cast()) {
                    continue;
                }
            }
            _ => {}
        }
        if mask & bits != 0 {
            return Others::Change;
        }
        if mask != 0 {
            seen = Others::Read;
        }
    }
    seen
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
    /// this user DELETE. Then a sandbox of ours can delete it too, and its parent must not let
    /// others add entries.
    fn mine(&self, e: &Entry) -> bool {
        let is = |a: PSID, b: PSID| !a.is_null() && unsafe { EqualSid(a, b) } != 0;
        let not_user = |s: PSID| !is(s, self.user);
        is(e.owner, self.user)
            || is(e.owner, self.owner)
            // SAFETY: the entry's DACL is valid while it lives.
            || unsafe { others(e.dacl, &not_user, DELETE | GENERIC_ALL) } == Others::Change
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
    let f = std::fs::OpenOptions::new()
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
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
    Ok(Entry {
        sd,
        owner,
        dacl,
        dir: attrs & 0x10 != 0,
        link: attrs & 0x400 != 0 && is_name_surrogate(tag),
    })
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

/// The command that makes `p` private, for the messages.
fn fix(p: &Path) -> String {
    format!(
        r#"icacls "{}" /inheritance:r /grant:r "%USERNAME%:(OI)(CI)F" *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F"#,
        p.display()
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
    let changeable = |p: &Path| {
        deny(
            dir,
            &format!(
                "sits in a folder other users can change: {} (check it, then run: {})",
                p.display(),
                fix(p)
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
                changeable(&path)
            });
        }
        if let Some(p) = &parent {
            let bits = if t.mine(&e) {
                REPLACE_CHILD | ADD_CHILD
            } else {
                REPLACE_CHILD
            };
            // SAFETY: the parent's DACL is valid while it lives.
            if unsafe { others(p.dacl, &trusted, bits) } == Others::Change {
                return Err(changeable(path.parent().unwrap_or(&path)));
            }
        }
        // SAFETY: the entry's DACL is valid while it lives.
        let grant = unsafe {
            others(
                e.dacl,
                &trusted,
                if last { WRITE_DIR } else { REPLACE_SELF },
            )
        };
        if last {
            return match grant {
                Others::Change => Err(deny(
                    dir,
                    &format!(
                        "is writable by other users (check its files, then run: {})",
                        fix(dir)
                    ),
                )),
                Others::Read => Ok(DirState::OthersCanRead),
                Others::Nothing => Ok(DirState::Private),
            };
        }
        if grant == Others::Change {
            return Err(changeable(&path));
        }
        parent = Some(e);
    }
    unreachable!("the last component returns")
}

/// A security descriptor made from SDDL, freed on drop.
struct Descriptor(PSECURITY_DESCRIPTOR);

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW; freed once.
        unsafe { LocalFree(self.0) };
    }
}

impl Descriptor {
    /// Owner: this user. DACL, protected and inherited by what is created inside: full access
    /// for this user, SYSTEM and Administrators, nobody else.
    fn private() -> io::Result<Self> {
        let u = token_info::<TOKEN_USER>(TokenUser)
            .ok_or_else(|| io::Error::other("cannot read this process's token"))?;
        let mut text = std::ptr::null_mut();
        // SAFETY: `token_info` checked the buffer holds a whole TOKEN_USER, whose SID points
        // inside it; `text` is freed below.
        if unsafe { ConvertSidToStringSidW((*u.as_ptr().cast::<TOKEN_USER>()).User.Sid, &mut text) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `text` is a NUL-terminated string allocated by the call above, freed once.
        let user = unsafe {
            let len = (0..).take_while(|&i| *text.add(i) != 0).count();
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
            LocalFree(text.cast());
            s
        };
        let sddl = format!("O:{user}D:P(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
        let sddl: Vec<u16> = sddl.encode_utf16().chain([0]).collect();
        let mut sd = std::ptr::null_mut();
        // SAFETY: a NUL-terminated string; `sd` is freed by the Descriptor.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(sd))
    }
}

/// Like the Unix `create_private_dir`: an existing folder is checked first (one others can
/// change, a link or another owner's is an error and is left as found; one others can only read
/// gets the private DACL, which also reaches what it holds); a missing one, and each missing
/// parent, is created with the private descriptor. Then the folder is checked again.
pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    match check_private_dir(dir)? {
        DirState::Private => return Ok(()),
        DirState::OthersCanRead => {
            let sd = Descriptor::private()?;
            let (mut present, mut dacl, mut defaulted) = (0, std::ptr::null_mut(), 0);
            // SAFETY: a valid descriptor; the out pointers are valid; `dacl` points into `sd`.
            if unsafe { GetSecurityDescriptorDacl(sd.0, &mut present, &mut dacl, &mut defaulted) }
                == 0
            {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: a NUL-terminated path and the valid DACL above.
            let err = unsafe {
                SetNamedSecurityInfoW(
                    wide(dir).as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    dacl,
                    std::ptr::null(),
                )
            };
            if err != 0 {
                return Err(io::Error::from_raw_os_error(err as i32));
            }
        }
        DirState::Missing => {
            let sd = Descriptor::private()?;
            let sa = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd.0,
                bInheritHandle: 0,
            };
            let missing: Vec<&Path> = dir
                .ancestors()
                .take_while(|d| std::fs::symlink_metadata(d).is_err())
                .collect();
            for d in missing.iter().rev() {
                // SAFETY: a NUL-terminated path and valid attributes.
                if unsafe { CreateDirectoryW(wide(d).as_ptr(), &sa) } == 0 {
                    let e = io::Error::last_os_error();
                    if e.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
                        return Err(e);
                    }
                }
            }
        }
    }
    check_private_dir(dir).map(|_| ())
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
        let judge = |aces: &[(u8, u8, u32, &[u64])], bits| {
            let a = acl(aces);
            // SAFETY: a valid hand-built ACL.
            unsafe { others(a.as_ptr().cast(), &trusted, bits) }
        };
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
        // Inherit-only: not for this object. Deny: only takes away.
        assert_eq!(
            judge(&[(0, 0x08, GENERIC_ALL, &other)], WRITE_DIR),
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
            unsafe { others(std::ptr::null(), &trusted, WRITE_DIR) },
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

    fn err_text(r: io::Result<DirState>) -> String {
        let e = r.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
        e.to_string()
    }

    #[test]
    fn private_dir_rules() {
        let b = base("rules");
        assert_eq!(check_private_dir(&b).unwrap(), DirState::Private);
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
        create_private_dir(&dc.join("c")).unwrap_err();
        let t = err_text(check_private_dir(&dc.join("c")));
        assert!(t.contains("other users can change"), "{t}");
        // Others may only add entries to the parent: still refused (see the swap test below),
        // for an existing folder and for one about to be created.
        let add = b.join("add");
        create_private_dir(&add).unwrap();
        icacls(&add, &["/grant", "*S-1-1-0:(AD)"]);
        let t = create_private_dir(&add.join("c")).unwrap_err().to_string();
        assert!(t.contains("other users can change"), "{t}");
        assert!(add.join("c").is_dir());
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
        assert_eq!(check_private_dir(&rx.join("c")).unwrap(), DirState::Private);
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
        assert_eq!(
            check_private_dir(&real.join("c")).unwrap(),
            DirState::Private
        );
        std::fs::remove_dir(&j).unwrap();
        let _ = std::fs::remove_dir_all(&b);
    }

    /// Runs `f` on this thread as this same user through a token restricted the way sandboxes
    /// restrict it (write-restricted, restricting SID Everyone).
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

    /// T19: why a parent that only lets others add entries is refused. A sandbox of this same
    /// user moves our folder away (and could create its own under the name) when the parent lets
    /// Everyone add a folder; it cannot when the parent gives it nothing.
    #[test]
    fn a_sandbox_of_ours_can_swap_a_folder_whose_parent_lets_others_add() {
        let b = base("swap");
        let safe = b.join("safe");
        create_private_dir(&safe.join("data")).unwrap();
        assert_eq!(
            check_private_dir(&safe.join("data")).unwrap(),
            DirState::Private
        );
        let moved = as_restricted(|| std::fs::rename(safe.join("data"), safe.join("moved")));
        assert!(
            moved.is_err(),
            "the sandbox moved a folder the check passes"
        );
        assert!(safe.join("data").is_dir());

        let open = b.join("open");
        create_private_dir(&open).unwrap();
        icacls(&open, &["/grant", "*S-1-1-0:(AD)"]);
        let t = create_private_dir(&open.join("data"))
            .unwrap_err()
            .to_string();
        assert!(t.contains("other users can change"), "{t}");
        let moved = as_restricted(|| std::fs::rename(open.join("data"), open.join("moved")));
        assert!(moved.is_ok(), "premise: the sandbox moves it: {moved:?}");
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
