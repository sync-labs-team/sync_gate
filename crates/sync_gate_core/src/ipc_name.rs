//! Single place that maps a socket name string to an `interprocess` name, and that connects to
//! the daemon (control or hub socket) only after checking the server is the current user's.

use interprocess::local_socket::{GenericFilePath, GenericNamespaced, Name, Stream, prelude::*};
#[cfg(any(windows, test))]
use std::{ffi::OsStr, path::PathBuf};
use std::{fmt, io};

/// Access a guest's handle to a daemon pipe carries: SYNCHRONIZE | READ_CONTROL |
/// FILE_READ_ATTRIBUTES | FILE_WRITE_DATA | FILE_READ_DATA. No append, DAC or owner rights.
#[cfg(windows)]
pub const GUEST_PIPE_ACCESS: u32 = 0x0012_0083;

/// Pipe name on Windows, filesystem path on Unix (where `GenericNamespaced` would mean abstract sockets).
pub fn to_name(name: &str) -> io::Result<Name<'_>> {
    if cfg!(windows) {
        name.to_ns_name::<GenericNamespaced>()
    } else {
        name.to_fs_name::<GenericFilePath>()
    }
}

/// Error payload of [`connect`] when the socket or pipe is served by another user.
#[derive(Debug)]
pub struct ForeignServer;

impl fmt::Display for ForeignServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("socket is not owned by the current user")
    }
}

impl std::error::Error for ForeignServer {}

/// True when `connect` refused the server as another user's.
pub fn is_foreign(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<ForeignServer>())
}

fn foreign() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, ForeignServer)
}

/// Connects to the daemon socket `name`; the error is [`ForeignServer`] (see [`is_foreign`])
/// when another user serves it. Nothing is written on the connection here, so the caller
/// sends its first byte only to a server of its own user.
pub fn connect(name: &str) -> io::Result<Stream> {
    connect_checked(name, server_is_ours)
}

/// [`connect`] with the check of the connected server injectable (tests make it say "foreign").
/// Unix: the socket file must be ours before connecting, since another user could have squatted
/// on the name. Then `ours` judges the connected server; a refused stream is dropped unwritten.
pub fn connect_checked(name: &str, ours: fn(&Stream) -> bool) -> io::Result<Stream> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::symlink_metadata(name)?;
        if m.uid() != nix::unistd::getuid().as_raw() {
            return Err(foreign());
        }
    }
    let stream = Stream::connect(to_name(name)?)?;
    if ours(&stream) {
        Ok(stream)
    } else {
        Err(foreign())
    }
}

/// Whether the server of `s` is the current user's. Windows: anyone can create a pipe name
/// first, so the pipe object's owner, read through our client handle, must be our token user or
/// default owner; any failure to tell counts as not ours. Unix: the credential of the peer that
/// listens ([`peer_is_us`]); the socket file's owner is checked earlier, before connecting.
pub fn server_is_ours(s: &Stream) -> bool {
    #[cfg(windows)]
    {
        windows::pipe_server_is_ours(s)
    }
    #[cfg(unix)]
    {
        peer_is_us(s)
    }
}

#[cfg(any(unix, test))]
fn peer_allowed(peer_uid: Option<u32>, own_uid: u32) -> bool {
    peer_uid == Some(own_uid)
}

/// Unix: whether the process at the other end of `s` runs as our effective user (`SO_PEERCRED` /
/// `getpeereid`); an unreadable credential counts as not ours. On a connected client stream it
/// is the credential of whoever called `listen`.
#[cfg(unix)]
pub fn peer_is_us(s: &Stream) -> bool {
    use std::os::fd::{AsFd, AsRawFd};
    let Stream::UdSocket(socket) = s;
    let fd = socket.as_fd().as_raw_fd();
    // Use nix's OS bindings: its socket wrappers require an unavailable offline dependency.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let uid = {
        let mut creds: nix::libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of_val(&creds) as nix::libc::socklen_t;
        let ok = unsafe {
            nix::libc::getsockopt(
                fd,
                nix::libc::SOL_SOCKET,
                nix::libc::SO_PEERCRED,
                (&mut creds as *mut nix::libc::ucred).cast(),
                &mut len,
            )
        };
        (ok == 0 && len as usize == std::mem::size_of_val(&creds)).then_some(creds.uid)
    };
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    let uid = {
        let (mut uid, mut gid) = (0, 0);
        let ok = unsafe { nix::libc::getpeereid(fd, &mut uid, &mut gid) };
        (ok == 0).then_some(uid)
    };
    peer_allowed(uid, nix::unistd::geteuid().as_raw())
}

/// What this process is, for the queue: decided from its own token and the account its
/// environment names (%USERDOMAIN%\%USERNAME%).
#[derive(Debug, PartialEq, Eq)]
pub enum SelfKind {
    Owner,
    Account(String),
    AppContainer,
    Restricted,
}

/// Pure. Order: another account than the environment's -> `Account(name)` (the `elevated` token is
/// also restricted, so this comes first); AppContainer; restricted; else `Owner`.
pub fn classify_self(
    user_is_env_owner: bool,
    my_name: &str,
    app_container: bool,
    restricted: bool,
) -> SelfKind {
    if !user_is_env_owner {
        SelfKind::Account(my_name.to_owned())
    } else if app_container {
        SelfKind::AppContainer
    } else if restricted {
        SelfKind::Restricted
    } else {
        SelfKind::Owner
    }
}

/// What this process is. Any failure to read it is `Owner`: no guest path.
#[cfg(windows)]
pub fn self_kind() -> SelfKind {
    windows::self_kind().unwrap_or(SelfKind::Owner)
}

/// Windows: the pipe of this process's kind next to `name`: Account -> `guest_socket_name(name, me)`,
/// AppContainer/Restricted -> `sandbox_socket_name`. Trust before any byte: the pipe's owner must be
/// the environment's account; and, except for AppContainer (it cannot open processes outside its
/// container), every holder of the pipe must be the owner's full-token process or a peer of this
/// kind (Account -> same user, Restricted -> the owner's restricted). Errors: `Unsupported` = Owner
/// (not a guest); `NotFound` = no such pipe; [`is_foreign`] = wrong owner or holders.
#[cfg(windows)]
pub fn connect_guest(name: &str) -> io::Result<Stream> {
    use crate::config::{APPCONTAINER_GUEST, RESTRICTED_GUEST};
    use crate::protocol::{guest_socket_name, sandbox_socket_name};
    let unreadable = || io::Error::other("cannot read this account's SID");
    let (pipe, peers, owner) = match self_kind() {
        SelfKind::Owner => return Err(io::ErrorKind::Unsupported.into()),
        SelfKind::Account(me) => (
            guest_socket_name(name, &me),
            Some(Peers::SameUser),
            windows::env_account_sid().ok_or_else(unreadable)?,
        ),
        SelfKind::AppContainer => (
            sandbox_socket_name(name, APPCONTAINER_GUEST),
            None,
            windows::own_sid().ok_or_else(unreadable)?,
        ),
        SelfKind::Restricted => (
            sandbox_socket_name(name, RESTRICTED_GUEST),
            Some(Peers::RestrictedOwner),
            windows::own_sid().ok_or_else(unreadable)?,
        ),
    };
    windows::connect_guest_at(&format!(r"\\.\pipe\{pipe}"), &owner, peers)
}

/// The profile folder of this process's own account (`GetUserProfileDirectoryW` on the process
/// token) when the environment's USERPROFILE names another folder; None otherwise and on any failure.
#[cfg(windows)]
pub fn own_profile_if_env_is_foreign() -> Option<PathBuf> {
    profile_override(
        std::env::var_os("USERPROFILE").as_deref(),
        windows::own_profile(),
    )
}

/// Pure: `Some(own)` only when both exist and differ, ignoring case and a trailing separator.
#[cfg(any(windows, test))]
fn profile_override(env: Option<&OsStr>, own: Option<PathBuf>) -> Option<PathBuf> {
    let norm = |p: &OsStr| {
        p.to_string_lossy()
            .trim_end_matches(['\\', '/'])
            .to_lowercase()
    };
    let (env, own) = (env?, own?);
    (norm(env) != norm(own.as_os_str())).then_some(own)
}

/// What the client read of ONE process that holds a handle to the pipe (F41). None: that query
/// failed.
#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Default)]
struct HolderFacts {
    /// TokenUser == the account the pipe must belong to.
    user_is_expected: Option<bool>,
    /// TokenUser == this process's own user (a guest's account).
    user_is_self: Option<bool>,
    restricted: Option<bool>,
    app_container: Option<bool>,
    integrity_rid: Option<u32>,
}

/// Who, besides full-token processes of the expected account, may hold the pipe: its clients.
#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Peers {
    /// The owner's pipes.
    Nobody,
    /// `-guest-<account>`.
    SameUser,
    /// `-sbx-restricted`.
    RestrictedOwner,
}

/// The expected user, neither restricted nor AppContainer, integrity >= 0x2000 (medium).
#[cfg(any(windows, test))]
fn server_token_ok(f: HolderFacts) -> bool {
    f.user_is_expected == Some(true)
        && f.restricted == Some(false)
        && f.app_container == Some(false)
        && f.integrity_rid.is_some_and(|rid| rid >= 0x2000)
}

/// Trusted only when at least one holder passes [`server_token_ok`] and every holder passes it or
/// is a peer. A `None` in any fact the rule reads, or an empty list, is not trusted.
#[cfg(any(windows, test))]
fn holders_ok(holders: &[HolderFacts], peers: Peers) -> bool {
    let peer = |f: &HolderFacts| match peers {
        Peers::Nobody => false,
        Peers::SameUser => f.user_is_self == Some(true),
        Peers::RestrictedOwner => {
            f.user_is_expected == Some(true)
                && f.restricted == Some(true)
                && f.app_container == Some(false)
        }
    };
    holders.iter().any(|f| server_token_ok(*f))
        && holders.iter().all(|f| server_token_ok(*f) || peer(f))
}

/// Parses what NtQueryInformationFile(FileProcessIdsUsingFileInformation) wrote: `written` is the
/// returned extent (IO_STATUS_BLOCK.Information), `buf` the whole buffer. FILE_PROCESS_IDS_USING_
/// FILE_INFORMATION is a u32 count, then the usize ids from offset `size_of::<usize>()` (8 on
/// x64, 4 on x86). None when the extent exceeds the buffer, the header is incomplete, or the count
/// claims more ids than the written bytes hold. An empty list is `Some(vec![])`; [`holders_ok`]
/// refuses it, so the caller never trusts a pipe with no holders.
#[cfg(any(windows, test))]
fn parse_holder_ids(buf: &[u8], written: usize) -> Option<Vec<u32>> {
    let first = size_of::<usize>();
    let bytes = buf.get(..written)?;
    let room = bytes.len().checked_sub(first)? / size_of::<usize>();
    let count = usize::try_from(u32::from_ne_bytes(bytes[..4].try_into().ok()?)).ok()?;
    if count > room {
        return None;
    }
    bytes[first..]
        .as_chunks::<{ size_of::<usize>() }>()
        .0
        .iter()
        .take(count)
        .map(|c| u32::try_from(usize::from_ne_bytes(*c)).ok())
        .collect()
}

/// The restriction fact from the GroupCount of TokenRestrictedSids (None: the query failed). A
/// token is restricted when it has restricting SIDs; a failed query is unknown, not "unrestricted"
/// (IsTokenRestricted answers 0 for both).
#[cfg(any(windows, test))]
fn restricted_from_group_count(count: Option<u32>) -> Option<bool> {
    count.map(|n| n > 0)
}

/// Pure seam of the holders query. `first`: a pid already pinned before anything is listed (the
/// instance's server pid), with its pin. `list`: the kernel's list of pids that hold the pipe
/// (None: failed). `open`: pins one pid (None: gone or denied). Each round lists; done when the
/// list names only pinned pids, else it opens every listed pid not pinned yet and lists again. At
/// most 4 lists, else None. Returns the pids of the last list with their pins. Common case: the
/// server pinned first is the only holder, one list.
///
/// A pid is trusted only while pinned by an open handle, and only if it is listed after the pin
/// (F46): a pin taken before a list holds that pid, so the list names the pinned process.
#[cfg(any(windows, test))]
fn settle_holders<P>(
    first: Option<(u32, P)>,
    mut list: impl FnMut() -> Option<Vec<u32>>,
    mut open: impl FnMut(u32) -> Option<P>,
) -> Option<Vec<(u32, P)>> {
    let mut pinned: Vec<(u32, P)> = first.into_iter().collect();
    for _ in 0..4 {
        let listed = list()?;
        if listed
            .iter()
            .all(|pid| pinned.iter().any(|(p, _)| p == pid))
        {
            pinned.retain(|(p, _)| listed.contains(p));
            return Some(pinned);
        }
        for &pid in &listed {
            if pinned.iter().any(|(p, _)| *p == pid) {
                continue;
            }
            if let Some(pin) = open(pid) {
                pinned.push((pid, pin));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use interprocess::local_socket::ListenerOptions;

    #[test]
    fn only_a_readable_same_user_peer_is_allowed() {
        assert!(peer_allowed(Some(1000), 1000));
        assert!(!peer_allowed(Some(1001), 1000));
        assert!(!peer_allowed(None, 1000));
    }

    /// Child half of the two-user test: runs as another user, so the daemon socket is "foreign"
    /// to it. Does nothing unless the parent set the variable.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "run by xuser_peer_credentials_refuse_the_other_user"]
    fn xuser_child_connects() {
        let Ok(path) = std::env::var("SYNC_GATE_XUSER_SOCKET") else {
            return;
        };
        match connect(&path) {
            Err(e) if is_foreign(&e) => println!("XUSER_CHILD_REFUSED"),
            other => panic!(
                "expected a foreign-server refusal, got {:?}",
                other.map(|_| ())
            ),
        }
    }

    /// Two real users (root serves, uid 65534 connects): the credential of the peer, not the
    /// socket file's owner, must say "not ours" to the daemon and to the client.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs root; runs in the xtask container step"]
    fn xuser_peer_credentials_refuse_the_other_user() {
        use std::os::unix::fs::{PermissionsExt, chown};
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        if nix::unistd::geteuid().as_raw() != 0 {
            println!("skipped: needs root");
            return;
        }
        let dir = format!("/tmp/fg-xuser-{}", std::process::id());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let sock = format!("{dir}/s.sock");
        let listener = ListenerOptions::new()
            .name(to_name(&sock).unwrap())
            .create_sync()
            .unwrap();
        // The file says "the child's", the server is root: only the peer credential can refuse.
        chown(&sock, Some(65534), Some(65534)).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "ipc_name::tests::xuser_child_connects",
                "--ignored",
                "--nocapture",
            ])
            .env("SYNC_GATE_XUSER_SOCKET", &sock)
            .uid(65534)
            .gid(65534)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(listener.accept().map(|c| peer_is_us(&c)));
        });
        let accepted = rx.recv_timeout(Duration::from_secs(10));
        let start = Instant::now();
        let status = loop {
            if let Some(s) = child.try_wait().unwrap() {
                break Some(s);
            }
            if start.elapsed() > Duration::from_secs(30) {
                let _ = child.kill();
                break None;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let mut out = String::new();
        std::io::Read::read_to_string(&mut child.stdout.take().unwrap(), &mut out).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(matches!(accepted, Ok(Ok(false))), "server saw {accepted:?}");
        assert!(
            status.is_some_and(|s| s.success()),
            "child: {status:?} {out}"
        );
        assert!(
            out.lines().any(|l| l == "XUSER_CHILD_REFUSED"),
            "child: {out}"
        );
    }

    #[test]
    fn profile_override_rules() {
        use std::ffi::OsStr;
        use std::path::PathBuf;
        let own = |s: &str| Some(PathBuf::from(s));
        let env = |s: &'static str| Some(OsStr::new(s));
        assert_eq!(
            profile_override(env(r"C:\Users\Alice\"), own(r"c:\users\alice")),
            None
        );
        assert_eq!(profile_override(None, own(r"C:\Users\alice")), None);
        assert_eq!(profile_override(env(r"C:\Users\alice"), None), None);
        assert_eq!(
            profile_override(env(r"C:\Users\alice"), own(r"C:\Users\CodexSandboxOffline")),
            own(r"C:\Users\CodexSandboxOffline")
        );
    }

    #[test]
    fn classify_self_rules() {
        // The `elevated` token is restricted too, and is still an account.
        assert_eq!(
            classify_self(false, "codexsandboxoffline", false, true),
            SelfKind::Account("codexsandboxoffline".into())
        );
        assert_eq!(
            classify_self(true, "alice", true, false),
            SelfKind::AppContainer
        );
        assert_eq!(
            classify_self(true, "alice", false, true),
            SelfKind::Restricted
        );
        assert_eq!(classify_self(true, "alice", false, false), SelfKind::Owner);
    }

    /// A full-token process of the owner.
    const P: HolderFacts = HolderFacts {
        user_is_expected: Some(true),
        user_is_self: Some(true),
        restricted: Some(false),
        app_container: Some(false),
        integrity_rid: Some(0x2000),
    };

    #[test]
    fn an_unknown_restriction_is_refused() {
        assert_eq!(restricted_from_group_count(None), None);
        assert_eq!(restricted_from_group_count(Some(0)), Some(false));
        assert_eq!(restricted_from_group_count(Some(2)), Some(true));
        let unknown = HolderFacts {
            restricted: restricted_from_group_count(None),
            ..P
        };
        assert!(!server_token_ok(unknown));
        assert!(!holders_ok(&[unknown], Peers::Nobody));
        assert!(!holders_ok(&[P, unknown], Peers::Nobody));
    }

    /// A buffer as the kernel writes it: count, then `ids` from offset `size_of::<usize>()`.
    fn holder_buf(count: u32, ids: &[usize], len: usize) -> Vec<u8> {
        let mut b = vec![0u8; len];
        b[..4].copy_from_slice(&count.to_ne_bytes());
        for (i, id) in ids.iter().enumerate() {
            let at = size_of::<usize>() * (i + 1);
            b[at..at + size_of::<usize>()].copy_from_slice(&id.to_ne_bytes());
        }
        b
    }

    #[test]
    fn the_holder_list_is_bounded_by_the_bytes_written() {
        let w = size_of::<usize>();
        // well formed: 2 ids
        let b = holder_buf(2, &[7, 11], 64);
        assert_eq!(parse_holder_ids(&b, 3 * w), Some(vec![7, 11]));
        // count 0: an empty list (holders_ok refuses it)
        assert_eq!(parse_holder_ids(&holder_buf(0, &[], 64), w), Some(vec![]));
        assert!(!holders_ok(&[], Peers::Nobody));
        // short response: count 1, the id only partly written
        let b = holder_buf(1, &[1024], 64);
        assert_eq!(parse_holder_ids(&b, 2 * w - 1), None);
        // oversized count, including one that would wrap a 32-bit size computation
        let b = holder_buf(3, &[7, 11], 64);
        assert_eq!(parse_holder_ids(&b, 3 * w), None);
        let b = holder_buf(0x4000_0001, &[7], 64);
        assert_eq!(parse_holder_ids(&b, 2 * w), None);
        // extent beyond the buffer, or too small for the header
        assert_eq!(parse_holder_ids(&b, 65), None);
        assert_eq!(parse_holder_ids(&b, w - 1), None);
        // an id that is not a u32
        #[cfg(target_pointer_width = "64")]
        {
            let b = holder_buf(1, &[1usize << 32], 64);
            assert_eq!(parse_holder_ids(&b, 2 * w), None);
        }
    }

    #[test]
    fn the_holder_decision() {
        let r = HolderFacts {
            restricted: Some(true),
            ..P
        };
        let ac = HolderFacts {
            app_container: Some(true),
            ..P
        };
        let other = HolderFacts {
            user_is_expected: Some(false),
            user_is_self: Some(false),
            ..P
        };

        // server_token_ok
        assert!(server_token_ok(P));
        assert!(server_token_ok(HolderFacts {
            integrity_rid: Some(0x3000),
            ..P
        }));
        assert!(!server_token_ok(r));
        assert!(!server_token_ok(ac));
        assert!(!server_token_ok(HolderFacts {
            integrity_rid: Some(0x1000),
            ..P
        }));
        assert!(!server_token_ok(other));
        for none in [
            HolderFacts {
                user_is_expected: None,
                ..P
            },
            HolderFacts {
                restricted: None,
                ..P
            },
            HolderFacts {
                app_container: None,
                ..P
            },
            HolderFacts {
                integrity_rid: None,
                ..P
            },
        ] {
            assert!(!server_token_ok(none), "{none:?}");
        }

        // Peers::Nobody (the owner's pipes)
        let low = HolderFacts {
            integrity_rid: Some(0x1000),
            ..P
        };
        assert!(holders_ok(&[P], Peers::Nobody));
        assert!(holders_ok(&[P, P], Peers::Nobody));
        assert!(!holders_ok(&[], Peers::Nobody));
        assert!(!holders_ok(&[P, r], Peers::Nobody));
        assert!(!holders_ok(&[r], Peers::Nobody));
        assert!(!holders_ok(&[P, ac], Peers::Nobody));
        assert!(!holders_ok(&[P, low], Peers::Nobody));
        assert!(!holders_ok(&[P, other], Peers::Nobody));
        assert!(!holders_ok(&[P, HolderFacts::default()], Peers::Nobody));

        // Peers::SameUser (-guest-<account>): a guest runs as this very user, restricted
        let s = HolderFacts {
            user_is_expected: Some(false),
            user_is_self: Some(true),
            restricted: Some(true),
            ..P
        };
        let owner_restricted = HolderFacts {
            user_is_self: Some(false),
            ..r
        };
        assert!(holders_ok(&[P, s], Peers::SameUser));
        assert!(!holders_ok(&[s], Peers::SameUser));
        assert!(!holders_ok(&[P, owner_restricted], Peers::SameUser));
        assert!(!holders_ok(
            &[
                P,
                HolderFacts {
                    user_is_self: None,
                    ..s
                }
            ],
            Peers::SameUser
        ));

        // Peers::RestrictedOwner (-sbx-restricted)
        let owner_ac = HolderFacts {
            app_container: Some(true),
            ..r
        };
        let other_restricted = HolderFacts {
            user_is_expected: Some(false),
            ..r
        };
        assert!(holders_ok(&[P, r], Peers::RestrictedOwner));
        assert!(!holders_ok(&[r], Peers::RestrictedOwner));
        assert!(!holders_ok(&[P, owner_ac], Peers::RestrictedOwner));
        assert!(!holders_ok(&[P, other_restricted], Peers::RestrictedOwner));
        assert!(!holders_ok(
            &[
                P,
                HolderFacts {
                    restricted: None,
                    ..r
                }
            ],
            Peers::RestrictedOwner
        ));
    }

    /// What one run of `settle_holders` did: its result, the pids it opened, and its list calls.
    type Settled = (Option<Vec<u32>>, Vec<u32>, usize);

    /// Runs `settle_holders` on fake lists (served in order, the last repeating); `deny` pids
    /// fail to open. A pin is the pid times ten, so each pid is checked to carry its own pin.
    fn settle(lists: &[Option<&[u32]>], deny: &[u32]) -> Settled {
        settle_from(None, lists, deny)
    }

    /// [`settle`] with `first` pinned before any list (the server pid, opened by the caller).
    fn settle_from(first: Option<u32>, lists: &[Option<&[u32]>], deny: &[u32]) -> Settled {
        use std::cell::RefCell;
        let (opened, calls) = (RefCell::new(vec![]), RefCell::new(0usize));
        let got = settle_holders(
            first.map(|pid| (pid, pid * 10)),
            || {
                let i = (*calls.borrow()).min(lists.len() - 1);
                *calls.borrow_mut() += 1;
                lists[i].map(<[u32]>::to_vec)
            },
            |pid| {
                opened.borrow_mut().push(pid);
                (!deny.contains(&pid)).then_some(pid * 10)
            },
        );
        let got = got.map(|v| {
            assert!(v.iter().all(|(pid, pin)| *pin == pid * 10));
            v.into_iter().map(|(pid, _)| pid).collect()
        });
        (got, opened.into_inner(), calls.into_inner())
    }

    #[test]
    fn settle_holders_pins_before_it_trusts() {
        let (got, opened, _) = settle(&[Some(&[7, 9]), Some(&[7, 9])], &[]);
        assert_eq!((got, opened), (Some(vec![7, 9]), vec![7, 9]));

        // 11 joins in round 2: it is opened then, and the list read after its pin has both.
        let (got, opened, _) = settle(&[Some(&[7]), Some(&[7, 11]), Some(&[7, 11])], &[]);
        assert_eq!((got, opened), (Some(vec![7, 11]), vec![7, 11]));

        // 9 leaves: only 7 is returned.
        let (got, _, _) = settle(&[Some(&[7, 9]), Some(&[7])], &[]);
        assert_eq!(got, Some(vec![7]));

        // 9 could not be opened and is gone from the next list: not trusted, not needed.
        let (got, opened, _) = settle(&[Some(&[7, 9]), Some(&[7])], &[9]);
        assert_eq!((got, opened), (Some(vec![7]), vec![7, 9]));

        // 9 stays listed but cannot be pinned: never settles.
        let (got, _, calls) = settle(&[Some(&[7, 9])], &[9]);
        assert_eq!((got, calls), (None, 4));

        // Lists that grow every round: three rounds, then None.
        let growing: [Option<&[u32]>; 5] = [
            Some(&[1]),
            Some(&[1, 2]),
            Some(&[1, 2, 3]),
            Some(&[1, 2, 3, 4]),
            Some(&[1, 2, 3, 4, 5]),
        ];
        let (got, _, calls) = settle(&growing, &[]);
        assert_eq!((got, calls), (None, 4));

        // The kernel list failing, first or later: None.
        assert_eq!(settle(&[None], &[]).0, None);
        assert_eq!(settle(&[Some(&[7]), None], &[]).0, None);
    }

    /// The common case: the server pid is pinned first, so one list that names only it settles.
    #[test]
    fn settle_holders_lists_once_when_the_server_was_pinned_first() {
        let (got, opened, calls) = settle_from(Some(7), &[Some(&[7])], &[]);
        assert_eq!((got, opened, calls), (Some(vec![7]), vec![], 1));

        // A holder besides the server: the old rounds, and the list after its pin has both.
        let (got, opened, calls) = settle_from(Some(7), &[Some(&[7, 9]), Some(&[7, 9])], &[]);
        assert_eq!((got, opened, calls), (Some(vec![7, 9]), vec![9], 2));

        // The server handed its end over (F42): its pin is dropped, the holder is returned.
        let (got, opened, calls) = settle_from(Some(7), &[Some(&[9]), Some(&[9])], &[]);
        assert_eq!((got, opened, calls), (Some(vec![9]), vec![9], 2));

        // A new holder that cannot be pinned never settles; a failed list is None.
        let (got, _, calls) = settle_from(Some(7), &[Some(&[7, 9])], &[9]);
        assert_eq!((got, calls), (None, 4));
        assert_eq!(settle_from(Some(7), &[None], &[]), (None, vec![], 1));
        assert_eq!(
            settle_from(Some(7), &[Some(&[7]), None], &[]).0,
            Some(vec![7])
        );
    }

    /// The positive path of the real check (Windows: the pipe's owner, here our default owner,
    /// is ours; Unix: the peer credential).
    /// The refusal itself is covered by the relay and CLI tests through the same seam.
    #[test]
    fn a_socket_served_by_this_user_is_ours() {
        let n = format!("sync_gate_core-owner-{}", std::process::id());
        let name = if cfg!(windows) {
            n
        } else {
            std::env::temp_dir().join(n).to_string_lossy().into_owned()
        };
        let _ = std::fs::remove_file(&name);
        let listener = ListenerOptions::new()
            .name(to_name(&name).unwrap())
            .create_sync()
            .unwrap();
        let accept = std::thread::spawn(move || listener.accept());
        let client = connect(&name);
        let server = accept.join().unwrap();
        assert!(client.is_ok(), "{:?}", client.err());
        assert!(server.is_ok());
        let _ = std::fs::remove_file(&name);
    }
}

#[cfg(windows)]
mod windows {
    use super::{GUEST_PIPE_ACCESS, SelfKind, classify_self};
    use super::{
        HolderFacts, Peers, holders_ok, parse_holder_ids, restricted_from_group_count,
        settle_holders,
    };
    use interprocess::local_socket::Stream;
    use interprocess::os::windows::named_pipe::local_socket::Stream as NamedPipeStream;
    use std::ffi::OsString;
    use std::io;
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle};
    use std::path::PathBuf;
    use std::sync::Mutex;
    use windows_sys::Wdk::Storage::FileSystem::{
        FileProcessIdsUsingFileInformation, NtQueryInformationFile,
    };
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, HANDLE, INVALID_HANDLE_VALUE,
        STATUS_SUCCESS, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Security::{
        EqualSid, GetKernelObjectSecurity, GetLengthSid, GetSecurityDescriptorOwner,
        GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, LookupAccountNameW,
        LookupAccountSidW, OWNER_SECURITY_INFORMATION, PSID, SID_NAME_USE, TOKEN_INFORMATION_CLASS,
        TOKEN_MANDATORY_LABEL, TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER, TokenIntegrityLevel,
        TokenIsAppContainer, TokenOwner, TokenRestrictedSids, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, FILE_SHARE_WRITE, FileNameInfo,
        GetFileInformationByHandleEx, OPEN_EXISTING, SECURITY_CONTEXT_TRACKING,
        SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
    use windows_sys::Win32::System::Pipes::{GetNamedPipeServerProcessId, WaitNamedPipeW};
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SYNCHRONIZE, WaitForSingleObject,
    };
    use windows_sys::Win32::UI::Shell::GetUserProfileDirectoryW;

    /// Windows: owner check plus who holds the pipe now. The pid GetNamedPipeServerProcessId gives
    /// names the instance's creator, which may have handed its handle to a restricted process and
    /// exited (F42); the kernel's list of holders does not age (F41).
    ///
    /// The pipe object's owner must be this process's user or default owner; another non-admin
    /// user cannot create a pipe owned by either (F4, F5). And every process holding the pipe must
    /// be a full-token process of this user.
    ///
    /// A daemon verified once is remembered for the life of this process ([`remembered`]): a later
    /// instance of the same name created by that same live process skips the holders query.
    pub(super) fn pipe_server_is_ours(s: &Stream) -> bool {
        let Stream::NamedPipe(p) = s;
        let pipe = p.inner().as_handle().as_raw_handle();
        let sd = pipe_owner(pipe);
        let user = token_info::<TOKEN_USER>(TokenUser);
        let default_owner = token_info::<TOKEN_OWNER>(TokenOwner);
        // SAFETY: each buffer holds what it is read as (a descriptor `pipe_owner` checked, or the
        // whole struct `token_info` size-checked), and every SID points into its own buffer, all
        // alive until the end of this function; `pipe` is our open client end.
        unsafe {
            let user_sid = user
                .as_deref()
                .map(|b| (*b.as_ptr().cast::<TOKEN_USER>()).User.Sid);
            let owner_ok = owner_is_ours(
                sd.as_deref().map(|sd| owner_sid(sd)),
                user_sid,
                default_owner
                    .as_deref()
                    .map(|b| (*b.as_ptr().cast::<TOKEN_OWNER>()).Owner),
            );
            let (Some(expected), true) = (user_sid, owner_ok) else {
                return false;
            };
            let (server, name) = (server_pid(pipe), pipe_name(pipe));
            if server
                .zip(name.as_deref())
                .is_some_and(|(pid, n)| remembered(n, pid))
            {
                return true;
            }
            let Some((holders, server_pin)) = pipe_holders(pipe, expected, server) else {
                return false;
            };
            let ok = holders_ok(&holders, Peers::Nobody);
            if let (true, Some(pid), Some(name), Some(pin)) = (ok, server, name, server_pin) {
                remember(name, pid, pin);
            }
            ok
        }
    }

    /// Daemons this process verified, by pipe name: (name, server pid, a handle that pins it).
    ///
    /// Why a hit keeps the guarantee: the pid was a holder with a full token of this user when the
    /// full check passed, and the handle kept here since then means no other process can have
    /// that pid (F46). An instance whose server pid is that pid was created by that process, and
    /// the daemon never hands its server ends to other processes. While it is alive (checked at
    /// each hit) its instances are its own; once it has exited, a pipe still alive under the name
    /// is held by someone else (as in F42), so the entry is dropped and the full check runs. A
    /// squatter after the daemon dies is another process, so another server pid: full check too.
    /// In memory only: never shared with another process or written anywhere.
    static VERIFIED: Mutex<Vec<(Vec<u16>, u32, OwnedHandle)>> = Mutex::new(Vec::new());

    /// Whether `pid` is the live daemon remembered for pipe `name`. Anything else (another pid,
    /// the process exited, the wait failed) drops the entry.
    fn remembered(name: &[u16], pid: u32) -> bool {
        let Ok(mut cache) = VERIFIED.lock() else {
            return false;
        };
        let Some(i) = cache.iter().position(|(n, _, _)| n == name) else {
            return false;
        };
        let (_, cached, pin) = &cache[i];
        // SAFETY: `pin` is an open process handle; without SYNCHRONIZE the wait fails, not a hit.
        if *cached == pid && unsafe { WaitForSingleObject(pin.as_raw_handle(), 0) } == WAIT_TIMEOUT
        {
            return true;
        }
        cache.swap_remove(i);
        false
    }

    /// Remembers `pid`, pinned by `pin`, as the verified daemon of pipe `name`.
    fn remember(name: Vec<u16>, pid: u32, pin: OwnedHandle) {
        if let Ok(mut cache) = VERIFIED.lock() {
            cache.retain(|(n, _, _)| *n != name);
            cache.push((name, pid, pin));
        }
    }

    /// The pid GetNamedPipeServerProcessId gives for the instance behind `pipe`: its creator (F42).
    fn server_pid(pipe: HANDLE) -> Option<u32> {
        let mut pid = 0u32;
        // SAFETY: `pipe` is an open pipe handle (caller); `pid` is a valid out pointer.
        (unsafe { GetNamedPipeServerProcessId(pipe, &mut pid) } != 0).then_some(pid)
    }

    /// The pipe's name as the kernel keeps it (`\name`), read through our client end.
    fn pipe_name(pipe: HANDLE) -> Option<Vec<u16>> {
        // u32 elements keep the buffer aligned for FILE_NAME_INFO (a u32 length, then UTF-16).
        let mut buf = vec![0u32; 1024];
        // SAFETY: `buf` holds the given number of writable bytes; `pipe` is open (caller).
        let ok = unsafe {
            GetFileInformationByHandleEx(
                pipe,
                FileNameInfo,
                buf.as_mut_ptr().cast(),
                (buf.len() * 4) as u32,
            )
        };
        if ok == 0 {
            return None;
        }
        let units = buf[0] as usize / 2;
        // SAFETY: `buf` owns its initialised bytes, read as u16 units.
        let all = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u16>(), buf.len() * 2) };
        all.get(2..2 + units).map(<[u16]>::to_vec)
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain([0]).collect()
    }

    /// A copy of `sid` in a buffer aligned like the SIDs the rest of this module passes around.
    ///
    /// # Safety
    /// `sid` must point to a valid SID.
    unsafe fn sid_copy(sid: PSID) -> Vec<u64> {
        // SAFETY: `sid` is valid (caller); the copy reads exactly its length into a buffer at
        // least that long.
        unsafe {
            let len = GetLengthSid(sid) as usize;
            let mut buf = vec![0u64; len.div_ceil(8)];
            std::ptr::copy_nonoverlapping(sid.cast::<u8>(), buf.as_mut_ptr().cast::<u8>(), len);
            buf
        }
    }

    /// This process's own user SID.
    pub(super) fn own_sid() -> Option<Vec<u64>> {
        let user = token_info::<TOKEN_USER>(TokenUser)?;
        // SAFETY: `token_info` checked the buffer holds a whole TOKEN_USER; its SID points inside.
        Some(unsafe { sid_copy((*user.as_ptr().cast::<TOKEN_USER>()).User.Sid) })
    }

    /// The (name, domain) the system gives `sid`; None on failure.
    fn account_of(sid: PSID) -> Option<(String, String)> {
        let (mut nl, mut dl, mut kind) = (0u32, 0u32, 0 as SID_NAME_USE);
        // SAFETY: size query with null buffers; `sid` is valid (caller), the rest are out pointers.
        unsafe {
            LookupAccountSidW(
                std::ptr::null(),
                sid,
                std::ptr::null_mut(),
                &mut nl,
                std::ptr::null_mut(),
                &mut dl,
                &mut kind,
            )
        };
        if nl == 0 {
            return None;
        }
        let (mut name, mut domain) = (vec![0u16; nl as usize], vec![0u16; dl as usize]);
        // SAFETY: both buffers hold the sizes the query asked for.
        let ok = unsafe {
            LookupAccountSidW(
                std::ptr::null(),
                sid,
                name.as_mut_ptr(),
                &mut nl,
                domain.as_mut_ptr(),
                &mut dl,
                &mut kind,
            )
        };
        (ok != 0).then(|| {
            (
                String::from_utf16_lossy(&name[..nl as usize]),
                String::from_utf16_lossy(&domain[..dl as usize]),
            )
        })
    }

    /// `%USERDOMAIN%` and `%USERNAME%`: the account this process's environment names.
    fn env_account() -> Option<(String, String)> {
        Some((
            std::env::var("USERDOMAIN").ok()?,
            std::env::var("USERNAME").ok()?,
        ))
    }

    /// The SID of the user account `%USERDOMAIN%\%USERNAME%` names (only a user account counts).
    pub(super) fn env_account_sid() -> Option<Vec<u64>> {
        const SID_TYPE_USER: SID_NAME_USE = 1;
        let (domain, user) = env_account()?;
        let full = wide(&format!("{domain}\\{user}"));
        let (mut cb, mut cd, mut kind) = (0u32, 0u32, 0 as SID_NAME_USE);
        // SAFETY: size query with null buffers; `full` is NUL-terminated.
        unsafe {
            LookupAccountNameW(
                std::ptr::null(),
                full.as_ptr(),
                std::ptr::null_mut(),
                &mut cb,
                std::ptr::null_mut(),
                &mut cd,
                &mut kind,
            )
        };
        if cb == 0 {
            return None;
        }
        let mut sid = vec![0u64; (cb as usize).div_ceil(8)];
        let mut dom = vec![0u16; cd as usize];
        // SAFETY: the buffers hold the sizes the query asked for.
        let ok = unsafe {
            LookupAccountNameW(
                std::ptr::null(),
                full.as_ptr(),
                sid.as_mut_ptr().cast(),
                &mut cb,
                dom.as_mut_ptr(),
                &mut cd,
                &mut kind,
            )
        };
        (ok != 0 && kind == SID_TYPE_USER).then_some(sid)
    }

    /// What this process is; None when its token or environment cannot be read.
    pub(super) fn self_kind() -> Option<SelfKind> {
        let user = token_info::<TOKEN_USER>(TokenUser)?;
        // SAFETY: `token_info` checked the buffer holds a whole TOKEN_USER.
        let (name, domain) = account_of(unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid })?;
        let (env_domain, env_user) = env_account()?;
        let is_env =
            name.eq_ignore_ascii_case(&env_user) && domain.eq_ignore_ascii_case(&env_domain);
        // SAFETY: each buffer holds a whole DWORD, aligned.
        let restricted = restricted_from_group_count(
            token_info::<u32>(TokenRestrictedSids).map(|b| unsafe { *b.as_ptr().cast::<u32>() }),
        )?;
        let app_container = token_info::<u32>(TokenIsAppContainer)
            .map(|b| unsafe { *b.as_ptr().cast::<u32>() } != 0)?;
        Some(classify_self(
            is_env,
            &name.to_lowercase(),
            app_container,
            restricted,
        ))
    }

    /// The profile folder of this process's own account; None on any failure.
    pub(super) fn own_profile() -> Option<PathBuf> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: pseudo handle needs no closing; `token` is a valid out pointer.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return None;
        }
        let mut len = 0u32;
        // SAFETY: size query (null buffer, length 0); `token` is open.
        unsafe { GetUserProfileDirectoryW(token, std::ptr::null_mut(), &mut len) };
        let mut buf = vec![0u16; len as usize];
        // SAFETY: `buf` holds `len` UTF-16 units, as the query asked.
        let ok =
            len > 0 && unsafe { GetUserProfileDirectoryW(token, buf.as_mut_ptr(), &mut len) } != 0;
        // SAFETY: opened above, closed once.
        unsafe { CloseHandle(token) };
        // `len` counts the terminating NUL.
        ok.then(|| {
            PathBuf::from(OsString::from_wide(
                &buf[..(len as usize).saturating_sub(1)],
            ))
        })
    }

    /// Opens the guest pipe `path` (`\\.\pipe\...`) with the narrow access and an identification-only
    /// impersonation level (the daemon may identify this caller from each message but never act as
    /// it), then judges it before any byte: the pipe's owner must be `owner` (a SID) and, when
    /// `peers` is given, every holder must be one of `owner`'s full-token processes or a peer.
    /// `ERROR_PIPE_BUSY` waits (2 s) and retries, three tries in all.
    pub(super) fn connect_guest_at(
        path: &str,
        owner: &[u64],
        peers: Option<Peers>,
    ) -> io::Result<Stream> {
        let name = wide(path);
        let mut tries = 0;
        let handle = loop {
            tries += 1;
            // SAFETY: `name` is NUL-terminated; no security attributes, no template.
            let h = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    GUEST_PIPE_ACCESS,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED
                        | SECURITY_SQOS_PRESENT
                        | SECURITY_IDENTIFICATION
                        | SECURITY_CONTEXT_TRACKING,
                    std::ptr::null_mut(),
                )
            };
            if h != INVALID_HANDLE_VALUE {
                // SAFETY: a new handle nobody else owns.
                break unsafe { OwnedHandle::from_raw_handle(h) };
            }
            let e = io::Error::last_os_error();
            match e.raw_os_error().map(|c| c as u32) {
                // Maps to `ErrorKind::NotFound`.
                Some(ERROR_FILE_NOT_FOUND) => return Err(e),
                Some(ERROR_PIPE_BUSY) if tries < 3 => {
                    // SAFETY: `name` is NUL-terminated; the result only says whether one freed up.
                    unsafe { WaitNamedPipeW(name.as_ptr(), 2000) };
                }
                _ => return Err(e),
            }
        };
        let pipe = handle.as_raw_handle();
        let expected: PSID = owner.as_ptr().cast_mut().cast();
        let owned_by_owner = pipe_owner(pipe).is_some_and(|sd| {
            // SAFETY: `pipe_owner` returned a valid descriptor; `owner` is a valid SID (caller).
            unsafe { EqualSid(owner_sid(&sd), expected) != 0 }
        });
        // SAFETY: `pipe` is our open handle and `expected` a valid SID, both alive for the call.
        let holders_trusted = || match peers {
            None => true,
            Some(p) => unsafe { pipe_holders(pipe, expected, server_pid(pipe)) }
                .is_some_and(|(h, _)| holders_ok(&h, p)),
        };
        if !(owned_by_owner && holders_trusted()) {
            return Err(super::foreign());
        }
        NamedPipeStream::try_from(handle)
            .map(Stream::NamedPipe)
            .map_err(io::Error::from)
    }

    /// The pids that hold a handle to any instance or end of `pipe`, by the kernel (F41). The
    /// asking handle is not listed. None unless the query succeeded.
    fn list_holders(pipe: HANDLE) -> Option<Vec<u32>> {
        const LEN: usize = 64 * 1024;
        #[cfg(test)]
        tests::LISTS.with(|n| n.set(n.get() + 1));
        // u64 elements keep the buffer aligned for the count and the usize list.
        let mut buf = vec![0u64; LEN / 8];
        // SAFETY: plain C struct, all-zero is valid.
        let mut iosb: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
        // SAFETY: `buf` holds LEN writable bytes; `pipe` is an open handle (caller); `iosb` is a
        // valid out pointer.
        let status = unsafe {
            NtQueryInformationFile(
                pipe,
                &mut iosb,
                buf.as_mut_ptr().cast(),
                LEN as u32,
                FileProcessIdsUsingFileInformation,
            )
        };
        if status != STATUS_SUCCESS {
            return None;
        }
        // SAFETY: `buf` owns LEN initialised bytes, read as plain bytes.
        let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), LEN) };
        parse_holder_ids(bytes, iosb.Information)
    }

    /// Pins process `pid` by an open handle with `access` (at least enough to query its token);
    /// the handle closes on drop.
    fn pin_process(pid: u32, access: u32) -> Option<OwnedHandle> {
        // SAFETY: no pointers; a non-null result is a new handle we own.
        let h = unsafe { OpenProcess(access, 0, pid) };
        // SAFETY: `h` is a valid handle nobody else owns.
        (!h.is_null()).then(|| unsafe { OwnedHandle::from_raw_handle(h) })
    }

    /// What the token of the process behind `process` says; a failed query leaves its fact None.
    ///
    /// # Safety
    /// `process` must be an open process handle, `expected` and `own` valid SIDs, all alive for
    /// the call.
    unsafe fn holder_facts(process: HANDLE, expected: PSID, own: PSID) -> HolderFacts {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: `process` is open (caller); `token` is a valid out pointer.
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
            return HolderFacts::default();
        }
        let user = info_of::<TOKEN_USER>(token, TokenUser);
        // SAFETY: the buffer is a whole TOKEN_USER and its SID points inside it; `sid` is valid
        // (caller).
        let same = |sid: PSID| {
            user.as_deref()
                .map(|b| unsafe { EqualSid((*b.as_ptr().cast::<TOKEN_USER>()).User.Sid, sid) != 0 })
        };
        let facts = HolderFacts {
            user_is_expected: same(expected),
            user_is_self: same(own),
            // SAFETY: `token` is open for the call.
            restricted: restricted_from_group_count(
                info_of::<u32>(token, TokenRestrictedSids)
                    // SAFETY: the buffer holds a whole DWORD (GroupCount), aligned.
                    .map(|b| unsafe { *b.as_ptr().cast::<u32>() }),
            ),
            app_container: info_of::<u32>(token, TokenIsAppContainer)
                // SAFETY: the buffer holds a whole DWORD, aligned.
                .map(|b| unsafe { *b.as_ptr().cast::<u32>() } != 0),
            integrity_rid: info_of::<TOKEN_MANDATORY_LABEL>(token, TokenIntegrityLevel).and_then(
                |b| {
                    // SAFETY: the buffer is a whole TOKEN_MANDATORY_LABEL; its SID points inside
                    // it and its last sub authority is the integrity RID.
                    unsafe {
                        let sid = (*b.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()).Label.Sid;
                        let n = u32::from(*GetSidSubAuthorityCount(sid));
                        (n > 0).then(|| *GetSidSubAuthority(sid, n - 1))
                    }
                },
            ),
        };
        // SAFETY: opened above, closed once.
        unsafe { CloseHandle(token) };
        facts
    }

    /// The facts of every process that holds `pipe` now, each pinned by a handle before its token
    /// is read (F41, F46). A holder whose token cannot be read has None facts, which no rule
    /// trusts; None when the list cannot be settled. Every handle is closed once, except the
    /// server's pin, returned when `server` (the instance's server pid, pinned with SYNCHRONIZE
    /// before the first list so the common case lists once) is still among the holders.
    ///
    /// # Safety
    /// `pipe` must be an open pipe handle and `expected` a valid SID, both alive for the call.
    unsafe fn pipe_holders(
        pipe: HANDLE,
        expected: PSID,
        server: Option<u32>,
    ) -> Option<(Vec<HolderFacts>, Option<OwnedHandle>)> {
        let own = token_info::<TOKEN_USER>(TokenUser)?;
        // SAFETY: `token_info` checked the buffer holds a whole TOKEN_USER.
        let own_sid = unsafe { (*own.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        let query = PROCESS_QUERY_LIMITED_INFORMATION;
        let first =
            server.and_then(|pid| Some((pid, pin_process(pid, query | PROCESS_SYNCHRONIZE)?)));
        let pinned = settle_holders(first, || list_holders(pipe), |pid| pin_process(pid, query))?;
        let facts = pinned
            .iter()
            // SAFETY: each pin is an open process handle; the SIDs are valid (caller, above).
            .map(|(_, h)| unsafe { holder_facts(h.as_raw_handle(), expected, own_sid) })
            .collect();
        let pin = pinned.into_iter().find(|(p, _)| Some(*p) == server);
        Some((facts, pin.map(|(_, h)| h)))
    }

    /// The decision of [`pipe_server_is_ours`] from what its queries returned (None: the query
    /// failed): trusted only if every query worked and the owner is our user or default owner.
    ///
    /// # Safety
    /// Every non-null SID given must point to a valid SID for the whole call.
    unsafe fn owner_is_ours(
        owner: Option<PSID>,
        user: Option<PSID>,
        default: Option<PSID>,
    ) -> bool {
        let valid = |sid: Option<PSID>| sid.filter(|p| !p.is_null());
        let (Some(owner), Some(user), Some(default)) = (valid(owner), valid(user), valid(default))
        else {
            return false;
        };
        // SAFETY: all three are non-null and valid (caller).
        unsafe { EqualSid(owner, user) != 0 || EqualSid(owner, default) != 0 }
    }

    /// This process's token information of `class`, which must be a `T` (TOKEN_USER,
    /// TOKEN_OWNER), in a buffer aligned for it; the SID it holds points inside the buffer.
    fn token_info<T>(class: TOKEN_INFORMATION_CLASS) -> Option<Vec<u64>> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: GetCurrentProcess is a pseudo handle that needs no closing; `token` is a valid
        // out pointer.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return None;
        }
        let info = info_of::<T>(token, class);
        // SAFETY: closes the token opened above, exactly once.
        unsafe { CloseHandle(token) };
        info
    }

    /// The information of `class` of an open `token` (TOKEN_QUERY), which must be a `T`, in a
    /// buffer aligned for it.
    fn info_of<T>(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Option<Vec<u64>> {
        let mut len = 0u32;
        // SAFETY: size query: null buffer of length 0, `len` is a valid out pointer.
        unsafe { GetTokenInformation(token, class, std::ptr::null_mut(), 0, &mut len) };
        // u64 elements keep the buffer aligned for the TOKEN_* struct.
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        // SAFETY: `buf` holds at least `len` writable bytes.
        let ok =
            unsafe { GetTokenInformation(token, class, buf.as_mut_ptr().cast(), len, &mut len) };
        (ok != 0 && len as usize >= size_of::<T>()).then_some(buf)
    }

    /// The pipe's self-relative security descriptor, read through our client end (READ_CONTROL
    /// comes with the GENERIC_READ it was opened with); None if it has no owner.
    fn pipe_owner(pipe: HANDLE) -> Option<Vec<u64>> {
        let mut len = 0u32;
        // SAFETY: size query: null buffer of length 0, `len` is a valid out pointer; `pipe` is
        // the open client end, alive for this whole call.
        unsafe {
            GetKernelObjectSecurity(
                pipe,
                OWNER_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                0,
                &mut len,
            )
        };
        if len == 0 {
            return None;
        }
        // u64 elements keep the buffer aligned for the descriptor and the SID inside it.
        let mut sd = vec![0u64; (len as usize).div_ceil(8)];
        // SAFETY: `sd` holds at least `len` writable bytes. A descriptor grown since the size
        // query fails here (insufficient buffer) instead of overflowing.
        let ok = unsafe {
            GetKernelObjectSecurity(
                pipe,
                OWNER_SECURITY_INFORMATION,
                sd.as_mut_ptr().cast(),
                len,
                &mut len,
            )
        };
        // SAFETY: on success `sd` holds a valid self-relative descriptor.
        (ok != 0 && !unsafe { owner_sid(&sd) }.is_null()).then_some(sd)
    }

    /// The owner inside `sd` (null if it has none, or on failure); it points into `sd`.
    ///
    /// # Safety
    /// `sd` must hold a valid self-relative security descriptor.
    unsafe fn owner_sid(sd: &[u64]) -> PSID {
        let (mut owner, mut defaulted): (PSID, _) = (std::ptr::null_mut(), 0);
        // SAFETY: `sd` is a valid descriptor (caller) that the call only reads; the out pointers
        // are valid.
        let ok = unsafe {
            GetSecurityDescriptorOwner(sd.as_ptr().cast_mut().cast(), &mut owner, &mut defaulted)
        };
        if ok == 0 { std::ptr::null_mut() } else { owner }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// A SID S-1-5-<subs> built by hand, in a buffer aligned for it.
        fn sid(subs: &[u32]) -> Vec<u64> {
            let mut b = vec![1, subs.len() as u8, 0, 0, 0, 0, 0, 5];
            subs.iter().for_each(|s| b.extend(s.to_le_bytes()));
            b.resize(b.len().div_ceil(8) * 8, 0);
            b.chunks(8)
                .map(|c| u64::from_ne_bytes(c.try_into().unwrap()))
                .collect()
        }

        fn p(sid: &[u64]) -> Option<PSID> {
            Some(sid.as_ptr().cast_mut().cast())
        }

        /// Separate buffers with equal contents: the decision compares SIDs, not pointers.
        #[test]
        fn the_owner_decision_trusts_only_our_user_or_default_owner() {
            let (user, admins, system) = (sid(&[21, 1, 2, 3, 1001]), sid(&[32, 544]), sid(&[18]));
            let (user2, admins2) = (user.clone(), admins.clone());
            // SAFETY: every SID is a valid hand-built SID alive for the call.
            unsafe {
                assert!(owner_is_ours(p(&user2), p(&user), p(&admins)));
                assert!(owner_is_ours(p(&admins2), p(&user), p(&admins)));
                assert!(!owner_is_ours(p(&system), p(&user), p(&admins)));
                assert!(!owner_is_ours(
                    p(&sid(&[21, 1, 2, 3, 1002])),
                    p(&user),
                    p(&admins)
                ));
            }
        }

        /// Any failed query refuses, even when the other answers would trust the owner.
        #[test]
        fn the_owner_decision_refuses_any_failed_query() {
            let (user, admins) = (sid(&[21, 1, 2, 3, 1001]), sid(&[32, 544]));
            let null = Some(std::ptr::null_mut());
            // SAFETY: every non-null SID is a valid hand-built SID alive for the call.
            unsafe {
                assert!(!owner_is_ours(None, p(&user), p(&admins)));
                assert!(!owner_is_ours(null, p(&user), p(&admins)));
                assert!(!owner_is_ours(p(&admins), None, p(&admins)));
                assert!(!owner_is_ours(p(&admins), null, p(&admins)));
                assert!(!owner_is_ours(p(&user), p(&user), None));
                assert!(!owner_is_ours(p(&user), p(&user), null));
            }
        }

        use super::super::{connect_checked, is_foreign, server_is_ours};
        use crate::protocol::guest_socket_name;
        use std::cell::Cell;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        use windows_sys::Win32::Foundation::{
            DUPLICATE_SAME_ACCESS, DuplicateHandle, INVALID_HANDLE_VALUE,
        };
        use windows_sys::Win32::Security::{
            CreateRestrictedToken, IsTokenRestricted, SID_AND_ATTRIBUTES, TOKEN_ACCESS_INFORMATION,
            TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_GROUPS, TokenAccessInformation,
            TokenLogonSid, WRITE_RESTRICTED,
        };
        use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
        use windows_sys::Win32::System::Pipes::{
            CreateNamedPipeW, PIPE_TYPE_BYTE, PIPE_WAIT, PeekNamedPipe,
        };
        use windows_sys::Win32::System::Threading::{
            CREATE_SUSPENDED, CreateProcessAsUserW, CreateProcessW, OpenProcess,
            PROCESS_DUP_HANDLE, PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
            STARTUPINFOW, TerminateProcess,
        };

        fn wide(s: &str) -> Vec<u16> {
            s.encode_utf16().chain([0]).collect()
        }

        /// A suspended `ping` the test created; killed and closed through its handles on drop.
        struct Proc {
            process: HANDLE,
            thread: HANDLE,
            pid: u32,
        }

        impl Drop for Proc {
            fn drop(&mut self) {
                // SAFETY: both handles came from CreateProcess and are closed exactly once.
                unsafe {
                    TerminateProcess(self.process, 1);
                    CloseHandle(self.thread);
                    CloseHandle(self.process);
                }
            }
        }

        /// A suspended `ping`: with `token` (CreateProcessAsUserW) or with this process's own.
        /// Suspended because a restricted `ping` that runs exits at once (0xC0000142, F45).
        fn spawn_ping(token: Option<HANDLE>) -> Proc {
            let root = std::env::var("SystemRoot").unwrap();
            let mut cmd = wide(&format!("\"{root}\\System32\\ping.exe\" -n 30 127.0.0.1"));
            // SAFETY: plain C structs, all-zero is valid; `cb` is set below.
            let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
            si.cb = size_of::<STARTUPINFOW>() as u32;
            let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
            // SAFETY: `cmd` is a writable NUL-terminated buffer; `si` and `pi` are valid.
            let ok = unsafe {
                match token {
                    Some(t) => CreateProcessAsUserW(
                        t,
                        std::ptr::null(),
                        cmd.as_mut_ptr(),
                        std::ptr::null(),
                        std::ptr::null(),
                        0,
                        CREATE_SUSPENDED,
                        std::ptr::null(),
                        std::ptr::null(),
                        &si,
                        &mut pi,
                    ),
                    None => CreateProcessW(
                        std::ptr::null(),
                        cmd.as_mut_ptr(),
                        std::ptr::null(),
                        std::ptr::null(),
                        0,
                        CREATE_SUSPENDED,
                        std::ptr::null(),
                        std::ptr::null(),
                        &si,
                        &mut pi,
                    ),
                }
            };
            assert!(ok != 0, "{}", std::io::Error::last_os_error());
            Proc {
                process: pi.hProcess,
                thread: pi.hThread,
                pid: pi.dwProcessId,
            }
        }

        /// `ping` suspended with this token made WRITE_RESTRICTED over [Everyone, logon SID], the
        /// way Codex's sandbox does it (F32).
        fn spawn_restricted_ping() -> Proc {
            let mut own: HANDLE = std::ptr::null_mut();
            // SAFETY: valid out pointer; the pseudo handle needs no closing.
            assert!(
                unsafe {
                    OpenProcessToken(
                        GetCurrentProcess(),
                        TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY,
                        &mut own,
                    )
                } != 0
            );
            let mut len = 0u32;
            // SAFETY: size query, then a buffer of that many u64 (aligned for TOKEN_GROUPS).
            unsafe { GetTokenInformation(own, TokenLogonSid, std::ptr::null_mut(), 0, &mut len) };
            let mut groups = vec![0u64; (len as usize).div_ceil(8)];
            // SAFETY: `groups` holds at least `len` writable bytes.
            let ok = unsafe {
                GetTokenInformation(
                    own,
                    TokenLogonSid,
                    groups.as_mut_ptr().cast(),
                    len,
                    &mut len,
                )
            };
            assert!(ok != 0, "{}", std::io::Error::last_os_error());
            // SAFETY: on success the buffer is a TOKEN_GROUPS with one entry (the logon SID).
            let logon = unsafe { (*groups.as_ptr().cast::<TOKEN_GROUPS>()).Groups[0].Sid };
            // S-1-1-0 (Everyone) by hand: revision 1, one sub authority, authority 1.
            let everyone = [1u8, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
            let restrict = [
                SID_AND_ATTRIBUTES {
                    Sid: everyone.as_ptr().cast_mut().cast(),
                    Attributes: 0,
                },
                SID_AND_ATTRIBUTES {
                    Sid: logon,
                    Attributes: 0,
                },
            ];
            let mut restricted: HANDLE = std::ptr::null_mut();
            // SAFETY: both SIDs outlive the call; `restricted` is a valid out pointer.
            let ok = unsafe {
                CreateRestrictedToken(
                    own,
                    WRITE_RESTRICTED,
                    0,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    2,
                    restrict.as_ptr(),
                    &mut restricted,
                )
            };
            assert!(ok != 0, "{}", std::io::Error::last_os_error());
            // The fixture is what it claims: the token carries TOKEN_WRITE_RESTRICTED (0x8).
            assert_eq!(WRITE_RESTRICTED, 0x8);
            let access = info_of::<TOKEN_ACCESS_INFORMATION>(restricted, TokenAccessInformation)
                .expect("TokenAccessInformation");
            // SAFETY: info_of checked the buffer holds a whole TOKEN_ACCESS_INFORMATION, aligned.
            let flags = unsafe { (*access.as_ptr().cast::<TOKEN_ACCESS_INFORMATION>()).Flags };
            assert_eq!(flags & 0x8, 0x8, "token flags {flags:#x}");
            let proc = spawn_ping(Some(restricted));
            // SAFETY: both tokens were opened above and are closed once.
            unsafe {
                CloseHandle(restricted);
                CloseHandle(own);
            }
            proc
        }

        /// A listening instance of `\\.\pipe\<name>` owned by us by name (as the daemon's guest
        /// pipe is: an elevated token's default owner is Administrators, #12), with a DACL that
        /// mirrors the default one: Everyone and Anonymous read; SYSTEM, Administrators and us all.
        fn create_pipe(name: &str) -> HANDLE {
            use windows_sys::Win32::Foundation::LocalFree;
            use windows_sys::Win32::Security::Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                SDDL_REVISION_1,
            };
            use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
            let full = wide(&format!(r"\\.\pipe\{name}"));
            let mine = own_sid().unwrap();
            let mut text: *mut u16 = std::ptr::null_mut();
            // SAFETY: `mine` holds a whole SID; `text` is an out pointer, freed below.
            let ok = unsafe { ConvertSidToStringSidW(mine.as_ptr().cast_mut().cast(), &mut text) };
            assert!(ok != 0, "{}", std::io::Error::last_os_error());
            // SAFETY: `text` is the NUL-terminated string the call just made.
            let me = unsafe {
                let len = (0..).find(|&i| *text.add(i) == 0).unwrap();
                let me = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
                LocalFree(text.cast());
                me
            };
            let sddl = wide(&format!(
                "O:{me}D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{me})(A;;GR;;;WD)(A;;GR;;;AN)"
            ));
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            // SAFETY: NUL-terminated SDDL; `sd` is an out pointer, freed below.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut sd,
                    std::ptr::null_mut(),
                )
            };
            assert!(ok != 0, "{}", std::io::Error::last_os_error());
            let sa = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd,
                bInheritHandle: 0,
            };
            // SAFETY: `full` is NUL-terminated; `sa` and `sd` outlive the call.
            let h = unsafe {
                CreateNamedPipeW(
                    full.as_ptr(),
                    PIPE_ACCESS_DUPLEX,
                    PIPE_TYPE_BYTE | PIPE_WAIT,
                    255,
                    4096,
                    4096,
                    0,
                    &sa,
                )
            };
            assert!(
                h != INVALID_HANDLE_VALUE,
                "{}",
                std::io::Error::last_os_error()
            );
            // SAFETY: allocated by the conversion, freed once.
            unsafe { LocalFree(sd) };
            h
        }

        /// Duplicates `handle` of this process into `target` (a process handle with DUP_HANDLE).
        fn dup_into(handle: HANDLE, target: HANDLE) {
            let mut out: HANDLE = std::ptr::null_mut();
            // SAFETY: valid handles and out pointer.
            let ok = unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    handle,
                    target,
                    &mut out,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            };
            assert!(ok != 0, "{}", std::io::Error::last_os_error());
        }

        /// Whether the token of process `pid`, read through a fresh handle, is not restricted.
        fn has_full_token(pid: u32) -> bool {
            // SAFETY: handles opened here are closed here; `token` is a valid out pointer.
            unsafe {
                let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
                assert!(!process.is_null(), "{}", std::io::Error::last_os_error());
                let mut token: HANDLE = std::ptr::null_mut();
                assert!(OpenProcessToken(process, TOKEN_QUERY, &mut token) != 0);
                let restricted = IsTokenRestricted(token) != 0;
                CloseHandle(token);
                CloseHandle(process);
                !restricted
            }
        }

        thread_local! {
            /// The pid GetNamedPipeServerProcessId must name in the connection being judged.
            static CREATOR: Cell<u32> = const { Cell::new(0) };
            /// Class-47 queries (`list_holders`) made on this thread.
            pub(super) static LISTS: Cell<usize> = const { Cell::new(0) };
        }

        /// What `f` returned and how many class-47 queries it made on this thread.
        fn lists_in<T>(f: impl FnOnce() -> T) -> (T, usize) {
            let before = LISTS.get();
            let r = f();
            (r, LISTS.get() - before)
        }

        /// Makes this process the remembered daemon of another pipe name, as a CLI that verified
        /// its daemon before. Returns the two server ends, for the caller to close.
        fn remembered_elsewhere(tag: &str) -> [HANDLE; 2] {
            let name = format!("sync_gate_core-cached-{tag}-{}", std::process::id());
            let servers = [create_pipe(&name), create_pipe(&name)];
            let (first, _) = lists_in(|| connect_checked(&name, server_is_ours));
            let (again, lists) = lists_in(|| connect_checked(&name, server_is_ours));
            assert!(first.is_ok() && again.is_ok(), "premise: our own pipe");
            assert_eq!(lists, 0, "premise: this process is remembered as a daemon");
            servers
        }

        /// `server_is_ours` after the premise of F42: the pid the v4 rule would have read is the
        /// creator's and its token is full, so only the holders can refuse this server.
        fn premise_then_judge(s: &Stream) -> bool {
            let Stream::NamedPipe(p) = s;
            let mut pid = 0u32;
            // SAFETY: the client end is open for the whole call; `pid` is a valid out pointer.
            let ok = unsafe {
                GetNamedPipeServerProcessId(p.inner().as_handle().as_raw_handle(), &mut pid)
            };
            assert!(ok != 0, "{}", std::io::Error::last_os_error());
            assert_eq!(pid, CREATOR.get(), "premise: the creator's pid");
            assert!(has_full_token(pid), "premise: the creator's token is full");
            server_is_ours(s)
        }

        /// F42 E2dup: the creator (full token, alive) hands the server end to a restricted
        /// process and closes its own; only the holders show it.
        #[test]
        fn a_pipe_held_by_a_restricted_process_of_ours_is_foreign() {
            // This very pid is remembered as the daemon of another name: the refusal below must
            // not take it as the daemon of this one.
            let cached = remembered_elsewhere("e2");
            CREATOR.set(std::process::id());
            let name = format!("sync_gate_core-f27-{}", std::process::id());
            let server = create_pipe(&name);
            let b = spawn_restricted_ping();
            dup_into(server, b.process);
            // SAFETY: our own end, closed once; B keeps the instance alive.
            unsafe { CloseHandle(server) };
            let r = connect_checked(&name, premise_then_judge);
            assert!(
                r.as_ref().is_err_and(is_foreign),
                "held by a restricted process: {:?}",
                r.map(|_| ())
            );

            // Control: the same hand-over to a full-token process is trusted.
            let name = format!("{name}-control");
            let server = create_pipe(&name);
            let b2 = spawn_ping(None);
            dup_into(server, b2.process);
            // SAFETY: as above.
            unsafe { CloseHandle(server) };
            let r = connect_checked(&name, premise_then_judge);
            assert!(r.is_ok(), "held by a full-token process: {:?}", r.err());
            for h in cached {
                // SAFETY: our own ends, closed once.
                unsafe { CloseHandle(h) };
            }
        }

        /// Bytes waiting on the server end `pipe`; a client that closed without writing leaves 0
        /// (a broken pipe counts as 0). Never blocks.
        fn waiting(pipe: HANDLE) -> u32 {
            let mut avail = 0u32;
            // SAFETY: `pipe` is an open server end; only the available-bytes out pointer is given.
            unsafe {
                PeekNamedPipe(
                    pipe,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut avail,
                    std::ptr::null_mut(),
                )
            };
            avail
        }

        /// A new pipe `name` whose only server end now lives in `holder` (we close ours).
        fn pipe_held_by(name: &str, holder: &Proc) {
            let server = create_pipe(name);
            dup_into(server, holder.process);
            // SAFETY: our own end, closed once; the holder keeps the instance alive.
            unsafe { CloseHandle(server) };
        }

        /// Test 4: a guest trusts the named owner, and (except on the AppContainer path) every
        /// holder of the pipe.
        #[test]
        fn a_guest_trusts_only_the_named_owner_and_its_holders() {
            let base = format!("sync_gate_core-guest-{}", std::process::id());
            let path = |n: &str| format!(r"\\.\pipe\{}", guest_socket_name(&base, n));
            let me = own_sid().unwrap();

            // Served by this test: the named owner passes, and the server reads what we send.
            let name = guest_socket_name(&base, "tester");
            let server = create_pipe(&name);
            let mut ok = connect_guest_at(&path("tester"), &me, Some(Peers::SameUser))
                .unwrap_or_else(|e| panic!("trusted pipe refused: {e}"));
            std::io::Write::write_all(&mut ok, b"ping").unwrap();
            std::io::Write::flush(&mut ok).unwrap();
            assert_eq!(waiting(server), 4, "control: bytes do arrive");
            drop(ok);
            // SAFETY: our own end, closed once.
            unsafe { CloseHandle(server) };

            // Another owner: refused before any byte.
            let server = create_pipe(&name);
            let system = sid(&[18]);
            let r = connect_guest_at(&path("tester"), &system, Some(Peers::SameUser));
            assert!(r.as_ref().is_err_and(is_foreign), "{:?}", r.map(|_| ()));
            assert_eq!(waiting(server), 0);
            // SAFETY: as above.
            unsafe { CloseHandle(server) };

            // No such pipe.
            let r = connect_guest_at(&path("absent"), &me, Some(Peers::SameUser));
            assert_eq!(
                r.err().map(|e| e.kind()),
                Some(std::io::ErrorKind::NotFound)
            );

            // The only server end is in a restricted process of ours (suspended).
            let b = spawn_restricted_ping();
            for (suffix, peers, trusted) in [
                ("a", Some(Peers::RestrictedOwner), false),
                ("b", Some(Peers::Nobody), false),
                // The AppContainer path takes no holder check: the residue of decision 4.
                ("c", None, true),
            ] {
                let n = format!("held{suffix}");
                pipe_held_by(&guest_socket_name(&base, &n), &b);
                let r = connect_guest_at(&path(&n), &me, peers);
                if trusted {
                    assert!(r.is_ok(), "{suffix}: {:?}", r.err());
                } else {
                    assert!(
                        r.as_ref().is_err_and(is_foreign),
                        "{suffix}: {:?}",
                        r.map(|_| ())
                    );
                }
            }

            // Two instances: one held by this test (full token), one by the restricted process.
            for (suffix, peers, trusted) in [
                ("d", Peers::RestrictedOwner, true),
                ("e", Peers::Nobody, false),
            ] {
                let n = format!("two{suffix}");
                let full = guest_socket_name(&base, &n);
                let ours = create_pipe(&full);
                pipe_held_by(&full, &b);
                let r = connect_guest_at(&path(&n), &me, Some(peers));
                if trusted {
                    assert!(r.is_ok(), "{suffix}: {:?}", r.err());
                } else {
                    assert!(
                        r.as_ref().is_err_and(is_foreign),
                        "{suffix}: {:?}",
                        r.map(|_| ())
                    );
                }
                drop(r);
                // SAFETY: our own end, closed once.
                unsafe { CloseHandle(ours) };
            }
        }

        /// Child half of test 46: creates the pipe, hands the server end to the process whose pid
        /// is in the environment, then exits. Does nothing unless the parent set the variables.
        #[test]
        #[ignore = "run by a_handle_kept_after_its_creator_exits_is_judged_by_its_holder"]
        fn pipe_creator_helper() {
            let (Ok(name), Ok(pid)) = (
                std::env::var("SYNC_GATE_F27_PIPE"),
                std::env::var("SYNC_GATE_F27_HOLDER"),
            ) else {
                return;
            };
            let server = create_pipe(&name);
            // SAFETY: the handle is closed below; the pid is the parent's `ping`.
            let target = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, pid.parse().unwrap()) };
            assert!(!target.is_null(), "{}", std::io::Error::last_os_error());
            dup_into(server, target);
            // SAFETY: opened above, closed once.
            unsafe { CloseHandle(target) };
            println!("handed");
        }

        /// Waits up to 60 s for `child` to exit; else kills it and panics.
        fn wait_or_kill(child: &mut std::process::Child, what: &str) -> std::process::ExitStatus {
            let start = Instant::now();
            loop {
                if let Some(s) = child.try_wait().unwrap() {
                    return s;
                }
                if start.elapsed() > Duration::from_secs(60) {
                    // Close our end of its stdout first so nothing can block on it, then kill and
                    // wait a bounded time (termination is asynchronous).
                    drop(child.stdout.take());
                    let killed = child.kill();
                    let end = Instant::now() + Duration::from_secs(10);
                    while child.try_wait().ok().flatten().is_none() && Instant::now() < end {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    panic!("{what} still running after 60 s (kill: {killed:?})");
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }

        /// Runs the creator child for `name` (holder pid `holder`) and returns it exited, still
        /// unreaped: its process object stays, so its pid still reads a full token (F42).
        fn run_creator(name: &str, holder: u32) -> std::process::Child {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "ipc_name::windows::tests::pipe_creator_helper",
                    "--ignored",
                    "--nocapture",
                ])
                .env("SYNC_GATE_F27_PIPE", name)
                .env("SYNC_GATE_F27_HOLDER", holder.to_string())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let status = wait_or_kill(&mut child, "creator helper");
            // The creator exited, so its stdout reaches EOF.
            let mut out = String::new();
            std::io::Read::read_to_string(&mut child.stdout.take().unwrap(), &mut out).unwrap();
            assert!(status.success(), "creator: {status:?} {out}");
            assert!(out.lines().any(|l| l == "handed"), "creator: {out}");
            child
        }

        /// F42 E3dup: the creator is another process that hands the end over and exits; the
        /// pid the v4 rule would read still has a full token, the holder does not.
        #[test]
        fn a_handle_kept_after_its_creator_exits_is_judged_by_its_holder() {
            let name = format!("sync_gate_core-f27-{}-e3", std::process::id());
            let cached = remembered_elsewhere("e3");
            let b = spawn_restricted_ping();
            let mut creator = run_creator(&name, b.pid);
            CREATOR.set(creator.id());
            let r = connect_checked(&name, premise_then_judge);
            assert!(
                r.as_ref().is_err_and(is_foreign),
                "held by a restricted process: {:?}",
                r.map(|_| ())
            );

            // Control: the same with a full-token holder is trusted.
            let name = format!("{name}-control");
            let b2 = spawn_ping(None);
            let mut creator2 = run_creator(&name, b2.pid);
            CREATOR.set(creator2.id());
            let r = connect_checked(&name, premise_then_judge);
            assert!(r.is_ok(), "held by a full-token process: {:?}", r.err());
            // Already exited; the handle of its process object lives until `Child` drops.
            creator.wait().unwrap();
            creator2.wait().unwrap();
            for h in cached {
                // SAFETY: our own ends, closed once.
                unsafe { CloseHandle(h) };
            }
        }

        /// Child half of the cache test: a daemon in another process. Creates the pipe, says
        /// `ready`, and on a line from stdin creates a second instance, hands it to the process
        /// whose pid is in the environment, says `handed` and exits. Does nothing unless the
        /// parent set the variables.
        #[test]
        #[ignore = "run by a_verified_daemon_is_remembered_only_while_it_serves"]
        fn daemon_helper() {
            let (Ok(name), Ok(pid)) = (
                std::env::var("SYNC_GATE_F27_DAEMON"),
                std::env::var("SYNC_GATE_F27_HOLDER"),
            ) else {
                return;
            };
            // Kept until this process exits.
            let _first = create_pipe(&name);
            println!("ready");
            std::io::stdin().read_line(&mut String::new()).unwrap();
            let server = create_pipe(&name);
            // SAFETY: the handle is closed below; the pid is the parent's `ping`.
            let target = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, pid.parse().unwrap()) };
            assert!(!target.is_null(), "{}", std::io::Error::last_os_error());
            dup_into(server, target);
            // SAFETY: opened above, closed once.
            unsafe { CloseHandle(target) };
            println!("handed");
        }

        /// Reads lines of `out` until `line`; false at EOF.
        /// Waits at most 30 s for `line` from the helper's stdout (a reader thread feeds `rx`).
        /// On a timeout or a closed pipe the helper is killed through its handle (bounded wait)
        /// before the panic, so a stalled helper cannot hang the test or outlive it.
        fn read_until(
            rx: &std::sync::mpsc::Receiver<String>,
            child: &mut std::process::Child,
            line: &str,
        ) {
            let end = Instant::now() + Duration::from_secs(30);
            let found = loop {
                let left = end.saturating_duration_since(Instant::now());
                match rx.recv_timeout(left) {
                    Ok(l) if l == line => break true,
                    Ok(_) => {}
                    Err(_) => break false,
                }
            };
            if !found {
                let killed = child.kill();
                let end = Instant::now() + Duration::from_secs(10);
                while child.try_wait().ok().flatten().is_none() && Instant::now() < end {
                    std::thread::sleep(Duration::from_millis(50));
                }
                panic!("daemon helper never printed {line:?} (kill: {killed:?})");
            }
        }

        /// A verified daemon spares later connections the class-47 query, and only while the
        /// same live process serves the name.
        #[test]
        fn a_verified_daemon_is_remembered_only_while_it_serves() {
            // In process: the first connection lists once (its server pinned first), the second
            // not at all.
            let name = format!("sync_gate_core-cache-{}", std::process::id());
            let servers = [create_pipe(&name), create_pipe(&name)];
            let ((a, b), lists) = lists_in(|| {
                (
                    connect_checked(&name, server_is_ours),
                    connect_checked(&name, server_is_ours),
                )
            });
            assert!(a.is_ok() && b.is_ok(), "{:?} {:?}", a.err(), b.err());
            assert_eq!(lists, 1, "two connections, one class-47 query");
            drop((a, b));
            for h in servers {
                // SAFETY: our own ends, closed once; the name has no instance left.
                unsafe { CloseHandle(h) };
            }

            // The first server stopped, another process serves the name: its pid is not the
            // remembered one, so the full check runs.
            let full = spawn_ping(None);
            let mut creator = run_creator(&name, full.pid);
            CREATOR.set(creator.id());
            let (r, lists) = lists_in(|| connect_checked(&name, premise_then_judge));
            assert!(r.is_ok(), "held by a full-token process: {:?}", r.err());
            assert!(lists >= 1, "the full check ran");
            drop(r);
            creator.wait().unwrap();

            // A daemon in another process, verified and remembered...
            let name = format!("{name}-daemon");
            let b = spawn_restricted_ping();
            let mut daemon = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "ipc_name::windows::tests::daemon_helper",
                    "--ignored",
                    "--nocapture",
                ])
                .env("SYNC_GATE_F27_DAEMON", &name)
                .env("SYNC_GATE_F27_HOLDER", b.pid.to_string())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let out = std::io::BufReader::new(daemon.stdout.take().unwrap());
            let (tx, lines) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                for l in std::io::BufRead::lines(out).map_while(Result::ok) {
                    if tx.send(l).is_err() {
                        break;
                    }
                }
            });
            read_until(&lines, &mut daemon, "ready");
            let (r, lists) = lists_in(|| connect_checked(&name, server_is_ours));
            assert!(r.is_ok(), "the daemon's own pipe: {:?}", r.err());
            assert_eq!(lists, 1);
            drop(r);
            // ...then hands a new instance to a restricted process and exits. That instance's
            // server pid is the remembered one, still pinned by the cache, but no longer alive.
            let mut stdin = daemon.stdin.take().unwrap();
            std::io::Write::write_all(&mut stdin, b"go\n").unwrap();
            drop(stdin);
            read_until(&lines, &mut daemon, "handed");
            let status = wait_or_kill(&mut daemon, "daemon helper");
            assert!(status.success(), "daemon helper: {status:?}");
            CREATOR.set(daemon.id());
            let (r, lists) = lists_in(|| connect_checked(&name, premise_then_judge));
            assert!(
                r.as_ref().is_err_and(is_foreign),
                "held by a restricted process: {:?}",
                r.map(|_| ())
            );
            assert!(lists >= 1, "the full check ran");
        }
    }
}
