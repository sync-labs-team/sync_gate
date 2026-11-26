//! The guests' door: a sandboxed Codex (another local account, an AppContainer, or the owner's
//! write-restricted token) queues its commands through its own narrow pipe. Every request is
//! judged by the identity of the message itself (F47); a guest acts only on its own tickets,
//! never reaches the leases, the MCP hub or the owner's history.

use crate::control_loop::{Caller, Control, Core};
use std::time::Instant;
use sync_gate_core::{APPCONTAINER_GUEST, RESTRICTED_GUEST, Request, Response};
use sync_gate_probe::IdentKind;

/// Live connections one guest pipe serves at once; the one over is dropped unread.
#[cfg_attr(not(windows), allow(dead_code))]
pub const GUEST_MAX_CONNECTIONS: usize = 16;

/// The capability Codex `mxc` asks for (src-codex mxc-policy.rs:337), as a SID: the
/// DeriveCapabilitySidsFromName("registryRead") value measured in F31 (test 14 re-derives it).
pub const REGISTRY_READ_CAPABILITY: &str = "S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681";

/// SidTypeUser in SID_NAME_USE.
const SID_TYPE_USER: i32 = 1;

#[cfg_attr(not(windows), allow(dead_code))]
pub struct Guest {
    pub index: u8,
    /// Lowercase account, or "@appcontainer" / "@restricted".
    pub name: String,
    pub kind: IdentKind,
    /// Account SID | REGISTRY_READ_CAPABILITY | the daemon's logon SID.
    pub ace_sid: String,
    /// Windows: (ident, start in seconds): process_ident(pid, &kind), then
    /// sync_gate_probe::start_time(pid) while that handle is still open; the handle is closed on
    /// return. The seconds only feed R13a and the pause's root check, which re-reads the ident
    /// through a handle: a wrong value can only make the job look gone or skip a pause (fail
    /// open). Tests fake it.
    pub ident_of_pid: Box<dyn Fn(u32) -> Option<(String, u64)> + Send + Sync>,
}

/// One resolved entry: (index, name, kind, the SID its pipe's ACE names).
pub type Resolved = (u8, String, IdentKind, String);

/// Resolves `cfg.guests`. An account (name -> (sid, SID_NAME_USE) by `lookup`) is kept when it is
/// a user account (SidTypeUser) of the local account domain (its SID minus the last RID equals
/// `local_domain`, ignoring case) and not `own_sid`; "@appcontainer" -> AppContainer(own_sid)
/// with REGISTRY_READ_CAPABILITY; "@restricted" -> Restricted(own_sid) with `logon`. One note
/// per skipped entry ("<name>: <why>"); indices consecutive from 0.
pub fn resolve(
    names: &[String],
    lookup: impl Fn(&str) -> Option<(String, i32)>,
    own_sid: &str,
    local_domain: &str,
    logon: Option<&str>,
) -> (Vec<Resolved>, Vec<String>) {
    let (mut kept, mut notes) = (Vec::new(), Vec::new());
    for name in names {
        let entry = match name.as_str() {
            APPCONTAINER_GUEST => Ok((
                IdentKind::AppContainer(own_sid.into()),
                REGISTRY_READ_CAPABILITY.to_string(),
            )),
            RESTRICTED_GUEST => logon
                .map(|l| (IdentKind::Restricted(own_sid.into()), l.to_string()))
                .ok_or("cannot read this session's logon SID"),
            _ => account(name, &lookup, own_sid, local_domain)
                .map(|sid| (IdentKind::Account(sid.clone()), sid)),
        };
        match entry {
            Ok((kind, ace)) => {
                let index = kept.len() as u8;
                kept.push((index, name.to_lowercase(), kind, ace));
            }
            Err(note) => notes.push(format!("{name}: {note}")),
        }
    }
    (kept, notes)
}

/// The SID of a local user account other than the daemon's own (uppercase), or why not.
fn account(
    name: &str,
    lookup: &impl Fn(&str) -> Option<(String, i32)>,
    own_sid: &str,
    local_domain: &str,
) -> Result<String, &'static str> {
    let (sid, kind) = lookup(name).ok_or("unknown account")?;
    if kind != SID_TYPE_USER {
        return Err("is not a user account");
    }
    let local = sid
        .rsplit_once('-')
        .is_some_and(|(domain, _)| domain.eq_ignore_ascii_case(local_domain));
    if !local {
        return Err("is not a local account");
    }
    if sid.eq_ignore_ascii_case(own_sid) {
        return Err("is the daemon's own account");
    }
    // SIDs are digits and dashes after "S": uppercasing only normalises the prefix.
    Ok(sid.to_uppercase())
}

/// The guest door: the lease requests are refused; a Started is checked against the identity
/// of its pid; everything else goes to `handle_as`. Never reaches the MCP hub or the services.
/// `client` is the ident serve_guest read from this request's message (F47), never from a pid.
pub fn respond_guest<C: Control>(
    core: &Core<C>,
    g: &Guest,
    client: &str,
    req: Request,
    now: Instant,
) -> Response {
    let checked = match &req {
        Request::Lease { .. }
        | Request::LeaseHolder { .. }
        | Request::ReleaseLease { .. }
        | Request::LeaseGiveUp { .. }
        | Request::TemplateReady { .. } => {
            return Response::Error {
                message: "not available to sandboxed callers".into(),
            };
        }
        Request::Started { pid, .. } => (g.ident_of_pid)(*pid)
            .filter(|(ident, _)| ident == client)
            .map(|(_, start)| start),
        _ => None,
    };
    let caller = Caller::Guest {
        index: g.index,
        name: &g.name,
        client,
        checked,
    };
    core.handle_as(caller, req, now)
}

/// The real `ident_of_pid` for guests of `kind`.
#[cfg(windows)]
pub fn os_ident_of_pid(kind: IdentKind) -> Box<dyn Fn(u32) -> Option<(String, u64)> + Send + Sync> {
    Box::new(move |pid| {
        let (ident, _, handle) = sync_gate_probe::process_ident(pid, &kind)?;
        // Read while the handle pins the pid; it is closed on return.
        let start = sync_gate_probe::start_time(pid);
        drop(handle);
        Some((ident, start?))
    })
}

/// Name and SID of this machine's account domain, from the LSA (LsaOpenPolicy +
/// PolicyAccountDomainInformation); never from the environment (F17). None on any failure.
#[cfg(windows)]
pub fn local_account_domain() -> Option<(String, String)> {
    use windows_sys::Win32::Security::Authentication::Identity::{
        LSA_HANDLE, LSA_OBJECT_ATTRIBUTES, LsaClose, LsaFreeMemory, LsaOpenPolicy,
        LsaQueryInformationPolicy, POLICY_ACCOUNT_DOMAIN_INFO, POLICY_VIEW_LOCAL_INFORMATION,
        PolicyAccountDomainInformation,
    };
    let attrs = LSA_OBJECT_ATTRIBUTES {
        Length: size_of::<LSA_OBJECT_ATTRIBUTES>() as u32,
        ..Default::default()
    };
    let mut policy: LSA_HANDLE = 0;
    // SAFETY: null system name (this machine), valid attributes and out pointer.
    let status = unsafe {
        LsaOpenPolicy(
            std::ptr::null(),
            &attrs,
            POLICY_VIEW_LOCAL_INFORMATION as u32,
            &mut policy,
        )
    };
    if status != 0 {
        return None;
    }
    let mut buf: *mut core::ffi::c_void = std::ptr::null_mut();
    // SAFETY: `policy` is open; `buf` is a valid out pointer.
    let status =
        unsafe { LsaQueryInformationPolicy(policy, PolicyAccountDomainInformation, &mut buf) };
    let result = (status == 0 && !buf.is_null()).then(|| {
        // SAFETY: on success `buf` holds a POLICY_ACCOUNT_DOMAIN_INFO the LSA allocated.
        let info = unsafe { &*buf.cast::<POLICY_ACCOUNT_DOMAIN_INFO>() };
        let name = &info.DomainName;
        let text = if name.Buffer.is_null() {
            String::new()
        } else {
            // SAFETY: `Length` bytes of UTF-16 at `Buffer`, inside the LSA's allocation.
            String::from_utf16_lossy(unsafe {
                std::slice::from_raw_parts(name.Buffer, usize::from(name.Length) / 2)
            })
        };
        // SAFETY: the domain SID points inside the same allocation, alive until it is freed.
        let sid = unsafe { crate::ipc::sid_string(info.DomainSid) }.ok()?;
        Some((text, sid))
    });
    // SAFETY: each freed or closed exactly once, on every path.
    unsafe {
        if !buf.is_null() {
            LsaFreeMemory(buf);
        }
        LsaClose(policy);
    }
    result.flatten().filter(|(name, _)| !name.is_empty())
}

/// `{domain}\{name}` looked up on this machine: (SID, SID_NAME_USE). None on any failure.
#[cfg(windows)]
pub fn lookup_account(domain: &str, name: &str) -> Option<(String, i32)> {
    use windows_sys::Win32::Security::{LookupAccountNameW, SID_NAME_USE};
    let full: Vec<u16> = format!("{domain}\\{name}")
        .encode_utf16()
        .chain([0])
        .collect();
    let (mut sid_len, mut dom_len, mut kind): (u32, u32, SID_NAME_USE) = (0, 0, 0);
    // SAFETY: size query with null buffers; the lengths and kind are valid out pointers.
    unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            full.as_ptr(),
            std::ptr::null_mut(),
            &mut sid_len,
            std::ptr::null_mut(),
            &mut dom_len,
            &mut kind,
        )
    };
    if sid_len == 0 {
        return None;
    }
    // u64 elements keep the SID buffer aligned.
    let mut sid = vec![0u64; (sid_len as usize).div_ceil(8)];
    let mut dom = vec![0u16; dom_len.max(1) as usize];
    // SAFETY: both buffers hold at least the sizes the first call asked for.
    let ok = unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            full.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
            dom.as_mut_ptr(),
            &mut dom_len,
            &mut kind,
        )
    };
    if ok == 0 {
        return None;
    }
    // SAFETY: `sid` holds the SID just written, alive for the call.
    let sid = unsafe { crate::ipc::sid_string(sid.as_mut_ptr().cast()) }.ok()?;
    Some((sid, kind))
}

/// The logon SID of this process's session (`S-1-5-5-X-Y`), from its token.
#[cfg(windows)]
pub fn logon_sid() -> Option<String> {
    use windows_sys::Win32::Security::{TOKEN_GROUPS, TokenLogonSid};
    let buf = crate::ipc::token_info::<TOKEN_GROUPS>(TokenLogonSid).ok()?;
    // SAFETY: `buf` holds a whole TOKEN_GROUPS (size checked); its SIDs point inside `buf`.
    let groups = unsafe { &*buf.as_ptr().cast::<TOKEN_GROUPS>() };
    if groups.GroupCount == 0 {
        return None;
    }
    // SAFETY: the first group's SID points inside `buf`, alive here.
    unsafe { crate::ipc::sid_string(groups.Groups[0].Sid) }.ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOMAIN: &str = "S-1-5-21-1-2-3";
    const OWN: &str = "S-1-5-21-1-2-3-1000";

    fn fake(name: &str) -> Option<(String, i32)> {
        let entry = |sid: &str, kind| Some((sid.to_string(), kind));
        match name {
            "tester" => entry("S-1-5-21-1-2-3-1004", 1),
            "Second" => entry("s-1-5-21-1-2-3-1006", 1),
            "Users" => entry("S-1-5-32-545", 4),
            "group" => entry("S-1-5-21-1-2-3-513", 2),
            "Everyone" => entry("S-1-1-0", 5),
            "CodexSandboxOnline" => entry("S-1-5-21-9-9-9-1104", 1),
            "me" => entry(OWN, 1),
            _ => None,
        }
    }

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn guests_resolve_to_local_user_accounts_and_the_two_kinds() {
        let (kept, notes) = resolve(
            &names(&[
                "tester",
                "Users",
                "group",
                "Everyone",
                "CodexSandboxOnline",
                "Second",
                "me",
                "ghost",
                "@appcontainer",
                "@restricted",
            ]),
            fake,
            OWN,
            DOMAIN,
            Some("S-1-5-5-0-7"),
        );
        let account = |sid: &str| IdentKind::Account(sid.into());
        assert_eq!(
            kept,
            vec![
                (
                    0,
                    "tester".to_string(),
                    account("S-1-5-21-1-2-3-1004"),
                    "S-1-5-21-1-2-3-1004".to_string()
                ),
                (
                    1,
                    "second".to_string(),
                    account("S-1-5-21-1-2-3-1006"),
                    "S-1-5-21-1-2-3-1006".to_string()
                ),
                (
                    2,
                    "@appcontainer".to_string(),
                    IdentKind::AppContainer(OWN.into()),
                    "S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681".to_string()
                ),
                (
                    3,
                    "@restricted".to_string(),
                    IdentKind::Restricted(OWN.into()),
                    "S-1-5-5-0-7".to_string()
                ),
            ]
        );
        assert_eq!(
            notes,
            names(&[
                "Users: is not a user account",
                "group: is not a user account",
                "Everyone: is not a user account",
                "CodexSandboxOnline: is not a local account",
                "me: is the daemon's own account",
                "ghost: unknown account",
            ])
        );
        // Without the session's logon SID the restricted entry is skipped, and the rest keeps
        // consecutive indices.
        let (kept, notes) = resolve(
            &names(&["@restricted", "@appcontainer", "tester"]),
            fake,
            OWN,
            DOMAIN,
            None,
        );
        let got: Vec<(u8, &str)> = kept.iter().map(|k| (k.0, k.1.as_str())).collect();
        assert_eq!(got, vec![(0, "@appcontainer"), (1, "tester")]);
        assert_eq!(
            notes,
            names(&["@restricted: cannot read this session's logon SID"])
        );
    }

    #[cfg(windows)]
    #[test]
    fn the_local_lookup_and_the_session_are_read_from_the_system() {
        let (name, sid) = local_account_domain().expect("account domain");
        assert!(sid.starts_with("S-1-5-21-"), "{sid}");
        let own = crate::ipc::user_sid().unwrap();
        // Reading a variable never changes the environment.
        let user = std::env::var("USERNAME").unwrap_or_default();
        // Local = the account's SID is under the local account domain's SID. Then the lookup
        // must succeed, or the negative lookups below would be vacuous (always None).
        if own.starts_with(&format!("{sid}-")) {
            let found = lookup_account(&name, &user)
                .unwrap_or_else(|| panic!("local account {user} not found in {name}"));
            assert_eq!((found.0.as_str(), found.1), (own.as_str(), 1)); // 1 = SidTypeUser
        } else {
            println!("skipped: test account {own} is not under the local domain {sid}");
        }
        let missing = format!("NoSuchAccountFg{}", std::process::id());
        for n in ["Users", "SYSTEM", missing.as_str()] {
            assert_eq!(lookup_account(&name, n), None, "{n}");
        }
        let logon = logon_sid().expect("logon SID");
        assert!(logon.starts_with("S-1-5-5-"), "{logon}");
        assert_eq!(
            derive_capability("registryRead"),
            "S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681"
        );
        assert_eq!(derive_capability("registryRead"), REGISTRY_READ_CAPABILITY);
    }

    /// The capability SID Windows derives from `name` (test only).
    #[cfg(windows)]
    fn derive_capability(name: &str) -> String {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::{DeriveCapabilitySidsFromName, PSID};
        let wide: Vec<u16> = name.encode_utf16().chain([0]).collect();
        let (mut groups, mut ngroups): (*mut PSID, u32) = (std::ptr::null_mut(), 0);
        let (mut caps, mut ncaps): (*mut PSID, u32) = (std::ptr::null_mut(), 0);
        // SAFETY: a NUL-terminated name and valid out pointers.
        let ok = unsafe {
            DeriveCapabilitySidsFromName(
                wide.as_ptr(),
                &mut groups,
                &mut ngroups,
                &mut caps,
                &mut ncaps,
            )
        };
        assert_ne!(ok, 0, "{}", std::io::Error::last_os_error());
        assert_eq!(ncaps, 1);
        // SAFETY: `caps` holds `ncaps` SIDs; each SID and both arrays are freed once with
        // LocalFree, as the API asks.
        unsafe {
            let sid = crate::ipc::sid_string(*caps).unwrap();
            for i in 0..ngroups as usize {
                LocalFree(*groups.add(i));
            }
            for i in 0..ncaps as usize {
                LocalFree(*caps.add(i));
            }
            LocalFree(groups.cast());
            LocalFree(caps.cast());
            sid
        }
    }

    /// The real `ident_of_pid` for the test's own account: a child of the test gives its
    /// ident and start; pid 4 (System) gives nothing.
    #[cfg(windows)]
    #[test]
    fn the_guest_ident_of_pid_reads_a_child_and_refuses_the_system() {
        let own = crate::ipc::user_sid().unwrap();
        let f = os_ident_of_pid(IdentKind::Account(own.clone()));
        let mut child = std::process::Command::new("ping")
            .args(["-n", "30", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        let got = f(pid);
        let start = sync_gate_probe::start_time(pid);
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(got, Some((format!("account:{own}"), start.unwrap())));
        assert_eq!(f(4), None);
    }
}
