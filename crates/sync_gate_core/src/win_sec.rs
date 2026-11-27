//! Windows security helpers shared by the pipe checks (`ipc_name`) and the data folder checks
//! (`private_dir`): this process's token, the owner inside a descriptor, SIDs built by hand.
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
#[cfg(feature = "ipc")]
use windows_sys::Win32::Security::{EqualSid, GetSecurityDescriptorOwner, PSID};
use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_INFORMATION_CLASS, TOKEN_QUERY};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// The decision of the pipe check (`ipc_name`) from what its queries returned (None: the query
/// failed): trusted only if every query worked and the owner is our user or default owner.
///
/// # Safety
/// Every non-null SID given must point to a valid SID for the whole call.
#[cfg(feature = "ipc")]
pub(crate) unsafe fn owner_is_ours(
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
pub(crate) fn token_info<T>(class: TOKEN_INFORMATION_CLASS) -> Option<Vec<u64>> {
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
pub(crate) fn info_of<T>(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Option<Vec<u64>> {
    let mut len = 0u32;
    // SAFETY: size query: null buffer of length 0, `len` is a valid out pointer.
    unsafe { GetTokenInformation(token, class, std::ptr::null_mut(), 0, &mut len) };
    // u64 elements keep the buffer aligned for the TOKEN_* struct.
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buf` holds at least `len` writable bytes.
    let ok = unsafe { GetTokenInformation(token, class, buf.as_mut_ptr().cast(), len, &mut len) };
    (ok != 0 && len as usize >= size_of::<T>()).then_some(buf)
}

/// The owner inside `sd` (null if it has none, or on failure); it points into `sd`.
///
/// # Safety
/// `sd` must hold a valid self-relative security descriptor.
#[cfg(feature = "ipc")]
pub(crate) unsafe fn owner_sid(sd: &[u64]) -> PSID {
    let (mut owner, mut defaulted): (PSID, _) = (std::ptr::null_mut(), 0);
    // SAFETY: `sd` is a valid descriptor (caller) that the call only reads; the out pointers
    // are valid.
    let ok = unsafe {
        GetSecurityDescriptorOwner(sd.as_ptr().cast_mut().cast(), &mut owner, &mut defaulted)
    };
    if ok == 0 { std::ptr::null_mut() } else { owner }
}

/// A SID S-1-<authority>-<subs> built by hand, in a buffer aligned for it.
pub(crate) fn sid(authority: u8, subs: &[u32]) -> Vec<u64> {
    let mut b = vec![1, subs.len() as u8, 0, 0, 0, 0, 0, authority];
    subs.iter().for_each(|s| b.extend(s.to_le_bytes()));
    b.resize(b.len().div_ceil(8) * 8, 0);
    b.chunks(8)
        .map(|c| u64::from_ne_bytes(c.try_into().unwrap()))
        .collect()
}

#[cfg(all(test, feature = "ipc"))]
mod tests {
    use super::*;

    fn p(sid: &[u64]) -> Option<PSID> {
        Some(sid.as_ptr().cast_mut().cast())
    }

    /// Separate buffers with equal contents: the decision compares SIDs, not pointers.
    #[test]
    fn the_owner_decision_trusts_only_our_user_or_default_owner() {
        let (user, admins, system) = (
            sid(5, &[21, 1, 2, 3, 1001]),
            sid(5, &[32, 544]),
            sid(5, &[18]),
        );
        let (user2, admins2) = (user.clone(), admins.clone());
        // SAFETY: every SID is a valid hand-built SID alive for the call.
        unsafe {
            assert!(owner_is_ours(p(&user2), p(&user), p(&admins)));
            assert!(owner_is_ours(p(&admins2), p(&user), p(&admins)));
            assert!(!owner_is_ours(p(&system), p(&user), p(&admins)));
            assert!(!owner_is_ours(
                p(&sid(5, &[21, 1, 2, 3, 1002])),
                p(&user),
                p(&admins)
            ));
        }
    }

    /// Any failed query refuses, even when the other answers would trust the owner.
    #[test]
    fn the_owner_decision_refuses_any_failed_query() {
        let (user, admins) = (sid(5, &[21, 1, 2, 3, 1001]), sid(5, &[32, 544]));
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
}
