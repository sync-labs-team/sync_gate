//! The one place that takes OS file locks: the daemon's single-instance lock, which a CLI also
//! takes (exclusively, without blocking) to run a recovery pass, goes through [`try_lock`].
use std::fs::File;
use std::io;

/// File name of the daemon's single-instance lock inside the data dir.
pub const LOCK_FILE: &str = "sync_gated.lock";

/// A held lock, released on drop (or when the process dies).
pub struct FileLock {
    #[cfg(windows)]
    file: File,
    #[cfg(unix)]
    _file: nix::fcntl::Flock<File>,
}

/// Non-blocking whole-file lock (byte 0 on Windows): `Ok(None)` when someone else holds a
/// conflicting lock, `Err` for any other failure.
pub fn try_lock(file: File, exclusive: bool) -> io::Result<Option<FileLock>> {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::ERROR_LOCK_VIOLATION;
        use windows_sys::Win32::Storage::FileSystem::{
            LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx,
        };
        let mut overlapped = unsafe { std::mem::zeroed() };
        let flags = LOCKFILE_FAIL_IMMEDIATELY
            | if exclusive {
                LOCKFILE_EXCLUSIVE_LOCK
            } else {
                0
            };
        let ok = unsafe { LockFileEx(file.as_raw_handle(), flags, 0, 1, 0, &mut overlapped) };
        if ok != 0 {
            return Ok(Some(FileLock { file }));
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(ERROR_LOCK_VIOLATION as i32) {
            Ok(None)
        } else {
            Err(e)
        }
    }
    #[cfg(unix)]
    {
        use nix::fcntl::{Flock, FlockArg};
        let arg = if exclusive {
            FlockArg::LockExclusiveNonblock
        } else {
            FlockArg::LockSharedNonblock
        };
        match Flock::lock(file, arg) {
            Ok(_file) => Ok(Some(FileLock { _file })),
            Err((_, nix::errno::Errno::EWOULDBLOCK)) => Ok(None),
            Err((_, e)) => Err(io::Error::from(e)),
        }
    }
}

#[cfg(windows)]
impl Drop for FileLock {
    fn drop(&mut self) {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::UnlockFileEx;
        let mut overlapped = unsafe { std::mem::zeroed() };
        // Explicit, so a recovery pass's lock is gone at once (a closed handle unlocks lazily).
        unsafe { UnlockFileEx(self.file.as_raw_handle(), 0, 1, 0, &mut overlapped) };
    }
}
