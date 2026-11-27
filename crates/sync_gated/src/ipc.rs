//! Server side of the local sockets (control and MCP hub). One thread per connection, so a
//! blocking `Wait` never stalls others.

use interprocess::local_socket::{Listener, ListenerOptions, Stream, prelude::*};
#[cfg(windows)]
use interprocess::os::windows::security_descriptor::SecurityDescriptor;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use sync_gate_core::ipc_name::to_name;
use sync_gate_core::{Request, Response};
#[cfg(windows)]
use windows_sys::Win32::Security::{PSID, TOKEN_INFORMATION_CLASS, TOKEN_USER, TokenUser};

/// Longest request line accepted, in bytes.
const MAX_LINE: u64 = 1024 * 1024;
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
/// How often shutdown re-checks the accept thread and, if no attempt is in flight, connects again.
const WAKE_RETRY: Duration = Duration::from_millis(20);
/// After this, shutdown gives up on the accept thread and returns without joining it.
const WAKE_DEADLINE: Duration = Duration::from_secs(5);

/// Unix: only our own user's connections reach a handler. Windows: the pipe's DACL decides.
#[cfg(unix)]
const PEER_CHECK: fn(&Stream) -> bool = sync_gate_core::ipc_name::peer_is_us;
#[cfg(windows)]
const PEER_CHECK: fn(&Stream) -> bool = |_| true;

pub struct ServerHandle {
    name: String,
    stop: Arc<AtomicBool>,
    accept: JoinHandle<()>,
}

impl ServerHandle {
    /// Stops accepting and waits for the accept thread (at most `WAKE_DEADLINE`); connection
    /// threads finish on their own.
    pub fn shutdown(self) {
        self.stop_within(WAKE_DEADLINE);
    }

    /// Wakes the blocking accept with connections held open until the accept thread is gone: a
    /// client that closes before the server's `ConnectNamedPipe` is discarded as dead
    /// (ERROR_NO_DATA) on Windows and accept blocks again. Returns true only if the accept thread
    /// finished and was joined; false if it gave up.
    pub(crate) fn stop_within(self, deadline: Duration) -> bool {
        self.stop.store(true, Ordering::SeqCst);
        let start = Instant::now();
        let mut held = Vec::new();
        let mut attempt: Option<mpsc::Receiver<io::Result<Stream>>> = None;
        loop {
            if let Some(rx) = &attempt {
                match rx.try_recv() {
                    // Still connecting: Stream::connect waits unbounded on a busy pipe.
                    Err(TryRecvError::Empty) => {}
                    r => {
                        held.extend(r.ok().and_then(Result::ok));
                        attempt = None;
                    }
                }
            }
            if self.accept.is_finished() {
                break;
            }
            if start.elapsed() >= deadline {
                eprintln!("sync_gated: accept thread did not stop; leaving it");
                return false;
            }
            if attempt.is_none() {
                attempt = Some(connect_in_background(&self.name));
            }
            thread::sleep(WAKE_RETRY);
        }
        let _ = self.accept.join();
        // Only now may the wake streams (and an attempt still in flight) close.
        drop((held, attempt));
        true
    }
}

/// One connect attempt on its own thread, so a connect that never returns cannot block shutdown.
fn connect_in_background(name: &str) -> mpsc::Receiver<io::Result<Stream>> {
    let (tx, rx) = mpsc::channel();
    let name = name.to_owned();
    // A failed spawn drops `tx`, so the receiver reads Disconnected and the next pass retries.
    let _ = thread::Builder::new().spawn(move || {
        let _ = tx.send(to_name(&name).and_then(Stream::connect));
    });
    rx
}

/// Reads one request line (at most `MAX_LINE` bytes). `Ok(None)` means the peer closed without sending.
fn read_request<R: BufRead>(r: R) -> Result<Option<Request>, String> {
    read_line(r)?.map(|buf| parse_request(&buf)).transpose()
}

/// The raw bytes of one request line, not yet interpreted.
fn read_line<R: BufRead>(r: R) -> Result<Option<Vec<u8>>, String> {
    let mut buf = Vec::new();
    r.take(MAX_LINE)
        .read_until(b'\n', &mut buf)
        .map_err(|e| e.to_string())?;
    if buf.is_empty() {
        return Ok(None);
    }
    if buf.last() != Some(&b'\n') && buf.len() as u64 >= MAX_LINE {
        return Err(format!("request exceeds {MAX_LINE} bytes"));
    }
    Ok(Some(buf))
}

fn parse_request(buf: &[u8]) -> Result<Request, String> {
    serde_json::from_slice(buf).map_err(|e| format!("invalid request: {e}"))
}

fn handle(conn: Stream, handler: &(dyn Fn(Request) -> Response + Send + Sync)) {
    let mut conn = BufReader::new(conn);
    let resp = match read_request(&mut conn) {
        Ok(Some(req)) => handler(req),
        Ok(None) => return,
        Err(message) => Response::Error { message },
    };
    reply(&mut conn, &resp);
}

fn reply<W: Write + Read>(conn: &mut BufReader<W>, resp: &Response) {
    let Ok(mut line) = serde_json::to_vec(resp) else {
        return;
    };
    line.push(b'\n');
    let out = conn.get_mut();
    let _ = out.write_all(&line).and_then(|()| out.flush());
}

/// Unix only: serialises daemon starts with an exclusive lock on `<path>.lock`, held by the
/// returned guard for the server's lifetime, then removes a leftover socket file nobody listens on.
#[cfg(unix)]
fn lock_and_clear_stale(path: &str) -> io::Result<nix::fcntl::Flock<std::fs::File>> {
    use nix::errno::Errno;
    use nix::fcntl::{Flock, FlockArg};
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(format!("{path}.lock"))?;
    let lock = Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|(_, e)| {
        if e == Errno::EWOULDBLOCK {
            io::Error::from(io::ErrorKind::AddrInUse)
        } else {
            io::Error::from(e)
        }
    })?;
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            if Stream::connect(to_name(path)?).is_ok() {
                return Err(io::ErrorKind::AddrInUse.into());
            }
            std::fs::remove_file(path)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    Ok(lock)
}

/// Unix: mode 0600 is applied by `fchmod` before bind; `set_permissions` is the fallback where unsupported.
#[cfg(unix)]
fn bind(name: &str) -> io::Result<Listener> {
    use interprocess::os::unix::local_socket::ListenerOptionsExt;
    use std::os::unix::fs::PermissionsExt;
    let make = |with_mode: bool| -> io::Result<Listener> {
        let opts = ListenerOptions::new().name(to_name(name)?);
        if with_mode {
            opts.mode(0o600).create_sync()
        } else {
            opts.create_sync()
        }
    };
    match make(true) {
        Err(e) if e.kind() == io::ErrorKind::Unsupported => {
            let l = make(false)?;
            std::fs::set_permissions(name, std::fs::Permissions::from_mode(0o600))?;
            Ok(l)
        }
        r => r,
    }
}

/// Windows: the default pipe DACL lets other local users connect (and pin connection threads or
/// exhaust pipe instances), so every pipe gets an explicit descriptor (`serve`: the current
/// user's SID only). The first instance is created with FILE_FLAG_FIRST_PIPE_INSTANCE, so a name
/// someone already holds is refused (access denied); the error keeps that cause and its kind.
#[cfg(windows)]
fn bind(name: &str, sd: SecurityDescriptor) -> io::Result<Listener> {
    use interprocess::os::windows::local_socket::ListenerOptionsExt;
    ListenerOptions::new()
        .name(to_name(name)?)
        .security_descriptor(sd)
        .create_sync()
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "cannot create pipe {name}: {e} (in use by another process: another \
                     sync_gated, or another user's)"
                ),
            )
        })
}

#[cfg(windows)]
fn owner_only_descriptor() -> io::Result<SecurityDescriptor> {
    descriptor_for(&user_sid()?)
}

/// D:P = protected DACL with one allow-ACE, GENERIC_ALL, for `sid`; nothing for Everyone or Anonymous.
#[cfg(windows)]
fn descriptor_for(sid: &str) -> io::Result<SecurityDescriptor> {
    sddl_descriptor(&format!("D:P(A;;GA;;;{sid})"))
}

/// A guest pipe owned by `owner` (named, so an elevated token's default owner, the Administrators
/// group, does not become it: the client accepts only the user, #12). GENERIC_ALL for `full`, and
/// for `ace_sid` exactly FILE_READ_DATA |
/// FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE (0x120083): never
/// FILE_CREATE_PIPE_INSTANCE (0x4), so a guest can connect but never serve this name.
#[cfg(windows)]
fn guest_descriptor(owner: &str, full: &str, ace_sid: &str) -> io::Result<SecurityDescriptor> {
    sddl_descriptor(&format!(
        "O:{owner}D:P(A;;GA;;;{full})(A;;0x120083;;;{ace_sid})"
    ))
}

#[cfg(windows)]
fn sddl_descriptor(sddl: &str) -> io::Result<SecurityDescriptor> {
    let sddl = widestring::U16CString::from_str(sddl)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    SecurityDescriptor::deserialize(&sddl)
}

/// The current user's SID as a string (`S-1-5-21-…`).
#[cfg(windows)]
pub(crate) fn user_sid() -> io::Result<String> {
    let buf = token_info::<TOKEN_USER>(TokenUser)?;
    // SAFETY: `buf` holds a whole TOKEN_USER (size checked); its SID points inside `buf`.
    unsafe { sid_string((*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid) }
}

/// This process's token information of `class`, which must be a `T` (TOKEN_USER, TOKEN_OWNER),
/// in a buffer aligned for it; the SID it holds points inside the buffer.
#[cfg(windows)]
pub(crate) fn token_info<T>(class: TOKEN_INFORMATION_CLASS) -> io::Result<Vec<u64>> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess is a pseudo handle that needs no closing; `token` is a valid out
    // pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut len = 0u32;
    // SAFETY: size query: null buffer of length 0, `len` is a valid out pointer.
    unsafe { GetTokenInformation(token, class, std::ptr::null_mut(), 0, &mut len) };
    // u64 elements keep the buffer aligned for the TOKEN_* struct.
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buf` holds at least `len` writable bytes.
    let ok = unsafe { GetTokenInformation(token, class, buf.as_mut_ptr().cast(), len, &mut len) };
    let err = io::Error::last_os_error();
    // SAFETY: closes the token opened above, exactly once.
    unsafe { CloseHandle(token) };
    match ok {
        0 => Err(err),
        _ if (len as usize) < size_of::<T>() => Err(io::Error::other("short token information")),
        _ => Ok(buf),
    }
}

/// The string form (`S-1-5-…`) of a SID.
///
/// # Safety
/// `sid` must point to a valid SID for the whole call.
#[cfg(windows)]
pub(crate) unsafe fn sid_string(sid: PSID) -> io::Result<String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    let mut wide: *mut u16 = std::ptr::null_mut();
    // SAFETY: `sid` is valid (caller); `wide` is a valid out pointer.
    if unsafe { ConvertSidToStringSidW(sid, &mut wide) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: on success `wide` is a NUL-terminated string the system allocated; it is read up
    // to the NUL and then freed with LocalFree, exactly once.
    unsafe {
        let n = (0..).take_while(|&i| *wide.add(i) != 0).count();
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(wide, n));
        LocalFree(wide.cast());
        Ok(s)
    }
}

/// Binds `name` and serves requests on a background thread; returns once the socket is listening.
pub fn serve(
    name: &str,
    handler: impl Fn(Request) -> Response + Send + Sync + 'static,
) -> io::Result<ServerHandle> {
    listen(name, None, PEER_CHECK, move |conn| handle(conn, &handler))
}

/// Forcibly ends one connection from any thread: blocked reads and writes on it return, and
/// later ones fail. Idempotent; a no-op once the connection is gone.
pub type Closer = Arc<dyn Fn() + Send + Sync>;

/// Stack of the hub's byte-moving threads (dozens of them must stay cheap).
pub const STREAM_THREAD_STACK: usize = 128 * 1024;
/// Stack of the threads that may parse or drop JSON values (up to `hub::MAX_JSON_DEPTH` levels
/// deep): a debug build needs roughly 2-3 KiB per nesting level to build, write and drop a
/// `Value`, and a stack overflow aborts the daemon. Only touched pages cost memory (the address
/// space is reserved per hub thread: connection, reader and writer, ~1.5 MiB per client).
pub const PARSE_THREAD_STACK: usize = 512 * 1024;

/// Same owner-only bind as [`serve`], but hands each connection over as a byte stream (no
/// line limit here) with a [`Closer`]. `on_conn` runs on the connection's own thread.
pub fn serve_stream(
    name: &str,
    on_conn: impl Fn(Box<dyn Read + Send>, Box<dyn Write + Send>, Closer) + Send + Sync + 'static,
) -> io::Result<ServerHandle> {
    serve_stream_with(name, PEER_CHECK, on_conn)
}

/// [`serve_stream`] with the accept-loop check injectable (a test makes it refuse).
fn serve_stream_with(
    name: &str,
    allowed: fn(&Stream) -> bool,
    on_conn: impl Fn(Box<dyn Read + Send>, Box<dyn Write + Send>, Closer) + Send + Sync + 'static,
) -> io::Result<ServerHandle> {
    listen(name, Some(PARSE_THREAD_STACK), allowed, move |conn| {
        let conn = Arc::new(conn);
        let close = closer(&conn);
        on_conn(
            Box::new(Shared(conn.clone())),
            Box::new(Shared(conn)),
            close,
        )
    })
}

/// One stream shared by its reader and writer halves (`&Stream` is `Read + Write`).
struct Shared(Arc<Stream>);

impl Read for Shared {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&*self.0).read(buf)
    }
}

impl Write for Shared {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&*self.0).write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        (&*self.0).flush()
    }
}

/// Holds only a weak reference, so a stored closer never keeps the connection open.
fn closer(conn: &Arc<Stream>) -> Closer {
    let weak = Arc::downgrade(conn);
    Arc::new(move || {
        if let Some(s) = weak.upgrade() {
            force_close(&s);
        }
    })
}

/// Unix: `shutdown` wakes a blocked read (EOF) and write (EPIPE) on any thread.
#[cfg(unix)]
fn force_close(s: &Stream) {
    let Stream::UdSocket(u) = s;
    let _ = u.inner().shutdown(std::net::Shutdown::Both);
}

/// Windows: disconnecting the server end of the pipe instance fails its pending and later I/O.
#[cfg(windows)]
fn force_close(s: &Stream) {
    use std::os::windows::io::{AsHandle, AsRawHandle};
    let Stream::NamedPipe(p) = s;
    // SAFETY: the handle is alive (we hold the stream) and is the server end of the instance.
    unsafe {
        windows_sys::Win32::System::Pipes::DisconnectNamedPipe(
            p.inner().as_handle().as_raw_handle(),
        );
    }
}

/// Binds `name` (owner only) and runs `on_conn` for each connection on its own thread (`stack`
/// bytes of stack, or the default); a connection whose thread cannot be created is dropped, and
/// so is one `allowed` refuses (before any byte is read).
fn listen(
    name: &str,
    stack: Option<usize>,
    allowed: fn(&Stream) -> bool,
    on_conn: impl Fn(Stream) + Send + Sync + 'static,
) -> io::Result<ServerHandle> {
    #[cfg(unix)]
    let (keep, listener) = {
        let lock = lock_and_clear_stale(name)?;
        (lock, bind(name)?)
    };
    #[cfg(windows)]
    let (keep, listener) = ((), bind(name, owner_only_descriptor()?)?);
    Ok(accept_loop(
        name, listener, keep, stack, allowed, None, on_conn,
    ))
}

/// Reserves a connection slot in the accept thread, before any worker exists: `None` = full, the
/// connection is dropped unread. The returned guard lives as long as the worker (or until the
/// spawn fails) and gives the slot back.
type Admit = Arc<dyn Fn() -> Option<Box<dyn Send>> + Send + Sync>;

/// The accept loop of a bound listener; `keep` lives as long as the loop.
fn accept_loop(
    name: &str,
    listener: Listener,
    keep: impl Send + 'static,
    stack: Option<usize>,
    allowed: fn(&Stream) -> bool,
    admit: Option<Admit>,
    on_conn: impl Fn(Stream) + Send + Sync + 'static,
) -> ServerHandle {
    let on_conn: Arc<dyn Fn(Stream) + Send + Sync> = Arc::new(on_conn);
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let accept = thread::spawn(move || {
        // Held for the server's lifetime so a second daemon gets AddrInUse (Unix).
        let _keep = keep;
        let spawn_failed = std::sync::Mutex::new(None);
        // Dropping the listener on exit also unlinks the socket file on Unix.
        loop {
            match listener.accept() {
                Ok(_) if flag.load(Ordering::SeqCst) => break,
                Ok(conn) => {
                    // Every accepted connection, on both sockets (control and hub), is checked.
                    if !allowed(&conn) {
                        eprintln!("sync_gated: refused a connection from another user");
                        continue;
                    }
                    let permit = match &admit {
                        None => None,
                        Some(admit) => match admit() {
                            Some(p) => Some(p),
                            None => continue,
                        },
                    };
                    let h = on_conn.clone();
                    let b = stack.map_or_else(thread::Builder::new, |s| {
                        thread::Builder::new().stack_size(s)
                    });
                    // On a failed spawn the closure, and with it the permit, is dropped.
                    if let Err(e) = b.spawn(move || {
                        let _permit = permit;
                        h(conn)
                    }) {
                        let line = format!("sync_gated: cannot start a connection thread: {e}");
                        if admit.is_some() {
                            once_a_minute(&spawn_failed, &line);
                        } else {
                            eprintln!("{line}");
                        }
                    }
                }
                Err(_) if flag.load(Ordering::SeqCst) => break,
                Err(e) => {
                    eprintln!("sync_gated: accept error: {e}");
                    thread::sleep(ACCEPT_BACKOFF);
                }
            }
        }
    });
    ServerHandle {
        name: name.to_owned(),
        stop,
        accept,
    }
}

/// Says `line` at most once a minute per `last`.
fn once_a_minute(last: &std::sync::Mutex<Option<Instant>>, line: &str) {
    let mut last = last.lock().unwrap_or_else(|e| e.into_inner());
    if last.is_none_or(|t| t.elapsed() >= Duration::from_secs(60)) {
        *last = Some(Instant::now());
        eprintln!("{line}");
    }
}

/// The token of whoever wrote the last message read on `conn` (F47): the connection thread
/// impersonates the client, opens its own thread token as itself, and reverts at once. Never a
/// pid: GetNamedPipeClientProcessId names whoever opened the client end, which may have handed
/// it on (review 4, defect 1).
#[cfg(windows)]
fn message_token(conn: &Stream) -> Option<sync_gate_probe::TokenView> {
    use std::os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Security::{RevertToSelf, TOKEN_QUERY};
    use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
    use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};
    let Stream::NamedPipe(p) = conn;
    let pipe = p.inner().as_handle().as_raw_handle();
    // SAFETY: the server end of a connected instance, alive while `conn` is.
    if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
        return None;
    }
    let mut token = std::ptr::null_mut();
    // SAFETY: a pseudo handle for this thread, which now impersonates; OpenAsSelf = TRUE checks
    // the access as the daemon; `token` is a valid out pointer.
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } != 0;
    // SAFETY: no arguments. The thread must never run on as the client.
    if unsafe { RevertToSelf() } == 0 {
        std::process::abort();
    }
    if !opened {
        return None;
    }
    // SAFETY: a fresh handle nobody else owns, closed once on drop.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    sync_gate_probe::token_view(token.as_raw_handle())
}

/// A guest's pipe `name`, open to `ace_sid` with 0x120083 only (`guest_descriptor`), with the
/// accept loop of `serve`. Per connection, on its own thread: the cap of
/// `GUEST_MAX_CONNECTIONS` first (the one over is dropped unread); then the request line is
/// read and, BEFORE it is interpreted, the identity of that very message (F47): a client whose
/// token `client_ident` does not accept gets no reply. `label` names the guest in the log.
#[cfg(windows)]
pub fn serve_guest(
    name: &str,
    label: &str,
    ace_sid: &str,
    client_ident: impl Fn(&sync_gate_probe::TokenView) -> Option<String> + Send + Sync + 'static,
    handler: impl Fn(&str, Request) -> Response + Send + Sync + 'static,
) -> io::Result<ServerHandle> {
    serve_guest_with(
        GUEST_IO_DEADLINE,
        spawn_watchdog,
        name,
        label,
        ace_sid,
        client_ident,
        handler,
    )
}

/// Longest a guest may take to send its request line, and longest its reply may take to be
/// read: one request per connection, so a slower client is hung or hostile, and keeping its slot
/// would let 16 of them lock every other guest caller out.
#[cfg(windows)]
const GUEST_IO_DEADLINE: Duration = Duration::from_secs(10);

/// Closes the connection when `deadline` passes before the guard is dropped. `force_close`
/// (`DisconnectNamedPipe` on the server end) fails the pending and later I/O of every thread on
/// the instance (proven by the blocked read/write/flush tests), so a blocked `read_line` or
/// `flush` returns and the connection thread frees its slot.
#[cfg(windows)]
struct Watchdog(#[allow(dead_code)] mpsc::Sender<()>); // dropping it ends the watch

/// How a watchdog's thread is started: a seam, so a test can make the start fail.
#[cfg(windows)]
type SpawnWatchdog = fn(Box<dyn FnOnce() + Send>) -> io::Result<()>;

#[cfg(windows)]
fn spawn_watchdog(job: Box<dyn FnOnce() + Send>) -> io::Result<()> {
    thread::Builder::new()
        .stack_size(STREAM_THREAD_STACK)
        .spawn(job)
        .map(drop)
}

#[cfg(windows)]
impl Watchdog {
    /// Fails when the thread cannot start: the caller must then not enter blocking I/O.
    fn start(spawn: SpawnWatchdog, close: &Closer, deadline: Duration) -> io::Result<Self> {
        let (tx, rx) = mpsc::channel();
        let close = close.clone();
        spawn(Box::new(move || {
            if let Err(mpsc::RecvTimeoutError::Timeout) = rx.recv_timeout(deadline) {
                close();
            }
        }))?;
        Ok(Self(tx))
    }
}

/// Test seam: guest workers that started, counted per listener (pipe name) so parallel guest tests
/// cannot change each other's count (a worker only starts for an admitted connection).
#[cfg(all(test, windows))]
static WORKERS_ENTERED: std::sync::Mutex<Vec<(String, usize)>> = std::sync::Mutex::new(Vec::new());

#[cfg(all(test, windows))]
fn workers_entered(name: &str, bump: bool) -> usize {
    let mut all = WORKERS_ENTERED.lock().unwrap();
    let at = match all.iter().position(|(n, _)| n == name) {
        Some(at) => at,
        None => {
            all.push((name.to_owned(), 0));
            all.len() - 1
        }
    };
    all[at].1 += bump as usize;
    all[at].1
}

/// [`serve_guest`] with the I/O deadline injectable (a test shortens it).
#[cfg(windows)]
fn serve_guest_with(
    deadline: Duration,
    spawn: SpawnWatchdog,
    name: &str,
    label: &str,
    ace_sid: &str,
    client_ident: impl Fn(&sync_gate_probe::TokenView) -> Option<String> + Send + Sync + 'static,
    handler: impl Fn(&str, Request) -> Response + Send + Sync + 'static,
) -> io::Result<ServerHandle> {
    use crate::guest::GUEST_MAX_CONNECTIONS;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;
    /// One live connection, given back on every exit path.
    struct Slot(Arc<AtomicUsize>);
    impl Drop for Slot {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    let user = user_sid()?;
    let listener = bind(name, guest_descriptor(&user, &user, ace_sid)?)?;
    let live = Arc::new(AtomicUsize::new(0));
    #[cfg(test)]
    let worker_name = name.to_owned();
    let (full, refused) = (Mutex::new(None), Mutex::new(None));
    let refused_line = format!("sync_gated: guest {label}: refused a client of another kind");
    let no_deadline = Mutex::new(None);
    let no_deadline_line =
        format!("sync_gated: guest {label}: could not start a deadline; dropped a client");
    let admit: Admit = Arc::new(move || {
        let slot = Slot(live.clone());
        if slot.0.fetch_add(1, Ordering::SeqCst) >= GUEST_MAX_CONNECTIONS {
            once_a_minute(&full, "sync_gated: guest connection limit reached");
            return None;
        }
        Some(Box::new(slot))
    });
    Ok(accept_loop(
        name,
        listener,
        (),
        None,
        PEER_CHECK,
        Some(admit),
        move |conn| {
            #[cfg(test)]
            workers_entered(&worker_name, true);
            let conn = Arc::new(conn);
            let close = closer(&conn);
            let mut reader = BufReader::new(Shared(conn.clone()));
            let line = {
                // Fail closed: with no deadline a silent client could hold its slot forever.
                let Ok(_deadline) = Watchdog::start(spawn, &close, deadline) else {
                    once_a_minute(&no_deadline, &no_deadline_line);
                    return;
                };
                read_line(&mut reader)
            };
            let Ok(Some(line)) = line else {
                return;
            };
            let Some(ident) = message_token(&conn).and_then(|v| client_ident(&v)) else {
                once_a_minute(&refused, &refused_line);
                return;
            };
            // The handler (a Wait included) keeps its own timeout; no deadline runs over it.
            let resp = match parse_request(&line) {
                Ok(req) => handler(&ident, req),
                Err(message) => Response::Error { message },
            };
            let Ok(_deadline) = Watchdog::start(spawn, &close, deadline) else {
                once_a_minute(&no_deadline, &no_deadline_line);
                return;
            };
            reply(&mut reader, &resp);
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// The accept loop's check, on both systems: a refused connection is dropped unread and never
    /// reaches the handler; the next one does.
    #[test]
    fn a_refused_peer_never_reaches_the_hub_handler() {
        use std::sync::atomic::AtomicUsize;
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        fn first_refused(_: &Stream) -> bool {
            CALLS.fetch_add(1, Ordering::SeqCst) > 0
        }
        let tag = format!("sync_gate-refuse-{}", std::process::id());
        let name = if cfg!(windows) {
            tag
        } else {
            std::env::temp_dir()
                .join(tag)
                .to_string_lossy()
                .into_owned()
        };
        let (tx, rx) = mpsc::channel();
        let tx = std::sync::Mutex::new(tx);
        // The handler reads the connection's first byte before it lets go of the stream, so the
        // client's write cannot race a drop, and reports what it read: served == one byte seen.
        let server = serve_stream_with(&name, first_refused, move |mut r, _w, _close| {
            let mut b = [0u8; 1];
            if r.read_exact(&mut b).is_ok() {
                let _ = tx.lock().unwrap().send(b[0]);
            }
        })
        .unwrap();
        let wait = Duration::from_secs(5);
        let mut first = Stream::connect(to_name(&name).unwrap()).unwrap();
        let (done, read) = mpsc::channel();
        thread::spawn(move || {
            let _ = done.send(first.read(&mut [0u8; 1]));
        });
        // The server dropped it: end of file or an error. A timeout means it was kept open.
        assert!(
            matches!(read.recv_timeout(wait), Ok(Ok(0) | Err(_))),
            "refused connection was not closed by the server"
        );
        let mut second = Stream::connect(to_name(&name).unwrap()).unwrap();
        second.write_all(b"x").unwrap();
        // The handler ran for the second connection (it read its byte), so the first is settled.
        assert_eq!(
            rx.recv_timeout(wait),
            Ok(b'x'),
            "accepted connection was not handled"
        );
        assert!(rx.try_recv().is_err(), "handler ran more than once");
        assert_eq!(CALLS.load(Ordering::SeqCst), 2);
        server.shutdown();
    }

    #[cfg(unix)]
    #[test]
    fn same_user_peer_is_served() {
        let name = std::env::temp_dir()
            .join(format!("sync_gate-peer-{}", std::process::id()))
            .to_string_lossy()
            .into_owned();
        let server = serve(&name, |_| Response::Ack).unwrap();
        let mut conn = Stream::connect(to_name(&name).unwrap()).unwrap();
        conn.write_all(b"\"Status\"\n").unwrap();
        let mut reply = String::new();
        BufReader::new(conn).read_line(&mut reply).unwrap();
        server.shutdown();
        assert_eq!(
            serde_json::from_str::<Response>(&reply).unwrap(),
            Response::Ack
        );
    }

    #[test]
    fn oversize_line_is_rejected_not_buffered() {
        let big = vec![b'a'; MAX_LINE as usize + 10];
        assert!(
            read_request(Cursor::new(big))
                .unwrap_err()
                .contains("exceeds")
        );
    }

    #[test]
    fn garbage_is_an_error_and_empty_is_none() {
        assert!(read_request(Cursor::new(b"nope\n".to_vec())).is_err());
        assert_eq!(read_request(Cursor::new(Vec::new())).unwrap(), None);
        assert_eq!(
            read_request(Cursor::new(b"\"Status\"\n".to_vec())).unwrap(),
            Some(Request::Status)
        );
    }

    #[test]
    fn shutdown_gives_up_on_a_stuck_accept_thread() {
        // Nothing listens on this name, and the accept thread never ends.
        let tag = format!("sync_gate-test-{}-nobody", std::process::id());
        let name = if cfg!(windows) {
            tag
        } else {
            std::env::temp_dir()
                .join(tag)
                .to_string_lossy()
                .into_owned()
        };
        let handle = ServerHandle {
            name,
            stop: Arc::new(AtomicBool::new(false)),
            accept: thread::spawn(|| {
                loop {
                    thread::park();
                }
            }),
        };
        let t0 = Instant::now();
        assert!(!handle.stop_within(Duration::from_millis(100)));
        assert!(t0.elapsed() < Duration::from_secs(2), "{:?}", t0.elapsed());
    }

    /// The closer must wake a reader blocked on a real connection, and the peer must see the end.
    #[test]
    fn stream_closer_unblocks_a_blocked_read_and_the_peer_sees_the_end() {
        let tag = format!("sync_gate-test-{}-stream-close", std::process::id());
        let name = if cfg!(windows) {
            tag
        } else {
            std::env::temp_dir()
                .join(tag)
                .to_string_lossy()
                .into_owned()
        };
        let (close_tx, close_rx) = mpsc::channel::<Closer>();
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let done_tx = std::sync::Mutex::new(done_tx);
        let server = serve_stream(&name, move |mut r, mut w, close| {
            w.write_all(b"hi\n").unwrap();
            let _ = close_tx.send(close);
            let _ = r.read(&mut [0u8; 16]);
            let _ = done_tx.lock().unwrap().send(());
        })
        .unwrap();
        let mut client = BufReader::new(Stream::connect(to_name(&name).unwrap()).unwrap());
        let mut line = String::new();
        client.read_line(&mut line).unwrap();
        assert_eq!(line, "hi\n");
        let close = close_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        close();
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the closer did not wake the blocked read");
        let (end_tx, end_rx) = mpsc::channel();
        thread::spawn(move || {
            let mut rest = String::new();
            let _ = end_tx.send(client.read_line(&mut rest).map_or(true, |n| n == 0));
        });
        assert!(
            end_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            "client did not see the connection end"
        );
        assert!(server.stop_within(Duration::from_secs(5)));
    }

    /// A peer that connects and never reads: a writer on the server side blocks once the OS
    /// buffers are full. The closer must end it (the thread and the pipe instance must not leak).
    /// `flush` also covers `FlushFileBuffers` on a named pipe, which waits for the peer to read.
    fn blocked_writer_ends_on_close(tag: &str, flush: bool) {
        use std::sync::atomic::AtomicUsize;
        const CHUNK: usize = 64 * 1024;
        const GIVE_UP: usize = 256 * 1024 * 1024;
        let name = if cfg!(windows) {
            format!("sync_gate-test-{}-{tag}", std::process::id())
        } else {
            std::env::temp_dir()
                .join(format!("sync_gate-test-{}-{tag}", std::process::id()))
                .to_string_lossy()
                .into_owned()
        };
        let (close_tx, close_rx) = mpsc::channel::<(Closer, Arc<AtomicUsize>)>();
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let (close_tx, done_tx) = (
            std::sync::Mutex::new(close_tx),
            std::sync::Mutex::new(done_tx),
        );
        let server = serve_stream(&name, move |_keep_reader_open, mut w, close| {
            let written = Arc::new(AtomicUsize::new(0));
            let _ = close_tx.lock().unwrap().send((close, written.clone()));
            let chunk = vec![b'x'; CHUNK];
            while written.load(Ordering::SeqCst) < GIVE_UP {
                if w.write_all(&chunk).is_err() {
                    break;
                }
                written.fetch_add(CHUNK, Ordering::SeqCst);
                if flush && w.flush().is_err() {
                    break;
                }
            }
            let _ = done_tx.lock().unwrap().send(());
        })
        .unwrap();
        // Connects, never reads.
        let _peer = Stream::connect(to_name(&name).unwrap()).unwrap();
        let (close, written) = close_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        // Blocked = no progress for 300 ms (the first chunk may already be too big for the pipe).
        let (mut last, mut still) = (usize::MAX, 0);
        while still < 6 {
            assert!(
                done_rx.try_recv().is_err(),
                "the writer was never blocked (wrote {} bytes)",
                written.load(Ordering::SeqCst)
            );
            thread::sleep(Duration::from_millis(50));
            let now = written.load(Ordering::SeqCst);
            still = if now == last { still + 1 } else { 0 };
            last = now;
        }
        close();
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the closer did not end the blocked writer");
        assert!(server.stop_within(Duration::from_secs(5)));
    }

    #[test]
    fn closer_ends_a_writer_blocked_on_a_peer_that_never_reads() {
        blocked_writer_ends_on_close("blocked-write", false);
    }

    #[test]
    fn closer_ends_a_writer_blocked_in_flush_on_a_peer_that_never_reads() {
        blocked_writer_ends_on_close("blocked-flush", true);
    }

    #[cfg(windows)]
    #[test]
    fn owner_only_descriptor_builds() {
        owner_only_descriptor().unwrap();
    }

    #[cfg(windows)]
    fn test_pipe(case: &str) -> String {
        format!("sync_gate-test-{}-{case}", std::process::id())
    }

    /// A first pipe instance on `name` with `sd` (None: the default descriptor).
    #[cfg(windows)]
    fn raw_listener(name: &str, sd: Option<SecurityDescriptor>) -> io::Result<Listener> {
        use interprocess::os::windows::local_socket::ListenerOptionsExt;
        let opts = ListenerOptions::new().name(to_name(name)?);
        match sd {
            Some(sd) => opts.security_descriptor(sd),
            None => opts,
        }
        .create_sync()
    }

    #[cfg(windows)]
    fn sddl(s: &str) -> SecurityDescriptor {
        SecurityDescriptor::deserialize(&widestring::U16CString::from_str(s).unwrap()).unwrap()
    }

    /// A raw connect (no owner check), bounded: a busy pipe would make it wait forever.
    #[cfg(windows)]
    fn raw_connect(name: &str) -> io::Result<Stream> {
        connect_in_background(name)
            .recv_timeout(Duration::from_secs(5))
            .expect("the connect did not return in 5 s")
    }

    /// C2: FILE_FLAG_FIRST_PIPE_INSTANCE makes a taken name fail, and the error says why.
    #[cfg(windows)]
    #[test]
    fn a_taken_pipe_name_fails_the_daemon() {
        serve(&test_pipe("free"), |_| Response::Ack)
            .unwrap()
            .shutdown();
        serve_stream(&test_pipe("free-stream"), |_, _, _| {})
            .unwrap()
            .shutdown();
        let name = test_pipe("taken");
        let _squatter = raw_listener(&name, None).unwrap();
        let refused = |r: io::Result<ServerHandle>| {
            let e = r.err().expect("serve on a taken name succeeded");
            let text = e.to_string();
            assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{text}");
            assert!(text.contains("os error 5"), "{text}");
            assert!(text.contains("in use by another process"), "{text}");
        };
        refused(serve(&name, |_| Response::Ack));
        refused(serve_stream(&name, |_, _, _| {}));
    }

    /// The owner of the pipe as its client end reads it, as a string SID.
    #[cfg(windows)]
    fn owner_seen_by_client(s: &Stream) -> String {
        use std::os::windows::io::{AsHandle, AsRawHandle};
        use windows_sys::Win32::Security::{
            GetKernelObjectSecurity, GetSecurityDescriptorOwner, OWNER_SECURITY_INFORMATION,
        };
        let Stream::NamedPipe(p) = s;
        let h = p.inner().as_handle().as_raw_handle();
        let mut len = 0u32;
        // SAFETY: size query: null buffer of length 0, `len` is a valid out pointer.
        unsafe {
            GetKernelObjectSecurity(
                h,
                OWNER_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                0,
                &mut len,
            )
        };
        let mut sd = vec![0u64; (len as usize).div_ceil(8)];
        // SAFETY: `sd` holds at least `len` writable bytes.
        let ok = unsafe {
            GetKernelObjectSecurity(
                h,
                OWNER_SECURITY_INFORMATION,
                sd.as_mut_ptr().cast(),
                len,
                &mut len,
            )
        };
        assert_ne!(ok, 0, "{}", io::Error::last_os_error());
        let (mut owner, mut defaulted): (PSID, _) = (std::ptr::null_mut(), 0);
        // SAFETY: `sd` holds the descriptor just read; the out pointers are valid.
        let ok = unsafe {
            GetSecurityDescriptorOwner(sd.as_mut_ptr().cast(), &mut owner, &mut defaulted)
        };
        assert!(ok != 0 && !owner.is_null());
        // SAFETY: `owner` points into `sd`, alive here.
        unsafe { sid_string(owner) }.unwrap()
    }

    /// N1 and N3: the client reads the daemon pipe's owner through its own handle, and the real
    /// check accepts it.
    #[cfg(windows)]
    #[test]
    fn the_owner_only_pipe_is_ours() {
        use windows_sys::Win32::Security::{TOKEN_OWNER, TokenOwner};
        let user = user_sid().unwrap();
        let buf = token_info::<TOKEN_OWNER>(TokenOwner).unwrap();
        // SAFETY: `buf` holds a whole TOKEN_OWNER; its SID points inside `buf`.
        let default_owner =
            unsafe { sid_string((*buf.as_ptr().cast::<TOKEN_OWNER>()).Owner) }.unwrap();
        println!("TokenUser {user}; TokenOwner {default_owner}");
        let name = test_pipe("ours");
        let server = serve(&name, |_| Response::Ack).unwrap();
        let client = sync_gate_core::ipc_name::connect(&name);
        let owner = client.as_ref().ok().map(owner_seen_by_client);
        println!("pipe owner read by the client: {owner:?}");
        drop(client.expect("the real check refused our own daemon pipe"));
        server.shutdown();
        let owner = owner.unwrap();
        assert!(owner == user || owner == default_owner, "{owner}");
    }

    /// N2: the owner given at creation must be in our token (only the owner differs; the DACL
    /// grants the caller in both).
    #[cfg(windows)]
    #[test]
    fn an_owner_outside_our_token_cannot_be_set() {
        let sid = user_sid().unwrap();
        raw_listener(
            &test_pipe("owner-us"),
            Some(sddl(&format!("O:{sid}D:P(A;;GA;;;{sid})"))),
        )
        .unwrap();
        let e = raw_listener(
            &test_pipe("owner-system"),
            Some(sddl(&format!("O:SYD:P(A;;GA;;;{sid})"))),
        )
        .expect_err("a pipe owned by SYSTEM was created");
        assert_eq!(e.raw_os_error(), Some(1307), "{e}");
    }

    /// Automatic proxy of another user being denied: the same SDDL builder naming someone else.
    #[cfg(windows)]
    #[test]
    fn a_user_the_descriptor_does_not_name_is_denied() {
        let sid = user_sid().unwrap();
        let ours = test_pipe("dacl-us");
        let _l = raw_listener(&ours, Some(descriptor_for(&sid).unwrap())).unwrap();
        raw_connect(&ours).unwrap();
        let system = test_pipe("dacl-system");
        let _l = raw_listener(&system, Some(descriptor_for("S-1-5-18").unwrap())).unwrap();
        let e = raw_connect(&system).expect_err("a pipe for SYSTEM only let us in");
        assert_eq!(e.raw_os_error(), Some(5), "{e}");
    }

    // ---- guests ----

    /// Every ACE of a live pipe `name` created with `sd`: (type, mask, SID), read through the
    /// server end (its creator's handle carries READ_CONTROL; a client without an ACE has none).
    #[cfg(windows)]
    fn live_dacl(name: &str, sd: &SecurityDescriptor) -> Vec<(u8, u32, String)> {
        use interprocess::os::windows::security_descriptor::AsSecurityDescriptor;
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::Security::{
            ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce,
            GetKernelObjectSecurity, GetSecurityDescriptorDacl, SECURITY_ATTRIBUTES,
        };
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX,
        };
        use windows_sys::Win32::System::Pipes::CreateNamedPipeW;
        let path: Vec<u16> = format!(r"\\.\pipe\{name}")
            .encode_utf16()
            .chain([0])
            .collect();
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.as_sd().cast_mut(),
            bInheritHandle: 0,
        };
        // SAFETY: NUL-terminated path; `sa` and the descriptor it points to outlive the call.
        let h = unsafe {
            CreateNamedPipeW(
                path.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                0,
                1,
                512,
                512,
                0,
                &sa,
            )
        };
        assert_ne!(
            h,
            INVALID_HANDLE_VALUE,
            "{name}: {}",
            io::Error::last_os_error()
        );
        // SAFETY: a fresh handle nobody else owns.
        let h = unsafe { OwnedHandle::from_raw_handle(h) };
        let mut len = 0u32;
        // SAFETY: size query: null buffer of length 0, `len` is a valid out pointer.
        unsafe {
            GetKernelObjectSecurity(
                h.as_raw_handle(),
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                0,
                &mut len,
            )
        };
        let mut sd = vec![0u64; (len as usize).div_ceil(8)];
        // SAFETY: `sd` holds at least `len` writable bytes.
        let ok = unsafe {
            GetKernelObjectSecurity(
                h.as_raw_handle(),
                DACL_SECURITY_INFORMATION,
                sd.as_mut_ptr().cast(),
                len,
                &mut len,
            )
        };
        assert_ne!(ok, 0, "{}", io::Error::last_os_error());
        let (mut present, mut acl, mut defaulted): (i32, *mut ACL, i32) =
            (0, std::ptr::null_mut(), 0);
        // SAFETY: `sd` holds the descriptor just read; the out pointers are valid.
        let ok = unsafe {
            GetSecurityDescriptorDacl(
                sd.as_mut_ptr().cast(),
                &mut present,
                &mut acl,
                &mut defaulted,
            )
        };
        assert!(ok != 0 && present != 0 && !acl.is_null());
        // SAFETY: `acl` points into `sd`, alive here; each ACE is read by GetAce within it.
        unsafe {
            (0..u32::from((*acl).AceCount))
                .map(|i| {
                    let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
                    assert_ne!(GetAce(acl, i, &mut ace), 0);
                    let header = *ace.cast::<ACE_HEADER>();
                    let allowed = ace.cast::<ACCESS_ALLOWED_ACE>();
                    let sid = std::ptr::addr_of_mut!((*allowed).SidStart).cast();
                    (header.AceType, (*allowed).Mask, sid_string(sid).unwrap())
                })
                .collect()
        }
    }

    /// Test 16 (O3a): the guest ACE is exactly connect-and-talk, for each kind of SID.
    #[cfg(windows)]
    #[test]
    fn each_guest_ace_is_exactly_connect_never_create() {
        assert_eq!(sync_gate_core::ipc_name::GUEST_PIPE_ACCESS, 0x0012_0083);
        let own = user_sid().unwrap();
        let cap = "S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681";
        for (i, x) in [own.as_str(), "S-1-5-5-0-7", cap].into_iter().enumerate() {
            let name = test_pipe(&format!("ace-{i}"));
            let aces = live_dacl(&name, &guest_descriptor(&own, "S-1-5-18", x).unwrap());
            assert_eq!(aces.len(), 2, "{aces:?}");
            assert!(aces.iter().all(|a| a.0 == 0), "allow ACEs only: {aces:?}");
            let mask = aces.iter().find(|a| a.2 == x).expect("the guest's ACE").1;
            assert_eq!(mask, 0x1 | 0x2 | 0x80 | 0x2_0000 | 0x10_0000, "{x}");
            for bit in [0x4, 0x4000_0000, 0x1000_0000, 0x4_0000, 0x8_0000, 0x1_0000] {
                assert_eq!(mask & bit, 0, "{x}: forbidden bit {bit:#x}");
            }
        }
    }

    #[cfg(windows)]
    mod nt {
        use windows_sys::Win32::Foundation::HANDLE;

        #[repr(C)]
        pub struct UnicodeString {
            pub length: u16,
            pub maximum_length: u16,
            pub buffer: *mut u16,
        }

        #[repr(C)]
        pub struct ObjectAttributes {
            pub length: u32,
            pub root_directory: HANDLE,
            pub object_name: *mut UnicodeString,
            pub attributes: u32,
            pub security_descriptor: *mut core::ffi::c_void,
            pub security_quality_of_service: *mut core::ffi::c_void,
        }

        #[repr(C)]
        pub struct IoStatusBlock {
            pub status: usize,
            pub information: usize,
        }

        #[link(name = "ntdll")]
        unsafe extern "system" {
            #[allow(clippy::too_many_arguments)]
            pub fn NtCreateNamedPipeFile(
                file: *mut HANDLE,
                desired_access: u32,
                attributes: *mut ObjectAttributes,
                io: *mut IoStatusBlock,
                share_access: u32,
                create_disposition: u32,
                create_options: u32,
                pipe_type: u32,
                read_mode: u32,
                completion_mode: u32,
                maximum_instances: u32,
                inbound_quota: u32,
                outbound_quota: u32,
                default_timeout: *mut i64,
            ) -> i32;
        }
    }

    /// The NT status of creating one more server instance of `name` as this process, with the
    /// parameters the `interprocess` listener uses (F10, F18); a created handle is closed.
    #[cfg(windows)]
    fn create_instance_status(name: &str) -> i32 {
        use windows_sys::Win32::Foundation::CloseHandle;
        let mut path: Vec<u16> = format!(r"\??\pipe\{name}").encode_utf16().collect();
        let bytes = (path.len() * 2) as u16;
        let mut unicode = nt::UnicodeString {
            length: bytes,
            maximum_length: bytes,
            buffer: path.as_mut_ptr(),
        };
        let mut attrs = nt::ObjectAttributes {
            length: size_of::<nt::ObjectAttributes>() as u32,
            root_directory: std::ptr::null_mut(),
            object_name: &mut unicode,
            attributes: 0x40, // OBJ_CASE_INSENSITIVE
            security_descriptor: std::ptr::null_mut(),
            security_quality_of_service: std::ptr::null_mut(),
        };
        let mut io = nt::IoStatusBlock {
            status: 0,
            information: 0,
        };
        // interprocess's default wait timeout (0 = the 50 ms default, as kernel32 passes it).
        let mut timeout: i64 = -500_000;
        let mut handle = std::ptr::null_mut();
        // SAFETY: every pointer is to a live local; `path` outlives the call.
        let status = unsafe {
            nt::NtCreateNamedPipeFile(
                &mut handle,
                0x10_0003, // FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE
                &mut attrs,
                &mut io,
                0x3,      // FILE_SHARE_READ | FILE_SHARE_WRITE
                3,        // FILE_OPEN_IF
                0,        // overlapped: no FILE_SYNCHRONOUS_IO_*
                0x2,      // byte type, remote clients rejected (PIPE_REJECT_REMOTE_CLIENTS)
                0,        // byte read mode
                0,        // queued (blocking) completion
                u32::MAX, // PIPE_UNLIMITED_INSTANCES (255) as kernel32 passes it
                512,
                512,
                &mut timeout,
            )
        };
        if status >= 0 {
            // SAFETY: the handle the call just created, closed once.
            unsafe { CloseHandle(handle) };
        }
        status
    }

    /// Test 17 (O3b; S4, S8): a guest can connect and talk, never create an instance.
    #[cfg(windows)]
    #[test]
    fn a_guest_can_never_create_an_instance() {
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        };
        let own = user_sid().unwrap();
        let a = test_pipe("instance-a");
        let _la =
            raw_listener(&a, Some(guest_descriptor(&own, "S-1-5-18", &own).unwrap())).unwrap();
        let b = test_pipe("instance-b");
        let mutant = format!("O:{own}D:P(A;;GA;;;S-1-5-18)(A;;0x120087;;;{own})");
        let _lb = raw_listener(&b, Some(sddl(&mutant))).unwrap();
        let denied = create_instance_status(&a);
        let control = create_instance_status(&b);
        println!("NtCreateNamedPipeFile: pipe A {denied:#010x}, pipe B (0x120087) {control:#010x}");
        assert!(control >= 0, "control: {control:#010x}");
        assert_eq!(denied as u32, 0xC000_0022, "STATUS_ACCESS_DENIED");
        let e = raw_connect(&a).expect_err("GENERIC_WRITE was granted");
        assert_eq!(e.raw_os_error(), Some(5), "{e}");
        let path: Vec<u16> = format!(r"\\.\pipe\{a}").encode_utf16().chain([0]).collect();
        // SAFETY: NUL-terminated path; no security attributes or template.
        let h = unsafe {
            CreateFileW(
                path.as_ptr(),
                sync_gate_core::ipc_name::GUEST_PIPE_ACCESS,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(h, INVALID_HANDLE_VALUE, "{}", io::Error::last_os_error());
        // SAFETY: the handle just opened, closed once.
        unsafe { CloseHandle(h) };
    }

    /// #12: the descriptor names its owner (an elevated token's default owner is the Administrators
    /// group, which the client refuses), and a live guest pipe is owned by the user for the
    /// client that connects to it, as `connect_guest_at` reads it. Without a user in `O:`, the
    /// first passes only where the default owner already is the user (not elevated).
    #[cfg(windows)]
    #[test]
    fn a_guest_pipe_is_owned_by_the_user() {
        use interprocess::os::windows::security_descriptor::AsSecurityDescriptor;
        use sync_gate_probe::{IdentKind, ident_of};
        use windows_sys::Win32::Security::GetSecurityDescriptorOwner;
        let own = user_sid().unwrap();
        let sd = guest_descriptor(&own, "S-1-5-18", &own).unwrap();
        let (mut owner, mut defaulted) = (std::ptr::null_mut(), 0);
        // SAFETY: `sd` is a valid descriptor that the call only reads; the out pointers are valid.
        let ok = unsafe {
            GetSecurityDescriptorOwner(sd.as_sd().cast_mut(), &mut owner, &mut defaulted)
        };
        assert!(ok != 0 && !owner.is_null(), "the descriptor has no owner");
        // SAFETY: `owner` points into `sd`, alive here.
        assert_eq!(unsafe { sid_string(owner) }.unwrap(), own);
        // The production path: `serve_guest` binds, a client reads the owner off its own handle.
        let name = test_pipe("guest-owner");
        let kind = IdentKind::Account(own.clone());
        let server = serve_guest(
            &name,
            "tester",
            &own,
            move |v| ident_of(&kind, v),
            |_, _| Response::Ack,
        )
        .unwrap();
        let s = raw_connect(&name).unwrap();
        assert_eq!(owner_seen_by_client(&s), own);
        drop(s);
        server.shutdown();
    }

    /// Reads one reply line on its own thread; the result comes on the channel.
    #[cfg(windows)]
    fn read_reply(s: Stream) -> mpsc::Receiver<io::Result<String>> {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut line = String::new();
            let _ = tx.send(BufReader::new(s).read_line(&mut line).map(|_| line));
        });
        rx
    }

    /// Test 18: at most 16 live connections per guest pipe; the 17th is dropped unread.
    #[cfg(windows)]
    #[test]
    fn a_guest_connection_beyond_the_cap_is_dropped() {
        use sync_gate_probe::{IdentKind, ident_of};
        let own = user_sid().unwrap();
        let name = test_pipe("guest-cap");
        let (calls_tx, calls) = mpsc::channel::<()>();
        let (release, release_rx) = mpsc::channel::<()>();
        let release_rx = std::sync::Mutex::new(release_rx);
        let kind = IdentKind::Account(own.clone());
        let server = serve_guest(
            &name,
            "tester",
            &own,
            move |v| ident_of(&kind, v),
            move |_, _| {
                let _ = calls_tx.send(());
                let rx = release_rx.lock().unwrap();
                let _ = rx.recv_timeout(Duration::from_secs(30));
                Response::Ack
            },
        )
        .unwrap();
        let wait = Duration::from_secs(5);
        let replies: Vec<_> = (0..16)
            .map(|_| {
                let mut s = raw_connect(&name).unwrap();
                s.write_all(b"\"Status\"\n").unwrap();
                read_reply(s)
            })
            .collect();
        for i in 0..16 {
            calls
                .recv_timeout(wait)
                .unwrap_or_else(|_| panic!("call {i}"));
        }
        let mut over = raw_connect(&name).unwrap();
        let _ = over.write_all(b"\"Status\"\n");
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(over.read(&mut [0u8; 16]));
        });
        assert!(
            matches!(rx.recv_timeout(wait), Ok(Ok(0) | Err(_))),
            "the 17th connection was not dropped"
        );
        assert!(calls.try_recv().is_err(), "the handler ran for the 17th");
        // One lets go: its reply arrives, and a new connection is served.
        release.send(()).unwrap();
        let served = (0..50).find_map(|_| {
            replies
                .iter()
                .find_map(|r| r.recv_timeout(Duration::from_millis(100)).ok())
        });
        assert!(
            matches!(served, Some(Ok(ref l)) if l.contains("Ack")),
            "{served:?}"
        );
        let mut next = raw_connect(&name).unwrap();
        next.write_all(b"\"Status\"\n").unwrap();
        let next = read_reply(next);
        calls
            .recv_timeout(wait)
            .expect("a connection after the release is served");
        for _ in 0..17 {
            let _ = release.send(());
        }
        assert!(matches!(next.recv_timeout(wait), Ok(Ok(ref l)) if l.contains("Ack")));
        drop(replies);
        assert!(server.stop_within(Duration::from_secs(10)));
    }

    /// Final review, Important 1: the cap bounds worker CREATION, not just handling. 16 silent
    /// connections hold the 16 slots (their workers wait in the read); 8 more are dropped unread
    /// and none of them starts a worker. Then a slot frees and a new connection is served.
    #[cfg(windows)]
    #[test]
    fn excess_guest_connections_never_start_a_worker() {
        use sync_gate_probe::{IdentKind, ident_of};
        let own = user_sid().unwrap();
        let name = test_pipe("guest-bound");
        let kind = IdentKind::Account(own.clone());
        let server = serve_guest_with(
            Duration::from_secs(30),
            spawn_watchdog,
            &name,
            "tester",
            &own,
            move |v| ident_of(&kind, v),
            move |_, _| Response::Ack,
        )
        .unwrap();
        let mut held: Vec<_> = (0..16).map(|_| raw_connect(&name).unwrap()).collect();
        let wait = Duration::from_secs(5);
        let end = Instant::now() + wait;
        while workers_entered(&name, false) < 16 {
            assert!(
                Instant::now() < end,
                "the 16 admitted workers never started"
            );
            thread::sleep(Duration::from_millis(10));
        }
        for i in 0..8 {
            let mut over = raw_connect(&name).unwrap();
            let (tx, rx) = mpsc::channel();
            thread::spawn(move || {
                let _ = tx.send(over.read(&mut [0u8; 16]));
            });
            assert!(
                matches!(rx.recv_timeout(wait), Ok(Ok(0) | Err(_))),
                "excess connection {i} was not dropped unread"
            );
        }
        assert_eq!(
            workers_entered(&name, false),
            16,
            "a worker was started for an excess connection"
        );
        // Positive control: one slot frees (its client leaves) and a new connection is served.
        drop(held.pop());
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            let mut next = raw_connect(&name).unwrap();
            if next.write_all(b"\"Status\"\n").is_ok()
                && let Ok(Ok(l)) = read_reply(next).recv_timeout(Duration::from_secs(2))
                && l.contains("Ack")
            {
                break;
            }
            assert!(
                Instant::now() < end,
                "no connection was served after a slot freed"
            );
            thread::sleep(Duration::from_millis(100));
        }
        drop(held);
        assert!(server.stop_within(Duration::from_secs(10)));
    }

    /// A guest pipe with a short I/O deadline for the tests below; `calls` counts handler runs and
    /// the handler answers `big` (4 MiB, never fits the pipe) while the flag is set, else Ack.
    #[cfg(windows)]
    fn deadline_server(
        name: &str,
        deadline: Duration,
        spawn: SpawnWatchdog,
        big: Arc<AtomicBool>,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    ) -> ServerHandle {
        use sync_gate_probe::{IdentKind, ident_of};
        let own = user_sid().unwrap();
        let kind = IdentKind::Account(own.clone());
        serve_guest_with(
            deadline,
            spawn,
            name,
            "tester",
            &own,
            move |v| ident_of(&kind, v),
            move |_, _| {
                calls.fetch_add(1, Ordering::SeqCst);
                if big.load(Ordering::SeqCst) {
                    Response::Error {
                        message: "x".repeat(4 * 1024 * 1024),
                    }
                } else {
                    Response::Ack
                }
            },
        )
        .unwrap()
    }

    /// With the 16 slots held, the 17th is dropped unread (the slots are really
    /// taken); then, within 10 s, a new connection is served again (the deadline freed a slot).
    #[cfg(windows)]
    fn assert_slot_freed_after_deadline(name: &str, calls: &std::sync::atomic::AtomicUsize) {
        let before = calls.load(Ordering::SeqCst);
        let mut over = raw_connect(name).unwrap();
        let _ = over.write_all(b"\"Status\"\n");
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(over.read(&mut [0u8; 16]));
        });
        assert!(
            matches!(rx.recv_timeout(Duration::from_secs(5)), Ok(Ok(0) | Err(_))),
            "the 17th connection was not dropped while the 16 were held"
        );
        assert_eq!(calls.load(Ordering::SeqCst), before, "handler ran for it");
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            let mut next = raw_connect(name).unwrap();
            // A failed write or an empty line is a connection dropped at the door (no slot
            // yet; the accept thread drops it at once): try again.
            if next.write_all(b"\"Status\"\n").is_ok()
                && let Ok(Ok(l)) = read_reply(next).recv_timeout(Duration::from_secs(2))
                && !l.is_empty()
            {
                assert!(l.contains("Ack"), "{l}");
                return;
            }
            thread::sleep(Duration::from_millis(100));
            assert!(Instant::now() < end, "no slot was freed after the deadline");
        }
    }

    /// Review 4, Important 2: 16 connections that never send a newline hold every slot until the
    /// deadline drops them; then a new connection is served.
    #[cfg(windows)]
    #[test]
    fn guest_connections_that_never_finish_a_request_are_dropped() {
        use std::sync::atomic::AtomicUsize;
        let name = test_pipe("guest-slow-read");
        let calls = Arc::new(AtomicUsize::new(0));
        let server = deadline_server(
            &name,
            Duration::from_millis(1500),
            spawn_watchdog,
            Arc::new(AtomicBool::new(false)),
            calls.clone(),
        );
        let mut held: Vec<_> = (0..16).map(|_| raw_connect(&name).unwrap()).collect();
        for s in &mut held {
            s.write_all(b"\"Status\"").unwrap(); // no newline
        }
        assert_slot_freed_after_deadline(&name, &calls);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "only the control was served"
        );
        drop(held);
        assert!(server.stop_within(Duration::from_secs(10)));
    }

    /// Review 4, Important 2: 16 clients send a request and never read a reply too big for the
    /// pipe, so each reply blocks in write/flush; the deadline frees the slots.
    #[cfg(windows)]
    #[test]
    fn guest_connections_that_never_read_their_reply_are_dropped() {
        use std::sync::atomic::AtomicUsize;
        let name = test_pipe("guest-slow-reply");
        let (big, calls) = (
            Arc::new(AtomicBool::new(true)),
            Arc::new(AtomicUsize::new(0)),
        );
        let server = deadline_server(
            &name,
            Duration::from_millis(1500),
            spawn_watchdog,
            big.clone(),
            calls.clone(),
        );
        let mut held: Vec<_> = (0..16).map(|_| raw_connect(&name).unwrap()).collect();
        for s in &mut held {
            s.write_all(b"\"Status\"\n").unwrap();
        }
        let end = Instant::now() + Duration::from_secs(5);
        while calls.load(Ordering::SeqCst) < 16 {
            assert!(Instant::now() < end, "the 16 requests were not all handled");
            thread::sleep(Duration::from_millis(20));
        }
        big.store(false, Ordering::SeqCst);
        assert_slot_freed_after_deadline(&name, &calls);
        drop(held);
        assert!(server.stop_within(Duration::from_secs(10)));
    }

    #[cfg(windows)]
    fn no_thread(_: Box<dyn FnOnce() + Send>) -> io::Result<()> {
        Err(io::Error::other("no thread"))
    }

    /// Review 5, Important 2: when the deadline's thread cannot start, the connection is dropped
    /// before any blocking I/O (not read, not answered) and its slot is free; with the thread
    /// startable (the control server) the same request is answered.
    #[cfg(windows)]
    #[test]
    fn a_guest_connection_whose_deadline_cannot_start_is_dropped() {
        use std::sync::atomic::AtomicUsize;
        let wait = Duration::from_secs(5);
        for (tag, spawn, served) in [
            ("guest-nospawn", no_thread as SpawnWatchdog, false),
            ("guest-spawn-ok", spawn_watchdog as SpawnWatchdog, true),
        ] {
            let name = test_pipe(tag);
            let calls = Arc::new(AtomicUsize::new(0));
            let server = deadline_server(
                &name,
                Duration::from_secs(60),
                spawn,
                Arc::new(AtomicBool::new(false)),
                calls.clone(),
            );
            // More connections than slots, one after the other: a leaked slot would show up.
            for _ in 0..20 {
                let mut c = raw_connect(&name).unwrap();
                // Dropped before any read, the server may close the pipe before this write lands:
                // "being closed" (BrokenPipe) is then the drop itself, never for the control.
                match c.write_all(b"\"Status\"\n") {
                    Err(e) if !served && e.kind() == io::ErrorKind::BrokenPipe => continue,
                    r => r.unwrap(),
                }
                let line = read_reply(c)
                    .recv_timeout(wait)
                    .expect("no answer or close");
                match line {
                    Ok(l) if served => assert!(l.contains("Ack"), "{l}"),
                    Ok(l) => assert!(l.is_empty(), "answered without a deadline: {l}"),
                    Err(_) => assert!(!served, "positive control failed"),
                }
            }
            assert_eq!(calls.load(Ordering::SeqCst), if served { 20 } else { 0 });
            assert!(server.stop_within(Duration::from_secs(10)));
        }
    }

    /// This process's token, write-restricted to Everyone and `logon`, for impersonation.
    #[cfg(windows)]
    fn restricted_impersonation(logon: &str) -> std::os::windows::io::OwnedHandle {
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
        use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
        use windows_sys::Win32::Security::{
            CreateRestrictedToken, DuplicateTokenEx, PSID, SID_AND_ATTRIBUTES,
            SecurityImpersonation, TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_QUERY,
            TokenImpersonation, WRITE_RESTRICTED,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        let own = |h: HANDLE| {
            assert!(!h.is_null(), "{}", io::Error::last_os_error());
            // SAFETY: a fresh handle nobody else owns.
            unsafe { OwnedHandle::from_raw_handle(h) }
        };
        let sid = |s: &str| {
            let w: Vec<u16> = s.encode_utf16().chain([0]).collect();
            let mut p: PSID = std::ptr::null_mut();
            // SAFETY: NUL-terminated string; `p` is freed by the caller with LocalFree.
            assert_ne!(unsafe { ConvertStringSidToSidW(w.as_ptr(), &mut p) }, 0);
            p
        };
        let mut t: HANDLE = std::ptr::null_mut();
        // SAFETY: pseudo handle; `t` is a valid out pointer.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut t) };
        let token = own(t);
        let (everyone, logon) = (sid("S-1-1-0"), sid(logon));
        let sids = [
            SID_AND_ATTRIBUTES {
                Sid: everyone,
                Attributes: 0,
            },
            SID_AND_ATTRIBUTES {
                Sid: logon,
                Attributes: 0,
            },
        ];
        let mut restricted: HANDLE = std::ptr::null_mut();
        // SAFETY: an open token, two valid SIDs (freed once below), a valid out pointer.
        unsafe {
            CreateRestrictedToken(
                token.as_raw_handle(),
                WRITE_RESTRICTED,
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                2,
                sids.as_ptr(),
                &mut restricted,
            );
            LocalFree(everyone.cast());
            LocalFree(logon.cast());
        }
        let restricted = own(restricted);
        let mut imp: HANDLE = std::ptr::null_mut();
        // SAFETY: an open token; `imp` is a valid out pointer.
        unsafe {
            DuplicateTokenEx(
                restricted.as_raw_handle(),
                TOKEN_ALL_ACCESS,
                std::ptr::null(),
                SecurityImpersonation,
                TokenImpersonation,
                &mut imp,
            )
        };
        own(imp)
    }

    /// Sets (Some) or clears (None) the current thread's impersonation token.
    #[cfg(windows)]
    fn impersonate(token: Option<&std::os::windows::io::OwnedHandle>) {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Threading::SetThreadToken;
        let raw = token.map_or(std::ptr::null_mut(), |t| t.as_raw_handle());
        // SAFETY: null = the current thread; `raw` is an open impersonation token or null.
        assert_ne!(unsafe { SetThreadToken(std::ptr::null(), raw) }, 0);
    }

    /// The guest CLI's open: GUEST_PIPE_ACCESS with SQOS | IDENTIFICATION | CONTEXT_TRACKING.
    #[cfg(windows)]
    fn guest_open(name: &str) -> io::Result<Stream> {
        use interprocess::os::windows::named_pipe::local_socket::Stream as NamedPipeStream;
        use std::os::windows::io::{FromRawHandle, OwnedHandle};
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
            SECURITY_CONTEXT_TRACKING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
        };
        let path: Vec<u16> = format!(r"\\.\pipe\{name}")
            .encode_utf16()
            .chain([0])
            .collect();
        // SAFETY: NUL-terminated path; no security attributes or template.
        let h = unsafe {
            CreateFileW(
                path.as_ptr(),
                sync_gate_core::ipc_name::GUEST_PIPE_ACCESS,
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
        if h == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a fresh handle nobody else owns.
        let h = unsafe { OwnedHandle::from_raw_handle(h) };
        NamedPipeStream::try_from(h)
            .map(Stream::NamedPipe)
            .map_err(io::Error::from)
    }

    /// The server closed without a reply: end of file or an error, within the wait.
    #[cfg(windows)]
    fn dropped(r: Result<io::Result<String>, mpsc::RecvTimeoutError>) {
        let closed = matches!(&r, Ok(Ok(l)) if l.is_empty()) || matches!(r, Ok(Err(_)));
        assert!(
            closed,
            "expected no reply and a closed connection, got {r:?}"
        );
    }

    /// Test 41 (F36, F47): the door judges the token of whoever wrote the message.
    #[cfg(windows)]
    #[test]
    fn the_guest_door_reads_the_identity_of_each_message() {
        use sync_gate_probe::{IdentKind, ident_of};
        let own = user_sid().unwrap();
        let logon = crate::guest::logon_sid().unwrap();
        let wait = Duration::from_secs(5);
        let serve_as = |tag: &str, kind: IdentKind, ace: &str| {
            let (tx, rx) = mpsc::channel::<String>();
            let tx = std::sync::Mutex::new(tx);
            let name = test_pipe(tag);
            let server = serve_guest(
                &name,
                tag,
                ace,
                move |v| ident_of(&kind, v),
                move |ident, _| {
                    let _ = tx.lock().unwrap().send(ident.to_string());
                    Response::Ack
                },
            )
            .unwrap();
            (name, server, rx)
        };
        let (name, server, calls) =
            serve_as("sbx-restricted", IdentKind::Restricted(own.clone()), &logon);
        let token = restricted_impersonation(&logon);
        // The request written under the restricted token.
        impersonate(Some(&token));
        let sent = guest_open(&name).and_then(|mut s| s.write_all(b"\"Status\"\n").map(|()| s));
        impersonate(None);
        let reply = read_reply(sent.unwrap());
        let mut sids = ["S-1-1-0".to_string(), logon.clone()];
        sids.sort();
        let want = format!("restricted:{own}:{}", sids.join(","));
        assert_eq!(calls.recv_timeout(wait), Ok(want));
        assert!(matches!(reply.recv_timeout(wait), Ok(Ok(ref l)) if l.contains("Ack")));
        // Handed on: opened under the restricted token, written with the full one.
        impersonate(Some(&token));
        let opened = guest_open(&name);
        impersonate(None);
        let mut handed = opened.unwrap();
        handed.write_all(b"\"Status\"\n").unwrap();
        let reply = read_reply(handed);
        dropped(reply.recv_timeout(wait));
        // The test's full token (GA through the owner's ACE).
        let mut full = raw_connect(&name).unwrap();
        full.write_all(b"\"Status\"\n").unwrap();
        let reply = read_reply(full);
        dropped(reply.recv_timeout(wait));
        assert!(
            calls.try_recv().is_err(),
            "the handler ran for another kind"
        );
        server.shutdown();
        // Control: the full client on an account door is served, by its account.
        let (name, server, calls) = serve_as("guest-own", IdentKind::Account(own.clone()), &own);
        let mut full = raw_connect(&name).unwrap();
        full.write_all(b"\"Status\"\n").unwrap();
        let reply = read_reply(full);
        assert_eq!(calls.recv_timeout(wait), Ok(format!("account:{own}")));
        assert!(matches!(reply.recv_timeout(wait), Ok(Ok(ref l)) if l.contains("Ack")));
        server.shutdown();
    }
}
