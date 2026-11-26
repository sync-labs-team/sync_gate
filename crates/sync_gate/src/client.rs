//! Client side of the local socket: one request line out, one response line back.

use interprocess::local_socket::Stream;
use std::io::{self, BufRead, BufReader, Write};
use std::sync::mpsc;
use std::time::Duration;
use sync_gate_core::ipc_name::{connect_checked, is_foreign, server_is_ours};
use sync_gate_core::{Request, Response, socket_name};

/// Total time any request except `Wait` may take; a wedged daemon must not hang `sync_gate run`.
const DEADLINE: Duration = Duration::from_secs(2);

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Could not connect: nobody listens on the socket (or it is not ours).
    #[error("sync_gated is not running")]
    DaemonDown,
    /// Connected, but no reply within the deadline: slow or wedged, not gone.
    #[error("sync_gated did not answer in time")]
    Timeout,
    #[error("io error talking to sync_gated: {0}")]
    Io(#[from] io::Error),
    #[error("protocol error: {0}")]
    Protocol(String),
    /// A guest connection closed without a reply (the daemon dropped it over the guest's
    /// connection cap, or went away mid-request): the command runs directly.
    #[error("sync_gated is busy for this account")]
    Busy,
}

/// Sends `req` to the daemon at the default per-user socket.
pub fn call(req: &Request) -> Result<Response, ClientError> {
    call_at(&socket_name(), req)
}

/// Sends `req` to the daemon listening on `name` and blocks for its reply.
/// Everything but `Wait` is bounded by `DEADLINE`; past it the result is `Timeout`, not `DaemonDown`.
pub fn call_at(name: &str, req: &Request) -> Result<Response, ClientError> {
    call_with_deadline(name, req, DEADLINE)
}

/// [`call_at`] with the call's own patience, counted from the start of the call (connecting
/// included): the lease request waits `lease_wait_secs`, not the usual 2 s.
pub fn call_with_deadline(
    name: &str,
    req: &Request,
    deadline: Duration,
) -> Result<Response, ClientError> {
    call_checked(name, req, server_is_ours, deadline)
}

/// [`call_at`] with the check of who serves the socket injectable (tests make it say "foreign").
fn call_checked(
    name: &str,
    req: &Request,
    ours: fn(&Stream) -> bool,
    deadline: Duration,
) -> Result<Response, ClientError> {
    call_spawned(name, req, ours, deadline, |job| {
        std::thread::Builder::new().spawn(job).map(drop)
    })
}

/// [`call_checked`] with the thread of the exchange injectable (tests make it refuse). A thread
/// the OS refuses is an error value, never a panic: the command still has to run.
fn call_spawned(
    name: &str,
    req: &Request,
    ours: fn(&Stream) -> bool,
    deadline: Duration,
    spawn: impl FnOnce(Box<dyn FnOnce() + Send>) -> io::Result<()>,
) -> Result<Response, ClientError> {
    if matches!(req, Request::Wait { .. }) {
        return exchange(name, req, ours);
    }
    let (tx, rx) = mpsc::channel();
    let (name, req) = (name.to_owned(), req.clone());
    // A timed-out helper thread lingers until the daemon answers or the process exits.
    spawn(Box::new(move || {
        let _ = tx.send(exchange(&name, &req, ours));
    }))
    .map_err(|e| {
        ClientError::Io(io::Error::new(
            e.kind(),
            format!("cannot start a thread: {e}"),
        ))
    })?;
    rx.recv_timeout(deadline)
        .unwrap_or(Err(ClientError::Timeout))
}

/// A socket served by another user is treated like no daemon at all (fail open), said once.
fn foreign_daemon() -> ClientError {
    static SAID: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !SAID.swap(true, std::sync::atomic::Ordering::SeqCst) {
        eprintln!("sync_gate: daemon pipe is not owned by this user; continuing without queue");
    }
    ClientError::DaemonDown
}

/// Set once the not-listed explanation has been printed (it already says the command runs
/// without the queue, so the generic "daemon not running" line must not follow it).
static GUEST_EXPLAINED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// True when this process already told a guest it is not listed.
pub fn guest_explained() -> bool {
    GUEST_EXPLAINED.load(std::sync::atomic::Ordering::SeqCst)
}

/// A guest the owner did not list: said once, then the command runs directly.
#[cfg(any(windows, test))]
fn guest_not_allowed() -> ClientError {
    if !GUEST_EXPLAINED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        eprintln!(
            "sync_gate: this account may not use the owner's sync_gate queue (the owner can list it \
             in `guests` in config.toml; see docs/sandbox.md); continuing without queue"
        );
    }
    ClientError::DaemonDown
}

/// Why the guest pipe could not be used.
#[cfg(any(windows, test))]
#[derive(Debug, PartialEq, Eq)]
enum GuestOutcome {
    Denied,
    NotAllowed,
    Foreign,
    Down,
}

#[cfg(any(windows, test))]
fn guest_outcome(e: &io::Error) -> GuestOutcome {
    if e.kind() == io::ErrorKind::Unsupported {
        GuestOutcome::Denied // not a guest: the owner's path, unchanged
    } else if e.kind() == io::ErrorKind::NotFound {
        GuestOutcome::NotAllowed
    } else if is_foreign(e) {
        GuestOutcome::Foreign
    } else {
        GuestOutcome::Down
    }
}

/// All four outcomes are `DaemonDown` to the caller: the command runs directly.
#[cfg(any(windows, test))]
fn guest_fallback(e: io::Error) -> ClientError {
    match guest_outcome(&e) {
        GuestOutcome::Denied => denied_daemon(),
        GuestOutcome::NotAllowed => guest_not_allowed(),
        GuestOutcome::Foreign => foreign_daemon(),
        GuestOutcome::Down => ClientError::DaemonDown,
    }
}

/// A pipe that exists but refuses us (most likely a daemon running elevated, whose DACL names
/// the elevated token) is treated like no daemon at all (fail open), said once.
fn denied_daemon() -> ClientError {
    static SAID: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !SAID.swap(true, std::sync::atomic::Ordering::SeqCst) {
        eprintln!(
            "sync_gate: access to the daemon pipe was denied (is sync_gated running elevated?); \
             continuing without queue"
        );
    }
    ClientError::DaemonDown
}

fn connect_error(e: io::Error) -> ClientError {
    if is_foreign(&e) {
        foreign_daemon()
    } else if e.kind() == io::ErrorKind::PermissionDenied {
        denied_daemon()
    } else {
        ClientError::DaemonDown
    }
}

const CLOSED: &str = "connection closed before a reply";

/// The control pipe, or (Windows) this account's guest pipe when the main one is denied; `true`
/// with a guest stream.
fn connect(name: &str, ours: fn(&Stream) -> bool) -> Result<(Stream, bool), ClientError> {
    match connect_checked(name, ours) {
        Ok(s) => Ok((s, false)),
        #[cfg(windows)]
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied && !is_foreign(&e) => {
            sync_gate_core::ipc_name::connect_guest(name)
                .map(|s| (s, true))
                .map_err(guest_fallback)
        }
        Err(e) => Err(connect_error(e)),
    }
}

/// On a guest stream a write error or a close before the reply is `Busy`; on the owner's, the
/// error as it was.
fn after_connect(e: ClientError, guest: bool) -> ClientError {
    match e {
        ClientError::Io(_) if guest => ClientError::Busy,
        ClientError::Protocol(m) if guest && m == CLOSED => ClientError::Busy,
        e => e,
    }
}

fn exchange(name: &str, req: &Request, ours: fn(&Stream) -> bool) -> Result<Response, ClientError> {
    // Nothing is sent before the server is known to be ours.
    let (stream, guest) = connect(name, ours)?;
    let mut conn = BufReader::new(stream);
    let mut line = serde_json::to_vec(req).map_err(|e| ClientError::Protocol(e.to_string()))?;
    line.push(b'\n');
    let mut reply = Vec::new();
    conn.get_mut()
        .write_all(&line)
        .and_then(|()| conn.get_mut().flush())
        .map_err(ClientError::Io)
        .and_then(|()| match conn.read_until(b'\n', &mut reply) {
            Ok(0) => Err(ClientError::Protocol(CLOSED.into())),
            Ok(_) => Ok(()),
            Err(e) => Err(ClientError::Io(e)),
        })
        .map_err(|e| after_connect(e, guest))?;
    serde_json::from_slice(&reply).map_err(|e| ClientError::Protocol(e.to_string()))
}

/// Serialises the tests that spawn a process with the tests that have a pipe peer. The pipe
/// handles are not inheritable (measured), so this is a precaution, not what keeps them apart.
#[cfg(test)]
pub(crate) static SPAWN_VS_PIPES: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use interprocess::local_socket::{ListenerOptions, prelude::*};
    use std::io::Read;
    use std::sync::mpsc;

    /// Connects on a helper thread so a stalled accept cannot hang the test; a connect that
    /// completes after `limit` leaves a thread holding one stream (acceptable in a failing test).
    fn connect_within(name: &str, limit: Duration) -> Option<Stream> {
        let (tx, rx) = mpsc::channel();
        let name = name.to_owned();
        std::thread::Builder::new()
            .spawn(move || {
                let _ = tx.send(sync_gate_core::ipc_name::connect(&name));
            })
            .ok()?;
        rx.recv_timeout(limit).ok()?.ok()
    }

    #[test]
    fn a_daemon_pipe_of_another_user_is_daemon_down_and_gets_no_byte() {
        let _own = SPAWN_VS_PIPES.lock().unwrap_or_else(|e| e.into_inner());
        let n = format!("sync_gate-client-foreign-{}", std::process::id());
        let name = if cfg!(windows) {
            n
        } else {
            std::env::temp_dir().join(n).to_string_lossy().into_owned()
        };
        let listener = ListenerOptions::new()
            .name(sync_gate_core::ipc_name::to_name(&name).unwrap())
            .create_sync()
            .unwrap();
        // Windows discards a client that closes before an accept is pending on its pipe
        // instance (ERROR_NO_DATA), so the refused connection may never reach the server. One
        // accept loop that reads each connection itself reports in accept order: whatever
        // arrives before an attempt's probe byte came from that attempt's refused connection.
        let (got, received) = mpsc::channel();
        let (ended, server_done) = mpsc::channel();
        let server = std::thread::spawn(move || {
            while let Ok(mut c) = listener.accept() {
                let mut buf = [0u8; 64];
                let n = c.read(&mut buf).unwrap_or(0);
                let probe = &buf[..n] == b"p";
                if got.send((n, probe)).is_err() {
                    break;
                }
            }
            // Last action: the test joins only after receiving this.
            let _ = ended.send(());
        });
        let mut observed = Vec::new();
        let mut attempts = 0;
        while observed.is_empty() && attempts < 50 {
            attempts += 1;
            let reply = call_checked(&name, &Request::Status, |_| false, DEADLINE);
            assert!(matches!(reply, Err(ClientError::DaemonDown)), "{reply:?}");
            // The probe stays open until it is read, so it cannot be discarded.
            let mut probe = connect_within(&name, Duration::from_secs(5))
                .expect("the probe connection did not complete in 5 s");
            probe.write_all(b"p").unwrap();
            loop {
                match received.recv_timeout(Duration::from_secs(5)) {
                    Ok((_, true)) => break,
                    Ok((n, false)) => observed.push(n),
                    Err(e) => panic!("the probe did not reach the server: {e}"),
                }
            }
        }
        // Ends the accept loop: its next send fails once the receiver is gone.
        drop(received);
        let mut last = connect_within(&name, Duration::from_secs(5))
            .expect("the closing connection did not complete in 5 s");
        last.write_all(b"p").unwrap();
        // Past the bound the server thread is left behind: the test fails anyway.
        if server_done.recv_timeout(Duration::from_secs(5)).is_err() {
            panic!("the server thread did not end within 5 s of the closing connection");
        }
        server.join().unwrap();
        assert!(
            !observed.is_empty(),
            "inconclusive: no refused connection reached the server in {attempts} attempts"
        );
        assert!(observed.iter().all(|n| *n == 0), "bytes: {observed:?}");
        println!("refused connection observed after {attempts} attempt(s)");
        let _ = std::fs::remove_file(&name);
    }

    #[test]
    fn the_deadline_is_the_one_given_and_runs_out_as_a_timeout() {
        let _own = SPAWN_VS_PIPES.lock().unwrap_or_else(|e| e.into_inner());
        let n = format!("sync_gate-client-slow-{}", std::process::id());
        let name = if cfg!(windows) {
            n
        } else {
            std::env::temp_dir().join(n).to_string_lossy().into_owned()
        };
        let server = sync_gated::ipc::serve_stream(&name, |mut r, _w, _close| {
            // Never answers; ends when the client closes.
            let _ = r.read_to_end(&mut Vec::new());
        })
        .unwrap();
        let start = std::time::Instant::now();
        let reply = call_checked(
            &name,
            &Request::Status,
            server_is_ours,
            Duration::from_millis(300),
        );
        assert!(matches!(reply, Err(ClientError::Timeout)), "{reply:?}");
        assert!(start.elapsed() < DEADLINE, "the short deadline was used");
        server.shutdown();
    }

    #[test]
    fn access_denied_is_daemon_down() {
        let denied = io::Error::from(io::ErrorKind::PermissionDenied);
        assert!(matches!(connect_error(denied), ClientError::DaemonDown));
    }

    #[test]
    fn guest_fallback_maps_each_outcome() {
        use sync_gate_core::ipc_name::ForeignServer;
        let kind = |k: io::ErrorKind| io::Error::from(k);
        let foreign = io::Error::new(io::ErrorKind::PermissionDenied, ForeignServer);
        assert_eq!(
            guest_outcome(&kind(io::ErrorKind::Unsupported)),
            GuestOutcome::Denied
        );
        assert_eq!(
            guest_outcome(&kind(io::ErrorKind::NotFound)),
            GuestOutcome::NotAllowed
        );
        assert_eq!(guest_outcome(&foreign), GuestOutcome::Foreign);
        assert_eq!(
            guest_outcome(&kind(io::ErrorKind::TimedOut)),
            GuestOutcome::Down
        );
        // Fail open: all four are DaemonDown to the caller.
        for e in [
            kind(io::ErrorKind::Unsupported),
            kind(io::ErrorKind::NotFound),
            foreign,
            kind(io::ErrorKind::TimedOut),
        ] {
            assert!(matches!(guest_fallback(e), ClientError::DaemonDown));
        }
    }

    #[test]
    fn a_lost_reply_is_busy_only_on_a_guest_stream() {
        let closed = || ClientError::Protocol(CLOSED.into());
        let broken = || ClientError::Io(io::ErrorKind::BrokenPipe.into());
        assert!(matches!(after_connect(closed(), true), ClientError::Busy));
        assert!(matches!(after_connect(broken(), true), ClientError::Busy));
        assert!(matches!(
            after_connect(closed(), false),
            ClientError::Protocol(m) if m == CLOSED
        ));
        assert!(matches!(
            after_connect(broken(), false),
            ClientError::Io(e) if e.kind() == io::ErrorKind::BrokenPipe
        ));
        // A reply that does not parse is not a lost reply.
        assert!(matches!(
            after_connect(ClientError::Protocol("bad json".into()), true),
            ClientError::Protocol(_)
        ));
    }

    /// A pipe whose descriptor names only SYSTEM: this very (full-token) user is denied.
    #[cfg(windows)]
    #[test]
    fn the_owner_never_turns_guest() {
        use interprocess::os::windows::{
            local_socket::ListenerOptionsExt, security_descriptor::SecurityDescriptor,
        };
        let _own = SPAWN_VS_PIPES.lock().unwrap_or_else(|e| e.into_inner());
        let name = format!("sync_gate-client-deny-{}", std::process::id());
        let sd = SecurityDescriptor::deserialize(
            &widestring::U16CString::from_str("D:P(A;;GA;;;S-1-5-18)").unwrap(),
        )
        .unwrap();
        let _l = ListenerOptions::new()
            .name(sync_gate_core::ipc_name::to_name(&name).unwrap())
            .security_descriptor(sd)
            .create_sync()
            .unwrap();
        let reply = call_checked(&name, &Request::Status, server_is_ours, DEADLINE);
        assert!(matches!(reply, Err(ClientError::DaemonDown)), "{reply:?}");
        // The test process is the account the environment names: not a guest.
        let e = sync_gate_core::ipc_name::connect_guest(&name).unwrap_err();
        assert_eq!(guest_outcome(&e), GuestOutcome::Denied, "{e}");
    }

    #[test]
    fn a_thread_the_os_refuses_is_an_error_value_not_a_panic() {
        let refuse = |_job: Box<dyn FnOnce() + Send>| Err(io::Error::other("no threads"));
        let reply = call_spawned(
            "sync_gate-unused",
            &Request::Status,
            server_is_ours,
            DEADLINE,
            refuse,
        );
        let Err(ClientError::Io(e)) = reply else {
            panic!("expected an io error");
        };
        assert!(e.to_string().contains("cannot start a thread"), "{e}");
    }
}
