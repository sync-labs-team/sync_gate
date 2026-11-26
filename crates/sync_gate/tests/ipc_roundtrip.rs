use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};
use sync_gate::client::{ClientError, call_at};
use sync_gate_core::{MachineSnapshot, Request, Response, StatusReport};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// Unique socket name per test: pipe name on Windows, temp-dir path on Unix.
fn test_name() -> String {
    let id = format!(
        "sync_gate-test-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    );
    if cfg!(windows) {
        id
    } else {
        std::env::temp_dir()
            .join(format!("{id}.sock"))
            .to_string_lossy()
            .into_owned()
    }
}

fn report() -> StatusReport {
    StatusReport {
        snapshot: MachineSnapshot {
            total: 16,
            available: 8,
            reclaimable: 0,
            swap_used: 0,
            swap_total: 0,
            vram: None,
        },
        running: vec![(1, "cargo build".into(), 10)],
        queued: vec![],
        paused: vec![],
        decisions: vec!["ok".into()],
        mcp: vec![],
        daemon: sync_gate_core::DaemonInfo::default(),
        services: vec![],
    }
}

#[test]
fn status_roundtrip_through_the_socket() {
    let name = test_name();
    let expected = report();
    let r = expected.clone();
    let server = sync_gated::ipc::serve(&name, move |req| match req {
        Request::Status => Response::Status(r.clone()),
        _ => Response::Ack,
    })
    .unwrap();
    assert_eq!(
        call_at(&name, &Request::Status).unwrap(),
        Response::Status(expected)
    );
    assert_eq!(
        call_at(&name, &Request::Cancel { id: 1 }).unwrap(),
        Response::Ack
    );
    server.shutdown();
}

#[test]
fn no_server_means_daemon_down_fast() {
    let t = Instant::now();
    let r = call_at(&test_name(), &Request::Status);
    assert!(matches!(r, Err(ClientError::DaemonDown)), "{r:?}");
    assert!(t.elapsed() < Duration::from_secs(1));
}

#[test]
fn blocking_wait_does_not_stall_other_clients() {
    let name = test_name();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let entered_tx = std::sync::Mutex::new(entered_tx);
    let server = sync_gated::ipc::serve(&name, move |req| {
        if let Request::Wait { .. } = req {
            entered_tx.lock().unwrap().send(()).unwrap();
            std::thread::sleep(Duration::from_millis(600));
        }
        Response::Ack
    })
    .unwrap();
    let n = name.clone();
    let slow = std::thread::spawn(move || {
        call_at(
            &n,
            &Request::Wait {
                id: 1,
                timeout_secs: None,
            },
        )
        .unwrap()
    });
    // Only fire the second call once the first handler is inside its slow path.
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let t = Instant::now();
    call_at(&name, &Request::Status).unwrap();
    assert!(
        t.elapsed() < Duration::from_millis(150),
        "second client waited {:?}",
        t.elapsed()
    );
    assert!(!slow.is_finished(), "first client must still be blocked");
    slow.join().unwrap();
    server.shutdown();
}

#[test]
fn wedged_daemon_is_a_timeout_not_daemon_down() {
    let name = test_name();
    let server = sync_gated::ipc::serve(&name, |_| {
        std::thread::sleep(Duration::from_secs(5));
        Response::Ack
    })
    .unwrap();
    let t = Instant::now();
    let r = call_at(&name, &Request::Status);
    // Slow is not dead: only a failed connect means the daemon is down.
    assert!(matches!(r, Err(ClientError::Timeout)), "{r:?}");
    assert!(
        t.elapsed() < Duration::from_secs(3),
        "took {:?}",
        t.elapsed()
    );
    server.shutdown();
}

#[cfg(unix)]
#[test]
fn second_server_on_same_name_is_addr_in_use() {
    let name = test_name();
    let first = sync_gated::ipc::serve(&name, |_| Response::Ack).unwrap();
    let second = sync_gated::ipc::serve(&name, |_| Response::Ack);
    assert_eq!(
        second.err().map(|e| e.kind()),
        Some(std::io::ErrorKind::AddrInUse)
    );
    first.shutdown();
}

#[test]
fn invalid_json_gets_an_error_response() {
    use interprocess::local_socket::{Stream, prelude::*};
    use std::io::{BufRead, BufReader, Write};
    use sync_gate_core::ipc_name::to_name;
    let name = test_name();
    let server = sync_gated::ipc::serve(&name, |_| Response::Ack).unwrap();
    let ns = to_name(&name).unwrap();
    let mut conn = BufReader::new(Stream::connect(ns).unwrap());
    conn.get_mut().write_all(b"{not json\n").unwrap();
    let mut line = String::new();
    conn.read_line(&mut line).unwrap();
    assert!(matches!(
        serde_json::from_str::<Response>(&line).unwrap(),
        Response::Error { .. }
    ));
    server.shutdown();
}

#[test]
fn shutdown_returns_and_closes_the_socket() {
    let name = test_name();
    let server = sync_gated::ipc::serve(&name, |_| Response::Ack).unwrap();
    assert_eq!(call_at(&name, &Request::Status).unwrap(), Response::Ack);
    server.shutdown();
    assert!(matches!(
        call_at(&name, &Request::Status),
        Err(ClientError::DaemonDown)
    ));
}
