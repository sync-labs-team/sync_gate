//! Hub tests: a fake launcher whose children the test plays, in-memory client connections,
//! and time driven through `Hub::tick(now + ...)`.

use super::testkit::*;
use super::*;
use serde_json::json;
use std::sync::atomic::AtomicU32;
use std::sync::mpsc;
use sync_gate_hub::{GROW_WAIT, SHRINK_IDLE};

fn hub(l: &Arc<FakeLauncher>) -> Hub {
    Hub::new(&config(), l.clone(), None, None)
}

fn row<'a>(r: &'a [McpStatus], server: &str) -> &'a McpStatus {
    r.iter().find(|s| s.server == server).unwrap()
}

fn docs(hub: &Hub) -> McpStatus {
    row(&hub.report(), "docs").clone()
}

fn notes_contain(hub: &Hub, seen: &mut Vec<String>, needle: &str) -> bool {
    seen.extend(hub.take_notes());
    seen.iter().any(|n| n.contains(needle))
}

#[test]
fn ten_clients_share_one_child() {
    let l = Arc::new(FakeLauncher::default());
    let hub = hub(&l);
    let mut clients: Vec<TestClient> = (0..10)
        .map(|_| connect(&hub, hello("docs", &[("TOKEN", "t")], "/r/a")))
        .collect();
    for c in &clients {
        assert_eq!(c.reply(), HubReply::Ok);
    }
    assert_eq!(l.spawns(), 1);
    let mut child = l.take_child();
    child.handshake();
    for (i, c) in clients.iter_mut().enumerate() {
        c.send(request(7, "tools/list"));
        let seen = child.answer();
        assert_eq!(seen["method"], "tools/list");
        let reply = c.recv();
        assert_eq!(reply["id"], 7, "client {i}: {reply}");
        assert_eq!(reply["result"]["echo"], "tools/list");
    }
    let r = docs(&hub);
    assert_eq!((r.instances, r.clients, r.in_flight), (1, 10, 0));
    assert_eq!(l.spawns(), 1);
    hub.shutdown();
}

#[test]
fn different_env_from_values_get_different_children() {
    let l = Arc::new(FakeLauncher::default());
    let hub = hub(&l);
    let a = connect(&hub, hello("docs", &[("TOKEN", "a"), ("OTHER", "x")], "/r"));
    let b = connect(&hub, hello("docs", &[("TOKEN", "b")], "/r"));
    assert_eq!((a.reply(), b.reply()), (HubReply::Ok, HubReply::Ok));
    assert_eq!(l.spawns(), 2);
    let (ca, cb) = (l.take_child(), l.take_child());
    assert_eq!(ca.env.get("TOKEN").map(String::as_str), Some("a"));
    assert_eq!(cb.env.get("TOKEN").map(String::as_str), Some("b"));
    // Only the env_from names are passed on.
    assert!(!ca.env.contains_key("OTHER"));
    let shown = serde_json::to_string(&hub.report()).unwrap();
    assert!(
        !shown.contains("\"a\"") && !shown.contains("\"b\""),
        "{shown}"
    );
    assert_eq!(docs(&hub).instances, 2);
    hub.shutdown();
}

#[test]
fn a_forwarded_variable_the_session_lacks_is_removed_not_inherited() {
    let l = Arc::new(FakeLauncher::default());
    let hub = hub(&l);
    let without = connect(&hub, hello("docs", &[], "/r"));
    let with = connect(&hub, hello("docs", &[("TOKEN", "t")], "/r"));
    assert_eq!(
        (without.reply(), with.reply()),
        (HubReply::Ok, HubReply::Ok)
    );
    let (a, b) = (l.take_child(), l.take_child());
    // Without it the child must not get the daemon's own TOKEN.
    assert!(!a.env.contains_key("TOKEN"));
    assert_eq!(a.env_remove, ["TOKEN"]);
    assert_eq!(b.env.get("TOKEN").map(String::as_str), Some("t"));
    assert!(b.env_remove.is_empty(), "{:?}", b.env_remove);
    hub.shutdown();
}

#[test]
fn inherit_cwd_splits_by_directory() {
    let l = Arc::new(FakeLauncher::default());
    let hub = hub(&l);
    let a1 = connect(&hub, hello("files", &[], "/r/a"));
    let b = connect(&hub, hello("files", &[], "/r/b"));
    let a2 = connect(&hub, hello("files", &[], "/r/a"));
    for c in [&a1, &b, &a2] {
        assert_eq!(c.reply(), HubReply::Ok);
    }
    assert_eq!(l.spawns(), 2);
    let children = [l.take_child(), l.take_child()];
    let cwds: Vec<_> = children.iter().map(|c| c.cwd.clone().unwrap()).collect();
    assert_eq!(cwds, [abs_dir("/r/a"), abs_dir("/r/b")]);
    let r = row(&hub.report(), "files").clone();
    assert_eq!((r.instances, r.clients), (2, 3));
    // `docs` does not inherit: the cwd plays no part in its key.
    let d1 = connect(&hub, hello("docs", &[], "/r/a"));
    let d2 = connect(&hub, hello("docs", &[], "/r/b"));
    assert_eq!((d1.reply(), d2.reply()), (HubReply::Ok, HubReply::Ok));
    assert_eq!(l.spawns(), 3);
    hub.shutdown();
}

// #2 item 20: a relay that could not read its folder sends an empty one; a relative folder
// would be read from the daemon's, so an `inherit` server runs in that session instead.
#[test]
fn a_relative_hello_cwd_runs_an_inherit_server_per_session() {
    let l = Arc::new(FakeLauncher::default());
    let hub = hub(&l);
    // `\x` has a root but no drive: on Windows it names the daemon's drive, not the session's.
    for cwd in ["", "rel/a", r"\rel"] {
        let c = connect(&hub, hello("files", &[], cwd));
        assert_eq!(c.reply(), HubReply::PerSession, "{cwd:?}");
    }
    assert_eq!(l.spawns(), 0);
    assert!(notes_contain(
        &hub,
        &mut Vec::new(),
        "files: the session sent no absolute folder"
    ));
    // A server that does not inherit ignores the folder.
    let d = connect(&hub, hello("docs", &[], ""));
    assert_eq!(d.reply(), HubReply::Ok);
    hub.shutdown();
}

#[test]
fn child_crash_restarts_and_clients_keep_working() {
    let l = Arc::new(FakeLauncher::default());
    let hub = hub(&l);
    let mut c = connect(&hub, hello("docs", &[], "/r"));
    assert_eq!(c.reply(), HubReply::Ok);
    let mut child = l.take_child();
    child.handshake();
    c.send(request(1, "tools/call"));
    assert_eq!(child.next()["method"], "tools/call");
    // The hub records the crash at or after this instant.
    let before_crash = Instant::now();
    l.kill(&mut child);
    // The request in flight fails; the client stays connected.
    let failed = c.recv();
    assert_eq!(failed["id"], 1);
    assert_eq!(failed["error"]["code"], -32000);
    wait_until("the crash to be seen", || docs(&hub).instances == 0);
    let after_crash = Instant::now();
    // A new request waits for the next child. The ticks are relative to the crash bounds, not
    // to real elapsed time: the backoff is 1 s, so +500 ms is always early and +2 s always late.
    c.send(request(2, "tools/list"));
    hub.tick(before_crash + Duration::from_millis(500));
    assert_eq!(l.spawns(), 1, "restarted before the backoff");
    hub.tick(after_crash + Duration::from_secs(2));
    assert_eq!(l.spawns(), 2);
    let mut child = l.take_child();
    child.handshake();
    child.answer();
    let reply = c.recv();
    assert_eq!(reply["id"], 2);
    assert_eq!(reply["result"]["echo"], "tools/list");
    let r = docs(&hub);
    assert_eq!((r.instances, r.clients, r.restarts), (1, 1, 1));
    let notes = hub.take_notes();
    assert!(
        notes
            .iter()
            .any(|n| n == "mcp docs: restarted (child exited, code unknown)"),
        "{notes:?}"
    );
    // The dead child went through the supervisor.
    assert!(l.calls().contains(&"reap 100".to_string()));
    hub.shutdown();
}

/// Crashes `docs` five times in a row: the instance ends in its crash-loop pause (5 spawns).
fn enter_crash_loop(l: &FakeLauncher, hub: &Hub) {
    for n in 1..=5 {
        let mut child = l.take_child();
        l.kill(&mut child);
        wait_until("the crash to be seen", || docs(hub).instances == 0);
        hub.tick(Instant::now() + Duration::from_secs(60));
        let expected = if n < 5 { n + 1 } else { 5 };
        assert_eq!(l.spawns(), expected, "after crash {n}");
    }
}

#[test]
fn crash_loop_disconnects_every_client_and_refuses_hellos_during_the_pause() {
    let l = Arc::new(FakeLauncher::default());
    let hub = hub(&l);
    let mut a = connect(&hub, hello("docs", &[], "/r"));
    let b = connect(&hub, hello("docs", &[], "/r"));
    assert_eq!((a.reply(), b.reply()), (HubReply::Ok, HubReply::Ok));
    // Waits in the mux (the children never get ready): nobody may answer it.
    a.send(request(9, "tools/list"));
    enter_crash_loop(&l, &hub);
    for c in [&a, &b] {
        wait_until("the client to be disconnected", || {
            c.closed.load(Ordering::SeqCst)
        });
        assert_eq!(c.rest(), Vec::<String>::new());
    }
    let mut seen = Vec::new();
    let note = "mcp docs: unavailable through the hub (keeps crashing); sessions run it directly";
    assert!(notes_contain(&hub, &mut seen, note), "{seen:?}");
    assert_eq!(count_notes(&seen, "unavailable through the hub"), 1);
    // During the pause: refused, and nothing is started.
    hub.tick(Instant::now() + Duration::from_secs(120));
    let late = connect(&hub, hello("docs", &[], "/r"));
    assert_eq!(late.reply(), unavailable());
    assert_eq!(l.spawns(), 5, "a 6th spawn inside the crash-loop pause");
    // After the pause, the next hello starts a child on demand.
    hub.tick(Instant::now() + CRASH_PAUSE + Duration::from_secs(1));
    assert_eq!(l.spawns(), 5, "restarted with nobody to serve");
    let again = connect(&hub, hello("docs", &[], "/r"));
    assert_eq!(again.reply(), HubReply::Ok);
    assert_eq!(l.spawns(), 6);
    hub.shutdown();
}

fn unavailable() -> HubReply {
    HubReply::Error {
        message: "server unavailable through the hub".into(),
    }
}

#[test]
fn idle_retirement_waits_for_the_crash_loop_pause() {
    let l = Arc::new(FakeLauncher::default());
    let hub = hub(&l);
    let c = connect(&hub, hello("docs", &[], "/r"));
    assert_eq!(c.reply(), HubReply::Ok);
    enter_crash_loop(&l, &hub);
    wait_until("the client to leave", || docs(&hub).clients == 0);
    // idle_stop_secs is 10: well past it, but the pause (300 s) has not ended.
    hub.tick(Instant::now() + Duration::from_secs(60));
    assert_eq!(
        lock(&hub.inner.map).instances.len(),
        1,
        "retired in the pause"
    );
    let c2 = connect(&hub, hello("docs", &[], "/r"));
    assert_eq!(c2.reply(), unavailable(), "the pause was skipped");
    assert_eq!(l.spawns(), 5);
    hub.shutdown();
}

#[test]
fn idle_child_is_stopped_after_idle_stop_secs() {
    let l = Arc::new(FakeLauncher::default());
    let hub = hub(&l);
    let mut c = connect(&hub, hello("docs", &[], "/r"));
    assert_eq!(c.reply(), HubReply::Ok);
    let _child = l.take_child();
    c.hang_up();
    wait_until("the client to leave", || docs(&hub).clients == 0);
    hub.tick(Instant::now() + Duration::from_secs(5));
    assert_eq!(docs(&hub).instances, 1, "stopped before idle_stop_secs");
    hub.tick(Instant::now() + Duration::from_secs(11));
    assert_eq!(docs(&hub).instances, 0);
    // stop_own: stdin closed, the child exited on EOF, so it is reaped and never terminated.
    wait_until("stop_own", || l.calls().contains(&"reap 100".to_string()));
    assert!(!l.calls().iter().any(|c| c.starts_with("terminate")));
    // The next client starts a new one on demand.
    let c2 = connect(&hub, hello("docs", &[], "/r"));
    assert_eq!(c2.reply(), HubReply::Ok);
    assert_eq!(l.spawns(), 2);
    hub.shutdown();
}

#[test]
fn per_session_and_unknown_are_not_spawned_by_the_daemon() {
    let l = Arc::new(FakeLauncher::default());
    let hub = hub(&l);
    let p = connect(&hub, hello("browser", &[], "/r"));
    assert_eq!(p.reply(), HubReply::PerSession);
    let u = connect(&hub, hello("nope", &[], "/r"));
    assert_eq!(u.reply(), HubReply::Unknown);
    // The tick closes a refused connection after its grace, never the reply thread.
    hub.tick(Instant::now() + 2 * REFUSAL_GRACE);
    wait_until("the refusals to be closed", || {
        p.closed.load(Ordering::SeqCst) && u.closed.load(Ordering::SeqCst)
    });
    assert!(p.closed.load(Ordering::SeqCst) && u.closed.load(Ordering::SeqCst));
    assert_eq!(l.spawns(), 0);
    assert!(
        hub.report()
            .iter()
            .all(|r| r.instances == 0 && r.clients == 0)
    );
}

#[test]
fn slow_client_is_disconnected_without_stalling_others() {
    let l = Arc::new(FakeLauncher::default());
    let hub = hub(&l);
    let mut fast = connect(&hub, hello("docs", &[], "/r"));
    let mut slow = connect_stuck(&hub, hello("docs", &[], "/r"));
    assert_eq!(fast.reply(), HubReply::Ok);
    let mut child = l.take_child();
    child.handshake();
    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
    fast.send(init.clone());
    slow.send(init);
    assert_eq!(fast.recv()["id"], 1);
    // The slow client's pipe fills only while its `initialize` reply is being written: from then
    // on the mux counts it as handshaken, so every broadcast below is queued for it.
    wait_until("the slow client's handshake", || {
        slow.unread() == STUCK_PIPE_BYTES
    });
    // Broadcasts reach every handshaken client; the slow one never reads.
    let changed = json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"});
    let batch = 50;
    let mut sent = 0;
    while !slow.closed.load(Ordering::SeqCst) {
        assert!(
            sent < 4 * CLIENT_QUEUE_MESSAGES,
            "slow client never disconnected"
        );
        for _ in 0..batch {
            child.send(changed.clone());
        }
        for _ in 0..batch {
            assert_eq!(fast.recv()["method"], "notifications/tools/list_changed");
        }
        sent += batch;
    }
    wait_until("the slow client to be detached", || docs(&hub).clients == 1);
    // The fast client and the child still work.
    fast.send(request(2, "tools/list"));
    child.answer();
    assert_eq!(fast.recv()["id"], 2);
    let mut seen = Vec::new();
    assert!(notes_contain(
        &hub,
        &mut seen,
        "client disconnected (output queue full)"
    ));
    hub.shutdown();
}

/// Review F08 (r5): the hub stops a child and forgets its registry row by the launch id the
/// launcher gave it (the fake answers only to that id).
#[test]
fn a_stopped_child_leaves_no_registry_row() {
    let dir = std::env::temp_dir().join(format!("sync_gate_hub-row-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let l = Arc::new(FakeLauncher::default());
    let hub = Hub::new(&config(), l.clone(), Some(&dir), None);
    let mut c = connect(&hub, hello("docs", &[], "/r"));
    assert_eq!(c.reply(), HubReply::Ok);
    let _child = l.take_child();
    let rows = || crate::store::load_services(&dir.join("services.json")).len();
    assert_eq!(rows(), 1);
    c.hang_up();
    wait_until("the client to leave", || docs(&hub).clients == 0);
    hub.tick(Instant::now() + Duration::from_secs(11));
    wait_until("stop_own", || l.calls().contains(&"reap 100".to_string()));
    wait_until("the row to go", || rows() == 0);
    hub.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn env_from_secret_never_leaves_memory() {
    const CANARY: &str = "canary-5f3c9e1d-secret";
    let dir = std::env::temp_dir().join(format!("sync_gate_hub-canary-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let l = Arc::new(FakeLauncher::default());
    let hub = Hub::new(&config(), l.clone(), Some(&dir), None);
    let mut c = connect(&hub, hello("docs", &[("TOKEN", CANARY)], "/r"));
    assert_eq!(c.reply(), HubReply::Ok);
    let mut child = l.take_child();
    // The secret does reach the child...
    assert_eq!(child.env.get("TOKEN").map(String::as_str), Some(CANARY));
    // ...and nothing else: crash, restart, failure notes, status, the registry file.
    child.handshake();
    c.send(request(1, "tools/call"));
    child.next();
    l.kill(&mut child);
    c.recv();
    wait_until("the crash to be seen", || docs(&hub).instances == 0);
    hub.tick(Instant::now() + Duration::from_secs(2));
    let mut child = l.take_child();
    let bad = json!({"jsonrpc": "2.0", "id": child.next()["id"], "result": {"supportedVersions": ["1999-01-01"]}});
    child.send(bad);
    let mut notes = Vec::new();
    wait_until("the unsupported note", || {
        notes_contain(&hub, &mut notes, "no supported protocol version")
    });
    let registry = std::fs::read_to_string(dir.join("services.json")).unwrap_or_default();
    let report = serde_json::to_string(&hub.report()).unwrap();
    let seen = format!("{notes:?}{registry}{report}");
    assert!(!seen.contains(CANARY), "{seen}");
    assert!(seen.contains("docs"), "{seen}");
    hub.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unsupported_child_is_stopped_and_the_server_is_unavailable_until_its_retry() {
    let l = Arc::new(FakeLauncher::default());
    let hub = hub(&l);
    let c = connect(&hub, hello("docs", &[], "/r"));
    assert_eq!(c.reply(), HubReply::Ok);
    let mut child = l.take_child();
    let probe = child.next();
    child.send(json!({"jsonrpc": "2.0", "id": probe["id"], "result": {"supportedVersions": ["2099-01-01"]}}));
    let mut notes = Vec::new();
    wait_until("the decision", || {
        notes_contain(
            &hub,
            &mut notes,
            "mcp docs: no supported protocol version; not restarting for 10 min",
        )
    });
    assert!(notes_contain(
        &hub,
        &mut notes,
        "mcp docs: unavailable through the hub (unsupported protocol version); sessions run it directly"
    ));
    wait_until("stop_own", || l.calls().contains(&"reap 100".to_string()));
    assert_eq!(docs(&hub).instances, 0);
    // The client was disconnected, without an answer.
    wait_until("the client to be disconnected", || {
        c.closed.load(Ordering::SeqCst)
    });
    assert_eq!(c.rest(), Vec::<String>::new());
    // Long after the crash-loop pause and the idle stop, but before the retry: still refused.
    let until = unsupported_until(&hub, 0);
    hub.tick(Instant::now() + CRASH_PAUSE + Duration::from_secs(1));
    hub.tick(until - Duration::from_secs(1));
    let c2 = connect(&hub, hello("docs", &[], "/r"));
    assert_eq!(c2.reply(), unavailable());
    assert_eq!(l.spawns(), 1, "an unsupported server was restarted");
    hub.shutdown();
}

fn initialize_request(id: u64) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "initialize", "params": {}})
}

#[test]
fn an_unsupported_first_child_answers_no_queued_initialize() {
    let l = Arc::new(FakeLauncher::default());
    let hub = hub(&l);
    let mut c = connect_draining(&hub, hello("docs", &[], "/r"));
    assert_eq!(c.reply(), HubReply::Ok);
    let mut child = l.take_child();
    let probe = child.next();
    // The reader handles lines in order: this parse error proves initialize is queued.
    c.send(initialize_request(0));
    c.send_raw("{");
    assert_eq!(
        c.recv(),
        json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "parse error"}})
    );
    child.send(json!({"jsonrpc": "2.0", "id": probe["id"], "result": {"supportedVersions": ["2099-01-01"]}}));
    wait_until("the client to be disconnected", || {
        c.closed.load(Ordering::SeqCst)
    });
    // Nothing after the barrier reply: the relay replays initialize on its own server.
    assert_eq!(c.rest(), Vec::<String>::new());
    hub.shutdown();
}

#[test]
fn the_fifth_failed_initialize_answers_no_queued_initialize() {
    let l = Arc::new(FakeLauncher::default());
    let hub = hub(&l);
    let mut c = connect_draining(&hub, hello("docs", &[], "/r"));
    assert_eq!(c.reply(), HubReply::Ok);
    for n in 1..=4 {
        let mut child = l.take_child();
        time_out_initialize(&hub, &mut child);
        hub.tick(Instant::now() + Duration::from_secs(340));
        assert_eq!(l.spawns(), n + 1, "after failure {n}");
    }
    let mut child = l.take_child();
    // The reader handles lines in order: this parse error proves initialize is queued.
    c.send(initialize_request(0));
    c.send_raw("{");
    assert_eq!(
        c.recv(),
        json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "parse error"}})
    );
    time_out_initialize(&hub, &mut child);
    wait_until("the client to be disconnected", || {
        c.closed.load(Ordering::SeqCst)
    });
    assert_eq!(c.rest(), Vec::<String>::new());
    let mut notes = Vec::new();
    assert!(notes_contain(
        &hub,
        &mut notes,
        "mcp docs: unavailable through the hub (keeps crashing)"
    ));
    hub.shutdown();
}

#[test]
fn no_child_is_spawned_once_the_hub_was_told_to_stop() {
    let l = Arc::new(FakeLauncher::default());
    let hub = hub(&l);
    let c = connect(&hub, hello("docs", &[], "/r"));
    assert_eq!(c.reply(), HubReply::Ok);
    let mut child = l.take_child();
    l.kill(&mut child);
    wait_until("the crash to be seen", || docs(&hub).instances == 0);
    // A tick in progress turned the unit `Starting`; shutdown arrives before its spawn.
    let inst = lock(&hub.inner.map)
        .instances
        .values()
        .next()
        .unwrap()
        .clone();
    lock(&inst.st).units[0].child = Child::Starting;
    hub.shutdown();
    hub.inner.start_child(&inst, 0);
    assert_eq!(l.spawns(), 1, "a child was spawned after the stop");
}

#[test]
fn a_spawn_error_disconnects_at_once_and_refuses_hellos_until_the_pause_ends() {
    let l = Arc::new(FakeLauncher::default());
    l.fail_spawns.store(1, Ordering::SeqCst);
    let hub = hub(&l);
    // `attach` tried the spawn before returning: no wait for the request timeout.
    let c = connect(&hub, hello("docs", &[], "/r"));
    assert!(c.closed.load(Ordering::SeqCst), "the client was kept");
    let mut notes = Vec::new();
    assert!(notes_contain(
        &hub,
        &mut notes,
        "mcp docs: unavailable through the hub (cannot start); sessions run it directly"
    ));
    let refused = connect(&hub, hello("docs", &[], "/r"));
    assert_eq!(refused.reply(), unavailable());
    // Never retried in a tight loop: nothing is started before the pause ends.
    hub.tick(Instant::now() + Duration::from_secs(60));
    assert_eq!(
        connect(&hub, hello("docs", &[], "/r")).reply(),
        unavailable()
    );
    assert_eq!(l.spawns(), 0);
    assert_eq!(l.calls(), ["spawn failed"]);
    hub.tick(Instant::now() + CRASH_PAUSE + Duration::from_secs(1));
    let ok = connect(&hub, hello("docs", &[], "/r"));
    assert_eq!(ok.reply(), HubReply::Ok);
    assert_eq!(l.spawns(), 1);
    let _child = l.take_child();
    hub.shutdown();
}

/// Not a modern server: the hub sends `initialize`, which the child never answers; the request
/// timeout (300 s) gives it up.
fn time_out_initialize(hub: &Hub, child: &mut FakeChild) {
    refuse_probe_then_initialize(child);
    hub.tick(Instant::now() + Duration::from_secs(301));
}

/// A child that never answers `initialize` is restarted through the backoff (one that rejects
/// it makes the key run directly: `a_server_that_rejects_initialize_falls_back_to_direct`).
#[test]
fn failed_child_is_restarted() {
    let l = Arc::new(FakeLauncher::default());
    let hub = hub(&l);
    let c = connect(&hub, hello("docs", &[], "/r"));
    assert_eq!(c.reply(), HubReply::Ok);
    let mut child = l.take_child();
    time_out_initialize(&hub, &mut child);
    wait_until("stop_own", || l.calls().contains(&"reap 100".to_string()));
    hub.tick(Instant::now() + Duration::from_secs(340));
    assert_eq!(l.spawns(), 2);
    let mut child = l.take_child();
    child.handshake();
    let r = docs(&hub);
    assert_eq!((r.instances, r.restarts), (1, 1));
    let mut notes = Vec::new();
    assert!(notes_contain(
        &hub,
        &mut notes,
        "mcp docs: restarted (initialize failed, code unknown)"
    ));
    assert!(notes_contain(
        &hub,
        &mut notes,
        "mcp docs: child did not answer initialize in time"
    ));
    hub.shutdown();
}

#[test]
fn hub_shutdown_returns_with_a_client_and_a_child_that_ignores_eof() {
    let l = Arc::new(FakeLauncher::default());
    l.ignore_eof.store(true, Ordering::SeqCst);
    let hub = Hub::new(&config(), l.clone(), None, None).with_stop_grace(Duration::from_millis(50));
    let c = connect(&hub, hello("docs", &[], "/r"));
    assert_eq!(c.reply(), HubReply::Ok);
    let _child = l.take_child();
    let t0 = Instant::now();
    hub.shutdown();
    assert!(t0.elapsed() < Duration::from_secs(3), "{:?}", t0.elapsed());
    let calls = l.calls();
    assert!(calls.contains(&"terminate 100".to_string()), "{calls:?}");
    assert!(calls.contains(&"reap 100".to_string()), "{calls:?}");
    assert!(c.closed.load(Ordering::SeqCst));
    // No new clients after shutdown.
    let late = connect(&hub, hello("docs", &[], "/r"));
    assert!(late.closed.load(Ordering::SeqCst));
    assert_eq!(l.spawns(), 1);
}

#[test]
fn shutdown_gives_a_child_five_seconds_after_stdin_closes() {
    let l = Arc::new(FakeLauncher::default());
    l.ignore_eof.store(true, Ordering::SeqCst);
    let hub = hub(&l);
    let c = connect(&hub, hello("docs", &[], "/r"));
    assert_eq!(c.reply(), HubReply::Ok);
    let mut child = l.take_child();
    // The child needs 3 s after its stdin closes to flush and exit on its own.
    let exits = {
        let l = l.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(3));
            l.kill(&mut child);
        })
    };
    let t0 = Instant::now();
    hub.shutdown();
    assert!(t0.elapsed() < STOP_GRACE + STOP_SLACK, "{:?}", t0.elapsed());
    exits.join().unwrap();
    let calls = l.calls();
    assert!(!calls.contains(&"terminate 100".to_string()), "{calls:?}");
    assert!(calls.contains(&"reap 100".to_string()), "{calls:?}");
}

#[test]
fn bad_or_missing_hello_is_refused() {
    let l = Arc::new(FakeLauncher::default());
    let hub = Arc::new(hub(&l));
    let mut garbage = raw_conn(hub.clone());
    garbage.send(json!({"server": 1}));
    assert!(matches!(garbage.reply(), HubReply::Error { .. }));
    hub.tick(Instant::now() + 2 * REFUSAL_GRACE);
    wait_until("the bad connection to close", || {
        garbage.closed.load(Ordering::SeqCst)
    });
    // A connection that never says hello is closed by the tick after the deadline.
    let silent = raw_conn(hub.clone());
    wait_until("the connection to register", || {
        !lock(&hub.inner.map).hellos.is_empty()
    });
    hub.tick(Instant::now() + Duration::from_secs(1));
    assert!(!silent.closed.load(Ordering::SeqCst));
    hub.tick(Instant::now() + HELLO_DEADLINE + Duration::from_secs(1));
    assert_eq!(
        silent.reply(),
        HubReply::Error {
            message: "hello timed out".into()
        }
    );
    hub.tick(Instant::now() + HELLO_DEADLINE + 2 * REFUSAL_GRACE);
    wait_until("the silent connection to close", || {
        silent.closed.load(Ordering::SeqCst)
    });
    // A good hello over the same path works.
    let mut good = raw_conn(hub.clone());
    good.send(serde_json::to_value(hello("docs", &[], "/r")).unwrap());
    assert_eq!(good.reply(), HubReply::Ok);
    // The reply is written before `attach` starts the child: wait for the spawn.
    wait_until("the child to start", || l.spawns() == 1);
    hub.shutdown();
}

#[test]
fn oversized_client_line_gets_a_parse_error_and_the_stream_stays_in_sync() {
    let l = Arc::new(FakeLauncher::default());
    let hub = hub(&l);
    let mut c = connect(&hub, hello("docs", &[], "/r"));
    assert_eq!(c.reply(), HubReply::Ok);
    let mut child = l.take_child();
    child.handshake();
    let big = "x".repeat(MAX_MESSAGE_BYTES + 1);
    c.send(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"a": big}}));
    let reply = c.recv();
    assert_eq!(reply["error"]["code"], -32700);
    assert_eq!(reply["id"], Value::Null);
    c.send(request(2, "tools/list"));
    child.answer();
    assert_eq!(c.recv()["id"], 2);
    hub.shutdown();
}

#[test]
fn read_line_caps_and_resyncs() {
    let input = b"short\nwaytoolongline\nok\nlast".to_vec();
    let mut r = BufReader::with_capacity(4, &input[..]);
    let mut buf = Vec::new();
    let mut got = Vec::new();
    loop {
        match read_line(&mut r, 6, &mut buf).unwrap() {
            Line::Eof => break,
            Line::TooLong => got.push("<too long>".to_string()),
            Line::Data => got.push(String::from_utf8(buf.clone()).unwrap()),
        }
    }
    assert_eq!(got, ["short", "<too long>", "ok", "last"]);
}

#[test]
fn hello_after_shutdown_is_closed_not_left_waiting() {
    let l = Arc::new(FakeLauncher::default());
    let hub = Arc::new(hub(&l));
    hub.shutdown();
    // Accepted just before the listener stopped, its thread ran after the hellos were drained.
    let late = raw_conn(hub.clone());
    wait_until("the late connection to close", || {
        late.closed.load(Ordering::SeqCst)
    });
    assert!(lock(&hub.inner.map).hellos.is_empty());
}

#[test]
fn a_refusal_after_shutdown_closes_without_writing_or_registering() {
    struct Unwritten(Arc<AtomicUsize>, Arc<AtomicBool>, mpsc::Sender<()>);
    impl Write for Unwritten {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.fetch_add(buf.len(), Ordering::SeqCst);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl Drop for Unwritten {
        fn drop(&mut self) {
            assert!(self.1.load(Ordering::SeqCst), "writer dropped before close");
            let _ = self.2.send(());
        }
    }
    let l = Arc::new(FakeLauncher::default());
    let hub = hub(&l);
    hub.shutdown();
    let bytes = Arc::new(AtomicUsize::new(0));
    let closed = Arc::new(AtomicBool::new(false));
    let flag = closed.clone();
    let (tx, rx) = mpsc::channel();
    hub.serve_conn(
        Box::new(io::empty()),
        Box::new(Unwritten(bytes.clone(), closed.clone(), tx)),
        Arc::new(move || flag.store(true, Ordering::SeqCst)),
    );
    assert!(lock(&hub.inner.map).closing.is_empty(), "orphaned refusal");
    ended(&rx, "the stopped refusal writer");
    assert!(closed.load(Ordering::SeqCst));
    assert_eq!(bytes.load(Ordering::SeqCst), 0, "wrote after shutdown");
}

/// `[[[...]]]` nested `n` levels.
fn nested(n: usize) -> String {
    format!("{}{}", "[".repeat(n), "]".repeat(n))
}

/// A request whose params nest `arrays` levels (the object adds one).
fn deep_request(id: u64, arrays: usize) -> String {
    let params = nested(arrays);
    format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{params}}}"#)
}

/// Replies until one with `id` arrives (a parse error for a refused line may come first).
fn recv_id(c: &TestClient, id: impl Into<Value>) -> Value {
    let id = id.into();
    loop {
        let v = c.recv();
        if v["id"] == id {
            return v;
        }
    }
}

/// The deepest line the hub takes: the object plus this many arrays is `MAX_JSON_DEPTH`.
const DEEPEST_OK: usize = MAX_JSON_DEPTH - 1;
/// The deepest line serde_json would still parse (128 levels): the hub refuses it, not aborts.
const SERDE_DEEPEST: usize = 126;

#[test]
fn deepest_valid_json_through_the_client_and_child_reader_threads() {
    let l = Arc::new(FakeLauncher::default());
    let hub = hub(&l);
    let mut c = connect(&hub, hello("docs", &[], "/r"));
    assert_eq!(c.reply(), HubReply::Ok);
    let mut child = l.take_child();
    child.handshake();
    // Client reader thread: parse + forward to the child.
    c.send_raw(&deep_request(1, DEEPEST_OK));
    let seen = child.next();
    assert_eq!(seen["method"], "tools/call");
    // Child reader thread: parse + forward the deep result back.
    let result = nested(DEEPEST_OK);
    child.send_raw(&format!(
        r#"{{"jsonrpc":"2.0","id":{},"result":{result}}}"#,
        seen["id"]
    ));
    assert_eq!(recv_id(&c, 1)["id"], 1);
    // Over the hub's limit (serde's own, and beyond it): the invalid-line path, and the
    // connection keeps working.
    c.send_raw(&deep_request(2, SERDE_DEEPEST));
    assert_eq!(
        recv_id(&c, serde_json::Value::Null)["error"]["code"],
        -32700
    );
    c.send_raw(&deep_request(2, 300));
    c.send(request(3, "tools/list"));
    child.answer();
    assert_eq!(recv_id(&c, 3)["result"]["echo"], "tools/list");
    for depth in [SERDE_DEEPEST, 300] {
        child.send_raw(&format!(
            r#"{{"jsonrpc":"2.0","method":"x","params":{}}}"#,
            nested(depth)
        ));
    }
    c.send(request(4, "tools/list"));
    child.answer();
    assert_eq!(recv_id(&c, 4)["result"]["echo"], "tools/list");
    hub.shutdown();
}

#[test]
fn deep_json_in_the_hello_on_the_connection_thread() {
    let l = Arc::new(FakeLauncher::default());
    let hub = Arc::new(hub(&l));
    // The hello on the real connection thread (`serve_stream`'s own stack).
    let name = socket_name("hub-deep-hello");
    let h2 = hub.clone();
    let server =
        crate::ipc::serve_stream(&name, move |r, w, close| h2.serve_conn(r, w, close)).unwrap();
    for depth in [DEEPEST_OK, SERDE_DEEPEST, 300] {
        let mut peer = Wire(Arc::new(connect_raw(&name)));
        writeln!(
            peer,
            r#"{{"server":"docs","cwd":"/r","env":{{}},"client":"t","x":{}}}"#,
            nested(depth)
        )
        .unwrap();
        let rx = lines(Wire(peer.0.clone()));
        recv_json(&rx, "the hello reply");
    }
    hub.shutdown();
    assert!(server.stop_within(Duration::from_secs(5)));
}

/// A name for a real local socket (a path on Unix, a pipe name on Windows).
fn socket_name(tag: &str) -> String {
    let tag = format!("sync_gate-test-{}-{tag}", std::process::id());
    if cfg!(windows) {
        tag
    } else {
        std::env::temp_dir()
            .join(tag)
            .to_string_lossy()
            .into_owned()
    }
}

/// A real socket stream as `Read`/`Write` halves.
struct Wire(Arc<interprocess::local_socket::Stream>);

impl Read for Wire {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&*self.0).read(buf)
    }
}

impl Write for Wire {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&*self.0).write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        (&*self.0).flush()
    }
}

/// Dials the hub socket and sends the docs hello.
fn dial(name: &str) -> Wire {
    use interprocess::local_socket::{Stream, traits::Stream as _};
    let s = Stream::connect(sync_gate_core::ipc_name::to_name(name).unwrap()).unwrap();
    let mut w = Wire(Arc::new(s));
    let line = serde_json::to_string(&hello("docs", &[], "/r")).unwrap();
    writeln!(w, "{line}").unwrap();
    w
}

#[test]
fn slow_client_on_a_real_socket_is_disconnected_and_the_fast_one_keeps_working() {
    let l = Arc::new(FakeLauncher::default());
    let hub = Arc::new(hub(&l));
    let name = socket_name("hub-slow");
    let h2 = hub.clone();
    let server =
        crate::ipc::serve_stream(&name, move |r, w, close| h2.serve_conn(r, w, close)).unwrap();
    let mut fast = dial(&name);
    let fast_rx = lines(Wire(fast.0.clone()));
    assert_eq!(
        serde_json::from_value::<HubReply>(recv_json(&fast_rx, "fast hello reply")).unwrap(),
        HubReply::Ok
    );
    // The slow client says hello and initializes, then never reads again.
    let mut slow = dial(&name);
    let mut child = l.take_child();
    child.handshake();
    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
    writeln!(fast, "{init}").unwrap();
    writeln!(slow, "{init}").unwrap();
    assert_eq!(recv_json(&fast_rx, "fast initialize reply")["id"], 1);
    wait_until("both clients attached", || docs(&hub).clients == 2);
    let pad = "x".repeat(32 * 1024);
    let changed = json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed", "params": {"pad": pad}});
    let mut sent = 0;
    while docs(&hub).clients == 2 {
        assert!(sent < 1000, "slow client never disconnected");
        child.send(changed.clone());
        let got = recv_json(&fast_rx, "fast broadcast");
        assert_eq!(got["method"], "notifications/tools/list_changed");
        sent += 1;
    }
    writeln!(fast, "{}", request(2, "tools/list")).unwrap();
    child.answer();
    assert_eq!(recv_json(&fast_rx, "fast reply")["id"], 2);
    hub.shutdown();
    assert!(server.stop_within(Duration::from_secs(5)));
    drop(slow);
}

/// A writer that signals when it is dropped: the reply thread owns it until it ends.
struct DropSignal(Box<dyn Write + Send>, mpsc::Sender<()>);

impl Write for DropSignal {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl Drop for DropSignal {
    fn drop(&mut self) {
        let _ = self.1.send(());
    }
}

/// A hub on a real socket that reports when each connection thread returns and when each
/// connection's writer is dropped.
struct Watched {
    name: String,
    server: crate::ipc::ServerHandle,
    conn_done: mpsc::Receiver<()>,
    writer_dropped: mpsc::Receiver<()>,
}

fn serve_watched(hub: &Arc<Hub>, tag: &str) -> Watched {
    let name = socket_name(tag);
    let (done_tx, conn_done) = mpsc::channel();
    let (drop_tx, writer_dropped) = mpsc::channel();
    let (done_tx, drop_tx) = (Mutex::new(done_tx), Mutex::new(drop_tx));
    let h = hub.clone();
    let server = crate::ipc::serve_stream(&name, move |r, w, close| {
        let w = DropSignal(w, lock(&drop_tx).clone());
        h.serve_conn(r, Box::new(w), close);
        let _ = lock(&done_tx).send(());
    })
    .unwrap();
    Watched {
        name,
        server,
        conn_done,
        writer_dropped,
    }
}

fn ended(rx: &mpsc::Receiver<()>, what: &str) {
    rx.recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|_| panic!("{what} did not end"));
}

fn connect_raw(name: &str) -> interprocess::local_socket::Stream {
    use interprocess::local_socket::{Stream, traits::Stream as _};
    Stream::connect(sync_gate_core::ipc_name::to_name(name).unwrap()).unwrap()
}

#[test]
fn a_silent_peer_that_never_reads_is_closed_by_the_tick_on_a_real_socket() {
    let l = Arc::new(FakeLauncher::default());
    let hub = Arc::new(hub(&l));
    let w = serve_watched(&hub, "hub-silent");
    let _peer = connect_raw(&w.name);
    wait_until("the connection to register", || {
        !lock(&hub.inner.map).hellos.is_empty()
    });
    let now = Instant::now();
    hub.tick(now + HELLO_DEADLINE);
    hub.tick(now + HELLO_DEADLINE + 2 * REFUSAL_GRACE);
    ended(&w.conn_done, "the connection thread");
    ended(&w.writer_dropped, "the reply thread");
    hub.shutdown();
    assert!(w.server.stop_within(Duration::from_secs(5)));
}

#[test]
fn a_bad_hello_from_a_peer_that_never_reads_is_closed_by_the_tick_on_a_real_socket() {
    let l = Arc::new(FakeLauncher::default());
    let hub = Arc::new(hub(&l));
    let w = serve_watched(&hub, "hub-bad-hello");
    let mut peer = Wire(Arc::new(connect_raw(&w.name)));
    use interprocess::local_socket::traits::Stream as _;
    peer.0.set_nonblocking(true).unwrap();
    writeln!(peer, r#"{{"server":1}}"#).unwrap();
    ended(&w.conn_done, "the connection thread");
    hub.tick(Instant::now() + 2 * REFUSAL_GRACE);
    ended(&w.writer_dropped, "the reply thread");
    assert_peer_disconnected(&mut peer);
    hub.shutdown();
    assert!(w.server.stop_within(Duration::from_secs(5)));
}

/// A failed flush leaves real bytes unread and sends a dropped Windows pipe to limbo.
#[test]
fn a_refusal_with_a_failed_flush_keeps_the_real_socket_reachable_until_close() {
    struct FailedFlush(Box<dyn Write + Send>, mpsc::Sender<()>);
    impl Write for FailedFlush {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            signal_thread_exit(self.1.clone());
            Err(io::ErrorKind::Other.into())
        }
    }
    let l = Arc::new(FakeLauncher::default());
    let hub = Arc::new(hub(&l));
    let name = socket_name("hub-failed-flush");
    let (done_tx, done_rx) = mpsc::channel();
    let (conn_tx, conn_rx) = mpsc::channel();
    let h = hub.clone();
    let server = crate::ipc::serve_stream(&name, move |r, w, close| {
        h.serve_conn(r, Box::new(FailedFlush(w, done_tx.clone())), close);
        let _ = conn_tx.send(());
    })
    .unwrap();
    let mut peer = Wire(Arc::new(connect_raw(&name)));
    use interprocess::local_socket::traits::Stream as _;
    peer.0.set_nonblocking(true).unwrap();
    writeln!(peer, "not json").unwrap();
    ended(&conn_rx, "the connection thread");
    ended(&done_rx, "the failed-flush reply worker");
    hub.tick(Instant::now() + 2 * REFUSAL_GRACE);
    // Never read the peer: doing so would release the linger flush and hide the leak.
    assert_peer_disconnected(&mut peer);
    hub.shutdown();
    assert!(server.stop_within(Duration::from_secs(5)));
}

fn assert_peer_disconnected(peer: &mut Wire) {
    wait_until(
        "the unread peer's writes to fail after the tick",
        || match peer.write(b"x") {
            Err(e) => !matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ),
            Ok(_) => false,
        },
    );
}

/// A connection whose reads and writes block until it is closed from outside, like a Windows
/// pipe flush to a peer that never reads. `first` is what the peer sent (nothing: it blocks).
fn stuck_conn(
    first: &'static [u8],
) -> (
    Box<dyn Read + Send>,
    Box<dyn Write + Send>,
    Closer,
    Arc<AtomicBool>,
) {
    struct Stuck(Arc<AtomicBool>, &'static [u8]);
    impl Read for Stuck {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if !self.1.is_empty() {
                let n = self.1.len().min(buf.len());
                buf[..n].copy_from_slice(&self.1[..n]);
                self.1 = &self.1[n..];
                return Ok(n);
            }
            while !self.0.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(0)
        }
    }
    impl Write for Stuck {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            while !self.0.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }
            let _ = buf;
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let closed = Arc::new(AtomicBool::new(false));
    let c2 = closed.clone();
    let close: Closer = Arc::new(move || c2.store(true, Ordering::SeqCst));
    (
        Box::new(Stuck(closed.clone(), first)),
        Box::new(Stuck(closed.clone(), b"")),
        close,
        closed,
    )
}

/// Closing a connection discards what its peer has not read (a named pipe disconnect), so a
/// refusal's reply thread must leave the close to the tick: it only ever writes the reply.
#[test]
fn a_refusal_is_not_closed_by_its_reply_thread() {
    struct Reply(mpsc::Sender<()>);
    impl Write for Reply {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            signal_thread_exit(self.0.clone());
            Ok(())
        }
    }
    let l = Arc::new(FakeLauncher::default());
    let hub = hub(&l);
    let flag = || Arc::new(AtomicBool::new(false));
    let closed = flag();
    let (done_tx, done_rx) = mpsc::channel();
    let c2 = closed.clone();
    let close: Closer = Arc::new(move || c2.store(true, Ordering::SeqCst));
    let (r, w) = (
        io::Cursor::new(
            b"not json
"
            .to_vec(),
        ),
        Reply(done_tx),
    );
    hub.serve_conn(Box::new(r), Box::new(w), close);
    ended(&done_rx, "the reply worker after parking its writer");
    assert!(!closed.load(Ordering::SeqCst), "closed by the reply thread");
    hub.tick(Instant::now() + 2 * REFUSAL_GRACE);
    wait_until("the tick to close the refusal", || {
        closed.load(Ordering::SeqCst)
    });
}

#[test]
fn a_reply_that_never_finishes_does_not_keep_a_refused_connection_open() {
    let l = Arc::new(FakeLauncher::default());
    let hub = Arc::new(hub(&l));
    // Hello timeout: the reader blocks, then the reply write blocks.
    let (r, w, close, closed) = stuck_conn(b"");
    let h = hub.clone();
    std::thread::spawn(move || h.serve_conn(r, w, close));
    wait_until("the connection to register", || {
        !lock(&hub.inner.map).hellos.is_empty()
    });
    let now = Instant::now();
    hub.tick(now + HELLO_DEADLINE);
    assert!(!closed.load(Ordering::SeqCst), "closed before the grace");
    hub.tick(now + HELLO_DEADLINE + 2 * REFUSAL_GRACE);
    wait_until("the timed-out connection to be closed by the tick", || {
        closed.load(Ordering::SeqCst)
    });
    // Bad hello: the reply write blocks at once.
    let (r, w, close, closed) = stuck_conn(b"not json\n");
    let h = hub.clone();
    std::thread::spawn(move || h.serve_conn(r, w, close));
    wait_until("the refusal to be registered", || {
        !lock(&hub.inner.map).closing.is_empty()
    });
    hub.tick(Instant::now() + 2 * REFUSAL_GRACE);
    wait_until("the refused connection to be closed by the tick", || {
        closed.load(Ordering::SeqCst)
    });
    // Shutdown closes whatever is still waiting for its grace.
    let (r, w, close, closed) = stuck_conn(b"not json\n");
    let h = hub.clone();
    std::thread::spawn(move || h.serve_conn(r, w, close));
    wait_until("the refusal to be registered", || {
        !lock(&hub.inner.map).closing.is_empty()
    });
    hub.shutdown();
    wait_until("shutdown to close the refused connection", || {
        closed.load(Ordering::SeqCst)
    });
    assert!(lock(&hub.inner.map).closing.is_empty());
}

// ---- elastic pool -------------------------------------------------------

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

/// The test config with `docs` limited to `max_instances` children of `max_in_flight` each.
fn pool_hub(l: &Arc<FakeLauncher>, max_instances: u32, max_in_flight: u32) -> Hub {
    let mut cfg = config();
    if let Some(d) = cfg.mcp.get_mut("docs") {
        d.max_instances = max_instances;
        d.max_in_flight = max_in_flight;
    }
    Hub::new(&cfg, l.clone(), None, None)
}

/// Requests waiting in the hub queues.
fn queued(hub: &Hub) -> usize {
    lock(&hub.inner.map)
        .instances
        .values()
        .map(|i| lock(&i.st).queue.len())
        .sum()
}

/// A docs client whose first child is ready (stateless, or legacy with subscriptions).
fn pool_client(hub: &Hub, l: &FakeLauncher, legacy: bool) -> (TestClient, FakeChild) {
    let mut c = connect(hub, hello("docs", &[], "/r"));
    assert_eq!(c.reply(), HubReply::Ok);
    let mut child = l.take_child();
    if legacy {
        child.handshake_legacy();
    } else {
        child.handshake();
    }
    // The mux answers a ping only once the child is ready: until then requests wait in the
    // mux's own queue, not the hub's.
    c.send(json!({"jsonrpc": "2.0", "id": "ready", "method": "ping"}));
    assert_eq!(c.recv()["id"], "ready");
    (c, child)
}

/// Sends `tools/call` requests with `ids`: the first `in_flight` reach `child` (returned, in
/// order), the rest wait in the hub queue.
fn overflow(
    hub: &Hub,
    c: &mut TestClient,
    child: &FakeChild,
    ids: std::ops::RangeInclusive<u64>,
    in_flight: usize,
) -> Vec<Value> {
    let n = ids.clone().count();
    for id in ids {
        c.send(request(id, "tools/call"));
    }
    let seen = (0..in_flight).map(|_| child.next()).collect();
    wait_until("the overflow to queue in the hub", || {
        queued(hub) == n - in_flight
    });
    seen
}

/// Ticks past `GROW_WAIT` with plenty of memory: one more child is spawned and handshaken.
fn grow(hub: &Hub, l: &FakeLauncher, legacy: bool) -> FakeChild {
    let spawns = l.spawns();
    hub.set_memory(4 * GIB, GIB / 2);
    hub.tick(Instant::now() + GROW_WAIT + Duration::from_millis(100));
    assert_eq!(l.spawns(), spawns + 1, "the pool did not grow");
    let mut child = l.take_child();
    if legacy {
        child.handshake_legacy();
    } else {
        child.handshake();
    }
    child
}

fn reply_to(child: &mut FakeChild, req: &Value) {
    let result = json!({"echo": req["method"]});
    child.send(json!({"jsonrpc": "2.0", "id": req["id"], "result": result}));
}

/// The client ids of the next `n` replies.
fn reply_ids(c: &TestClient, n: usize) -> std::collections::BTreeSet<u64> {
    (0..n).map(|_| c.recv()["id"].as_u64().unwrap()).collect()
}

#[test]
fn hub_scales_to_two_and_back() {
    let l = Arc::new(FakeLauncher::default());
    let hub = pool_hub(&l, 2, 8);
    let (mut c, mut first) = pool_client(&hub, &l, false);
    let mine = overflow(&hub, &mut c, &first, 1..=20, 8);
    hub.set_memory(4 * GIB, GIB / 2);
    hub.tick(Instant::now());
    assert_eq!(l.spawns(), 1, "grew on a short wait");
    let mut second = grow(&hub, &l, false);
    let theirs: Vec<Value> = (0..8).map(|_| second.next()).collect();
    assert_eq!(queued(&hub), 4);
    assert_eq!(docs(&hub).instances, 2);
    // The first child frees room one at a time and, as the least loaded, takes the other 4.
    for req in &mine {
        reply_to(&mut first, req);
    }
    for _ in 0..4 {
        first.answer();
    }
    for req in &theirs {
        reply_to(&mut second, req);
    }
    assert_eq!(reply_ids(&c, 20), (1..=20).collect());
    assert_eq!(queued(&hub), 0);
    hub.tick(Instant::now() + Duration::from_secs(60));
    assert_eq!(docs(&hub).instances, 2, "shrunk before SHRINK_IDLE");
    hub.tick(Instant::now() + SHRINK_IDLE + Duration::from_secs(1));
    assert_eq!(docs(&hub).instances, 1);
    // The second child went through stop_own; the first keeps serving.
    wait_until("stop_own", || l.calls().contains(&"reap 101".to_string()));
    assert!(!l.calls().contains(&"reap 100".to_string()));
    c.send(request(21, "tools/list"));
    first.answer();
    assert_eq!(c.recv()["id"], 21);
    let mut seen = Vec::new();
    assert!(notes_contain(
        &hub,
        &mut seen,
        "mcp docs: scaling up to 2 instances"
    ));
    assert!(notes_contain(
        &hub,
        &mut seen,
        "mcp docs: scaling down to 1 instance"
    ));
    hub.shutdown();
}

#[test]
fn subscriber_stays_on_its_instance() {
    let l = Arc::new(FakeLauncher::default());
    let hub = pool_hub(&l, 2, 2);
    let (mut a, mut first) = pool_client(&hub, &l, true);
    let mut b = connect(&hub, hello("docs", &[], "/r"));
    assert_eq!(b.reply(), HubReply::Ok);
    a.send(
        json!({"jsonrpc": "2.0", "id": 1, "method": "resources/subscribe", "params": {"uri": "u"}}),
    );
    let sub = first.next();
    assert_eq!(sub["method"], "resources/subscribe");
    reply_to(&mut first, &sub);
    assert_eq!(a.recv()["id"], 1);
    // B fills the first child and queues one more, which goes to the second child.
    let held = overflow(&hub, &mut b, &first, 1..=3, 2);
    let mut second = grow(&hub, &l, true);
    let moved = second.next();
    assert_eq!(moved["method"], "tools/call");
    reply_to(&mut second, &moved);
    assert_eq!(b.recv()["id"], 3);
    // The second child is idle and the first is full, yet A's request waits for the first.
    a.send(request(2, "resources/read"));
    wait_until("A to wait for its instance", || queued(&hub) == 1);
    reply_to(&mut first, &held[0]);
    assert_eq!(first.next()["method"], "resources/read");
    assert_eq!(b.recv()["id"], 1);
    hub.shutdown();
}

#[test]
fn a_cancelled_queued_request_gets_no_reply_and_frees_its_place() {
    let l = Arc::new(FakeLauncher::default());
    let hub = pool_hub(&l, 3, 1);
    let (mut c, mut child) = pool_client(&hub, &l, false);
    let seen = overflow(&hub, &mut c, &child, 1..=2, 1);
    c.send(
        json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 2}}),
    );
    wait_until("the queued request to be cancelled", || queued(&hub) == 0);
    reply_to(&mut child, &seen[0]);
    assert_eq!(c.recv()["id"], 1);
    c.send(request(3, "tools/list"));
    assert_eq!(child.answer()["method"], "tools/list");
    assert_eq!(c.recv()["id"], 3, "the cancelled request was answered");
    hub.shutdown();
}

// #2 item 20 (JSON-RPC 2.0, section 4): with a pool the hub reads a line before any mux. One
// without "jsonrpc":"2.0" neither waits in the hub queue nor cancels a request queued there.
#[test]
fn a_line_without_jsonrpc_neither_waits_nor_cancels_in_the_hub_queue() {
    let l = Arc::new(FakeLauncher::default());
    let hub = pool_hub(&l, 3, 1);
    let (mut c, mut child) = pool_client(&hub, &l, false);
    let seen = overflow(&hub, &mut c, &child, 1..=2, 1);
    c.send(json!({"method": "notifications/cancelled", "params": {"requestId": 2}}));
    c.send(json!({"id": 9, "method": "tools/list"}));
    let refused = c.recv();
    assert_eq!(refused["id"], 9);
    assert_eq!(refused["error"]["code"], -32600);
    assert_eq!(
        queued(&hub),
        1,
        "request 2 must stay queued: the line without jsonrpc cancels nothing"
    );
    reply_to(&mut child, &seen[0]);
    assert_eq!(c.recv()["id"], 1);
    let moved = child.next();
    reply_to(&mut child, &moved);
    assert_eq!(c.recv()["id"], 2);
    hub.shutdown();
}

#[test]
fn a_queued_request_times_out() {
    let l = Arc::new(FakeLauncher::default());
    let hub = pool_hub(&l, 3, 1);
    let (mut c, child) = pool_client(&hub, &l, false);
    overflow(&hub, &mut c, &child, 1..=2, 1);
    hub.tick(Instant::now() + Duration::from_secs(299));
    assert_eq!(queued(&hub), 1, "expired early");
    hub.tick(Instant::now() + Duration::from_secs(301));
    let mut replies: Vec<Value> = (0..2).map(|_| c.recv()).collect();
    replies.sort_by_key(|r| r["id"].as_u64());
    let queued_reply = &replies[1];
    assert_eq!(queued_reply["id"], 2);
    assert_eq!(queued_reply["error"]["code"], -32001);
    assert_eq!(queued_reply["error"]["message"], "request timed out");
    assert_eq!(queued(&hub), 0);
    hub.shutdown();
}

#[test]
fn a_hub_queued_request_keeps_its_first_deadline() {
    let l = Arc::new(FakeLauncher::default());
    let mut cfg = config();
    if let Some(d) = cfg.mcp.get_mut("docs") {
        d.max_instances = 3;
        d.max_in_flight = 1;
        d.request_timeout_secs = 2;
    }
    let hub = Hub::new(&cfg, l.clone(), None, None);
    let (mut c, mut child) = pool_client(&hub, &l, false);
    let t0 = Instant::now();
    let seen = overflow(&hub, &mut c, &child, 1..=2, 1);
    // A slot opens about half way through the timeout: the queued request goes out then,
    // but its clock started when the client sent it.
    std::thread::sleep(Duration::from_secs(1));
    reply_to(&mut child, &seen[0]);
    assert_eq!(c.recv()["id"], 1);
    child.next();
    hub.tick(t0 + Duration::from_millis(2050));
    let e = c.recv();
    assert_eq!(e["id"], 2);
    assert_eq!(e["error"]["code"], -32001);
    hub.shutdown();
}

#[test]
fn an_expired_hub_queued_request_never_reaches_the_server() {
    let l = Arc::new(FakeLauncher::default());
    let mut cfg = config();
    if let Some(d) = cfg.mcp.get_mut("docs") {
        d.max_instances = 3;
        d.max_in_flight = 1;
        d.request_timeout_secs = 2;
    }
    let hub = Hub::new(&cfg, l.clone(), None, None);
    let (mut c, mut child) = pool_client(&hub, &l, false);
    let seen = overflow(&hub, &mut c, &child, 1..=2, 1);
    // shortcut: real sleep (the hub reads Instant::now() per event), 0.5 s past the deadline and
    // no tick; swap for an injected clock if the hub ever takes one.
    std::thread::sleep(Duration::from_millis(2500));
    reply_to(&mut child, &seen[0]);
    assert_eq!(c.recv()["id"], 1);
    let e = c.recv();
    assert_eq!(e["id"], 2);
    assert_eq!(e["error"]["code"], -32001);
    // The server reads its stdin in order: had request 2 gone out, it would come first.
    c.send(request(3, "tools/list"));
    assert_eq!(
        child.next()["method"],
        "tools/list",
        "the expired request reached the server"
    );
    hub.shutdown();
}

#[test]
fn the_hub_queue_is_bounded_per_client() {
    let l = Arc::new(FakeLauncher::default());
    let hub = pool_hub(&l, 3, 1);
    let (mut c, child) = pool_client(&hub, &l, false);
    let cap = sync_gate_hub::MAX_QUEUED_PER_CLIENT as u64;
    overflow(&hub, &mut c, &child, 1..=cap + 1, 1);
    c.send(request(cap + 2, "tools/call"));
    let busy = c.recv();
    assert_eq!(busy["id"], cap + 2);
    assert_eq!(busy["error"]["code"], -32000);
    assert_eq!(busy["error"]["message"], "mcp server busy");
    assert_eq!(queued(&hub), cap as usize);
    hub.shutdown();
}

#[test]
fn with_one_instance_every_request_reaches_the_child_at_once() {
    let l = Arc::new(FakeLauncher::default());
    let hub = pool_hub(&l, 1, 8);
    let (mut c, child) = pool_client(&hub, &l, false);
    for id in 1..=20 {
        c.send(request(id, "tools/call"));
    }
    for _ in 0..20 {
        assert_eq!(child.next()["method"], "tools/call");
    }
    assert_eq!(queued(&hub), 0);
    assert_eq!(docs(&hub).in_flight, 20);
    hub.set_memory(4 * GIB, GIB / 2);
    hub.tick(Instant::now() + GROW_WAIT + Duration::from_secs(1));
    assert_eq!(l.spawns(), 1);
    hub.shutdown();
}

#[test]
fn list_changed_from_the_second_instance_reaches_a_client_once() {
    let l = Arc::new(FakeLauncher::default());
    let hub = pool_hub(&l, 2, 1);
    let (mut c, mut first) = pool_client(&hub, &l, false);
    // Handshaken before the second instance exists.
    c.send(json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}}));
    assert_eq!(c.recv()["id"], 0);
    let held = overflow(&hub, &mut c, &first, 1..=2, 1);
    let mut second = grow(&hub, &l, false);
    let moved = second.next();
    let changed = json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"});
    second.send(changed.clone());
    reply_to(&mut second, &moved);
    assert_eq!(c.recv()["method"], "notifications/tools/list_changed");
    assert_eq!(c.recv()["id"], 2, "list_changed delivered twice");
    first.send(changed);
    reply_to(&mut first, &held[0]);
    assert_eq!(c.recv()["method"], "notifications/tools/list_changed");
    assert_eq!(c.recv()["id"], 1, "list_changed delivered twice");
    hub.shutdown();
}

#[test]
fn a_pinned_backlog_does_not_grow_the_pool() {
    let l = Arc::new(FakeLauncher::default());
    let hub = pool_hub(&l, 3, 1);
    let (mut c, mut child) = pool_client(&hub, &l, true);
    c.send(
        json!({"jsonrpc": "2.0", "id": 1, "method": "resources/subscribe", "params": {"uri": "u"}}),
    );
    let sub = child.next();
    reply_to(&mut child, &sub);
    assert_eq!(c.recv()["id"], 1);
    overflow(&hub, &mut c, &child, 2..=3, 1);
    hub.set_memory(4 * GIB, GIB / 2);
    hub.tick(Instant::now() + GROW_WAIT + Duration::from_secs(1));
    assert_eq!(l.spawns(), 1, "a new instance cannot serve a pinned client");
    hub.shutdown();
}

#[test]
fn no_growth_before_set_memory() {
    let l = Arc::new(FakeLauncher::default());
    let hub = pool_hub(&l, 3, 1);
    let (mut c, child) = pool_client(&hub, &l, false);
    overflow(&hub, &mut c, &child, 1..=2, 1);
    hub.tick(Instant::now() + GROW_WAIT + Duration::from_secs(1));
    assert_eq!(l.spawns(), 1);
    assert!(hub.take_notes().iter().all(|n| !n.contains("not scaling")));
    grow(&hub, &l, false);
    hub.shutdown();
}

#[test]
fn short_memory_blocks_growth_with_one_note() {
    let l = Arc::new(FakeLauncher::default());
    let hub = pool_hub(&l, 3, 1);
    let (mut c, child) = pool_client(&hub, &l, false);
    overflow(&hub, &mut c, &child, 1..=2, 1);
    hub.measure(|_| 100 * MIB);
    hub.set_memory(600 * MIB, 512 * MIB);
    for s in 1..=3 {
        hub.tick(Instant::now() + GROW_WAIT + Duration::from_secs(s));
    }
    assert_eq!(l.spawns(), 1);
    let notes = hub.take_notes();
    let n = notes
        .iter()
        .filter(|n| *n == "mcp docs: not scaling, memory is the limit")
        .count();
    assert_eq!(n, 1, "{notes:?}");
    hub.shutdown();
}

#[test]
fn a_crash_of_the_second_instance_fails_only_its_own_requests() {
    let l = Arc::new(FakeLauncher::default());
    let hub = pool_hub(&l, 2, 1);
    let (mut c, mut first) = pool_client(&hub, &l, false);
    let held = overflow(&hub, &mut c, &first, 1..=2, 1);
    let mut second = grow(&hub, &l, false);
    assert_eq!(second.next()["method"], "tools/call");
    l.kill(&mut second);
    let failed = c.recv();
    assert_eq!(failed["id"], 2);
    assert_eq!(failed["error"]["code"], -32000);
    wait_until("the crash to be seen", || docs(&hub).instances == 1);
    reply_to(&mut first, &held[0]);
    assert_eq!(c.recv()["id"], 1);
    c.send(request(3, "tools/list"));
    first.answer();
    assert_eq!(c.recv()["id"], 3);
    hub.shutdown();
}

/// `pool_hub` whose requests outlive every tick below (the queue keeps waiting).
fn patient_pool_hub(l: &Arc<FakeLauncher>, max_instances: u32, max_in_flight: u32) -> Hub {
    let mut cfg = config();
    if let Some(d) = cfg.mcp.get_mut("docs") {
        d.max_instances = max_instances;
        d.max_in_flight = max_in_flight;
        d.request_timeout_secs = 3600;
    }
    Hub::new(&cfg, l.clone(), None, None)
}

fn count_notes(notes: &[String], needle: &str) -> usize {
    notes.iter().filter(|n| n.contains(needle)).count()
}

#[test]
fn a_crash_looping_extra_instance_is_kept_until_its_pause_ends() {
    let l = Arc::new(FakeLauncher::default());
    let hub = patient_pool_hub(&l, 2, 1);
    let (mut c, first) = pool_client(&hub, &l, false);
    overflow(&hub, &mut c, &first, 1..=2, 1);
    hub.set_memory(4 * GIB, GIB / 2);
    hub.tick(Instant::now() + GROW_WAIT + Duration::from_millis(100));
    assert_eq!(l.spawns(), 2);
    // The second copy cannot run: five exits in a row start its crash-loop pause.
    for n in 1..=5 {
        let mut child = l.take_child();
        l.kill(&mut child);
        wait_until("the crash to be seen", || docs(&hub).instances == 1);
        hub.tick(Instant::now() + Duration::from_secs(60));
        let expected = if n < 5 { n + 2 } else { 6 };
        assert_eq!(l.spawns(), expected, "after crash {n}");
    }
    let mut notes = hub.take_notes();
    assert_eq!(count_notes(&notes, "keeps crashing"), 1, "{notes:?}");
    // A bad extra instance changes nothing for clients.
    assert_eq!(count_notes(&notes, "unavailable through the hub"), 0);
    assert!(!c.closed.load(Ordering::SeqCst));
    // Well past SHRINK_IDLE, inside the pause: neither shrunk nor replaced.
    for s in [130, 200, 290] {
        hub.tick(Instant::now() + Duration::from_secs(s));
    }
    assert_eq!(l.spawns(), 6, "the paused instance was replaced");
    notes.extend(hub.take_notes());
    assert_eq!(count_notes(&notes, "scaling down"), 0, "{notes:?}");
    assert_eq!(count_notes(&notes, "scaling up"), 1, "{notes:?}");
    // After the pause it restarts as usual, and an idle extra instance is then shrunk.
    hub.tick(Instant::now() + CRASH_PAUSE + Duration::from_secs(60));
    assert_eq!(l.spawns(), 7);
    let _restarted = l.take_child();
    hub.tick(Instant::now() + CRASH_PAUSE + Duration::from_secs(61));
    let mut seen = Vec::new();
    assert!(notes_contain(
        &hub,
        &mut seen,
        "mcp docs: scaling down to 1 instance"
    ));
    hub.shutdown();
}

#[test]
fn an_unsupported_extra_instance_is_not_respawned_before_its_retry() {
    let l = Arc::new(FakeLauncher::default());
    let hub = patient_pool_hub(&l, 2, 1);
    let (mut c, mut first) = pool_client(&hub, &l, false);
    let held = overflow(&hub, &mut c, &first, 1..=3, 1);
    hub.set_memory(4 * GIB, GIB / 2);
    hub.tick(Instant::now() + GROW_WAIT + Duration::from_millis(100));
    assert_eq!(l.spawns(), 2);
    let mut second = l.take_child();
    let probe = second.next();
    second.send(json!({"jsonrpc": "2.0", "id": probe["id"], "result": {"supportedVersions": ["2099-01-01"]}}));
    wait_until("stop_own", || l.calls().contains(&"reap 101".to_string()));
    for s in [130, 400, 590] {
        hub.tick(Instant::now() + Duration::from_secs(s));
    }
    assert_eq!(l.spawns(), 2, "an unsupported instance was replaced");
    assert_eq!(docs(&hub).instances, 1);
    assert!(!c.closed.load(Ordering::SeqCst));
    let notes = hub.take_notes();
    assert_eq!(
        count_notes(&notes, "unavailable through the hub"),
        0,
        "{notes:?}"
    );
    assert_eq!(queued(&hub), 2);
    // The first instance serves everything, in order.
    reply_to(&mut first, &held[0]);
    assert_eq!(c.recv()["id"], 1);
    first.answer();
    assert_eq!(c.recv()["id"], 2);
    first.answer();
    assert_eq!(c.recv()["id"], 3);
    hub.shutdown();
}

#[test]
fn a_client_handshaken_after_growth_gets_list_changed_once() {
    let l = Arc::new(FakeLauncher::default());
    let hub = pool_hub(&l, 2, 1);
    let (mut a, first) = pool_client(&hub, &l, false);
    overflow(&hub, &mut a, &first, 1..=2, 1);
    let mut second = grow(&hub, &l, false);
    assert_eq!(second.next()["method"], "tools/call");
    let mut b = connect(&hub, hello("docs", &[], "/r"));
    assert_eq!(b.reply(), HubReply::Ok);
    b.send(json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}}));
    assert_eq!(b.recv()["id"], 0);
    second.send(json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}));
    second.send(json!({"jsonrpc": "2.0", "method": "notifications/prompts/list_changed"}));
    assert_eq!(b.recv()["method"], "notifications/tools/list_changed");
    assert_eq!(
        b.recv()["method"],
        "notifications/prompts/list_changed",
        "list_changed delivered twice"
    );
    hub.shutdown();
}

#[test]
fn the_hub_queue_byte_bound_answers_busy() {
    let l = Arc::new(FakeLauncher::default());
    let hub = pool_hub(&l, 3, 1);
    let (mut c, child) = pool_client(&hub, &l, false);
    overflow(&hub, &mut c, &child, 1..=1, 1);
    let big = |id: u64| {
        let pad = "x".repeat(sync_gate_hub::MAX_QUEUED_BYTES_PER_CLIENT / 2 + 1);
        json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"pad": pad}})
    };
    c.send(big(2));
    wait_until("the first large request to queue", || queued(&hub) == 1);
    c.send(big(3));
    let busy = c.recv();
    assert_eq!(busy["id"], 3);
    assert_eq!(busy["error"]["code"], -32000);
    assert_eq!(busy["error"]["message"], "mcp server busy");
    assert_eq!(queued(&hub), 1);
    hub.shutdown();
}

#[test]
fn two_pools_do_not_spend_the_same_free_memory_in_one_tick() {
    let l = Arc::new(FakeLauncher::default());
    let hub = pool_hub(&l, 3, 1);
    let mut clients = Vec::new();
    for token in ["a", "b"] {
        let mut c = connect(&hub, hello("docs", &[("TOKEN", token)], "/r"));
        assert_eq!(c.reply(), HubReply::Ok);
        let mut child = l.take_child();
        child.handshake();
        c.send(json!({"jsonrpc": "2.0", "id": "ready", "method": "ping"}));
        assert_eq!(c.recv()["id"], "ready");
        c.send(request(1, "tools/call"));
        child.next();
        c.send(request(2, "tools/call"));
        clients.push((c, child));
    }
    wait_until("both overflows to queue", || queued(&hub) == 2);
    hub.measure(|_| 400 * MIB);
    // Room for one more 400 MiB instance above the 512 MiB reserve, not for two.
    hub.set_memory(GIB, 512 * MIB);
    hub.tick(Instant::now() + GROW_WAIT + Duration::from_millis(100));
    assert_eq!(l.spawns(), 3, "exactly one pool grows");
    // The new instance is still starting (not measured): the next tick does not spend it again.
    hub.tick(Instant::now() + GROW_WAIT + Duration::from_millis(600));
    assert_eq!(l.spawns(), 3);
    hub.shutdown();
}

/// A hub on `config()` whose config reread answers `reread`.
fn reloading(
    l: &Arc<FakeLauncher>,
    reread: impl Fn() -> Result<BTreeMap<String, McpServer>, ConfigLoadError> + Send + Sync + 'static,
) -> Hub {
    Hub::new(&config(), l.clone(), None, Some(Arc::new(reread)))
}

fn shared(command: &str) -> McpServer {
    McpServer {
        command: command.into(),
        mode: McpMode::Shared,
        idle_stop_secs: 10,
        ..McpServer::default()
    }
}

fn names(hub: &Hub) -> Vec<(String, String)> {
    hub.report()
        .into_iter()
        .map(|r| (r.server, r.mode))
        .collect()
}

/// As if the last reread had been `ago` before now.
fn reread_ago(hub: &Hub, ago: Duration) {
    *lock(&hub.inner.reloaded) = Some(Instant::now().checked_sub(ago).unwrap());
}

fn with_program(server: &str, program: &str) -> HubHello {
    HubHello {
        program: Some(PathBuf::from(program)),
        ..hello(server, &[], "/r")
    }
}

#[test]
fn hubreload_a_server_added_after_start_is_served_and_shared() {
    let l = Arc::new(FakeLauncher::default());
    let hub = reloading(&l, || {
        let mut mcp = config().mcp;
        let args = vec!["--flag".to_string(), "v".to_string()];
        mcp.insert(
            "x".into(),
            McpServer {
                args,
                ..shared("x-mcp")
            },
        );
        Ok(mcp)
    });
    let a = connect(&hub, hello("x", &[], "/r"));
    let b = connect(&hub, hello("x", &[], "/r"));
    assert_eq!((a.reply(), b.reply()), (HubReply::Ok, HubReply::Ok));
    assert_eq!(l.spawns(), 1);
    // What the new server runs is what the config says, command and arguments.
    let child = l.take_child();
    assert_eq!(child.command, "x-mcp");
    assert_eq!(child.args, ["--flag", "v"]);
    let x = row(&hub.report(), "x").clone();
    assert_eq!((x.mode.as_str(), x.clients), ("shared", 2));
    let mut seen = Vec::new();
    assert!(notes_contain(
        &hub,
        &mut seen,
        "mcp x: added from the config"
    ));
    // Only the new name: the three it already had are not "added".
    let added = seen.iter().filter(|n| n.contains("added")).count();
    assert_eq!(added, 1, "{seen:?}");
    hub.shutdown();
}

#[test]
fn hubreload_an_existing_server_is_never_changed_by_a_reload() {
    let l = Arc::new(FakeLauncher::default());
    // The reread config turns `docs` per-session under another command, drops `files` and
    // `browser`, and adds `y`.
    let hub = reloading(&l, || {
        let docs = McpServer {
            command: "other-mcp".into(),
            ..McpServer::default()
        };
        Ok(BTreeMap::from([
            ("docs".to_string(), docs),
            ("y".to_string(), shared("y-mcp")),
        ]))
    });
    // A client of `docs` is attached before the reload happens.
    let mut docs = connect(&hub, hello("docs", &[("TOKEN", "t")], "/r"));
    assert_eq!(docs.reply(), HubReply::Ok);
    let mut child = l.take_child();
    child.handshake();
    docs.send(request(1, "tools/call"));
    child.answer();
    assert_eq!(docs.recv()["id"], 1);
    assert_eq!(connect(&hub, hello("y", &[], "/r")).reply(), HubReply::Ok);
    let files = connect(&hub, hello("files", &[], "/r"));
    let browser = connect(&hub, hello("browser", &[], "/r"));
    assert_eq!(
        (files.reply(), browser.reply()),
        (HubReply::Ok, HubReply::PerSession)
    );
    // The reload did not touch it: same child, and it still gets its answers.
    docs.send(request(2, "tools/call"));
    child.answer();
    assert_eq!(docs.recv()["id"], 2);
    let calls = l.calls();
    assert!(
        calls.iter().all(|c| !c.starts_with("terminate")),
        "{calls:?}"
    );
    // A second `docs` session shares that child.
    let again = connect(&hub, hello("docs", &[("TOKEN", "t")], "/r"));
    assert_eq!(again.reply(), HubReply::Ok);
    let d = row(&hub.report(), "docs").clone();
    assert_eq!((d.clients, d.instances), (2, 1));
    let want = [
        ("browser", "per-session"),
        ("docs", "shared"),
        ("files", "shared"),
        ("y", "shared"),
    ]
    .map(|(s, m)| (s.to_string(), m.to_string()));
    assert_eq!(names(&hub), want);
    let mut seen = Vec::new();
    assert!(notes_contain(
        &hub,
        &mut seen,
        "mcp y: added from the config"
    ));
    let touched = seen
        .iter()
        .any(|n| n.contains("docs") || n.contains("files"));
    assert!(!touched, "{seen:?}");
    hub.shutdown();
}

const SECRET: &str = "SECRET-VALUE";

/// Config texts that do not load, each with a secret in or next to the broken part, and where
/// the note may say the parser found it (a `Config::from_toml` error with no location: `None`).
const BROKEN: [(&str, Option<&str>); 2] = [
    ("[postgres]\nport = \"SECRET-VALUE\"\n", None),
    (
        "[mcp.x]\ncommand = \"c\"\nenv = { TOKEN = \"SECRET-VALUE }\n",
        Some("line 3"),
    ),
];

#[test]
fn hubreload_an_invalid_config_changes_nothing_and_says_only_that_it_did_not_load() {
    for (text, at) in BROKEN {
        let l = Arc::new(FakeLauncher::default());
        let hub = reloading(&l, move || {
            Config::from_toml(text)
                .map(|c| c.mcp)
                .map_err(|e| ConfigLoadError::parse(text, &e))
        });
        let before = names(&hub);
        let x = connect(&hub, hello("x", &[], "/r"));
        assert_eq!(x.reply(), HubReply::Unknown);
        assert_eq!(l.spawns(), 0);
        assert_eq!(names(&hub), before);
        let mut seen = Vec::new();
        notes_contain(&hub, &mut seen, "");
        assert!(seen.iter().all(|n| !n.contains(SECRET)), "{seen:?}");
        assert!(
            notes_contain(&hub, &mut seen, "config did not load"),
            "{seen:?}"
        );
        if let Some(at) = at {
            assert!(notes_contain(&hub, &mut seen, at), "{seen:?}");
        }
        // What it had is still served.
        let docs = connect(&hub, hello("docs", &[], "/r"));
        assert_eq!(docs.reply(), HubReply::Ok);
        hub.shutdown();
    }
}

#[test]
fn hubreload_two_concurrent_hellos_for_a_new_name_share_one_child() {
    let l = Arc::new(FakeLauncher::default());
    let (entered_tx, entered) = mpsc::channel::<()>();
    let (release, release_rx) = mpsc::channel::<()>();
    let release_rx = Mutex::new(release_rx);
    let calls = Arc::new(AtomicU32::new(0));
    let counted = calls.clone();
    let hub = reloading(&l, move || {
        counted.fetch_add(1, Ordering::SeqCst);
        entered_tx.send(()).unwrap();
        // The first hello holds the reread until the second one is waiting behind it.
        let _ = release_rx.lock().unwrap().recv_timeout(WAIT);
        let mut mcp = config().mcp;
        mcp.insert("x".into(), shared("x-mcp"));
        Ok(mcp)
    });
    let (a, b) = std::thread::scope(|s| {
        let first = s.spawn(|| connect(&hub, hello("x", &[], "/r1")));
        entered.recv_timeout(WAIT).expect("the first hello rereads");
        let second = s.spawn(|| connect(&hub, hello("x", &[], "/r2")));
        // Whether or not the second has reached the lock, it must not reread on its own.
        std::thread::sleep(Duration::from_millis(100));
        release.send(()).unwrap();
        (first.join().unwrap(), second.join().unwrap())
    });
    assert_eq!((a.reply(), b.reply()), (HubReply::Ok, HubReply::Ok));
    assert_eq!(calls.load(Ordering::SeqCst), 1, "one reread for both");
    assert_eq!(l.spawns(), 1, "one child for both");
    assert_eq!(row(&hub.report(), "x").clients, 2);
    hub.shutdown();
}

#[test]
fn hubreload_a_bare_name_with_no_safe_candidate_runs_per_session() {
    let d = std::env::temp_dir().join(format!("sync_gate_hubreload-shim-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    let shims = d.join("shims");
    std::fs::create_dir_all(&shims).unwrap();
    std::fs::write(shims.join(sync_gate_core::SHIMS_MANIFEST), "{}").unwrap();
    let name = if cfg!(windows) { "node.exe" } else { "node" };
    let marker = d.join("ran");
    let shim = shims.join(name);
    // Where a script runs it leaves the marker; on Windows the shim cannot start at all.
    std::fs::write(&shim, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    // The PATH holds the shims folder and nothing else: no safe candidate.
    let env = BTreeMap::from([("PATH".to_string(), shims.to_string_lossy().into_owned())]);
    let mut cfg = config();
    cfg.mcp.insert(
        "node".into(),
        McpServer {
            env,
            ..shared(name)
        },
    );
    let hub = Hub::new(&cfg, Arc::new(crate::OsLauncher::default()), None, None);
    let c = connect(&hub, hello("node", &[], "/r"));
    assert_eq!(c.reply(), HubReply::PerSession);
    // Only an instance's unit is ever started: with none, nothing ran and nothing will.
    assert!(
        lock(&hub.inner.map).instances.is_empty(),
        "the hub took the server"
    );
    assert!(!marker.exists(), "the shim ran");
    hub.shutdown();
    let _ = std::fs::remove_dir_all(&d);
}

#[cfg(unix)]
#[test]
fn hubreload_a_relative_path_entry_with_an_inherited_cwd_runs_per_session() {
    // Two projects with their own node_modules/.bin/tool: the daemon cannot tell which folder
    // the entry means, so the session (which is in its own project) runs its own server.
    let l = Arc::new(FakeLauncher::default());
    let server = |cwd: Option<&str>, path: &str| McpServer {
        cwd: cwd.map(String::from),
        env: BTreeMap::from([("PATH".to_string(), path.to_string())]),
        ..shared("tool")
    };
    let mut cfg = config();
    for (name, srv) in [
        (
            "rel-inherit",
            server(Some("inherit"), "node_modules/.bin:/usr/bin"),
        ),
        ("empty-inherit", server(Some("inherit"), "/usr/bin::/bin")),
        ("abs-inherit", server(Some("inherit"), "/usr/bin:/bin")),
        ("rel-no-cwd", server(None, "node_modules/.bin:/usr/bin")),
        // A fixed folder: the hub resolves from its own folder, the child runs in /projeto-A.
        (
            "rel-fixed",
            server(Some("/projeto-A"), "node_modules/.bin:/usr/bin"),
        ),
    ] {
        cfg.mcp.insert(name.into(), srv);
    }
    let hub = Hub::new(&cfg, l.clone(), None, None);
    let reply = |name: &str| connect(&hub, hello(name, &[], "/projeto-B")).reply();
    assert_eq!(reply("rel-inherit"), HubReply::PerSession);
    assert_eq!(reply("empty-inherit"), HubReply::PerSession);
    assert_eq!(reply("rel-fixed"), HubReply::PerSession);
    assert_eq!(l.spawns(), 0);
    // Only the combination is ambiguous: an absolute PATH, or the daemon's own folder.
    assert_eq!(reply("abs-inherit"), HubReply::Ok);
    assert_eq!(reply("rel-no-cwd"), HubReply::Ok);
    hub.shutdown();
}

#[test]
fn hubreload_reloads_at_most_every_2_seconds() {
    assert_eq!(RELOAD_EVERY, Duration::from_secs(2));
    let l = Arc::new(FakeLauncher::default());
    let calls = Arc::new(AtomicU32::new(0));
    let counted = calls.clone();
    let hub = reloading(&l, move || {
        counted.fetch_add(1, Ordering::SeqCst);
        Ok(config().mcp)
    });
    let unknown = || connect(&hub, hello("x", &[], "/r")).reply();
    let rereads = || calls.load(Ordering::SeqCst);
    assert_eq!((unknown(), rereads()), (HubReply::Unknown, 1));
    assert_eq!((unknown(), rereads()), (HubReply::Unknown, 1));
    reread_ago(&hub, RELOAD_EVERY - Duration::from_secs(1));
    assert_eq!((unknown(), rereads()), (HubReply::Unknown, 1));
    reread_ago(&hub, RELOAD_EVERY);
    assert_eq!((unknown(), rereads()), (HubReply::Unknown, 2));
    // A name it knows never rereads.
    reread_ago(&hub, RELOAD_EVERY);
    let docs = connect(&hub, hello("docs", &[], "/r"));
    assert_eq!(docs.reply(), HubReply::Ok);
    assert_eq!(rereads(), 2);
    hub.shutdown();
}

#[test]
fn hubreload_a_session_resolving_another_program_runs_per_session() {
    let l = Arc::new(FakeLauncher::default());
    *l.resolved.lock().unwrap() = Some(PathBuf::from("/hub/bin/docs-mcp"));
    let hub = hub(&l);
    let other = connect(&hub, with_program("docs", "/session/bin/docs-mcp"));
    assert_eq!(other.reply(), HubReply::PerSession);
    assert_eq!(l.spawns(), 0);
    let mut seen = Vec::new();
    assert!(notes_contain(
        &hub,
        &mut seen,
        "mcp docs: this session runs 'docs-mcp' from /session/bin/docs-mcp, the hub from \
         /hub/bin/docs-mcp; that session runs it itself"
    ));
    let same = connect(&hub, with_program("docs", "/hub/bin/docs-mcp"));
    assert_eq!(same.reply(), HubReply::Ok);
    assert_eq!(l.spawns(), 1);
    #[cfg(windows)]
    {
        let upper = connect(&hub, with_program("docs", "/HUB/BIN/DOCS-MCP"));
        assert_eq!(upper.reply(), HubReply::Ok, "Windows paths ignore case");
        assert_eq!(l.spawns(), 1);
    }
    // The hub finds the command nowhere: the session that does runs it itself.
    l.unresolvable.store(true, Ordering::SeqCst);
    let alone = connect(&hub, with_program("files", "/session/bin/docs-mcp"));
    assert_eq!(alone.reply(), HubReply::PerSession);
    assert!(notes_contain(&hub, &mut seen, "the hub from nowhere"));
    hub.shutdown();
}

#[test]
fn hubreload_an_old_relay_without_program_is_served() {
    let l = Arc::new(FakeLauncher::default());
    *l.resolved.lock().unwrap() = Some(PathBuf::from("/hub/bin/docs-mcp"));
    let hub = Arc::new(hub(&l));
    let mut old = raw_conn(hub.clone());
    // A hello as relays wrote it before `program`.
    old.send(json!({"server": "docs", "cwd": "/r", "env": {}, "client": "sync_gate_mcp"}));
    assert_eq!(old.reply(), HubReply::Ok);
    wait_until("the child to start", || l.spawns() == 1);
    hub.shutdown();
}

// Final review I7: a resolved path that is not Unicode would reach the spawn as a lossy name
// ("raw-\u{FFFD}"), which may be another existing file. The hub never approves such a path.
#[cfg(unix)]
#[test]
fn hubreload_a_resolved_path_that_is_not_unicode_runs_per_session() {
    use std::os::unix::ffi::OsStrExt;
    let l = Arc::new(FakeLauncher::default());
    *l.resolved.lock().unwrap() = Some(PathBuf::from(std::ffi::OsStr::from_bytes(
        b"/opt/raw-\xFF/bin/docs-mcp",
    )));
    let hub = Arc::new(hub(&l));
    let mut old = raw_conn(hub.clone());
    old.send(json!({"server": "docs", "cwd": "/r", "env": {}, "client": "sync_gate_mcp"}));
    assert_eq!(old.reply(), HubReply::PerSession);
    assert_eq!(l.spawns(), 0);
    hub.shutdown();
}

/// The OS launcher, deleting `victim` right before each start: the compared file disappears
/// between the hub's comparison and the spawn (an update in that window). `asked` records what
/// the hub asked it to start.
struct RemovesBeforeSpawn {
    os: crate::OsLauncher,
    victim: PathBuf,
    asked: Mutex<Vec<String>>,
}

impl crate::supervisor::Launcher for RemovesBeforeSpawn {
    fn spawn(
        &self,
        command: &str,
        args: &[String],
        env: &BTreeMap<String, String>,
        env_remove: &[String],
        cwd: Option<&Path>,
    ) -> std::io::Result<crate::supervisor::Spawned> {
        self.asked.lock().unwrap().push(command.to_string());
        let _ = std::fs::remove_file(&self.victim);
        self.os.spawn(command, args, env, env_remove, cwd)
    }
    fn is_alive(&self, pid: u32, start_time: u64, launch: u64) -> bool {
        self.os.is_alive(pid, start_time, launch)
    }
    fn terminate(&self, pid: u32, start_time: u64, launch: u64) -> std::io::Result<()> {
        self.os.terminate(pid, start_time, launch)
    }
    fn exe_of(&self, pid: u32) -> Option<PathBuf> {
        self.os.exe_of(pid)
    }
    fn resolve(&self, command: &str, env: &BTreeMap<String, String>) -> Option<PathBuf> {
        self.os.resolve(command, env)
    }
    fn reap(&self, pid: u32, launch: u64) -> Option<i32> {
        self.os.reap(pid, launch)
    }
}

#[test]
fn hubreload_the_hub_starts_the_file_it_compared_or_nothing() {
    let d = std::env::temp_dir().join(format!("sync_gate_hub-compared-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    let (a, b) = (d.join("a"), d.join("b"));
    let name = if cfg!(windows) { "tool.cmd" } else { "tool" };
    for dir in [&a, &b] {
        std::fs::create_dir_all(dir).unwrap();
        let ran = dir.join("ran");
        let script = if cfg!(windows) {
            format!("@echo x> \"{}\"\r\n", ran.display())
        } else {
            format!("#!/bin/sh\ntouch '{}'\n", ran.display())
        };
        std::fs::write(dir.join(name), script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::Permissions::from_mode(0o755);
            std::fs::set_permissions(dir.join(name), mode).unwrap();
        }
    }
    let path = std::env::join_paths([&a, &b]).unwrap();
    let env = BTreeMap::from([("PATH".to_string(), path.to_string_lossy().into_owned())]);
    let mut cfg = config();
    cfg.mcp.insert(
        "tool".into(),
        McpServer {
            env,
            ..shared("tool")
        },
    );
    let compared = a.join(name);
    let l = Arc::new(RemovesBeforeSpawn {
        os: crate::OsLauncher::default(),
        victim: compared.clone(),
        asked: Mutex::new(Vec::new()),
    });
    let hub = Hub::new(&cfg, l.clone(), None, None);
    let c = connect(&hub, with_program("tool", compared.to_str().unwrap()));
    assert_eq!(
        c.reply(),
        HubReply::Ok,
        "the session and the hub found the same file"
    );
    wait_until("the hub to start the server", || {
        !l.asked.lock().unwrap().is_empty()
    });
    // A start that failed pauses the unit; a process that ran ends with its stdout, after its
    // mark. Either way nothing is left Starting or Running.
    wait_until("whatever was started to end", || {
        lock(&hub.inner.map).instances.values().all(|i| {
            lock(&i.st)
                .units
                .iter()
                .all(|u| !matches!(u.child, Child::Starting | Child::Running(_)))
        })
    });
    let asked = l.asked.lock().unwrap().clone();
    hub.shutdown();
    assert!(
        !b.join("ran").exists(),
        "the hub started another file than the one it compared: {asked:?}"
    );
    // Windows: the extension is spelled as PATHEXT writes it.
    let fold = |s: &str| {
        if cfg!(windows) {
            s.to_lowercase()
        } else {
            s.to_owned()
        }
    };
    assert_eq!(
        fold(&asked[0]),
        fold(compared.to_str().unwrap()),
        "no second search"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_restart_note_names_the_exit_code() {
    let l = Arc::new(FakeLauncher::default());
    let hub = hub(&l);
    let c = connect(&hub, hello("docs", &[], "/r"));
    assert_eq!(c.reply(), HubReply::Ok);
    let mut child = l.take_child();
    child.handshake();
    l.exit_codes.lock().unwrap().insert(100, 3);
    l.kill(&mut child);
    wait_until("the crash to be seen", || docs(&hub).instances == 0);
    // `reap` returns before the hub records the code: wait for the record itself.
    wait_until("the exit code to be recorded", || {
        unit_exits(&hub).contains(&Some((1, Some(3))))
    });
    hub.tick(Instant::now() + Duration::from_secs(2));
    assert_eq!(l.spawns(), 2);
    // No code known for the second child.
    let mut child = l.take_child();
    child.handshake();
    l.kill(&mut child);
    wait_until("stop_own", || l.calls().contains(&"reap 101".to_string()));
    hub.tick(Instant::now() + Duration::from_secs(5));
    assert_eq!(l.spawns(), 3);
    let notes = hub.take_notes();
    for want in [
        "mcp docs: restarted (child exited, code 3)",
        "mcp docs: restarted (child exited, code unknown)",
    ] {
        assert_eq!(count_notes(&notes, want), 1, "{want}: {notes:?}");
    }
    hub.shutdown();
}

#[test]
fn a_poisoned_hub_lock_is_noted_once() {
    let l = Arc::new(FakeLauncher::default());
    let hub = hub(&l);
    let inner = hub.inner.clone();
    // A thread that panics while it holds the lock leaves it poisoned.
    let _ = std::thread::spawn(move || {
        let _g = inner.restarts.lock().unwrap();
        panic!("poison the lock");
    })
    .join();
    assert!(hub.inner.restarts.is_poisoned());
    let _ = hub.report();
    let _ = hub.report();
    let notes = hub.take_notes();
    assert_eq!(count_notes(&notes, "poisoned"), 1, "{notes:?}");
    assert!(!hub.inner.restarts.is_poisoned(), "not recovered");
    let seen = crate::supervisor::poisonings();
    let _ = hub.report();
    let again = hub.take_notes();
    // Another test of this binary may poison a lock of its own meanwhile.
    if crate::supervisor::poisonings() == seen {
        assert_eq!(count_notes(&again, "poisoned"), 0, "{again:?}");
    }
    hub.shutdown();
}

#[test]
fn stop_grace_secs_is_honored() {
    let l = Arc::new(FakeLauncher::default());
    l.ignore_eof.store(true, Ordering::SeqCst);
    let mut cfg = config();
    cfg.mcp.get_mut("docs").unwrap().stop_grace_secs = 1;
    let hub = Hub::new(&cfg, l.clone(), None, None);
    let c = connect(&hub, hello("docs", &[], "/r"));
    assert_eq!(c.reply(), HubReply::Ok);
    let _child = l.take_child();
    let t0 = Instant::now();
    hub.shutdown();
    let took = t0.elapsed();
    // 1 s of grace, then the (instant) fake terminate; the default would be 5 s.
    assert!(
        took >= Duration::from_secs(1) && took < Duration::from_secs(4),
        "{took:?}"
    );
    assert!(l.calls().contains(&"terminate 100".to_string()));
}

/// A fake launcher whose spawn reports `entered`, then waits for `go`: the hub can be told to
/// stop while a child is being started.
struct GatedSpawn {
    fake: Arc<FakeLauncher>,
    entered: Mutex<mpsc::Sender<()>>,
    go: Mutex<mpsc::Receiver<()>>,
}

impl crate::supervisor::Launcher for GatedSpawn {
    fn spawn(
        &self,
        command: &str,
        args: &[String],
        env: &BTreeMap<String, String>,
        env_remove: &[String],
        cwd: Option<&Path>,
    ) -> std::io::Result<crate::supervisor::Spawned> {
        let _ = lock(&self.entered).send(());
        let _ = lock(&self.go).recv();
        self.fake.spawn(command, args, env, env_remove, cwd)
    }
    fn is_alive(&self, pid: u32, start_time: u64, launch: u64) -> bool {
        self.fake.is_alive(pid, start_time, launch)
    }
    fn terminate(&self, pid: u32, start_time: u64, launch: u64) -> std::io::Result<()> {
        self.fake.terminate(pid, start_time, launch)
    }
    fn reap(&self, pid: u32, launch: u64) -> Option<i32> {
        self.fake.reap(pid, launch)
    }
}

#[test]
fn a_child_spawned_while_the_hub_stops_is_stopped() {
    let fake = Arc::new(FakeLauncher::default());
    // Only `terminate` ends it: proves the hub stopped it, not its stdin EOF.
    fake.ignore_eof.store(true, Ordering::SeqCst);
    let (entered, started) = mpsc::channel();
    let (go, wait) = mpsc::channel();
    let l = Arc::new(GatedSpawn {
        fake: fake.clone(),
        entered: Mutex::new(entered),
        go: Mutex::new(wait),
    });
    let hub =
        Arc::new(Hub::new(&config(), l, None, None).with_stop_grace(Duration::from_millis(50)));
    // `attach` starts the child on the calling thread: not on the test's.
    let attaching = {
        let hub = hub.clone();
        std::thread::spawn(move || connect(&hub, hello("docs", &[], "/r")))
    };
    started
        .recv_timeout(Duration::from_secs(10))
        .expect("the spawn to begin");
    hub.shutdown();
    go.send(()).unwrap();
    let _c = attaching.join().unwrap();
    wait_until("the late child to be stopped", || {
        fake.calls().contains(&"reap 100".to_string())
    });
    assert!(fake.calls().contains(&"terminate 100".to_string()));
    assert!(!fake.is_alive_quiet(100));
}

/// `exit` of every unit of every instance.
fn unit_exits(hub: &Hub) -> Vec<Option<(u64, Option<i32>)>> {
    let map = lock(&hub.inner.map);
    map.instances
        .values()
        .flat_map(|i| lock(&i.st).units.iter().map(|u| u.exit).collect::<Vec<_>>())
        .collect()
}

/// A later failure of the same unit (a start that failed) is not that exit: its restart note
/// must not carry the older child's code.
#[test]
fn a_new_crash_forgets_an_older_exit_code() {
    let l = Arc::new(FakeLauncher::default());
    let hub = hub(&l);
    let c = connect(&hub, hello("docs", &[], "/r"));
    assert_eq!(c.reply(), HubReply::Ok);
    let mut child = l.take_child();
    child.handshake();
    let inst = lock(&hub.inner.map)
        .instances
        .values()
        .next()
        .unwrap()
        .clone();
    {
        let mut g = lock(&inst.st);
        // An older child exited with 3; then this unit failed again before any restart.
        g.units[0].exit = Some((0, Some(3)));
        hub.inner
            .crashed("docs", &mut g, 0, Instant::now(), "start failed");
        assert_eq!(g.units[0].exit, None);
    }
    hub.shutdown();
}

#[test]
fn a_stopper_thread_that_cannot_start_is_noted() {
    let l = Arc::new(FakeLauncher::default());
    let hub = hub(&l);
    let mut c = connect(&hub, hello("docs", &[], "/r"));
    assert_eq!(c.reply(), HubReply::Ok);
    let _child = l.take_child();
    c.hang_up();
    wait_until("the client to leave", || docs(&hub).clients == 0);
    // The idle stop runs on this (the ticking) thread: its stopper thread fails to start.
    fail_next_threads(1);
    hub.tick(Instant::now() + Duration::from_secs(11));
    fail_next_threads(0);
    // Stopped anyway, inline, and said.
    assert!(l.calls().contains(&"reap 100".to_string()));
    let notes = hub.take_notes();
    assert_eq!(
        count_notes(&notes, "mcp docs: cannot start a stopper thread"),
        1,
        "{notes:?}"
    );
    hub.shutdown();
}

// ---- #2 items 7, 8 and 18 (hub) ----------------------------------------------------------

/// The legacy path: the probe is refused, then comes `initialize` (returned).
fn refuse_probe_then_initialize(child: &mut FakeChild) -> Value {
    let probe = child.next();
    let no = json!({"code": -32601, "message": "no"});
    child.send(json!({"jsonrpc": "2.0", "id": probe["id"], "error": no}));
    let init = child.next();
    assert_eq!(init["method"], "initialize");
    init
}

/// A client line that waits in the mux: the parse error the reader sends after it is the
/// barrier (the reader handles lines in order).
fn queue_in_the_mux(c: &mut TestClient, line: &str) {
    c.send_raw(line);
    c.send_raw("{");
    assert_eq!(c.recv()["error"]["code"], -32700);
}

#[test]
fn a_server_that_rejects_initialize_falls_back_to_direct() {
    let l = Arc::new(FakeLauncher::default());
    let hub = hub(&l);
    let mut c = connect_draining(&hub, hello("docs", &[], "/r"));
    assert_eq!(c.reply(), HubReply::Ok);
    let mut child = l.take_child();
    queue_in_the_mux(&mut c, &initialize_request(0).to_string());
    let init = refuse_probe_then_initialize(&mut child);
    let boom = json!({"code": -32603, "message": "boom"});
    child.send(json!({"jsonrpc": "2.0", "id": init["id"], "error": boom}));
    wait_until("the client to be disconnected", || {
        c.closed.load(Ordering::SeqCst)
    });
    // Unanswered: the relay replays its initialize on its own server.
    assert_eq!(c.rest(), Vec::<String>::new());
    let mut notes = Vec::new();
    let note =
        "mcp docs: unavailable through the hub (initialize rejected); sessions run it directly";
    assert!(notes_contain(&hub, &mut notes, note), "{notes:?}");
    wait_until("stop_own", || l.calls().contains(&"reap 100".to_string()));
    assert_eq!(
        connect(&hub, hello("docs", &[], "/r")).reply(),
        unavailable()
    );
    assert_eq!(l.spawns(), 1, "retried at once");
    hub.tick(Instant::now() + CRASH_PAUSE + Duration::from_secs(1));
    let again = connect(&hub, hello("docs", &[], "/r"));
    assert_eq!(again.reply(), HubReply::Ok);
    assert_eq!(l.spawns(), 2);
    hub.shutdown();
}

/// MCP 2026-07-28 stdio fallback: a modern server whose `server/discover` answer comes after
/// the probe timeout gets `initialize`, which it rejects. The session still works: directly.
#[test]
fn a_discover_answer_after_the_probe_timeout_falls_back_to_direct() {
    let l = Arc::new(FakeLauncher::default());
    let hub = hub(&l);
    let mut c = connect_draining(&hub, hello("docs", &[], "/r"));
    assert_eq!(c.reply(), HubReply::Ok);
    let mut child = l.take_child();
    queue_in_the_mux(&mut c, &initialize_request(0).to_string());
    let probe = child.next();
    hub.tick(Instant::now() + sync_gate_hub::PROBE_TIMEOUT + Duration::from_millis(100));
    let init = child.next();
    assert_eq!(init["method"], "initialize");
    let result = json!({"supportedVersions": ["2026-07-28"], "capabilities": {"tools": {}}});
    child.send(json!({"jsonrpc": "2.0", "id": probe["id"], "result": result}));
    let no = json!({"code": -32601, "message": "initialize is not supported"});
    child.send(json!({"jsonrpc": "2.0", "id": init["id"], "error": no}));
    wait_until("the client to be disconnected", || {
        c.closed.load(Ordering::SeqCst)
    });
    assert_eq!(c.rest(), Vec::<String>::new());
    let mut notes = Vec::new();
    assert!(
        notes_contain(&hub, &mut notes, "(initialize rejected)"),
        "{notes:?}"
    );
    hub.shutdown();
}

/// A pool of 2 with 1 request in flight each: A subscribed on the SECOND instance, B holds the
/// first one's only slot with `held`.
struct Pinned {
    hub: Hub,
    l: Arc<FakeLauncher>,
    a: TestClient,
    b: TestClient,
    first: FakeChild,
    second: FakeChild,
    held: Value,
}

fn pinned_to_the_second() -> Pinned {
    let l = Arc::new(FakeLauncher::default());
    let hub = patient_pool_hub(&l, 2, 1);
    let (mut a, first) = pool_client(&hub, &l, true);
    let mut b = connect(&hub, hello("docs", &[], "/r"));
    assert_eq!(b.reply(), HubReply::Ok);
    let held = overflow(&hub, &mut b, &first, 1..=2, 1).remove(0);
    let mut second = grow(&hub, &l, true);
    let moved = second.next();
    reply_to(&mut second, &moved);
    assert_eq!(b.recv()["id"], 2);
    // The first instance is full: A's subscription lands on the second.
    a.send(
        json!({"jsonrpc": "2.0", "id": 1, "method": "resources/subscribe", "params": {"uri": "u"}}),
    );
    let sub = second.next();
    assert_eq!(sub["method"], "resources/subscribe");
    reply_to(&mut second, &sub);
    assert_eq!(a.recv()["id"], 1);
    Pinned {
        hub,
        l,
        a,
        b,
        first,
        second,
        held,
    }
}

/// A's `resources/read` went to `first` and its echo came back to A.
fn served_by(a: &TestClient, first: &mut FakeChild) {
    let seen = first.next();
    assert_eq!(seen["method"], "resources/read");
    reply_to(first, &seen);
    let r = a.recv();
    assert_eq!(r["id"], 5, "{r}");
    assert_eq!(r["result"]["echo"], "resources/read", "{r}");
}

#[test]
fn a_subscriber_of_an_instance_in_backoff_is_served_by_a_healthy_one() {
    let Pinned {
        hub,
        l,
        mut a,
        b,
        mut first,
        mut second,
        held,
    } = pinned_to_the_second();
    reply_to(&mut first, &held);
    assert_eq!(b.recv()["id"], 1);
    l.kill(&mut second);
    wait_until("the crash to be seen", || docs(&hub).instances == 1);
    // No tick: the second instance stays in its backoff, and the first has room.
    a.send(request(5, "resources/read"));
    served_by(&a, &mut first);
    hub.shutdown();
}

#[test]
fn a_subscriber_of_a_paused_instance_is_served_by_a_healthy_one() {
    let Pinned {
        hub,
        l,
        mut a,
        b,
        mut first,
        mut second,
        held,
    } = pinned_to_the_second();
    for n in 1..=5 {
        l.kill(&mut second);
        wait_until("the crash to be seen", || docs(&hub).instances == 1);
        hub.tick(Instant::now() + Duration::from_secs(60));
        let expected = if n < 5 { n + 2 } else { 6 };
        assert_eq!(l.spawns(), expected, "after crash {n}");
        if n < 5 {
            second = l.take_child();
        }
    }
    let mut notes = Vec::new();
    assert!(
        notes_contain(&hub, &mut notes, "keeps crashing"),
        "{notes:?}"
    );
    // The first instance is healthy but full: A waits for it, and never gets "keeps crashing".
    a.send(request(5, "resources/read"));
    wait_until("A to wait for the healthy instance", || queued(&hub) == 1);
    reply_to(&mut first, &held);
    assert_eq!(b.recv()["id"], 1);
    served_by(&a, &mut first);
    hub.shutdown();
}

#[test]
fn an_unsupported_instance_is_retried_after_its_ttl() {
    // The TTL is 10 minutes.
    let ttl = Duration::from_secs(600);
    let l = Arc::new(FakeLauncher::default());
    // Never idle-retired here: the retry itself must clear the verdict, not a fresh instance.
    let mut cfg = config();
    if let Some(d) = cfg.mcp.get_mut("docs") {
        d.idle_stop_secs = 3600;
    }
    let hub = Hub::new(&cfg, l.clone(), None, None);
    let c = connect(&hub, hello("docs", &[], "/r"));
    assert_eq!(c.reply(), HubReply::Ok);
    let mut child = l.take_child();
    let probe = child.next();
    let result = json!({"supportedVersions": ["2099-01-01"]});
    let before = Instant::now();
    child.send(json!({"jsonrpc": "2.0", "id": probe["id"], "result": result}));
    wait_until("the client to be disconnected", || {
        c.closed.load(Ordering::SeqCst)
    });
    let until = unsupported_until(&hub, 0);
    assert!(
        until >= before + ttl && until <= Instant::now() + ttl,
        "the retry is not 10 min after the decision"
    );
    hub.tick(until - Duration::from_secs(1));
    assert_eq!(
        connect(&hub, hello("docs", &[], "/r")).reply(),
        unavailable()
    );
    hub.tick(until + Duration::from_secs(1));
    // A tick between the retry and the next hello must not bring the old verdict back.
    hub.tick(until + Duration::from_secs(2));
    let again = connect(&hub, hello("docs", &[], "/r"));
    assert_eq!(again.reply(), HubReply::Ok);
    assert_eq!(l.spawns(), 2, "not retried after the TTL");
    hub.shutdown();
}

/// When unit `i` of the only instance is retried after its unsupported verdict.
fn unsupported_until(hub: &Hub, i: usize) -> Instant {
    let map = lock(&hub.inner.map);
    let inst = map.instances.values().next().expect("an instance");
    match lock(&inst.st).units[i].child {
        Child::Unsupported { until } => until,
        _ => panic!("unit {i} is not unsupported"),
    }
}

#[test]
fn crash_history_survives_idle_retirement() {
    let l = Arc::new(FakeLauncher::default());
    let hub = hub(&l);
    // Each session crashes the server and leaves; each tick is past the backoff and
    // idle_stop_secs (10 s), and all of them are well inside the 60 s crash window.
    for n in 1..=5 {
        let mut c = connect(&hub, hello("docs", &[], "/r"));
        assert_eq!(c.reply(), HubReply::Ok, "session {n}");
        let mut child = l.take_child();
        l.kill(&mut child);
        wait_until("the crash to be seen", || docs(&hub).instances == 0);
        c.hang_up();
        wait_until("the client to leave", || docs(&hub).clients == 0);
        hub.tick(Instant::now() + Duration::from_secs(11));
    }
    assert_eq!(l.spawns(), 5);
    let mut notes = Vec::new();
    assert!(
        notes_contain(&hub, &mut notes, "keeps crashing"),
        "{notes:?}"
    );
    assert_eq!(
        connect(&hub, hello("docs", &[], "/r")).reply(),
        unavailable()
    );
    hub.shutdown();
}

#[test]
fn a_deep_json_request_during_crash_backoff_is_answered() {
    let l = Arc::new(FakeLauncher::default());
    let hub = hub(&l);
    let mut c = connect(&hub, hello("docs", &[], "/r"));
    assert_eq!(c.reply(), HubReply::Ok);
    let mut child = l.take_child();
    child.handshake();
    l.kill(&mut child);
    wait_until("the crash to be seen", || docs(&hub).instances == 0);
    // In the backoff, the deepest request the hub takes waits in the mux...
    queue_in_the_mux(&mut c, &deep_request(1, DEEPEST_OK));
    assert_eq!(l.spawns(), 1);
    // ...and reaches the next child, whose deepest answer reaches the client.
    hub.tick(Instant::now() + Duration::from_secs(2));
    let mut child = l.take_child();
    child.handshake();
    let seen = child.next();
    assert_eq!(seen["method"], "tools/call");
    assert_eq!(
        seen["params"],
        serde_json::from_str::<Value>(&nested(DEEPEST_OK)).unwrap()
    );
    let result = nested(DEEPEST_OK);
    child.send_raw(&format!(
        r#"{{"jsonrpc":"2.0","id":{},"result":{result}}}"#,
        seen["id"]
    ));
    let reply = recv_id(&c, 1);
    assert!(reply["result"].is_array(), "{reply}");
    // A deep request that waits through its whole deadline is answered too.
    l.kill(&mut child);
    wait_until("the crash to be seen", || docs(&hub).instances == 0);
    queue_in_the_mux(&mut c, &deep_request(2, DEEPEST_OK));
    hub.tick(Instant::now() + Duration::from_secs(301));
    let late = recv_id(&c, 2);
    assert_eq!(late["error"]["code"], -32001, "{late}");
    hub.shutdown();
}

#[test]
fn a_subscriber_s_subscription_changes_wait_for_its_own_instance() {
    let Pinned {
        hub,
        l,
        mut a,
        mut b,
        mut first,
        mut second,
        held,
    } = pinned_to_the_second();
    reply_to(&mut first, &held);
    assert_eq!(b.recv()["id"], 1);
    l.kill(&mut second);
    wait_until("the crash to be seen", || docs(&hub).instances == 1);
    // The first instance has room, yet neither change may go there: it holds none of A's
    // subscriptions, and the second would restore "u" when it comes back.
    // Subscribe first: A still holds "u" when it goes, so both belong to the second instance.
    a.send(
        json!({"jsonrpc": "2.0", "id": 7, "method": "resources/subscribe", "params": {"uri": "v"}}),
    );
    a.send(json!({"jsonrpc": "2.0", "id": 6, "method": "resources/unsubscribe", "params": {"uri": "u"}}));
    wait_until("A's changes to wait for their instance", || {
        queued(&hub) == 2
    });
    hub.tick(Instant::now() + Duration::from_secs(2));
    let mut third = l.take_child();
    third.handshake_legacy();
    let restore = third.next();
    assert_eq!(restore["method"], "resources/subscribe");
    assert_eq!(restore["params"]["uri"], "u");
    reply_to(&mut third, &restore);
    for (id, method, uri) in [
        (7, "resources/subscribe", "v"),
        (6, "resources/unsubscribe", "u"),
    ] {
        let seen = third.next();
        assert_eq!(
            (seen["method"].as_str(), seen["params"]["uri"].as_str()),
            (Some(method), Some(uri))
        );
        reply_to(&mut third, &seen);
        assert_eq!(a.recv()["id"], id);
    }
    // The first instance never saw them: the next line it reads is B's.
    b.send(request(9, "tools/list"));
    assert_eq!(first.next()["method"], "tools/list");
    hub.shutdown();
}

#[test]
fn an_extra_instance_with_a_recent_crash_is_not_shrunk() {
    let l = Arc::new(FakeLauncher::default());
    let hub = patient_pool_hub(&l, 2, 1);
    let (mut c, mut first) = pool_client(&hub, &l, false);
    let held = overflow(&hub, &mut c, &first, 1..=2, 1);
    let mut second = grow(&hub, &l, false);
    second.answer();
    reply_to(&mut first, &held[0]);
    assert_eq!(reply_ids(&c, 2), [1, 2].into());
    // Idle well past SHRINK_IDLE, with a crash 10 s before that tick.
    let t = Instant::now() + SHRINK_IDLE + Duration::from_secs(1);
    {
        let map = lock(&hub.inner.map);
        let inst = map.instances.values().next().unwrap();
        lock(&inst.st).units[1]
            .crashes
            .push_back(t - Duration::from_secs(10));
    }
    hub.tick(t);
    assert_eq!(docs(&hub).instances, 2, "shrunk with its crash history");
    hub.tick(t + CRASH_WINDOW);
    assert_eq!(docs(&hub).instances, 1);
    hub.shutdown();
}

#[test]
fn an_unsupported_extra_instance_keeps_the_key_until_its_retry() {
    let l = Arc::new(FakeLauncher::default());
    let hub = patient_pool_hub(&l, 2, 1);
    let (mut c, first) = pool_client(&hub, &l, false);
    overflow(&hub, &mut c, &first, 1..=2, 1);
    hub.set_memory(4 * GIB, GIB / 2);
    hub.tick(Instant::now() + GROW_WAIT + Duration::from_millis(100));
    let mut second = l.take_child();
    let probe = second.next();
    second.send(json!({"jsonrpc": "2.0", "id": probe["id"], "result": {"supportedVersions": ["2099-01-01"]}}));
    wait_until("stop_own", || l.calls().contains(&"reap 101".to_string()));
    c.hang_up();
    wait_until("the client to leave", || docs(&hub).clients == 0);
    // Past idle_stop_secs (10 s): retiring now would forget the verdict before its retry.
    hub.tick(Instant::now() + Duration::from_secs(11));
    assert_eq!(
        lock(&hub.inner.map).instances.len(),
        1,
        "retired before the retry"
    );
    let until = unsupported_until(&hub, 1);
    hub.tick(until + Duration::from_secs(1));
    assert_eq!(lock(&hub.inner.map).instances.len(), 0);
    hub.shutdown();
}
