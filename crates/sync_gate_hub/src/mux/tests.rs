use super::*;
use serde_json::{Value, json};

const T: Duration = Duration::from_secs(30);
const INIT: &str = r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{"sampling":{}},"clientInfo":{"name":"c","version":"1"}}}"#;

fn to_child(out: &[Out]) -> Vec<Value> {
    out.iter()
        .filter_map(|o| match o {
            Out::ToChild(l) => Some(serde_json::from_str(l).unwrap()),
            _ => None,
        })
        .collect()
}
fn to_client(out: &[Out], id: ClientId) -> Vec<Value> {
    out.iter()
        .filter_map(|o| match o {
            Out::ToClient(c, l) if *c == id => Some(serde_json::from_str(l).unwrap()),
            _ => None,
        })
        .collect()
}
fn any_client(out: &[Out]) -> bool {
    out.iter().any(|o| matches!(o, Out::ToClient(..)))
}
fn notes(out: &[Out]) -> usize {
    out.iter().filter(|o| matches!(o, Out::Note(_))).count()
}
fn feed(m: &mut Mux, v: Value, now: Instant) -> Vec<Out> {
    m.child_line(&v.to_string(), now)
}
fn start_legacy(m: &mut Mux, now: Instant, name: &str) -> Vec<Out> {
    let out = m.child_started(now);
    let probe = to_child(&out)[0]["id"].clone();
    let out = feed(
        m,
        json!({"jsonrpc":"2.0","id":probe,"error":{"code":-32601,"message":"nope"}}),
        now,
    );
    let init = to_child(&out)[0]["id"].clone();
    feed(
        m,
        json!({"jsonrpc":"2.0","id":init,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":name,"version":"1"}}}),
        now,
    )
}
fn ready(m: &mut Mux, now: Instant) {
    start_legacy(m, now, "s");
    assert_eq!(m.era(), Some(Era::Legacy));
}
fn req(c: &mut Mux, id: ClientId, rid: Value, method: &str, now: Instant) -> Vec<Out> {
    c.client_line(
        id,
        &json!({"jsonrpc":"2.0","id":rid,"method":method}).to_string(),
        now,
    )
}

#[test]
fn probes_then_initializes_once_and_serves_clients_from_cache() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    let out = m.child_started(now);
    assert_eq!(to_child(&out)[0]["method"], "server/discover");
    let meta = &to_child(&out)[0]["params"]["_meta"];
    assert_eq!(
        meta["io.modelcontextprotocol/protocolVersion"],
        "2026-07-28"
    );
    assert_eq!(
        meta["io.modelcontextprotocol/clientInfo"]["name"],
        "sync_gate_hub"
    );
    assert_eq!(
        meta["io.modelcontextprotocol/clientInfo"]["version"],
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(
        meta["io.modelcontextprotocol/clientCapabilities"],
        json!({})
    );
    let probe_id = to_child(&out)[0]["id"].clone();
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":probe_id,"error":{"code":-32601,"message":"nope"}}),
        now,
    );
    let init = &to_child(&out)[0];
    assert_eq!(init["method"], "initialize");
    assert_eq!(init["params"]["protocolVersion"], "2025-11-25");
    assert_eq!(init["params"]["capabilities"], json!({}));
    assert_eq!(init["params"]["clientInfo"]["name"], "sync_gate_hub");
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":init["id"],"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"s","version":"1"}}}),
        now,
    );
    assert_eq!(to_child(&out)[0]["method"], "notifications/initialized");
    assert_eq!(m.era(), Some(Era::Legacy));
    for c in [1, 2] {
        m.client_attached(c);
        let out = m.client_line(c, INIT, now);
        assert!(to_child(&out).is_empty());
        assert_eq!(to_client(&out, c)[0]["id"], 0);
        assert_eq!(to_client(&out, c)[0]["result"]["serverInfo"]["name"], "s");
        assert!(
            m.client_line(
                c,
                r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
                now
            )
            .is_empty()
        );
    }
}

#[test]
fn probe_silence_falls_back_to_initialize() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    m.child_started(now);
    assert!(
        m.tick(now + PROBE_TIMEOUT - Duration::from_millis(1))
            .is_empty()
    );
    let out = m.tick(now + PROBE_TIMEOUT);
    assert_eq!(to_child(&out)[0]["method"], "initialize");
}

#[test]
fn probe_error_with_any_code_means_legacy() {
    for code in [-32602, -32600, -1] {
        let mut m = Mux::new("docs", T);
        let now = Instant::now();
        let out = m.child_started(now);
        let id = to_child(&out)[0]["id"].clone();
        let out = feed(
            &mut m,
            json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":"x"}}),
            now,
        );
        assert_eq!(to_child(&out)[0]["method"], "initialize", "{code}");
    }
}

#[test]
fn ids_are_integers_and_never_reused_across_restarts() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    let mut seen = vec![];
    for _ in 0..2 {
        let out = m.child_started(now);
        let id = to_child(&out)[0]["id"].clone();
        seen.push(id.as_u64().unwrap());
        let out = feed(
            &mut m,
            json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"x"}}),
            now,
        );
        seen.push(to_child(&out)[0]["id"].as_u64().unwrap());
        m.child_exited();
    }
    let mut dedup = seen.clone();
    dedup.sort();
    dedup.dedup();
    assert_eq!(dedup.len(), seen.len());
}

#[test]
fn same_ids_from_two_clients_do_not_collide() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    ready(&mut m, now);
    m.client_attached(1);
    m.client_attached(2);
    let a = to_child(&req(&mut m, 1, json!(7), "tools/call", now))[0]["id"].clone();
    let b = to_child(&req(&mut m, 2, json!(7), "tools/call", now))[0]["id"].clone();
    assert_ne!(a, b);
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":b,"result":{"who":2}}),
        now,
    );
    assert_eq!(to_client(&out, 2)[0]["result"]["who"], 2);
    assert_eq!(to_client(&out, 2)[0]["id"], 7);
    assert!(to_client(&out, 1).is_empty());
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":a,"result":{"who":1}}),
        now,
    );
    assert_eq!(to_client(&out, 1)[0]["result"]["who"], 1);
    assert_eq!(to_client(&out, 1)[0]["id"], 7);
    assert_eq!(m.in_flight(), 0);
}

#[test]
fn progress_token_and_cancel_are_rewritten() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    ready(&mut m, now);
    m.client_attached(1);
    m.client_attached(2);
    let out = m.client_line(
        1,
        r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"_meta":{"progressToken":"p"}}}"#,
        now,
    );
    let sent = &to_child(&out)[0];
    let token = sent["params"]["_meta"]["progressToken"].clone();
    assert_ne!(token, json!("p"));
    let hub = sent["id"].clone();
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":token,"progress":1}}),
        now,
    );
    assert!(to_client(&out, 2).is_empty());
    assert_eq!(to_client(&out, 1)[0]["params"]["progressToken"], "p");
    assert_eq!(to_client(&out, 1)[0]["params"]["progress"], 1);
    let out = m.client_line(
        1,
        r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7,"reason":"x"}}"#,
        now,
    );
    let c = &to_child(&out)[0];
    assert_eq!(c["method"], "notifications/cancelled");
    assert_eq!(c["params"]["requestId"], hub);
    assert_eq!(c["params"]["reason"], "x");
    assert_eq!(m.in_flight(), 0);
}

#[test]
fn detach_cancels_in_flight_and_drops_the_late_reply() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    ready(&mut m, now);
    m.client_attached(1);
    let hub = to_child(&req(&mut m, 1, json!(7), "tools/call", now))[0]["id"].clone();
    let out = m.client_detached(1);
    let c = &to_child(&out)[0];
    assert_eq!(c["method"], "notifications/cancelled");
    assert_eq!(c["params"]["requestId"], hub);
    let out = feed(&mut m, json!({"jsonrpc":"2.0","id":hub,"result":{}}), now);
    assert!(!any_client(&out));
    assert_eq!(m.in_flight(), 0);
    assert_eq!(m.clients(), 0);
}

#[test]
fn list_changed_is_broadcast_and_updated_goes_to_subscribers_only() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    ready(&mut m, now);
    for c in [1, 2, 3] {
        m.client_attached(c);
        m.client_line(c, INIT, now);
    }
    let sub =
        r#"{"jsonrpc":"2.0","id":1,"method":"resources/subscribe","params":{"uri":"file:///a"}}"#;
    let out = m.client_line(1, sub, now);
    let sent = to_child(&out);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["method"], "resources/subscribe");
    feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":sent[0]["id"],"result":{}}),
        now,
    );
    let out = m.client_line(2, sub, now);
    assert!(to_child(&out).is_empty());
    assert_eq!(to_client(&out, 2)[0]["result"], json!({}));
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","method":"notifications/tools/list_changed"}),
        now,
    );
    for c in [1, 2, 3] {
        assert_eq!(to_client(&out, c).len(), 1, "{c}");
    }
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"file:///a"}}),
        now,
    );
    assert_eq!(to_client(&out, 1).len(), 1);
    assert_eq!(to_client(&out, 2).len(), 1);
    assert!(to_client(&out, 3).is_empty());
    let unsub =
        r#"{"jsonrpc":"2.0","id":2,"method":"resources/unsubscribe","params":{"uri":"file:///a"}}"#;
    let out = m.client_line(1, unsub, now);
    assert!(to_child(&out).is_empty());
    assert_eq!(to_client(&out, 1)[0]["result"], json!({}));
    let out = m.client_line(2, unsub, now);
    let sent = to_child(&out);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["method"], "resources/unsubscribe");
}

#[test]
fn detach_of_last_subscriber_unsubscribes_and_failed_subscribe_rolls_back() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    ready(&mut m, now);
    m.client_attached(1);
    m.client_attached(2);
    let sub = r#"{"jsonrpc":"2.0","id":1,"method":"resources/subscribe","params":{"uri":"u"}}"#;
    let id = to_child(&m.client_line(1, sub, now))[0]["id"].clone();
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"x"}}),
        now,
    );
    assert_eq!(to_client(&out, 1)[0]["error"]["code"], -32601);
    // rolled back: the next subscriber is "first" again and reaches the child
    let id = to_child(&m.client_line(2, sub, now))[0]["id"].clone();
    feed(&mut m, json!({"jsonrpc":"2.0","id":id,"result":{}}), now);
    let out = m.client_detached(2);
    assert_eq!(to_child(&out)[0]["method"], "resources/unsubscribe");
}

#[test]
fn unknown_notifications_are_dropped_with_one_note_per_method() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    ready(&mut m, now);
    m.client_attached(1);
    let msg = json!({"jsonrpc":"2.0","method":"notifications/message","params":{"data":"secret"}});
    let out = feed(&mut m, msg.clone(), now);
    assert!(!any_client(&out));
    assert_eq!(notes(&out), 1);
    let Out::Note(t) = &out[0] else {
        panic!("expected a note")
    };
    assert!(!t.contains("secret"));
    assert_eq!(notes(&feed(&mut m, msg, now)), 0);
}

#[test]
fn server_requests_are_answered_by_the_hub() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    ready(&mut m, now);
    m.client_attached(1);
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":"s1","method":"sampling/createMessage"}),
        now,
    );
    assert!(!any_client(&out));
    assert_eq!(to_child(&out)[0]["id"], "s1");
    assert_eq!(to_child(&out)[0]["error"]["code"], -32601);
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":"s2","method":"ping"}),
        now,
    );
    assert_eq!(to_child(&out)[0]["id"], "s2");
    assert_eq!(to_child(&out)[0]["result"], json!({}));
}

#[test]
fn ping_and_set_level_are_answered_locally() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    ready(&mut m, now);
    m.client_attached(1);
    for method in ["ping", "logging/setLevel"] {
        let out = req(&mut m, 1, json!(3), method, now);
        assert!(to_child(&out).is_empty());
        assert_eq!(to_client(&out, 1)[0]["result"], json!({}));
        assert_eq!(to_client(&out, 1)[0]["id"], 3);
    }
}

#[test]
fn requests_before_ready_are_queued_in_order() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    m.client_attached(1);
    assert!(req(&mut m, 1, json!(1), "tools/list", now).is_empty());
    let out = m.child_started(now);
    let probe = to_child(&out)[0]["id"].clone();
    assert!(req(&mut m, 1, json!(2), "prompts/list", now).is_empty());
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":probe,"error":{"code":-32601,"message":"x"}}),
        now,
    );
    let init = to_child(&out)[0]["id"].clone();
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":init,"result":{"capabilities":{}}}),
        now,
    );
    let methods: Vec<_> = to_child(&out).iter().map(|v| v["method"].clone()).collect();
    assert_eq!(
        methods,
        ["notifications/initialized", "tools/list", "prompts/list"]
    );
}

#[test]
fn queue_is_capped_per_client() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    m.client_attached(1);
    m.client_attached(2);
    for i in 0..256 {
        assert!(req(&mut m, 1, json!(i), "tools/list", now).is_empty());
    }
    let out = req(&mut m, 1, json!(999), "tools/list", now);
    let e = &to_client(&out, 1)[0];
    assert_eq!(e["id"], 999);
    assert_eq!(e["error"]["code"], -32000);
    assert_eq!(e["error"]["message"], "mcp server not ready");
    assert!(req(&mut m, 2, json!(1), "tools/list", now).is_empty());
}

#[test]
fn cancel_removes_a_queued_request() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    m.client_attached(1);
    req(&mut m, 1, json!(1), "tools/list", now);
    m.client_line(
        1,
        r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}"#,
        now,
    );
    let out = start_legacy(&mut m, now, "s");
    let methods: Vec<_> = to_child(&out).iter().map(|v| v["method"].clone()).collect();
    assert_eq!(methods, ["notifications/initialized"]);
    assert_eq!(m.in_flight(), 0);
}

#[test]
fn child_exit_fails_in_flight_and_restarts_cleanly() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    ready(&mut m, now);
    m.client_attached(1);
    m.client_attached(2);
    req(&mut m, 1, json!(4), "tools/call", now);
    req(&mut m, 2, json!(5), "tools/call", now);
    let out = m.child_exited();
    for (c, id) in [(1, 4), (2, 5)] {
        let e = &to_client(&out, c)[0];
        assert_eq!(e["id"], id);
        assert_eq!(e["error"]["code"], -32000);
        assert_eq!(e["error"]["message"], "mcp server restarted");
    }
    assert_eq!(m.in_flight(), 0);
    assert_eq!(m.era(), None);
    // requests in the gap are queued
    assert!(req(&mut m, 1, json!(6), "tools/list", now).is_empty());
    let out = m.child_started(now);
    assert_eq!(to_child(&out)[0]["method"], "server/discover");
    let probe = to_child(&out)[0]["id"].clone();
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":probe,"error":{"code":-32601,"message":"x"}}),
        now,
    );
    let init = to_child(&out)[0]["id"].clone();
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":init,"result":{"capabilities":{},"serverInfo":{"name":"new","version":"2"}}}),
        now,
    );
    let sent = to_child(&out);
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[1]["method"], "tools/list");
    let out = m.client_line(2, INIT, now);
    assert_eq!(to_client(&out, 2)[0]["result"]["serverInfo"]["name"], "new");
}

#[test]
fn request_timeout_replies_error_and_cancels() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    ready(&mut m, now);
    m.client_attached(1);
    let hub = to_child(&req(&mut m, 1, json!(4), "tools/call", now))[0]["id"].clone();
    assert!(m.tick(now + T - Duration::from_secs(1)).is_empty());
    let out = m.tick(now + T + Duration::from_secs(1));
    let e = &to_client(&out, 1)[0];
    assert_eq!(e["id"], 4);
    assert_eq!(e["error"]["code"], -32001);
    assert_eq!(e["error"]["message"], "request timed out");
    assert_eq!(to_child(&out)[0]["method"], "notifications/cancelled");
    assert_eq!(to_child(&out)[0]["params"]["requestId"], hub);
    assert_eq!(m.in_flight(), 0);
}

#[test]
fn garbage_from_child_is_dropped_and_parsing_continues() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    ready(&mut m, now);
    m.client_attached(1);
    let hub = to_child(&req(&mut m, 1, json!(1), "tools/call", now))[0]["id"].clone();
    let out = m.child_line("npm WARN something", now);
    assert_eq!(out.len(), 1);
    assert_eq!(notes(&out), 1);
    let batch = r#"[{"jsonrpc":"2.0","id":1,"result":{}}]"#;
    assert_eq!(notes(&m.child_line(batch, now)), 1);
    let line = format!("{}\r\n", json!({"jsonrpc":"2.0","id":hub,"result":{}}));
    let out = m.child_line(&line, now);
    assert_eq!(to_client(&out, 1)[0]["id"], 1);
}

#[test]
fn oversized_lines_are_dropped() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    ready(&mut m, now);
    m.client_attached(1);
    let big = " ".repeat(MAX_MESSAGE_BYTES + 1);
    assert_eq!(notes(&m.child_line(&big, now)), 1);
    let out = m.client_line(1, &big, now);
    let e = &to_client(&out, 1)[0];
    assert_eq!(e["error"]["code"], -32700);
    assert_eq!(e["id"], Value::Null);
}

#[test]
fn invalid_client_lines_get_parse_or_invalid_request_errors() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    ready(&mut m, now);
    m.client_attached(1);
    let out = m.client_line(1, "not json", now);
    assert_eq!(to_client(&out, 1)[0]["error"]["code"], -32700);
    assert_eq!(to_client(&out, 1)[0]["id"], Value::Null);
    let out = m.client_line(1, r#"[{"id":1,"method":"x"}]"#, now);
    // JSON-RPC 2.0 section 5.1: valid JSON that is no Request object is -32600 (null id).
    assert_eq!(to_client(&out, 1)[0]["error"]["code"], -32600);
    assert_eq!(to_client(&out, 1)[0]["id"], Value::Null);
    let out = m.client_line(1, r#"{"jsonrpc":"2.0","id":9,"method":5}"#, now);
    assert_eq!(to_client(&out, 1)[0]["error"]["code"], -32600);
    assert_eq!(to_client(&out, 1)[0]["id"], 9);
}

#[test]
fn discover_from_client_on_legacy_child_gets_method_not_found() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    ready(&mut m, now);
    m.client_attached(1);
    let out = req(&mut m, 1, json!("d"), "server/discover", now);
    assert!(to_child(&out).is_empty());
    assert_eq!(to_client(&out, 1)[0]["error"]["code"], -32601);
    assert_eq!(to_client(&out, 1)[0]["id"], "d");
}

#[test]
fn failed_initialize_answers_queued_and_later_requests_with_an_error() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    m.client_attached(1);
    req(&mut m, 1, json!(1), "tools/list", now);
    let out = m.child_started(now);
    let id = to_child(&out)[0]["id"].clone();
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"x"}}),
        now,
    );
    let init = to_child(&out)[0]["id"].clone();
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":init,"error":{"code":-32603,"message":"boom"}}),
        now,
    );
    assert_eq!(notes(&out), 1);
    assert_eq!(to_client(&out, 1)[0]["error"]["code"], -32000);
    let out = req(&mut m, 1, json!(2), "tools/list", now);
    assert_eq!(to_client(&out, 1)[0]["error"]["code"], -32000);
}

// ---- fix round 1 ---------------------------------------------------------

fn methods(out: &[Out]) -> Vec<Value> {
    to_child(out).iter().map(|v| v["method"].clone()).collect()
}
fn subscribe(m: &mut Mux, c: ClientId, rid: i64, uri: &str, now: Instant) -> Vec<Out> {
    let line =
        json!({"jsonrpc":"2.0","id":rid,"method":"resources/subscribe","params":{"uri":uri}});
    m.client_line(c, &line.to_string(), now)
}
fn updated(m: &mut Mux, uri: &str, now: Instant) -> Vec<Out> {
    feed(
        m,
        json!({"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":uri}}),
        now,
    )
}
fn two_ready(now: Instant) -> Mux {
    let mut m = Mux::new("docs", T);
    ready(&mut m, now);
    m.client_attached(1);
    m.client_attached(2);
    m
}

#[test]
fn queued_request_times_out_when_child_never_starts() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    m.client_attached(1);
    assert!(req(&mut m, 1, json!(3), "tools/list", now).is_empty());
    assert!(m.tick(now + T - Duration::from_millis(1)).is_empty());
    let out = m.tick(now + T);
    let e = &to_client(&out, 1)[0];
    assert_eq!(e["id"], 3);
    assert_eq!(e["error"]["code"], -32001);
    assert_eq!(e["error"]["message"], "request timed out");
    assert!(to_child(&out).is_empty());
    // gone from the queue: it never reaches a later child
    let out = start_legacy(&mut m, now + T, "s");
    assert_eq!(methods(&out), ["notifications/initialized"]);
}

#[test]
fn an_expired_queued_request_is_answered_not_served_when_the_child_gets_ready() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    m.client_attached(1);
    assert!(req(&mut m, 1, json!(3), "tools/list", now).is_empty());
    // ready exactly at the deadline, before any tick has swept the queue
    let out = start_legacy(&mut m, now + T, "s");
    assert!(!methods(&out).contains(&json!("tools/list")));
    let e = &to_client(&out, 1)[0];
    assert_eq!(e["id"], 3);
    assert_eq!(e["error"]["code"], -32001);
    assert!(m.tick(now + T * 2).is_empty(), "answered once only");
}

#[test]
fn a_queued_request_keeps_its_first_deadline() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    m.client_attached(1);
    assert!(req(&mut m, 1, json!(3), "tools/list", now).is_empty());
    // the child is ready after 0.9 T: the request goes out, but its clock started at `now`
    let ready_at = now + T * 9 / 10;
    let out = start_legacy(&mut m, ready_at, "s");
    assert_eq!(methods(&out), ["notifications/initialized", "tools/list"]);
    assert!(m.tick(now + T - Duration::from_millis(1)).is_empty());
    let out = m.tick(now + T);
    let e = &to_client(&out, 1)[0];
    assert_eq!(e["id"], 3);
    assert_eq!(e["error"]["code"], -32001);
}

#[test]
fn queued_request_times_out_when_child_keeps_crashing() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    m.client_attached(1);
    req(&mut m, 1, json!(3), "tools/list", now);
    for i in 1..=3u64 {
        m.child_started(now + Duration::from_secs(i));
        assert!(m.child_exited().is_empty());
    }
    let out = m.tick(now + T);
    assert_eq!(to_client(&out, 1)[0]["error"]["code"], -32001);
    assert!(to_child(&out).is_empty());
}

#[test]
fn subscribe_refused_fails_every_waiter_with_its_own_id() {
    let now = Instant::now();
    let mut m = two_ready(now);
    let sent = to_child(&subscribe(&mut m, 1, 11, "u", now));
    assert_eq!(sent.len(), 1);
    // B subscribes while A's request is in flight: it waits, nothing is answered yet
    assert!(subscribe(&mut m, 2, 22, "u", now).is_empty());
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":sent[0]["id"],"error":{"code":-32002,"message":"no"}}),
        now,
    );
    assert_eq!(to_client(&out, 1)[0]["id"], 11);
    assert_eq!(to_client(&out, 1)[0]["error"]["code"], -32002);
    assert_eq!(to_client(&out, 2)[0]["id"], 22);
    assert_eq!(to_client(&out, 2)[0]["error"]["code"], -32002);
    assert!(!any_client(&updated(&mut m, "u", now)));
    // entry removed: the next subscriber is first again
    assert_eq!(to_child(&subscribe(&mut m, 2, 23, "u", now)).len(), 1);
}

#[test]
fn subscribe_success_answers_every_waiter_and_all_get_updates() {
    let now = Instant::now();
    let mut m = two_ready(now);
    let sent = to_child(&subscribe(&mut m, 1, 11, "u", now));
    assert!(subscribe(&mut m, 2, 22, "u", now).is_empty());
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":sent[0]["id"],"result":{}}),
        now,
    );
    assert_eq!(to_client(&out, 1)[0]["id"], 11);
    assert_eq!(to_client(&out, 1)[0]["result"], json!({}));
    assert_eq!(to_client(&out, 2)[0]["id"], 22);
    assert_eq!(to_client(&out, 2)[0]["result"], json!({}));
    let out = updated(&mut m, "u", now);
    assert_eq!(to_client(&out, 1).len(), 1);
    assert_eq!(to_client(&out, 2).len(), 1);
}

#[test]
fn first_subscriber_detaching_while_pending_keeps_the_request_for_waiters() {
    let now = Instant::now();
    let mut m = two_ready(now);
    let sent = to_child(&subscribe(&mut m, 1, 11, "u", now));
    assert!(subscribe(&mut m, 2, 22, "u", now).is_empty());
    let out = m.client_detached(1);
    assert!(to_child(&out).is_empty());
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":sent[0]["id"],"result":{}}),
        now,
    );
    assert!(to_client(&out, 1).is_empty());
    assert_eq!(to_client(&out, 2)[0]["id"], 22);
    assert_eq!(to_client(&out, 2)[0]["result"], json!({}));
    let out = updated(&mut m, "u", now);
    assert_eq!(to_client(&out, 2).len(), 1);
    assert!(to_client(&out, 1).is_empty());
}

#[test]
fn first_subscriber_cancelling_while_pending_keeps_the_request_for_waiters() {
    let now = Instant::now();
    let mut m = two_ready(now);
    let sent = to_child(&subscribe(&mut m, 1, 11, "u", now));
    assert!(subscribe(&mut m, 2, 22, "u", now).is_empty());
    let out = m.client_line(
        1,
        r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":11}}"#,
        now,
    );
    assert!(to_child(&out).is_empty());
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":sent[0]["id"],"result":{}}),
        now,
    );
    assert!(to_client(&out, 1).is_empty());
    assert_eq!(to_client(&out, 2)[0]["result"], json!({}));
    assert!(to_client(&updated(&mut m, "u", now), 1).is_empty());
}

#[test]
fn first_subscriber_detaching_with_no_waiters_cancels_and_clears_the_entry() {
    let now = Instant::now();
    let mut m = two_ready(now);
    subscribe(&mut m, 1, 11, "u", now);
    let out = m.client_detached(1);
    assert_eq!(methods(&out), ["notifications/cancelled"]);
    assert_eq!(to_child(&subscribe(&mut m, 2, 22, "u", now)).len(), 1);
}

#[test]
fn waiter_detaching_while_pending_is_not_answered() {
    let now = Instant::now();
    let mut m = two_ready(now);
    let sent = to_child(&subscribe(&mut m, 1, 11, "u", now));
    subscribe(&mut m, 2, 22, "u", now);
    m.client_detached(2);
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":sent[0]["id"],"result":{}}),
        now,
    );
    assert!(to_client(&out, 2).is_empty());
    assert_eq!(to_client(&out, 1)[0]["id"], 11);
}

#[test]
fn subscribe_timeout_fails_waiters_and_cancels() {
    let now = Instant::now();
    let mut m = two_ready(now);
    subscribe(&mut m, 1, 11, "u", now);
    subscribe(&mut m, 2, 22, "u", now);
    let out = m.tick(now + T);
    assert_eq!(to_client(&out, 1)[0]["error"]["code"], -32001);
    assert_eq!(to_client(&out, 2)[0]["id"], 22);
    assert_eq!(to_client(&out, 2)[0]["error"]["code"], -32001);
    assert_eq!(methods(&out), ["notifications/cancelled"]);
}

#[test]
fn child_exit_while_subscribe_pending_fails_both_and_does_not_resubscribe() {
    let now = Instant::now();
    let mut m = two_ready(now);
    subscribe(&mut m, 1, 11, "u", now);
    subscribe(&mut m, 2, 22, "u", now);
    let out = m.child_exited();
    for (c, id) in [(1, 11), (2, 22)] {
        assert_eq!(to_client(&out, c)[0]["id"], id);
        assert_eq!(to_client(&out, c)[0]["error"]["code"], -32000);
    }
    let out = start_legacy(&mut m, now, "s");
    assert_eq!(methods(&out), ["notifications/initialized"]);
    assert!(!any_client(&updated(&mut m, "u", now)));
}

#[test]
fn active_subscription_is_restored_after_restart_and_a_refusal_drops_it() {
    let now = Instant::now();
    let mut m = two_ready(now);
    let sent = to_child(&subscribe(&mut m, 1, 11, "u", now));
    feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":sent[0]["id"],"result":{}}),
        now,
    );
    m.child_exited();
    // restored and accepted
    let out = start_legacy(&mut m, now, "s");
    let sent = to_child(&out);
    assert_eq!(sent[1]["method"], "resources/subscribe");
    assert_eq!(sent[1]["params"]["uri"], "u");
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":sent[1]["id"],"result":{}}),
        now,
    );
    assert!(out.is_empty());
    assert_eq!(to_client(&updated(&mut m, "u", now), 1).len(), 1);
    // restored but refused: dropped with exactly one note
    m.child_exited();
    let out = start_legacy(&mut m, now, "s");
    let id = to_child(&out)[1]["id"].clone();
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"no"}}),
        now,
    );
    assert_eq!(notes(&out), 1);
    assert!(!any_client(&out));
    assert!(!any_client(&updated(&mut m, "u", now)));
}

#[test]
fn unsubscribe_from_a_non_member_is_a_noop() {
    let now = Instant::now();
    let mut m = two_ready(now);
    let sent = to_child(&subscribe(&mut m, 1, 11, "u", now));
    feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":sent[0]["id"],"result":{}}),
        now,
    );
    let unsub = r#"{"jsonrpc":"2.0","id":5,"method":"resources/unsubscribe","params":{"uri":"u"}}"#;
    let out = m.client_line(2, unsub, now);
    assert!(to_child(&out).is_empty());
    assert_eq!(to_client(&out, 2)[0]["result"], json!({}));
    assert_eq!(to_client(&updated(&mut m, "u", now), 1).len(), 1);
    // only the last active client's unsubscribe reaches the child
    let out = m.client_line(1, unsub, now);
    assert_eq!(methods(&out), ["resources/unsubscribe"]);
}

#[test]
fn in_flight_requests_are_capped_per_client() {
    let now = Instant::now();
    let mut m = two_ready(now);
    for i in 0..MAX_IN_FLIGHT_PER_CLIENT {
        let out = req(&mut m, 1, json!(i), "tools/call", now);
        assert_eq!(to_child(&out).len(), 1, "{i}");
    }
    let out = req(&mut m, 1, json!(9999), "tools/call", now);
    assert!(to_child(&out).is_empty());
    let e = &to_client(&out, 1)[0];
    assert_eq!(e["id"], 9999);
    assert_eq!(e["error"]["code"], -32000);
    assert_eq!(e["error"]["message"], "too many requests in flight");
    assert_eq!(
        to_child(&req(&mut m, 2, json!(1), "tools/call", now)).len(),
        1
    );
}

#[test]
fn queued_bytes_are_capped_per_client() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    m.client_attached(1);
    m.client_attached(2);
    let big = |id: i64| {
        let pad = "x".repeat(1024 * 1024);
        json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"pad":pad}}).to_string()
    };
    for i in 0..7 {
        assert!(m.client_line(1, &big(i), now).is_empty(), "{i}");
    }
    let out = m.client_line(1, &big(7), now);
    let e = &to_client(&out, 1)[0];
    assert_eq!(e["id"], 7);
    assert_eq!(e["error"]["message"], "mcp server not ready");
    assert!(m.client_line(2, &big(0), now).is_empty());
}

#[test]
fn a_successful_probe_result_without_supported_versions_means_legacy() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    let out = m.child_started(now);
    let id = to_child(&out)[0]["id"].clone();
    let out = feed(&mut m, json!({"jsonrpc":"2.0","id":id,"result":{}}), now);
    assert_eq!(to_child(&out)[0]["method"], "initialize");
    assert_eq!(m.era(), None);
}

#[test]
fn long_child_method_names_are_truncated_in_notes() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    let base = "\u{e9}".repeat(100); // 200 bytes: the cut must land on a char boundary
    let a = json!({"jsonrpc":"2.0","method":format!("{base}a")});
    let b = json!({"jsonrpc":"2.0","method":format!("{base}b")});
    let out = feed(&mut m, a, now);
    let Out::Note(t) = &out[0] else {
        panic!("expected a note")
    };
    assert!(t.len() < 200, "{}", t.len());
    // names that differ only after the cut are the same method for noting purposes
    assert_eq!(notes(&feed(&mut m, b, now)), 0);
}

#[test]
fn list_changed_only_reaches_clients_that_completed_the_handshake() {
    let now = Instant::now();
    let mut m = two_ready(now);
    m.client_line(1, INIT, now);
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","method":"notifications/tools/list_changed"}),
        now,
    );
    assert_eq!(to_client(&out, 1).len(), 1);
    assert!(to_client(&out, 2).is_empty());
}

#[test]
fn failed_reports_an_unusable_child() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    assert!(!m.failed());
    let out = m.child_started(now);
    let id = to_child(&out)[0]["id"].clone();
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":id,"error":{"code":-1,"message":"x"}}),
        now,
    );
    assert!(!m.failed());
    let init = to_child(&out)[0]["id"].clone();
    feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":init,"error":{"code":-1,"message":"x"}}),
        now,
    );
    assert!(m.failed());
    m.child_exited();
    assert!(!m.failed());
}

#[test]
fn initialize_timeout_fails_the_child_and_queued_requests() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    m.client_attached(1);
    let out = m.child_started(now);
    let id = to_child(&out)[0]["id"].clone();
    feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":id,"error":{"code":-1,"message":"x"}}),
        now,
    );
    // queued after the probe fell through, with a later deadline than the initialize one
    let later = now + Duration::from_secs(1);
    req(&mut m, 1, json!(4), "tools/list", later);
    let out = m.tick(now + T);
    assert!(m.failed());
    assert_eq!(notes(&out), 1);
    assert_eq!(to_client(&out, 1)[0]["id"], 4);
    assert_eq!(to_client(&out, 1)[0]["error"]["code"], -32000);
}

#[test]
fn child_exit_during_initializing_keeps_the_queue_for_the_next_child() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    m.client_attached(1);
    req(&mut m, 1, json!(4), "tools/list", now);
    let out = m.child_started(now);
    let id = to_child(&out)[0]["id"].clone();
    feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":id,"error":{"code":-1,"message":"x"}}),
        now,
    );
    assert!(m.child_exited().is_empty());
    assert_eq!(m.era(), None);
    let out = start_legacy(&mut m, now, "s");
    assert_eq!(methods(&out), ["notifications/initialized", "tools/list"]);
}

#[test]
fn a_late_reply_after_a_request_timeout_is_dropped() {
    let now = Instant::now();
    let mut m = two_ready(now);
    let hub = to_child(&req(&mut m, 1, json!(4), "tools/call", now))[0]["id"].clone();
    let out = m.tick(now + T);
    assert_eq!(to_client(&out, 1)[0]["error"]["code"], -32001);
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":hub,"result":{}}),
        now + T,
    );
    assert!(out.is_empty());
}

#[test]
fn detaching_with_queued_requests_sends_nothing_later() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    m.client_attached(1);
    req(&mut m, 1, json!(1), "tools/list", now);
    assert!(m.client_detached(1).is_empty());
    let out = start_legacy(&mut m, now, "s");
    assert_eq!(methods(&out), ["notifications/initialized"]);
}

#[test]
fn a_client_cannot_cancel_another_clients_request() {
    let now = Instant::now();
    let mut m = two_ready(now);
    let hub = to_child(&req(&mut m, 1, json!(7), "tools/call", now))[0]["id"].clone();
    let out = m.client_line(
        2,
        r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7}}"#,
        now,
    );
    assert!(out.is_empty());
    assert_eq!(m.in_flight(), 1);
    let out = feed(&mut m, json!({"jsonrpc":"2.0","id":hub,"result":{}}), now);
    assert_eq!(to_client(&out, 1)[0]["id"], 7);
}

#[test]
fn a_response_line_from_a_client_is_ignored() {
    let now = Instant::now();
    let mut m = two_ready(now);
    let out = m.client_line(1, r#"{"jsonrpc":"2.0","id":1,"result":{}}"#, now);
    assert!(out.is_empty());
}

#[test]
fn an_integer_progress_token_is_restored_as_an_integer() {
    let now = Instant::now();
    let mut m = two_ready(now);
    let out = m.client_line(
        1,
        r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"_meta":{"progressToken":42}}}"#,
        now,
    );
    let token = to_child(&out)[0]["params"]["_meta"]["progressToken"].clone();
    assert_ne!(token, json!(42));
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":token,"progress":1}}),
        now,
    );
    assert_eq!(to_client(&out, 1)[0]["params"]["progressToken"], json!(42));
}

// ---- fix round 2 ---------------------------------------------------------

fn unsubscribe(m: &mut Mux, c: ClientId, rid: i64, uri: &str, now: Instant) -> Vec<Out> {
    let line =
        json!({"jsonrpc":"2.0","id":rid,"method":"resources/unsubscribe","params":{"uri":uri}});
    m.client_line(c, &line.to_string(), now)
}
fn cancel(m: &mut Mux, c: ClientId, rid: i64, now: Instant) -> Vec<Out> {
    let line =
        json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":rid}});
    m.client_line(c, &line.to_string(), now)
}
fn is_too_many(out: &[Out], c: ClientId, msg: &str) -> bool {
    to_client(out, c)
        .iter()
        .any(|v| v["error"]["code"] == -32000 && v["error"]["message"] == msg)
}

#[test]
fn unsubscribing_while_own_subscribe_is_pending_leaves_the_uri() {
    let now = Instant::now();
    let mut m = two_ready(now);
    let sent = to_child(&subscribe(&mut m, 1, 11, "u", now));
    assert!(subscribe(&mut m, 2, 22, "u", now).is_empty());
    let out = unsubscribe(&mut m, 1, 33, "u", now);
    assert!(to_child(&out).is_empty());
    assert_eq!(to_client(&out, 1)[0]["id"], 33);
    assert_eq!(to_client(&out, 1)[0]["result"], json!({}));
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":sent[0]["id"],"result":{}}),
        now,
    );
    assert_eq!(to_client(&out, 1)[0]["id"], 11);
    assert_eq!(to_client(&out, 1)[0]["result"], json!({}));
    assert_eq!(to_client(&out, 2)[0]["id"], 22);
    assert_eq!(to_client(&out, 2)[0]["result"], json!({}));
    assert!(to_child(&out).is_empty());
    let out = updated(&mut m, "u", now);
    assert!(to_client(&out, 1).is_empty());
    assert_eq!(to_client(&out, 2).len(), 1);
}

#[test]
fn everyone_unsubscribing_while_pending_undoes_the_subscription() {
    let now = Instant::now();
    let mut m = two_ready(now);
    let sent = to_child(&subscribe(&mut m, 1, 11, "u", now));
    subscribe(&mut m, 2, 22, "u", now);
    unsubscribe(&mut m, 1, 33, "u", now);
    unsubscribe(&mut m, 2, 44, "u", now);
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":sent[0]["id"],"result":{}}),
        now,
    );
    assert_eq!(to_client(&out, 1)[0]["id"], 11);
    assert_eq!(to_client(&out, 2)[0]["id"], 22);
    assert_eq!(methods(&out), ["resources/unsubscribe"]);
    assert!(!any_client(&updated(&mut m, "u", now)));
    // entry removed: the next subscriber is first again
    assert_eq!(to_child(&subscribe(&mut m, 1, 55, "u", now)).len(), 1);
}

#[test]
fn resubscribing_while_pending_cancels_the_earlier_unsubscribe() {
    let now = Instant::now();
    let mut m = two_ready(now);
    let sent = to_child(&subscribe(&mut m, 1, 11, "u", now));
    unsubscribe(&mut m, 1, 33, "u", now);
    assert!(subscribe(&mut m, 1, 44, "u", now).is_empty());
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":sent[0]["id"],"result":{}}),
        now,
    );
    assert_eq!(to_client(&out, 1).len(), 2);
    assert_eq!(to_client(&updated(&mut m, "u", now), 1).len(), 1);
}

#[test]
fn waiters_cannot_bypass_the_in_flight_cap() {
    let now = Instant::now();
    let mut m = two_ready(now);
    let mut rejected = false;
    for i in 0..(MAX_IN_FLIGHT_PER_CLIENT as i64 * 2) {
        let uri = format!("u{i}");
        let first = 10_000 + i * 3;
        subscribe(&mut m, 1, first, &uri, now);
        let out = subscribe(&mut m, 1, first + 1, &uri, now);
        rejected |= is_too_many(&out, 1, "too many requests in flight");
        cancel(&mut m, 1, first, now);
    }
    assert!(rejected);
    assert!(m.in_flight() <= MAX_IN_FLIGHT_PER_CLIENT);
}

#[test]
fn a_client_cannot_queue_more_than_the_cap_as_a_waiter() {
    let now = Instant::now();
    let mut m = two_ready(now);
    subscribe(&mut m, 1, 1, "u", now);
    for i in 0..MAX_IN_FLIGHT_PER_CLIENT as i64 {
        assert!(subscribe(&mut m, 2, 100 + i, "u", now).is_empty(), "{i}");
    }
    let out = subscribe(&mut m, 2, 9999, "u", now);
    assert!(is_too_many(&out, 2, "too many requests in flight"));
}

#[test]
fn refused_restore_does_not_delete_a_newer_pending_subscription() {
    let now = Instant::now();
    let mut m = two_ready(now);
    m.client_attached(3);
    let sent = to_child(&subscribe(&mut m, 1, 11, "u", now));
    feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":sent[0]["id"],"result":{}}),
        now,
    );
    m.child_exited();
    let out = start_legacy(&mut m, now, "s");
    let restore = to_child(&out)[1]["id"].clone();
    m.client_detached(1);
    let sent = to_child(&subscribe(&mut m, 2, 22, "u", now));
    assert!(subscribe(&mut m, 3, 33, "u", now).is_empty());
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":restore,"error":{"code":-32601,"message":"no"}}),
        now,
    );
    assert!(out.is_empty()); // A's detach forgot the restore request
    assert!(!any_client(&out));
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":sent[0]["id"],"result":{}}),
        now,
    );
    assert_eq!(to_client(&out, 2)[0]["id"], 22);
    assert_eq!(to_client(&out, 3)[0]["id"], 33);
    assert_eq!(to_client(&out, 3)[0]["result"], json!({}));
    let out = updated(&mut m, "u", now);
    assert_eq!(to_client(&out, 2).len(), 1);
    assert_eq!(to_client(&out, 3).len(), 1);
}

#[test]
fn a_waiter_cancelling_its_subscribe_is_not_answered_nor_activated() {
    let now = Instant::now();
    let mut m = two_ready(now);
    let sent = to_child(&subscribe(&mut m, 1, 11, "u", now));
    assert!(subscribe(&mut m, 2, 22, "u", now).is_empty());
    let out = cancel(&mut m, 2, 22, now);
    assert!(out.is_empty());
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":sent[0]["id"],"result":{}}),
        now,
    );
    assert!(to_client(&out, 2).is_empty());
    assert_eq!(to_client(&out, 1)[0]["id"], 11);
    let out = updated(&mut m, "u", now);
    assert_eq!(to_client(&out, 1).len(), 1);
    assert!(to_client(&out, 2).is_empty());
}

#[test]
fn subscriptions_are_capped_per_client() {
    let now = Instant::now();
    let mut m = two_ready(now);
    for i in 0..MAX_SUBSCRIPTIONS_PER_CLIENT as i64 {
        let uri = format!("u{i}");
        let sent = to_child(&subscribe(&mut m, 1, i, &uri, now));
        let out = feed(
            &mut m,
            json!({"jsonrpc":"2.0","id":sent[0]["id"],"result":{}}),
            now,
        );
        assert_eq!(to_client(&out, 1)[0]["result"], json!({}), "{i}");
    }
    let out = subscribe(&mut m, 1, 99_999, "extra", now);
    assert!(to_child(&out).is_empty());
    assert!(is_too_many(&out, 1, "too many subscriptions"));
    // re-subscribing to one already held is still fine; another client is unaffected
    let out = subscribe(&mut m, 1, 99_998, "u0", now);
    assert_eq!(to_client(&out, 1)[0]["result"], json!({}));
    assert_eq!(to_child(&subscribe(&mut m, 2, 1, "extra", now)).len(), 1);
}

// ---- task 3: stateless generation -----------------------------------------

const DISCOVER: &str = r#"{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{}},"instructions":"be nice","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"s","version":"1"}}}"#;
const MODERN_META: &str = "io.modelcontextprotocol/protocolVersion";

fn start_stateless(m: &mut Mux, now: Instant) -> Vec<Out> {
    let out = m.child_started(now);
    let probe = to_child(&out)[0]["id"].clone();
    let result: Value = serde_json::from_str(DISCOVER).unwrap();
    let out = feed(m, json!({"jsonrpc":"2.0","id":probe,"result":result}), now);
    assert_eq!(m.era(), Some(Era::Stateless));
    out
}
fn stateless_two(now: Instant) -> Mux {
    let mut m = Mux::new("docs", T);
    start_stateless(&mut m, now);
    m.client_attached(1);
    m.client_attached(2);
    m
}
fn modern_line(rid: i64, method: &str, extra: Value) -> String {
    let mut meta =
        json!({MODERN_META: "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {"x":1}});
    if let Some(o) = extra.as_object() {
        for (k, v) in o {
            meta[k] = v.clone();
        }
    }
    json!({"jsonrpc":"2.0","id":rid,"method":method,"params":{"_meta":meta}}).to_string()
}

#[test]
fn discover_result_selects_stateless_without_initialize() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    let out = start_stateless(&mut m, now);
    assert!(to_child(&out).is_empty());
    assert_eq!(notes(&out), 0);
    assert!(!m.failed());
}

#[test]
fn queued_requests_are_served_once_stateless_is_known() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    m.client_attached(1);
    req(&mut m, 1, json!(5), "tools/list", now);
    let out = start_stateless(&mut m, now);
    let sent = to_child(&out);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["method"], "tools/list");
    assert_eq!(sent[0]["params"]["_meta"][MODERN_META], "2026-07-28");
}

#[test]
fn modern_client_passes_through_with_its_own_meta() {
    let now = Instant::now();
    let mut m = stateless_two(now);
    let line = modern_line(9, "tools/list", json!({}));
    let out = m.client_line(1, &line, now);
    let sent = &to_child(&out)[0];
    let orig: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(sent["params"], orig["params"]);
    assert_eq!(
        sent["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"],
        json!({"x":1})
    );
    assert_ne!(sent["id"], 9);
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":sent["id"],"result":{"resultType":"complete","tools":[]}}),
        now,
    );
    assert_eq!(to_client(&out, 1)[0]["id"], 9);
    assert_eq!(to_client(&out, 1)[0]["result"]["tools"], json!([]));
    assert_eq!(m.in_flight(), 0);
}

#[test]
fn modern_client_discover_is_served_from_cache() {
    let now = Instant::now();
    let mut m = stateless_two(now);
    let out = m.client_line(1, &modern_line(3, "server/discover", json!({})), now);
    assert!(to_child(&out).is_empty());
    assert_eq!(to_client(&out, 1)[0]["id"], 3);
    assert_eq!(
        to_client(&out, 1)[0]["result"]["supportedVersions"],
        json!(["2026-07-28"])
    );
    assert_eq!(
        to_client(&out, 1)[0]["result"]["capabilities"],
        json!({"tools":{}})
    );
}

#[test]
fn modern_client_keeps_input_required_results() {
    let now = Instant::now();
    let mut m = stateless_two(now);
    let sent = to_child(&m.client_line(1, &modern_line(3, "tools/call", json!({})), now));
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":sent[0]["id"],"result":{"resultType":"input_required","inputRequests":{}}}),
        now,
    );
    assert_eq!(
        to_client(&out, 1)[0]["result"]["resultType"],
        "input_required"
    );
}

#[test]
fn legacy_client_on_stateless_child_gets_synthetic_initialize_and_meta_injection() {
    let now = Instant::now();
    let mut m = stateless_two(now);
    let out = m.client_line(1, INIT, now);
    assert!(to_child(&out).is_empty());
    let r = &to_client(&out, 1)[0]["result"];
    assert_eq!(r["protocolVersion"], "2025-11-25");
    assert_eq!(r["serverInfo"]["name"], "s");
    assert!(r["capabilities"].get("tools").is_some());
    assert_eq!(r["instructions"], "be nice");
    let line = r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"t","_meta":{"progressToken":"p"}}}"#;
    let sent = to_child(&m.client_line(1, line, now));
    let meta = &sent[0]["params"]["_meta"];
    assert_eq!(meta[MODERN_META], "2026-07-28");
    assert_eq!(
        meta["io.modelcontextprotocol/clientCapabilities"],
        json!({})
    );
    assert_eq!(
        meta["io.modelcontextprotocol/clientInfo"]["name"],
        "sync_gate_hub"
    );
    assert_eq!(sent[0]["params"]["name"], "t");
    // a request with no params at all also gets the meta
    let sent = to_child(&req(&mut m, 1, json!(5), "tools/list", now));
    assert_eq!(sent[0]["params"]["_meta"][MODERN_META], "2026-07-28");
    // ping and setLevel stay with the hub
    for method in ["ping", "logging/setLevel"] {
        let out = req(&mut m, 1, json!(6), method, now);
        assert!(to_child(&out).is_empty());
        assert_eq!(to_client(&out, 1)[0]["result"], json!({}));
    }
    // discover is modern only: without its required `_meta` it is malformed (-32602)
    let out = req(&mut m, 1, json!(7), "server/discover", now);
    assert_eq!(to_client(&out, 1)[0]["error"]["code"], -32602);
}

#[test]
fn unsupported_version_error_does_not_fall_back_to_initialize() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    m.client_attached(1);
    req(&mut m, 1, json!(5), "tools/list", now);
    let out = m.child_started(now);
    let id = to_child(&out)[0]["id"].clone();
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":id,"error":{"code":-32022,"message":"x"}}),
        now,
    );
    assert!(to_child(&out).is_empty());
    assert_eq!(notes(&out), 1);
    assert_eq!(to_client(&out, 1)[0]["id"], 5);
    assert_eq!(to_client(&out, 1)[0]["error"]["code"], -32000);
    assert_eq!(
        to_client(&out, 1)[0]["error"]["message"],
        "mcp server speaks no supported version"
    );
    let out = req(&mut m, 1, json!(6), "tools/list", now);
    assert_eq!(
        to_client(&out, 1)[0]["error"]["message"],
        "mcp server speaks no supported version"
    );
    assert!(to_child(&out).is_empty());
    assert!(m.unsupported());
    assert!(!m.failed());
    // the probe deadline passing must not start initialize either
    assert!(to_child(&m.tick(now + PROBE_TIMEOUT)).is_empty());
}

#[test]
fn discover_result_without_the_modern_version_is_unsupported() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    let out = m.child_started(now);
    let id = to_child(&out)[0]["id"].clone();
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":id,"result":{"supportedVersions":["2027-01-01"]}}),
        now,
    );
    assert!(to_child(&out).is_empty());
    assert_eq!(notes(&out), 1);
    m.client_attached(1);
    let out = req(&mut m, 1, json!(1), "tools/list", now);
    assert_eq!(
        to_client(&out, 1)[0]["error"]["message"],
        "mcp server speaks no supported version"
    );
}

#[test]
fn input_required_for_a_legacy_client_becomes_an_error() {
    let now = Instant::now();
    let mut m = stateless_two(now);
    let hub = to_child(&req(&mut m, 1, json!(8), "tools/call", now))[0]["id"].clone();
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":hub,"result":{"resultType":"input_required","inputRequests":{}}}),
        now,
    );
    let e = &to_client(&out, 1)[0];
    assert_eq!(e["id"], 8);
    assert_eq!(e["error"]["code"], -32000);
    assert_eq!(
        e["error"]["message"],
        "server requires input not supported through the hub"
    );
    assert!(e.get("result").is_none());
    // a complete result still goes through
    let hub = to_child(&req(&mut m, 1, json!(9), "tools/call", now))[0]["id"].clone();
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":hub,"result":{"resultType":"complete","content":[]}}),
        now,
    );
    assert_eq!(to_client(&out, 1)[0]["result"]["content"], json!([]));
}

#[test]
fn stateless_keeps_progress_cancel_caps_detach_timeout_and_restart() {
    let now = Instant::now();
    let mut m = stateless_two(now);
    // progress token rewrite (modern client) and cancel translation
    let out = m.client_line(
        1,
        &modern_line(7, "tools/call", json!({"progressToken":"p"})),
        now,
    );
    let sent = &to_child(&out)[0];
    let token = sent["params"]["_meta"]["progressToken"].clone();
    assert_ne!(token, json!("p"));
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":token,"progress":1}}),
        now,
    );
    assert_eq!(to_client(&out, 1)[0]["params"]["progressToken"], "p");
    assert!(to_client(&out, 2).is_empty());
    let out = cancel(&mut m, 1, 7, now);
    assert_eq!(to_child(&out)[0]["params"]["requestId"], sent["id"]);
    assert_eq!(m.in_flight(), 0);
    // per-client cap
    for i in 0..MAX_IN_FLIGHT_PER_CLIENT {
        assert_eq!(
            to_child(&req(&mut m, 1, json!(i), "tools/call", now)).len(),
            1
        );
    }
    let out = req(&mut m, 1, json!(9999), "tools/call", now);
    assert!(is_too_many(&out, 1, "too many requests in flight"));
    // detach cancels, timeout answers
    let out = m.client_detached(1);
    assert_eq!(to_child(&out).len(), MAX_IN_FLIGHT_PER_CLIENT);
    let hub = to_child(&req(&mut m, 2, json!(1), "tools/call", now))[0]["id"].clone();
    let out = m.tick(now + T);
    assert_eq!(to_client(&out, 2)[0]["error"]["code"], -32001);
    assert_eq!(to_child(&out)[0]["params"]["requestId"], hub);
    // child exit fails in flight and returns to the probe
    req(&mut m, 2, json!(2), "tools/call", now);
    let out = m.child_exited();
    assert_eq!(
        to_client(&out, 2)[0]["error"]["message"],
        "mcp server restarted"
    );
    assert_eq!(m.era(), None);
    let out = m.child_started(now);
    assert_eq!(to_child(&out)[0]["method"], "server/discover");
}

#[test]
fn subscriptions_are_refused_on_a_stateless_child_with_one_note() {
    let now = Instant::now();
    let mut m = stateless_two(now);
    let mut total_notes = 0;
    for method in [
        "resources/subscribe",
        "resources/unsubscribe",
        "subscriptions/listen",
    ] {
        let line = json!({"jsonrpc":"2.0","id":1,"method":method,"params":{"uri":"u"}});
        let out = m.client_line(1, &line.to_string(), now);
        assert!(to_child(&out).is_empty(), "{method}");
        let e = &to_client(&out, 1)[0]["error"];
        assert_eq!(e["code"], -32601);
        assert_eq!(
            e["message"],
            "subscriptions are not supported through the hub for this server"
        );
        total_notes += notes(&out);
    }
    assert_eq!(total_notes, 1);
}

#[test]
fn a_late_restore_timeout_does_not_drop_a_newer_active_subscription() {
    let now = Instant::now();
    let mut m = two_ready(now);
    let sent = to_child(&subscribe(&mut m, 1, 11, "u", now));
    feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":sent[0]["id"],"result":{}}),
        now,
    );
    m.child_exited();
    start_legacy(&mut m, now, "s"); // restore of "u" in flight
    m.client_detached(1);
    let sent = to_child(&subscribe(&mut m, 2, 22, "u", now));
    feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":sent[0]["id"],"result":{}}),
        now,
    );
    // the old restore times out late: B's subscription survives
    let out = m.tick(now + T);
    assert!(to_child(&out).is_empty());
    assert_eq!(notes(&out), 0);
    assert_eq!(to_client(&updated(&mut m, "u", now), 2).len(), 1);
}

#[test]
fn a_late_restore_refusal_does_not_touch_an_entry_after_unsubscribe() {
    let now = Instant::now();
    let mut m = two_ready(now);
    let sent = to_child(&subscribe(&mut m, 1, 11, "u", now));
    feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":sent[0]["id"],"result":{}}),
        now,
    );
    m.child_exited();
    let out = start_legacy(&mut m, now, "s");
    let restore = to_child(&out)[1]["id"].clone();
    let out = unsubscribe(&mut m, 1, 12, "u", now);
    assert_eq!(methods(&out), ["resources/unsubscribe"]);
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":restore,"error":{"code":-1,"message":"x"}}),
        now,
    );
    assert!(out.is_empty());
    assert_eq!(m.in_flight(), 1); // only the unsubscribe request
}

// ---- task 3 fix round 1 ---------------------------------------------------

#[test]
fn unsupported_is_not_failed() {
    let now = Instant::now();
    let cases = [
        json!({"error":{"code":-32022,"message":"x"}}),
        json!({"result":{"supportedVersions":["2027-01-01"]}}),
    ];
    for body in cases {
        let mut m = Mux::new("docs", T);
        let out = m.child_started(now);
        let mut reply = body;
        reply["jsonrpc"] = json!("2.0");
        reply["id"] = to_child(&out)[0]["id"].clone();
        feed(&mut m, reply, now);
        assert!(m.unsupported());
        assert!(!m.failed());
        m.child_exited();
        assert!(!m.unsupported());
    }
    let mut m = Mux::new("docs", T);
    let out = m.child_started(now);
    let id = to_child(&out)[0]["id"].clone();
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":id,"error":{"code":-1,"message":"x"}}),
        now,
    );
    let init = to_child(&out)[0]["id"].clone();
    feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":init,"error":{"code":-1,"message":"x"}}),
        now,
    );
    assert!(m.failed());
    assert!(!m.unsupported());
}

fn stateless_with(discover: Value, now: Instant) -> Mux {
    let mut m = Mux::new("docs", T);
    let out = m.child_started(now);
    let probe = to_child(&out)[0]["id"].clone();
    feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":probe,"result":discover}),
        now,
    );
    m.client_attached(1);
    m
}

#[test]
fn advertised_capabilities_drop_what_the_hub_refuses() {
    let now = Instant::now();
    let d = json!({"supportedVersions":["2026-07-28"],"capabilities":{
        "tools":{"listChanged":true},"prompts":{"listChanged":true,"x":1},
        "resources":{"subscribe":true,"listChanged":true,"y":2},"logging":{}}});
    let mut m = stateless_with(d, now);
    let want = json!({"tools":{},"prompts":{"x":1},"resources":{"y":2},"logging":{}});
    let out = m.client_line(1, INIT, now);
    assert_eq!(to_client(&out, 1)[0]["result"]["capabilities"], want);
    let out = m.client_line(1, &modern_line(2, "server/discover", json!({})), now);
    assert_eq!(to_client(&out, 1)[0]["result"]["capabilities"], want);
    // keys that do not exist are not invented
    let d = json!({"supportedVersions":["2026-07-28"],"capabilities":{"tools":{}}});
    let mut m = stateless_with(d, now);
    let out = m.client_line(1, INIT, now);
    assert_eq!(
        to_client(&out, 1)[0]["result"]["capabilities"],
        json!({"tools":{}})
    );
}

#[test]
fn a_legacy_to_stateless_restart_clears_old_subscriptions() {
    let now = Instant::now();
    let mut m = two_ready(now);
    let sent = to_child(&subscribe(&mut m, 1, 11, "u", now));
    feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":sent[0]["id"],"result":{}}),
        now,
    );
    m.child_exited();
    // restore request in flight on a legacy child, then the child restarts as stateless
    start_legacy(&mut m, now, "s");
    m.child_exited();
    start_stateless(&mut m, now);
    assert_eq!(m.in_flight(), 0);
    let out = subscribe(&mut m, 1, 12, "u", now);
    assert_eq!(to_client(&out, 1)[0]["error"]["code"], -32601);
    assert!(!any_client(&updated(&mut m, "u", now)));
    // same for a restart into the unsupported state
    let mut m = two_ready(now);
    let sent = to_child(&subscribe(&mut m, 1, 11, "u", now));
    feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":sent[0]["id"],"result":{}}),
        now,
    );
    m.child_exited();
    let out = m.child_started(now);
    let id = to_child(&out)[0]["id"].clone();
    feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":id,"error":{"code":-32022,"message":"x"}}),
        now,
    );
    assert!(!any_client(&updated(&mut m, "u", now)));
}

#[test]
fn a_legacy_version_is_rewritten_except_on_discover_which_gets_32022() {
    let now = Instant::now();
    let mut m = stateless_two(now);
    for v in [json!("2025-11-25"), json!("2024-11-05")] {
        let line = json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{MODERN_META: v}}});
        let sent = to_child(&m.client_line(1, &line.to_string(), now));
        // legacy: the hub's own meta replaces the client's value
        assert_eq!(sent[0]["params"]["_meta"][MODERN_META], "2026-07-28", "{v}");
        // discover is modern only: a legacy version is one the hub does not serve there
        let line = json!({"jsonrpc":"2.0","id":2,"method":"server/discover","params":{"_meta":{MODERN_META: v}}});
        let out = m.client_line(1, &line.to_string(), now);
        let e = &to_client(&out, 1)[0]["error"];
        assert_eq!(e["code"], -32022, "{v}");
        assert_eq!(e["data"]["requested"], v);
    }
    let out = m.client_line(1, &modern_line(3, "server/discover", json!({})), now);
    assert!(to_client(&out, 1)[0].get("result").is_some());
}

#[test]
fn legacy_and_modern_clients_interleave_on_one_stateless_child() {
    let now = Instant::now();
    let mut m = stateless_two(now);
    let a = to_child(&req(&mut m, 1, json!(1), "tools/call", now))[0]["id"].clone();
    let b =
        to_child(&m.client_line(2, &modern_line(1, "tools/call", json!({})), now))[0]["id"].clone();
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":b,"result":{"resultType":"input_required"}}),
        now,
    );
    assert!(to_client(&out, 1).is_empty());
    assert_eq!(
        to_client(&out, 2)[0]["result"]["resultType"],
        "input_required"
    );
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":a,"result":{"resultType":"complete","ok":1}}),
        now,
    );
    assert!(to_client(&out, 2).is_empty());
    assert_eq!(to_client(&out, 1)[0]["result"]["ok"], 1);
    assert_eq!(m.in_flight(), 0);
}

#[test]
fn one_client_can_mix_legacy_and_modern_requests() {
    let now = Instant::now();
    let mut m = stateless_two(now);
    let a = to_child(&req(&mut m, 1, json!(1), "tools/list", now))[0]["id"].clone();
    let b =
        to_child(&m.client_line(1, &modern_line(2, "tools/list", json!({})), now))[0]["id"].clone();
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":b,"result":{"resultType":"input_required"}}),
        now,
    );
    assert_eq!(to_client(&out, 1)[0]["id"], 2);
    assert_eq!(
        to_client(&out, 1)[0]["result"]["resultType"],
        "input_required"
    );
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":a,"result":{"resultType":"input_required"}}),
        now,
    );
    assert_eq!(to_client(&out, 1)[0]["id"], 1);
    assert_eq!(to_client(&out, 1)[0]["error"]["code"], -32000);
}

#[test]
fn odd_legacy_params_are_forwarded_unchanged_without_panic() {
    let now = Instant::now();
    let mut m = stateless_two(now);
    for params in [json!([1, 2]), json!({"_meta": 5, "k": 1})] {
        let line = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":params});
        let sent = to_child(&m.client_line(1, &line.to_string(), now));
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0]["params"], params);
    }
    let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":null}"#;
    assert_eq!(to_child(&m.client_line(1, line, now)).len(), 1);
}

#[test]
fn modern_retry_with_input_responses_reaches_the_child_unchanged() {
    let now = Instant::now();
    let mut m = stateless_two(now);
    let first = to_child(&m.client_line(1, &modern_line(1, "tools/call", json!({})), now));
    feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":first[0]["id"],"result":{"resultType":"input_required","inputRequests":{"a":{}},"requestState":"st"}}),
        now,
    );
    assert_eq!(m.in_flight(), 0);
    let mut retry: Value = serde_json::from_str(&modern_line(2, "tools/call", json!({}))).unwrap();
    retry["params"]["inputResponses"] = json!({"a":{"action":"accept"}});
    retry["params"]["requestState"] = json!("st");
    let sent = to_child(&m.client_line(1, &retry.to_string(), now));
    assert_eq!(sent[0]["params"], retry["params"]);
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":sent[0]["id"],"result":{"resultType":"complete"}}),
        now,
    );
    assert_eq!(to_client(&out, 1)[0]["id"], 2);
    assert_eq!(m.in_flight(), 0);
}

#[test]
fn synthetic_server_info_falls_back_without_discover_meta() {
    let now = Instant::now();
    let d = json!({"supportedVersions":["2026-07-28"],"capabilities":{}});
    let mut m = stateless_with(d, now);
    let out = m.client_line(1, INIT, now);
    let r = &to_client(&out, 1)[0]["result"];
    assert_eq!(r["serverInfo"]["name"], "docs");
    assert_eq!(r["serverInfo"]["version"], "unknown");
    assert!(r.get("instructions").is_none());
}

#[test]
// A request with clientCapabilities but no protocolVersion is a malformed modern one (see
// `a_malformed_modern_request_is_invalid_params_not_legacy`); the optional clientInfo alone keeps
// a request legacy, and the hub's own fields replace the client's.
fn a_legacy_client_own_meta_fields_are_replaced() {
    let now = Instant::now();
    let mut m = stateless_two(now);
    let line = json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{
        "io.modelcontextprotocol/clientInfo":{"name":"c","version":"1"},"keep":1}}});
    let sent = to_child(&m.client_line(1, &line.to_string(), now));
    let meta = &sent[0]["params"]["_meta"];
    assert_eq!(
        meta["io.modelcontextprotocol/clientCapabilities"],
        json!({})
    );
    assert_eq!(
        meta["io.modelcontextprotocol/clientInfo"]["name"],
        "sync_gate_hub"
    );
    assert_eq!(meta["keep"], 1);
}

#[test]
fn pool_accessors_report_readiness_subscriptions_and_handshake() {
    let mut m = Mux::new("docs", T);
    let now = Instant::now();
    assert!(!m.ready());
    m.child_started(now);
    assert!(!m.ready(), "probing is not ready");
    let mut m = Mux::new("docs", T);
    ready(&mut m, now);
    assert!(m.ready());
    m.client_attached(1);
    m.client_attached(2);
    assert!(!m.handshaken(1));
    m.client_line(1, INIT, now);
    assert!(m.handshaken(1));
    // A client handshaken on another instance of the pool gets broadcasts here too.
    m.mark_handshaken(2);
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","method":"notifications/tools/list_changed"}),
        now,
    );
    assert_eq!(to_client(&out, 2).len(), 1);
    m.mark_handshaken(9);
    assert!(!m.handshaken(9), "unknown clients are not tracked");
    // Pending, then active, then released.
    let sub = r#"{"jsonrpc":"2.0","id":1,"method":"resources/subscribe","params":{"uri":"u"}}"#;
    assert!(!m.holds_subscriptions(1));
    let sent = to_child(&m.client_line(1, sub, now));
    assert!(m.holds_subscriptions(1), "pending subscribe");
    let wait = m.client_line(2, sub, now);
    assert!(wait.is_empty());
    assert!(m.holds_subscriptions(2), "waiter");
    feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":sent[0]["id"],"result":{}}),
        now,
    );
    assert!(m.holds_subscriptions(1) && m.holds_subscriptions(2));
    let unsub = r#"{"jsonrpc":"2.0","id":2,"method":"resources/unsubscribe","params":{"uri":"u"}}"#;
    m.client_line(1, unsub, now);
    assert!(!m.holds_subscriptions(1));
    m.client_detached(2);
    assert!(!m.holds_subscriptions(2));
    // Stateless children are ready too.
    let m = stateless_two(now);
    assert!(m.ready());
}

// ---- #2 item 20 and item 13 (MCP 2026-07-28) ----------------------------

// JSON-RPC 2.0, section 4 (Request object: "jsonrpc" MUST be exactly "2.0") and 5.1 (-32600
// Invalid Request); MCP 2026-07-28 basic/transports/stdio: the client MUST NOT write anything to
// the server's stdin that is not a valid MCP message, so the hub forwards none of these.
#[test]
fn a_client_request_without_jsonrpc_2_0_is_invalid() {
    let now = Instant::now();
    let mut m = two_ready(now);
    for (i, envelope) in [
        None,
        Some(json!("1.0")),
        Some(json!(2.0)),
        Some(json!(null)),
    ]
    .into_iter()
    .enumerate()
    {
        let mut line = json!({"id":i,"method":"tools/list"});
        if let Some(e) = &envelope {
            line["jsonrpc"] = e.clone();
        }
        let out = m.client_line(1, &line.to_string(), now);
        assert!(to_child(&out).is_empty(), "{envelope:?}");
        let e = &to_client(&out, 1)[0];
        assert_eq!(e["error"]["code"], -32600, "{envelope:?}");
        assert_eq!(e["id"], i, "{envelope:?}");
    }
    // an `initialize` without it is no handshake either
    let out = m.client_line(1, &INIT.replace(r#""jsonrpc":"2.0","#, ""), now);
    assert_eq!(to_client(&out, 1)[0]["error"]["code"], -32600);
    assert!(!m.handshaken(1));
    // queued phases refuse it too: it never waits for the child
    let mut q = Mux::new("docs", T);
    q.client_attached(1);
    let out = q.client_line(1, r#"{"id":4,"method":"tools/list"}"#, now);
    assert_eq!(to_client(&out, 1)[0]["error"]["code"], -32600);
    // a well-formed request still goes through
    let out = req(&mut m, 1, json!(9), "tools/list", now);
    assert_eq!(to_child(&out).len(), 1);
}

// JSON-RPC 2.0, section 4.1: the server MUST NOT reply to a notification; without "jsonrpc":"2.0"
// it is no valid message (section 4), so it has no effect: dropped, with one note.
#[test]
fn a_client_notification_without_jsonrpc_is_dropped_with_a_note() {
    let now = Instant::now();
    let mut m = two_ready(now);
    let hub = to_child(&req(&mut m, 1, json!(7), "tools/call", now))[0]["id"].clone();
    let mut total_notes = 0;
    for _ in 0..2 {
        let out = m.client_line(
            1,
            r#"{"method":"notifications/cancelled","params":{"requestId":7}}"#,
            now,
        );
        assert!(!any_client(&out));
        assert!(to_child(&out).is_empty(), "no cancel reaches the child");
        total_notes += notes(&out);
    }
    assert_eq!(total_notes, 1);
    assert_eq!(m.in_flight(), 1, "the request is still in flight");
    let out = feed(&mut m, json!({"jsonrpc":"2.0","id":hub,"result":{}}), now);
    assert_eq!(to_client(&out, 1)[0]["id"], 7);
}

// MCP 2026-07-28 basic/patterns/subscriptions, "Opening a Stream": the server MUST NOT send
// notification types the client has not explicitly requested. A modern client never sent
// `initialize`, so a child's list_changed is not for it; legacy clients still get it.
#[test]
fn a_modern_client_gets_no_list_changed_it_did_not_request() {
    let now = Instant::now();
    for mut m in [stateless_two(now), two_ready(now)] {
        m.client_line(1, &modern_line(1, "tools/list", json!({})), now);
        m.client_line(2, INIT, now);
        assert!(!m.handshaken(1), "a modern request is no handshake");
        let out = feed(
            &mut m,
            json!({"jsonrpc":"2.0","method":"notifications/tools/list_changed"}),
            now,
        );
        assert!(to_client(&out, 1).is_empty());
        assert_eq!(to_client(&out, 2).len(), 1);
    }
}

// MCP 2026-07-28 basic/versioning, "Protocol Version Negotiation": a server that does not
// implement the requested version MUST respond with UnsupportedProtocolVersionError (-32022)
// listing the versions it supports in `data.supported`, with `data.requested`.
#[test]
fn a_modern_request_in_a_version_the_hub_does_not_serve_gets_32022() {
    let now = Instant::now();
    let mut m = stateless_two(now);
    for method in ["tools/list", "server/discover", "ping"] {
        let mut line: Value = serde_json::from_str(&modern_line(3, method, json!({}))).unwrap();
        line["params"]["_meta"][MODERN_META] = json!("2099-01-01");
        let out = m.client_line(1, &line.to_string(), now);
        assert!(to_child(&out).is_empty(), "{method}");
        let e = &to_client(&out, 1)[0];
        assert_eq!(e["id"], 3);
        assert_eq!(e["error"]["code"], -32022, "{method}");
        assert_eq!(e["error"]["data"]["supported"], json!(["2026-07-28"]));
        assert_eq!(e["error"]["data"]["requested"], "2099-01-01");
    }
    assert_eq!(m.in_flight(), 0);
}

fn unsupported_one(now: Instant, queued: &[String]) -> (Mux, Vec<Out>) {
    let mut m = Mux::new("docs", T);
    m.client_attached(1);
    for line in queued {
        assert!(m.client_line(1, line, now).is_empty(), "queued");
    }
    let id = to_child(&m.child_started(now))[0]["id"].clone();
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":id,"result":{"supportedVersions":["2027-01-01"]}}),
        now,
    );
    assert!(m.unsupported());
    (m, out)
}

// Same section: through the hub, a child it cannot speak to supports no version at all, so a
// modern request (queued or new) gets -32022 with an empty `supported`: the client surfaces an
// error instead of retrying. Legacy requests keep their error.
#[test]
fn an_unsupported_child_answers_32022_with_supported_versions() {
    let now = Instant::now();
    let (mut m, out) = unsupported_one(
        now,
        &[
            modern_line(1, "tools/list", json!({})),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}).to_string(),
        ],
    );
    let replies = to_client(&out, 1);
    assert_eq!(replies[0]["id"], 1);
    assert_eq!(replies[0]["error"]["code"], -32022);
    assert_eq!(replies[0]["error"]["data"]["supported"], json!([]));
    assert_eq!(replies[0]["error"]["data"]["requested"], "2026-07-28");
    assert_eq!(replies[1]["id"], 2);
    assert_eq!(replies[1]["error"]["message"], NO_VERSION);
    let out = m.client_line(1, &modern_line(3, "server/discover", json!({})), now);
    let e = &to_client(&out, 1)[0]["error"];
    assert_eq!(e["code"], -32022);
    assert_eq!(e["data"]["supported"], json!([]));
    let out = req(&mut m, 1, json!(4), "tools/list", now);
    assert_eq!(to_client(&out, 1)[0]["error"]["message"], NO_VERSION);
}

// Same section: `server/discover` is modern whatever version it names (legacy revisions have
// none), so through an unsupported child one naming a legacy version also gets -32022, queued
// or new, as `serve` classifies it on a stateless child.
#[test]
fn an_unsupported_child_answers_32022_to_a_discover_naming_a_legacy_version() {
    let now = Instant::now();
    let discover = |rid: i64| {
        let mut line: Value =
            serde_json::from_str(&modern_line(rid, "server/discover", json!({}))).unwrap();
        line["params"]["_meta"][MODERN_META] = json!("2025-11-25");
        line.to_string()
    };
    let (mut m, out) = unsupported_one(now, &[discover(1)]);
    let queued = to_client(&out, 1);
    let new = to_client(&m.client_line(1, &discover(2), now), 1);
    for (what, e) in [("queued", &queued[0]), ("new", &new[0])] {
        assert_eq!(e["error"]["code"], -32022, "{what}: {e}");
        assert_eq!(e["error"]["data"]["supported"], json!([]), "{what}");
        assert_eq!(e["error"]["data"]["requested"], "2025-11-25", "{what}");
    }
}

// MCP 2026-07-28 basic, "ResultType": the `result` MUST include a `resultType` field. Results the
// hub makes itself for a modern request say "complete"; a legacy client's stay as they were.
#[test]
fn local_results_to_a_modern_request_carry_result_type() {
    let now = Instant::now();
    let mut m = stateless_two(now);
    for method in ["ping", "logging/setLevel"] {
        let out = m.client_line(1, &modern_line(5, method, json!({})), now);
        assert!(to_child(&out).is_empty(), "{method}");
        assert_eq!(
            to_client(&out, 1)[0]["result"],
            json!({"resultType":"complete"}),
            "{method}"
        );
        let out = req(&mut m, 2, json!(6), method, now);
        assert_eq!(to_client(&out, 2)[0]["result"], json!({}), "{method}");
    }
}

// MCP 2026-07-28 basic, "_meta" (per-request protocol fields): protocolVersion and
// clientCapabilities are required; a request missing one is malformed and the server MUST
// reject it with -32602.
#[test]
fn a_modern_request_without_client_capabilities_is_invalid_params() {
    let now = Instant::now();
    let mut m = stateless_two(now);
    for method in ["tools/list", "ping", "server/discover"] {
        let line = json!({"jsonrpc":"2.0","id":8,"method":method,
            "params":{"_meta":{MODERN_META:"2026-07-28"}}});
        let out = m.client_line(1, &line.to_string(), now);
        assert!(to_child(&out).is_empty(), "{method}");
        assert_eq!(to_client(&out, 1)[0]["error"]["code"], -32602, "{method}");
        assert_eq!(to_client(&out, 1)[0]["id"], 8);
    }
    assert_eq!(m.in_flight(), 0);
}

// MCP 2026-07-28 basic/patterns/subscriptions, "Acknowledgment": the server MUST send
// `notifications/subscriptions/acknowledged` first, carrying the subscription id (the listen
// request's id) in `_meta`; types it does not support are omitted. The hub opens no stream on
// the child, so it honors none: an empty filter, nothing sent to the child, then a completion
// result that ends the subscription at once (basic/index: all implementations MUST support the
// message patterns).
#[test]
fn subscriptions_listen_is_acknowledged_with_no_notification_types() {
    let now = Instant::now();
    let mut m = stateless_two(now);
    let mut line: Value =
        serde_json::from_str(&modern_line(11, "subscriptions/listen", json!({}))).unwrap();
    line["params"]["notifications"] =
        json!({"toolsListChanged":true,"resourceSubscriptions":["file:///a"]});
    let out = m.client_line(1, &line.to_string(), now);
    assert!(to_child(&out).is_empty());
    let sent = to_client(&out, 1);
    assert_eq!(
        sent.len(),
        2,
        "the acknowledgment, then the end of the stream"
    );
    assert_eq!(
        sent[0],
        json!({"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged",
            "params":{"_meta":{"io.modelcontextprotocol/subscriptionId":11},"notifications":{}}})
    );
    // "Graceful Closure": a server ending a subscription on its own SHOULD answer the listen
    // request with a completion result carrying the subscription id; nothing stays open.
    assert_eq!(
        sent[1],
        json!({"jsonrpc":"2.0","id":11,"result":{"resultType":"complete",
            "_meta":{"io.modelcontextprotocol/subscriptionId":11}}})
    );
    assert_eq!(m.in_flight(), 0);
    assert!(!m.holds_subscriptions(1));
    // the child's list_changed still does not reach it
    let out = feed(
        &mut m,
        json!({"jsonrpc":"2.0","method":"notifications/tools/list_changed"}),
        now,
    );
    assert!(to_client(&out, 1).is_empty());
}

// MCP 2026-07-28 basic/versioning: the hub answers -32022 for any version but 2026-07-28, so its
// `server/discover` must list only that one, whatever else the child supports.
#[test]
fn discover_lists_only_the_version_the_hub_serves() {
    let now = Instant::now();
    let mut m = Mux::new("docs", T);
    let id = to_child(&m.child_started(now))[0]["id"].clone();
    feed(
        &mut m,
        json!({"jsonrpc":"2.0","id":id,"result":{"resultType":"complete",
            "supportedVersions":["2027-01-01","2026-07-28"],"capabilities":{}}}),
        now,
    );
    assert_eq!(m.era(), Some(Era::Stateless));
    m.client_attached(1);
    let out = m.client_line(1, &modern_line(1, "server/discover", json!({})), now);
    assert_eq!(
        to_client(&out, 1)[0]["result"]["supportedVersions"],
        json!(["2026-07-28"])
    );
}

// MCP 2026-07-28 basic, "_meta": a request that carries per-request protocol fields is modern
// even when one is missing or of the wrong type; it is malformed (-32602), not a legacy request
// (whose discover would get -32601 and send the client back to `initialize`).
#[test]
fn a_malformed_modern_request_is_invalid_params_not_legacy() {
    let now = Instant::now();
    let mut m = stateless_two(now);
    let caps = "io.modelcontextprotocol/clientCapabilities";
    // `server/discover` exists only in the modern revision: even an empty `_meta` makes it one
    for meta in [json!({}), json!(null)] {
        let line =
            json!({"jsonrpc":"2.0","id":8,"method":"server/discover","params":{"_meta":meta}});
        let out = m.client_line(1, &line.to_string(), now);
        assert_eq!(to_client(&out, 1)[0]["error"]["code"], -32602, "{meta}");
    }
    for meta in [
        json!({caps: {}}),
        json!({MODERN_META: null, caps: {}}),
        json!({MODERN_META: 5, caps: {}}),
        json!({MODERN_META: "2026-07-28", caps: null}),
        json!({MODERN_META: "2026-07-28", caps: []}),
    ] {
        for method in ["server/discover", "tools/list"] {
            let line =
                json!({"jsonrpc":"2.0","id":8,"method":method,"params":{"_meta":meta.clone()}});
            let out = m.client_line(1, &line.to_string(), now);
            assert!(to_child(&out).is_empty(), "{method} {meta}");
            assert_eq!(
                to_client(&out, 1)[0]["error"]["code"],
                -32602,
                "{method} {meta}"
            );
        }
    }
    assert_eq!(m.in_flight(), 0);
}
