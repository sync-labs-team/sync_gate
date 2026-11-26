//! `sync_gate mcp serve`: sync_gate's own read-only MCP server (machine state and the queue).
//! It only reads: the one tool asks the daemon for `Status` and prints what `sync_gate status`
//! prints. Nothing here requests, cancels or releases anything.

use crate::client::call_at;
use crate::runner::{render, socket};
use serde_json::{Value, json};
use std::io::{BufRead, Write};
use sync_gate_core::{
    Kind, Request, Response, StatusReport, classify, error_response, result_response,
};

pub const TOOL: &str = "sync_gate_status";
/// Protocol versions this server implements, newest first. Same flow in all of them: `initialize`,
/// `ping`, `tools/list`, `tools/call` over stdio.
const SUPPORTED: [&str; 4] = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const DOWN: &str = "sync_gate daemon is not running: heavy commands run directly (no queue).";
/// Sent to every agent on `initialize`; the same rules as the repository's AGENTS.md.
const INSTRUCTIONS: &str = "sync_gate shares one machine between coding agents. \
Call sync_gate_status to see memory, running jobs and the queue (read-only). \
Found a bug or a way to make sync_gate more useful? Draft an issue for \
https://github.com/sync-labs-team/sync_gate: search the existing issues first, remove secrets and \
private data, and open it only after the user approves.";

pub fn serve() -> i32 {
    serve_with(
        std::io::stdin().lock(),
        std::io::stdout().lock(),
        || match call_at(&socket(), &Request::Status) {
            Ok(Response::Status(s)) => Some(s),
            _ => None,
        },
    )
}

fn tools_list() -> Value {
    json!({"tools": [{
        "name": TOOL,
        "description": "Memory, running jobs, the queue and recent decisions of sync_gate on this machine. Read-only.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
        // MCP 2025-11-25 tool annotations: Codex runs a read-only tool without asking for approval.
        "annotations": {"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false},
    }]})
}

fn ok_status(id: &Value, status: &mut impl FnMut() -> Option<StatusReport>) -> Value {
    let text = status().map_or_else(|| DOWN.to_string(), |s| render(&s));
    result_response(
        id,
        json!({"content": [{"type": "text", "text": text}], "isError": false}),
    )
}

/// One JSON-RPC message per line in, one per line out; stdout carries nothing else.
pub fn serve_with(
    input: impl BufRead,
    mut output: impl Write,
    mut status: impl FnMut() -> Option<StatusReport>,
) -> i32 {
    for line in input.lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Err(_) => Some(error_response(&Value::Null, -32700, "parse error")),
            Ok(v) => match classify(&v) {
                // classify is shared with the hub and lenient; MCP needs "2.0" and no `id: null`.
                _ if v["jsonrpc"] != "2.0" || v.get("id").is_some_and(Value::is_null) => {
                    Some(error_response(&Value::Null, -32600, "invalid request"))
                }
                Kind::Invalid => Some(error_response(&Value::Null, -32600, "invalid request")),
                Kind::Notification { .. } | Kind::Response { .. } => None,
                Kind::Request { id, method } => Some(match method.as_str() {
                    "initialize" => match v["params"]["protocolVersion"].as_str() {
                        None => error_response(&id, -32602, "protocolVersion is required"),
                        Some(asked) => result_response(
                            &id,
                            json!({
                                "protocolVersion": SUPPORTED.iter().find(|s| **s == asked).unwrap_or(&SUPPORTED[0]),
                                "capabilities": {"tools": {}},
                                "serverInfo": {"name": "sync_gate", "version": env!("CARGO_PKG_VERSION")},
                                "instructions": INSTRUCTIONS,
                            }),
                        ),
                    },
                    "ping" => result_response(&id, json!({})),
                    "tools/list" => result_response(&id, tools_list()),
                    "tools/call" => {
                        match (v["params"]["name"].as_str(), v["params"].get("arguments")) {
                            (Some(TOOL), None) => ok_status(&id, &mut status),
                            (Some(TOOL), Some(Value::Object(o))) if o.is_empty() => {
                                ok_status(&id, &mut status)
                            }
                            // Input validation failure is a tool error the model can read and retry.
                            (Some(TOOL), Some(Value::Object(_))) => result_response(
                                &id,
                                json!({"content": [{"type": "text", "text": "sync_gate_status takes no arguments"}], "isError": true}),
                            ),
                            (Some(TOOL), Some(_)) => {
                                error_response(&id, -32602, "arguments must be an object")
                            }
                            _ => error_response(&id, -32602, "unknown tool"),
                        }
                    }
                    _ => error_response(&id, -32601, "method not found"),
                }),
            },
        };
        if let Some(r) = reply
            && (writeln!(output, "{r}").is_err() || output.flush().is_err())
        {
            break;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use sync_gate_core::MachineSnapshot;

    fn report() -> StatusReport {
        StatusReport {
            snapshot: MachineSnapshot {
                total: 8192 << 20,
                available: 4096 << 20,
                reclaimable: 0,
                swap_used: 0,
                swap_total: 0,
                vram: None,
            },
            running: vec![(1, "cargo".into(), 0)],
            queued: Vec::new(),
            paused: Vec::new(),
            decisions: Vec::new(),
            mcp: Vec::new(),
            services: Vec::new(),
            daemon: Default::default(),
        }
    }

    fn run(input: &str, st: Option<StatusReport>) -> (i32, Vec<Value>) {
        let mut out = Vec::new();
        let code = serve_with(input.as_bytes(), &mut out, || st.clone());
        let lines = String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        (code, lines)
    }

    fn init(ver: &str) -> String {
        format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{\"protocolVersion\":\"{ver}\"}}}}\n"
        )
    }

    #[test]
    fn initialize_echoes_a_supported_version_else_the_newest() {
        for ver in SUPPORTED {
            assert_eq!(run(&init(ver), None).1[0]["result"]["protocolVersion"], ver);
        }
        let (_, o) = run(&init("2099-01-01"), None);
        assert_eq!(o[0]["result"]["protocolVersion"], "2025-11-25");
        assert_eq!(o[0]["result"]["serverInfo"]["name"], "sync_gate");
        assert_eq!(o[0]["result"]["capabilities"], json!({"tools": {}}));
    }

    // Agents that use sync_gate are invited to report bugs and improvements, with the user's approval
    // (same rule as AGENTS.md).
    #[test]
    fn initialize_invites_contributions() {
        let (_, o) = run(&init("2025-11-25"), None);
        let text = o[0]["result"]["instructions"]
            .as_str()
            .expect("initialize carries instructions");
        assert!(
            text.contains("https://github.com/sync-labs-team/sync_gate"),
            "{text}"
        );
        assert!(text.contains("only after the user approves"), "{text}");
        assert!(text.contains("sync_gate_status"), "{text}");
    }

    #[test]
    fn initialize_without_a_protocol_version_is_32602() {
        let (_, o) = run(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n",
            None,
        );
        assert_eq!(o[0]["error"]["code"], -32602);
        assert_eq!(o[0]["id"], 1);
    }

    /// Runs `input` and returns the replies and how many times the daemon was asked.
    fn run_counted(input: &str) -> (Vec<Value>, u32) {
        let (mut out, mut n) = (Vec::new(), 0);
        serve_with(input.as_bytes(), &mut out, || {
            n += 1;
            None
        });
        let lines = String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        (lines, n)
    }

    fn call(params: &str) -> String {
        format!("{{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{params}}}\n")
    }

    #[test]
    fn arguments_omitted_or_empty_are_fine() {
        let (o, n) = run_counted(
            &(call(r#"{"name":"sync_gate_status"}"#)
                + &call(r#"{"name":"sync_gate_status","arguments":{}}"#)),
        );
        assert_eq!((n, o.len()), (2, 2));
        assert!(o.iter().all(|r| r["result"]["isError"] == false));
    }

    #[test]
    fn bad_arguments_never_reach_the_daemon() {
        for bad in ["42", "null", "[]", r#""x""#] {
            let (o, n) = run_counted(&call(&format!(
                r#"{{"name":"sync_gate_status","arguments":{bad}}}"#
            )));
            assert_eq!(n, 0, "{bad}");
            assert_eq!(
                (&o[0]["error"]["code"], &o[0]["id"]),
                (&json!(-32602), &json!(7))
            );
        }
        let (o, n) = run_counted(&call(
            r#"{"name":"sync_gate_status","arguments":{"unexpected":true}}"#,
        ));
        assert_eq!(n, 0);
        assert_eq!(o[0]["result"]["isError"], true);
    }

    #[test]
    fn unknown_tool_is_a_32602_error_with_the_id() {
        let (o, n) = run_counted(&(call(r#"{"name":"nope"}"#) + &call("{}")));
        assert_eq!((n, o.len()), (0, 2));
        for r in o {
            assert_eq!((&r["error"]["code"], &r["id"]), (&json!(-32602), &json!(7)));
            assert!(r.get("result").is_none());
        }
    }

    #[test]
    fn a_bad_envelope_is_32600() {
        let (_, o) = run(
            "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"ping\"}\n\
             {\"id\":2,\"method\":\"ping\"}\n\
             {\"jsonrpc\":\"2.0\",\"id\":null,\"method\":\"ping\"}\n\
             {\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\"}\n\
             {\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
            None,
        );
        assert_eq!(o.len(), 4);
        for r in &o[..3] {
            assert_eq!(r["error"]["code"], -32600);
            assert!(r["id"].is_null());
        }
        assert_eq!(o[3]["id"], 3);
    }

    #[test]
    fn tools_list_has_sync_gate_status() {
        let (_, o) = run(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n",
            None,
        );
        let t = &o[0]["result"]["tools"];
        assert_eq!(t.as_array().unwrap().len(), 1);
        assert_eq!(t[0]["name"], TOOL);
        assert_eq!(t[0]["inputSchema"]["additionalProperties"], false);
    }

    #[test]
    fn tools_list_marks_sync_gate_status_read_only() {
        // Codex runs a tool without asking only when it says it only reads.
        let (_, o) = run(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n",
            None,
        );
        assert_eq!(
            o[0]["result"]["tools"][0]["annotations"],
            json!({"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false})
        );
    }

    #[test]
    fn status_call_returns_the_rendered_report() {
        let (_, o) = run(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"sync_gate_status\",\"arguments\":{}}}\n",
            Some(report()),
        );
        assert_eq!(o[0]["result"]["isError"], false);
        let text = o[0]["result"]["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, render(&report()));
        assert!(text.contains("memory"));
    }

    /// T4.5 (X1): the status the MCP tool hands the agent (and its model provider) carries no
    /// credential from the command's arguments.
    #[test]
    fn credentials_never_reach_cost_status_or_mcp() {
        let argv: Vec<std::ffi::OsString> = [
            "docker",
            "build",
            "--build-arg",
            "PUBLIC=1",
            "https://alice:dummy-secret@example.invalid/repo.git",
        ]
        .iter()
        .map(Into::into)
        .collect();
        let key = sync_gate_core::signature(&argv, std::path::Path::new("/r/site"))
            .unwrap()
            .key;
        let mut st = report();
        st.running = vec![(1, key.clone(), 0)];
        st.queued = vec![(2, key, 1)];
        let (_, o) = run(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"sync_gate_status\",\"arguments\":{}}}\n",
            Some(st),
        );
        let text = o[0]["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("docker build @ site"), "{text}");
        assert!(!text.contains("dummy-secret"), "{text}");
    }

    #[test]
    fn status_call_with_the_daemon_down_says_so() {
        let (_, o) = run(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"sync_gate_status\"}}\n",
            None,
        );
        assert_eq!(o[0]["result"]["isError"], false);
        assert_eq!(o[0]["result"]["content"][0]["text"], DOWN);
    }

    #[test]
    fn unknown_method_is_32601_and_notifications_get_no_reply() {
        let (_, o) = run(
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n\
             {\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/list\"}\n\
             {\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n",
            None,
        );
        assert_eq!(o.len(), 2);
        assert_eq!(o[0]["error"]["code"], -32601);
        assert_eq!(o[1]["result"], json!({}));
    }

    #[test]
    fn a_bad_line_is_32700_and_the_server_keeps_going() {
        let (code, o) = run(
            "{nope\n{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\"}\n",
            None,
        );
        assert_eq!(code, 0);
        assert_eq!(o[0]["error"]["code"], -32700);
        assert!(o[0]["id"].is_null());
        assert_eq!(o[1]["id"], 3);
    }

    #[test]
    fn eof_ends_with_0() {
        assert_eq!(run("", None), (0, vec![]));
    }
}
