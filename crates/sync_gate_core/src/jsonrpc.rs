//! Minimal JSON-RPC 2.0 helpers for the MCP hub.

use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    Request { id: Value, method: String },
    Notification { method: String },
    Response { id: Value },
    Invalid,
}

/// Classifies one JSON-RPC message. Batches (arrays) are `Invalid`: MCP removed them.
pub fn classify(v: &Value) -> Kind {
    let Some(o) = v.as_object() else {
        return Kind::Invalid;
    };
    let id = o.get("id").filter(|i| !i.is_null());
    // MCP ids are strings or integers only.
    if id.is_some_and(|i| !(i.is_string() || i.is_i64() || i.is_u64())) {
        return Kind::Invalid;
    }
    match (o.get("method"), id) {
        (Some(Value::String(m)), Some(id)) => Kind::Request {
            id: id.clone(),
            method: m.clone(),
        },
        (Some(Value::String(m)), None) => Kind::Notification { method: m.clone() },
        (None, Some(id)) if o.contains_key("result") || o.contains_key("error") => {
            Kind::Response { id: id.clone() }
        }
        _ => Kind::Invalid,
    }
}

pub fn error_response(id: &Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

pub fn result_response(id: &Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn classify_kinds() {
        assert!(matches!(
            classify(&json!({"jsonrpc":"2.0","id":1,"method":"tools/list"})),
            Kind::Request { .. }
        ));
        assert!(matches!(
            classify(&json!({"jsonrpc":"2.0","method":"notifications/progress"})),
            Kind::Notification { .. }
        ));
        assert!(matches!(
            classify(&json!({"jsonrpc":"2.0","id":"a","result":{}})),
            Kind::Response { .. }
        ));
        assert!(matches!(
            classify(&json!({"jsonrpc":"2.0","id":"a","error":{"code":-1,"message":"x"}})),
            Kind::Response { .. }
        ));
        assert!(matches!(
            classify(&json!([{"jsonrpc":"2.0","id":1,"method":"x"}])),
            Kind::Invalid
        ));
        assert!(matches!(classify(&json!("x")), Kind::Invalid));
        assert!(matches!(
            classify(&json!({"id":1,"method":5})),
            Kind::Invalid
        ));
    }

    #[test]
    fn responses_have_expected_shape() {
        let e = error_response(&json!(7), -32000, "boom");
        assert_eq!(
            e,
            json!({"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"boom"}})
        );
        let r = result_response(&json!("a"), json!({"ok":true}));
        assert_eq!(r, json!({"jsonrpc":"2.0","id":"a","result":{"ok":true}}));
    }

    #[test]
    fn ids_must_be_string_or_integer() {
        for id in [json!(true), json!(1.5), json!([1]), json!({"a":1})] {
            assert_eq!(
                classify(&json!({"id":id,"method":"x"})),
                Kind::Invalid,
                "{id}"
            );
            assert_eq!(
                classify(&json!({"id":id,"result":{}})),
                Kind::Invalid,
                "{id}"
            );
        }
        assert!(matches!(
            classify(&json!({"id":-3,"method":"x"})),
            Kind::Request { .. }
        ));
    }

    #[test]
    fn null_id_means_no_id() {
        assert!(matches!(
            classify(&json!({"id":null,"method":"x"})),
            Kind::Notification { .. }
        ));
        assert_eq!(classify(&json!({"id":null,"result":{}})), Kind::Invalid);
    }
}
