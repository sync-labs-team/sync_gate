//! Read, edit and restore the MCP server entries of the agents' own configs, by exact byte ranges.
//!
//! Claude Code: JSON (`~/.claude.json`, `.mcp.json`), top-level `mcpServers`. Codex: TOML
//! (`config.toml`), `[mcp_servers.*]`. Pure text in, text out: the file transaction lives elsewhere.
//! `env` values are never read into any value this module returns.

use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::ops::Range;

use serde::de::{self, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::config::is_mcp_name;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    ClaudeJson,
    CodexToml,
}

/// One stdio server of the user scope. Never carries `env` values.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Found {
    pub server: String,
    pub command: String,
    /// `None`: the entry has no `args`.
    pub args: Option<Vec<String>>,
    pub env_keys: Vec<String>,
    pub cwd: Option<String>,
    /// Why sync_gate must not adopt it.
    pub skip: Option<String>,
}

/// The exact source text of a server's launch values: what restore puts back.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct LaunchText {
    pub command: String,
    /// `None`: there was no `args`.
    pub args: Option<String>,
}

pub struct Edited {
    pub text: String,
    pub original: LaunchText,
    pub inserted_args: bool,
}

pub enum Restored {
    Done(String),
    Gone,
    AlreadyOriginal,
    Changed,
}

const LAYOUT: &str =
    "unsupported layout (command is not a plain key and args is absent); edit by hand";
const BOM: char = '\u{feff}';

struct Parsed {
    found: Found,
    /// Byte range (in the whole text) of the value, and its text if it is a string.
    cmd: Option<(Range<usize>, Option<String>)>,
    /// Same for `args`; the inner `None` is "not an array of strings".
    args: Option<(Range<usize>, Option<Vec<String>>)>,
    /// The whole entry as a value (env values included), only ever compared, never printed.
    rest: serde_json::Value,
}

fn build(
    name: &str,
    cmd: Option<(Range<usize>, Option<String>)>,
    args: Option<(Range<usize>, Option<Vec<String>>)>,
    remote: bool,
    env_keys: Vec<String>,
    cwd: Option<String>,
    rest: serde_json::Value,
) -> Parsed {
    let command = cmd.as_ref().and_then(|c| c.1.clone());
    let arg_list = args.as_ref().and_then(|a| a.1.clone());
    let skip = if remote {
        Some("remote server (url or non-stdio type)".to_string())
    } else if command.is_none() {
        Some("no command".to_string())
    } else if !is_mcp_name(name) {
        Some("name must match [A-Za-z0-9_-]{1,64}".to_string())
    } else if args.as_ref().is_some_and(|a| a.1.is_none()) {
        Some("args are not all text".to_string())
    } else if is_adopted(command.as_deref().unwrap_or(""), arg_list.as_deref()) {
        Some("already adopted".to_string())
    } else if command.as_deref().is_some_and(|c| c.contains("${"))
        || arg_list.iter().flatten().any(|a| a.contains("${"))
    {
        Some("uses ${...} expansion, which the sync_gate config does not do".to_string())
    } else {
        looks_like_credential(arg_list.as_deref().unwrap_or(&[]))
            .map(|c| format!("an argument looks like a credential ({c})"))
    };
    Parsed {
        found: Found {
            server: name.to_string(),
            command: command.unwrap_or_default(),
            args: arg_list,
            env_keys,
            cwd,
            skip,
        },
        cmd,
        args,
        rest,
    }
}

/// An error text without file content: serde's `invalid type: string "v", expected ...`
/// echoes the offending value, so only the kind and the expectation are kept. The LAST
/// `, expected` is the separator: the expectation comes from code and follows the value, which
/// may itself contain `, expected`.
fn scrub(msg: &str) -> String {
    let head = msg.split(':').next().unwrap_or("");
    match (msg.starts_with("invalid "), msg.rfind(", expected")) {
        (true, Some(i)) => format!("{head}{}", &msg[i..]),
        (true, None) => head.to_string(),
        _ => msg.to_string(),
    }
}

fn toml_err(body: &str, e: &toml::de::Error) -> String {
    let at = e.span().map_or(String::new(), |s| {
        let line = body[..s.start].matches('\n').count() + 1;
        let col = s.start - body[..s.start].rfind('\n').map_or(0, |p| p + 1) + 1;
        format!(" at line {line} column {col}")
    });
    format!("{}{at}", scrub(e.message()))
}

fn is_adopted(command: &str, args: Option<&[String]>) -> bool {
    let file = command.rsplit(['/', '\\']).next().unwrap_or("");
    (file == "sync_gate" || file == "sync_gate.exe")
        && args.is_some_and(|a| a.len() >= 2 && a[0] == "mcp" && a[1] == "connect")
}

fn text_list(v: &serde_json::Value) -> Option<Vec<String>> {
    v.as_array()?
        .iter()
        .map(|x| x.as_str().map(str::to_string))
        .collect()
}

/// A JSON object read as ordered members whose values stay unparsed slices of the input.
/// A repeated key is an error: a map type would keep the last one in silence.
struct Members<'a>(Vec<(String, &'a RawValue)>);

impl<'de: 'a, 'a> Deserialize<'de> for Members<'a> {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<'a>(PhantomData<&'a ()>);
        impl<'de: 'a, 'a> Visitor<'de> for V<'a> {
            type Value = Members<'a>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut m: M) -> Result<Members<'a>, M::Error> {
                let mut out: Vec<(String, &'a RawValue)> = Vec::new();
                while let Some(k) = m.next_key::<String>()? {
                    if out.iter().any(|(n, _)| *n == k) {
                        return Err(de::Error::custom(format!("duplicate key `{k}`")));
                    }
                    out.push((k, m.next_value::<&'de RawValue>()?));
                }
                Ok(Members(out))
            }
        }
        d.deserialize_map(V(PhantomData))
    }
}

fn members(s: &str) -> Result<Vec<(String, &RawValue)>, String> {
    serde_json::from_str::<Members>(s)
        .map(|m| m.0)
        .map_err(|e| scrub(&e.to_string()))
}

fn get<'a>(m: &[(String, &'a RawValue)], key: &str) -> Option<&'a RawValue> {
    m.iter().find(|(k, _)| k == key).map(|(_, v)| *v)
}

fn json_parse(body: &str, off: usize) -> Result<Vec<Parsed>, String> {
    // Every RawValue is a slice of `body` (borrowed by `from_str`), so its distance from the
    // start of `body` is its byte position; no search for the text is needed.
    let range = |r: &RawValue| {
        let s = r.get().as_ptr() as usize - body.as_ptr() as usize + off;
        s..s + r.get().len()
    };
    let top = members(body)?;
    let Some(servers) = get(&top, "mcpServers") else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (name, raw) in members(servers.get())? {
        let m = members(raw.get()).map_err(|e| format!("mcpServers.{name}: {e}"))?;
        let value = |k: &str| {
            get(&m, k).and_then(|r| serde_json::from_str::<serde_json::Value>(r.get()).ok())
        };
        let slot = |k: &str| get(&m, k).map(range);
        let cmd = slot("command")
            .zip(value("command"))
            .map(|(r, v)| (r, v.as_str().map(str::to_string)));
        let args = slot("args")
            .zip(value("args"))
            .map(|(r, v)| (r, text_list(&v)));
        let remote =
            get(&m, "url").is_some() || value("type").is_some_and(|t| t.as_str() != Some("stdio"));
        let env_keys = match get(&m, "env") {
            Some(e) => serde_json::from_str::<BTreeMap<String, IgnoredAny>>(e.get())
                .map(|e| e.into_keys().collect())
                .unwrap_or_default(),
            None => Vec::new(),
        };
        let cwd = value("cwd").and_then(|v| v.as_str().map(str::to_string));
        let rest = serde_json::from_str(raw.get()).unwrap_or_default();
        out.push(build(&name, cmd, args, remote, env_keys, cwd, rest));
    }
    Ok(out)
}

#[derive(Deserialize)]
struct TomlDoc {
    mcp_servers: Option<BTreeMap<String, TomlServer>>,
}

#[derive(Deserialize)]
struct TomlServer {
    command: Option<toml::Spanned<toml::Value>>,
    args: Option<toml::Spanned<toml::Value>>,
    env: Option<BTreeMap<String, IgnoredAny>>,
    env_vars: Option<Vec<toml::Value>>,
    cwd: Option<String>,
    url: Option<toml::Value>,
    #[serde(rename = "type")]
    kind: Option<toml::Value>,
}

fn toml_parse(body: &str, off: usize) -> Result<Vec<Parsed>, String> {
    let doc: TomlDoc = toml::from_str(body).map_err(|e| toml_err(body, &e))?;
    let table: toml::Table = toml::from_str(body).map_err(|e| toml_err(body, &e))?;
    let mut out = Vec::new();
    for (name, s) in doc.mcp_servers.unwrap_or_default() {
        let shift = |r: Range<usize>| r.start + off..r.end + off;
        let cmd = s.command.map(|c| {
            let r = shift(c.span());
            (r, c.into_inner().as_str().map(str::to_string))
        });
        let args = s.args.map(|a| {
            let r = shift(a.span());
            let list = a.into_inner().as_array().and_then(|v| {
                v.iter()
                    .map(|x| x.as_str().map(str::to_string))
                    .collect::<Option<Vec<_>>>()
            });
            (r, list)
        });
        let remote = s.url.is_some() || s.kind.is_some_and(|t| t.as_str() != Some("stdio"));
        let mut env_keys: Vec<String> = s.env.into_iter().flat_map(BTreeMap::into_keys).collect();
        for v in s.env_vars.unwrap_or_default() {
            let n = v
                .as_str()
                .or_else(|| v.get("name").and_then(toml::Value::as_str));
            env_keys.extend(n.map(str::to_string));
        }
        let rest = table
            .get("mcp_servers")
            .and_then(|m| m.get(&name))
            .and_then(|v| serde_json::to_value(v).ok())
            .unwrap_or_default();
        out.push(build(&name, cmd, args, remote, env_keys, s.cwd, rest));
    }
    Ok(out)
}

fn parse(f: Format, text: &str) -> Result<Vec<Parsed>, String> {
    // Neither parser accepts a byte order mark; it is kept in the text and skipped here.
    let (off, body) = match text.strip_prefix(BOM) {
        Some(rest) => (BOM.len_utf8(), rest),
        None => (0, text),
    };
    match f {
        Format::ClaudeJson => json_parse(body, off),
        Format::CodexToml => toml_parse(body, off),
    }
}

/// Stdio servers of the user scope: Claude top-level "mcpServers", Codex [mcp_servers.*].
pub fn servers(f: Format, text: &str) -> Result<Vec<Found>, String> {
    Ok(parse(f, text)?.into_iter().map(|p| p.found).collect())
}

/// The flag or NAME= that makes an argument look like a credential.
pub fn looks_like_credential(args: &[String]) -> Option<String> {
    const WORDS: [&str; 7] = [
        "token",
        "key",
        "secret",
        "password",
        "passwd",
        "auth",
        "credential",
    ];
    let named = |n: &str| {
        let n = n.trim_start_matches('-').to_ascii_lowercase();
        WORDS.iter().any(|w| n.contains(w))
    };
    for (i, a) in args.iter().enumerate() {
        if let Some((n, _)) = a.split_once('=') {
            if named(n) {
                return Some(n.to_string());
            }
        } else if a.starts_with('-') && named(a) && i + 1 < args.len() {
            // Any next argument counts, even one starting with `-`: a secret may look like a flag.
            return Some(a.clone());
        }
    }
    None
}

fn toml_string(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

fn toml_list(args: &[String]) -> String {
    toml::Value::Array(
        args.iter()
            .map(|a| toml::Value::String(a.clone()))
            .collect(),
    )
    .to_string()
}

fn new_values(f: Format, command: &str, args: &[String]) -> Result<(String, String), String> {
    match f {
        Format::ClaudeJson => Ok((
            serde_json::to_string(command).map_err(|e| e.to_string())?,
            serde_json::to_string(args).map_err(|e| e.to_string())?,
        )),
        Format::CodexToml => Ok((toml_string(command), toml_list(args))),
    }
}

/// TOML: the key in front of a value on its line (or inline-table member): where it starts,
/// whether it sits in an inline table, and its trimmed text.
fn toml_key(text: &str, vs: usize) -> Result<(usize, bool, &str), String> {
    let b = text.as_bytes();
    let mut i = vs;
    while i > 0 && matches!(b[i - 1], b' ' | b'\t') {
        i -= 1;
    }
    if i == 0 || b[i - 1] != b'=' {
        return Err("cannot find the key of a value".into());
    }
    let end = i - 1;
    i = end;
    while i > 0 && !matches!(b[i - 1], b'\n' | b'{' | b',') {
        i -= 1;
    }
    let inline = i > 0 && b[i - 1] != b'\n';
    let seg = &text[i..end];
    Ok((i + (seg.len() - seg.trim_start().len()), inline, seg.trim()))
}

fn is_plain(key: &str, name: &str) -> bool {
    key == name || key == format!("\"{name}\"") || key == format!("'{name}'")
}

/// The member (`"args": v` or `args = v`) of a JSON object or TOML inline table whose value is
/// `vs..ve`, with the comma that ties it to its neighbours: what to cut to drop it.
fn member_range(text: &str, vs: usize, ve: usize, sep: u8) -> Result<Range<usize>, String> {
    const BAD: &str = "cannot remove the inserted args cleanly; edit by hand";
    let b = text.as_bytes();
    let back = |mut i: usize| {
        while i > 0 && b[i - 1].is_ascii_whitespace() {
            i -= 1;
        }
        i
    };
    let i = back(vs);
    if i == 0 || b[i - 1] != sep {
        return Err(BAD.into());
    }
    let i = back(i - 1);
    if i == 0 {
        return Err(BAD.into());
    }
    let q = b[i - 1];
    let ks = if q == b'"' || q == b'\'' {
        let mut j = i - 1;
        loop {
            if j == 0 {
                return Err(BAD.into());
            }
            j -= 1;
            let slashes = b[..j].iter().rev().take_while(|c| **c == b'\\').count();
            if b[j] == q && (q == b'\'' || slashes % 2 == 0) {
                break;
            }
        }
        let key = &text[j..i];
        let decoded = if q == b'"' {
            serde_json::from_str::<String>(key).ok()
        } else {
            Some(key[1..key.len() - 1].to_string())
        };
        if decoded.as_deref() != Some("args") {
            return Err(BAD.into());
        }
        j
    } else {
        let mut j = i;
        while j > 0 && (b[j - 1].is_ascii_alphanumeric() || matches!(b[j - 1], b'_' | b'-')) {
            j -= 1;
        }
        if &text[j..i] != "args" {
            return Err(BAD.into());
        }
        j
    };
    let j = back(ks);
    match j.checked_sub(1).map(|k| b[k]) {
        Some(b',') => Ok(j - 1..ve),
        Some(b'{') => {
            let mut k = ve;
            while k < b.len() && b[k].is_ascii_whitespace() {
                k += 1;
            }
            if b.get(k) == Some(&b',') {
                k += 1;
                while k < b.len() && b[k].is_ascii_whitespace() {
                    k += 1;
                }
                Ok(ks..k)
            } else {
                Ok(ks..ve)
            }
        }
        _ => Err(BAD.into()),
    }
}

/// End of the line holding `from` (before its break) and that break.
fn line_end(text: &str, from: usize) -> (usize, &'static str) {
    match text[from..].find('\n') {
        Some(p) if text[..from + p].ends_with('\r') => (from + p - 1, "\r\n"),
        Some(p) => (from + p, "\n"),
        None => (
            text.len(),
            if text.contains("\r\n") { "\r\n" } else { "\n" },
        ),
    }
}

/// Edits to apply, back to front, so earlier ranges stay valid.
fn apply(text: &str, mut edits: Vec<(Range<usize>, String)>) -> String {
    edits.sort_by_key(|e| std::cmp::Reverse(e.0.start));
    let mut out = text.to_string();
    for (r, s) in edits {
        out.replace_range(r, &s);
    }
    out
}

fn find<'a>(all: &'a [Parsed], server: &str) -> Option<&'a Parsed> {
    all.iter().find(|p| p.found.server == server)
}

/// The entry without the two launch values: all that an edit must leave alone in the target.
fn without_launch(v: &serde_json::Value) -> serde_json::Value {
    let mut v = v.clone();
    if let Some(o) = v.as_object_mut() {
        o.remove("command");
        o.remove("args");
    }
    v
}

/// The edited text must reparse, give `server` exactly these values, keep every other field of
/// `server`, and leave every other server value-for-value as before. Errors name no value.
fn verify_edit(
    f: Format,
    before: &[Parsed],
    text: &str,
    server: &str,
    command: &str,
    args: Option<&[String]>,
) -> Result<(), String> {
    let after = parse(f, text)?;
    let t = find(&after, server).ok_or("the edit lost the server")?;
    let got_args = t.args.as_ref().and_then(|a| a.1.as_deref());
    if t.cmd.as_ref().and_then(|c| c.1.as_deref()) != Some(command)
        || got_args != args
        || t.args.is_some() != args.is_some()
    {
        return Err("the edit did not produce the expected command/args".into());
    }
    let old = find(before, server).ok_or("the server was not there before")?;
    if without_launch(&t.rest) != without_launch(&old.rest) {
        return Err("the edit changed another field of the server".into());
    }
    let others = |v: &[Parsed]| {
        v.iter()
            .filter(|x| x.found.server != server)
            .map(|x| (x.found.server.clone(), x.rest.clone()))
            .collect::<Vec<_>>()
    };
    if others(&after) != others(before) {
        return Err("the edit changed another server".into());
    }
    Ok(())
}

/// Replaces only the bytes of the `command` and `args` values; inserts `args` right after
/// `command` when it is absent.
pub fn set_launch(
    f: Format,
    text: &str,
    server: &str,
    command: &str,
    args: &[String],
) -> Result<Edited, String> {
    let all = parse(f, text)?;
    let p = find(&all, server).ok_or_else(|| format!("server `{server}` not found"))?;
    let (cr, ctext) = p.cmd.clone().ok_or("the server has no command")?;
    if ctext.is_none() || p.args.as_ref().is_some_and(|a| a.1.is_none()) {
        return Err("command or args are not text; edit by hand".into());
    }
    let (new_cmd, new_args) = new_values(f, command, args)?;
    let original = LaunchText {
        command: text[cr.clone()].to_string(),
        args: p.args.as_ref().map(|a| text[a.0.clone()].to_string()),
    };
    let mut edits = vec![(cr.clone(), new_cmd.clone())];
    match (&p.args, f) {
        (Some((ar, _)), _) => edits.push((ar.clone(), new_args)),
        (None, Format::ClaudeJson) => edits[0].1 = format!("{new_cmd}, \"args\": {new_args}"),
        (None, Format::CodexToml) => {
            let (_, inline, key) = toml_key(text, cr.start)?;
            if inline {
                edits[0].1 = format!("{new_cmd}, args = {new_args}");
            } else if is_plain(key, "command") {
                let (at, eol) = line_end(text, cr.end);
                edits.push((at..at, format!("{eol}args = {new_args}")));
            } else {
                return Err(LAYOUT.into());
            }
        }
    }
    let out = apply(text, edits);
    verify_edit(f, &all, &out, server, command, Some(args))?;
    Ok(Edited {
        text: out,
        original,
        inserted_args: p.args.is_none(),
    })
}

/// Drops the `args` that `set_launch` inserted, wherever its value is now.
fn remove_args(f: Format, text: &str, ar: &Range<usize>) -> Result<Range<usize>, String> {
    if f == Format::ClaudeJson {
        return member_range(text, ar.start, ar.end, b':');
    }
    let (ks, inline, key) = toml_key(text, ar.start)?;
    if inline {
        return member_range(text, ar.start, ar.end, b'=');
    }
    let (le, _) = line_end(text, ar.end);
    let rest = text[ar.end..le].trim();
    if !is_plain(key, "args") || !(rest.is_empty() || rest.starts_with('#')) {
        return Err("cannot remove the inserted args cleanly; edit by hand".into());
    }
    // The line and the break before it: the inverse of "break + line" at insertion.
    let ls = text[..ks].rfind('\n').map_or(0, |p| p + 1);
    let mut start = ls.checked_sub(1).ok_or("args line has no previous line")?;
    if start > 0 && text.as_bytes()[start - 1] == b'\r' {
        start -= 1;
    }
    Ok(start..le)
}

/// Puts `original` back where the current values are, only if they still equal (as values)
/// `expected`; removes an `args` that `set_launch` inserted.
pub fn restore_launch(
    f: Format,
    text: &str,
    server: &str,
    expected: (&str, &[String]),
    original: &LaunchText,
    original_values: (&str, Option<&[String]>),
    inserted_args: bool,
) -> Result<Restored, String> {
    let all = parse(f, text)?;
    let Some(p) = find(&all, server) else {
        return Ok(Restored::Gone);
    };
    let cmd = p.cmd.as_ref().and_then(|c| c.1.as_deref());
    let args = p.args.as_ref().and_then(|a| a.1.as_deref());
    if cmd == Some(original_values.0)
        && args == original_values.1
        && p.args.is_some() == original_values.1.is_some()
    {
        return Ok(Restored::AlreadyOriginal);
    }
    if cmd != Some(expected.0) || args != Some(expected.1) {
        return Ok(Restored::Changed);
    }
    let (cr, _) = p.cmd.clone().ok_or("the server has no command")?;
    let (ar, _) = p.args.clone().ok_or("the server has no args")?;
    let mut edits = vec![(cr, original.command.clone())];
    match (&original.args, inserted_args) {
        (Some(a), false) => edits.push((ar, a.clone())),
        (None, true) => edits.push((remove_args(f, text, &ar)?, String::new())),
        _ => return Err("inconsistent restore record".into()),
    }
    let out = apply(text, edits);
    verify_edit(f, &all, &out, server, original_values.0, original_values.1)?;
    Ok(Restored::Done(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use Format::{ClaudeJson as J, CodexToml as T};

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    const CLAUDE: &str = r#"{
  "numStartups": 3,
  "mcpServers": {
    "context7": {
      "type": "stdio",
      "command": "npx",
      "args": [
        "-y",
        "@upstash/context7-mcp"
      ],
      "env": {
        "API_KEY": "SECRET-VALUE-1"
      }
    },
    "remote": {
      "type": "http",
      "url": "https://x.example/mcp"
    },
    "bare": {
      "command": "node"
    },
    "other": {
      "command": "node",
      "args": ["a.js"],
      "cwd": "C:\\work"
    }
  },
  "projects": {}
}
"#;

    /// set_launch then restore_launch from the adopted text: returns the adopted text.
    fn round_trip(f: Format, text: &str, server: &str) -> Edited {
        let before = servers(f, text).unwrap();
        let b = before.iter().find(|x| x.server == server).unwrap();
        let new_args = s(&["mcp", "connect", server]);
        let ed = set_launch(f, text, server, "sync_gate", &new_args).unwrap();
        let r = restore_launch(
            f,
            &ed.text,
            server,
            ("sync_gate", &new_args),
            &ed.original,
            (&b.command, b.args.as_deref()),
            ed.inserted_args,
        )
        .unwrap();
        match r {
            Restored::Done(t) => assert_eq!(t, text, "restore must be byte-identical"),
            _ => panic!("expected Done"),
        }
        ed
    }

    #[test]
    fn claude_servers_reads_stdio_and_skips_remote() {
        let v = servers(J, CLAUDE).unwrap();
        let by = |n: &str| v.iter().find(|x| x.server == n).unwrap();
        let c7 = by("context7");
        assert_eq!(c7.command, "npx");
        assert_eq!(c7.args, Some(s(&["-y", "@upstash/context7-mcp"])));
        assert_eq!(c7.env_keys, s(&["API_KEY"]));
        assert_eq!(c7.skip, None);
        assert!(by("remote").skip.as_deref().unwrap().contains("remote"));
        assert_eq!(by("bare").args, None);
        assert_eq!(by("other").cwd.as_deref(), Some("C:\\work"));
        assert!(!format!("{v:?}").contains("SECRET-VALUE-1"));
    }

    #[test]
    fn codex_servers_reads_env_keys_env_vars_and_cwd() {
        let t = "[mcp_servers.a]\ncommand = \"npx\"\nargs = [\"-y\", \"x\"]\ncwd = \"C:\\\\w\"\nenv_vars = [\"HOME_X\"]\n\n[mcp_servers.a.env]\nTOKEN = \"SECRET-VALUE-1\"\n\n[mcp_servers.r]\nurl = \"https://x.example\"\n";
        let v = servers(T, t).unwrap();
        assert_eq!(v[0].env_keys, s(&["TOKEN", "HOME_X"]));
        assert_eq!(v[0].cwd.as_deref(), Some("C:\\w"));
        assert_eq!(v[0].skip, None);
        assert!(v[1].skip.is_some());
        assert!(!format!("{v:?}").contains("SECRET-VALUE-1"));
    }

    #[test]
    fn skips_names_sync_gate_cannot_hold_dollar_brace_and_already_adopted() {
        let j = r#"{"mcpServers":{
          "bad name":{"command":"x"},
          "dollar":{"command":"${HOME}/x"},
          "dollar-arg":{"command":"x","args":["--p","${X}"]},
          "adopted":{"command":"C:\\f\\sync_gate.exe","args":["mcp","connect","adopted"]},
          "nontext":{"command":"x","args":["a",1]},
          "cred":{"command":"x","args":["--api-key","v"]},
          "nocmd":{"args":["a"]},
          "ok":{"command":"x","args":["--port","3000"]}}}"#;
        let v = servers(J, j).unwrap();
        let skip = |n: &str| v.iter().find(|x| x.server == n).unwrap().skip.clone();
        assert!(skip("bad name").unwrap().contains("name must match"));
        assert!(skip("dollar").unwrap().contains("${"));
        assert!(skip("dollar-arg").unwrap().contains("${"));
        assert!(skip("adopted").unwrap().contains("already adopted"));
        assert!(skip("nontext").unwrap().contains("not all text"));
        assert!(skip("cred").unwrap().contains("--api-key"));
        assert!(skip("nocmd").unwrap().contains("no command"));
        assert_eq!(skip("ok"), None);
    }

    #[test]
    fn set_then_restore_is_byte_identical_claude() {
        let ed = round_trip(J, CLAUDE, "context7");
        assert!(!ed.inserted_args);
        assert_eq!(ed.original.command, "\"npx\"");
        assert!(ed.original.args.as_deref().unwrap().contains("@upstash"));
        assert!(
            ed.text
                .contains("\"other\": {\n      \"command\": \"node\"")
        );
        let ed = round_trip(J, CLAUDE, "bare");
        assert!(ed.inserted_args);
        assert!(
            ed.text
                .contains("\"command\": \"sync_gate\", \"args\": [\"mcp\",\"connect\",\"bare\"]")
        );
    }

    #[test]
    fn set_then_restore_is_byte_identical_codex_single_quotes() {
        let t = "model = \"x\"\n\n[mcp_servers.a]\ncommand = 'npx'\nargs = ['-y', 'pkg']\n\n[mcp_servers.b]\ncommand = 'node'\nargs = ['b.js']\n";
        let ed = round_trip(T, t, "a");
        assert_eq!(ed.original.command, "'npx'");
        assert!(
            ed.text
                .contains("[mcp_servers.b]\ncommand = 'node'\nargs = ['b.js']\n")
        );
    }

    #[test]
    fn set_then_restore_is_byte_identical_codex_without_args() {
        let t = "[mcp_servers.markitdown]\ncommand = \"markitdown-mcp\"\n\n[mcp_servers.z]\ncommand = \"z\"\nargs = [\"q\"]\n";
        let ed = round_trip(T, t, "markitdown");
        assert!(ed.inserted_args);
        assert!(ed.text.contains("command = \"sync_gate\"\nargs = ["));
        // The last line of a file without a final newline.
        round_trip(T, "[mcp_servers.m]\ncommand = \"m\"", "m");
    }

    #[test]
    fn set_then_restore_is_byte_identical_codex_multiline_args_with_comments() {
        let t = "[mcp_servers.a]\n# why\ncommand = \"npx\"\nargs = [\n  \"-y\", # yes\n  # c\n  \"pkg\",\n]\nstartup_timeout_sec = 20\n";
        let ed = round_trip(T, t, "a");
        assert!(ed.text.ends_with("startup_timeout_sec = 20\n"));
    }

    #[test]
    fn set_then_restore_is_byte_identical_codex_trailing_comment_on_command_line() {
        let t = "[mcp_servers.a]\ncommand = \"a\"   # the runner\nenabled = true\n";
        let ed = round_trip(T, t, "a");
        assert!(
            ed.text
                .contains("command = \"sync_gate\"   # the runner\nargs = [")
        );
    }

    #[test]
    fn set_then_restore_is_byte_identical_codex_inline_table_and_dotted_keys() {
        let t = "mcp_servers.b.command = 'b.exe'\nmcp_servers.b.args = ['--flag', \"v\"]\nmcp_servers.a = { command = \"npx\", args = [\"-y\", \"x\"] }\nmcp_servers.c = { command = \"c\" }\nmcp_servers.d = { args = [\"q\"], command = \"d\" }\n";
        round_trip(T, t, "a");
        round_trip(T, t, "b");
        let ed = round_trip(T, t, "c");
        assert!(ed.text.contains("{ command = \"sync_gate\", args = ["));
        round_trip(T, t, "d");
    }

    #[test]
    fn set_then_restore_keeps_crlf_line_endings() {
        let t = "[mcp_servers.a]\r\ncommand = \"a\"\r\nenabled = true\r\n".to_string();
        let ed = round_trip(T, &t, "a");
        assert!(ed.text.contains("\"sync_gate\"\r\nargs = "));
        assert_eq!(
            ed.text.matches('\n').count(),
            ed.text.matches("\r\n").count()
        );
        round_trip(J, &CLAUDE.replace('\n', "\r\n"), "bare");
    }

    #[test]
    fn set_changes_only_the_two_values() {
        for (f, text, name) in [
            (J, CLAUDE, "context7"),
            (
                T,
                "[mcp_servers.a]\ncommand = 'npx'\n# mid\nargs = ['-y']\nenv = {}\n",
                "a",
            ),
        ] {
            let p = &parse(f, text).unwrap();
            let p = find(p, name).unwrap();
            let (c, a) = (p.cmd.clone().unwrap().0, p.args.clone().unwrap().0);
            let ed = set_launch(f, text, name, "sync_gate", &s(&["mcp", "connect", name])).unwrap();
            assert!(ed.text.starts_with(&text[..c.start]));
            assert!(ed.text.ends_with(&text[a.end..]));
            let mid = &text[c.end..a.start];
            assert!(ed.text.contains(mid));
        }
    }

    #[test]
    fn restore_after_other_edits_changes_only_that_server() {
        let new_args = s(&["mcp", "connect", "context7"]);
        let ed = set_launch(J, CLAUDE, "context7", "sync_gate", &new_args).unwrap();
        let edited = ed
            .text
            .replace("SECRET-VALUE-1", "SECRET-VALUE-2")
            .replace("\"projects\": {}", "\"projects\": {}, \"added\": 1")
            .replace(
                "\"bare\": {",
                "\"bare2\": {\"command\": \"n\"}, \"bare\": {",
            );
        let r = restore_launch(
            J,
            &edited,
            "context7",
            ("sync_gate", &new_args),
            &ed.original,
            ("npx", Some(&s(&["-y", "@upstash/context7-mcp"]))),
            false,
        )
        .unwrap();
        let Restored::Done(t) = r else { panic!() };
        assert_eq!(
            t,
            CLAUDE
                .replace("SECRET-VALUE-1", "SECRET-VALUE-2")
                .replace("\"projects\": {}", "\"projects\": {}, \"added\": 1")
                .replace(
                    "\"bare\": {",
                    "\"bare2\": {\"command\": \"n\"}, \"bare\": {"
                )
        );
    }

    #[test]
    fn restore_reports_gone_already_original_and_changed() {
        let orig = ("npx", Some(&s(&["-y", "@upstash/context7-mcp"])[..]));
        let new_args = s(&["mcp", "connect", "context7"]);
        let ed = set_launch(J, CLAUDE, "context7", "sync_gate", &new_args).unwrap();
        let run = |text: &str| {
            restore_launch(
                J,
                text,
                "context7",
                ("sync_gate", &new_args),
                &ed.original,
                (orig.0, orig.1),
                false,
            )
            .unwrap()
        };
        assert!(matches!(run(CLAUDE), Restored::AlreadyOriginal));
        assert!(matches!(run("{\"mcpServers\":{}}"), Restored::Gone));
        assert!(matches!(run("{}"), Restored::Gone));
        assert!(matches!(
            run(&ed.text.replace("\"sync_gate\"", "\"mine\"")),
            Restored::Changed
        ));
        assert!(matches!(run(&ed.text), Restored::Done(_)));
    }

    #[test]
    fn restore_after_claude_reformatted_the_file_still_puts_the_values_back() {
        let compact = r#"{"mcpServers":{"a":{"command":"npx","env":{"K":"v"}},"b":{"command":"x","args":["1"]}}}"#;
        let new_args = s(&["mcp", "connect", "a"]);
        let ed = set_launch(J, compact, "a", "sync_gate", &new_args).unwrap();
        assert!(ed.inserted_args);
        let v: serde_json::Value = serde_json::from_str(&ed.text).unwrap();
        let pretty = serde_json::to_string_pretty(&v).unwrap();
        assert!(pretty.contains("\"args\": [\n"));
        let r = restore_launch(
            J,
            &pretty,
            "a",
            ("sync_gate", &new_args),
            &ed.original,
            ("npx", None),
            true,
        )
        .unwrap();
        let Restored::Done(t) = r else { panic!() };
        let got: serde_json::Value = serde_json::from_str(&t).unwrap();
        assert_eq!(
            got,
            serde_json::from_str::<serde_json::Value>(compact).unwrap()
        );
        assert!(t.contains("\"command\": \"npx\""));
    }

    #[test]
    fn credential_like_args_are_detected() {
        let c = |v: &[&str]| looks_like_credential(&s(v));
        assert_eq!(c(&["--api-key", "abc"]).as_deref(), Some("--api-key"));
        assert_eq!(c(&["--token=abc"]).as_deref(), Some("--token"));
        assert_eq!(c(&["MY_SECRET=abc"]).as_deref(), Some("MY_SECRET"));
        assert_eq!(c(&["--password", "p"]).as_deref(), Some("--password"));
        assert_eq!(c(&["-y", "@upstash/context7-mcp"]), None);
        assert_eq!(c(&["--port", "3000"]), None);
        assert_eq!(c(&["--auth"]), None);
    }

    #[test]
    fn set_refuses_a_dotted_key_without_args_and_nothing_changes() {
        let t = "mcp_servers.a.command = 'a.exe'\nmcp_servers.b.command = 'b.exe'\n";
        for n in ["a", "b"] {
            let e = set_launch(T, t, n, "sync_gate", &s(&["mcp", "connect", n]));
            assert!(e.err().unwrap().contains("unsupported layout"));
        }
        assert!(servers(T, t).is_ok());
    }

    #[test]
    fn bom_is_preserved_in_both_formats_and_restores_identical() {
        let j = format!("\u{feff}{CLAUDE}");
        let ed = round_trip(J, &j, "context7");
        assert!(ed.text.starts_with('\u{feff}'));
        let ed = round_trip(J, &j, "bare");
        assert!(ed.text.starts_with("\u{feff}{"));
        let t = "\u{feff}[mcp_servers.a]\ncommand = \"a\"\n";
        let ed = round_trip(T, t, "a");
        assert!(ed.text.starts_with("\u{feff}[mcp"));
    }

    #[test]
    fn an_escaped_key_without_args_is_refused_and_with_args_is_edited() {
        let no = "[mcp_servers.a]\n\"comm\\u0061nd\" = \"x\"\n";
        let e = set_launch(T, no, "a", "sync_gate", &s(&["mcp", "connect", "a"]));
        assert!(e.err().unwrap().contains("unsupported layout"));
        let yes = "[mcp_servers.a]\n\"comm\\u0061nd\" = \"x\"\nargs = [\"y\"]\n";
        round_trip(T, yes, "a");
    }

    #[test]
    fn duplicate_keys_are_refused_without_writing() {
        let t = "[mcp_servers.a]\ncommand = \"x\"\ncommand = \"y\"\n";
        assert!(servers(T, t).err().unwrap().contains("duplicate key"));
        assert!(
            set_launch(T, t, "a", "f", &[])
                .err()
                .unwrap()
                .contains("duplicate key")
        );
        for j in [
            r#"{"mcpServers":{"a":{"command":"x","command":"y"}}}"#,
            r#"{"mcpServers":{"a":{"command":"x"},"a":{"command":"y"}}}"#,
            r#"{"mcpServers":{"a":{"command":"x"}},"mcpServers":{}}"#,
        ] {
            assert!(
                servers(J, j).err().unwrap().contains("duplicate key"),
                "{j}"
            );
            assert!(
                set_launch(J, j, "a", "f", &[])
                    .err()
                    .unwrap()
                    .contains("duplicate key")
            );
        }
    }

    #[test]
    fn the_semantic_check_rejects_an_edit_that_touched_another_server() {
        let orig = r#"{"mcpServers":{"a":{"command":"npx"},"b":{"command":"y"}}}"#;
        let before = parse(J, orig).unwrap();
        // args fell at the root instead of inside the server
        let bad = r#"{"mcpServers":{"a":{"command":"sync_gate"},"b":{"command":"y"}},"args":["mcp","connect","a"]}"#;
        let a = s(&["mcp", "connect", "a"]);
        assert!(verify_edit(J, &before, bad, "a", "sync_gate", Some(&a)).is_err());
        // args landed in the neighbour
        let bad = r#"{"mcpServers":{"a":{"command":"sync_gate"},"b":{"command":"y","args":["mcp","connect","a"]}}}"#;
        assert!(verify_edit(J, &before, bad, "a", "sync_gate", Some(&a)).is_err());
        let good = r#"{"mcpServers":{"a":{"command":"sync_gate","args":["mcp","connect","a"]},"b":{"command":"y"}}}"#;
        assert!(verify_edit(J, &before, good, "a", "sync_gate", Some(&a)).is_ok());
    }

    #[test]
    fn parse_errors_never_carry_file_content() {
        let secret = "SECRET-VALUE-1";
        let tomls = [
            "[mcp_servers.a]\ncommand = \"x\"\nenv = { TOKEN = \"SECRET-VALUE-1\" } oops\n",
            "[mcp_servers.a]\ncommand = \"x\"\nenv = \"SECRET-VALUE-1\"\n",
            "[mcp_servers.a]\ncommand = \"x\"\ncwd = \"SECRET-VALUE-1\"\ncwd = 1\n",
            // The value itself contains the separator the scrubber looks for.
            "[mcp_servers.a]\ncommand = \"x\"\nenv = \"p, expected SECRET-VALUE-1\"\n",
        ];
        for t in tomls {
            let e = servers(T, t).err().unwrap();
            assert!(!e.contains(secret), "{e}");
            assert!(e.contains("line"), "{e}");
            let e = set_launch(T, t, "a", "f", &[]).err().unwrap();
            assert!(!e.contains(secret), "{e}");
        }
        let jsons = [
            r#"{"mcpServers":{"a":{"command":"x","env":{"T":"SECRET-VALUE-1"} oops}}}"#,
            r#"{"mcpServers":"SECRET-VALUE-1"}"#,
            r#"{"mcpServers":{"a":"SECRET-VALUE-1"}}"#,
            r#"{"mcpServers":"p, expected SECRET-VALUE-1"}"#,
        ];
        for j in jsons {
            let e = servers(J, j).err().unwrap();
            assert!(!e.contains(secret), "{e}");
            let e = set_launch(J, j, "a", "f", &[]).err().unwrap();
            assert!(!e.contains(secret), "{e}");
        }
    }

    #[test]
    fn any_value_after_a_sensitive_flag_is_a_credential() {
        let c = |v: &[&str]| looks_like_credential(&s(v));
        assert_eq!(c(&["--token", "-abc"]).as_deref(), Some("--token"));
        assert_eq!(c(&["--api-key", "--x"]).as_deref(), Some("--api-key"));
        assert_eq!(c(&["--api-key=-abc"]).as_deref(), Some("--api-key"));
    }

    #[test]
    fn restore_does_not_call_a_present_invalid_args_original() {
        let new_args = s(&["mcp", "connect", "a"]);
        for bad in ["null", "[1]", "\"s\""] {
            let text = format!(r#"{{"mcpServers":{{"a":{{"command":"npx","args":{bad}}}}}}}"#);
            let ed = LaunchText {
                command: "\"npx\"".into(),
                args: None,
            };
            let r = restore_launch(
                J,
                &text,
                "a",
                ("sync_gate", &new_args),
                &ed,
                ("npx", None),
                true,
            )
            .unwrap();
            assert!(matches!(r, Restored::Changed), "{bad}");
        }
    }

    #[test]
    fn the_semantic_check_compares_every_other_field() {
        let orig = r#"{"mcpServers":{"a":{"command":"npx","env":{"K":"SECRET-VALUE-1"}},"b":{"command":"y","env":{"K":"SECRET-VALUE-2"}}}}"#;
        let before = parse(J, orig).unwrap();
        let a = s(&["mcp", "connect", "a"]);
        let ok = r#"{"mcpServers":{"a":{"command":"sync_gate","args":["mcp","connect","a"],"env":{"K":"SECRET-VALUE-1"}},"b":{"command":"y","env":{"K":"SECRET-VALUE-2"}}}}"#;
        assert!(verify_edit(J, &before, ok, "a", "sync_gate", Some(&a)).is_ok());
        for bad in [
            ok.replace("SECRET-VALUE-2", "SECRET-VALUE-3"),
            ok.replace("\"y\",", "\"y\",\"cwd\":\"/\","),
            ok.replace("SECRET-VALUE-1", "SECRET-VALUE-9"),
            ok.replace("\"args\"", "\"cwd\":\"/\",\"args\""),
        ] {
            let e = verify_edit(J, &before, &bad, "a", "sync_gate", Some(&a)).unwrap_err();
            assert!(!e.contains("SECRET"), "{e}");
        }
        let t = "[mcp_servers.a]\ncommand = \"x\"\n[mcp_servers.b]\ncommand = \"y\"\nenv = { K = \"SECRET-VALUE-2\" }\n";
        let before = parse(T, t).unwrap();
        let bad = "[mcp_servers.a]\ncommand = \"f\"\nargs = [\"mcp\", \"connect\", \"a\"]\n[mcp_servers.b]\ncommand = \"y\"\nenv = { K = \"SECRET-VALUE-3\" }\n";
        assert!(verify_edit(T, &before, bad, "a", "f", Some(&a)).is_err());
    }

    #[test]
    fn restore_finds_args_by_its_decoded_key() {
        let compact = r#"{"mcpServers":{"a":{"command":"npx"}}}"#;
        let new_args = s(&["mcp", "connect", "a"]);
        let ed = set_launch(J, compact, "a", "sync_gate", &new_args).unwrap();
        let text = ed.text.replace("\"args\"", "\"\\u0061rgs\"");
        let r = restore_launch(
            J,
            &text,
            "a",
            ("sync_gate", &new_args),
            &ed.original,
            ("npx", None),
            true,
        )
        .unwrap();
        let Restored::Done(t) = r else { panic!() };
        assert_eq!(t, compact);
    }
}
