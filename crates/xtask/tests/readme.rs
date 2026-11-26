//! Keeps the three READMEs aligned (same sections, commands, links and benchmark block) and checks
//! the wording of `SECURITY.md` that the READMEs rely on.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

/// (anchor id, English, Portuguese, Spanish): the exact heading of each section.
const TITLES: [(&str, &str, &str, &str); 7] = [
    ("install", "Install", "Instalação", "Instalación"),
    ("highlights", "Highlights", "Destaques", "Destacados"),
    ("quickstart", "Quickstart", "Início rápido", "Inicio rápido"),
    ("agents", "Agents", "Agentes", "Agentes"),
    ("limits", "Limits", "Limites", "Límites"),
    ("docs", "Documentation", "Documentação", "Documentación"),
    ("license", "License", "Licença", "Licencia"),
];

const LANG_LINE: &str = "English | [Português](README.pt-BR.md) | [Español](README.es.md)";
const FILES: [&str; 3] = ["README.md", "README.pt-BR.md", "README.es.md"];
const BENCH_OPEN: &str = "<!-- bench -->";
const BENCH_CLOSE: &str = "<!-- /bench -->";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    let p = root().join(rel);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {rel}: {e}"))
}

fn readmes() -> Vec<(&'static str, String)> {
    FILES.iter().map(|f| (*f, read(f))).collect()
}

fn anchors(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.strip_prefix("<!-- s:")?.strip_suffix(" -->"))
        .map(str::to_string)
        .collect()
}

/// (anchor id, the first non-empty line after it)
fn headings(text: &str) -> Vec<(String, String)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        if let Some(id) = l
            .strip_prefix("<!-- s:")
            .and_then(|r| r.strip_suffix(" -->"))
        {
            let next = lines[i + 1..].iter().find(|x| !x.trim().is_empty());
            out.push((
                id.to_string(),
                next.map_or(String::new(), |s| s.to_string()),
            ));
        }
    }
    out
}

fn block<'a>(text: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let s = text.find(open)?;
    let e = text[s..].find(close)? + s + close.len();
    Some(&text[s..e])
}

/// Contents of the fenced code blocks, in order (the fence lines included).
fn code_blocks(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur: Option<String> = None;
    for l in text.lines() {
        if l.starts_with("```") {
            match cur.take() {
                Some(mut b) => {
                    b.push_str(l);
                    out.push(b);
                }
                None => cur = Some(format!("{l}\n")),
            }
        } else if let Some(b) = cur.as_mut() {
            b.push_str(l);
            b.push('\n');
        }
    }
    out
}

fn outside_code(text: &str) -> String {
    let mut in_code = false;
    let mut out = String::new();
    for l in text.lines() {
        if l.starts_with("```") {
            in_code = !in_code;
        } else if !in_code {
            out.push_str(l);
            out.push('\n');
        }
    }
    out
}

/// Relative link and image targets: every `](target)` that is not a URL or a same-page anchor.
fn local_targets(text: &str) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for part in outside_code(text).split("](").skip(1) {
        if let Some(end) = part.find(')') {
            let t = &part[..end];
            if !t.starts_with("http") && !t.starts_with('#') && !t.starts_with("mailto:") {
                set.insert(t.to_string());
            }
        }
    }
    set
}

#[test]
fn readmes_exist_and_start_the_same_way() {
    for (name, t) in readmes() {
        assert_eq!(t.lines().next(), Some("# sync_gate"), "{name}: line 1");
        assert!(
            t.lines().take(6).any(|l| l == LANG_LINE),
            "{name}: the language line is missing or different from `{LANG_LINE}`"
        );
    }
}

#[test]
fn same_sections_in_the_same_order() {
    let want: Vec<String> = TITLES.iter().map(|t| t.0.to_string()).collect();
    for (name, t) in readmes() {
        assert_eq!(anchors(&t), want, "{name}: anchors differ from TITLES");
    }
}

#[test]
fn each_section_has_its_own_title() {
    for (name, t) in readmes() {
        let got = headings(&t);
        for (id, line) in &got {
            let row = TITLES
                .iter()
                .find(|r| r.0 == id)
                .unwrap_or_else(|| panic!("{name}: unknown anchor {id}"));
            let title = match name {
                "README.md" => row.1,
                "README.pt-BR.md" => row.2,
                _ => row.3,
            };
            let want = format!("## {title}");
            assert_eq!(line, &want, "{name}: heading under anchor `{id}`");
        }
        assert_eq!(got.len(), TITLES.len(), "{name}: number of anchors");
    }
}

#[test]
fn bench_block_is_identical_and_matches_the_benchmark_doc() {
    let all = readmes();
    let first = block(&all[0].1, BENCH_OPEN, BENCH_CLOSE).expect("README.md has no bench block");
    for (name, t) in &all[1..] {
        let b =
            block(t, BENCH_OPEN, BENCH_CLOSE).unwrap_or_else(|| panic!("{name}: no bench block"));
        assert_eq!(b, first, "{name}: the bench block differs from README.md");
    }
    // The doc exists, so it must carry the same block (a doc without it would assert nothing).
    let doc = read("docs/benchmark.md");
    let d = block(&doc, BENCH_OPEN, BENCH_CLOSE).expect("docs/benchmark.md has no bench block");
    assert_eq!(d, first, "docs/benchmark.md has a different bench block");
}

#[test]
fn limits_state_the_exception_to_the_25_hours() {
    // Part B of SECURITY.md: an `elevated` guest that does not enqueue, and an orphan marker, have no limit.
    for (name, t) in readmes() {
        let key = match name {
            "README.md" => "no time limit",
            "README.pt-BR.md" => "sem prazo",
            _ => "sin plazo",
        };
        let l = t.lines().find(|l| l.contains("25 ")).unwrap_or("");
        assert!(
            l.contains(key) && l.contains("elevated"),
            "{name}: the 25 hours line must also say who has `{key}` (elevated guest, orphan marker)"
        );
    }
}

#[test]
fn code_blocks_are_identical_and_in_the_same_order() {
    let all = readmes();
    let first = code_blocks(&all[0].1);
    assert!(!first.is_empty(), "README.md has no code block");
    for (name, t) in &all[1..] {
        assert_eq!(
            code_blocks(t),
            first,
            "{name}: a code block differs from README.md"
        );
    }
}

#[test]
fn same_links_and_images() {
    let all = readmes();
    let first = local_targets(&all[0].1);
    assert!(
        first.contains("docs/install.md"),
        "README.md must link docs/install.md"
    );
    for (name, t) in &all[1..] {
        assert_eq!(
            local_targets(t),
            first,
            "{name}: relative links or images differ from README.md"
        );
    }
}

#[test]
fn size_limits() {
    let all = readmes();
    for (name, t) in &all {
        assert!(t.lines().count() <= 150, "{name}: more than 150 lines");
    }
    let words = outside_code(&all[0].1)
        .split_whitespace()
        .filter(|w| w.chars().any(char::is_alphanumeric))
        .count();
    assert!(
        words <= 600,
        "README.md: {words} words outside code blocks (max 600)"
    );
}

// ---- SECURITY.md ----

/// Wording the READMEs rely on. `q1` is the line `<!-- q1: N -->` of the file.
fn check_security(text: &str) -> Result<(), String> {
    let q1 = text
        .lines()
        .find_map(|l| l.strip_prefix("<!-- q1: ")?.strip_suffix(" -->"))
        .ok_or("no `<!-- q1: N -->` line")?;
    if !["1", "2", "3"].contains(&q1) {
        return Err(format!("q1 must be 1, 2 or 3, not {q1}"));
    }
    // A: who can read the pending files.
    if !(text.contains("CodexSandboxUsers") && text.contains("readable by other accounts")) {
        return Err("part A missing: the sandbox group can read the pending files".into());
    }
    // B: how long they stay. Words, not the whole sentence.
    if text.contains("until they run") {
        return Err("part B: `until they run` without a limit".into());
    }
    let has25 = text.contains("25 hours");
    if q1 == "1" && !has25 {
        return Err("part B missing: q1 = 1 needs the 25 hours limit".into());
    }
    if q1 != "1" && has25 {
        return Err(format!("q1 = {q1} but the text still says 25 hours"));
    }
    // C: the cost key leaves the machine.
    for w in ["cost key", "leaves the machine", "provider"] {
        if !text.contains(w) {
            return Err(format!("part C missing: `{w}`"));
        }
    }
    Ok(())
}

#[test]
fn security_md_has_parts_a_b_and_c() {
    if let Err(e) = check_security(&read("SECURITY.md")) {
        panic!("SECURITY.md: {e}");
    }
}

#[test]
fn security_check_catches_each_control() {
    let ok = read("SECURITY.md");
    assert!(check_security(&ok).is_ok());
    let q1_changed = ok.replace("<!-- q1: 1 -->", "<!-- q1: 2 -->");
    assert!(
        check_security(&q1_changed).is_err(),
        "q1 changed without the text"
    );
    assert!(
        check_security(&ok.replace("cost key", "key")).is_err(),
        "part C"
    );
    assert!(
        check_security(&ok.replace("CodexSandboxUsers", "group")).is_err(),
        "part A"
    );
    assert!(
        check_security(&ok.replace("for up to 25 hours", "until they run")).is_err(),
        "part B"
    );
}
