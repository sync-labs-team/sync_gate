//! `cargo xtask dist` and `cargo xtask scan`: the release archives, and the search that keeps
//! private names out of them.

use std::env;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const WINDOWS_TARGET: &str = "x86_64-pc-windows-msvc";
// The `sync_gate_shim` package builds the `sync_gate_mcp` binary.
const EXES: [&str; 3] = ["sync_gate", "sync_gated", "sync_gate_mcp"];
const SCRIPTS: [&str; 2] = ["install.sh", "install.ps1"];
const LICENSES: [&str; 2] = ["LICENSE-MIT", "LICENSE-APACHE"];
/// Image of the Linux build (`tools/dist/Dockerfile`), apart from the CI image.
const IMAGE: &str = "sync_gate-dist:1.100";
/// The texts the release prints on its own; a deny entry that would match inside them is refused.
const PUBLIC_TEXTS: [&str; 2] = [
    "noreply@synclabs.team",
    "https://gate.synclabs.team/install.ps1",
];
/// Words too common to be a finding: a customer with such a name goes in by the whole compound name.
const COMMON_WORDS: &[&str] = &[
    "setup",
    "global",
    "trade",
    "plataforma",
    "platform",
    "administradora",
    "administrador",
    "dashboard",
    "system",
    "systems",
    "sistema",
    "sistemas",
    "gateway",
    "cliente",
    "clientes",
    "client",
    "clients",
    "customer",
    "customers",
    "projeto",
    "project",
    "empresa",
    "company",
    "group",
    "grupo",
    "service",
    "services",
    "servico",
    "servicos",
    "solutions",
    "total",
    "ambiental",
    "backoffice",
    "office",
    "portal",
    "contrato",
    "contract",
    "financeiro",
    "finance",
    "pagamento",
    "pagamentos",
    "payment",
    "payments",
    "ledger",
    "monitoring",
    "infrastructure",
    "docs",
    "test",
    "teste",
    "tests",
    "admin",
    "sales",
    "vendas",
    "digital",
    "tech",
    "software",
    "server",
    "servidor",
    "banco",
    "bank",
    "data",
    "dados",
    "main",
    "core",
];

/// One thing the privacy search looks for.
#[derive(Debug, Clone, PartialEq)]
pub struct Needle {
    pub term: String,
    /// Whole word: the characters around a match are not letters or digits.
    pub whole: bool,
    /// Where it came from (`line 3 of the deny list`); the term itself is never printed.
    pub origin: String,
}

#[derive(Debug, PartialEq)]
pub struct Hit {
    pub file: String,
    pub pos: usize,
    pub origin: String,
    pub name: bool,
}

/// One `deny.txt` entry.
#[derive(Debug, PartialEq)]
pub struct Entry {
    pub whole: bool,
    pub term: String,
    pub line: usize,
}

/// Lower-cases ASCII and the Latin-1 capitals (`À`..`Þ`, UTF-8 `C3 80..9E` or UTF-16 `00C0..00DE`),
/// byte for byte, so positions stay the same.
// shortcut: only ASCII and Latin-1 capitals are folded; Latin Extended (`Ł`, `Ő`) is not, upgrade
// when a listed name has one.
fn fold(bytes: &[u8], unit: usize) -> Vec<u8> {
    let mut hay = bytes.to_ascii_lowercase();
    for i in 0..hay.len().saturating_sub(1) {
        let (a, b) = (hay[i], hay[i + 1]);
        if unit == 1 && a == 0xc3 && (0x80..=0x9e).contains(&b) && b != 0x97 {
            hay[i + 1] = b + 0x20;
        } else if unit == 2 && b == 0 && (0xc0..=0xde).contains(&a) && a != 0xd7 {
            hay[i] = a + 0x20;
        }
    }
    hay
}

/// A form to look for, and the words it is made of when a line break may split them.
type Pattern = (Vec<u8>, Option<Vec<Vec<u8>>>);

/// Characters a line break can drag in between two words: indentation and comment or quote marks.
const GAP: &str = " \t\r\n>/*#";

/// Where `words` end when separated by single spaces and at least one line break.
fn broken_end(hay: &[u8], pos: usize, words: &[Vec<u8>], unit: usize) -> Option<usize> {
    let mut at = pos;
    let mut broke_line = false;
    for (i, word) in words.iter().enumerate() {
        if i > 0 {
            let (mut newline, mut n) = (false, 0);
            let start = at;
            while n < 12 && at + unit <= hay.len() {
                let code = if unit == 1 {
                    u32::from(hay[at])
                } else {
                    u32::from(u16::from_le_bytes([hay[at], hay[at + 1]]))
                };
                match char::from_u32(code).filter(|c| GAP.contains(*c)) {
                    Some(c) => newline |= c == '\n',
                    None => break,
                }
                at += unit;
                n += 1;
            }
            if !newline && (n != 1 || hay[start] != b' ') {
                return None;
            }
            broke_line |= newline;
        }
        if hay.get(at..at + word.len())? != &word[..] {
            return None;
        }
        at += word.len();
    }
    broke_line.then_some(at)
}

/// `(position, index into needles)` of every match, in UTF-8 and in UTF-16LE, without case.
pub fn privacy_hits(bytes: &[u8], needles: &[Needle]) -> Vec<(usize, usize)> {
    let hays = [(1, fold(bytes, 1)), (2, fold(bytes, 2))];
    let encode = |form: &str, unit: usize| -> Vec<u8> {
        if unit == 1 {
            form.as_bytes().to_vec()
        } else {
            form.encode_utf16().flat_map(u16::to_le_bytes).collect()
        }
    };
    let mut hits = Vec::new();
    for (index, needle) in needles.iter().enumerate() {
        let term = needle.term.trim().to_lowercase();
        if term.chars().count() < 3 {
            continue;
        }
        // a name with spaces is also looked for as a slug, a path, a URL or a query:
        // `a b` is `a-b`, `a_b`, `ab`, `a.b`, `a/b`, `a\b`, `a%20b`, `a+b`, `a%2fb`
        let forms: Vec<String> = if term.contains(' ') {
            [" ", "-", "_", "", ".", "/", "\\", "%20", "+", "%2f"]
                .iter()
                .map(|sep| term.replace(' ', sep))
                .collect()
        } else {
            vec![term.clone()]
        };
        for (unit, hay) in &hays {
            let mut pats: Vec<Pattern> = forms.iter().map(|f| (encode(f, *unit), None)).collect();
            // the same name with a line break (and its indentation or comment mark) between words
            if term.contains(' ') {
                let words: Vec<Vec<u8>> = term.split(' ').map(|w| encode(w, *unit)).collect();
                pats.push((words[0].clone(), Some(words)));
            }
            for (pat, words) in pats {
                for pos in 0..hay.len().saturating_sub(pat.len() - 1) {
                    if hay[pos..pos + pat.len()] != pat[..] {
                        continue;
                    }
                    let len = match &words {
                        None => Some(pat.len()),
                        Some(words) => broken_end(hay, pos, words, *unit).map(|end| end - pos),
                    };
                    if len.is_some_and(|len| !needle.whole || edges_ok(hay, pos, len, *unit)) {
                        hits.push((pos, index));
                    }
                }
            }
        }
    }
    hits.sort_unstable();
    hits
}

/// True when the characters around a match are not letters or digits.
fn edges_ok(hay: &[u8], pos: usize, len: usize, unit: usize) -> bool {
    let end = pos + len;
    let (before, after) = if unit == 1 {
        let before = hay[..pos]
            .iter()
            .rev()
            .take(4)
            .position(|byte| byte & 0xc0 != 0x80)
            .and_then(|offset| std::str::from_utf8(&hay[pos - offset - 1..pos]).ok())
            .and_then(|text| text.chars().next());
        let after = hay[end..(end + 4).min(hay.len())]
            .utf8_chunks()
            .next()
            .and_then(|chunk| chunk.valid().chars().next());
        (before, after)
    } else {
        // In a binary, UTF-16 matches may start at either byte alignment. Keep treating
        // neighboring code units outside Latin-1 as noise.
        let latin1 = |bytes: &[u8]| {
            let [low, 0] = bytes else { return None };
            Some(char::from(*low))
        };
        let before = pos.checked_sub(2).and_then(|at| latin1(&hay[at..pos]));
        let after = hay.get(end..end + 2).and_then(latin1);
        (before, after)
    };
    !before.is_some_and(char::is_alphanumeric) && !after.is_some_and(char::is_alphanumeric)
}

pub fn parse_deny(text: &str) -> Result<Vec<Entry>, String> {
    let mut entries = Vec::new();
    for (i, raw) in text.trim_start_matches('\u{feff}').lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (whole, term) = match (line.strip_prefix("w "), line.strip_prefix("s ")) {
            (Some(term), _) => (true, term.trim()),
            (_, Some(term)) => (false, term.trim()),
            _ => {
                return Err(format!(
                    "deny list line {}: expected `w <term>` or `s <term>`",
                    i + 1
                ));
            }
        };
        if term.is_empty() {
            return Err(format!("deny list line {}: empty term", i + 1));
        }
        entries.push(Entry {
            whole,
            term: term.into(),
            line: i + 1,
        });
    }
    Ok(entries)
}

pub fn parse_allow(text: &str) -> Result<Vec<(String, String)>, String> {
    let mut allowed = Vec::new();
    for (i, raw) in text.trim_start_matches('\u{feff}').lines().enumerate() {
        if raw.trim().is_empty() || raw.trim().starts_with('#') {
            continue;
        }
        match raw.split_once('\t') {
            Some((term, reason)) if !term.trim().is_empty() && !reason.trim().is_empty() => {
                allowed.push((term.trim().to_string(), reason.trim().to_string()));
            }
            _ => {
                return Err(format!(
                    "allow list line {}: expected `<term><TAB><reason>`",
                    i + 1
                ));
            }
        }
    }
    Ok(allowed)
}

pub fn lint_deny(entries: &[Entry]) -> Result<(), String> {
    let mut errors = Vec::new();
    for entry in entries {
        let term = entry.term.to_lowercase();
        let letters = entry.term.chars().count();
        let squashed: String = term.chars().filter(|c| !" _-".contains(*c)).collect();
        let needle = Needle {
            term: entry.term.clone(),
            whole: entry.whole,
            origin: String::new(),
        };
        let problem = if squashed.contains(&"sync_gate".replace('_', ""))
            || (squashed.contains("synclabs") && !term.contains('@'))
        {
            "the product or the brand name is not a private term"
        } else if PUBLIC_TEXTS
            .iter()
            .any(|text| !privacy_hits(text.as_bytes(), std::slice::from_ref(&needle)).is_empty())
        {
            "would match inside a fixed public text; list the exact personal address or name"
        } else if letters < 3 {
            "a term under 3 characters is never searched"
        } else if entry.whole && letters < 4 {
            "a `w` term needs 4 letters or more"
        } else if COMMON_WORDS.contains(&term.as_str()) {
            "a common word; list the whole compound name"
        } else if !entry.whole && letters < 8 && !term.contains(['\\', '/', '@', '.']) {
            "a short `s` fragment; use `w`, or a path, address or domain"
        } else {
            continue;
        };
        errors.push(format!("deny list line {}: {problem}", entry.line));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("\n"))
    }
}

/// Lints the deny list and removes the terms the allow list excuses; the second value is the
/// `allowed: …` lines to print.
pub fn load_needles(deny: &str, allow: &str) -> Result<(Vec<Needle>, Vec<String>), String> {
    let entries = parse_deny(deny)?;
    lint_deny(&entries)?;
    let allowed = parse_allow(allow)?;
    let (mut needles, mut notes) = (Vec::new(), Vec::new());
    for entry in entries {
        let excuse = allowed
            .iter()
            .find(|(term, _)| term.to_lowercase() == entry.term.to_lowercase());
        match excuse {
            Some((term, reason)) => notes.push(format!("allowed: {term} ({reason})")),
            None => needles.push(Needle {
                term: entry.term,
                whole: entry.whole,
                origin: format!("line {} of the deny list", entry.line),
            }),
        }
    }
    if needles.is_empty() {
        return Err("deny list has no effective terms".into());
    }
    Ok((needles, notes))
}

struct Scan<'a> {
    needles: &'a [Needle],
    found: Vec<Hit>,
    entries: usize,
}

impl<'a> Scan<'a> {
    fn new(needles: &'a [Needle]) -> Self {
        Self {
            needles,
            found: Vec::new(),
            entries: 0,
        }
    }

    fn visit(
        &mut self,
        path: &Path,
        relative: &Path,
        parent_hits: &[(usize, usize)],
        read_contents: &impl Fn(&Path) -> bool,
    ) -> Result<(), String> {
        self.entries += 1;
        let mut name_hits = privacy_hits(relative.as_os_str().as_encoded_bytes(), self.needles);
        name_hits.dedup();
        let label = if !name_hits.is_empty() {
            format!("entry #{} [path redacted]", self.entries)
        } else if relative.as_os_str().is_empty() {
            ".".into()
        } else {
            relative.to_string_lossy().escape_debug().to_string()
        };
        let unreadable = |e| format!("cannot read {label}: {e}");
        let meta = fs::symlink_metadata(path).map_err(unreadable)?;
        // A link would hide files from the gate: refuse it instead of passing in silence.
        if meta.file_type().is_symlink() {
            return Err(format!(
                "{label} is a link; the scan does not follow links, replace it with the real file"
            ));
        }
        for &(pos, index) in &name_hits {
            if parent_hits.binary_search(&(pos, index)).is_err() {
                self.found.push(Hit {
                    file: label.clone(),
                    pos,
                    origin: self.needles[index].origin.clone(),
                    name: true,
                });
            }
        }
        if meta.is_dir() {
            let mut children: Vec<_> = fs::read_dir(path)
                .and_then(|dir| dir.map(|entry| entry.map(|e| e.file_name())).collect())
                .map_err(unreadable)?;
            children.sort();
            for child in children {
                self.visit(
                    &path.join(&child),
                    &relative.join(&child),
                    &name_hits,
                    read_contents,
                )?;
            }
        } else if meta.is_file() && read_contents(path) {
            let bytes = fs::read(path).map_err(unreadable)?;
            for (pos, index) in privacy_hits(&bytes, self.needles) {
                self.found.push(Hit {
                    file: label.clone(),
                    pos,
                    origin: self.needles[index].origin.clone(),
                    name: false,
                });
            }
        }
        Ok(())
    }
}

pub fn scan_paths(paths: &[PathBuf], needles: &[Needle]) -> Result<Vec<Hit>, String> {
    let mut scan = Scan::new(needles);
    for path in paths {
        let relative = path.file_name().map_or(Path::new("."), Path::new);
        scan.visit(path, relative, &[], &|_| true)?;
    }
    Ok(scan.found)
}

fn read_lists(deny: &Path, allow: Option<&Path>) -> Result<(Vec<Needle>, Vec<String>), String> {
    let read = |path: &Path, label| {
        fs::read_to_string(path).map_err(|e| format!("cannot read the {label} list: {e}"))
    };
    let allow_text = allow
        .map(|path| read(path, "allow"))
        .transpose()?
        .unwrap_or_default();
    let (needles, notes) = load_needles(&read(deny, "deny")?, &allow_text)?;
    notes.iter().for_each(|note| println!("{note}"));
    Ok((needles, notes))
}

fn report(hits: &[Hit]) -> bool {
    for hit in hits {
        let kind = if hit.name { "name " } else { "" };
        eprintln!("{}: {kind}offset {}: {}", hit.file, hit.pos, hit.origin);
    }
    println!("scan: {} finding(s)", hits.len());
    hits.is_empty()
}

/// `cargo xtask scan`: `Ok(true)` when nothing was found.
pub fn scan(
    root: &Path,
    deny: &Path,
    allow: Option<&Path>,
    paths: &[PathBuf],
) -> Result<bool, String> {
    let (mut needles, _) = read_lists(deny, allow)?;
    needles.extend(own_needles(root));
    Ok(report(&scan_paths(paths, &needles)?))
}

/// `CARGO_ENCODED_RUSTFLAGS` of the Windows build: one flag per item, joined by `\x1f`.
pub fn encoded_rustflags(repo: &str, cargo_home: &str, rustup_home: &str) -> String {
    [
        "-C",
        "target-feature=+crt-static",
        &format!("--remap-path-prefix={repo}=sync_gate"),
        &format!("--remap-path-prefix={cargo_home}=cargo"),
        &format!("--remap-path-prefix={rustup_home}=rustup"),
        "-C",
        "link-arg=/PDBALTPATH:%_PDB%",
    ]
    .join("\x1f")
}

/// The `cargo build` of the Windows binaries.
pub fn windows_build(root: &Path, cargo_home: &str, rustup_home: &str) -> Command {
    let mut command = Command::new(env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
    command
        .args(["build", "--release", "--locked", "--target", WINDOWS_TARGET])
        .args([
            "-p",
            "sync_gate",
            "-p",
            "sync_gated",
            "-p",
            "sync_gate_shim",
        ])
        .current_dir(root)
        .env("CARGO_TARGET_DIR", root.join("target").join("dist-build"))
        .env("CARGO_PROFILE_RELEASE_STRIP", "symbols")
        // RUSTFLAGS would split the repository path at its space; the encoded form does not.
        .env_remove("RUSTFLAGS")
        .env(
            "CARGO_ENCODED_RUSTFLAGS",
            encoded_rustflags(&root.display().to_string(), cargo_home, rustup_home),
        );
    command
}

/// Runs inside the container: builds, copies the raw binaries to /stage (for the guard) and
/// packs the archives into /out (a bind mount would lose the executable bit).
const LINUX_SCRIPT: &str = r#"set -e
mkdir -p /cargo/h /target/t
[ -d /cargo/h/registry ] || cp -r /seed /cargo/h/registry
base="--remap-path-prefix=/src=sync_gate --remap-path-prefix=/cargo/h=cargo --remap-path-prefix=/usr/local/rustup=rustup"
for t in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
  extra=""
  [ "$t" = aarch64-unknown-linux-musl ] && extra="-C linker=rust-lld"
  if RUSTFLAGS="$base $extra" cargo build --release --locked --target "$t" -p sync_gate -p sync_gated -p sync_gate_shim; then
    rm -rf "/stage/$t"; mkdir -p "/stage/$t"
    for n in sync_gate sync_gated sync_gate_mcp; do cp "/target/t/$t/release/$n" "/stage/$t/$n"; done
    cp LICENSE-MIT LICENSE-APACHE "/stage/$t/"
    tar -czf "/out/sync_gate-$VER-$t.tar.gz" -C "/stage/$t" sync_gate sync_gated sync_gate_mcp LICENSE-MIT LICENSE-APACHE
  elif [ "$t" = x86_64-unknown-linux-musl ]; then
    exit 1
  else
    echo "arm64 left out: the link failed for $t"
  fi
done
"#;

fn run(mut command: Command) -> Result<(), String> {
    let label: Vec<String> = std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(|part| part.to_string_lossy().into_owned())
        .collect();
    println!("\n==> {}", label.join(" "));
    match command.status() {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(format!("`{}` failed: {status}", label[0])),
        Err(error) => Err(format!("could not start `{}`: {error}", label[0])),
    }
}

fn home_dir() -> Option<PathBuf> {
    env::var_os("USERPROFILE")
        .or_else(|| env::var_os("HOME"))
        .map(PathBuf::from)
}

/// What no binary may contain, apart from the deny list: the user folder, the user name and the
/// repository path.
fn own_needles(root: &Path) -> Vec<Needle> {
    let mut needles = Vec::new();
    let mut path = |text: String, origin: &str| {
        needles.push(Needle {
            term: text.replace('/', "\\"),
            whole: false,
            origin: origin.into(),
        });
        needles.push(Needle {
            term: text.replace('\\', "/"),
            whole: false,
            origin: origin.into(),
        });
    };
    if let Some(home) = home_dir() {
        path(home.display().to_string(), "the user folder");
    }
    path(root.display().to_string(), "the repository path");
    if let Some(user) = env::var("USERNAME")
        .or_else(|_| env::var("USER"))
        .ok()
        .filter(|u| u.chars().count() >= 3)
    {
        needles.push(Needle {
            term: user,
            whole: true,
            origin: "the user name".into(),
        });
    }
    needles
}

fn copy(from: &Path, to: &Path) -> Result<(), String> {
    let name = from.file_name().unwrap_or_default().to_string_lossy();
    let meta = fs::symlink_metadata(from).map_err(|e| format!("cannot read {name}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{name} is not a regular file"));
    }
    fs::copy(from, to)
        .map(drop)
        .map_err(|e| format!("cannot copy {name}: {e}"))
}

/// `cargo xtask dist`: `Ok(true)` when the archives are in `target/dist/v<version>`.
// shortcut: Windows host only (the Windows archive needs the MSVC toolchain and `tar.exe`);
// upgrade when a Linux or macOS machine has to cut the release.
pub fn dist(root: &Path, linux: bool, deny: &Path, allow: Option<&Path>) -> Result<bool, String> {
    if env::consts::OS != "windows" {
        return Err("dist runs on a Windows host".into());
    }
    let (mut needles, _) = read_lists(deny, allow)?;
    needles.extend(own_needles(root));
    let version = env!("CARGO_PKG_VERSION");
    let target = root.join("target");
    ensure_dist_dir(&target, "target directory")?;
    let out = target.join("dist").join(format!("v{version}"));
    let approved = with_dist_output(&out, |pending, stage| {
        build_dist(root, linux, version, pending, stage, &needles)
    })?;
    if approved {
        println!("\ndist: {}", out.display());
    }
    Ok(approved)
}

fn with_dist_output(
    out: &Path,
    build: impl FnOnce(&Path, &Path) -> Result<bool, String>,
) -> Result<bool, String> {
    let mut pending_name = std::ffi::OsString::from(".");
    pending_name.push(out.file_name().expect("dist version directory"));
    pending_name.push(".pending");
    let work = out.with_file_name(pending_name);
    let parent = out.parent().expect("dist parent directory");
    ensure_dist_dir(parent, "dist directory")?;
    ensure_dist_dir(&work, "pending dist directory")?;
    let dist_root =
        fs::canonicalize(parent).map_err(|e| format!("cannot resolve the dist directory: {e}"))?;
    let work_root = resolved_dist_child(&work, &dist_root)?;
    let _lock = lock_dist(&work_root.join("writer.lock"))?;

    let previous = work.join("previous");
    let has_output = is_dist_dir(out, "dist destination")?;
    if is_dist_dir(&previous, "prior dist backup")? {
        let backup = resolved_dist_child(&previous, &work_root)?;
        if has_output {
            fs::remove_dir_all(backup)
                .map_err(|e| format!("cannot remove the old dist backup: {e}"))?;
        } else {
            fs::rename(backup, out).map_err(|e| format!("cannot restore the prior dist: {e}"))?;
        }
    }
    for entry in
        fs::read_dir(&work_root).map_err(|e| format!("cannot list pending dist staging: {e}"))?
    {
        let entry = entry.map_err(|e| format!("cannot read a pending dist entry: {e}"))?;
        let name = entry.file_name();
        if name == "release" || name == "stage" || is_dist_run(&name) {
            clean_dist_stage(&entry.path(), &work_root)?;
        }
    }

    // A child command can outlive xtask. A new attempt must never share its output paths.
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("cannot name the dist staging directory: {e}"))?
        .as_nanos();
    let run = work.join(format!("run-{}-{nonce}", std::process::id()));
    fs::create_dir(&run).map_err(|e| format!("cannot create the dist staging directory: {e}"))?;
    let staged = run.join("release");
    let stage = run.join("stage");
    let result = (|| {
        fs::create_dir(&staged).map_err(|e| format!("cannot create pending release: {e}"))?;
        fs::create_dir(&stage).map_err(|e| format!("cannot create dist stage: {e}"))?;
        if !build(&staged, &stage)? {
            return Ok(false);
        }
        publish_dist(out, &staged, &previous)?;
        Ok(true)
    })();
    if matches!(result, Ok(true))
        && let Err(error) = clean_dist_stage(&previous, &work_root)
    {
        eprintln!("{error}");
    }
    if let Err(error) = clean_dist_stage(&run, &work_root) {
        eprintln!("{error}");
    }
    result
}

fn is_dist_run(name: &std::ffi::OsStr) -> bool {
    name.to_str()
        .and_then(|s| s.strip_prefix("run-"))
        .and_then(|s| s.split_once('-'))
        .is_some_and(|(pid, nonce)| {
            !pid.is_empty()
                && !nonce.is_empty()
                && pid.bytes().chain(nonce.bytes()).all(|b| b.is_ascii_digit())
        })
}

fn dist_link(meta: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    meta.file_type().is_symlink()
}

fn is_dist_dir(path: &Path, label: &str) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() && !dist_link(&meta) => Ok(true),
        Ok(_) => Err(format!("the {label} is not a plain directory")),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("cannot inspect the {label}: {error}")),
    }
}

fn ensure_dist_dir(path: &Path, label: &str) -> Result<(), String> {
    match fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::AlreadyExists && is_dist_dir(path, label)? => {
            Ok(())
        }
        Err(error) => Err(format!("cannot create the {label}: {error}")),
    }
}

fn resolved_dist_child(path: &Path, parent: &Path) -> Result<PathBuf, String> {
    let resolved =
        fs::canonicalize(path).map_err(|e| format!("cannot resolve dist staging: {e}"))?;
    if resolved.parent() != Some(parent) || resolved.file_name() != path.file_name() {
        return Err("dist staging resolves outside its expected location".into());
    }
    Ok(resolved)
}

fn clean_dist_stage(path: &Path, work_root: &Path) -> Result<(), String> {
    if is_dist_dir(path, "abandoned dist staging directory")? {
        let resolved = resolved_dist_child(path, work_root)?;
        if let Err(error) = fs::remove_dir_all(resolved) {
            eprintln!("cannot remove abandoned dist staging: {error}");
        }
    }
    Ok(())
}

fn lock_dist(path: &Path) -> Result<sync_gate_probe::FileLock, String> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ_WRITE: u32 = 0x1 | 0x2;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options
            .share_mode(FILE_SHARE_READ_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let check_file = |meta: fs::Metadata| {
        if meta.is_file() && !dist_link(&meta) {
            Ok(())
        } else {
            Err("the dist lock is not a plain file".to_string())
        }
    };
    match fs::symlink_metadata(path) {
        Ok(meta) => check_file(meta)?,
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(format!("cannot inspect the dist lock: {error}")),
    }
    let file = options
        .open(path)
        .map_err(|e| format!("cannot open the dist lock: {e}"))?;
    check_file(
        file.metadata()
            .map_err(|e| format!("cannot inspect the dist lock: {e}"))?,
    )?;
    sync_gate_probe::try_lock(file, true)
        .map_err(|e| format!("cannot lock dist: {e}"))?
        .ok_or_else(|| "another process is building this dist".into())
}

fn publish_dist(out: &Path, staged: &Path, previous: &Path) -> Result<(), String> {
    let backed_up = is_dist_dir(out, "dist destination")?;
    if backed_up {
        fs::rename(out, previous).map_err(|e| format!("cannot back up the prior dist: {e}"))?;
    }
    if let Err(error) = fs::rename(staged, out) {
        if backed_up && let Err(rollback) = fs::rename(previous, out) {
            return Err(format!(
                "cannot publish dist: {error}; cannot restore the prior dist: {rollback}; the prior dist is preserved inside the pending directory"
            ));
        }
        return Err(format!("cannot publish dist: {error}"));
    }
    Ok(())
}

fn build_dist(
    root: &Path,
    linux: bool,
    version: &str,
    out: &Path,
    stage: &Path,
    needles: &[Needle],
) -> Result<bool, String> {
    let home = home_dir().ok_or("no user folder (USERPROFILE)")?;
    let cargo_home =
        env::var("CARGO_HOME").unwrap_or_else(|_| home.join(".cargo").display().to_string());
    let rustup_home =
        env::var("RUSTUP_HOME").unwrap_or_else(|_| home.join(".rustup").display().to_string());

    run(windows_build(root, &cargo_home, &rustup_home))?;
    let win = stage.join("windows");
    fs::create_dir_all(&win).map_err(|e| format!("cannot create {}: {e}", win.display()))?;
    let built = root
        .join("target")
        .join("dist-build")
        .join(WINDOWS_TARGET)
        .join("release");
    for name in EXES {
        copy(
            &built.join(format!("{name}.exe")),
            &win.join(format!("{name}.exe")),
        )?;
    }
    for name in LICENSES {
        copy(&root.join(name), &win.join(name))?;
    }
    if linux {
        linux_build(root, out, stage, Path::new(&cargo_home), version)?;
    }

    for script in SCRIPTS {
        copy(
            &root.join("tools").join("install").join(script),
            &out.join(script),
        )?;
    }
    let zip = out.join(format!("sync_gate-{version}-{WINDOWS_TARGET}.zip"));
    let tar = Path::new(&env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
        .join("System32")
        .join("tar.exe");
    let mut pack = Command::new(tar);
    pack.args(["-a", "-c", "-f"]).arg(&zip).arg("-C").arg(&win);
    pack.args(EXES.map(|n| format!("{n}.exe"))).args(LICENSES);
    run(pack)?;
    checksums(out, linux)?;
    Ok(report(&scan_dist_artifacts(out, stage, version, needles)?))
}

fn scan_dist_artifacts(
    out: &Path,
    stage: &Path,
    version: &str,
    needles: &[Needle],
) -> Result<Vec<Hit>, String> {
    let mut scan = Scan::new(needles);
    scan.visit(stage, Path::new(""), &[], &|_| true)?;
    // The staged contents are the archive members. Check the archives' filenames here.
    scan.visit(out, Path::new(&format!("v{version}")), &[], &|path| {
        let name = path.file_name().unwrap_or_default().as_encoded_bytes();
        !name.ends_with(b".zip") && !name.ends_with(b".tar.gz")
    })?;
    Ok(scan.found)
}

fn linux_build(
    root: &Path,
    out: &Path,
    stage: &Path,
    cargo_home: &Path,
    version: &str,
) -> Result<(), String> {
    const PLATFORM: [&str; 2] = ["--platform", "linux/amd64"];
    let has_image = Command::new("docker")
        .args(["image", "inspect", IMAGE])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !has_image {
        let mut build = Command::new("docker");
        build
            .arg("build")
            .args(PLATFORM)
            .args(["-t", IMAGE, "tools/dist"])
            .current_dir(root);
        run(build)?;
    }
    let mount = |from: &Path, to: &str, mode: &str| format!("{}:{to}:{mode}", from.display());
    let mut docker = Command::new("docker");
    docker
        .args(["run", "--rm", "--init"])
        .args(PLATFORM)
        .args(["--user", "0", "-e", &format!("VER={version}")])
        .args([
            "-e",
            "CARGO_HOME=/cargo/h",
            "-e",
            "CARGO_TARGET_DIR=/target/t",
        ])
        .args(["-e", "CARGO_PROFILE_RELEASE_STRIP=symbols"])
        // Without a value: passed through when set on the host.
        .args(["-e", "CARGO_NET_OFFLINE", "-e", "CARGO_BUILD_JOBS"])
        .args(["-v", &mount(root, "/src", "ro")])
        .args(["-v", &mount(&cargo_home.join("registry"), "/seed", "ro")])
        .args(["-v", &mount(out, "/out", "rw")])
        .args(["-v", &mount(stage, "/stage", "rw")])
        .args([
            "-v",
            "sync_gate-dist-target:/target",
            "-v",
            "sync_gate-dist-cargo:/cargo",
        ])
        .args(["-w", "/src", IMAGE, "sh", "-c", LINUX_SCRIPT]);
    run(docker)
}

/// `SHA256SUMS` of every file in `out`: `sha256sum` in the container, or `Get-FileHash` without it.
fn checksums(out: &Path, linux: bool) -> Result<(), String> {
    if linux {
        let mut docker = Command::new("docker");
        docker
            .args(["run", "--rm", "--platform", "linux/amd64", "-v"])
            .arg(format!("{}:/d", out.display()))
            .args([
                "-w",
                "/d",
                IMAGE,
                "sh",
                "-c",
                "sha256sum * > /tmp/s && cp /tmp/s SHA256SUMS",
            ]);
        return run(docker);
    }
    let script = "$d=$env:SG_DIST_DIR; $t=(Get-ChildItem -LiteralPath $d -File | Sort-Object Name | ForEach-Object { (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLower() + '  ' + $_.Name + \"`n\" }) -join ''; [IO.File]::WriteAllText((Join-Path $d 'SHA256SUMS'), $t)";
    let mut ps = Command::new("powershell");
    ps.args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("SG_DIST_DIR", out);
    run(ps)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(term: &str) -> Needle {
        Needle {
            term: term.into(),
            whole: true,
            origin: "t".into(),
        }
    }
    fn s(term: &str) -> Needle {
        Needle {
            term: term.into(),
            whole: false,
            origin: "t".into(),
        }
    }
    fn utf16(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }
    fn found(bytes: &[u8], needle: Needle) -> bool {
        !privacy_hits(bytes, &[needle]).is_empty()
    }
    fn lint(text: &str) -> Result<(), String> {
        parse_deny(text).and_then(|entries| lint_deny(&entries))
    }

    #[test]
    fn hits_in_ascii_and_utf16_without_case_and_ignore_the_wrong() {
        assert_eq!(privacy_hits(b"xx AcMe yy", &[w("acme")]), vec![(3, 0)]);
        assert_eq!(privacy_hits(&utf16("xx AcMe"), &[w("ACME")]), vec![(6, 0)]);
        assert!(!found(b"nothing here", w("acme")));
        assert!(!found(b"acme", w("")));
        assert!(!found(b"ab", w("ab")));
        assert!(found(br"...C:\Users\x\y", s(r"C:\Users\x")));
        assert!(found(&utf16(r"...C:\Users\x\y"), s(r"c:\users\x")));
    }

    #[test]
    fn a_term_with_spaces_also_matches_slug_forms() {
        for text in [
            "acme widgets",
            "acme-widgets",
            "ACME_Widgets",
            "acmewidgets",
            "acme.widgets",
            "x/acme-widgets/y",
        ] {
            assert!(found(text.as_bytes(), w("acme widgets")), "{text}");
            assert!(found(&utf16(text), w("Acme Widgets")), "{text} utf16");
        }
        assert!(!found(b"acme  widgets", w("acme widgets")));
        assert!(!found(b"acme-widgetsx", w("acme widgets")));
    }

    #[test]
    fn a_name_with_spaces_also_matches_a_path_url_or_plus_form() {
        for text in [
            "x/acme/widgets/y",
            r"x\acme\widgets",
            "?q=acme%20widgets",
            "?q=Acme%20Widgets&",
            "acme+widgets",
            "x/acme%2Fwidgets",
        ] {
            assert!(found(text.as_bytes(), w("acme widgets")), "{text}");
            assert!(found(&utf16(text), w("Acme Widgets")), "{text} utf16");
        }
    }

    #[test]
    fn a_name_broken_over_lines_is_still_found() {
        for text in [
            "made for Acme\nWidgets today",
            "made for Acme\r\nWidgets",
            "// Acme\n// Widgets",
            "> Acme\n> Widgets",
            " * Acme\n   * Widgets",
            "Acme   \n\n  Widgets",
        ] {
            assert!(found(text.as_bytes(), w("acme widgets")), "{text:?}");
            assert!(found(&utf16(text), w("acme widgets")), "{text:?} utf16");
        }
        // words far apart, or a comma, are another matter
        assert!(!found(
            b"Acme\nthen some other words\nWidgets",
            w("acme widgets")
        ));
        assert!(!found(b"Acme\nWidgetsx", w("acme widgets")));
        assert!(!found(b"Acme, Widgets", w("acme widgets")));
    }

    #[test]
    fn a_name_can_mix_spaces_and_line_breaks() {
        for text in [
            "Acme North\n> Widgets",
            "Acme\r\n// North Widgets",
            "Acme North Widgets",
        ] {
            assert_eq!(
                privacy_hits(text.as_bytes(), &[w("acme north widgets")]),
                vec![(0, 0)]
            );
            assert_eq!(
                privacy_hits(&utf16(text), &[w("acme north widgets")]),
                vec![(0, 0)]
            );
        }
        for text in [
            "Acme  North Widgets",
            "Acme > North\nWidgets",
            "Acme North\nWidgets2",
        ] {
            assert!(!found(text.as_bytes(), w("acme north widgets")));
            assert!(!found(&utf16(text), w("acme north widgets")));
        }
    }

    #[test]
    fn an_upper_case_accented_letter_is_folded() {
        // the text has the capital, the list may spell the name in either case
        for (text, term) in [
            ("MARIA JOS\u{c9} ", "maria josé"),
            ("S\u{c3}O PAULO", "são paulo"),
            ("A\u{c7}\u{c3}O", "ação"),
            ("Jos\u{e9}", "JOSÉ"),
        ] {
            assert!(found(text.as_bytes(), s(term)), "{text}");
            assert!(found(&utf16(text), s(term)), "{text} utf16");
        }
        assert!(!found("JOS\u{c8}".as_bytes(), s("josé")));
    }

    #[test]
    fn whole_word_needs_a_non_alphanumeric_edge() {
        for text in ["Acme", "acme.", "(ACME)", "a acme b"] {
            assert!(found(text.as_bytes(), w("acme")), "{text}");
            assert!(found(&utf16(text), w("acme")), "{text} utf16");
        }
        for text in ["acmeware", "macme", "acme2"] {
            assert!(!found(text.as_bytes(), w("acme")), "{text}");
            assert!(!found(&utf16(text), w("acme")), "{text} utf16");
        }
        assert!(found(b"acmeware", s("acme")));
    }

    #[test]
    fn utf8_word_edges_decode_characters_next_to_invalid_bytes() {
        for text in ["DÉCAFÉ", "CAFÉÉ", "界CAFÉ", "CAFÉ٣"] {
            let bytes = [b"\xff".as_slice(), text.as_bytes(), b"\xfe"].concat();
            assert!(!found(&bytes, w("café")), "{text}");
        }
        let bytes = [b"\xff".as_slice(), "CAFÉ".as_bytes(), b"\xc3"].concat();
        assert_eq!(privacy_hits(&bytes, &[w("café")]), vec![(1, 0)]);
        assert!(found("(CAFÉ·)".as_bytes(), w("café")));
    }

    #[test]
    fn lint_refuses_the_bad_entries_and_accepts_the_good() {
        for bad in [
            "w sync_gate",
            "s sync_gate",
            "w Sync Labs",
            "w setup",
            "w ab",
            "s acme",
            "s @synclabs.team",
            "s synclabs.team",
            "w synclabs",
            "w gate",
            "acme",
            "x acme corp",
            "w Global",
            "w Sistema",
        ] {
            assert!(lint(bad).is_err(), "{bad} should be refused");
        }
        for good in [
            "w Acme Corp",
            "s fulano@synclabs.team",
            "s oldproduct",
            "s C:\\Users\\x",
        ] {
            assert!(lint(good).is_ok(), "{good} should pass");
        }
        assert!(lint("# comment\n\nw Acme Corp\n").is_ok());
        // the line number of the list is in the message
        assert!(lint("w Acme Corp\nw setup").unwrap_err().contains("line 2"));
    }

    #[test]
    fn allow_needs_a_reason_and_a_term_in_both_lists_is_not_searched() {
        assert!(parse_allow("acme\t").is_err());
        assert!(parse_allow("acme").is_err());
        assert_eq!(parse_allow("acme\tour partner").unwrap().len(), 1);
        let (needles, notes) = load_needles(
            "w Acme Corp\nw Zorbax Holdings\n",
            "acme corp\tpublic partner\n",
        )
        .unwrap();
        assert_eq!(needles.len(), 1);
        assert_eq!(needles[0].term, "Zorbax Holdings");
        assert_eq!(
            notes,
            vec!["allowed: acme corp (public partner)".to_string()]
        );
        assert!(load_needles("w setup\n", "").is_err());
    }

    fn tree(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("xtask-scan-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        dir
    }

    #[test]
    fn scan_finds_text_and_utf16_binaries_and_a_clean_tree_has_none() {
        let dir = tree("find");
        std::fs::write(dir.join("a.txt"), "hello Zorbax Holdings!").unwrap();
        let mut bin = vec![0u8, 1, 2];
        bin.extend(utf16("zorbax holdings"));
        std::fs::write(dir.join("sub").join("b.bin"), &bin).unwrap();
        std::fs::write(dir.join("clean.txt"), "nothing").unwrap();
        let (needles, _) = load_needles("w Zorbax Holdings\n", "").unwrap();
        let mut hits = scan_paths(std::slice::from_ref(&dir), &needles).unwrap();
        hits.sort_by(|a, b| a.file.cmp(&b.file));
        assert_eq!(hits.len(), 2);
        assert!(hits[0].file.ends_with("a.txt") && hits[0].pos == 6);
        assert!(hits[1].file.ends_with("b.bin") && hits[1].pos == 3);
        assert_eq!(hits[0].origin, "line 1 of the deny list");
        let clean = tree("clean");
        std::fs::write(clean.join("x.txt"), "fine").unwrap();
        assert!(scan_paths(&[clean], &needles).unwrap().is_empty());
    }

    #[test]
    fn scan_reaches_zero_by_fixing_the_source_alone() {
        let dir = tree("reach");
        let doc = dir.join("doc.txt");
        std::fs::write(&doc, "SyncGate, the setup, made for Zorbax Holdings").unwrap();
        let deny = "w Zorbax Holdings\n";
        let (needles, _) = load_needles(deny, "").unwrap();
        // the product name and a common word are not findings
        assert_eq!(
            scan_paths(std::slice::from_ref(&dir), &needles)
                .unwrap()
                .len(),
            1
        );
        std::fs::write(&doc, "SyncGate, the setup, made for a customer").unwrap();
        let (needles, _) = load_needles(deny, "").unwrap();
        assert!(scan_paths(&[dir], &needles).unwrap().is_empty());
    }

    #[test]
    fn scan_checks_names_and_redacts_sensitive_labels() {
        let dir = tree("names");
        let private_dir = dir.join("acme");
        fs::create_dir_all(private_dir.join("widgets")).unwrap();
        fs::write(private_dir.join("widgets").join("note.txt"), "Zorbax").unwrap();
        fs::write(dir.join("Zorbax.txt"), "clean").unwrap();
        let needles = [w("acme widgets"), w("zorbax")];
        let hits = scan_paths(std::slice::from_ref(&dir), &needles).unwrap();
        assert_eq!(hits.len(), 3);
        assert_eq!(hits.iter().filter(|hit| hit.name).count(), 2);
        for hit in hits {
            assert!(!hit.file.to_lowercase().contains("zorbax"));
            assert!(!hit.file.to_lowercase().contains("widgets"));
            assert!(!hit.file.contains(&*dir.to_string_lossy()));
        }
        assert_eq!(
            scan_paths(&[dir.join("Zorbax.txt")], &needles)
                .unwrap()
                .len(),
            1
        );
        let error = scan_paths(&[dir.join("missing-Zorbax.txt")], &needles).unwrap_err();
        assert!(!error.to_lowercase().contains("zorbax"));
    }

    #[test]
    fn a_dist_scan_error_preserves_the_prior_release_and_cleans_staging() {
        let dir = tree("dist-scan");
        let out = dir.join("v1");
        fs::create_dir(&out).unwrap();
        fs::write(out.join("prior"), "approved").unwrap();
        let result = with_dist_output(&out, |pending, stage| {
            fs::write(pending.join("linux.tar.gz"), "unscanned").unwrap();
            assert_eq!(fs::read_to_string(out.join("prior")).unwrap(), "approved");
            assert!(!out.join("linux.tar.gz").exists());
            let error = scan_paths(&[stage.join("missing")], &[w("zorbax")]).unwrap_err();
            Err(error)
        });
        assert!(result.unwrap_err().contains("cannot read"));
        assert_eq!(fs::read_to_string(out.join("prior")).unwrap(), "approved");
        assert!(!out.join("linux.tar.gz").exists());
        assert_dist_staging_cleared(&dir);
    }

    #[test]
    fn dist_checks_release_names_without_searching_compressed_bytes() {
        let dir = tree("dist-archives");
        let stage = dir.join("sub");
        let out = dir.join("release");
        fs::create_dir(&out).unwrap();
        for script in SCRIPTS {
            fs::write(out.join(script), "clean").unwrap();
        }
        fs::write(out.join("zorbax.zip"), "clean").unwrap();
        fs::write(out.join("clean.tar.gz"), "Zorbax").unwrap();
        fs::write(stage.join("component"), "Zorbax").unwrap();
        let hits = scan_dist_artifacts(&out, &stage, "1", &[w("zorbax")]).unwrap();
        assert_eq!(hits.len(), 2);
        assert!(
            hits.iter()
                .any(|hit| hit.name && !hit.file.contains("zorbax"))
        );
        assert!(hits.iter().any(|hit| !hit.name && hit.file == "component"));
    }

    #[test]
    fn dist_serializes_writers_and_promotes_only_an_approved_release() {
        let dir = tree("dist-publish");
        let out = dir.join("v1");
        fs::create_dir(&out).unwrap();
        fs::write(out.join("prior"), "approved").unwrap();
        let approved = with_dist_output(&out, |pending, _| {
            fs::write(pending.join("new"), "approved").unwrap();
            let duplicate = with_dist_output(&out, |_, _| panic!("started a duplicate build"));
            assert!(duplicate.is_err());
            assert!(out.join("prior").exists());
            assert!(!out.join("new").exists());
            Ok(true)
        })
        .unwrap();
        assert!(approved);
        assert_eq!(fs::read_to_string(out.join("new")).unwrap(), "approved");
        assert!(!out.join("prior").exists());
        assert_dist_staging_cleared(&dir);
    }

    #[test]
    fn failed_dist_promotion_restores_the_prior_release() {
        let dir = tree("dist-rollback");
        let out = dir.join("v1");
        fs::create_dir(&out).unwrap();
        fs::write(out.join("prior"), "approved").unwrap();
        let result = with_dist_output(&out, |pending, _| {
            fs::remove_dir(pending).unwrap();
            Ok(true)
        });
        assert!(result.unwrap_err().contains("cannot publish dist"));
        assert_eq!(fs::read_to_string(out.join("prior")).unwrap(), "approved");
        assert_dist_staging_cleared(&dir);
    }

    fn assert_dist_staging_cleared(dir: &Path) {
        let work = dir.join(".v1.pending");
        assert!(work.join("writer.lock").is_file());
        assert_eq!(fs::read_dir(work).unwrap().count(), 1);
    }

    #[test]
    fn dist_retry_restores_the_prior_release_before_building() {
        let dir = tree("dist-recover");
        let out = dir.join("v1");
        let work = dir.join(".v1.pending");
        fs::create_dir_all(work.join("previous")).unwrap();
        fs::write(work.join("previous/prior"), "approved").unwrap();
        fs::create_dir(work.join("release")).unwrap();
        fs::write(work.join("release/partial"), "unscanned").unwrap();
        fs::write(work.join("keep"), "unrelated").unwrap();

        let approved = with_dist_output(&out, |release, _| {
            assert_eq!(fs::read_to_string(out.join("prior")).unwrap(), "approved");
            assert!(!work.join("release").exists());
            assert!(!release.join("partial").exists());
            Ok(false)
        })
        .unwrap();
        assert!(!approved);
        assert!(out.join("prior").is_file());
        assert!(!work.join("previous").exists());
        assert_eq!(fs::read_to_string(work.join("keep")).unwrap(), "unrelated");
    }

    #[test]
    fn dist_retry_keeps_the_published_release_and_cleans_the_old_backup() {
        let dir = tree("dist-after-promotion");
        let out = dir.join("v1");
        let work = dir.join(".v1.pending");
        fs::create_dir(&out).unwrap();
        fs::write(out.join("new"), "approved").unwrap();
        fs::create_dir_all(work.join("previous")).unwrap();
        fs::write(work.join("previous/prior"), "also approved").unwrap();
        fs::create_dir(work.join("stage")).unwrap();

        assert!(!with_dist_output(&out, |_, _| Ok(false)).unwrap());
        assert_eq!(fs::read_to_string(out.join("new")).unwrap(), "approved");
        assert!(!work.join("previous").exists());
        assert!(!work.join("stage").exists());
    }

    #[test]
    fn dist_writer_child() {
        let Some(out) = env::var_os("XTASK_TEST_DIST_WRITER") else {
            return;
        };
        let out = PathBuf::from(out);
        with_dist_output(&out, |release, stage| {
            fs::write(release.join("partial"), "unscanned").unwrap();
            fs::write(
                out.with_file_name("ready"),
                stage.parent().unwrap().to_str().unwrap(),
            )
            .unwrap();
            std::thread::sleep(std::time::Duration::from_secs(10));
            Err("test writer was not stopped".into())
        })
        .unwrap();
    }

    #[test]
    fn dist_retry_after_terminating_a_writer_releases_the_lock() {
        use std::time::{Duration, Instant};

        let dir = tree("dist-child");
        let out = dir.join("v1");
        let ready = dir.join("ready");
        let mut child = Command::new(env::current_exe().unwrap())
            .args(["--exact", "dist::tests::dist_writer_child"])
            .env("XTASK_TEST_DIST_WRITER", &out)
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let abandoned = loop {
            if let Ok(path) = fs::read_to_string(&ready)
                && !path.is_empty()
            {
                break Some(PathBuf::from(path));
            }
            if Instant::now() >= deadline {
                break None;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let blocked = with_dist_output(&out, |_, _| Ok(false)).is_err();
        let killed = child.kill();
        let status = child.wait().unwrap();
        assert!(killed.is_ok() && !status.success());
        let abandoned = abandoned.expect("test writer never entered the build");
        assert!(blocked);

        assert!(
            !with_dist_output(&out, |release, stage| {
                assert!(!abandoned.exists());
                assert_ne!(stage.parent().unwrap(), abandoned);
                assert!(!release.join("partial").exists());
                Ok(false)
            })
            .unwrap()
        );
        assert!(!out.exists());
    }

    #[test]
    fn dist_rejects_a_linked_dist_parent() {
        let dir = tree("dist-link-parent");
        let real = dir.join("sub");
        let link = dir.join("link");
        assert!(link_dir(&real, &link));
        assert!(with_dist_output(&link.join("v1"), |_, _| Ok(false)).is_err());
        assert_eq!(fs::read_dir(real).unwrap().count(), 0);
    }

    #[cfg(windows)]
    #[test]
    fn failed_dist_build_preserves_the_previous_release() {
        let dir = tree("dist-build");
        let out = dir
            .join("target/dist")
            .join(format!("v{}", env!("CARGO_PKG_VERSION")));
        fs::create_dir_all(&out).unwrap();
        let prior = out.join("prior");
        fs::write(&prior, "approved").unwrap();
        let deny = dir.join("deny.txt");
        fs::write(&deny, "w zorbax\n").unwrap();
        assert!(dist(&dir, false, &deny, None).is_err());
        assert_eq!(fs::read_to_string(prior).unwrap(), "approved");
    }

    /// A link to a directory (a junction on Windows, which needs no privilege) or None when the
    /// machine will not make one.
    fn link_dir(target: &Path, link: &Path) -> bool {
        #[cfg(windows)]
        let ok = Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(link)
            .arg(target)
            .stdout(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        #[cfg(unix)]
        let ok = std::os::unix::fs::symlink(target, link).is_ok();
        ok
    }

    #[test]
    fn scan_refuses_a_link_instead_of_passing_silently() {
        let real = tree("linkreal");
        std::fs::write(real.join("a.txt"), "Zorbax Holdings").unwrap();
        let dir = tree("linkdir");
        if !link_dir(&real, &dir.join("link")) {
            eprintln!("skipped: this machine would not create a link");
            return;
        }
        let (needles, _) = load_needles("w Zorbax Holdings\n", "").unwrap();
        let error = scan_paths(&[dir], &needles).unwrap_err();
        assert!(error.contains("link"), "{error}");
    }

    #[test]
    fn a_deny_list_with_no_effective_term_is_refused() {
        for (deny, allow) in [
            ("", ""),
            ("# only a comment\n\n", ""),
            ("w Acme Corp\n", "acme corp\tpublic partner\n"),
        ] {
            let error = load_needles(deny, allow).unwrap_err();
            assert!(error.contains("no effective terms"), "{deny:?}: {error}");
        }
    }

    #[test]
    fn scan_always_adds_the_own_needles_even_with_a_list_that_matches_nothing() {
        let dir = tree("own");
        let root = dir.join("repo");
        std::fs::write(dir.join("leak.txt"), format!("built at {}", root.display())).unwrap();
        let deny = dir.join("deny.txt");
        std::fs::write(&deny, "w Zorbax Holdings\n").unwrap();
        assert!(!scan(&root, &deny, None, &[dir.join("leak.txt")]).unwrap());
    }

    #[test]
    fn lint_refuses_a_one_or_two_character_term_with_a_separator() {
        for bad in ["s a/", "s s\\", "s @a", "s .x"] {
            assert!(lint(bad).is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn rustflags_keep_a_path_with_a_space_as_one_item_and_the_child_has_no_rustflags() {
        let flags = encoded_rustflags(r"C:\x\Sync Labs\repo", r"C:\h\.cargo", r"C:\h\.rustup");
        let items: Vec<&str> = flags.split('\x1f').collect();
        assert_eq!(items.len(), 7);
        assert_eq!(
            items[2],
            r"--remap-path-prefix=C:\x\Sync Labs\repo=sync_gate"
        );
        assert_eq!(items[6], "link-arg=/PDBALTPATH:%_PDB%");
        let command = windows_build(
            Path::new(r"C:\x\Sync Labs\repo"),
            r"C:\h\.cargo",
            r"C:\h\.rustup",
        );
        let envs: Vec<_> = command.get_envs().collect();
        assert!(envs.iter().any(|(k, v)| *k == "RUSTFLAGS" && v.is_none()));
        assert!(envs.iter().all(|(k, v)| *k != "RUSTFLAGS" || v.is_none()));
        assert!(
            envs.iter()
                .any(|(k, v)| *k == "CARGO_ENCODED_RUSTFLAGS" && v.is_some())
        );
    }
}
