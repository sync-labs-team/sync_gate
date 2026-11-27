//! Job signature (stable key for a command in a repository) and heavy-command classification.

use std::ffi::{OsStr, OsString};
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Identifies "the same kind of job" across runs: program, subcommands and repository.
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Debug)]
pub struct JobSignature {
    pub key: String,
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum SignatureError {
    #[error("empty argv: no program to run")]
    EmptyArgv,
}

fn program(arg: &OsStr) -> String {
    let p = Path::new(arg);
    p.file_stem()
        .unwrap_or(arg)
        .to_string_lossy()
        .to_lowercase()
}

/// A word shaped like a subcommand: 1 to 24 bytes of `a-z 0-9 . _ -`, starting with `a-z`.
/// Options, `KEY=value`, URLs, paths and long or upper-case tokens never are.
fn is_key_word(w: &str) -> bool {
    let b = w.as_bytes();
    (1..=24).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b.iter().all(|&c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
        })
}

/// The key's words: from the start of the arguments, while each is [`is_key_word`], at most two.
/// It stops at the first other word, so a refused word never promotes a later one.
fn key_words(argv: &[OsString]) -> Vec<String> {
    argv.iter()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .take_while(|w| is_key_word(w))
        .take(2)
        .collect()
}

fn repo_name(cwd: &Path) -> String {
    let root = cwd
        .ancestors()
        .find(|a| a.join(".git").exists())
        .unwrap_or(cwd);
    root.file_name()
        .unwrap_or(root.as_os_str())
        .to_string_lossy()
        .into_owned()
}

pub fn signature(argv: &[OsString], cwd: &Path) -> Result<JobSignature, SignatureError> {
    let first = argv.first().ok_or(SignatureError::EmptyArgv)?;
    let mut parts = vec![program(first)];
    parts.extend(key_words(argv));
    Ok(JobSignature {
        key: format!("{} @ {}", parts.join(" "), repo_name(cwd)),
    })
}

/// Key of a guest's job. Pure: `cwd` comes from another account's process and is only read as
/// text, never looked up on disk (no `.git` search, no `std::fs`).
pub fn guest_signature(
    guest: &str,
    argv: &[OsString],
    cwd: &Path,
) -> Result<JobSignature, SignatureError> {
    let first = argv.first().ok_or(SignatureError::EmptyArgv)?;
    let mut parts = vec![program(first)];
    parts.extend(key_words(argv));
    let last = cwd.file_name().unwrap_or(cwd.as_os_str()).to_string_lossy();
    Ok(JobSignature {
        key: format!("[guest {guest}] {} @ {last}", parts.join(" ")),
    })
}

/// Programs `is_heavy` can classify as heavy; the shims are made for exactly these.
/// shortcut: `is_heavy` keeps its own `match` (sub-command rules per program), so the test only
/// proves every name here is heavy; a new arm in the `match` must be added here by hand.
pub const HEAVY_PROGRAMS: &[&str] = &[
    "npm", "pnpm", "yarn", "bun", "next", "docker", "kiri", "cargo", "go", "pytest", "vitest",
    "jest", "tsc", "gradle", "mvn",
];

/// Global options that take their value as the next argument, per program (checked against
/// each tool's `--help` or docs: docker `--help`, npm `--prefix`/`-C` (config definitions),
/// bun `--cwd` (install/run docs), pnpm `--filter`/`-F` (filtering docs). `docker compose`'s
/// `-f`, `-p` and `--project-directory` ride on docker's list, so `compose -f x up --build` is seen.
/// shortcut: only the `--opt value` form is skipped; `--opt=value` already starts with `-`.
/// Add a program here when a new one is confirmed.
fn value_options(prog: &str) -> &'static [&'static str] {
    match prog {
        "cargo" => &["--color", "-C", "--config", "-Z"],
        "go" => &["-C"],
        "docker" => &[
            "--config",
            "-c",
            "--context",
            "-H",
            "--host",
            "-l",
            "--log-level",
            "--tlscacert",
            "--tlscert",
            "--tlskey",
            "-f",
            "-p",
            "--project-directory",
        ],
        "yarn" | "bun" => &["--cwd"],
        "npm" => &["--prefix", "-C"],
        "pnpm" => &["-C", "--dir", "--filter", "-F"],
        _ => &[],
    }
}

/// Drops `+toolchain` (cargo) and the value of a global option, so the first word is the
/// subcommand. Only for `is_heavy`; the job key uses `key_words`.
fn heavy_words(prog: &str, argv: &[OsString]) -> Vec<String> {
    let opts = value_options(prog);
    let mut out = Vec::new();
    let mut skip = false;
    for a in argv.iter().skip(1).map(|a| a.to_string_lossy()) {
        if std::mem::take(&mut skip) {
            continue;
        }
        if opts.contains(&a.as_ref()) {
            skip = true;
        } else if !a.starts_with('-') && !(prog == "cargo" && a.starts_with('+')) {
            out.push(a.to_lowercase());
        }
    }
    out
}

pub fn is_heavy(argv: &[OsString]) -> bool {
    let Some(first) = argv.first() else {
        return false;
    };
    let prog = program(first);
    let w = heavy_words(&prog, argv);
    let sub = |i: usize| w.get(i).map(String::as_str);
    match prog.as_str() {
        "npm" | "pnpm" | "yarn" | "bun" => match sub(0) {
            Some("test" | "build" | "install" | "ci") => true,
            Some("run") => matches!(sub(1), Some("build" | "test")),
            _ => false,
        },
        "next" => sub(0) == Some("build"),
        "docker" | "kiri" => {
            sub(0) == Some("build")
                || (sub(0) == Some("compose")
                    && sub(1) == Some("up")
                    && argv.iter().any(|a| a == "--build"))
        }
        "cargo" => matches!(sub(0), Some("build" | "test" | "clippy" | "xtask")),
        "go" => matches!(sub(0), Some("build" | "test")),
        "pytest" | "vitest" | "jest" | "tsc" | "gradle" | "mvn" => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(c: &[&str]) -> Vec<OsString> {
        c.iter().map(OsString::from).collect()
    }
    fn sig(c: &[&str], cwd: &str) -> JobSignature {
        signature(&os(c), Path::new(cwd)).unwrap()
    }

    #[test]
    fn key_ignores_flags_and_extension() {
        let a = sig(&["NPM.cmd", "run", "build", "--silent"], "/r/site");
        assert_eq!(a.key, "npm run build @ site");
    }
    #[test]
    fn same_command_other_repo_differs() {
        assert_ne!(
            sig(&["npm", "run", "build"], "/r/a").key,
            sig(&["npm", "run", "build"], "/r/b").key
        );
    }
    #[test]
    fn empty_argv_is_error() {
        assert!(matches!(
            signature(&[], Path::new("/")),
            Err(SignatureError::EmptyArgv)
        ));
    }
    #[test]
    fn guest_signature_never_touches_the_disk() {
        let d = std::env::temp_dir().join(format!("fg-gsig-{}", std::process::id()));
        std::fs::create_dir_all(d.join("repo/.git")).unwrap();
        std::fs::create_dir_all(d.join("repo/pkg/web")).unwrap();
        let cwd = d.join("repo/pkg/web");
        let control = signature(&os(&["cargo", "test"]), &cwd).unwrap();
        let guest = guest_signature("tester", &os(&["cargo", "test"]), &cwd).unwrap();
        std::fs::remove_dir_all(&d).unwrap();
        assert_eq!(control.key, "cargo test @ repo");
        assert_eq!(guest.key, "[guest tester] cargo test @ web");
        let unreachable = if cfg!(windows) {
            r"\\203.0.113.1\share\sub"
        } else {
            "/nonexistent/a/sub"
        };
        let g = guest_signature("tester", &os(&["cargo", "build"]), Path::new(unreachable));
        assert_eq!(g.unwrap().key, "[guest tester] cargo build @ sub");
        assert_eq!(
            guest_signature("t", &[], Path::new("/")),
            Err(SignatureError::EmptyArgv)
        );
    }
    #[test]
    fn repo_is_first_ancestor_with_git() {
        let d = std::env::temp_dir().join(format!("fg-sig-{}", std::process::id()));
        std::fs::create_dir_all(d.join("repo/.git")).unwrap();
        std::fs::create_dir_all(d.join("repo/pkg/web")).unwrap();
        let s = signature(&os(&["cargo", "test"]), &d.join("repo/pkg/web")).unwrap();
        std::fs::remove_dir_all(&d).unwrap();
        assert_eq!(s.key, "cargo test @ repo");
    }
    #[cfg(windows)]
    #[test]
    fn non_utf8_does_not_panic() {
        use std::os::windows::ffi::OsStringExt;
        let argv = vec![OsString::from("tool"), OsString::from_wide(&[0xD800])];
        assert!(signature(&argv, Path::new("/r/site")).is_ok());
    }
    #[cfg(unix)]
    #[test]
    fn non_utf8_does_not_panic() {
        use std::os::unix::ffi::OsStringExt;
        let argv = vec![OsString::from("tool"), OsString::from_vec(vec![0xff])];
        assert!(signature(&argv, Path::new("/r/site")).is_ok());
    }
    /// T4.1 (X1): only subcommand-shaped words from the start of the arguments reach the key.
    #[test]
    fn the_key_holds_only_the_program_subcommand_words_and_the_folder() {
        let hostile: [&[&str]; 10] = [
            &["docker", "build", "--build-arg", "TOKEN=dummy-secret", "."],
            &[
                "docker",
                "build",
                "https://alice:dummy-secret@example.invalid/r.git",
            ],
            &["npm", "run", "build", "--token", "dummy-secret"],
            &["mvn", "deploy", "-Dpassword=dummy-secret"],
            &["pytest", "--api-key", "dummy-secret"],
            &["npm", "run", "user:dummy-secret"],
            &["go", "test", "DUMMY-SECRET"],
            &["vitest", "dummysecretdummysecretdummysecret"],
            &["docker", "build", "./dummy-secret"],
            &["cargo", "build", r"C:\dummy-secret"],
        ];
        for argv in hostile {
            let owner = sig(argv, "/r/site").key;
            let guest = guest_signature("tester", &os(argv), Path::new("/r/site"))
                .unwrap()
                .key;
            let guest_words = guest.strip_prefix("[guest tester] ").unwrap();
            for key in [owner.as_str(), guest_words] {
                assert!(!key.to_lowercase().contains("dummy"), "{argv:?} -> {key}");
                let (head, folder) = key.split_once(" @ ").unwrap();
                assert_eq!(folder, "site");
                let words: Vec<&str> = head.split(' ').skip(1).collect();
                assert!(words.len() <= 2, "{key}");
                assert!(words.iter().all(|w| is_key_word(w)), "{key}");
            }
        }
        // Declared limit (M3): short lower-case words right after the program still enter.
        assert_eq!(
            sig(&["vitest", "hunter2"], "/r/site").key,
            "vitest hunter2 @ site"
        );
        assert_eq!(
            sig(&["cargo", "test", "hunter2"], "/r/site").key,
            "cargo test hunter2 @ site"
        );
        assert_eq!(
            guest_signature(
                "tester",
                &os(&["cargo", "test", "hunter2"]),
                Path::new("/r/site")
            )
            .unwrap()
            .key,
            "[guest tester] cargo test hunter2 @ site"
        );
    }

    /// T4.2 (X1): a refused word never promotes a later one.
    #[test]
    fn a_rejected_word_never_promotes_a_later_one() {
        let argv = [
            "docker",
            "build",
            "--build-arg",
            "PUBLIC=1",
            "https://alice:dummy-secret@example.invalid/repo.git",
        ];
        assert_eq!(sig(&argv, "/r/site").key, "docker build @ site");
    }

    #[test]
    fn heavy_programs_match_is_heavy() {
        let table: [(&str, &[&str]); 15] = [
            ("npm", &["npm", "install"]),
            ("pnpm", &["pnpm", "test"]),
            ("yarn", &["yarn", "build"]),
            ("bun", &["bun", "ci"]),
            ("next", &["next", "build"]),
            ("docker", &["docker", "build", "."]),
            ("kiri", &["kiri", "build", "."]),
            ("cargo", &["cargo", "test"]),
            ("go", &["go", "build"]),
            ("pytest", &["pytest"]),
            ("vitest", &["vitest"]),
            ("jest", &["jest"]),
            ("tsc", &["tsc"]),
            ("gradle", &["gradle"]),
            ("mvn", &["mvn"]),
        ];
        let names: Vec<&str> = table.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, HEAVY_PROGRAMS);
        for (_, argv) in table {
            assert!(is_heavy(&os(argv)), "{argv:?}");
        }
        for argv in [
            ["make", "build"].as_slice(),
            &["node", "build.js"],
            &["python", "-m", "pytest"],
        ] {
            assert!(!is_heavy(&os(argv)), "{argv:?}");
        }
    }
    #[test]
    fn heavy_examples() {
        for c in [
            ["next", "build"].as_slice(),
            &["docker", "build", "."],
            &["kiri", "build", "."],
            &["cargo", "test"],
            &["pnpm", "run", "test"],
            &["docker", "compose", "up", "--build"],
            &["pytest"],
            // every `cargo xtask` is heavy: it always compiles the xtask crate
            &["cargo", "xtask"],
            &["cargo", "xtask", "ci"],
            &["cargo", "xtask", "dist"],
            // tool options (some with a value) before the subcommand
            &["cargo", "+nightly", "build"],
            &["cargo", "--color", "always", "test"],
            &["cargo", "-C", "web", "build"],
            &["go", "-C", "web", "build"],
            &["docker", "-c", "ctx", "build", "."],
            &["docker", "--context", "ctx", "build", "."],
            &["yarn", "--cwd", "web", "build"],
            &["pnpm", "-C", "web", "test"],
            &["pnpm", "--dir", "web", "run", "build"],
            &["npm", "--prefix", "x", "install"],
            &["npm", "-C", "x", "test"],
            &["bun", "--cwd", "x", "install"],
            &["pnpm", "--filter", "x", "build"],
            &["pnpm", "-F", "x", "test"],
            &["docker", "-l", "debug", "build", "."],
            &["docker", "--log-level", "debug", "build", "."],
            &["docker", "--tlscacert", "ca.pem", "build", "."],
            &["docker", "--tlscert", "c.pem", "build", "."],
            &["docker", "--tlskey", "k.pem", "build", "."],
            &["docker", "--tls", "build", "."],
            &["docker", "--tlsverify", "build", "."],
            &["docker", "compose", "-f", "x.yml", "up", "--build"],
            &["docker", "compose", "-p", "x", "up", "--build"],
            &[
                "docker",
                "compose",
                "--project-directory",
                "x",
                "up",
                "--build",
            ],
        ] {
            assert!(is_heavy(&os(c)), "{c:?}");
        }
        for c in [
            ["git", "status"].as_slice(),
            &["ls"],
            &["npm", "--version"],
            &["docker", "compose", "up"],
            &["cargo", "run"],
            &["cargo", "--version"],
            &["cargo", "--color", "always", "run"],
            &["go", "-C", "web", "vet"],
            &["docker", "-c", "ctx", "ps"],
            &["docker", "-l", "debug", "ps"],
            &["docker", "compose", "-f", "x.yml", "up"],
            &["npm", "--prefix", "x", "--version"],
            &["pnpm", "--filter", "x", "outdated"],
        ] {
            assert!(!is_heavy(&os(c)), "{c:?}");
        }
    }
}
