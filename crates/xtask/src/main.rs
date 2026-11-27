//! `cargo xtask ci`: the checks of the project, run on this machine instead of on hosted runners.
//! With `--publish` the result is recorded on the commit as GitHub commit statuses
//! (`local/<system>`), so a pull request shows it.

mod bench;
mod dist;

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

const USAGE: &str = "\
usage: cargo xtask ci [--no-linux] [--publish]
       cargo xtask dist [--no-linux] --deny <file> [--allow <file>]
       cargo xtask scan --deny <file> [--allow <file>] <path>...
       cargo xtask bench setup --work <dir> --rev <sha> [--workloads <file>]
       cargo xtask bench run --work <dir> --bin <dir> [--phase without|with|both] [--repeat N] --out <json>
       cargo xtask bench report <json> [--svg <file>]

Runs on this machine: rustfmt, clippy for Linux, macOS and Windows, and the workspace tests.
On a Windows or macOS host it then runs the tests again on Linux, in a Docker container.

  --no-linux   skip the Linux container
  --publish    record the result on the HEAD commit as GitHub commit statuses; needs `gh`,
               a clean working tree and the commit already pushed

Needs SYNC_GATE_TEST_PG_BIN (the `bin` folder of a PostgreSQL, see docs/postgres.md) and the
rustup targets of the systems this machine is not: x86_64-unknown-linux-gnu,
x86_64-apple-darwin, x86_64-pc-windows-msvc.

dist writes the release archives to target/dist/v<version> (Windows host: the Windows zip with the
MSVC toolchain, and the Linux musl archives in a Docker container), and refuses to pack a binary
that holds a private name: the user folder, the user name, the repository path or a term of the
--deny list (kept outside the repository; --allow excuses terms, one reason each).
scan runs the same search over any files or folders.

bench is the proof scenario with and without sync_gate (docs/benchmark.md).";

/// The system (as `std::env::consts::OS` names it) and the target clippy checks for it.
const TARGETS: [(&str, &str); 3] = [
    ("linux", "x86_64-unknown-linux-gnu"),
    ("macos", "x86_64-apple-darwin"),
    ("windows", "x86_64-pc-windows-msvc"),
];

/// PostgreSQL of the Linux container (`tools/linux-pg/Dockerfile`).
const PG_MAJOR: &str = "17";

/// GitHub cuts a status description at this many characters.
const DESCRIPTION_MAX: usize = 140;

#[derive(Debug, PartialEq)]
struct Opts {
    linux: bool,
    publish: bool,
}

#[derive(Debug, PartialEq)]
struct DistOpts {
    linux: bool,
    deny: PathBuf,
    allow: Option<PathBuf>,
}

#[derive(Debug, PartialEq)]
struct ScanOpts {
    deny: PathBuf,
    allow: Option<PathBuf>,
    paths: Vec<PathBuf>,
}

#[derive(Debug, PartialEq)]
enum Cmd {
    Ci(Opts),
    Dist(DistOpts),
    Scan(ScanOpts),
    Bench(bench::BenchCmd),
}

fn parse(args: &[String]) -> Result<Cmd, String> {
    let Some((command, flags)) = args.split_first() else {
        return Err(USAGE.into());
    };
    match command.as_str() {
        "ci" => parse_ci(flags).map(Cmd::Ci),
        "dist" => parse_dist(flags).map(Cmd::Dist),
        "scan" => parse_scan(flags).map(Cmd::Scan),
        "bench" => bench::parse(flags).map(Cmd::Bench),
        _ => Err(format!("unknown command `{command}`\n\n{USAGE}")),
    }
}

fn parse_dist(flags: &[String]) -> Result<DistOpts, String> {
    let (mut linux, mut deny, mut allow) = (true, None, None);
    let mut flags = flags.iter();
    while let Some(flag) = flags.next() {
        match flag.as_str() {
            "--no-linux" => linux = false,
            "--deny" => deny = flags.next().map(PathBuf::from),
            "--allow" => allow = flags.next().map(PathBuf::from),
            other => return Err(format!("unknown option `{other}`\n\n{USAGE}")),
        }
    }
    let deny = deny.ok_or_else(|| format!("dist needs --deny <file>\n\n{USAGE}"))?;
    Ok(DistOpts { linux, deny, allow })
}

fn parse_scan(flags: &[String]) -> Result<ScanOpts, String> {
    let (mut deny, mut allow, mut paths) = (None, None, Vec::new());
    let mut flags = flags.iter();
    while let Some(flag) = flags.next() {
        match flag.as_str() {
            "--deny" => deny = flags.next().map(PathBuf::from),
            "--allow" => allow = flags.next().map(PathBuf::from),
            other if other.starts_with("--") => {
                return Err(format!("unknown option `{other}`\n\n{USAGE}"));
            }
            path => paths.push(PathBuf::from(path)),
        }
    }
    match deny {
        Some(deny) if !paths.is_empty() => Ok(ScanOpts { deny, allow, paths }),
        _ => Err(format!("scan needs --deny <file> and a path\n\n{USAGE}")),
    }
}

fn parse_ci(flags: &[String]) -> Result<Opts, String> {
    let mut opts = Opts {
        linux: env::consts::OS != "linux",
        publish: false,
    };
    for flag in flags {
        match flag.as_str() {
            "--no-linux" => opts.linux = false,
            "--publish" => opts.publish = true,
            other => return Err(format!("unknown option `{other}`\n\n{USAGE}")),
        }
    }
    Ok(opts)
}

/// One status: a list of steps that stops at the first failure.
struct Outcome {
    context: String,
    what: &'static str,
    failed: Option<String>,
    elapsed: Duration,
}

impl Outcome {
    fn description(&self) -> String {
        let secs = self.elapsed.as_secs();
        let time = format!("{}m{:02}s", secs / 60, secs % 60);
        let text = match &self.failed {
            None => format!("{}: passed in {time}", self.what),
            Some(step) => format!("failed after {time}: {step}"),
        };
        text.chars().take(DESCRIPTION_MAX).collect()
    }
}

fn label(command: &Command) -> String {
    std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(|part| part.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ")
}

/// A command and its short name. The name goes into the published status, so it carries no
/// path of this machine; the full command is only printed.
type Step = (String, Command);

fn run_job(context: String, what: &'static str, root: &Path, steps: Vec<Step>) -> Outcome {
    let start = Instant::now();
    let mut failed = None;
    for (name, mut command) in steps {
        println!("\n==> [{context}] {name}\n    {}", label(&command));
        match command.current_dir(root).status() {
            Ok(status) if status.success() => {}
            Ok(status) => {
                eprintln!("[{context}] {status}");
                failed = Some(name);
                break;
            }
            Err(error) => {
                eprintln!("[{context}] could not start: {error}");
                failed = Some(name);
                break;
            }
        }
    }
    Outcome {
        context,
        what,
        failed,
        elapsed: start.elapsed(),
    }
}

fn cargo(args: &[&str]) -> Step {
    // `cargo run` sets `CARGO`: the checks use the toolchain that built this program.
    let mut command = Command::new(env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
    command.args(args);
    (format!("cargo {}", args.join(" ")), command)
}

/// Windows cannot overwrite a running .exe, and `cargo test --workspace` relinks `xtask.exe` (the
/// test profile unifies other features). A running .exe can be renamed, so move it aside first.
/// shortcut: leftovers of a crashed run stay until the next run; errors are ignored, drop this
/// when the oldest supported cargo removes a running .exe itself.
#[cfg(windows)]
fn free_own_exe() {
    let Ok(exe) = env::current_exe() else { return };
    let (Some(dir), Some(name)) = (exe.parent(), exe.file_name()) else {
        return;
    };
    let prefix = format!("{}.old-", name.to_string_lossy());
    for old in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        if old.file_name().to_string_lossy().starts_with(&prefix) {
            let _ = std::fs::remove_file(old.path());
        }
    }
    let _ = std::fs::rename(&exe, dir.join(format!("{prefix}{}", std::process::id())));
}

fn host_steps() -> Vec<Step> {
    #[cfg(windows)]
    free_own_exe();
    let clippy = |target: Option<&str>| {
        let mut args = vec!["clippy", "--workspace", "--all-targets", "--locked"];
        if let Some(target) = target {
            args.extend(["--target", target]);
        }
        args.extend(["--", "-D", "warnings"]);
        cargo(&args)
    };
    let mut steps = vec![cargo(&["fmt", "--all", "--check"]), clippy(None)];
    for (_, target) in TARGETS.iter().filter(|(os, _)| *os != env::consts::OS) {
        steps.push(clippy(Some(target)));
    }
    let mut test = cargo(&["test", "--workspace", "--locked"]);
    // Under `CI` the tests that need a real PostgreSQL fail instead of skipping, and the heavy
    // end-to-end tests run.
    test.1.env("CI", "1");
    steps.push(test);
    steps
}

fn linux_steps(root: &Path) -> Vec<Step> {
    const VOLUMES: [&str; 4] = [
        "-v",
        "sync_gate-linux-target:/target",
        "-v",
        "sync_gate-linux-cargo:/cargo",
    ];
    // The image pins an x86_64 toolchain: an ARM host runs it emulated.
    const PLATFORM: [&str; 2] = ["--platform", "linux/amd64"];
    let docker = || Command::new("docker");
    let image = format!("sync_gate-linux-pg:{PG_MAJOR}");
    let mut steps = Vec::new();

    let has_image = docker()
        .args(["image", "inspect", &image])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !has_image {
        let mut build = docker();
        build
            .arg("build")
            .args(PLATFORM)
            .args(["--build-arg", &format!("PG_MAJOR={PG_MAJOR}")])
            .args(["-t", &image, "tools/linux-pg"]);
        steps.push(("docker build of the Linux image".into(), build));
    }

    // A new named volume belongs to root and the image runs as `fg`. The cargo home and the
    // target folder are subfolders because not every engine keeps the owner of a volume's root.
    let mut own = docker();
    own.args(["run", "--rm"])
        .args(PLATFORM)
        .args(["--user", "0"])
        .args(VOLUMES)
        .args([&image, "sh", "-c"])
        .arg("mkdir -p /target/t /cargo/h && chown fg /target/t /cargo/h");
    steps.push(("prepare the container volumes".into(), own));

    let mut test = docker();
    test.args(["run", "--rm", "--init"])
        .args(PLATFORM)
        .args(["-e", "CI=1"])
        .args([
            "-e",
            "CARGO_HOME=/cargo/h",
            "-e",
            "CARGO_TARGET_DIR=/target/t",
        ])
        .args([
            "-e",
            &format!("SYNC_GATE_TEST_PG_BIN=/usr/lib/postgresql/{PG_MAJOR}/bin"),
        ])
        // Without a value: passed through when set on the host.
        .args(["-e", "CARGO_NET_OFFLINE", "-e", "CARGO_BUILD_JOBS"])
        .args(["-v", &format!("{}:/src:ro", root.display())])
        .args(VOLUMES)
        .args(["-w", "/src", &image])
        .args(["cargo", "test", "--workspace", "--locked"]);
    steps.push((
        "cargo test --workspace --locked, in the container".into(),
        test,
    ));

    // Root runs the two-real-users tests in its own target folder; the cargo home it touched
    // goes back to `fg` so the next run as `fg` finds nothing of root's.
    let mut cross = docker();
    cross
        .args(["run", "--rm", "--init"])
        .args(PLATFORM)
        .args(["--user", "0", "-e", "CI=1"])
        .args([
            "-e",
            "CARGO_HOME=/cargo/h",
            "-e",
            "CARGO_TARGET_DIR=/target/root",
        ])
        .args(["-e", "CARGO_NET_OFFLINE", "-e", "CARGO_BUILD_JOBS"])
        .args(["-v", &format!("{}:/src:ro", root.display())])
        .args(VOLUMES)
        .args(["-w", "/src", &image])
        .args(["sh", "-c"])
        .arg(
            "cargo test -p sync_gate_core -p sync_gate_probe --features sync_gate_core/ipc --locked \
             -- --ignored xuser_; s=$?; chown -R fg /cargo/h || exit 1; exit $s",
        );
    steps.push(("cross-user tests as root, in the container".into(), cross));
    steps
}

/// The trimmed standard output of a command that must succeed.
fn output(root: &Path, program: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(program)
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|error| format!("could not start `{program}`: {error}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("`{program} {}`: {}", args.join(" "), stderr.trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// The HEAD commit, when a status on it would be true: the working tree has nothing the commit
/// lacks, and GitHub has the commit.
// shortcut: the tree is compared before and after the run, not during it, so a file changed and
// restored while the checks run goes unseen; upgrade to running on a checkout of the commit.
fn publishable_head(root: &Path) -> Result<String, String> {
    // Untracked files are asked for by name: `status.showUntrackedFiles=no` would hide a new crate.
    let status = ["status", "--porcelain", "--untracked-files=all"];
    if !output(root, "git", &status)?.is_empty() {
        return Err("--publish needs a clean working tree: commit or stash first".into());
    }
    let sha = output(root, "git", &["rev-parse", "HEAD"])?;
    let commit = format!("repos/{{owner}}/{{repo}}/commits/{sha}");
    output(root, "gh", &["api", "--silent", &commit])
        .map_err(|error| format!("--publish needs the commit on GitHub (push first): {error}"))?;
    Ok(sha)
}

fn post_status(root: &Path, sha: &str, outcome: &Outcome) -> Result<(), String> {
    let state = if outcome.failed.is_none() {
        "success"
    } else {
        "failure"
    };
    let args = [
        "api",
        "--silent",
        "-X",
        "POST",
        &format!("repos/{{owner}}/{{repo}}/statuses/{sha}"),
        "-f",
        &format!("state={state}"),
        "-f",
        &format!("context={}", outcome.context),
        "-f",
        &format!("description={}", outcome.description()),
    ];
    output(root, "gh", &args).map(drop)
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate lives in <root>/crates/xtask")
        .to_owned()
}

/// `Ok(true)` when every job passed.
fn ci(opts: Opts) -> Result<bool, String> {
    let root = repo_root();
    // Asked here, before minutes of compilation, and not by the first test that needs it.
    if env::var_os("SYNC_GATE_TEST_PG_BIN").is_none() {
        return Err("set SYNC_GATE_TEST_PG_BIN to the `bin` folder of a PostgreSQL".into());
    }
    let sha = opts.publish.then(|| publishable_head(&root)).transpose()?;

    let mut outcomes = vec![run_job(
        format!("local/{}", env::consts::OS),
        "fmt, clippy for 3 systems, tests",
        &root,
        host_steps(),
    )];
    if opts.linux {
        outcomes.push(run_job(
            "local/linux".into(),
            "tests in a container",
            &root,
            linux_steps(&root),
        ));
    }

    println!();
    for outcome in &outcomes {
        println!("{}: {}", outcome.context, outcome.description());
    }
    if let Some(sha) = sha {
        if publishable_head(&root).ok().as_deref() != Some(sha.as_str()) {
            return Err("HEAD or the working tree changed during the run: not published".into());
        }
        for outcome in &outcomes {
            post_status(&root, &sha, outcome)?;
        }
        println!("published on {sha}");
    }
    Ok(outcomes.iter().all(|outcome| outcome.failed.is_none()))
}

fn run(cmd: Cmd) -> Result<bool, String> {
    match cmd {
        Cmd::Ci(opts) => ci(opts),
        Cmd::Dist(o) => dist::dist(&repo_root(), o.linux, &o.deny, o.allow.as_deref()),
        Cmd::Scan(o) => dist::scan(&repo_root(), &o.deny, o.allow.as_deref(), &o.paths),
        Cmd::Bench(c) => bench::bench(&repo_root(), &c),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match parse(&args).and_then(run) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| arg.to_string()).collect()
    }

    #[test]
    fn parse_reads_the_flags_and_refuses_the_rest() {
        let default_linux = env::consts::OS != "linux";
        assert_eq!(
            parse(&args(&["ci"])),
            Ok(Cmd::Ci(Opts {
                linux: default_linux,
                publish: false
            }))
        );
        assert_eq!(
            parse(&args(&["ci", "--publish", "--no-linux"])),
            Ok(Cmd::Ci(Opts {
                linux: false,
                publish: true
            }))
        );
        assert!(parse(&args(&[])).is_err());
        assert!(parse(&args(&["deploy"])).is_err());
        assert!(parse(&args(&["ci", "--force"])).is_err());
    }

    #[test]
    fn parse_reads_dist_and_scan_and_refuses_the_rest() {
        let path = |p: &str| PathBuf::from(p);
        assert_eq!(
            parse(&args(&["dist", "--deny", "d.txt"])),
            Ok(Cmd::Dist(DistOpts {
                linux: true,
                deny: path("d.txt"),
                allow: None
            }))
        );
        assert_eq!(
            parse(&args(&[
                "dist",
                "--no-linux",
                "--deny",
                "d",
                "--allow",
                "a"
            ])),
            Ok(Cmd::Dist(DistOpts {
                linux: false,
                deny: path("d"),
                allow: Some(path("a"))
            }))
        );
        assert_eq!(
            parse(&args(&[
                "scan", "--deny", "d", "--allow", "a", "one", "two"
            ])),
            Ok(Cmd::Scan(ScanOpts {
                deny: path("d"),
                allow: Some(path("a")),
                paths: vec![path("one"), path("two")]
            }))
        );
        // dist without a deny list refuses to run; scan needs a list and a path
        assert!(parse(&args(&["dist"])).is_err());
        assert!(parse(&args(&["dist", "--no-linux"])).is_err());
        assert!(parse(&args(&["dist", "--deny"])).is_err());
        assert!(parse(&args(&["dist", "--deny", "d", "--publish"])).is_err());
        assert!(parse(&args(&["scan", "--deny", "d"])).is_err());
        assert!(parse(&args(&["scan", "one"])).is_err());
        assert!(parse(&args(&["scan", "--deny", "d", "--bogus", "one"])).is_err());
    }

    #[test]
    fn description_names_the_failed_step_and_fits_the_github_limit() {
        let mut outcome = Outcome {
            context: "local/linux".into(),
            what: "tests in a container",
            failed: None,
            elapsed: Duration::from_secs(125),
        };
        assert_eq!(
            outcome.description(),
            "tests in a container: passed in 2m05s"
        );
        outcome.failed = Some("cargo test ".repeat(40));
        let description = outcome.description();
        assert!(description.starts_with("failed after 2m05s: cargo test"));
        assert_eq!(description.chars().count(), DESCRIPTION_MAX);
    }

    #[test]
    fn host_steps_check_the_other_two_systems_and_end_with_the_tests() {
        let steps = host_steps();
        let names: Vec<&str> = steps.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names.len(), 5);
        assert_eq!(names[0], "cargo fmt --all --check");
        let cross = names.iter().filter(|n| n.contains("--target")).count();
        assert_eq!(cross, 2);
        assert_eq!(names[4], "cargo test --workspace --locked");
    }
}
