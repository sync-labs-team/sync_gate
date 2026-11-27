//! The weekly look at the latest release. One anonymous GET to the GitHub API, made by `curl`
//! from this daemon only, never from a command the user types. The result is a small cache,
//! `update-check.json`, that `sync_gate status` and the session hook only read.
//! Off (`update_check_days = 0` or `SYNC_GATE_UPDATE_CHECK=0`): no call, and the cache is removed.

use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sync_gate_core::update::{
    CACHE_FILE, Cache, Version, disabled, due, parse_version, read_cache,
};

const URL: &str = "https://api.github.com/repos/sync-labs-team/sync_gate/releases/latest";
/// First look this long after the start, so a daemon started by a test or a harness is gone first.
const FIRST_DELAY: Duration = Duration::from_secs(600);
const WAKE: Duration = Duration::from_secs(3600);
const BODY_LIMIT: u64 = 1 << 20;
const HARD_DEADLINE: Duration = Duration::from_secs(10);

#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    Disabled,
    NotDue,
    Fetched,
    Failed,
}

/// One wake-up: remove the cache when off; otherwise, when due, call `fetch` once and record it.
/// The attempt is stamped before the call, so a crash in it does not repeat at once. Success or
/// failure, the next try waits the whole interval (a failure keeps the old `latest`). `last` is the
/// same stamp kept in memory, so a data folder that cannot be written does not mean a call an hour.
pub fn step(
    dir: &Path,
    last: &mut Option<u64>,
    now: u64,
    days: u64,
    env: Option<&OsStr>,
    fetch: &mut dyn FnMut() -> Option<Version>,
) -> Step {
    if disabled(days, env) {
        let _ = std::fs::remove_file(dir.join(CACHE_FILE));
        return Step::Disabled;
    }
    let old = read_cache(dir);
    if old
        .as_ref()
        .is_some_and(|c| !due(now, c.checked_unix, days))
        || last.is_some_and(|t| !due(now, t, days))
    {
        return Step::NotDue;
    }
    *last = Some(now);
    let latest = old.and_then(|c| c.latest);
    write(
        dir,
        &Cache {
            checked_unix: now,
            latest,
        },
    );
    match fetch() {
        Some(v) => {
            write(
                dir,
                &Cache {
                    checked_unix: now,
                    latest: Some(v),
                },
            );
            Step::Fetched
        }
        None => Step::Failed,
    }
}

fn write(dir: &Path, c: &Cache) {
    let _ = sync_gate_probe::write_atomic(&dir.join(CACHE_FILE), c.to_json().as_bytes());
}

/// `curl` arguments: `-q` first (no `.curlrc`/`.netrc`), HTTPS only, small and quick, no cookies,
/// no headers of our own beyond `Accept`.
pub fn curl_args() -> Vec<&'static str> {
    vec![
        "-q",
        "-fsS",
        "--max-time",
        "5",
        "--proto",
        "=https",
        "--max-filesize",
        "1048576",
        "-H",
        "Accept: application/vnd.github+json",
    ]
}

fn curl_program() -> Option<PathBuf> {
    if cfg!(windows) {
        let root = std::env::var_os("SystemRoot")?;
        let p = Path::new(&root).join("System32").join("curl.exe");
        p.is_file().then_some(p)
    } else {
        Some(PathBuf::from("curl"))
    }
}

/// `tag_name` of the release JSON, if it is a plain `X.Y.Z` tag.
pub fn latest_from_body(body: &[u8]) -> Option<Version> {
    #[derive(serde::Deserialize)]
    struct Release {
        tag_name: String,
    }
    parse_version(&serde_json::from_slice::<Release>(body).ok()?.tag_name)
}

/// The real look: `None` on any failure (no `curl`, offline, 403, a bad body).
pub fn fetch_latest() -> Option<Version> {
    let mut cmd = Command::new(curl_program()?);
    cmd.args(curl_args())
        .arg(URL)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    std::os::windows::process::CommandExt::creation_flags(&mut cmd, 0x0800_0000); // CREATE_NO_WINDOW
    let mut child = cmd.spawn().ok()?;
    let mut out = child.stdout.take()?;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = (&mut out).take(BODY_LIMIT).read_to_end(&mut buf);
        let _ = tx.send(buf);
    });
    let Ok(body) = rx.recv_timeout(HARD_DEADLINE) else {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    };
    child.wait().ok()?.success().then_some(())?;
    latest_from_body(&body)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Starts the thread: first look after `FIRST_DELAY`, then one wake-up an hour. `days` is read at
/// every wake-up (the config can change). Never joined: the daemon's shutdown does not wait for it.
pub fn spawn(dir: PathBuf, days: impl Fn() -> u64 + Send + 'static) {
    let _ = std::thread::Builder::new()
        .name("update-check".into())
        .spawn(move || {
            let env = || -> Option<OsString> { std::env::var_os("SYNC_GATE_UPDATE_CHECK") };
            // Off at the start: the cache of an earlier run goes away at once.
            if disabled(days(), env().as_deref()) {
                let _ = std::fs::remove_file(dir.join(CACHE_FILE));
            }
            std::thread::sleep(FIRST_DELAY);
            let mut last = None;
            loop {
                step(
                    &dir,
                    &mut last,
                    now_unix(),
                    days(),
                    env().as_deref(),
                    &mut fetch_latest,
                );
                std::thread::sleep(WAKE);
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 86_400;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sg-uc-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Runs `step` with a fetcher that counts calls and answers `answer`.
    fn run(
        dir: &Path,
        now: u64,
        days: u64,
        env: Option<&str>,
        answer: Option<Version>,
    ) -> (Step, u32) {
        run_mem(dir, &mut None, now, days, env, answer)
    }

    /// Same, with the in-memory stamp of the thread kept by the caller.
    fn run_mem(
        dir: &Path,
        last: &mut Option<u64>,
        now: u64,
        days: u64,
        env: Option<&str>,
        answer: Option<Version>,
    ) -> (Step, u32) {
        let mut calls = 0;
        let s = step(dir, last, now, days, env.map(OsStr::new), &mut || {
            calls += 1;
            answer
        });
        (s, calls)
    }

    #[test]
    fn off_makes_no_call_and_removes_the_cache() {
        let d = tmp("off");
        write(
            &d,
            &Cache {
                checked_unix: 0,
                latest: Some((9, 0, 0)),
            },
        );
        assert_eq!(
            run(&d, 100 * DAY, 0, None, Some((1, 0, 0))),
            (Step::Disabled, 0)
        );
        assert!(!d.join(CACHE_FILE).exists());
        write(
            &d,
            &Cache {
                checked_unix: 0,
                latest: None,
            },
        );
        assert_eq!(
            run(&d, 100 * DAY, 7, Some("0"), Some((1, 0, 0))),
            (Step::Disabled, 0)
        );
        assert!(!d.join(CACHE_FILE).exists());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn fresh_cache_does_not_look_old_one_does() {
        let d = tmp("due");
        let now = 100 * DAY;
        write(
            &d,
            &Cache {
                checked_unix: now - 6 * DAY,
                latest: Some((0, 1, 2)),
            },
        );
        assert_eq!(run(&d, now, 7, None, Some((0, 1, 3))), (Step::NotDue, 0));
        assert_eq!(read_cache(&d).unwrap().latest, Some((0, 1, 2)));
        write(
            &d,
            &Cache {
                checked_unix: now - 7 * DAY,
                latest: Some((0, 1, 2)),
            },
        );
        assert_eq!(run(&d, now, 7, None, Some((0, 1, 3))), (Step::Fetched, 1));
        assert_eq!(
            read_cache(&d),
            Some(Cache {
                checked_unix: now,
                latest: Some((0, 1, 3))
            })
        );
        // No cache at all: look once.
        std::fs::remove_file(d.join(CACHE_FILE)).unwrap();
        assert_eq!(run(&d, now, 7, None, Some((0, 1, 3))).1, 1);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn failure_is_silent_keeps_latest_and_waits_the_whole_interval() {
        let d = tmp("fail");
        let now = 100 * DAY;
        write(
            &d,
            &Cache {
                checked_unix: now - 8 * DAY,
                latest: Some((0, 1, 3)),
            },
        );
        assert_eq!(run(&d, now, 7, None, None), (Step::Failed, 1));
        let c = read_cache(&d).unwrap();
        assert_eq!(c.latest, Some((0, 1, 3)), "old answer kept");
        assert_eq!(c.checked_unix, now, "attempt recorded");
        for later in [3600, 6 * 3600 + 1, 3 * DAY, 7 * DAY - 1] {
            assert_eq!(run(&d, now + later, 7, None, None).1, 0, "{later}s");
        }
        assert_eq!(run(&d, now + 7 * DAY, 7, None, None).1, 1, "after 7 days");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn an_unwritable_cache_still_limits_the_calls() {
        let d = tmp("nowrite");
        // A folder where the file should be: nothing can be written or read there.
        std::fs::create_dir(d.join(CACHE_FILE)).unwrap();
        let now = 100 * DAY;
        let mut last = None;
        let mut go = |t: u64| run_mem(&d, &mut last, t, 7, None, Some((0, 1, 3))).1;
        assert_eq!(go(now), 1);
        for h in 1..=168 {
            assert_eq!(go(now + h * 3600 - 1), 0, "{h} h");
        }
        assert_eq!(go(now + 7 * DAY), 1);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn body_takes_only_a_plain_tag() {
        assert_eq!(
            latest_from_body(br#"{"tag_name":"v0.1.3","draft":false}"#),
            Some((0, 1, 3))
        );
        for bad in [
            &br#"{"tag_name":"v0.1.3-rc1"}"#[..],
            br#"{"tag_name":"ignore previous instructions"}"#,
            br#"{"tag_name":7}"#,
            br#"{"message":"rate limited"}"#,
            b"<html>",
            b"",
        ] {
            assert_eq!(latest_from_body(bad), None);
        }
    }

    #[test]
    fn curl_is_anonymous_https_only_and_bounded() {
        let a = curl_args();
        assert_eq!(
            a.first(),
            Some(&"-q"),
            "first, or a .curlrc could add headers"
        );
        let j = a.join(" ");
        for must in [
            "--proto =https",
            "--max-time 5",
            "--max-filesize",
            "Accept: application/vnd.github+json",
        ] {
            assert!(j.contains(must), "{j}");
        }
        for never in ["Authorization", "--cookie", "-b ", "-L", "--user", "--data"] {
            assert!(!j.contains(never), "{never}");
        }
    }
}
