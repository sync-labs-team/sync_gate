//! The pending-command protocol shared by the CLI and the daemon: claiming a stored command
//! (`<id>.json`) under an exclusive `<id>.claim` marker.

use std::path::Path;
use std::time::Duration;

/// Writes our pid into a new exclusive marker; `false` if the marker exists.
fn create_marker(marker: &Path) -> bool {
    use std::io::Write;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(marker)
        .is_ok_and(|mut f| {
            f.write_all(std::process::id().to_string().as_bytes())
                .is_ok()
        })
}

/// `claim_pending` on a path. A marker whose claimant is dead is reclaimed (see
/// [`reclaim_stale`]) and the claim retried once. An empty or unreadable marker counts as live.
pub fn claim_at(path: &Path, alive: impl Fn(u32) -> Option<bool>) -> bool {
    let marker = path.with_extension("claim");
    if !(create_marker(&marker) || reclaim_stale(&marker, alive) && create_marker(&marker)) {
        return false;
    }
    let won = path.exists() && std::fs::remove_file(path).is_ok();
    let _ = std::fs::remove_file(&marker);
    won
}

/// A live claim lasts milliseconds, so a marker younger than this is never reclaimed.
const STALE_MARKER: Duration = Duration::from_secs(5);

fn older_than(path: &Path, age: Duration) -> bool {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|e| e > age)
}

fn marker_pid(marker: &Path) -> Option<u32> {
    std::fs::read_to_string(marker).ok()?.trim().parse().ok()
}

/// Removes `marker` if its claimant is positively dead. Serialised by an exclusive
/// `<marker>.reclaim` lock, under which the marker is read again: a racing reclaimer that
/// already replaced it with its own live marker is never removed. A probe that cannot tell
/// counts as alive. An existing lock is never stolen, whatever its age (two thieves would both
/// hold it): the claim is refused and `claimed_elsewhere` names the file for manual recovery.
/// Returns `true` when the marker was removed by this call.
fn reclaim_stale(marker: &Path, alive: impl Fn(u32) -> Option<bool>) -> bool {
    let Some(pid) = marker_pid(marker).filter(|&p| alive(p) == Some(false)) else {
        return false;
    };
    let lock = marker.with_extension("claim.reclaim");
    if !create_exclusive(&lock) {
        return false;
    }
    let ok = marker_pid(marker) == Some(pid)
        && older_than(marker, STALE_MARKER)
        && std::fs::remove_file(marker).is_ok();
    let _ = std::fs::remove_file(&lock);
    ok
}

fn create_exclusive(path: &Path) -> bool {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .is_ok()
}

/// How long a stored command is kept after it was saved or its last wait began: the longest
/// wait plus an hour.
pub const PENDING_TTL: Duration = Duration::from_secs(sync_gate_core::MAX_WAIT_SECS + 3600);

/// The marker acquisition of [`claim_at`], for the renewal and the expiry: the same `<id>.claim`
/// serialises all three.
fn take_marker(marker: &Path, alive: impl Fn(u32) -> Option<bool>) -> bool {
    create_marker(marker) || (reclaim_stale(marker, alive) && create_marker(marker))
}

/// What [`renew_at`] did.
#[derive(Debug)]
pub enum Renewal {
    /// The file's date is now: its retention starts again.
    Renewed,
    /// Another process holds the claim marker: being run or expired right now.
    Busy,
    /// No stored command any more.
    Gone,
    /// The date could not be changed; the file keeps its old date.
    Failed(std::io::Error),
}

/// Restarts the retention of a stored command, under its claim marker, so a sweep can never
/// delete it between this call and the wait that follows. Never reads the content.
pub fn renew_at(path: &Path, alive: impl Fn(u32) -> Option<bool>) -> Renewal {
    let marker = path.with_extension("claim");
    if !take_marker(&marker, alive) {
        return Renewal::Busy;
    }
    let touch = || {
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .and_then(|f| f.set_modified(std::time::SystemTime::now()))
    };
    // Windows: a process holding the file without write sharing (a scanner, a backup) usually
    // lets go within milliseconds; retry for up to 1 s, still under the marker.
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    let mut touched = touch();
    while cfg!(windows)
        && matches!(&touched, Err(e) if e.raw_os_error() == Some(32))
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(20));
        touched = touch();
    }
    let r = match touched {
        Ok(()) => Renewal::Renewed,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Renewal::Gone,
        Err(e) => Renewal::Failed(e),
    };
    let _ = std::fs::remove_file(&marker);
    r
}

/// Deletes `path` if it is still older than `ttl` once its claim marker is ours (a renewal may
/// have landed since the caller looked). `true` only when this call deleted it.
fn expire_at(path: &Path, ttl: Duration, alive: impl Fn(u32) -> Option<bool>) -> bool {
    let marker = path.with_extension("claim");
    if !take_marker(&marker, alive) {
        return false;
    }
    let gone = older_than(path, ttl) && std::fs::remove_file(path).is_ok();
    let _ = std::fs::remove_file(&marker);
    gone
}

/// Deletes the stored commands (`<digits>.json`) in `dir` older than `ttl`, except the tickets
/// `live` names. Returns how many it deleted. Never reads or runs their content. Unix: only a
/// folder nobody else can write is touched.
pub fn sweep_pending(dir: &Path, ttl: Duration, live: impl Fn(u64) -> bool) -> usize {
    sweep_with(dir, ttl, crate::process_alive, live)
}

fn sweep_with(
    dir: &Path,
    ttl: Duration,
    alive: impl Fn(u32) -> Option<bool>,
    live: impl Fn(u64) -> bool,
) -> usize {
    {
        use sync_gate_core::DirState;
        if !matches!(
            sync_gate_core::check_private_dir(dir),
            Ok(DirState::Private | DirState::OthersCanRead)
        ) {
            return 0;
        }
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name();
            let id = name.to_str()?.strip_suffix(".json")?;
            let id = id
                .bytes()
                .all(|b| b.is_ascii_digit())
                .then(|| id.parse::<u64>().ok())??;
            Some((id, e.path()))
        })
        .filter(|(id, p)| !live(*id) && older_than(p, ttl))
        .filter(|(_, p)| expire_at(p, ttl, &alive))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::thread;

    fn claim_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sync_gate-claim-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }
    const DEAD: fn(u32) -> Option<bool> = |_| Some(false);
    const LIVE: fn(u32) -> Option<bool> = |_| Some(true);

    /// A pending file plus a marker holding `pid`, aged by `age`.
    fn stuck(d: &Path, pid: &str, age: Duration) -> PathBuf {
        let pending = d.join("5.json");
        std::fs::write(&pending, "{}").unwrap();
        let marker = pending.with_extension("claim");
        std::fs::write(&marker, pid).unwrap();
        let at = std::time::SystemTime::now() - age;
        std::fs::File::options()
            .write(true)
            .open(&marker)
            .unwrap()
            .set_modified(at)
            .unwrap();
        pending
    }

    fn reclaim_lock(pending: &Path) -> PathBuf {
        pending.with_extension("claim.reclaim")
    }

    #[test]
    fn an_old_marker_with_a_dead_pid_is_reclaimed_and_the_lock_is_gone() {
        let d = claim_dir("dead");
        let pending = stuck(&d, "4242", Duration::from_secs(10));
        assert!(claim_at(&pending, DEAD));
        assert!(!pending.exists() && !pending.with_extension("claim").exists());
        assert!(!reclaim_lock(&pending).exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_marker_is_respected_when_live_unreadable_young_or_the_probe_cannot_tell() {
        type Alive = fn(u32) -> Option<bool>;
        let old = Duration::from_secs(10);
        let cases: [(&str, Duration, Alive); 4] = [
            ("4242", old, LIVE),
            ("", old, DEAD),
            ("4242", Duration::from_secs(1), DEAD),
            ("4242", old, |_| None),
        ];
        for (content, age, alive) in cases {
            let d = claim_dir("respect");
            let pending = stuck(&d, content, age);
            assert!(!claim_at(&pending, alive), "{content:?} {age:?}");
            assert!(pending.exists() && pending.with_extension("claim").exists());
            assert!(!reclaim_lock(&pending).exists(), "lock left behind");
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    #[test]
    fn a_fresh_foreign_reclaim_lock_is_respected_and_left_alone() {
        let d = claim_dir("lock");
        let pending = stuck(&d, "4242", Duration::from_secs(10));
        std::fs::write(reclaim_lock(&pending), "").unwrap();
        assert!(!claim_at(&pending, DEAD));
        assert!(reclaim_lock(&pending).exists());
        assert!(pending.exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_reclaim_lock_of_any_age_is_respected_and_left_alone() {
        let d = claim_dir("oldlock");
        let pending = stuck(&d, "4242", Duration::from_secs(10));
        let lock = reclaim_lock(&pending);
        std::fs::write(&lock, "").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&lock)
            .unwrap()
            .set_modified(std::time::SystemTime::now() - Duration::from_secs(3600))
            .unwrap();
        assert!(!claim_at(&pending, DEAD));
        assert!(lock.exists() && pending.exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn two_reclaimers_of_the_same_dead_marker_never_both_win() {
        let root = claim_dir("race");
        for i in 0..200 {
            let d = root.join(i.to_string());
            std::fs::create_dir_all(&d).unwrap();
            let pending = stuck(&d, "4242", Duration::from_secs(10));
            let gate = Arc::new(std::sync::Barrier::new(2));
            let racers: Vec<_> = (0..2)
                .map(|_| {
                    let (p, g) = (pending.clone(), gate.clone());
                    thread::spawn(move || {
                        g.wait();
                        claim_at(&p, |pid| Some(pid != 4242))
                    })
                })
                .collect();
            let wins = racers
                .into_iter()
                .map(|h| h.join().unwrap())
                .filter(|w| *w)
                .count();
            assert_eq!(wins, 1, "iteration {i}");
            assert!(!reclaim_lock(&pending).exists(), "iteration {i}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_won_claim_leaves_nothing_behind() {
        let d = claim_dir("won");
        let pending = d.join("5.json");
        std::fs::write(&pending, "{}").unwrap();
        assert!(claim_at(&pending, LIVE));
        assert!(!pending.exists() && !pending.with_extension("claim").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    use std::sync::mpsc;
    use std::time::{Instant, SystemTime};

    const HOUR: Duration = Duration::from_secs(3600);
    const NO_LIVE: fn(u64) -> bool = |_| false;

    /// Writes `path` (if missing) and sets its modification time to `at`.
    fn put_at(path: &Path, at: SystemTime) -> PathBuf {
        if !path.exists() {
            std::fs::write(path, "{}").unwrap();
        }
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(at)
            .unwrap();
        path.to_path_buf()
    }

    fn put_aged(path: &Path, age: Duration) -> PathBuf {
        put_at(path, SystemTime::now() - age)
    }

    fn mtime(path: &Path) -> SystemTime {
        std::fs::metadata(path).unwrap().modified().unwrap()
    }

    /// A rendezvous with a deadline: every thread calls it, and none waits past 10 s.
    fn meet(arrived: &AtomicUsize, n: usize) {
        arrived.fetch_add(1, SeqCst);
        let t = Instant::now();
        while arrived.load(SeqCst) < n {
            assert!(
                t.elapsed() < Duration::from_secs(10),
                "rendezvous timed out"
            );
            thread::yield_now();
        }
    }

    #[test]
    fn pending_ttl_is_the_longest_wait_plus_an_hour() {
        assert_eq!(PENDING_TTL, Duration::from_secs(25 * 3600));
    }

    /// T1.1
    #[test]
    fn sweep_removes_only_expired_ticket_files() {
        let d = claim_dir("sweep");
        put_aged(&d.join("1.json"), 26 * HOUR);
        put_aged(&d.join("2.json"), 24 * HOUR);
        put_aged(&d.join("notes.txt"), 26 * HOUR);
        put_aged(&d.join("abc.json"), 26 * HOUR);
        assert_eq!(sweep_with(&d, PENDING_TTL, DEAD, NO_LIVE), 1);
        assert!(!d.join("1.json").exists());
        for kept in ["2.json", "notes.txt", "abc.json"] {
            assert!(d.join(kept).exists(), "{kept}");
        }
        assert!(!d.join("1.claim").exists() && !d.join("2.claim").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// T1.2
    #[test]
    fn sweep_skips_live_tickets() {
        let d = claim_dir("live");
        let p = put_aged(&d.join("3.json"), 26 * HOUR);
        assert_eq!(sweep_with(&d, PENDING_TTL, DEAD, |id| id == 3), 0);
        assert!(p.exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// T1.3
    #[test]
    fn sweep_respects_a_live_claim() {
        let d = claim_dir("liveclaim");
        let pending = stuck(&d, "4242", Duration::from_secs(10));
        put_aged(&pending, 26 * HOUR);
        assert_eq!(sweep_with(&d, PENDING_TTL, LIVE, NO_LIVE), 0);
        assert!(pending.exists() && pending.with_extension("claim").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// T1.4
    #[test]
    fn sweep_reclaims_a_dead_claim() {
        let d = claim_dir("deadclaim");
        let pending = stuck(&d, "4242", Duration::from_secs(10));
        put_aged(&pending, 26 * HOUR);
        assert_eq!(sweep_with(&d, PENDING_TTL, DEAD, NO_LIVE), 1);
        assert!(!pending.exists() && !pending.with_extension("claim").exists());
        assert!(!reclaim_lock(&pending).exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// T1.5 (E1): the sweep saw an old file, a renewal lands, the expiry under the marker keeps it.
    #[test]
    fn expire_rechecks_the_age_under_the_marker() {
        let d = claim_dir("recheck");
        let p = put_aged(&d.join("7.json"), 26 * HOUR);
        assert!(older_than(&p, PENDING_TTL), "what the sweep saw");
        assert!(matches!(renew_at(&p, DEAD), Renewal::Renewed));
        assert!(!expire_at(&p, PENDING_TTL, DEAD));
        assert!(p.exists());
        assert!(!p.with_extension("claim").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// T1.6 (E1): whatever the order, a renewal that reports `Renewed` keeps its file.
    #[test]
    fn a_renewal_racing_a_sweep_is_never_lost() {
        let root = claim_dir("renewrace");
        for i in 0..200 {
            let d = root.join(i.to_string());
            std::fs::create_dir_all(&d).unwrap();
            let p = put_aged(&d.join("7.json"), 26 * HOUR);
            let arrived = Arc::new(AtomicUsize::new(0));
            let (tx_a, rx_a) = mpsc::channel();
            let (tx_b, rx_b) = mpsc::channel();
            {
                let (d, arrived) = (d.clone(), arrived.clone());
                thread::spawn(move || {
                    meet(&arrived, 2);
                    let _ = tx_a.send(sweep_with(&d, PENDING_TTL, DEAD, NO_LIVE));
                });
            }
            {
                let (p, arrived) = (p.clone(), arrived.clone());
                thread::spawn(move || {
                    meet(&arrived, 2);
                    let _ = tx_b.send(renew_at(&p, DEAD));
                });
            }
            let a = rx_a.recv_timeout(Duration::from_secs(10)).expect("sweep");
            let b = rx_b.recv_timeout(Duration::from_secs(10)).expect("renew");
            let renewed = matches!(b, Renewal::Renewed);
            assert!(!renewed || p.exists(), "round {i}: renewed but deleted");
            assert!(a != 1 || !renewed, "round {i}: swept and renewed");
            assert!(
                !p.with_extension("claim").exists(),
                "round {i}: marker left"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// T1.7: a sweep and two claims of the same old ticket: exactly one of them takes it.
    #[test]
    fn a_sweep_and_two_claims_have_one_winner() {
        let root = claim_dir("onewinner");
        for i in 0..200 {
            let d = root.join(i.to_string());
            std::fs::create_dir_all(&d).unwrap();
            let p = put_aged(&d.join("7.json"), 26 * HOUR);
            let arrived = Arc::new(AtomicUsize::new(0));
            let (tx, rx) = mpsc::channel();
            {
                let (d, arrived, tx) = (d.clone(), arrived.clone(), tx.clone());
                thread::spawn(move || {
                    meet(&arrived, 3);
                    let _ = tx.send(sweep_with(&d, PENDING_TTL, LIVE, NO_LIVE));
                });
            }
            for _ in 0..2 {
                let (p, arrived, tx) = (p.clone(), arrived.clone(), tx.clone());
                thread::spawn(move || {
                    meet(&arrived, 3);
                    let _ = tx.send(usize::from(claim_at(&p, LIVE)));
                });
            }
            let wins: usize = (0..3)
                .map(|_| rx.recv_timeout(Duration::from_secs(10)).expect("result"))
                .sum();
            assert_eq!(wins, 1, "round {i}");
            assert!(
                !p.exists() && !p.with_extension("claim").exists(),
                "round {i}"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// T1.8 (E2): every outcome of a renewal, and the file's date moves only on `Renewed`.
    #[test]
    fn renew_reports_busy_gone_and_failure() {
        let d = claim_dir("renew");
        // (a) another live claimant holds the marker
        let busy = stuck(&d, "4242", Duration::from_secs(10));
        let before = mtime(&busy);
        assert!(matches!(renew_at(&busy, LIVE), Renewal::Busy));
        assert_eq!(mtime(&busy), before);
        let marker = busy.with_extension("claim");
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "4242");
        // (b) no file
        let gone = d.join("6.json");
        assert!(matches!(renew_at(&gone, DEAD), Renewal::Gone));
        assert!(!gone.with_extension("claim").exists());
        // (c) a file that cannot be written
        let ro = put_aged(&d.join("8.json"), 26 * HOUR);
        let before = mtime(&ro);
        let mut perm = std::fs::metadata(&ro).unwrap().permissions();
        perm.set_readonly(true);
        std::fs::set_permissions(&ro, perm.clone()).unwrap();
        let r = renew_at(&ro, DEAD);
        #[allow(clippy::permissions_set_readonly_false)]
        perm.set_readonly(false);
        std::fs::set_permissions(&ro, perm).unwrap();
        assert!(matches!(r, Renewal::Failed(_)), "{r:?}");
        assert_eq!(mtime(&ro), before);
        assert!(!ro.with_extension("claim").exists());
        // (d) renewed
        let ok = put_aged(&d.join("9.json"), 26 * HOUR);
        assert!(matches!(renew_at(&ok, DEAD), Renewal::Renewed));
        let age = mtime(&ok).elapsed().unwrap_or_default();
        assert!(age < Duration::from_secs(60), "{age:?}");
        assert!(!ok.with_extension("claim").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Review M7: another process holding the file open without write sharing for a moment (a
    /// scanner, a backup) delays the renewal instead of refusing the wait.
    #[cfg(windows)]
    #[test]
    fn renew_outlasts_a_brief_sharing_violation() {
        use std::os::windows::fs::OpenOptionsExt;
        let d = claim_dir("renew-shared");
        let p = put_aged(&d.join("5.json"), 26 * HOUR);
        let held = std::fs::File::options()
            .read(true)
            .share_mode(0)
            .open(&p)
            .unwrap();
        let release = thread::spawn(move || {
            thread::sleep(Duration::from_millis(300));
            drop(held);
        });
        let r = renew_at(&p, DEAD);
        release.join().unwrap();
        assert!(matches!(r, Renewal::Renewed), "{r:?}");
        assert!(!p.with_extension("claim").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// T1.9 (M4): a file dated in the future is kept until the clock reaches it.
    #[test]
    fn a_ticket_file_from_the_future_is_kept() {
        let d = claim_dir("future");
        let p = put_at(&d.join("8.json"), SystemTime::now() + HOUR);
        assert_eq!(sweep_with(&d, PENDING_TTL, DEAD, NO_LIVE), 0);
        assert!(p.exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// T1.10: a folder other users can write is never swept.
    #[test]
    fn an_unsafe_pending_folder_is_not_swept() {
        let d = claim_dir("unsafe");
        let p = put_aged(&d.join("1.json"), 26 * HOUR);
        crate::recovery::others_write(&d, true);
        assert_eq!(sweep_with(&d, PENDING_TTL, DEAD, NO_LIVE), 0);
        assert!(p.exists());
        crate::recovery::others_write(&d, false);
        assert_eq!(sweep_with(&d, PENDING_TTL, DEAD, NO_LIVE), 1);
        assert!(!p.exists());
        let _ = std::fs::remove_dir_all(&d);
    }
}
