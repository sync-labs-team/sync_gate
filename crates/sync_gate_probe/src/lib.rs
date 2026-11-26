//! sync_gate_probe
//! Cheap, real machine measurement: memory snapshot, process-tree RSS and NVIDIA VRAM.

mod control;
mod gpu;
mod lock;
mod memory;
mod pending;
mod recovery;
mod tree;

pub use control::{
    FrozenUnit, GuestSuspension, GuestUnit, IdentKind, Suspension, TokenView, ident_kind, ident_of,
    process_alive, resume_guest_units, resume_tree, start_time, suspend_tree, suspend_tree_as,
    suspend_tree_recorded,
};
#[cfg(windows)]
pub use control::{process_ident, token_view};
pub use lock::{FileLock, LOCK_FILE, try_lock};
pub use memory::Probe;
pub use pending::{PENDING_TTL, Renewal, claim_at, renew_at, sweep_pending};
pub use recovery::{
    GUEST_PAUSED_FILE, GuestRecord, OsRecover, PAUSED_FILE, Pass, PausedRecord, Recover,
    RecoveryOutcome, create_private_dir, data_dir, guest_recovery_pass, load_paused, load_record,
    recover_as_owner, recover_as_owner_with, recovery_pass, recovery_pass_with, save_guest_record,
    save_record, still_ours, write_atomic,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// Child-process entry: re-executed by tests via `SYNC_GATE_TEST_CHILD=<mode>:<args>`.
    /// Add a mode by adding one match arm.
    #[test]
    fn child_entry() {
        let Ok(spec) = std::env::var("SYNC_GATE_TEST_CHILD") else {
            return;
        };
        let parts: Vec<&str> = spec.split(':').collect();
        match parts[0] {
            "membomb" => {
                let mib: usize = parts[1].parse().unwrap();
                let secs: u64 = parts[2].parse().unwrap();
                let mut buf = vec![0u8; mib << 20];
                for i in (0..buf.len()).step_by(4096) {
                    buf[i] = 1;
                }
                std::hint::black_box(&buf);
                std::thread::sleep(Duration::from_secs(secs));
                std::process::exit(0);
            }
            "ticker" => {
                // ticker:<file>:<ticks>; the file path may itself contain ':' (Windows drive).
                let ticks: u64 = parts[parts.len() - 1].parse().unwrap();
                let file = parts[1..parts.len() - 1].join(":");
                for n in 1..=ticks {
                    std::fs::write(&file, n.to_string()).unwrap();
                    std::thread::sleep(Duration::from_millis(50));
                }
                std::process::exit(0);
            }
            other => panic!("unknown child mode {other}"),
        }
    }

    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            // Never leave a frozen process behind when a test fails mid-way.
            let _ = resume_tree(self.0.id());
            // Fixtures have finite lifetimes; let them exit after resuming.
            let _ = self.0.wait();
        }
    }

    fn spawn_child(spec: &str) -> Child {
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "tests::child_entry",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("SYNC_GATE_TEST_CHILD", spec)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        Child(child)
    }

    #[test]
    fn snapshot_is_consistent() {
        let s = Probe::new().snapshot();
        assert!(s.total > 0);
        assert!(s.available <= s.total);
        assert!(s.available + s.reclaimable <= s.total);
    }

    #[test]
    fn tree_rss_of_self_is_positive() {
        assert!(Probe::new().tree_rss(std::process::id()) > 0);
    }

    #[test]
    fn unknown_pid_is_zero() {
        assert_eq!(Probe::new().tree_rss(u32::MAX - 1), 0);
    }

    #[test]
    fn tree_rss_includes_children() {
        let mut probe = Probe::new();
        let me = std::process::id();
        let base = probe.tree_rss(me);
        let _child = spawn_child("membomb:200:10");
        let want = 150 << 20;
        let start = Instant::now();
        let mut grown = 0;
        while start.elapsed() < Duration::from_secs(3) {
            grown = probe.tree_rss(me).saturating_sub(base);
            if grown >= want {
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        assert!(grown >= want, "tree grew only {grown} bytes");
    }

    fn table(rows: &[(u32, u32, u64)]) -> std::collections::HashMap<u32, (u32, u64)> {
        rows.iter()
            .map(|&(pid, ppid, rss)| (pid, (ppid, rss)))
            .collect()
    }

    #[test]
    fn sum_tree_survives_parent_cycle() {
        let t = table(&[(1, 2, 10), (2, 1, 20), (3, 2, 5)]);
        assert_eq!(tree::sum_tree(1, &t), 35);
    }

    #[test]
    fn sum_tree_survives_self_parented_zero() {
        let t = table(&[(0, 0, 5), (1, 0, 7)]);
        assert_eq!(tree::sum_tree(0, &t), 12);
        assert_eq!(tree::sum_tree(9, &t), 0);
    }

    #[test]
    fn tree_rss_of_pid_zero_terminates() {
        let _ = Probe::new().tree_rss(0);
    }

    #[test]
    fn descendants_orders_parents_first_and_survives_cycle() {
        let ppid: std::collections::HashMap<u32, u32> =
            [(1, 2), (2, 1), (3, 2), (4, 3)].into_iter().collect();
        assert_eq!(tree::descendants(1, &ppid), vec![1, 2, 3, 4]);
        assert!(tree::descendants(9, &ppid).is_empty());
    }

    #[test]
    fn refuses_pid_zero_and_self() {
        for pid in [0, std::process::id()] {
            assert_eq!(
                suspend_tree(pid).unwrap_err().kind(),
                std::io::ErrorKind::InvalidInput
            );
            assert_eq!(
                resume_tree(pid).unwrap_err().kind(),
                std::io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn unknown_pid_is_not_found() {
        assert_eq!(
            suspend_tree(u32::MAX - 1).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
    }

    fn read_counter(file: &std::path::Path) -> u64 {
        // The child truncates then writes; retry past an empty read.
        for _ in 0..50 {
            if let Ok(n) = std::fs::read_to_string(file).unwrap_or_default().parse() {
                return n;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        0
    }

    #[test]
    fn suspend_then_resume_keeps_process_alive() {
        let dir = std::env::temp_dir().join(format!("sync_gate-ticker-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("ticks");
        let mut child = spawn_child(&format!("ticker:{}:40", file.display()));
        let start = Instant::now();
        while read_counter(&file) == 0 {
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "ticker never started"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        suspend_tree(child.0.id()).unwrap();
        std::thread::sleep(Duration::from_millis(100)); // let an in-flight write land
        let frozen = read_counter(&file);
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(read_counter(&file), frozen, "counter moved while suspended");
        resume_tree(child.0.id()).unwrap();
        let start = Instant::now();
        while read_counter(&file) <= frozen {
            assert!(start.elapsed() < Duration::from_secs(2), "did not resume");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(child.0.wait().unwrap().success());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn child_older_than_parent_is_not_a_descendant() {
        // pid 20 claims parent 10 but started before it: 10 reused a dead parent's pid.
        let rows = [(10, 1, 100), (20, 10, 50), (30, 10, 100), (40, 10, 0)];
        let ppid = tree::links_from(&rows);
        // start_time 0 means unknown: keep the link rather than miss a real child.
        assert_eq!(tree::descendants(10, &ppid), vec![10, 30, 40]);
    }

    fn scripted(
        scans: Vec<Vec<control::Unit>>,
        fail_on: Option<control::Unit>,
    ) -> (
        std::io::Result<()>,
        Vec<(control::Unit, control::Action)>,
        usize,
    ) {
        let (mut calls, mut n) = (Vec::new(), 0);
        let res = control::suspend_with_rollback(
            1,
            &mut || {
                n += 1;
                Ok(scans[(n - 1).min(scans.len() - 1)].clone())
            },
            &mut |_| Ok(()),
            &mut |u, a| {
                calls.push((u, a));
                if Some(u) == fail_on && a == control::Action::Suspend {
                    return Err(std::io::ErrorKind::PermissionDenied.into());
                }
                Ok(())
            },
        );
        (res.map(|_| ()).map_err(|(_, e)| e), calls, n)
    }

    #[test]
    fn failure_rolls_back_what_this_call_suspended() {
        use control::Action::{Resume, Suspend};
        let (res, calls, _) = scripted(vec![vec![(1, 0), (2, 0), (3, 0)]], Some((2, 0)));
        assert_eq!(
            res.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        // 3 was never touched; 1 (the only success) is resumed; 2 never suspended so not resumed.
        assert_eq!(
            calls,
            vec![((1, 0), Suspend), ((2, 0), Suspend), ((1, 0), Resume)]
        );
    }

    #[test]
    fn failed_rollback_hands_back_what_is_still_frozen() {
        use control::Action::{Resume, Suspend};
        use std::io::ErrorKind::PermissionDenied;
        let res = control::suspend_with_rollback(
            1,
            &mut || Ok(vec![(1, 0), (2, 0), (3, 0)]),
            &mut |_| Ok(()),
            &mut |u, a| match (u.0, a) {
                (3, Suspend) | (2, Resume) => Err(PermissionDenied.into()),
                _ => Ok(()),
            },
        );
        // 3 failed to suspend; rolling back 2 failed too, so 2 is still frozen and comes back.
        let (frozen, e) = res.unwrap_err();
        assert_eq!(e.kind(), PermissionDenied);
        assert_eq!(frozen, vec![(2, 0)]);
    }

    #[test]
    fn unreached_root_rolls_back() {
        use control::Action::{Resume, Suspend};
        let (res, calls, _) = scripted(vec![vec![(2, 0)]], None);
        assert_eq!(res.unwrap_err().kind(), std::io::ErrorKind::NotFound);
        assert_eq!(calls, vec![((2, 0), Suspend), ((2, 0), Resume)]);
    }

    #[test]
    fn rescan_catches_new_units_once_and_stops_when_stable() {
        use control::Action::Suspend;
        let scans = vec![vec![(1, 0)], vec![(1, 0), (1, 7)], vec![(1, 0), (1, 7)]];
        let (res, calls, n) = scripted(scans, None);
        res.unwrap();
        assert_eq!(calls, vec![((1, 0), Suspend), ((1, 7), Suspend)]);
        assert_eq!(n, 3);
    }

    #[test]
    fn rescan_is_capped_at_three_passes() {
        let scans = vec![
            vec![(1, 0)],
            vec![(1, 0), (1, 1)],
            vec![(1, 0), (1, 1), (1, 2)],
            vec![(1, 0), (1, 1), (1, 2), (1, 3)],
        ];
        let (res, calls, n) = scripted(scans, None);
        res.unwrap();
        assert_eq!(n, 3);
        assert_eq!(calls.len(), 3);
    }

    #[test]
    fn suspension_resumes_its_units_in_reverse_and_skips_vanished() {
        use control::Action::Resume;
        let mut calls = Vec::new();
        let units = vec![(1, 0), (2, 0), (3, 0), (4, 0)];
        let res = control::resume_units(&units, &mut |u, a| {
            calls.push((u, a));
            match u.0 {
                3 => Err(std::io::ErrorKind::NotFound.into()),
                2 => Err(std::io::ErrorKind::PermissionDenied.into()),
                1 => Err(std::io::ErrorKind::Other.into()),
                _ => Ok(()),
            }
        });
        // every unit is tried, newest first; a vanished one is dropped; the first real error wins
        // and only the units that really failed are kept (in suspend order) for a retry
        let (failed, err) = res.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(failed, vec![(1, 0), (2, 0)]);
        assert_eq!(
            calls,
            vec![
                ((4, 0), Resume),
                ((3, 0), Resume),
                ((2, 0), Resume),
                ((1, 0), Resume)
            ]
        );
    }

    #[test]
    fn recorded_suspension_lists_exactly_what_was_suspended() {
        let mut n = 0;
        let scans = [vec![(1, 0), (1, 5)], vec![(1, 0), (1, 5), (9, 0)]];
        let done = control::suspend_with_rollback(
            1,
            &mut || {
                n += 1;
                Ok(scans[(n - 1).min(1)].clone())
            },
            &mut |_| Ok(()),
            &mut |u, _| {
                if u.1 == 5 {
                    Err(std::io::ErrorKind::NotFound.into())
                } else {
                    Ok(())
                }
            },
        )
        .unwrap();
        assert_eq!(done, vec![(1, 0), (9, 0)]);
    }

    /// Test 26 (K3): parentage alone never reaches a process; identity and age both have to hold.
    #[test]
    fn guest_order_keeps_only_matching_younger_processes() {
        let (r, a, o, b, v, c) = (1, 2, 3, 4, 5, 6);
        let ppids: std::collections::HashMap<u32, u32> =
            [(r, 900), (a, r), (o, r), (b, o), (v, r), (c, a)].into();
        // (matches the job's ident, creation): O is the owner's, V is older than the root.
        let info = |pid| match pid {
            1 => Some((true, 100)),
            2 => Some((true, 101)),
            3 => Some((false, 102)),
            4 => Some((true, 103)),
            5 => Some((true, 50)),
            6 => Some((true, 104)),
            _ => None,
        };
        assert_eq!(control::guest_order(r, &ppids, info), vec![r, a, c]);
        let unreadable_a = |pid| if pid == a { None } else { info(pid) };
        assert_eq!(control::guest_order(r, &ppids, unreadable_a), vec![r]);
        let foreign_root = |pid| {
            if pid == r {
                Some((false, 100))
            } else {
                info(pid)
            }
        };
        assert!(control::guest_order(r, &ppids, foreign_root).is_empty());
    }

    /// Test 34: what a token's identity is for each kind of guest, and back.
    #[test]
    fn ident_rules() {
        use IdentKind::{Account, AppContainer, Restricted};
        let view = |user: &str, restricted: &[&str], container: Option<&str>| TokenView {
            user: user.to_string(),
            restricted: restricted.iter().map(|s| s.to_string()).collect(),
            app_container: container.map(str::to_string),
        };
        let owner = "S-1-5-21-1-2-3-1001";
        let account = Account("S-1-5-21-1-2-3-1004".to_string());
        assert_eq!(
            ident_of(&account, &view("s-1-5-21-1-2-3-1004", &[], None)).as_deref(),
            Some("account:S-1-5-21-1-2-3-1004")
        );
        assert_eq!(ident_of(&account, &view(owner, &[], None)), None);

        let container = AppContainer(owner.to_string());
        assert_eq!(
            ident_of(&container, &view(owner, &[], Some("S-1-15-2-9"))).as_deref(),
            Some("appcontainer:S-1-5-21-1-2-3-1001:S-1-15-2-9")
        );
        assert_eq!(ident_of(&container, &view(owner, &[], None)), None);
        assert_eq!(
            ident_of(
                &container,
                &view("S-1-5-21-1-2-3-1004", &[], Some("S-1-15-2-9"))
            ),
            None
        );

        let restricted = Restricted(owner.to_string());
        let sids = ["S-1-1-0", "S-1-5-5-0-1", "S-1-5-21-7-7-7-7"];
        assert_eq!(
            ident_of(&restricted, &view(owner, &sids, None)).as_deref(),
            Some("restricted:S-1-5-21-1-2-3-1001:S-1-1-0,S-1-5-21-7-7-7-7,S-1-5-5-0-1")
        );
        assert_eq!(ident_of(&restricted, &view(owner, &[], None)), None);
        assert_eq!(
            ident_of(&restricted, &view(owner, &sids, Some("S-1-15-2-9"))),
            None
        );
        // F36: the `elevated` token is the sandbox account, restricted, with the owner's logon SID.
        let elevated = view(
            "S-1-5-21-1-2-3-1004",
            &["S-1-5-21-1-2-3-1004", "S-1-5-5-0-1", "S-1-1-0"],
            None,
        );
        assert_eq!(ident_of(&restricted, &elevated), None);

        for (ident, kind) in [
            ("account:S-1-5-21-1-2-3-1004", account),
            ("appcontainer:S-1-5-21-1-2-3-1001:S-1-15-2-9", container),
            (
                "restricted:S-1-5-21-1-2-3-1001:S-1-1-0,S-1-5-21-7-7-7-7,S-1-5-5-0-1",
                restricted,
            ),
        ] {
            assert_eq!(ident_kind(ident), Some(kind), "{ident}");
        }
        assert_eq!(ident_kind("x:y"), None);
    }

    /// Fix round 1, Important 1: on the owner path a failing action is an error that rolls back
    /// the earlier units, whatever its kind (only `NotFound` means "gone").
    #[test]
    fn an_owner_action_error_rolls_back_the_earlier_units() {
        use control::Action::{Resume, Suspend};
        use std::io::ErrorKind::PermissionDenied;
        let events = std::cell::RefCell::new(Vec::new());
        let res = control::suspend_with_rollback(
            1,
            &mut || Ok(vec![(1, 10), (1, 11)]),
            &mut |_| Ok(()),
            &mut |u, a| {
                events.borrow_mut().push((u, a));
                if (u, a) == ((1, 11), Suspend) {
                    Err(PermissionDenied.into())
                } else {
                    Ok(())
                }
            },
        );
        let (left, e) = res.unwrap_err();
        assert_eq!((left, e.kind()), (vec![], PermissionDenied));
        assert_eq!(
            events.into_inner(),
            vec![((1, 10), Suspend), ((1, 11), Suspend), ((1, 10), Resume)]
        );
    }

    /// Fix round 1, Important 2: a thread that cannot be opened for a reason other than "gone"
    /// fails the pause and rolls back; a gone one is skipped.
    #[test]
    fn an_unexpected_thread_open_error_fails_the_pause() {
        use control::Action::{Resume, Suspend};
        use control::{Unit, retain_openable};
        use std::io::ErrorKind::{NotFound, PermissionDenied};
        let open = |u: Unit| match u.0 {
            2 => Err(PermissionDenied.into()),
            3 => Err(NotFound.into()),
            _ => Ok(()),
        };
        // Control: a gone thread is skipped, the others are kept.
        assert_eq!(
            retain_openable(vec![(1, 10), (3, 30), (1, 11)], &mut { open }).unwrap(),
            vec![(1, 10), (1, 11)]
        );
        let events = std::cell::RefCell::new(Vec::new());
        let mut scans = 0;
        let res = control::suspend_with_rollback(
            1,
            &mut || {
                scans += 1;
                if scans == 1 {
                    retain_openable(vec![(1, 10)], &mut { open })
                } else {
                    retain_openable(vec![(1, 10), (2, 20)], &mut { open })
                }
            },
            &mut |_| Ok(()),
            &mut |u, a| {
                events.borrow_mut().push((u, a));
                Ok(())
            },
        );
        let (left, e) = res.unwrap_err();
        assert_eq!((left, e.kind()), (vec![], PermissionDenied));
        assert_eq!(
            events.into_inner(),
            vec![((1, 10), Suspend), ((1, 10), Resume)]
        );
    }

    /// Fix round 1, Important 3: recovery drops a unit only when its process is gone or another;
    /// one that could not be verified stays in the record.
    #[test]
    fn recovery_keeps_a_unit_it_could_not_verify() {
        use control::{GuestUnit, check_recorded, unsettled};
        use std::io::ErrorKind::{NotFound, PermissionDenied};
        let ident = "account:S-1-5-21-1-2-3-1004";
        let unit = |pid: u32, ident: &str| GuestUnit {
            pid,
            tid: pid + 1,
            created: 500,
            ident: ident.to_string(),
        };
        // pid 1 verifies; 2 cannot be checked; 3 is gone; 4 has another ident; 5 another
        // creation time; 6 has a malformed ident.
        let query = |u: &GuestUnit| -> std::io::Result<Option<(String, u64)>> {
            match u.pid {
                1 => Ok(Some((ident.to_string(), 500))),
                2 => Err(PermissionDenied.into()),
                3 => Ok(None),
                4 => Ok(Some(("account:S-1-5-18".to_string(), 500))),
                _ => Ok(Some((ident.to_string(), 501))),
            }
        };
        let units: Vec<GuestUnit> = (1..=6)
            .map(|p| unit(p, if p == 6 { "x:y" } else { ident }))
            .collect();
        assert!(check_recorded(&units[0], |_| query(&units[0])).is_ok());
        assert_eq!(
            check_recorded(&units[1], |_| query(&units[1]))
                .unwrap_err()
                .kind(),
            PermissionDenied
        );
        for u in &units[2..] {
            let e = check_recorded(u, |_| query(u)).unwrap_err();
            assert_eq!(e.kind(), NotFound, "{u:?}");
        }
        let left = unsettled(units.clone(), |u| check_recorded(u, |_| query(u)));
        assert_eq!(left, vec![units[1].clone()]);
    }

    /// Test 35 (D2, E3): each batch is planned before any of its units is suspended.
    #[test]
    fn write_ahead_plans_each_batch_before_suspending() {
        use control::Action::{Resume, Suspend};
        use control::{Action, Unit};
        use std::io::ErrorKind::{Other, PermissionDenied, StorageFull};
        #[derive(Debug, PartialEq)]
        enum Ev {
            Plan(Vec<Unit>),
            Act(Unit, Action),
        }
        type Run = Result<Vec<Unit>, (Vec<Unit>, std::io::Error)>;
        // Two passes: (1,10) and (1,11), then (2,20) as well. `plan_fails` is the failing call (1-based).
        let run = |plan_fails: usize, act_fails: &[(Unit, Action)]| -> (Run, Vec<Ev>) {
            let events = std::cell::RefCell::new(Vec::new());
            let (mut scans, mut plans) = (0, 0);
            let res = control::suspend_with_rollback(
                1,
                &mut || {
                    scans += 1;
                    Ok(if scans == 1 {
                        vec![(1, 10), (1, 11)]
                    } else {
                        vec![(1, 10), (1, 11), (2, 20)]
                    })
                },
                &mut |batch| {
                    plans += 1;
                    events.borrow_mut().push(Ev::Plan(batch.to_vec()));
                    if plans == plan_fails {
                        return Err(StorageFull.into());
                    }
                    Ok(())
                },
                &mut |u, a| {
                    events.borrow_mut().push(Ev::Act(u, a));
                    match act_fails.contains(&(u, a)) {
                        true if a == Suspend => Err(PermissionDenied.into()),
                        true => Err(Other.into()),
                        false => Ok(()),
                    }
                },
            );
            (res, events.into_inner())
        };

        let (res, events) = run(0, &[]);
        assert_eq!(res.unwrap(), vec![(1, 10), (1, 11), (2, 20)]);
        assert_eq!(
            events,
            vec![
                Ev::Plan(vec![(1, 10), (1, 11)]),
                Ev::Act((1, 10), Suspend),
                Ev::Act((1, 11), Suspend),
                Ev::Plan(vec![(2, 20)]),
                Ev::Act((2, 20), Suspend),
            ]
        );

        // The second plan fails: its batch is never suspended, the first one is resumed.
        let (res, events) = run(2, &[]);
        let (left, e) = res.unwrap_err();
        assert_eq!((left, e.kind()), (vec![], StorageFull));
        assert_eq!(
            events,
            vec![
                Ev::Plan(vec![(1, 10), (1, 11)]),
                Ev::Act((1, 10), Suspend),
                Ev::Act((1, 11), Suspend),
                Ev::Plan(vec![(2, 20)]),
                Ev::Act((1, 11), Resume),
                Ev::Act((1, 10), Resume),
            ]
        );

        // E3: suspending (1,11) fails and so does resuming (1,10): what stays frozen comes back.
        let (res, _) = run(0, &[((1, 11), Suspend), ((1, 10), Resume)]);
        let (left, e) = res.unwrap_err();
        assert_eq!((left, e.kind()), (vec![(1, 10)], PermissionDenied));
    }

    #[test]
    fn process_alive_answers_only_from_a_real_read() {
        assert_eq!(process_alive(std::process::id()), Some(true));
        assert_eq!(process_alive(u32::MAX - 1), Some(false));
    }

    #[test]
    fn start_time_of_self_is_known_and_dead_pid_is_none() {
        assert!(start_time(std::process::id()).is_some_and(|t| t > 0));
        assert_eq!(start_time(u32::MAX - 1), None);
    }

    #[test]
    fn suspension_roundtrips_its_units() {
        let u = vec![FrozenUnit {
            pid: 7,
            tid: 8,
            start_time: 9,
        }];
        assert_eq!(Suspension::from_units(u.clone()).units(), u.as_slice());
    }

    #[cfg(feature = "nvidia")]
    #[test]
    fn vram_is_none_or_consistent() {
        if let Some(v) = gpu::vram() {
            assert!(v.used <= v.total);
        }
    }
}
