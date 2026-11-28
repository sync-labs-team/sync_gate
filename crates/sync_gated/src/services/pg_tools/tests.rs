use super::*;
use crate::services::pg_sql::{
    clone_adopt, create_database, create_database_from, create_extensions, create_role,
    in_database, missing_extensions, template_check, template_names_free, template_own,
    template_rename_db, template_rename_role, template_seal,
};
use crate::services::testkit::{
    SCRATCH_DEPTH, Scratch, ServerGuard, free_port, pg_bin, psql_run, psql_tcp, serial,
    user_server, user_server_at,
};
use crate::supervisor::run_tool;
use std::fs;
use std::sync::MutexGuard;
use sync_gate_probe::{process_alive, start_time};

/// A cluster layout under a fresh scratch folder (`<scratch>/pg/17`); nothing below the
/// scratch folder exists yet. `bin` does not exist either: these tests must refuse before any
/// tool runs.
fn layout(tag: &str) -> (Scratch, ClusterPaths) {
    let s = Scratch::new(tag);
    let c = ClusterPaths::new(&s.join("bin"), &s.join("pg").join("17"), 40000);
    (s, c)
}

/// A registered, stopped cluster made of plain files: `PG_VERSION` and `cluster.json`.
fn registered(c: &ClusterPaths) {
    fs::create_dir_all(&c.data).unwrap();
    fs::write(c.data.join("PG_VERSION"), "17\n").unwrap();
    let rec = ClusterRecord {
        data: canonical(&c.data).unwrap(),
        bin: c.bin.clone(),
        system_identifier: 7311234567890123456,
        major: 17,
    };
    fs::write(&c.record, serde_json::to_vec(&rec).unwrap()).unwrap();
}

/// `link` becomes a directory link to `target` (Unix: symlink; Windows: junction).
fn link_dir(link: &Path, target: &Path) {
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link).unwrap();
    #[cfg(windows)]
    {
        let out = Command::new("cmd")
            .arg("/c")
            .arg("mklink")
            .arg("/J")
            .arg(link)
            .arg(target)
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
    }
    assert!(fs::symlink_metadata(link).is_ok());
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn err_of<T: std::fmt::Debug>(r: io::Result<T>) -> String {
    r.unwrap_err().to_string()
}

/// A `postmaster.pid` in the layout of PostgreSQL 17, naming `pid` started at `started`.
fn write_pidfile(c: &ClusterPaths, pid: u32, started: u64) {
    let text = format!(
        "{pid}\n{}\n{started}\n{}\n{}\n127.0.0.1\n  0         0\nready   \n",
        c.data.display(),
        c.port,
        c.sock.display()
    );
    fs::write(c.data.join("postmaster.pid"), text).unwrap();
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn parse_major_reads_real_banners() {
    assert_eq!(
        parse_major("pg_ctl (PostgreSQL) 17.12 (Debian 17.12-0+deb13u1)"),
        Some(17)
    );
    assert_eq!(parse_major("16.15 (Ubuntu 16.15-1.pgdg24.04+1)"), Some(16));
    assert_eq!(parse_major("pg_ctl (PostgreSQL) 19rc2"), Some(19));
    assert_eq!(parse_major("garbage"), None);
}

#[test]
fn parse_system_identifier_reads_controldata() {
    let text = "pg_control version number:            1700\n\
                Database system identifier:           7311234567890123456\n\
                Database cluster state:               shut down\n";
    assert_eq!(parse_system_identifier(text), Some(7311234567890123456));
    assert_eq!(parse_system_identifier("garbage"), None);
}

#[test]
fn socket_path_limit() {
    let base = std::env::temp_dir();
    let long = base.join("x".repeat(200));
    assert!(!ClusterPaths::new(&base, &long, 28543).socket_path_ok());
    assert!(ClusterPaths::new(&base, &base.join("r"), 28543).socket_path_ok());
    // PF27: the server accepts it, but `psql -h` splits the host on the comma.
    assert!(!ClusterPaths::new(&base, &base.join("a,b"), 28543).socket_path_ok());
}

#[test]
fn a_linked_data_dir_is_refused() {
    let (s, c) = layout("link-data");
    let outside = s.join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("marker"), "m").unwrap();
    fs::create_dir_all(&c.root).unwrap();
    link_dir(&c.data, &outside);
    let e = err_of(OsPgTools.init(&c, 10));
    assert!(e.contains("link"), "{e}");
    assert_eq!(entries(&outside), ["marker"]);
    assert_eq!(fs::read_to_string(outside.join("marker")).unwrap(), "m");
}

#[test]
fn a_linked_pg_dir_is_refused() {
    let (s, c) = layout("link-pg");
    let outside = s.join("outside");
    let fake = outside.join("17");
    fs::create_dir_all(fake.join("data")).unwrap();
    let record = format!(
        r#"{{"data":{:?},"bin":{:?},"system_identifier":1,"major":17}}"#,
        c.data, c.bin
    );
    let files = [
        ("data/PG_VERSION", "17\n".to_string()),
        ("cluster.json", record),
        ("leases.json", LEASES_EMPTY.to_string()),
    ];
    for (f, text) in &files {
        fs::write(fake.join(f), text).unwrap();
    }
    link_dir(&s.join("pg"), &outside);
    let e = err_of(OsPgTools.init(&c, 10));
    assert!(e.contains("link"), "{e}");
    assert_eq!(entries(&fake), ["cluster.json", "data", "leases.json"]);
    assert_eq!(entries(&fake.join("data")), ["PG_VERSION"]);
    for (f, text) in &files {
        assert_eq!(&fs::read_to_string(fake.join(f)).unwrap(), text);
    }
}

#[test]
fn a_postgresql_auto_conf_that_sets_a_parameter_is_refused() {
    let (_s, c) = layout("auto-conf");
    registered(&c);
    let auto = c.data.join("postgresql.auto.conf");
    let set = "# Do not edit this file manually!\nshared_buffers = '1GB'\n";
    fs::write(&auto, set).unwrap();
    let e = err_of(OsPgTools.init(&c, 10));
    assert!(e.contains("postgresql.auto.conf sets parameters"), "{e}");
    assert_eq!(fs::read_to_string(&auto).unwrap(), set);

    // Comments and blank lines (what `initdb` writes) pass the rule; `init` then goes on to
    // its later checks, which this layout (no binaries) cannot pass.
    let comments = "# Do not edit this file manually!\n\
                    # It will be overwritten by the ALTER SYSTEM command.\n\n  \n";
    fs::write(&auto, comments).unwrap();
    check_paths(&c).unwrap();
    let e = err_of(OsPgTools.init(&c, 10));
    assert!(!e.contains("postgresql.auto.conf"), "{e}");
    assert_eq!(fs::read_to_string(&auto).unwrap(), comments);

    fs::remove_file(&auto).unwrap();
    check_paths(&c).unwrap();
    assert!(!auto.exists());
}

#[test]
fn a_linked_socket_dir_is_refused() {
    let (s, c) = layout("link-sock");
    let outside = s.join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::create_dir_all(&c.root).unwrap();
    link_dir(&c.sock, &outside);
    let e = err_of(OsPgTools.init(&c, 10));
    assert!(e.contains("link"), "{e}");
    assert!(entries(&outside).is_empty());
    assert!(
        fs::symlink_metadata(&c.sock).is_ok(),
        "the link was removed"
    );
}

#[cfg(unix)]
#[test]
fn a_linked_config_file_in_a_stopped_cluster_is_refused() {
    let (s, c) = layout("link-conf");
    registered(&c);
    let external = s.join("external");
    fs::write(&external, "external").unwrap();
    std::os::unix::fs::symlink(&external, c.data.join("pg_hba.conf")).unwrap();
    let e = err_of(OsPgTools.init(&c, 10));
    assert!(e.contains("link"), "{e}");
    assert_eq!(fs::read_to_string(&external).unwrap(), "external");
}

#[test]
fn an_unrecorded_cluster_is_refused() {
    let (_s, c) = layout("unrecorded");
    fs::create_dir_all(&c.data).unwrap();
    fs::write(c.data.join("PG_VERSION"), "17\n").unwrap();
    let e = err_of(OsPgTools.init(&c, 10));
    assert!(e.contains("not a sync_gate cluster"), "{e}");
    assert_eq!(entries(&c.data), ["PG_VERSION"]);
    assert!(!c.record.exists());

    // A data folder that is not empty and has no PG_VERSION is not ours either.
    fs::remove_file(c.data.join("PG_VERSION")).unwrap();
    fs::write(c.data.join("other"), "x").unwrap();
    let e = err_of(OsPgTools.init(&c, 10));
    assert!(e.contains("not a sync_gate cluster"), "{e}");
    assert_eq!(entries(&c.data), ["other"]);
}

/// PF8: a `.tmp` sibling that is a link fails the operation before anything is written.
#[test]
fn a_linked_tmp_file_is_refused() {
    let (s, c) = layout("link-tmp");
    let outside = s.join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::create_dir_all(&c.root).unwrap();
    link_dir(&c.root.join("cluster.json.tmp"), &outside);
    let e = err_of(OsPgTools.init(&c, 10));
    assert!(e.contains("link"), "{e}");
    assert!(entries(&outside).is_empty());

    // Every atomic write checks its own `.tmp`, not only the listed ones.
    fs::create_dir_all(&c.data).unwrap();
    let hba = c.data.join("pg_hba.conf");
    link_dir(&c.data.join("pg_hba.conf.tmp"), &outside);
    let e = err_of(write_checked(&hba, b"x"));
    assert!(e.contains("link"), "{e}");
    assert!(!hba.exists());
    assert!(entries(&outside).is_empty());
}

#[test]
fn check_paths_covers_the_template_files() {
    for name in [
        "templates.json",
        "templates.json.tmp",
        "templates.json.unreadable",
    ] {
        let (s, c) = layout(&format!("tpl-{}", name.len()));
        registered(&c);
        let outside = s.join("outside");
        fs::create_dir_all(&outside).unwrap();
        check_paths(&c).unwrap();
        link_dir(&c.root.join(name), &outside);
        let e = err_of(check_paths(&c));
        assert!(e.contains("link"), "{name}: {e}");
    }
}

/// A cluster file or folder another user could have written is refused before it is read.
#[cfg(unix)]
#[test]
fn a_cluster_file_others_can_write_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let chmod = |p: &Path, mode| fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
    let (_s, c) = layout("open-file");
    registered(&c);
    fs::write(&c.leases, LEASES_EMPTY).unwrap();
    chmod(&c.leases, 0o666);
    let e = err_of(check_paths(&c));
    assert!(e.contains("writable by other users"), "{e}");
    chmod(&c.leases, 0o600);
    check_paths(&c).unwrap();
    // The same for a folder of the cluster.
    chmod(&c.data, 0o770);
    let e = err_of(check_paths(&c));
    assert!(e.contains("other users can change"), "{e}");
    chmod(&c.data, 0o700);
    check_paths(&c).unwrap();
}

/// A file others can change (Linux, macOS: mode 0666; Windows: Everyone may write it).
fn open_to_others(p: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(p, fs::Permissions::from_mode(0o666)).unwrap();
    }
    #[cfg(windows)]
    {
        let out = Command::new("icacls")
            .arg(p)
            .args(["/grant", "*S-1-1-0:(W)"])
            .output()
            .unwrap();
        assert!(out.status.success(), "icacls: {out:?}");
    }
}

/// C8: a cluster file others can change is refused on every system, configuration and
/// operational files alike; the cluster is left as it was.
#[test]
fn a_cluster_file_others_can_change_is_refused_everywhere() {
    for name in [
        "postgresql.conf",
        "postgresql.auto.conf",
        "pg_hba.conf",
        "postmaster.pid",
    ] {
        let (_s, c) = layout(&format!("open-{}", name.len()));
        registered(&c);
        let p = c.data.join(name);
        fs::write(&p, "").unwrap();
        check_paths(&c).unwrap();
        open_to_others(&p);
        let e = err_of(check_paths(&c));
        assert!(e.contains("writable by other users"), "{name}: {e}");
        assert_eq!(fs::read(&p).unwrap(), b"", "{name}");
        fs::remove_file(&p).unwrap();
    }
}

/// C8: a `postmaster.pid` others can change is never trusted to name a server.
#[test]
fn a_pid_file_others_can_change_names_no_server() {
    let (_s, c) = layout("open-pid");
    registered(&c);
    write_pidfile(&c, 1, 0);
    open_to_others(&c.data.join("postmaster.pid"));
    let e = running_postmaster(&c.data, &c.bin).unwrap_err();
    assert!(e.contains("writable by other users"), "{e}");
    fs::remove_file(c.data.join("postmaster.pid")).unwrap();
}

/// C8: the whole tree is judged before a start, data files included.
#[test]
fn check_tree_judges_every_file_and_folder() {
    let (_s, c) = layout("tree");
    registered(&c);
    let base = c.data.join("base");
    fs::create_dir_all(&base).unwrap();
    let x = base.join("x");
    fs::write(&x, "x").unwrap();
    check_tree(&c.root).unwrap();
    open_to_others(&x);
    let e = err_of(check_tree(&c.root));
    assert!(e.contains("writable by other users"), "{e}");
    assert_eq!(fs::read(&x).unwrap(), b"x");
}

/// C8, Windows: before a start nothing may hold a cluster file open for writing (the server is
/// stopped); a running server's own files are judged without that probe (`check_paths`).
#[cfg(windows)]
#[test]
fn check_tree_refuses_a_file_open_for_writing() {
    let (_s, c) = layout("tree-held");
    registered(&c);
    fs::create_dir_all(&c.root).unwrap();
    fs::write(&c.log, "").unwrap();
    let held = fs::OpenOptions::new().write(true).open(&c.log).unwrap();
    let e = err_of(check_tree(&c.root));
    assert!(e.contains("sharing violation"), "{e}");
    check_paths(&c).unwrap();
    write_pidfile(&c, 1, 0);
    let pid = fs::OpenOptions::new()
        .write(true)
        .open(c.data.join("postmaster.pid"))
        .unwrap();
    // Read the way a running server's file is read: no probe, so no refusal.
    let r = running_postmaster(&c.data, &c.bin);
    assert!(
        !r.as_ref().is_err_and(|e| e.contains("sharing violation")),
        "{r:?}"
    );
    drop((held, pid));
    check_tree(&c.root).unwrap();
    fs::remove_file(c.data.join("postmaster.pid")).unwrap();
}

/// 14.3: a refusal by the rules is told apart from an error of the system.
#[test]
fn a_policy_refusal_is_told_apart_from_a_system_error() {
    let (_s, c) = layout("policy");
    registered(&c);
    fs::write(&c.leases, LEASES_EMPTY).unwrap();
    assert!(write_target_refused(&c.leases).is_none());
    open_to_others(&c.leases);
    let e = write_target_refused(&c.leases).expect("refused");
    assert!(e.to_string().contains("writable by other users"), "{e}");
    assert!(is_policy_refusal(
        &write_checked(&c.leases, b"x").unwrap_err()
    ));
    assert_eq!(fs::read(&c.leases).unwrap(), LEASES_EMPTY.as_bytes());
    assert!(!is_policy_refusal(&io::Error::from_raw_os_error(32)));
    assert!(!is_policy_refusal(&io::Error::other("injected")));
    let link = c.root.join("cluster.json.tmp");
    fs::create_dir(&link).unwrap();
    assert!(is_policy_refusal(&write_target_refused(&c.record).unwrap()));
}

/// PF9: one canonical form, used by every identity comparison.
#[test]
fn one_canonical_form_for_every_comparison() {
    let s = Scratch::new("canon");
    let a = s.join("a");
    fs::create_dir_all(&a).unwrap();
    let canon = canonical(&a).unwrap();
    assert!(canon.is_absolute());
    assert!(!canon.to_string_lossy().starts_with(r"\\?\"), "{canon:?}");
    assert!(same_path(&a, &canon));
    assert!(same_path(&a, &s.join("a").join("..").join("a")));
    assert!(!same_path(&a, &s));
    assert!(!same_path(&a, &s.join("missing")));
    #[cfg(windows)]
    {
        let text = canon.to_string_lossy();
        assert!(same_path(&a, Path::new(&text.to_uppercase())));
        assert!(same_path(&a, Path::new(&text.replace('\\', "/"))));
        assert!(same_path(&a, Path::new(&format!(r"\\?\{text}"))));
    }
}

/// PF1: a pid file naming a process that is positively gone is stale, not a refusal.
#[test]
fn a_stale_pid_file_gives_none() {
    let (_s, c) = layout("stale");
    registered(&c);
    // A pid no process can have. The pid of a process that just exited will not do: on Windows
    // it stays in the process table while any handle to it is open, and it can be reused.
    let pid = u32::MAX - 1;
    assert_eq!(process_alive(pid), Some(false));
    write_pidfile(&c, pid, 1_700_000_000);
    assert_eq!(OsPgTools.server(&c), Ok(None));
    fs::remove_file(c.data.join("postmaster.pid")).unwrap();
}

/// A pid file naming a live process that is not this cluster's server (here the test process
/// itself, with its real start time) is refused, and nothing is signalled: the test lives on.
#[test]
fn a_stale_pid_file_with_a_reused_pid_is_refused() {
    let (_s, c) = layout("reused");
    registered(&c);
    let me = std::process::id();
    let started = start_time(me).unwrap();
    write_pidfile(&c, me, started);
    let r = OsPgTools.server(&c);
    assert!(r.is_err(), "{r:?}");
    let id = ServerId {
        pid: me,
        start: started,
    };
    let e = r.unwrap_err();
    assert!(
        e.contains("is not"),
        "the exe check is the one reached: {e}"
    );
    assert!(OsPgTools.stop(&c, id).is_err());
    assert_eq!(start_time(me), Some(started));
    fs::remove_file(c.data.join("postmaster.pid")).unwrap();
}

/// `sql` proves the cluster before it runs anything: no record, no `psql`.
#[test]
fn sql_without_a_cluster_record_runs_nothing() {
    let (_s, c) = layout("sql-no-record");
    let e = err_of(OsPgTools.sql(&c, "SELECT 1", &[]));
    assert!(e.starts_with("cluster record:"), "{e}");
}

#[test]
fn log_tail_reads_a_bounded_suffix_and_drops_the_cut_line() {
    let s = Scratch::new("log-tail");
    let path = s.join("server.log");
    // Over 300 KiB of lines, then one long line of two-byte characters with no newline in the
    // window, then the five known lines (blank line among them).
    let mut text = "ordinary line of filler text\n".repeat(10_000);
    let blob_at = text.len();
    text.push_str(&"\u{e9}".repeat(40_000));
    text.push('\n');
    text.push_str("a1\na2\n\na3\na4\na5\n");
    assert!(text.len() > 300 * 1024);
    // The cut falls in the middle of a two-byte character.
    assert_eq!((text.len() - LOG_TAIL_BYTES as usize - blob_at) % 2, 1);
    fs::write(&path, &text).unwrap();
    assert_eq!(log_tail(&path), "a1 | a2 | a3 | a4 | a5");
    assert_eq!(log_tail(&s.join("missing.log")), "");
    // A file shorter than the window is read from its start: nothing is dropped.
    fs::write(&path, "first\nsecond\n").unwrap();
    assert_eq!(log_tail(&path), "first | second");
}

/// Whether dropping `v` panics (a guard that finds a server possibly left running fails the test).
fn drop_panics<T>(v: T) -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(v))).is_err()
}

/// The cleanup of test folders keeps a folder that still holds a pid file, and says so with a panic.
#[test]
fn a_scratch_folder_with_a_pid_file_survives_its_drop() {
    let kept = Scratch::new("keep");
    let kept_path = kept.to_path_buf();
    fs::create_dir_all(kept.join("data")).unwrap();
    fs::write(kept.join("data").join("postmaster.pid"), "1\n").unwrap();
    let gone = Scratch::new("gone");
    let gone_path = gone.to_path_buf();
    fs::create_dir_all(gone.join("data")).unwrap();
    assert!(drop_panics(kept));
    assert!(!drop_panics(gone));
    assert!(kept_path.join("data").join("postmaster.pid").exists());
    assert!(!gone_path.exists());
    fs::remove_dir_all(&kept_path).unwrap();
}

/// A folder too deep to search, or that cannot be read, may hide a live server: keep it.
#[test]
fn a_scratch_folder_that_cannot_be_ruled_out_survives_its_drop() {
    let deep = Scratch::new("deep");
    let deep_path = deep.to_path_buf();
    let mut chain = deep_path.clone();
    for _ in 0..SCRATCH_DEPTH + 2 {
        chain.push("d");
    }
    fs::create_dir_all(&chain).unwrap();
    assert!(drop_panics(deep));
    assert!(chain.exists());
    fs::remove_dir_all(&deep_path).unwrap();
}

#[cfg(unix)]
#[test]
fn a_scratch_folder_with_an_unreadable_sub_folder_survives_its_drop() {
    use std::os::unix::fs::PermissionsExt;
    let s = Scratch::new("unreadable");
    let path = s.to_path_buf();
    let locked = path.join("locked");
    fs::create_dir_all(&locked).unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read_dir(&locked).is_ok() {
        println!("skipped: running as root");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        return;
    }
    let panicked = drop_panics(s);
    let kept = path.exists();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
    fs::remove_dir_all(&path).unwrap();
    assert!(kept && panicked);
}

/// A started sync_gate cluster. Fields drop in order: the server's guard, then the folder, then
/// the lock that keeps real-cluster tests one at a time.
struct Real {
    _guard: ServerGuard,
    c: ClusterPaths,
    id: ServerId,
    _dir: Scratch,
    _lock: MutexGuard<'static, ()>,
}

fn real(tag: &str) -> Option<Real> {
    let bin = pg_bin()?;
    let lock = serial();
    let dir = Scratch::new(tag);
    let major = OsPgTools.major_version(&bin).unwrap();
    assert!(major >= PG_MIN_MAJOR);
    let c = ClusterPaths::new(&bin, &dir.join("pg").join(major.to_string()), free_port());
    assert!(c.socket_path_ok(), "{}", c.sock.display());
    OsPgTools.init(&c, 20).unwrap();
    let guard = ServerGuard::new(&bin, &c.data);
    let id = OsPgTools.start(&c).unwrap();
    Some(Real {
        _guard: guard,
        c,
        id,
        _dir: dir,
        _lock: lock,
    })
}

fn major_of(bin: &Path) -> String {
    OsPgTools.major_version(bin).unwrap().to_string()
}

/// `psql` of the test (no preamble) as the administrator, over the cluster's socket.
fn psql_socket(c: &ClusterPaths, sql: &str) -> crate::supervisor::ToolOutput {
    psql_in(c, "postgres", sql)
}

/// `psql_socket` in the database `db`.
fn psql_in(c: &ClusterPaths, db: &str, sql: &str) -> crate::supervisor::ToolOutput {
    let mut q = tool_command(&c.bin, "psql");
    q.args(["-X", "-A", "-t", "-w", "-h"]).arg(&c.sock);
    q.args([
        "-p",
        &c.port.to_string(),
        "-U",
        "sync_gate",
        "-d",
        db,
        "-c",
        sql,
    ]);
    psql_run(q)
}

#[test]
fn real_cluster_inits_starts_answers_and_stops() {
    let Some(r) = real("cycle") else { return };
    let c = &r.c;
    let rec: ClusterRecord = serde_json::from_slice(&fs::read(&c.record).unwrap()).unwrap();
    let mut cd = tool_command(&c.bin, "pg_controldata");
    cd.arg("-D").arg(&c.data);
    let out = run_tool(cd, None, Duration::from_secs(15)).unwrap();
    assert_eq!(
        parse_system_identifier(&out.stdout),
        Some(rec.system_identifier)
    );
    assert!(same_path(&rec.data, &c.data) && same_path(&rec.bin, &c.bin));
    assert_eq!(fs::read_to_string(&c.leases).unwrap(), LEASES_EMPTY);
    assert!(OsPgTools.config_current(c, 20));
    assert!(!OsPgTools.config_current(c, 21));

    assert_eq!(OsPgTools.server(c), Ok(Some(r.id)));
    assert_eq!(OsPgTools.sql(c, "SELECT 1", &[]).unwrap(), "1\n");

    // Registered: no `initdb` (it would refuse the folder that is no longer empty), and nothing
    // is rewritten under a running server.
    let hba = c.data.join("pg_hba.conf");
    let before = fs::metadata(&hba).unwrap().modified().unwrap();
    OsPgTools.init(c, 20).unwrap();
    assert_eq!(fs::metadata(&hba).unwrap().modified().unwrap(), before);

    OsPgTools.stop(c, r.id).unwrap();
    assert_eq!(OsPgTools.server(c), Ok(None));

    // `initdb` writes a comments-only `postgresql.auto.conf`, so the run above covers that
    // case. An absent file is also accepted, and `init` does not create it.
    let auto = c.data.join("postgresql.auto.conf");
    fs::remove_file(&auto).unwrap();
    OsPgTools.init(c, 20).unwrap();
    assert!(!auto.exists());
}

/// The cluster runs in UTC whatever the host's time zone (`initdb` copies the host's into
/// `postgresql.conf`; `sync_gate.conf` comes last and overrides it).
#[test]
fn real_cluster_runs_in_utc() {
    let Some(r) = real("utc") else { return };
    let out = psql_socket(
        &r.c,
        "SELECT current_setting('timezone') || ' ' || (now()::timestamp = (now() AT TIME ZONE 'UTC'))",
    );
    assert_eq!(out.stdout.trim(), "UTC true");
}

/// Final review P1: while our server runs, the administrator connection uses the port in its
/// `postmaster.pid`, so a changed configured port does not block adoption; the changed
/// configuration is then applied by stop, init and start.
#[test]
fn a_running_server_is_adopted_after_the_configured_port_changed() {
    let Some(r) = real("port-moved") else { return };
    let b = ClusterPaths::new(&r.c.bin, &r.c.root, free_port());
    assert_ne!(b.port, r.c.port);
    assert_eq!(OsPgTools.server(&b), Ok(Some(r.id)));
    assert_eq!(OsPgTools.sql(&b, "SELECT 1", &[]).unwrap(), "1\n");
    assert!(!OsPgTools.config_current(&b, 20));
    OsPgTools.stop(&b, r.id).unwrap();
    assert_eq!(OsPgTools.server(&b), Ok(None));
    OsPgTools.init(&b, 20).unwrap();
    assert!(OsPgTools.config_current(&b, 20));
    let id = OsPgTools.start(&b).unwrap();
    let pidfile = fs::read_to_string(b.data.join("postmaster.pid")).unwrap();
    assert_eq!(pidfile.lines().nth(3), Some(b.port.to_string().as_str()));
    assert_eq!(OsPgTools.server(&b), Ok(Some(id)));
}

/// PF24: the server answers after every tool handle sync_gate had is gone.
#[test]
fn the_server_outlives_every_tool_resource() {
    let Some(r) = real("outlives") else { return };
    // `real` ran every tool through a temporary `OsPgTools`; all of it is dropped by now.
    let out = psql_socket(&r.c, "SELECT 1");
    assert_eq!(out.code, Some(0), "{}", out.stderr);
    assert_eq!(out.stdout, "1\n");
    assert_eq!(start_time(r.id.pid), Some(r.id.start));
}

#[test]
fn admin_is_refused_over_tcp() {
    let Some(r) = real("tcp") else { return };
    let out = psql_tcp(&r.c.bin, r.c.port, "sync_gate", "postgres", "SELECT 1");
    assert_ne!(out.code, Some(0));
    assert!(out.stderr.contains("rejects connection"), "{}", out.stderr);
}

#[test]
fn the_users_server_on_the_port_is_never_touched() {
    let Some(bin) = pg_bin() else { return };
    let _lock = serial();
    let dir = Scratch::new("user-port");
    let port = free_port();
    let _user = user_server(&bin, &dir.join("user"), port);
    let made = psql_tcp(&bin, port, "postgres", "postgres", "CREATE DATABASE userdb");
    assert_eq!(made.code, Some(0), "{}", made.stderr);

    let c = ClusterPaths::new(&bin, &dir.join("pg").join(major_of(&bin)), port);
    OsPgTools.init(&c, 20).unwrap();
    let _ours = ServerGuard::new(&bin, &c.data);
    let r = OsPgTools.start(&c);
    assert!(r.is_err(), "{r:?}");

    let out = psql_tcp(
        &bin,
        port,
        "postgres",
        "userdb",
        "SELECT current_database()",
    );
    assert_eq!(out.code, Some(0), "{}", out.stderr);
    assert_eq!(out.stdout, "userdb\n");
}

#[test]
fn a_forged_postmaster_pid_naming_a_real_server_is_refused() {
    let Some(bin) = pg_bin() else { return };
    let _lock = serial();
    let dir = Scratch::new("forged");
    let port = free_port();
    let _user = user_server(&bin, &dir.join("user"), port);
    let theirs = fs::read_to_string(dir.join("user").join("data").join("postmaster.pid")).unwrap();
    let mut lines = theirs.lines();
    let pid: u32 = lines.next().unwrap().parse().unwrap();
    let started: u64 = lines.nth(1).unwrap().parse().unwrap();
    let os_start = start_time(pid).unwrap();

    // Created and stopped, never started: no guard of its own (its pid file names theirs).
    let c = ClusterPaths::new(&bin, &dir.join("pg").join(major_of(&bin)), free_port());
    OsPgTools.init(&c, 20).unwrap();
    write_pidfile(&c, pid, started);
    let r = OsPgTools.server(&c);
    let e = r.clone().unwrap_err();
    if process_cmd(pid).is_some_and(|a| !a.is_empty()) {
        println!("branch: command line readable, the -D check decides");
        assert!(e.contains("serves another data folder"), "{e}");
    } else {
        println!("branch: command line unreadable here, only later checks can refuse");
        assert!(!e.is_empty(), "{r:?}");
    }
    let forged = ServerId {
        pid,
        start: os_start,
    };
    assert!(OsPgTools.stop(&c, forged).is_err());
    // The same real server with a start time 100 s off: a reused pid.
    write_pidfile(&c, pid, started + 100);
    let e = OsPgTools.server(&c).unwrap_err();
    assert!(e.contains("started at another time"), "{e}");
    fs::remove_file(c.data.join("postmaster.pid")).unwrap();

    assert_eq!(start_time(pid), Some(os_start));
    let out = psql_tcp(&bin, port, "postgres", "postgres", "SELECT 1");
    assert_eq!(out.stdout, "1\n", "{}", out.stderr);
}

#[test]
fn sync_gate_statements_never_reach_the_server_log() {
    let Some(r) = real("canary") else { return };
    let e = err_of(OsPgTools.sql(&r.c, "SELECT 'canary-x1'::int", &["canary-x1"]));
    assert!(e.contains("ERROR") && !e.contains("canary-x1"), "{e}");
    assert!(!contains(&fs::read(&r.c.log).unwrap(), b"canary-x1"));

    // Positive control: the same mistake without the preamble does reach the log.
    let out = psql_socket(&r.c, "SELECT 'canary-y2'::int");
    assert_ne!(out.code, Some(0));
    assert!(contains(&fs::read(&r.c.log).unwrap(), b"canary-y2"));
}

/// The review's sequence: no `cluster.json`, and someone else's server answers as the
/// administrator on the configured socket. `sql` must not run the script there.
#[test]
fn sql_never_runs_against_a_server_without_a_cluster_record() {
    let Some(bin) = pg_bin() else { return };
    let _lock = serial();
    let dir = Scratch::new("sql-foreign");
    let port = free_port();
    let c = ClusterPaths::new(&bin, &dir.join("pg").join(major_of(&bin)), port);
    assert!(c.socket_path_ok(), "{}", c.sock.display());
    fs::create_dir_all(&c.sock).unwrap();
    let _theirs = user_server_at(&bin, &dir.join("user"), port, "sync_gate", Some(&c.sock));
    let own = psql_socket(&c, "SELECT 1");
    assert_eq!(own.stdout, "1\n", "{}", own.stderr);

    let e = err_of(OsPgTools.sql(&c, "CREATE DATABASE fg_canary_a", &[]));
    assert!(e.starts_with("cluster record:"), "{e}");
    let n = psql_socket(
        &c,
        "SELECT count(*) FROM pg_database WHERE datname = 'fg_canary_a'",
    );
    assert_eq!(n.stdout, "0\n", "{}", n.stderr);
}

/// The in-session guard: the record names another system identifier than the running server.
#[test]
fn sql_stops_in_session_when_the_identifier_differs() {
    let Some(r) = real("sql-guard") else { return };
    let c = &r.c;
    let mut rec: ClusterRecord = serde_json::from_slice(&fs::read(&c.record).unwrap()).unwrap();
    rec.system_identifier += 1;
    fs::write(&c.record, serde_json::to_vec(&rec).unwrap()).unwrap();

    let e = err_of(OsPgTools.sql(c, "CREATE DATABASE fg_canary_b", &[]));
    assert!(e.contains("not the sync_gate cluster"), "{e}");
    let n = psql_socket(
        c,
        "SELECT count(*) FROM pg_database WHERE datname = 'fg_canary_b'",
    );
    assert_eq!(n.stdout, "0\n", "{}", n.stderr);
}

const LEASE: &str = "fg_l_00112233aabbccdd";
const OTHER: &str = "fg_l_99887766554433ff";
const TOKEN: &str = "a1b2c3d4e5f60718";
const LEASE_PW: &str = "00ff";

/// A lease role and its empty database, made by the slice 1a scripts.
fn lease(c: &ClusterPaths, name: &str) {
    let role = create_role(name, TOKEN, LEASE_PW, 5).unwrap();
    OsPgTools.sql(c, &role, &[LEASE_PW]).unwrap();
    OsPgTools
        .sql(c, &create_database(name).unwrap(), &[])
        .unwrap();
}

/// `psql` as the lease `name` in its own database, over TCP with its password: what the command
/// gets.
fn as_lease(c: &ClusterPaths, name: &str, sql: &str) -> crate::supervisor::ToolOutput {
    let mut q = tool_command(&c.bin, "psql");
    q.args(["-X", "-A", "-t", "-w", "-h", "127.0.0.1", "-p"]);
    q.args([&c.port.to_string(), "-U", name, "-d", name, "-c", sql]);
    q.env("PGPASSWORD", LEASE_PW);
    psql_run(q)
}

/// The owner of the extension `ext` in the database `db`, as `regrole` prints it.
fn ext_owner(c: &ClusterPaths, db: &str, ext: &str) -> String {
    let q = format!("SELECT extowner::regrole FROM pg_extension WHERE extname = '{ext}'");
    admin_in(c, db, &q)
}

/// A `gin_trgm_ops` index made by the lease itself; the last line printed is the user.
const TRGM_INDEX: &str =
    "CREATE TABLE t (s text); CREATE INDEX ON t USING gin (s gin_trgm_ops); SELECT current_user";

#[test]
fn pg_trgm_is_created_and_owned_by_the_lease() {
    let Some(r) = real("ext-trgm") else { return };
    let c = &r.c;
    lease(c, LEASE);
    let s = create_extensions(LEASE, &["pg_trgm".into()]).unwrap();
    OsPgTools.sql(c, &s, &[]).unwrap();
    assert_eq!(ext_owner(c, LEASE, "pg_trgm"), format!("{LEASE}\n"));
    let schema = "SELECT extnamespace::regnamespace FROM pg_extension WHERE extname = 'pg_trgm'";
    assert_eq!(admin_in(c, LEASE, schema), "public\n");
    let out = as_lease(c, LEASE, TRGM_INDEX);
    assert_eq!(out.code, Some(0), "{}", out.stderr);
    assert_eq!(out.stdout.lines().last(), Some(LEASE), "{}", out.stdout);
    // Run again: `IF NOT EXISTS` makes it a no-op.
    OsPgTools.sql(c, &s, &[]).unwrap();
    assert_eq!(ext_owner(c, LEASE, "pg_trgm"), format!("{LEASE}\n"));
}

/// `file_fdw` reads server files, so it is not trusted: a database owner may not create it.
#[test]
fn an_untrusted_extension_fails() {
    let Some(r) = real("ext-untrusted") else {
        return;
    };
    let c = &r.c;
    lease(c, LEASE);
    let s = create_extensions(LEASE, &["file_fdw".into()]).unwrap();
    let e = err_of(OsPgTools.sql(c, &s, &[]));
    assert!(
        e.contains("permission denied to create extension \"file_fdw\""),
        "{e}"
    );
    let n = "SELECT count(*) FROM pg_extension WHERE extname = 'file_fdw'";
    assert_eq!(admin_in(c, LEASE, n), "0\n");
}

/// A candidate given pg_trgm by `grant` passes S2, and the copy of its template hands the
/// extension to the copy's lease, as `promote` and the clone path of `grant` run them. The copy
/// is only checked: an extension the template lacks is reported, never created.
#[test]
fn a_template_with_pg_trgm_passes_the_check_and_its_clone_owns_it() {
    let Some(r) = real("ext-tpl") else { return };
    let c = &r.c;
    let run = |s: Result<String, crate::services::pg_sql::SqlError>| {
        OsPgTools.sql(c, &s.unwrap(), &[LEASE_PW]).unwrap()
    };
    let (ext, key) = (["pg_trgm".to_string()], "00112233aabbccdd");
    lease(c, LEASE);
    run(create_extensions(LEASE, &ext));
    assert_eq!(run(template_names_free(key)), "t\n");
    assert_eq!(run(template_seal(LEASE, TOKEN)), "t\n");
    assert_eq!(run(template_check(LEASE)), "t\n");
    run(template_own(LEASE));
    run(template_rename_role(LEASE, TOKEN, key));
    run(template_rename_db(LEASE, key));

    run(create_role(OTHER, TOKEN, LEASE_PW, 5));
    run(create_database_from(OTHER, key));
    run(clone_adopt(OTHER, key));
    assert_eq!(ext_owner(c, OTHER, "pg_trgm"), format!("{OTHER}\n"));
    assert_eq!(run(missing_extensions(OTHER, &ext)), "");
    let more = ["pg_trgm".to_string(), "citext".to_string()];
    assert_eq!(run(missing_extensions(OTHER, &more)), "citext\n");
    assert_eq!(ext_owner(c, OTHER, "citext"), "", "the check created it");
    let out = as_lease(c, OTHER, TRGM_INDEX);
    assert_eq!(out.code, Some(0), "{}", out.stderr);
    assert_eq!(out.stdout.lines().last(), Some(OTHER), "{}", out.stdout);
}

/// `psql_in` that must succeed; its output.
fn admin_in(c: &ClusterPaths, db: &str, sql: &str) -> String {
    let out = psql_in(c, db, sql);
    assert_eq!(out.code, Some(0), "{sql}: {}", out.stderr);
    out.stdout
}

fn role_exists(c: &ClusterPaths, name: &str) -> bool {
    let q = format!("SELECT count(*) FROM pg_roles WHERE rolname = '{name}'");
    admin_in(c, "postgres", &q) == "1\n"
}

#[test]
fn in_database_runs_in_the_named_database() {
    let Some(r) = real("in-db") else { return };
    lease(&r.c, LEASE);
    let s = in_database(LEASE, "SELECT pg_catalog.current_database();").unwrap();
    assert_eq!(OsPgTools.sql(&r.c, &s, &[]).unwrap(), format!("{LEASE}\n"));
}

/// Plan decision 4: a failed `\connect` stops the script; the body never runs in `postgres`.
#[test]
fn in_database_on_a_missing_database_is_an_error_and_runs_nothing() {
    let Some(r) = real("in-db-missing") else {
        return;
    };
    let s = in_database(LEASE, "CREATE ROLE fg_canary_c;").unwrap();
    let e = err_of(OsPgTools.sql(&r.c, &s, &[]));
    assert!(e.contains("does not exist"), "{e}");
    assert!(!role_exists(&r.c, "fg_canary_c"));
}

/// Every object below runs `public.fg_trap()`, which creates the role `fg_marker` as whoever
/// calls it, and then behaves like the system object it shadows.
const HOSTILE_OBJECTS: &str = "\
CREATE FUNCTION public.fg_trap() RETURNS boolean LANGUAGE plpgsql AS $$ BEGIN \
IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'fg_marker') \
THEN CREATE ROLE fg_marker; END IF; RETURN true; END $$; \
CREATE FUNCTION public.current_database() RETURNS name LANGUAGE plpgsql AS $$ BEGIN \
PERFORM public.fg_trap(); RETURN pg_catalog.current_database(); END $$; \
CREATE FUNCTION public.fg_ne(name, name) RETURNS boolean LANGUAGE plpgsql AS $$ BEGIN \
PERFORM public.fg_trap(); RETURN $1 OPERATOR(pg_catalog.<>) $2; END $$; \
CREATE OPERATOR public.<> (LEFTARG = name, RIGHTARG = name, FUNCTION = public.fg_ne); \
CREATE FUNCTION public.fg_ne(oid, oid) RETURNS boolean LANGUAGE plpgsql AS $$ BEGIN \
PERFORM public.fg_trap(); RETURN $1 OPERATOR(pg_catalog.<>) $2; END $$; \
CREATE OPERATOR public.<> (LEFTARG = oid, RIGHTARG = oid, FUNCTION = public.fg_ne);";

/// Review Focus 1 and plan decision 4: what a migration leaves in its database never runs as
/// the administrator.
#[test]
fn in_database_ignores_a_hostile_search_path() {
    let Some(r) = real("hostile") else { return };
    let c = &r.c;
    lease(c, LEASE);
    admin_in(c, LEASE, HOSTILE_OBJECTS);
    let path = format!("ALTER DATABASE \"{LEASE}\" SET search_path = public, pg_catalog");
    admin_in(c, "postgres", &path);

    let s = in_database(LEASE, "SELECT 1;").unwrap();
    assert_eq!(OsPgTools.sql(c, &s, &[]).unwrap(), "1\n");
    let check = template_check(LEASE).unwrap();
    assert_eq!(OsPgTools.sql(c, &check, &[]).unwrap(), "t\n");
    assert!(!role_exists(c, "fg_marker"));

    // Control: each trap does fire for a session of that database without the safe path.
    for q in [
        "SELECT current_database()",
        "SELECT 'a'::name <> 'b'::name",
        "SELECT 1::oid <> 2::oid",
    ] {
        admin_in(c, LEASE, q);
        assert!(role_exists(c, "fg_marker"), "{q}");
        admin_in(c, "postgres", "DROP ROLE fg_marker");
    }
}

#[test]
fn template_seal_clears_database_settings() {
    let Some(r) = real("seal") else { return };
    let c = &r.c;
    lease(c, LEASE);
    let path = format!("ALTER DATABASE \"{LEASE}\" SET search_path = public, pg_catalog");
    admin_in(c, "postgres", &path);
    let settings = format!(
        "SELECT count(*) FROM pg_db_role_setting WHERE setdatabase = \
         (SELECT oid FROM pg_database WHERE datname = '{LEASE}')"
    );
    assert_eq!(admin_in(c, "postgres", &settings), "1\n");

    // Another token's mark: refused, and nothing changes.
    let foreign = template_seal(LEASE, "ffff").unwrap();
    let e = err_of(OsPgTools.sql(c, &foreign, &[]));
    assert!(e.contains("does not carry its mark"), "{e}");
    assert_eq!(admin_in(c, "postgres", &settings), "1\n");

    let seal = template_seal(LEASE, TOKEN).unwrap();
    assert_eq!(OsPgTools.sql(c, &seal, &[]).unwrap(), "t\n");
    assert_eq!(admin_in(c, "postgres", &settings), "0\n");
    let login =
        format!("SELECT rolcanlogin, rolpassword IS NULL FROM pg_authid WHERE rolname = '{LEASE}'");
    assert_eq!(admin_in(c, "postgres", &login), "f|t\n");
}

/// Review Focus 5 and plan decision 6.
#[test]
fn template_check_accepts_only_what_the_candidate_owns() {
    let Some(r) = real("check") else { return };
    let c = &r.c;
    lease(c, LEASE);
    lease(c, OTHER);
    let script = template_check(LEASE).unwrap();
    let check = || OsPgTools.sql(c, &script, &[]).unwrap();
    admin_in(
        c,
        LEASE,
        &format!(
            "SET ROLE \"{LEASE}\"; CREATE TABLE t (id int); \
             CREATE FUNCTION f() RETURNS int LANGUAGE sql AS 'SELECT 1'; CREATE SEQUENCE s; \
             ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;"
        ),
    );
    assert_eq!(check(), "t\n");

    let cases = [
        (
            format!("CREATE POLICY p ON t TO \"{LEASE}\" USING (true)"),
            "DROP POLICY p ON t".to_string(),
        ),
        // A policy for PUBLIC, said or implied, leaves no dependency row at all.
        (
            "CREATE POLICY p ON t TO PUBLIC USING (true)".to_string(),
            "DROP POLICY p ON t".to_string(),
        ),
        (
            "CREATE POLICY p ON t USING (true)".to_string(),
            "DROP POLICY p ON t".to_string(),
        ),
        // A predefined role is pinned: its database grant leaves no dependency row either.
        (
            format!("GRANT CONNECT ON DATABASE \"{LEASE}\" TO pg_monitor"),
            format!("REVOKE CONNECT ON DATABASE \"{LEASE}\" FROM pg_monitor"),
        ),
        // So does a default privilege for one, which no copy can recreate for its own role.
        (
            format!(
                "SET ROLE \"{LEASE}\"; \
                 ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO pg_monitor"
            ),
            format!(
                "SET ROLE \"{LEASE}\"; \
                 ALTER DEFAULT PRIVILEGES REVOKE SELECT ON TABLES FROM pg_monitor"
            ),
        ),
        (
            format!("GRANT SELECT ON t TO \"{OTHER}\""),
            format!("REVOKE SELECT ON t FROM \"{OTHER}\""),
        ),
        (
            format!("GRANT CONNECT ON DATABASE \"{LEASE}\" TO \"{OTHER}\""),
            format!("REVOKE CONNECT ON DATABASE \"{LEASE}\" FROM \"{OTHER}\""),
        ),
        (
            format!("GRANT \"{LEASE}\" TO \"{OTHER}\""),
            format!("REVOKE \"{LEASE}\" FROM \"{OTHER}\""),
        ),
        // Owned by the administrator, whose ownership leaves no dependency row: only the
        // candidate's privilege can refuse it.
        (
            format!("CREATE TABLE theirs (id int); GRANT SELECT ON theirs TO \"{LEASE}\""),
            "DROP TABLE theirs".to_string(),
        ),
    ];
    for (make, undo) in &cases {
        admin_in(c, LEASE, make);
        assert_eq!(check(), "f\n", "{make}");
        admin_in(c, LEASE, undo);
        assert_eq!(check(), "t\n", "{undo}");
    }
}

#[test]
fn a_start_that_died_before_its_log_reports_what_pg_ctl_printed() {
    let s = Scratch::new("start-failure");
    let (log, out) = (s.join("server.log"), s.join("pg_ctl.out"));
    fs::write(&out, "pg_ctl: boom\n").unwrap();
    let e = start_failure(Some(1), &log, &out);
    assert!(e.contains("boom"), "{e}");
    // With a server log, the log wins and the printed text stays out.
    fs::write(&log, "LOG: the log line\n").unwrap();
    let e = start_failure(Some(1), &log, &out);
    assert!(e.contains("the log line") && !e.contains("boom"), "{e}");
}

fn twice(first: Option<i32>, second: Option<i32>, nothing: bool) -> (Option<i32>, u32, u32) {
    let (mut calls, mut noted) = (0, 0);
    let r = start_twice(
        &mut || {
            calls += 1;
            Ok(if calls == 1 { first } else { second })
        },
        &|| nothing,
        &mut |_| noted += 1,
    )
    .unwrap();
    (r, calls, noted)
}

#[test]
fn a_failed_start_that_left_nothing_is_repeated_once() {
    assert_eq!(twice(Some(1), Some(0), true), (Some(0), 2, 1));
    // Still failing: one repeat only, and the last result is reported.
    assert_eq!(twice(Some(1), Some(1), true), (Some(1), 2, 1));
}

#[test]
fn a_start_is_not_repeated_when_it_worked_or_left_a_log_or_a_server() {
    assert_eq!(twice(Some(0), Some(1), true), (Some(0), 1, 0));
    assert_eq!(twice(Some(1), Some(0), false), (Some(1), 1, 0));
}

/// Item 6: what `check_tree` costs before a start, on a real stopped cluster with 50 databases.
/// Prints folders, files and milliseconds. `cargo test -p sync_gated -- --ignored check_tree_cost`.
#[test]
#[ignore = "measures; needs SYNC_GATE_TEST_PG_BIN"]
fn check_tree_cost_with_50_databases() {
    let Some(r) = real("tree-cost") else {
        println!("skipped: no PostgreSQL");
        return;
    };
    let c = &r.c;
    for i in 0..50 {
        let mut cmd = tool_command(&c.bin, "createdb");
        cmd.arg("-h").arg(&c.sock).args(["-p", &c.port.to_string()]);
        cmd.args(["-U", ADMIN_ROLE, &format!("db{i}")]);
        let out = run_tool(cmd, None, Duration::from_secs(60)).unwrap();
        assert_eq!(out.code, Some(0), "{}", out.stderr);
    }
    OsPgTools.stop(c, r.id).unwrap();
    let (mut dirs, mut files, mut stack) = (0, 0, vec![c.root.clone()]);
    while let Some(d) = stack.pop() {
        dirs += 1;
        for e in fs::read_dir(&d).unwrap().flatten() {
            if e.file_type().unwrap().is_dir() {
                stack.push(e.path());
            } else {
                files += 1;
            }
        }
    }
    let t = std::time::Instant::now();
    check_tree(&c.root).unwrap();
    println!(
        "check_tree: {dirs} folders, {files} files, {} ms",
        t.elapsed().as_millis()
    );
}
