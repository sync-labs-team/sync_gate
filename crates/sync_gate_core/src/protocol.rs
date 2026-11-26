//! Wire protocol between the `sync_gate` CLI and the `sync_gated` daemon: one JSON object per line.

use crate::{MachineSnapshot, TicketId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Request {
    Acquire {
        argv: Vec<String>,
        cwd: PathBuf,
        session: String,
        heavy: bool,
    },
    Started {
        id: TicketId,
        pid: u32,
    },
    Finished {
        id: TicketId,
        peak_rss: u64,
        exit_code: Option<i32>,
    },
    /// Blocks (the connection stays open) until the ticket is admitted, for at most
    /// `min(timeout_secs, max_wait_secs)`; on expiry the reply is `Queued` and the ticket goes dormant.
    Wait {
        id: TicketId,
        timeout_secs: Option<u64>,
    },
    Cancel {
        id: TicketId,
    },
    Status,
    /// A database lease for the command about to run. `holder` is the CLI; `request` is chosen by the
    /// CLI (`[0-9a-f-]{1,64}`, unique per attempt, not a secret). Absent or empty = an older CLI: the
    /// request works but cannot be given up. `template` is the key of the project's migrated
    /// files (`None` for a project without `migrate`, and from an older CLI). `extensions` is the
    /// project's list as the CLI read it (empty from an older CLI); the daemon refuses a list
    /// other than its own.
    Lease {
        service: String,
        project: PathBuf,
        holder: Holder,
        #[serde(default)]
        request: String,
        #[serde(default)]
        template: Option<String>,
        #[serde(default)]
        extensions: Vec<String>,
    },
    /// The `migrate` authorised by `Prepare` on candidate `lease` ended: `ok` = exit code 0.
    TemplateReady {
        lease: String,
        ok: bool,
        /// The CLI was interrupted (Ctrl+C) while the `migrate` ran: not a failure of the key.
        #[serde(default)]
        interrupted: bool,
    },
    /// The process of the command that now owns the lease.
    LeaseHolder {
        lease: String,
        holder: Holder,
    },
    ReleaseLease {
        lease: String,
    },
    /// The CLI stopped waiting for request `request`; the answer is always `Ack`.
    LeaseGiveUp {
        request: String,
    },
}

/// A process identified by pid and start time (`None` = start time unreadable).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Holder {
    pub pid: u32,
    pub start: Option<u64>,
}

/// A value that never shows up in `Debug` output; only the wire carries it.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: String) -> Secret {
        Secret(s)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***)")
    }
}

/// Name of the shared PostgreSQL service in `Request::Lease` and in the status rows.
pub const SERVICE_POSTGRES: &str = "postgres";

// `Status` grew past the lint's threshold with both `mcp` and `daemon`; a Response lives for one
// IPC reply, so boxing it would only add an allocation and churn at every match.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Response {
    /// Deliberately carries no command: the CLI runs only what it stored locally, never what a daemon says.
    Admitted {
        id: TicketId,
    },
    Queued {
        id: TicketId,
        position: usize,
    },
    Ack,
    /// A lease was granted; `env` holds the variables to inject (secrets, in memory only).
    /// `template` is the key the database was copied from (`None`: an empty database).
    Leased {
        lease: String,
        env: BTreeMap<String, Secret>,
        #[serde(default)]
        template: Option<String>,
        /// The extension list the daemon used; an older daemon sends none.
        #[serde(default)]
        extensions: Vec<String>,
    },
    /// An empty candidate database whose only use is running the project's `migrate`, then
    /// `TemplateReady`.
    Prepare {
        lease: String,
        env: BTreeMap<String, Secret>,
        /// The extension list the daemon used; an older daemon sends none.
        #[serde(default)]
        extensions: Vec<String>,
    },
    Status(StatusReport),
    Error {
        message: String,
    },
}

/// Part of the daemon's `Error` for a `Wait` on a ticket it does not hold (cancelled, expired,
/// or lost in a daemon restart); the CLI then queues the stored command again.
pub const ERR_UNKNOWN_TICKET: &str = "was cancelled or is unknown";
/// A claimed admission can only be released with `Finished`.
pub const ERR_ADMITTED: &str = "already admitted";
/// Part of the daemon's `Error` for a `Wait` on a ticket already handed to another client.
pub const ERR_CLAIMED: &str = "was admitted to another client";
/// Part of the daemon's reply when a guest account already has its one queued command.
pub const ERR_BUSY: &str = "queue is busy for this account";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusReport {
    pub snapshot: MachineSnapshot,
    /// (id, command, peak tree RSS seen so far, in bytes)
    pub running: Vec<(TicketId, String, u64)>,
    /// (id, command, queue position)
    pub queued: Vec<(TicketId, String, usize)>,
    pub paused: Vec<TicketId>,
    pub decisions: Vec<String>,
    /// One row per configured MCP server.
    #[serde(default)]
    pub mcp: Vec<McpStatus>,
    /// Who answered; absent (all zero) from a daemon that predates it.
    #[serde(default)]
    pub daemon: DaemonInfo,
    /// One row per background service (shared PostgreSQL); absent from an older daemon.
    #[serde(default)]
    pub services: Vec<ServiceStatus>,
}

/// View of one daemon-owned service. Carries no secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub service: String,
    pub state: String,
    pub leases: u32,
    pub unknown_holders: u32,
    pub cleanup_pending: u32,
    pub rss: u64,
    pub restarts: u32,
    /// `tick` passes that examined the holders.
    pub checks: u64,
}

/// The daemon's identity and the data dir it really uses: the CLI recovers from that dir.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonInfo {
    pub pid: u32,
    /// Process start time (seconds since the epoch); 0 when unknown.
    pub start_time: u64,
    /// `None`: the daemon keeps no files (no paused record, no instance lock).
    pub data_dir: Option<PathBuf>,
}

/// MCP hub view of one configured server, summed over its running instances.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpStatus {
    pub server: String,
    /// `shared` or `per-session`.
    pub mode: String,
    /// Child processes running now.
    pub instances: u32,
    pub clients: u32,
    pub in_flight: u32,
    /// Tree RSS of the children in bytes, from the last daemon tick; 0 = no data.
    pub rss: u64,
    pub restarts: u32,
}

/// First line a relay sends on the hub socket. `env` holds the `env_from` values: secrets that
/// live only in memory, so this type deliberately has no `Debug`.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct HubHello {
    pub server: String,
    pub cwd: PathBuf,
    pub env: BTreeMap<String, String>,
    /// Free-form client label (e.g. the agent name); informational only.
    pub client: String,
    /// The relay's own resolution of the command (absolute), for a bare name; `None` from an
    /// older relay, or when it found none.
    #[serde(default)]
    pub program: Option<PathBuf>,
}

/// The hub's one-line answer to a [`HubHello`]. After `Ok` the connection carries MCP lines.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HubReply {
    Ok,
    /// The server is `per-session`: the relay starts it itself.
    PerSession,
    /// No such server in the daemon's config.
    Unknown,
    Error {
        message: String,
    },
}

/// Keeps only `[A-Za-z0-9_-]` so the name is safe as a pipe name or file name.
pub fn sanitize_user(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect()
}

/// `SYNC_GATE_SOCKET` when set and not empty, else the per-user default: a namespaced pipe name
/// on Windows; on Unix a path, in the first folder only this user can change (see `socket_path`).
pub fn socket_name() -> String {
    socket_name_from(std::env::var("SYNC_GATE_SOCKET").ok(), default_socket_name)
}

/// Pure core of `socket_name`: an empty override counts as none.
fn socket_name_from(over: Option<String>, default: impl FnOnce() -> String) -> String {
    over.filter(|s| !s.is_empty()).unwrap_or_else(default)
}

fn default_socket_name() -> String {
    let var = if cfg!(windows) { "USERNAME" } else { "USER" };
    let user = std::env::var(var)
        .map(|u| sanitize_user(&u))
        .unwrap_or_default();
    let user = if user.is_empty() {
        "user".to_string()
    } else {
        user
    };
    #[cfg(windows)]
    return format!("sync_gate-{user}");
    #[cfg(unix)]
    {
        let env = |k| {
            std::env::var_os(k)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        };
        socket_path(
            [env("XDG_RUNTIME_DIR"), env("TMPDIR")],
            crate::config::data_dir(),
            &format!("sync_gate-{user}.sock"),
        )
    }
}

/// Longest socket path we accept, measured on `<path>-mcp` (`sun_path` holds 104 on macOS and
/// 108 on Linux, `unix(7)`; the macOS figure was not read at the source).
#[cfg(unix)]
const MAX_SOCKET_PATH: usize = 100;

/// First of `$XDG_RUNTIME_DIR`, `$TMPDIR` that is private and short enough; else the data folder
/// when it is missing or ours (the daemon creates and tightens it before `bind`); else `/tmp`,
/// the last resort, where another user can still pre-create the socket and keep the daemon from
/// starting (the CLI stays safe and fails open).
#[cfg(unix)]
fn socket_path(runtime: [Option<PathBuf>; 2], data: Option<PathBuf>, file: &str) -> String {
    use crate::private_dir::{DirState, check_private_dir};
    // The string returned is the one measured; a path that is not UTF-8 is skipped, never rewritten.
    let candidate = |d: &std::path::Path, ok: &[DirState]| {
        let p = d.join(file).into_os_string().into_string().ok()?;
        (p.len() + 4 <= MAX_SOCKET_PATH && check_private_dir(d).is_ok_and(|s| ok.contains(&s)))
            .then_some(p)
    };
    for d in runtime.iter().flatten() {
        if let Some(p) = candidate(d, &[DirState::Private]) {
            return p;
        }
    }
    let any = [
        DirState::Missing,
        DirState::Private,
        DirState::OthersCanRead,
    ];
    if let Some(p) = data.and_then(|d| candidate(&d, &any)) {
        return p;
    }
    format!("/tmp/{file}")
}

/// Socket of the daemon's MCP hub: the control socket name plus `-mcp`.
pub fn hub_socket_name() -> String {
    format!("{}-mcp", socket_name())
}

/// `<name>-guest-<account>`, the account sanitized (`sanitize_user`) and lowercased.
pub fn guest_socket_name(name: &str, account: &str) -> String {
    format!("{name}-guest-{}", sanitize_user(account).to_lowercase())
}

/// `<name>-sbx-appcontainer` or `<name>-sbx-restricted` (the two reserved entries). Account names
/// cannot contain '@', so no account pipe can take these names.
pub fn sandbox_socket_name(name: &str, entry: &str) -> String {
    format!(
        "{name}-sbx-{}",
        sanitize_user(entry.trim_start_matches('@'))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MachineSnapshot, VramSnapshot};
    use std::path::PathBuf;

    /// Absolute on every platform: `/r/api` is relative on Windows.
    fn abs(rest: &str) -> PathBuf {
        PathBuf::from(format!("{}{rest}", if cfg!(windows) { "C:" } else { "" }))
    }

    fn roundtrip<T>(v: T)
    where
        T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let line = serde_json::to_string(&v).unwrap();
        assert!(!line.contains('\n'), "wire format is one line");
        assert_eq!(serde_json::from_str::<T>(&line).unwrap(), v);
    }

    fn report() -> StatusReport {
        StatusReport {
            snapshot: MachineSnapshot {
                total: 16,
                available: 8,
                reclaimable: 2,
                swap_used: 1,
                swap_total: 4,
                vram: Some(VramSnapshot { total: 8, used: 3 }),
            },
            running: vec![(1, "cargo build".into(), 1024)],
            queued: vec![(2, "next build".into(), 1)],
            paused: vec![3],
            decisions: vec!["admitted 1".into()],
            mcp: vec![McpStatus {
                server: "docs".into(),
                mode: "shared".into(),
                instances: 1,
                clients: 2,
                in_flight: 3,
                rss: 4,
                restarts: 5,
            }],
            daemon: DaemonInfo {
                pid: 42,
                start_time: 1_700_000_000,
                data_dir: Some(PathBuf::from("/home/u/.local/share/sync_gate")),
            },
            services: Vec::new(),
        }
    }

    #[test]
    fn a_status_from_a_daemon_without_identity_still_parses() {
        let mut old = serde_json::to_value(report()).unwrap();
        old.as_object_mut().unwrap().remove("daemon");
        let back: StatusReport = serde_json::from_value(old).unwrap();
        assert_eq!(back.daemon, DaemonInfo::default());
        assert_eq!(
            DaemonInfo::default(),
            DaemonInfo {
                pid: 0,
                start_time: 0,
                data_dir: None
            }
        );
    }

    #[test]
    fn every_request_roundtrips() {
        roundtrip(Request::Acquire {
            argv: vec!["cargo".into(), "build".into()],
            cwd: PathBuf::from("/tmp/x"),
            session: "s1".into(),
            heavy: true,
        });
        roundtrip(Request::Started { id: 7, pid: 4242 });
        roundtrip(Request::Finished {
            id: 7,
            peak_rss: 99,
            exit_code: Some(1),
        });
        roundtrip(Request::Finished {
            id: 7,
            peak_rss: 99,
            exit_code: None,
        });
        roundtrip(Request::Wait {
            id: 7,
            timeout_secs: None,
        });
        roundtrip(Request::Wait {
            id: 7,
            timeout_secs: Some(3),
        });
        roundtrip(Request::Cancel { id: 7 });
        roundtrip(Request::Status);
    }

    #[test]
    fn every_response_roundtrips() {
        roundtrip(Response::Admitted { id: 1 });
        roundtrip(Response::Queued { id: 2, position: 3 });
        roundtrip(Response::Ack);
        roundtrip(Response::Status(report()));
        roundtrip(Response::Error {
            message: "boom".into(),
        });
    }

    #[test]
    fn status_without_mcp_still_parses() {
        let mut v = serde_json::to_value(report()).unwrap();
        v.as_object_mut().unwrap().remove("mcp");
        let r: StatusReport = serde_json::from_value(v).unwrap();
        assert!(r.mcp.is_empty());
    }

    #[test]
    fn hub_messages_roundtrip() {
        let hello = HubHello {
            server: "docs".into(),
            cwd: PathBuf::from("/r/a"),
            env: BTreeMap::from([("TOKEN".to_string(), "x".to_string())]),
            client: "claude".into(),
            program: Some(PathBuf::from("/usr/bin/docs-mcp")),
        };
        let line = serde_json::to_string(&hello).unwrap();
        assert!(serde_json::from_str::<HubHello>(&line).unwrap() == hello);
        for r in [
            HubReply::Ok,
            HubReply::PerSession,
            HubReply::Unknown,
            HubReply::Error {
                message: "no".into(),
            },
        ] {
            roundtrip(r);
        }
        assert_eq!(hub_socket_name(), format!("{}-mcp", socket_name()));
    }

    #[test]
    fn secret_never_prints() {
        let r = Response::Leased {
            lease: "fg_l_00112233aabbccdd".into(),
            env: BTreeMap::from([("PGPASSWORD".into(), Secret::new("s3cr3t-canary".into()))]),
            template: None,
            extensions: vec![],
        };
        assert!(!format!("{r:?}").contains("s3cr3t-canary"));
        assert!(format!("{r:?}").contains("Secret(***)"));
        // only the wire carries it
        assert!(serde_json::to_string(&r).unwrap().contains("s3cr3t-canary"));
        assert_eq!(Secret::new("a".into()).expose(), "a");
        let p = Response::Prepare {
            lease: "fg_l_00112233aabbccdd".into(),
            env: BTreeMap::from([("PGPASSWORD".into(), Secret::new("s3cr3t-canary".into()))]),
            extensions: vec![],
        };
        assert!(!format!("{p:?}").contains("s3cr3t-canary"));
        assert!(format!("{p:?}").contains("Secret(***)"));
        assert!(serde_json::to_string(&p).unwrap().contains("s3cr3t-canary"));
    }

    #[test]
    fn lease_messages_roundtrip() {
        for start in [Some(1_700_000_000), None] {
            for template in [None, Some("0123456789abcdef".to_string())] {
                for extensions in [vec![], vec!["pg_trgm".into(), "uuid-ossp".into()]] {
                    roundtrip(Request::Lease {
                        service: SERVICE_POSTGRES.into(),
                        project: abs("/r/api"),
                        holder: Holder { pid: 42, start },
                        request: "2a-65f1c2a0-17a3b9c4d5e6f7".into(),
                        template: template.clone(),
                        extensions,
                    });
                }
            }
        }
        for (ok, interrupted) in [(true, false), (false, false), (false, true)] {
            roundtrip(Request::TemplateReady {
                lease: "fg_l_00112233aabbccdd".into(),
                ok,
                interrupted,
            });
        }
        roundtrip(Response::Prepare {
            lease: "fg_l_00112233aabbccdd".into(),
            env: BTreeMap::from([("DATABASE_URL".into(), Secret::new("postgres://x".into()))]),
            extensions: vec!["citext".into()],
        });
        roundtrip(Response::Leased {
            lease: "fg_l_00112233aabbccdd".into(),
            env: BTreeMap::from([("DATABASE_URL".into(), Secret::new("postgres://x".into()))]),
            template: Some("0123456789abcdef".into()),
            extensions: vec!["citext".into(), "pg_trgm".into()],
        });
        roundtrip(Request::LeaseHolder {
            lease: "fg_l_00112233aabbccdd".into(),
            holder: Holder {
                pid: 43,
                start: Some(9),
            },
        });
        roundtrip(Request::ReleaseLease {
            lease: "fg_l_00112233aabbccdd".into(),
        });
        roundtrip(Request::LeaseGiveUp {
            request: "2a-0-1".into(),
        });
        roundtrip(Response::Leased {
            lease: "fg_l_00112233aabbccdd".into(),
            env: BTreeMap::from([("DATABASE_URL".into(), Secret::new("postgres://x".into()))]),
            template: None,
            extensions: vec![],
        });
    }

    #[test]
    fn a_lease_without_a_request_id_still_parses() {
        let project = serde_json::to_string(&abs("/r/api")).unwrap();
        let old = format!(
            r#"{{"Lease":{{"service":"postgres","project":{project},"holder":{{"pid":1,"start":null}}}}}}"#
        );
        match serde_json::from_str::<Request>(&old).unwrap() {
            Request::Lease { request, .. } => assert!(request.is_empty()),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_lease_without_a_template_still_parses() {
        let project = serde_json::to_string(&abs("/r/api")).unwrap();
        let old = format!(
            r#"{{"Lease":{{"service":"postgres","project":{project},"holder":{{"pid":1,"start":null}},"request":"1a-0-1"}}}}"#
        );
        match serde_json::from_str::<Request>(&old).unwrap() {
            Request::Lease {
                request, template, ..
            } => assert_eq!((request.as_str(), template), ("1a-0-1", None)),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_lease_without_extensions_still_parses() {
        let project = serde_json::to_string(&abs("/r/api")).unwrap();
        let old = format!(
            r#"{{"Lease":{{"service":"postgres","project":{project},"holder":{{"pid":1,"start":null}},"request":"1a-0-1","template":"0123456789abcdef"}}}}"#
        );
        match serde_json::from_str::<Request>(&old).unwrap() {
            Request::Lease {
                template,
                extensions,
                ..
            } => {
                assert_eq!(template.as_deref(), Some("0123456789abcdef"));
                assert!(extensions.is_empty());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn template_ready_without_interrupted_still_parses() {
        let old = r#"{"TemplateReady":{"lease":"fg_l_00112233aabbccdd","ok":false}}"#;
        match serde_json::from_str::<Request>(old).unwrap() {
            Request::TemplateReady {
                ok, interrupted, ..
            } => assert_eq!((ok, interrupted), (false, false)),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_leased_without_a_template_still_parses() {
        let old = r#"{"Leased":{"lease":"fg_l_00112233aabbccdd","env":{"PGPORT":"28543"}}}"#;
        match serde_json::from_str::<Response>(old).unwrap() {
            Response::Leased {
                lease,
                env,
                template,
                extensions,
            } => {
                assert_eq!(lease, "fg_l_00112233aabbccdd");
                assert_eq!(env["PGPORT"].expose(), "28543");
                assert_eq!(template, None);
                assert!(extensions.is_empty());
            }
            other => panic!("{other:?}"),
        }
        let old = r#"{"Prepare":{"lease":"fg_l_00112233aabbccdd","env":{}}}"#;
        match serde_json::from_str::<Response>(old).unwrap() {
            Response::Prepare { extensions, .. } => assert!(extensions.is_empty()),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn status_without_services_still_parses() {
        let mut v = serde_json::to_value(report()).unwrap();
        v.as_object_mut().unwrap().remove("services");
        let r: StatusReport = serde_json::from_value(v).unwrap();
        assert!(r.services.is_empty());
    }

    #[test]
    fn service_status_roundtrips_in_a_report() {
        let mut r = report();
        r.services.push(ServiceStatus {
            service: SERVICE_POSTGRES.into(),
            state: "running".into(),
            leases: 2,
            unknown_holders: 1,
            cleanup_pending: 0,
            rss: 1024,
            restarts: 0,
            checks: 7,
        });
        roundtrip(Response::Status(r));
    }

    #[cfg(unix)]
    #[test]
    fn socket_path_skips_unusable_dirs() {
        use crate::private_dir::Scratch;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::PermissionsExt;
        let f = "sync_gate-u.sock";
        let s = Scratch::new("sock");
        let good = s.dir("good", 0o700);
        let path = |d: &PathBuf| d.join(f).to_string_lossy().into_owned();
        let none = || [None, None];
        // 1. the first private runtime folder wins
        assert_eq!(
            socket_path([Some(good.clone()), None], None, f),
            path(&good)
        );
        // 2. a 1777 runtime folder is skipped; the missing data folder is used
        let open = s.dir("open", 0o1777);
        let data = s.0.join("dados-inexistente");
        assert_eq!(
            socket_path([None, Some(open)], Some(data.clone()), f),
            path(&data)
        );
        // 3. missing first, private second
        assert_eq!(
            socket_path([Some(s.0.join("nope")), Some(good.clone())], None, f),
            path(&good)
        );
        // 4. a 0770 first folder passes to the next
        let grp = s.dir("grp", 0o770);
        assert_eq!(
            socket_path([Some(grp), Some(good.clone())], None, f),
            path(&good)
        );
        // 5. a 0777 data folder falls to /tmp
        let wide = s.dir("wide", 0o700);
        std::fs::set_permissions(&wide, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(socket_path(none(), Some(wide), f), format!("/tmp/{f}"));
        // 6. a data path too long for sun_path falls to /tmp
        let long = s.0.join("x".repeat(120));
        assert_eq!(socket_path(none(), Some(long), f), format!("/tmp/{f}"));
        // a non-UTF-8 folder is skipped, never rewritten with U+FFFD
        let bad = good.join(std::ffi::OsStr::from_bytes(b"\xff"));
        std::fs::create_dir(&bad).unwrap();
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(socket_path([Some(bad), None], None, f), format!("/tmp/{f}"));
        // 7. nothing at all
        assert_eq!(socket_path(none(), None, f), format!("/tmp/{f}"));
    }

    #[test]
    fn pipe_names_per_kind() {
        assert_eq!(
            guest_socket_name("sync_gate-alice", "CodexSandboxOffline"),
            "sync_gate-alice-guest-codexsandboxoffline"
        );
        assert_eq!(guest_socket_name("x", "a\\b c"), "x-guest-abc");
        assert_eq!(
            sandbox_socket_name("sync_gate-alice", "@appcontainer"),
            "sync_gate-alice-sbx-appcontainer"
        );
        assert_eq!(
            sandbox_socket_name("sync_gate-alice", "@restricted"),
            "sync_gate-alice-sbx-restricted"
        );
    }

    #[test]
    fn socket_name_from_ignores_an_empty_override() {
        let d = || "dflt".to_string();
        assert_eq!(socket_name_from(Some("x".into()), d), "x");
        assert_eq!(socket_name_from(Some(String::new()), d), "dflt");
        assert_eq!(socket_name_from(None, d), "dflt");
    }

    #[test]
    fn socket_name_is_per_user_and_sanitized() {
        let n = socket_name();
        assert!(n.contains("sync_gate-"), "{n}");
        assert_eq!(sanitize_user("a b/c.."), "abc");
        assert_eq!(sanitize_user("ok_user-1"), "ok_user-1");
    }
}
