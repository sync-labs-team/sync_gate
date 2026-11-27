//! The adoption record (`mcp-adopted.json` in the data folder): what `sync_gate mcp adopt`
//! changed in each agent config, so `restore` (and the relay) can find the original launch.
//! It authorizes running a command, so on Unix it is read only after its folder, the folder's
//! ancestors and the file itself pass the private checks.

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::agent_config::{Format, LaunchText};

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Agent {
    Claude,
    Codex,
}

impl Agent {
    pub fn format(self) -> Format {
        match self {
            Agent::Claude => Format::ClaudeJson,
            Agent::Codex => Format::CodexToml,
        }
    }

    /// The product name, as messages say it.
    pub fn label(self) -> &'static str {
        match self {
            Agent::Claude => "Claude Code",
            Agent::Codex => "Codex",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AdoptedEntry {
    pub agent: Agent,
    pub file: PathBuf,
    pub server: String,
    pub original: LaunchText,
    pub original_command: String,
    pub original_args: Option<Vec<String>>,
    pub adopted_command: String,
    pub adopted_args: Vec<String>,
    pub inserted_args: bool,
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Adopted {
    pub version: u32,
    pub entries: Vec<AdoptedEntry>,
}

pub const RECORD: &str = "mcp-adopted.json";

/// `data_dir` (and every ancestor) through check_private_dir; then, Unix: the record is opened
/// without following a link and checked on the opened file, which is the one read
/// (open_private_file); Windows: read by path, which nobody else can swap. Missing → empty.
/// Refused → Err. A parse error names a category and a position, never the file's text.
pub fn read_adopted(data_dir: &Path) -> io::Result<Adopted> {
    let path = data_dir.join(RECORD);
    if crate::check_private_dir(data_dir)? == crate::DirState::Missing {
        return Ok(Adopted::default());
    }
    #[cfg(unix)]
    let bytes = {
        use crate::open_private_file;
        use std::io::Read;
        let mut bytes = Vec::new();
        match open_private_file(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Adopted::default()),
            r => r?.read_to_end(&mut bytes)?,
        };
        bytes
    };
    #[cfg(not(unix))]
    let bytes = match std::fs::read(&path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Adopted::default()),
        r => r?,
    };
    serde_json::from_slice(&bytes).map_err(|e| {
        use serde_json::error::Category;
        // Serde's own text can quote the value it did not expect.
        let what = match e.classify() {
            Category::Io => "read error",
            Category::Syntax => "syntax error",
            Category::Data => "unexpected value or type",
            Category::Eof => "unexpected end",
        };
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "invalid {}: {what} at line {}, column {}",
                path.display(),
                e.line(),
                e.column()
            ),
        )
    })
}

/// The original launch of `server`, from any entry (adopt never records two different ones).
pub fn find_original(a: &Adopted, server: &str) -> Option<(String, Vec<String>)> {
    a.entries.iter().find(|e| e.server == server).map(|e| {
        (
            e.original_command.clone(),
            e.original_args.clone().unwrap_or_default(),
        )
    })
}

/// The `[mcp.<name>]` table `adopt` appends to the sync_gate config, as TOML text.
pub fn mcp_table(
    name: &str,
    command: &str,
    args: &[String],
    env_from: &[String],
    cwd: Option<&str>,
) -> String {
    let s = |v: &str| toml::Value::String(v.to_string()).to_string();
    let list = |v: &[String]| {
        toml::Value::Array(v.iter().map(|a| toml::Value::String(a.clone())).collect()).to_string()
    };
    let cwd = cwd.map_or(String::new(), |c| format!("cwd = {}\n", s(c)));
    format!(
        "\n[mcp.{name}]\ncommand = {}\nargs = {}\nenv_from = {}\n{cwd}mode = \"shared\"\n",
        s(command),
        list(args),
        list(env_from)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_record_is_empty() {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("fg-adopted-{}-{n}", std::process::id()));
        // Neither the folder nor the record exists.
        assert!(read_adopted(&dir).unwrap().entries.is_empty());
        std::fs::create_dir(&dir).unwrap();
        // The folder exists, the record does not.
        let r = read_adopted(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(r.unwrap().entries.is_empty());
    }

    /// Windows: the record is read only from a folder nobody else can change. Control: the same
    /// record before the folder is opened to everyone.
    #[cfg(windows)]
    #[test]
    fn read_refuses_a_record_in_a_folder_others_can_write() {
        let dir = std::env::temp_dir().join(format!("fg-adopted-acl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(RECORD), br#"{"version":1,"entries":[]}"#).unwrap();
        assert_eq!(read_adopted(&dir).unwrap().version, 1);
        let out = std::process::Command::new("icacls")
            .arg(&dir)
            .args(["/grant", "*S-1-1-0:(OI)(CI)(M)"])
            .output()
            .unwrap();
        assert!(out.status.success(), "icacls: {out:?}");
        let r = read_adopted(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        let e = r.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
        assert!(e.to_string().contains("writable by other users"), "{e}");
    }

    #[cfg(unix)]
    fn record(dir: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(RECORD);
        std::fs::write(&p, br#"{"version":1,"entries":[]}"#).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn read_refuses_a_record_in_an_unsafe_folder() {
        let s = crate::private_dir::Scratch::new("adopted-dir");
        let dir = s.dir("data", 0o777);
        record(&dir, 0o600);
        let e = read_adopted(&dir).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
        // Control: the same record in a private folder is read.
        let ok = s.dir("ok", 0o700);
        record(&ok, 0o600);
        assert_eq!(read_adopted(&ok).unwrap().version, 1);
    }

    #[cfg(unix)]
    #[test]
    fn read_refuses_a_record_others_can_write() {
        let s = crate::private_dir::Scratch::new("adopted-file");
        let dir = s.dir("data", 0o700);
        record(&dir, 0o666);
        let e = read_adopted(&dir).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
        assert!(e.to_string().contains("writable"), "{e}");
    }
}
