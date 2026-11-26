//! The template key: a hash of the migration command, the declared extensions and the watched
//! files of a project. Same key, same template database; any change to a watched file, name,
//! argument or extension changes it.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Entries the walk visits, files and folders, the watched folders included.
pub const MAX_WATCH_FILES: usize = 10_000;
pub const MAX_WATCH_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    /// Relative path with `/` separators.
    #[error("cannot read the watched path `{0}`")]
    Unreadable(String),
    #[error("the watched files are over the limit (10000 files and folders, 64 MiB)")]
    TooLarge,
}

/// FNV-1a, 64 bits. Not cryptographic: the key only has to tell two inputs apart.
struct Fnv(u64);

impl Fnv {
    fn new() -> Self {
        Fnv(0xcbf2_9ce4_8422_2325)
    }

    fn bytes(&mut self, b: &[u8]) {
        for &x in b {
            self.0 = (self.0 ^ u64::from(x)).wrapping_mul(0x0000_0100_0000_01b3);
        }
    }

    fn number(&mut self, n: usize) {
        self.bytes(&(n as u64).to_le_bytes());
    }

    /// Length-prefixed, so bytes moved between fields change the hash.
    fn field(&mut self, b: &[u8]) {
        self.number(b.len());
        self.bytes(b);
    }
}

pub fn is_template_key(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// `extensions` in configuration order, the order they are created in: the key names exactly
/// what built the template (a reorder costs one more migration).
pub fn template_key(
    project: &Path,
    migrate: &[String],
    watch: &[String],
    extensions: &[String],
) -> Result<String, KeyError> {
    key_with_limits(
        project,
        migrate,
        watch,
        extensions,
        MAX_WATCH_FILES,
        MAX_WATCH_BYTES,
    )
}

fn key_with_limits(
    project: &Path,
    migrate: &[String],
    watch: &[String],
    extensions: &[String],
    max_files: usize,
    max_bytes: u64,
) -> Result<String, KeyError> {
    let root = fs::canonicalize(project).map_err(|_| KeyError::Unreadable(".".into()))?;
    let mut h = Fnv::new();
    // v2: the extensions joined the key; no v1 key can match a v2 one.
    h.bytes(b"sync_gate-template-v2");
    h.field(root.to_string_lossy().as_bytes());
    for list in [migrate, extensions] {
        h.number(list.len());
        for a in list {
            h.field(a.as_bytes());
        }
    }
    let mut files = Files {
        seen: 0,
        max: max_files,
    };
    let mut budget = max_bytes;
    for entry in watch {
        let rel = entry.replace('\\', "/");
        let mut found = Vec::new();
        collect(&root.join(&rel), &rel, &mut files, &mut found)?;
        found.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        for (rel, path) in found {
            let data =
                read_within(&path, budget)?.ok_or_else(|| KeyError::Unreadable(rel.clone()))?;
            budget -= data.len() as u64;
            h.field(rel.as_bytes());
            h.field(&data);
        }
    }
    Ok(format!("{:016x}", h.0))
}

/// Running count of entries visited, files and folders, so the walk stops at the limit instead of
/// at the end of the tree.
struct Files {
    seen: usize,
    max: usize,
}

/// Reads the file, never more than `budget` bytes: `Err(TooLarge)` when it holds more,
/// `Ok(None)` when it cannot be read. Counts the bytes actually read, not the metadata size.
fn read_within(path: &Path, budget: u64) -> Result<Option<Vec<u8>>, KeyError> {
    let mut data = Vec::new();
    let read = fs::File::open(path).and_then(|f| f.take(budget + 1).read_to_end(&mut data));
    if read.is_err() {
        return Ok(None);
    }
    if data.len() as u64 > budget {
        return Err(KeyError::TooLarge);
    }
    Ok(Some(data))
}

/// Files under `path` as (relative name, path). Links to files are read, links to
/// folders and anything that is neither file nor folder are errors.
fn collect(
    path: &Path,
    rel: &str,
    files: &mut Files,
    out: &mut Vec<(String, PathBuf)>,
) -> Result<(), KeyError> {
    let bad = || KeyError::Unreadable(rel.to_string());
    let mut meta = fs::symlink_metadata(path).map_err(|_| bad())?;
    if meta.file_type().is_symlink() {
        meta = fs::metadata(path).map_err(|_| bad())?;
        if meta.is_dir() {
            return Err(bad());
        }
    }
    files.seen += 1;
    if files.seen > files.max {
        return Err(KeyError::TooLarge);
    }
    if meta.is_file() {
        out.push((rel.to_string(), path.to_path_buf()));
        return Ok(());
    }
    if !meta.is_dir() {
        return Err(bad());
    }
    for e in fs::read_dir(path).map_err(|_| bad())? {
        let e = e.map_err(|_| bad())?;
        let name = e.file_name();
        let Some(name) = name.to_str() else {
            return Err(bad());
        };
        collect(&e.path(), &format!("{rel}/{name}"), files, out)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static N: AtomicU32 = AtomicU32::new(0);

    /// A scratch folder removed on drop.
    struct Tmp(PathBuf);

    impl Tmp {
        fn new() -> Tmp {
            let n = N.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!("sync_gate-key-{}-{n}", std::process::id()));
            fs::create_dir_all(&p).unwrap();
            Tmp(p)
        }

        fn write(&self, rel: &str, data: &str) {
            let p = self.0.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, data).unwrap();
        }

        fn key(&self, migrate: &[&str], watch: &[&str]) -> Result<String, KeyError> {
            self.key_ext(migrate, watch, &[])
        }

        fn key_ext(
            &self,
            migrate: &[&str],
            watch: &[&str],
            ext: &[&str],
        ) -> Result<String, KeyError> {
            template_key(&self.0, &strs(migrate), &strs(watch), &strs(ext))
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn fnv(b: &[u8]) -> u64 {
        let mut h = Fnv::new();
        h.bytes(b);
        h.0
    }

    #[test]
    fn fnv_vectors() {
        assert_eq!(fnv(b""), 0xcbf29ce484222325);
        assert_eq!(fnv(b"a"), 0xaf63dc4c8601ec8c);
        assert_eq!(fnv(b"foobar"), 0x85944171f73967e8);
    }

    #[test]
    fn key_is_16_hex_and_stable() {
        let t = Tmp::new();
        t.write("db/1.sql", "create table a();");
        let k = t.key(&["m"], &["db"]).unwrap();
        assert_eq!(k, t.key(&["m"], &["db"]).unwrap());
        assert!(is_template_key(&k));
        assert!(!is_template_key(&k[..15]));
        assert!(!is_template_key(&format!("{k}0")));
        assert!(!is_template_key("ABCDEF0123456789"));
        assert!(!is_template_key("zzzzzzzzzzzzzzzz"));
    }

    #[test]
    fn content_size_name_argv_and_project_each_change_the_key() {
        let t = Tmp::new();
        t.write("db/1.sql", "aaaa");
        let base = t.key(&["m", "x"], &["db"]).unwrap();
        t.write("db/1.sql", "aaab");
        let content = t.key(&["m", "x"], &["db"]).unwrap();
        t.write("db/1.sql", "aaaab");
        let size = t.key(&["m", "x"], &["db"]).unwrap();
        fs::rename(t.0.join("db/1.sql"), t.0.join("db/2.sql")).unwrap();
        let name = t.key(&["m", "x"], &["db"]).unwrap();
        let argv = t.key(&["m", "y"], &["db"]).unwrap();
        let all = [base, content, size, name, argv];
        for (i, a) in all.iter().enumerate() {
            assert!(all[i + 1..].iter().all(|b| a != b), "{all:?}");
        }
    }

    #[test]
    fn extensions_change_the_key() {
        let t = Tmp::new();
        t.write("db/1.sql", "x");
        let k = |ext: &[&str]| t.key_ext(&["m"], &["db"], ext).unwrap();
        assert_eq!(k(&["pg_trgm"]), k(&["pg_trgm"]));
        let all = [
            k(&[]),
            k(&["pg_trgm"]),
            k(&["pg_trgm", "citext"]),
            k(&["citext", "pg_trgm"]),
            k(&["pg_trgmcitext"]),
        ];
        for (i, a) in all.iter().enumerate() {
            assert!(all[i + 1..].iter().all(|b| a != b), "{all:?}");
        }
        // An extension name is its own field: it cannot pass for a migrate argument.
        assert_ne!(
            t.key_ext(&["m", "pg_trgm"], &["db"], &[]),
            t.key_ext(&["m"], &["db"], &["pg_trgm"])
        );
    }

    #[test]
    fn same_watched_files_in_two_projects_get_different_templates() {
        let (a, b) = (Tmp::new(), Tmp::new());
        a.write("db/1.sql", "x");
        b.write("db/1.sql", "x");
        assert_ne!(a.key(&["m"], &["db"]), b.key(&["m"], &["db"]));
    }

    #[test]
    fn moving_bytes_between_files_changes_the_key() {
        let t = Tmp::new();
        t.write("db/a", "xy");
        t.write("db/b", "z");
        let before = t.key(&["m"], &["db"]).unwrap();
        t.write("db/a", "x");
        t.write("db/b", "yz");
        assert_ne!(before, t.key(&["m"], &["db"]).unwrap());
    }

    #[test]
    fn order_of_directory_listing_does_not_matter() {
        let t = Tmp::new();
        for f in ["b", "a", "c"] {
            t.write(&format!("db/{f}"), f);
        }
        let k1 = t.key(&["m"], &["db"]).unwrap();
        fs::remove_dir_all(t.0.join("db")).unwrap();
        for f in ["c", "a", "b"] {
            t.write(&format!("db/{f}"), f);
        }
        assert_eq!(k1, t.key(&["m"], &["db"]).unwrap());
    }

    fn link_dir(target: &Path, link: &Path) -> bool {
        #[cfg(unix)]
        let r = std::os::unix::fs::symlink(target, link);
        #[cfg(windows)]
        let r = std::os::windows::fs::symlink_dir(target, link);
        r.is_ok()
    }

    #[test]
    fn unreadable_inputs_are_errors() {
        let t = Tmp::new();
        t.write("db/1.sql", "x");
        assert_eq!(
            t.key(&["m"], &["db/missing"]),
            Err(KeyError::Unreadable("db/missing".into()))
        );
        fs::create_dir_all(t.0.join("empty")).unwrap();
        assert!(t.key(&["m"], &["empty"]).is_ok());
        fs::create_dir_all(t.0.join("other")).unwrap();
        if link_dir(&t.0.join("other"), &t.0.join("db/link")) {
            assert_eq!(
                t.key(&["m"], &["db"]),
                Err(KeyError::Unreadable("db/link".into()))
            );
        } else {
            println!("skipped: cannot create a directory link here");
        }
    }

    #[test]
    fn file_limit_stops_collection() {
        let t = Tmp::new();
        for f in ["a", "b", "c", "d", "e"] {
            t.write(&format!("db/{f}"), "x");
        }
        let mut files = Files { seen: 0, max: 2 };
        let r = collect(&t.0.join("db"), "db", &mut files, &mut Vec::new());
        assert_eq!(r, Err(KeyError::TooLarge));
        assert_eq!(files.seen, 3); // stopped at the first entry over the limit, not after all 6
    }

    #[test]
    fn empty_folders_count_toward_the_limit() {
        let t = Tmp::new();
        t.write("db/a", "x");
        for d in ["e1", "e2", "e3/e4"] {
            fs::create_dir_all(t.0.join("db").join(d)).unwrap();
        }
        let run = |n| key_with_limits(&t.0, &strs(&["m"]), &strs(&["db"]), &[], n, 100);
        // `db`, `a` and four empty folders.
        assert_eq!(run(5), Err(KeyError::TooLarge));
        assert!(run(6).is_ok());
    }

    #[test]
    fn file_growth_cannot_bypass_byte_limit() {
        let t = Tmp::new();
        t.write("db/a", "12345");
        // the count uses the bytes actually read, whatever the metadata said earlier
        let run = |n| key_with_limits(&t.0, &strs(&["m"]), &strs(&["db"]), &[], 10, n);
        assert_eq!(run(4), Err(KeyError::TooLarge));
        assert!(run(5).is_ok());
        assert_eq!(read_within(&t.0.join("db/a"), 4), Err(KeyError::TooLarge));
        assert_eq!(
            read_within(&t.0.join("db/a"), 5),
            Ok(Some(b"12345".to_vec()))
        );
    }

    #[test]
    fn limits_are_errors() {
        let t = Tmp::new();
        for f in ["a", "b", "c"] {
            t.write(&format!("db/{f}"), "x");
        }
        let run =
            |files, bytes| key_with_limits(&t.0, &strs(&["m"]), &strs(&["db"]), &[], files, bytes);
        // `db` and its three files.
        assert_eq!(run(3, 100), Err(KeyError::TooLarge));
        assert!(run(4, 100).is_ok());
        t.write("db/a", "xxx");
        assert_eq!(run(10, 4), Err(KeyError::TooLarge));
        assert!(run(10, 5).is_ok());
    }
}
