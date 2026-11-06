//! Stack discovery: every `<root>/stacks/<name>/compose.yaml` is a stack.
//!
//! This module only finds paths; reading the files is the caller's job.
//!
//! # Rules
//! - Stack names are `[A-Za-z0-9._-]+` and don't start with `.`. They end
//!   up in `.sec/<name>.toml` and in full secret names (`<name>/secret`),
//!   so `/`, `:`, whitespace and non-ASCII are out.
//! - `shared` and `meta` are reserved, compared ASCII-case-insensitively:
//!   they would collide with `.sec/shared.toml` and `.sec/meta.toml` (also
//!   on case-insensitive filesystems). Two stacks whose names differ only
//!   in case are an error for the same reason.
//! - Only `compose.yaml` counts (not `compose.yml` or
//!   `docker-compose.yaml`). Directories without it are not stacks and are
//!   skipped, whatever their name.
//! - Entries starting with `.` are skipped. So are non-directories.
//! - Symlinks (to a stack directory or to `compose.yaml`) are followed: it
//!   is the user's repository. A dangling or looping symlink is an error
//!   rather than silently dropping what may be a stack.
//! - A directory that has a `compose.yaml` but whose name is not valid
//!   UTF-8, or not a valid stack name, is an error rather than skipped, so
//!   a stack never silently disappears from `sync`/`render`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const STACKS_DIR: &str = "stacks";
pub const COMPOSE_FILE: &str = "compose.yaml";
/// Names taken by `.sec/` itself (its file stems).
const RESERVED: &[&str] = &[crate::store::SHARED, crate::store::META];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stack {
    pub name: String,
    /// `<root>/stacks/<name>` (not canonicalised).
    pub dir: PathBuf,
    /// `<root>/stacks/<name>/compose.yaml`.
    pub compose: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum StackError {
    #[error("{}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("stack directory {} has a name that is not valid UTF-8", path.display())]
    NonUtf8Name { path: PathBuf },
    #[error(
        "invalid stack name {name:?}: use only A-Z, a-z, 0-9, '.', '_' and '-', \
         and don't start with '.'"
    )]
    InvalidName { name: String },
    #[error("stack name {name:?} is reserved (it would collide with a file lst keeps in .sec/)")]
    Reserved { name: String },
    #[error("stacks {first:?} and {second:?} differ only in case; rename one")]
    CaseCollision { first: String, second: String },
    #[error("{} exists but is not a regular file", path.display())]
    ComposeNotAFile { path: PathBuf },
    #[error("unknown stack {name:?} (known stacks: {known})")]
    Unknown { name: String, known: String },
}

fn io_err(path: &Path) -> impl FnOnce(io::Error) -> StackError + '_ {
    move |source| StackError::Io {
        path: path.to_owned(),
        source,
    }
}

/// Checks the stack-name rules (charset, leading `.`, reserved names). The
/// single source of truth: `store::is_valid_stack` delegates here.
pub fn validate_name(name: &str) -> Result<(), StackError> {
    let valid_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
    if name.is_empty() || name.starts_with('.') || !name.chars().all(valid_char) {
        return Err(StackError::InvalidName {
            name: name.to_owned(),
        });
    }
    if RESERVED.iter().any(|r| r.eq_ignore_ascii_case(name)) {
        return Err(StackError::Reserved {
            name: name.to_owned(),
        });
    }
    Ok(())
}

/// All stacks under `<root>/stacks`, sorted by name (byte order). A missing
/// `stacks/` directory means no stacks.
pub fn discover(root: &Path) -> Result<Vec<Stack>, StackError> {
    let dir = root.join(STACKS_DIR);
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io_err(&dir)(e)),
    };
    let mut stacks = Vec::new();
    for entry in entries {
        let entry = entry.map_err(io_err(&dir))?;
        let file_name = entry.file_name();
        if file_name.as_encoded_bytes().starts_with(b".") {
            continue;
        }
        let path = entry.path();
        // fs::metadata follows symlinks.
        if !fs::metadata(&path).map_err(io_err(&path))?.is_dir() {
            continue;
        }
        let compose = path.join(COMPOSE_FILE);
        match fs::metadata(&compose) {
            Ok(m) if m.is_file() => {}
            Ok(_) => return Err(StackError::ComposeNotAFile { path: compose }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(io_err(&compose)(e)),
        }
        let Some(name) = file_name.to_str() else {
            return Err(StackError::NonUtf8Name { path });
        };
        validate_name(name)?;
        stacks.push(Stack {
            name: name.to_owned(),
            dir: path,
            compose,
        });
    }
    stacks.sort_by(|a, b| a.name.cmp(&b.name));

    let mut folded: Vec<(String, &str)> = stacks
        .iter()
        .map(|s| (s.name.to_ascii_lowercase(), s.name.as_str()))
        .collect();
    folded.sort();
    if let Some(w) = folded.windows(2).find(|w| w[0].0 == w[1].0) {
        return Err(StackError::CaseCollision {
            first: w[0].1.to_owned(),
            second: w[1].1.to_owned(),
        });
    }
    Ok(stacks)
}

/// The stack called `name`. The name is validated before touching the
/// filesystem, so `../x` never becomes a path. Runs a full [`discover`], so
/// a broken sibling stack is reported here too.
pub fn find(root: &Path, name: &str) -> Result<Stack, StackError> {
    validate_name(name)?;
    let stacks = discover(root)?;
    let known = stacks
        .iter()
        .map(|s| s.name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    stacks
        .into_iter()
        .find(|s| s.name == name)
        .ok_or_else(|| StackError::Unknown {
            name: name.to_owned(),
            known: if known.is_empty() {
                "none".to_owned()
            } else {
                known
            },
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn root() -> TempDir {
        tempfile::tempdir().unwrap()
    }

    fn add_stack(root: &Path, name: &str) {
        let dir = root.join(STACKS_DIR).join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(COMPOSE_FILE), "services: {}\n").unwrap();
    }

    fn names(root: &Path) -> Vec<String> {
        discover(root)
            .unwrap()
            .into_iter()
            .map(|s| s.name)
            .collect()
    }

    #[test]
    fn missing_or_empty_stacks_dir() {
        let r = root();
        assert!(discover(r.path()).unwrap().is_empty());
        fs::create_dir(r.path().join(STACKS_DIR)).unwrap();
        assert!(discover(r.path()).unwrap().is_empty());
    }

    #[test]
    fn stacks_not_a_directory() {
        let r = root();
        fs::write(r.path().join(STACKS_DIR), "").unwrap();
        let err = discover(r.path()).unwrap_err();
        assert!(
            matches!(&err, StackError::Io { path, .. } if path == &r.path().join(STACKS_DIR)),
            "{err:?}"
        );
        assert!(err.to_string().contains("stacks"));
    }

    #[test]
    fn discovers_sorted_and_skips_non_stacks() {
        let r = root();
        let s = r.path().join(STACKS_DIR);
        for name in ["web", "db", "Zed", "a.b_c-1"] {
            add_stack(r.path(), name);
        }
        add_stack(r.path(), ".hidden");
        fs::create_dir_all(s.join("no-compose/sub")).unwrap();
        fs::create_dir_all(s.join("yml-only")).unwrap();
        fs::write(s.join("yml-only/compose.yml"), "").unwrap();
        fs::write(s.join("yml-only/docker-compose.yaml"), "").unwrap();
        fs::write(s.join("README.md"), "").unwrap();
        // Invalid names are fine as long as they aren't stacks.
        fs::create_dir_all(s.join("not a stack")).unwrap();

        let stacks = discover(r.path()).unwrap();
        let got: Vec<&str> = stacks.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(got, ["Zed", "a.b_c-1", "db", "web"]);
        assert_eq!(
            stacks[2],
            Stack {
                name: "db".into(),
                dir: s.join("db"),
                compose: s.join("db").join(COMPOSE_FILE),
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn follows_symlinks() {
        use std::os::unix::fs::symlink;
        let r = root();
        let elsewhere = root();
        let real = elsewhere.path().join("real");
        fs::create_dir(&real).unwrap();
        fs::write(real.join(COMPOSE_FILE), "").unwrap();
        fs::create_dir(r.path().join(STACKS_DIR)).unwrap();
        symlink(&real, r.path().join("stacks/linked")).unwrap();

        add_stack(r.path(), "plain");
        let file_link = r.path().join("stacks/file-link");
        fs::create_dir(&file_link).unwrap();
        symlink(real.join(COMPOSE_FILE), file_link.join(COMPOSE_FILE)).unwrap();
        // A symlink to a file directly in stacks/ is not a stack.
        symlink(real.join(COMPOSE_FILE), r.path().join("stacks/file")).unwrap();

        let stacks = discover(r.path()).unwrap();
        let got: Vec<&str> = stacks.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(got, ["file-link", "linked", "plain"]);
        assert_eq!(stacks[1].dir, r.path().join("stacks/linked"));
    }

    #[cfg(unix)]
    #[test]
    fn dangling_and_looping_symlinks_are_errors() {
        use std::os::unix::fs::symlink;
        let r = root();
        fs::create_dir(r.path().join(STACKS_DIR)).unwrap();
        let dangling = r.path().join("stacks/gone");
        symlink(r.path().join("nowhere"), &dangling).unwrap();
        let err = discover(r.path()).unwrap_err();
        assert!(
            matches!(&err, StackError::Io { path, .. } if path == &dangling),
            "{err:?}"
        );
        fs::remove_file(&dangling).unwrap();

        let dir = r.path().join("stacks/loop");
        fs::create_dir(&dir).unwrap();
        symlink(dir.join(COMPOSE_FILE), dir.join(COMPOSE_FILE)).unwrap();
        let err = discover(r.path()).unwrap_err();
        assert!(
            matches!(&err, StackError::Io { path, .. } if path == &dir.join(COMPOSE_FILE)),
            "{err:?}"
        );
    }

    #[test]
    fn compose_must_be_a_file() {
        let r = root();
        let compose = r.path().join("stacks/web").join(COMPOSE_FILE);
        fs::create_dir_all(&compose).unwrap();
        let err = discover(r.path()).unwrap_err();
        assert!(
            matches!(&err, StackError::ComposeNotAFile { path } if path == &compose),
            "{err:?}"
        );
        assert!(err.to_string().contains("not a regular file"));
    }

    #[test]
    fn invalid_names_with_compose_are_errors() {
        for name in ["has space", "ünï", "a:b", "a+b"] {
            let r = root();
            add_stack(r.path(), name);
            let err = discover(r.path()).unwrap_err();
            assert!(
                matches!(&err, StackError::InvalidName { name: n } if n == name),
                "{err:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_names() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let r = root();
        let s = r.path().join(STACKS_DIR);
        add_stack(r.path(), "ok");
        // Hidden or without compose.yaml: skipped.
        fs::create_dir_all(s.join(OsStr::from_bytes(b".hid\xff"))).unwrap();
        fs::write(
            s.join(OsStr::from_bytes(b".hid\xff")).join(COMPOSE_FILE),
            "",
        )
        .unwrap();
        fs::create_dir_all(s.join(OsStr::from_bytes(b"empty\xff"))).unwrap();
        assert_eq!(names(r.path()), ["ok"]);

        let bad = s.join(OsStr::from_bytes(b"bad\xff"));
        fs::create_dir_all(&bad).unwrap();
        fs::write(bad.join(COMPOSE_FILE), "").unwrap();
        let err = discover(r.path()).unwrap_err();
        assert!(
            matches!(&err, StackError::NonUtf8Name { path } if path == &bad),
            "{err:?}"
        );
        assert!(err.to_string().contains("not valid UTF-8"));
    }

    #[test]
    fn reserved_names() {
        for name in ["shared", "Shared", "SHARED", "meta", "Meta"] {
            let r = root();
            add_stack(r.path(), name);
            let err = discover(r.path()).unwrap_err();
            assert!(
                matches!(&err, StackError::Reserved { name: n } if n == name),
                "{err:?}"
            );
            assert!(err.to_string().contains("reserved"));
        }
        // Only the exact names (in any case) are reserved.
        let r = root();
        for name in ["shared-db", "metadata", "my.shared"] {
            add_stack(r.path(), name);
        }
        assert_eq!(names(r.path()), ["metadata", "my.shared", "shared-db"]);
    }

    #[test]
    fn case_collisions() {
        let r = root();
        for name in ["App", "middle", "app"] {
            add_stack(r.path(), name);
        }
        let err = discover(r.path()).unwrap_err();
        assert!(
            matches!(&err, StackError::CaseCollision { first, second }
                if first == "App" && second == "app"),
            "{err:?}"
        );
        assert!(err.to_string().contains("differ only in case"));
    }

    #[test]
    fn validate_name_rules() {
        for ok in ["a", "A", "0", "a.b", "a_b-9", "x.", "-x", "_"] {
            validate_name(ok).unwrap();
        }
        for bad in [
            "", ".", ".a", "..", "a/b", "../a", "a\\b", "a:b", "a b", "ä", "a\n",
        ] {
            let err = validate_name(bad).unwrap_err();
            assert!(matches!(err, StackError::InvalidName { .. }), "{bad:?}");
            assert!(err.to_string().contains("invalid stack name"));
        }
    }

    #[test]
    fn find_stacks() {
        let r = root();
        let err = find(r.path(), "web").unwrap_err();
        assert!(
            matches!(&err, StackError::Unknown { name, known } if name == "web" && known == "none"),
            "{err:?}"
        );

        add_stack(r.path(), "web");
        add_stack(r.path(), "db");
        let web = find(r.path(), "web").unwrap();
        assert_eq!(web.name, "web");
        assert_eq!(web.compose, r.path().join("stacks/web/compose.yaml"));

        let err = find(r.path(), "nope").unwrap_err();
        assert_eq!(
            err.to_string(),
            "unknown stack \"nope\" (known stacks: db, web)"
        );
        // Exact match only.
        assert!(matches!(
            find(r.path(), "Web").unwrap_err(),
            StackError::Unknown { .. }
        ));
    }

    #[test]
    fn find_validates_before_touching_the_filesystem() {
        let r = root();
        add_stack(r.path(), "web");
        // Would resolve to stacks/../stacks/web if used as a path.
        assert!(matches!(
            find(r.path(), "../stacks/web").unwrap_err(),
            StackError::InvalidName { .. }
        ));
        assert!(matches!(
            find(r.path(), "shared").unwrap_err(),
            StackError::Reserved { .. }
        ));
        // And discovery errors propagate.
        fs::create_dir_all(r.path().join("stacks/meta")).unwrap();
        fs::write(r.path().join("stacks/meta").join(COMPOSE_FILE), "").unwrap();
        assert!(matches!(
            find(r.path(), "web").unwrap_err(),
            StackError::Reserved { .. }
        ));
    }
}
