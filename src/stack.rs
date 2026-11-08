//! Stack discovery: every `<repo>/<stacks dir>/<name>/` with a compose file
//! is a stack. The stacks directory is `stacks` unless `.sec/meta.toml` says
//! otherwise ([`Layout`]); the rules below say `stacks/` for it.
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
//! - The compose file is any of [`COMPOSE_FILES`] (Docker's own names).
//!   Directories without one are not stacks and are skipped, whatever their
//!   name. With more than one, the first in Docker's precedence order wins
//!   (as `docker compose` does) and the others are listed in
//!   [`Stack::ignored`] so the CLI can warn. Ignored compose files are
//!   still ordinary stack files: their markers are scanned and their
//!   `<<set:…>>` values stored, so nothing leaks.
//! - Entries starting with `.` are skipped. So are regular files and other
//!   non-directories.
//! - Symlinks are **not** followed (changed in M2; M1 followed them). git
//!   stores a symlink as a link, so the pre-commit hook, which reads the
//!   index, can't see what it points to. To keep `sync`, `render` and the
//!   hook seeing the same stacks, a symlinked `stacks/` directory, a symlink
//!   directly in `stacks/` (whatever it points to, dangling included) and a
//!   symlinked compose file (any of the names) are errors rather than
//!   silently skipped.
//! - A directory that has a compose file but whose name is not valid
//!   UTF-8, or not a valid stack name, is an error rather than skipped, so
//!   a stack never silently disappears from `sync`/`render`.
//!
//! Which files of a stack `lst sync` reads is decided by git
//! (`git::worktree_files`: the files git would stage), not here.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The default stacks root.
pub const STACKS_DIR: &str = "stacks";
/// The compose file names, in Docker's precedence order (the first present
/// is the stack's compose file).
pub const COMPOSE_FILES: [&str; 4] = [
    "compose.yaml",
    "compose.yml",
    "docker-compose.yaml",
    "docker-compose.yml",
];
/// Names taken by `.sec/` itself (its file stems).
const RESERVED: &[&str] = &[crate::store::SHARED, crate::store::META];

/// Where the stacks live: the stacks root, relative to the repository root
/// (`stacks` by default, set in `.sec/meta.toml` as `stacks_dir`). A
/// stack is a directory directly below it. `.` is the repository root
/// itself (a flat layout: `./<stack>/compose.yaml`).
///
/// The root is a relative path of components made of `A-Z a-z 0-9 . _ -`,
/// none empty, `.`, `..` or starting with `.` (so it can never be or be
/// inside `.sec/`, `.git/` or a dot-directory), or exactly `.`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    root: String,
}

impl Default for Layout {
    fn default() -> Layout {
        Layout {
            root: STACKS_DIR.to_owned(),
        }
    }
}

impl Layout {
    /// The layout with stacks root `root` (see the type docs for the rules).
    pub fn new(root: &str) -> Result<Layout, StackError> {
        let bad = |problem: &str| StackError::InvalidStacksDir {
            dir: root.to_owned(),
            problem: problem.to_owned(),
        };
        if root == "." {
            return Ok(Layout {
                root: root.to_owned(),
            });
        }
        if root.is_empty() {
            return Err(bad("it is empty (use `.` for the repository root)"));
        }
        if root.starts_with('/') {
            return Err(bad("it must be relative to the repository root"));
        }
        let valid_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
        for part in root.split('/') {
            if part.is_empty() {
                return Err(bad("it has an empty component (`//` or a trailing `/`)"));
            }
            if part.starts_with('.') {
                return Err(bad("no component may be `.`, `..` or start with `.`"));
            }
            if !part.chars().all(valid_char) {
                return Err(bad("use only A-Z, a-z, 0-9, '.', '_', '-' and '/'"));
            }
        }
        Ok(Layout {
            root: root.to_owned(),
        })
    }

    /// The stacks root as written (`stacks`, `apps/stacks`, `.`).
    pub fn root(&self) -> &str {
        &self.root
    }

    pub fn is_default(&self) -> bool {
        self.root == STACKS_DIR
    }

    /// Whether the root is the repository root (`.`).
    pub fn is_flat(&self) -> bool {
        self.root == "."
    }

    /// The components of the root (none for `.`).
    fn below_root_parts(&self) -> impl Iterator<Item = &str> {
        self.root.split('/').filter(|p| *p != ".")
    }

    /// The stacks root below the repository at `repo`.
    pub fn dir(&self, repo: &Path) -> PathBuf {
        if self.is_flat() {
            repo.to_owned()
        } else {
            repo.join(&self.root)
        }
    }

    /// The stacks root as a repo-relative path prefix: `stacks/`, or empty
    /// for `.`.
    pub fn prefix(&self) -> String {
        if self.is_flat() {
            String::new()
        } else {
            format!("{}/", self.root)
        }
    }

    /// `stack`'s directory as a repo-relative path prefix (`stacks/web/`).
    pub fn stack_prefix(&self, stack: &str) -> String {
        format!("{}{stack}/", self.prefix())
    }

    /// `stack`'s directory, repo-relative (`stacks/web`).
    pub fn stack_dir(&self, stack: &str) -> PathBuf {
        PathBuf::from(format!("{}{stack}", self.prefix()))
    }

    /// The part of repo-relative `path` below the stacks root, if it is
    /// below it.
    pub fn below<'a>(&self, path: &'a str) -> Option<&'a str> {
        if self.is_flat() {
            Some(path)
        } else {
            path.strip_prefix(&self.root)?.strip_prefix('/')
        }
    }

    /// The stack directory name and the path inside it, if repo-relative
    /// `path` is a file in a (non-dot) directory directly below the root.
    pub fn split<'a>(&self, path: &'a str) -> Option<(&'a str, &'a str)> {
        let (dir, rest) = self.below(path)?.split_once('/')?;
        (!dir.starts_with('.') && !rest.is_empty()).then_some((dir, rest))
    }

    /// Whether repo-relative `path` is the stacks root, one of its parent
    /// directories, or a non-dot entry directly in it: the paths that must
    /// not be links, or the stacks behind them would silently disappear.
    pub fn is_structural(&self, path: &str) -> bool {
        if !self.is_flat() && (path == self.root || self.root.starts_with(&format!("{path}/"))) {
            return true;
        }
        self.below(path)
            .is_some_and(|rest| !rest.contains('/') && !rest.starts_with('.'))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stack {
    pub name: String,
    /// `<root>/stacks/<name>` (not canonicalised).
    pub dir: PathBuf,
    /// `<root>/stacks/<name>/<compose file>`.
    pub compose: PathBuf,
    /// The compose file's name (one of [`COMPOSE_FILES`]).
    pub compose_file: &'static str,
    /// Other compose files in the directory, shadowed by `compose_file`
    /// (Docker's precedence), in precedence order.
    pub ignored: Vec<&'static str>,
    /// The directory as a repo-relative prefix ([`Layout::stack_prefix`]).
    pub prefix: String,
}

impl Stack {
    /// The directory, repo-relative (`stacks/<name>`): compose's project
    /// directory.
    pub fn dir_rel(&self) -> PathBuf {
        PathBuf::from(self.prefix.trim_end_matches('/'))
    }

    /// The compose file's repo-relative path (`stacks/<name>/<file>`).
    pub fn compose_rel(&self) -> String {
        format!("{}{}", self.prefix, self.compose_file)
    }
}

/// The repo-relative paths of `stack`'s compose files among `files` (its
/// files by repo-relative path, as [`crate::scan::StackFiles`] holds them),
/// in precedence order: the first is the compose file, the rest are
/// shadowed.
pub fn compose_files_in<B>(layout: &Layout, stack: &str, files: &[(String, B)]) -> Vec<String> {
    let prefix = layout.stack_prefix(stack);
    let has = |name: &str| {
        files
            .iter()
            .any(|(p, _)| p.strip_prefix(&prefix) == Some(name))
    };
    COMPOSE_FILES
        .into_iter()
        .filter(|f| has(f))
        .map(|f| format!("{prefix}{f}"))
        .collect()
}

/// The repo-relative path of `stack`'s compose file among `files`: the first
/// of [`compose_files_in`].
pub fn compose_in<B>(layout: &Layout, stack: &str, files: &[(String, B)]) -> Option<String> {
    compose_files_in(layout, stack, files).into_iter().next()
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
    #[error("invalid stacks directory {dir:?}: {problem}")]
    InvalidStacksDir { dir: String, problem: String },
    #[error("unknown stack {name:?} (known stacks: {known})")]
    Unknown { name: String, known: String },
    #[error(
        "{} is a symlink; git stores it as a link, so lst can't see its files when committing. \
         Replace it with the real directory or file",
        path.display()
    )]
    Symlink { path: PathBuf },
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

/// All stacks under `layout`'s root in the repository at `root`, sorted by name (byte order). A missing
/// `stacks/` directory means no stacks.
pub fn discover(root: &Path, layout: &Layout) -> Result<Vec<Stack>, StackError> {
    let dir = layout.dir(root);
    let is_link = |p: &Path| fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink());
    // The root and every directory on the way to it (`.` has none).
    let mut on_the_way = root.to_owned();
    for part in layout.below_root_parts() {
        on_the_way.push(part);
        if is_link(&on_the_way) {
            return Err(StackError::Symlink { path: on_the_way });
        }
    }
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
        // DirEntry::file_type does not follow symlinks.
        let file_type = entry.file_type().map_err(io_err(&path))?;
        if file_type.is_symlink() {
            return Err(StackError::Symlink { path });
        }
        if !file_type.is_dir() {
            continue;
        }
        let mut found = Vec::new();
        for file in COMPOSE_FILES {
            let compose = path.join(file);
            match crate::git::lstat(&compose).map_err(io_err(&compose))? {
                None => continue,
                Some(m) if m.file_type().is_symlink() => {
                    return Err(StackError::Symlink { path: compose });
                }
                Some(m) if m.is_file() => found.push(file),
                Some(_) => return Err(StackError::ComposeNotAFile { path: compose }),
            }
        }
        let Some((&compose_file, ignored)) = found.split_first() else {
            continue;
        };
        let Some(name) = file_name.to_str() else {
            return Err(StackError::NonUtf8Name { path });
        };
        validate_name(name)?;
        stacks.push(Stack {
            name: name.to_owned(),
            compose: path.join(compose_file),
            dir: path,
            compose_file,
            ignored: ignored.to_vec(),
            prefix: layout.stack_prefix(name),
        });
    }
    stacks.sort_by(|a, b| a.name.cmp(&b.name));
    check_case_collisions(stacks.iter().map(|s| s.name.as_str()))?;
    Ok(stacks)
}

/// Fails if two of `names` differ only in ASCII case (they would share a
/// `.sec/` file on a case-insensitive filesystem). Reports the first such
/// pair in case-folded order.
pub fn check_case_collisions<'a>(
    names: impl IntoIterator<Item = &'a str>,
) -> Result<(), StackError> {
    let mut folded: Vec<(String, &str)> = names
        .into_iter()
        .map(|n| (n.to_ascii_lowercase(), n))
        .collect();
    folded.sort();
    match folded.windows(2).find(|w| w[0].0 == w[1].0) {
        Some(w) => Err(StackError::CaseCollision {
            first: w[0].1.to_owned(),
            second: w[1].1.to_owned(),
        }),
        None => Ok(()),
    }
}

/// The stack called `name`. The name is validated before touching the
/// filesystem, so `../x` never becomes a path. Runs a full [`discover`], so
/// a broken sibling stack is reported here too.
pub fn find(root: &Path, layout: &Layout, name: &str) -> Result<Stack, StackError> {
    validate_name(name)?;
    let stacks = discover(root, layout)?;
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
        fs::write(dir.join(COMPOSE_FILES[0]), "services: {}\n").unwrap();
    }

    fn names(root: &Path) -> Vec<String> {
        discover(root, &Layout::default())
            .unwrap()
            .into_iter()
            .map(|s| s.name)
            .collect()
    }

    #[test]
    fn missing_or_empty_stacks_dir() {
        let r = root();
        assert!(discover(r.path(), &Layout::default()).unwrap().is_empty());
        fs::create_dir(r.path().join(STACKS_DIR)).unwrap();
        assert!(discover(r.path(), &Layout::default()).unwrap().is_empty());
    }

    #[test]
    fn stacks_not_a_directory() {
        let r = root();
        fs::write(r.path().join(STACKS_DIR), "").unwrap();
        let err = discover(r.path(), &Layout::default()).unwrap_err();
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
        // Not a compose file name Docker knows.
        fs::create_dir_all(s.join("other-name")).unwrap();
        fs::write(s.join("other-name/compose.yaml.bak"), "").unwrap();
        fs::write(s.join("README.md"), "").unwrap();
        // Invalid names are fine as long as they aren't stacks.
        fs::create_dir_all(s.join("not a stack")).unwrap();

        let stacks = discover(r.path(), &Layout::default()).unwrap();
        let got: Vec<&str> = stacks.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(got, ["Zed", "a.b_c-1", "db", "web"]);
        assert_eq!(
            stacks[2],
            Stack {
                name: "db".into(),
                dir: s.join("db"),
                compose: s.join("db").join(COMPOSE_FILES[0]),
                compose_file: COMPOSE_FILES[0],
                ignored: vec![],
                prefix: "stacks/db/".into(),
            }
        );
    }

    #[test]
    fn every_compose_file_name_counts() {
        let r = root();
        let s = r.path().join(STACKS_DIR);
        for (i, file) in COMPOSE_FILES.iter().enumerate() {
            let dir = s.join(format!("s{i}"));
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join(file), "").unwrap();
        }
        let stacks = discover(r.path(), &Layout::default()).unwrap();
        assert_eq!(stacks.len(), COMPOSE_FILES.len());
        for (st, file) in stacks.iter().zip(COMPOSE_FILES) {
            assert_eq!(st.compose_file, file);
            assert_eq!(st.compose, st.dir.join(file));
            assert_eq!(st.compose_rel(), format!("stacks/{}/{file}", st.name));
            assert!(st.ignored.is_empty());
        }
    }

    #[test]
    fn several_compose_files_follow_docker_precedence() {
        let r = root();
        let dir = r.path().join("stacks/web");
        fs::create_dir_all(&dir).unwrap();
        for file in ["docker-compose.yml", "compose.yml", "docker-compose.yaml"] {
            fs::write(dir.join(file), "").unwrap();
        }
        let s = &discover(r.path(), &Layout::default()).unwrap()[0];
        assert_eq!(s.compose_file, "compose.yml");
        assert_eq!(s.ignored, ["docker-compose.yaml", "docker-compose.yml"]);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_shadowed_compose_file_is_still_an_error() {
        let r = root();
        add_stack(r.path(), "web");
        let link = r.path().join("stacks/web/docker-compose.yml");
        std::os::unix::fs::symlink("compose.yaml", &link).unwrap();
        let err = discover(r.path(), &Layout::default()).unwrap_err();
        assert!(
            matches!(&err, StackError::Symlink { path } if path == &link),
            "{err:?}"
        );
    }

    #[test]
    fn compose_in_uses_the_same_precedence() {
        let files = |names: &[&str]| -> Vec<(String, ())> {
            names
                .iter()
                .map(|n| (format!("stacks/web/{n}"), ()))
                .collect()
        };
        assert_eq!(
            compose_in(&Layout::default(), "web", &files(&["a.conf"])),
            None
        );
        let both = files(&["docker-compose.yml", "compose.yml"]);
        assert_eq!(
            compose_in(&Layout::default(), "web", &both).as_deref(),
            Some("stacks/web/compose.yml")
        );
        assert_eq!(
            compose_files_in(&Layout::default(), "web", &both),
            ["stacks/web/compose.yml", "stacks/web/docker-compose.yml"]
        );
        // Only directly in the stack directory, and only this stack's.
        assert_eq!(
            compose_in(&Layout::default(), "web", &files(&["sub/compose.yaml"])),
            None
        );
        let other = vec![("stacks/db/compose.yaml".to_owned(), ())];
        assert_eq!(compose_in(&Layout::default(), "web", &other), None);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_errors_not_followed() {
        use std::os::unix::fs::symlink;
        let elsewhere = root();
        let real = elsewhere.path().join("real");
        fs::create_dir(&real).unwrap();
        fs::write(real.join(COMPOSE_FILES[0]), "").unwrap();

        // A symlink directly in stacks/: to a stack directory, to a file,
        // or dangling.
        for target in [
            real.clone(),
            real.join(COMPOSE_FILES[0]),
            real.join("nowhere"),
        ] {
            let r = root();
            add_stack(r.path(), "plain");
            let link = r.path().join("stacks/linked");
            symlink(&target, &link).unwrap();
            let err = discover(r.path(), &Layout::default()).unwrap_err();
            assert!(
                matches!(&err, StackError::Symlink { path } if path == &link),
                "{target:?}: {err:?}"
            );
            assert!(
                err.to_string().ends_with(
                    "stacks/linked is a symlink; git stores it as a link, so lst can't see its \
                     files when committing. Replace it with the real directory or file"
                ),
                "{err}"
            );
        }
        // A dot-entry is skipped before it is looked at.
        let r = root();
        add_stack(r.path(), "plain");
        symlink(&real, r.path().join("stacks/.hidden")).unwrap();
        assert_eq!(names(r.path()), ["plain"]);

        // A symlinked compose.yaml: to a file, dangling, or looping.
        for target in [
            real.join(COMPOSE_FILES[0]),
            real.join("nowhere"),
            PathBuf::new(),
        ] {
            let r = root();
            let dir = r.path().join("stacks/file-link");
            fs::create_dir_all(&dir).unwrap();
            let target = if target.as_os_str().is_empty() {
                dir.join(COMPOSE_FILES[0])
            } else {
                target
            };
            symlink(&target, dir.join(COMPOSE_FILES[0])).unwrap();
            let err = discover(r.path(), &Layout::default()).unwrap_err();
            assert!(
                matches!(&err, StackError::Symlink { path } if path == &dir.join(COMPOSE_FILES[0])),
                "{err:?}"
            );
        }

        // A symlinked stacks/ directory.
        let r = root();
        symlink(elsewhere.path(), r.path().join(STACKS_DIR)).unwrap();
        let err = discover(r.path(), &Layout::default()).unwrap_err();
        assert!(
            matches!(&err, StackError::Symlink { path } if path == &r.path().join(STACKS_DIR)),
            "{err:?}"
        );
    }

    #[test]
    fn compose_must_be_a_file() {
        let r = root();
        let compose = r.path().join("stacks/web").join(COMPOSE_FILES[0]);
        fs::create_dir_all(&compose).unwrap();
        let err = discover(r.path(), &Layout::default()).unwrap_err();
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
            let err = discover(r.path(), &Layout::default()).unwrap_err();
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
            s.join(OsStr::from_bytes(b".hid\xff"))
                .join(COMPOSE_FILES[0]),
            "",
        )
        .unwrap();
        fs::create_dir_all(s.join(OsStr::from_bytes(b"empty\xff"))).unwrap();
        assert_eq!(names(r.path()), ["ok"]);

        let bad = s.join(OsStr::from_bytes(b"bad\xff"));
        fs::create_dir_all(&bad).unwrap();
        fs::write(bad.join(COMPOSE_FILES[0]), "").unwrap();
        let err = discover(r.path(), &Layout::default()).unwrap_err();
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
            let err = discover(r.path(), &Layout::default()).unwrap_err();
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
        let err = discover(r.path(), &Layout::default()).unwrap_err();
        assert!(
            matches!(&err, StackError::CaseCollision { first, second }
                if first == "App" && second == "app"),
            "{err:?}"
        );
        assert!(err.to_string().contains("differ only in case"));

        // The check on its own (the hook uses it on staged stack names).
        check_case_collisions(["a", "b", "A-1"]).unwrap();
        check_case_collisions([]).unwrap();
        assert!(matches!(
            check_case_collisions(["web", "x", "WEB"]).unwrap_err(),
            StackError::CaseCollision { first, second } if first == "WEB" && second == "web"
        ));
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
        let err = find(r.path(), &Layout::default(), "web").unwrap_err();
        assert!(
            matches!(&err, StackError::Unknown { name, known } if name == "web" && known == "none"),
            "{err:?}"
        );

        add_stack(r.path(), "web");
        add_stack(r.path(), "db");
        let web = find(r.path(), &Layout::default(), "web").unwrap();
        assert_eq!(web.name, "web");
        assert_eq!(web.compose, r.path().join("stacks/web/compose.yaml"));

        let err = find(r.path(), &Layout::default(), "nope").unwrap_err();
        assert_eq!(
            err.to_string(),
            "unknown stack \"nope\" (known stacks: db, web)"
        );
        // Exact match only.
        assert!(matches!(
            find(r.path(), &Layout::default(), "Web").unwrap_err(),
            StackError::Unknown { .. }
        ));
    }

    #[test]
    fn find_validates_before_touching_the_filesystem() {
        let r = root();
        add_stack(r.path(), "web");
        // Would resolve to stacks/../stacks/web if used as a path.
        assert!(matches!(
            find(r.path(), &Layout::default(), "../stacks/web").unwrap_err(),
            StackError::InvalidName { .. }
        ));
        assert!(matches!(
            find(r.path(), &Layout::default(), "shared").unwrap_err(),
            StackError::Reserved { .. }
        ));
        // And discovery errors propagate.
        fs::create_dir_all(r.path().join("stacks/meta")).unwrap();
        fs::write(r.path().join("stacks/meta").join(COMPOSE_FILES[0]), "").unwrap();
        assert!(matches!(
            find(r.path(), &Layout::default(), "web").unwrap_err(),
            StackError::Reserved { .. }
        ));
    }

    #[test]
    fn layout_rules() {
        for ok in [".", "stacks", "apps", "a/b-c/d_e.f", "x.y"] {
            assert_eq!(Layout::new(ok).unwrap().root(), ok);
        }
        for (bad, why) in [
            ("", "empty"),
            ("/abs", "relative"),
            ("a//b", "empty component"),
            ("a/", "empty component"),
            ("./a", "start with `.`"),
            ("a/..", "start with `.`"),
            ("..", "start with `.`"),
            (".sec", "start with `.`"),
            ("a/.git", "start with `.`"),
            ("a b", "use only"),
            ("a\\b", "use only"),
            ("ü", "use only"),
        ] {
            let err = Layout::new(bad).unwrap_err().to_string();
            assert!(err.contains(why), "{bad:?}: {err}");
        }
        assert!(Layout::default().is_default());
        assert!(!Layout::new(".").unwrap().is_default());
    }

    #[test]
    fn layout_paths() {
        let nested = Layout::new("a/b").unwrap();
        let flat = Layout::new(".").unwrap();
        assert_eq!(nested.stack_prefix("web"), "a/b/web/");
        assert_eq!(flat.stack_prefix("web"), "web/");
        assert_eq!(nested.stack_dir("web"), Path::new("a/b/web"));
        assert_eq!(flat.stack_dir("web"), Path::new("web"));
        assert_eq!(
            nested.split("a/b/web/compose.yaml"),
            Some(("web", "compose.yaml"))
        );
        assert_eq!(nested.split("a/bweb/compose.yaml"), None);
        assert_eq!(nested.split("a/b/web"), None);
        assert_eq!(nested.split("a/b/.x/compose.yaml"), None);
        assert_eq!(flat.split("web/conf/x"), Some(("web", "conf/x")));
        assert_eq!(flat.split("README.md"), None);
        for p in ["a", "a/b", "a/b/web"] {
            assert!(nested.is_structural(p), "{p}");
        }
        for p in ["a/c", "a/b/web/x", "a/b/.x", "ab", "b"] {
            assert!(!nested.is_structural(p), "{p}");
        }
        assert!(flat.is_structural("web"));
        assert!(!flat.is_structural(".git"));
        assert!(!flat.is_structural("web/compose.yaml"));
    }

    #[test]
    fn discover_in_other_layouts() {
        let r = root();
        let write = |rel: &str| {
            let p = r.path().join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, "").unwrap();
        };
        write("apps/web/docker-compose.yml");
        write("db/compose.yaml");
        write(".sec/meta.toml");
        write("README.md");
        let apps = discover(r.path(), &Layout::new("apps").unwrap()).unwrap();
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].compose_rel(), "apps/web/docker-compose.yml");
        let flat = discover(r.path(), &Layout::new(".").unwrap()).unwrap();
        let rels: Vec<String> = flat.iter().map(Stack::compose_rel).collect();
        assert_eq!(rels, ["db/compose.yaml"]);
        assert!(discover(r.path(), &Layout::default()).unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_parent_of_the_root_is_an_error() {
        let r = root();
        let real = r.path().join("real/b/web");
        fs::create_dir_all(&real).unwrap();
        fs::write(real.join("compose.yaml"), "").unwrap();
        std::os::unix::fs::symlink("real", r.path().join("a")).unwrap();
        let err = discover(r.path(), &Layout::new("a/b").unwrap()).unwrap_err();
        assert!(
            matches!(&err, StackError::Symlink { path } if path == &r.path().join("a")),
            "{err:?}"
        );
    }
}
