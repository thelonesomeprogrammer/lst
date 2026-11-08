//! The pre-commit hook (`lst hook run`): its planning, pure.
//!
//! Index entries, staged blobs and the sync report come in; which files to
//! scan, which values to store, what to write back and what to block on
//! come out. `cli` does the I/O around it (reading blobs, `.sec/`, the
//! index and the working tree).
//!
//! # What the hook reads
//! Only the index (whichever one `GIT_INDEX_FILE` names), never the working
//! tree, and every staged file, not only the changed ones (so orphans are
//! decided on the whole tree):
//! - A **stack** is `stacks/<name>/` with a staged compose file (any of
//!   [`stack::COMPOSE_FILES`]), under the same rules as [`stack::discover`]:
//!   the name must be valid, not reserved and not differ from another only
//!   in case; dot-directories are not stacks; every compose file must be a
//!   regular file. With several, Docker's precedence picks one
//!   ([`stack::compose_files_in`]); the others are still stack files.
//! - Every regular file of a stack is scanned for markers
//!   ([`scan::collect`], which also decides about non-UTF-8 files).
//! - Every other regular file (outside `stacks/`, directly in it, or in a
//!   directory that is not a stack) must not contain `<<set:`: lst would not
//!   process it, so its value would be committed as plaintext.
//! - `.sec/` is lst's own and is not scanned.
//! - Symlinks and submodules have no content lst can scan and are skipped,
//!   except where they would hide a stack: `stacks` itself, an entry
//!   directly in `stacks/` and a stack's compose files must not be links
//!   (git stores the link, not what it points to).
//!
//! # Temporary index
//! `git commit <paths>` runs the hook on a temporary index built from
//! `HEAD` plus those paths. git commits what the hook stages there, but
//! never copies it back: afterwards the real index still holds the paths as
//! they were before the hook (including a `<<set:…>>` plaintext) and the
//! old `.sec/`. So with a temporary index the hook only passes if it has
//! nothing to change, and blocks otherwise ([`HookError::TemporaryIndex`]).
//! `git commit -a` is fine: its index becomes the real index.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::crypto::SecretString;
use crate::git::IndexEntry;
use crate::marker::{self, MarkerKind};
use crate::scan::{self, ScanError, Uses};
use crate::stack::{self, COMPOSE_FILES, STACKS_DIR, StackError};
use crate::store::{self, ResolveError, SHARED, StoreError, SyncReport};

/// The hook script `lst hook install` writes (mode 0755). Not finding `lst`
/// blocks the commit rather than skipping the checks.
pub const SCRIPT: &str = "#!/bin/sh
# Installed by lst. Do not edit.
command -v lst >/dev/null 2>&1 || { echo \"lst: not on PATH; commit blocked\" >&2; exit 1; }
exec lst hook run
";

/// The hook's file name in the hooks directory.
pub const HOOK_FILE: &str = "pre-commit";

/// The store directory as a prefix of index paths.
const SEC_PREFIX: &str = ".sec/";
const SYMLINK_MODE: &str = "120000";
const SECRET_OPEN: &str = "<<secret:";
const MARKER_CLOSE: &str = ">>";

#[derive(Debug, thiserror::Error)]
pub enum HookError {
    #[error(transparent)]
    Stack(#[from] StackError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Scan(#[from] ScanError),
    #[error(
        "{path} is a submodule; lst can't see the files of a stack in another repository. \
         Commit the stack's files in this repository instead"
    )]
    Submodule { path: String },
    #[error(
        "{path}: contains `<<set:` but is not a file of a stack (stacks/<stack>/ with a \
         compose file), so lst would not process it and the value would be committed as \
         plaintext. Move the marker into a stack file, or remove it"
    )]
    SetOutsideStacks { path: String },
    #[error(
        "`{name}`: <<set:…>> is used with different values in {places}; give it one value \
         (or use different names)"
    )]
    ConflictingSet { name: String, places: String },
    #[error("{}", unset_message(.0))]
    Unset(Vec<UnsetSecret>),
    #[error(
        "this commit uses a temporary index (as `git commit <paths>` does), and lst has changes \
         to make (.sec/, or a <<set:…>> to store): git would commit them but leave your real \
         index with the old .sec/ and any <<set:…>> value. Stage the files with `git add` and \
         run `git commit` without paths (or use `git commit -a`)"
    )]
    TemporaryIndex,
}

/// A `<<secret:…>>` with no stored value, by full name and marker name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsetSecret {
    pub full_name: String,
    pub marker_name: String,
}

fn unset_message(list: &[UnsetSecret]) -> String {
    let plural = if list.len() == 1 { "" } else { "s" };
    let mut msg = format!("cannot commit: {} secret{plural} not set:", list.len());
    for u in list {
        let line = ResolveError::SecretUnset {
            name: u.full_name.clone(),
            marker_name: u.marker_name.clone(),
        };
        msg.push_str(&format!("\n  {line}"));
    }
    msg
}

// ---------------------------------------------------------------------------
// Which staged files to read
// ---------------------------------------------------------------------------

/// What the hook does with one index entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Role {
    /// A regular file of this stack: scanned for markers.
    Stack(String),
    /// A regular file outside every stack: must not contain `<<set:`.
    Other,
    /// A file in `.sec/`, by its path below `.sec/`.
    Sec(String),
    /// A symlink or submodule: not read.
    Skip,
}

/// The directory name of `path` if it is `stacks/<dir>/<compose file>`
/// (any of [`COMPOSE_FILES`]).
fn compose_dir(path: &str) -> Option<&str> {
    let (dir, rest) = path.strip_prefix("stacks/")?.split_once('/')?;
    (COMPOSE_FILES.contains(&rest) && !dir.starts_with('.')).then_some(dir)
}

/// The first component below `stacks/`, if `path` is deeper than that.
fn stack_dir(path: &str) -> Option<&str> {
    path.strip_prefix("stacks/")?
        .split_once('/')
        .map(|(dir, _)| dir)
}

/// Whether `path` is `stacks` itself or a (non-dot) entry directly in it.
fn is_stacks_entry(path: &str) -> bool {
    path == STACKS_DIR
        || path
            .strip_prefix("stacks/")
            .is_some_and(|rest| !rest.contains('/') && !rest.starts_with('.'))
}

/// The error for a link where a stack's directory or compose file must be.
fn link_error(e: &IndexEntry) -> HookError {
    if e.mode == SYMLINK_MODE {
        StackError::Symlink {
            path: PathBuf::from(&e.path),
        }
        .into()
    } else {
        HookError::Submodule {
            path: e.path.clone(),
        }
    }
}

/// The role of every entry of the index, in the same order (see the
/// module docs). Fails on a broken stack, like [`stack::discover`].
pub fn classify(entries: &[IndexEntry]) -> Result<Vec<Role>, HookError> {
    let mut stacks = BTreeSet::new();
    for e in entries {
        if is_stacks_entry(&e.path) && !e.is_file() {
            return Err(link_error(e));
        }
        if let Some(dir) = compose_dir(&e.path) {
            if !e.is_file() {
                return Err(link_error(e));
            }
            stack::validate_name(dir)?;
            stacks.insert(dir);
        }
    }
    stack::check_case_collisions(stacks.iter().copied())?;
    let role = |e: &IndexEntry| {
        if !e.is_file() {
            return Role::Skip;
        }
        if let Some(rest) = e.path.strip_prefix(SEC_PREFIX) {
            return Role::Sec(rest.to_owned());
        }
        match stack_dir(&e.path) {
            Some(dir) if stacks.contains(dir) => Role::Stack(dir.to_owned()),
            _ => Role::Other,
        }
    };
    Ok(entries.iter().map(role).collect())
}

// ---------------------------------------------------------------------------
// <<set:…>> processing
// ---------------------------------------------------------------------------

/// One `<<set:…>>` marker of a staged file.
#[derive(Debug, Clone)]
pub struct RawSet {
    /// The marker name as written (`cf`, `shared/smtp`).
    pub name: String,
    /// The whole marker exactly as written, value (escaped) included.
    pub raw: SecretString,
    /// The unescaped value.
    pub value: SecretString,
}

/// A staged file with its `<<set:…>>` markers replaced.
#[derive(Debug, Clone)]
pub struct Rewrite {
    /// The file with every `<<set:name:…>>` replaced by `<<secret:name>>`,
    /// all other bytes unchanged.
    pub text: SecretString,
    /// The markers replaced, in text order.
    pub sets: Vec<RawSet>,
}

/// `bytes` (the staged content of `path`) with its `<<set:…>>` markers
/// rewritten; `None` if it has none or isn't UTF-8 (a `<<set:` in a
/// non-UTF-8 stack file is [`scan::collect`]'s error).
pub fn rewrite_sets(path: &str, bytes: &[u8]) -> Result<Option<Rewrite>, ScanError> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Ok(None);
    };
    let markers = marker::parse(text).map_err(|e| scan::parse_error(path, text, e))?;
    let mut spans = Vec::new();
    let mut sets = Vec::new();
    for m in markers {
        if let MarkerKind::Set { name, value } = m.kind {
            let raw = SecretString::new(text[m.span.clone()].to_owned());
            spans.push(m.span);
            sets.push(RawSet { name, raw, value });
        }
    }
    if sets.is_empty() {
        return Ok(None);
    }
    // `<<secret:N>>` is 2 - len(VALUE) bytes longer than `<<set:N:VALUE>>`,
    // so at most one byte per marker (VALUE is never empty). Reserving that
    // up front means the buffer never reallocates.
    let mut out = SecretString::new(String::with_capacity(text.len() + sets.len()));
    let s = out.as_mut_string();
    let mut at = 0;
    for (span, set) in spans.iter().zip(&sets) {
        s.push_str(&text[at..span.start]);
        s.push_str(SECRET_OPEN);
        s.push_str(&set.name);
        s.push_str(MARKER_CLOSE);
        at = span.end;
    }
    s.push_str(&text[at..]);
    Ok(Some(Rewrite { text: out, sets }))
}

/// A staged stack file that has `<<set:…>>` markers.
#[derive(Debug, Clone)]
pub struct SetFile {
    pub path: String,
    pub stack: String,
    /// The index mode to write the rewritten blob with (keeps the exec bit).
    pub mode: String,
    pub rewrite: Rewrite,
}

/// A value to store with `Store::set_secret`.
#[derive(Debug)]
pub struct ToStore<'a> {
    pub stack: &'a str,
    pub name: &'a str,
    pub full_name: String,
    pub value: &'a SecretString,
}

/// One entry per distinct secret (by full name, so `shared/x` set in two
/// stacks is one) to store, in file and text order. The same name set to
/// two different values anywhere is an error naming both files.
pub fn values_to_store(files: &[SetFile]) -> Result<Vec<ToStore<'_>>, HookError> {
    let mut out: Vec<ToStore<'_>> = Vec::new();
    let mut first_seen: BTreeMap<String, (usize, &str)> = BTreeMap::new();
    for f in files {
        for s in &f.rewrite.sets {
            let full_name = store::scope(&f.stack, &s.name)?.full_name;
            if let Some(&(i, first)) = first_seen.get(&full_name) {
                if out[i].value.expose() != s.value.expose() {
                    let places = if first == f.path {
                        first.to_owned()
                    } else {
                        format!("{first} and {}", f.path)
                    };
                    return Err(HookError::ConflictingSet {
                        name: full_name,
                        places,
                    });
                }
                continue;
            }
            first_seen.insert(full_name.clone(), (out.len(), &f.path));
            out.push(ToStore {
                stack: &f.stack,
                name: &s.name,
                full_name,
                value: &s.value,
            });
        }
    }
    Ok(out)
}

/// `uses` with every `<<set:name:…>>` as `<<secret:name>>` (what the files
/// say once rewritten), for `Store::sync`. Drops (and so zeroizes) the
/// values.
pub fn secret_uses(uses: Uses) -> Uses {
    uses.into_iter()
        .map(|(stack, markers)| {
            let markers = markers
                .into_iter()
                .map(|m| match m {
                    MarkerKind::Set { name, .. } => MarkerKind::Secret { name },
                    other => other,
                })
                .collect();
            (stack, markers)
        })
        .collect()
}

/// Blocks if any `<<secret:…>>` is used without a stored value.
pub fn check_unset(report: &SyncReport) -> Result<(), HookError> {
    if report.unset.is_empty() {
        return Ok(());
    }
    let mut list = Vec::new();
    for full in &report.unset {
        let sc = store::parse_full_name(full)?;
        let marker_name = if sc.file == SHARED {
            sc.full_name.clone()
        } else {
            sc.key
        };
        list.push(UnsetSecret {
            full_name: sc.full_name,
            marker_name,
        });
    }
    Err(HookError::Unset(list))
}

/// The working-tree side of a rewrite: `bytes` with every occurrence of a
/// staged marker's exact text replaced by `<<secret:name>>` (leftmost
/// first, never overlapping), or `None` if none occurs. Also the names of
/// the markers that don't occur (the file was edited since `git add`),
/// deduplicated, in order.
pub fn replace_raw<'a>(
    bytes: &[u8],
    sets: &'a [RawSet],
) -> (Option<Zeroizing<Vec<u8>>>, Vec<&'a str>) {
    let at = |i: usize| {
        sets.iter()
            .position(|s| bytes[i..].starts_with(s.raw.expose().as_bytes()))
    };
    // First find every occurrence, so the output (which may hold other,
    // unstaged values) is allocated once and never reallocates.
    let mut hits = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match at(i) {
            Some(k) => {
                hits.push((i, k));
                i += sets[k].raw.expose().len();
            }
            None => i += 1,
        }
    }
    let found = |s: &RawSet| {
        hits.iter()
            .any(|&(_, k)| sets[k].raw.expose() == s.raw.expose())
    };
    let mut missing: Vec<&str> = Vec::new();
    for s in sets.iter().filter(|s| !found(s)) {
        if !missing.contains(&s.name.as_str()) {
            missing.push(&s.name);
        }
    }
    if hits.is_empty() {
        return (None, missing);
    }
    let added: usize = hits
        .iter()
        .map(|&(_, k)| SECRET_OPEN.len() + sets[k].name.len() + MARKER_CLOSE.len())
        .sum();
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len() + added));
    let mut from = 0;
    for (i, k) in hits {
        out.extend_from_slice(&bytes[from..i]);
        out.extend_from_slice(SECRET_OPEN.as_bytes());
        out.extend_from_slice(sets[k].name.as_bytes());
        out.extend_from_slice(MARKER_CLOSE.as_bytes());
        from = i + sets[k].raw.expose().len();
    }
    out.extend_from_slice(&bytes[from..]);
    (Some(out), missing)
}

// ---------------------------------------------------------------------------
// Temporary index
// ---------------------------------------------------------------------------

/// Whether `GIT_INDEX_FILE` (its value, if set) names a temporary index:
/// anything but `index` (a plain `git commit`, also in a linked worktree)
/// or `index.lock` (`git commit -a`/`-i`, which becomes the real index).
/// Unknown names count as temporary, so the hook errs on the side of
/// blocking.
pub fn is_temporary_index(index_file: Option<&OsStr>) -> bool {
    index_file.is_some_and(|f| {
        !matches!(
            Path::new(f).file_name().and_then(OsStr::to_str),
            Some("index" | "index.lock")
        )
    })
}

/// Whether every file the store would write (`Store::to_files`) is staged
/// in `.sec/` with exactly those bytes (`staged`: path below `.sec/` →
/// blob). Extra staged files don't matter.
pub fn sec_in_sync<B: AsRef<[u8]>>(
    files: &BTreeMap<String, String>,
    staged: &BTreeMap<String, B>,
) -> bool {
    files.iter().all(|(name, text)| {
        staged
            .get(name)
            .is_some_and(|b| b.as_ref() == text.as_bytes())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::Format;

    const OID: &str = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391";

    fn entry(mode: &str, path: &str) -> IndexEntry {
        IndexEntry {
            mode: mode.into(),
            oid: OID.into(),
            path: path.into(),
        }
    }

    fn file(path: &str) -> IndexEntry {
        entry("100644", path)
    }

    #[test]
    fn script_is_exact() {
        assert_eq!(
            SCRIPT,
            "#!/bin/sh\n# Installed by lst. Do not edit.\ncommand -v lst >/dev/null 2>&1 || { \
             echo \"lst: not on PATH; commit blocked\" >&2; exit 1; }\nexec lst hook run\n"
        );
    }

    #[test]
    fn classify_roles() {
        let entries = [
            file(".gitignore"),
            file(".sec/meta.toml"),
            file(".sec/web.toml"),
            file("README.md"),
            file("stacks/README.md"),
            file("stacks/.hidden/compose.yaml"),
            file("stacks/.hidden/x"),
            file("stacks/db/compose.yaml"),
            entry("100755", "stacks/db/init.sh"),
            file("stacks/notastack/config"),
            file("stacks/web/compose.yaml"),
            file("stacks/web/config/app.conf"),
            entry("120000", "stacks/web/link"),
            entry("160000", "stacks/web/sub"),
            entry("120000", "elsewhere"),
            file("stacksfoo/compose.yaml"),
        ];
        let roles = classify(&entries).unwrap();
        let stack = |s: &str| Role::Stack(s.into());
        assert_eq!(
            roles,
            [
                Role::Other,
                Role::Sec("meta.toml".into()),
                Role::Sec("web.toml".into()),
                Role::Other,
                Role::Other,
                Role::Other,
                Role::Other,
                stack("db"),
                stack("db"),
                Role::Other,
                stack("web"),
                stack("web"),
                Role::Skip,
                Role::Skip,
                Role::Skip,
                Role::Other,
            ]
        );
        assert_eq!(classify(&[]).unwrap(), []);
    }

    #[test]
    fn classify_accepts_every_compose_file_name() {
        for name in COMPOSE_FILES {
            let entries = [file(&format!("stacks/web/{name}")), file("stacks/web/x")];
            let stack = Role::Stack("web".into());
            assert_eq!(
                classify(&entries).unwrap(),
                [stack.clone(), stack],
                "{name}"
            );
        }
        // Several: still one stack; a shadowed one is an ordinary stack file
        // (its markers are scanned and its <<set:…>> values stored).
        let roles = classify(&[
            file("stacks/web/compose.yaml"),
            file("stacks/web/docker-compose.yml"),
        ])
        .unwrap();
        assert_eq!(
            roles,
            [Role::Stack("web".into()), Role::Stack("web".into())]
        );
        // Not Docker's names: not a stack.
        let roles = classify(&[file("stacks/web/compose.yaml.bak")]).unwrap();
        assert_eq!(roles, [Role::Other]);
        // A shadowed compose file that is a link is refused too.
        let err = classify(&[
            file("stacks/web/compose.yaml"),
            entry("120000", "stacks/web/docker-compose.yml"),
        ])
        .unwrap_err();
        assert!(
            err.to_string()
                .starts_with("stacks/web/docker-compose.yml is a symlink"),
            "{err}"
        );
    }

    #[test]
    fn classify_refuses_links_that_hide_stacks() {
        for (e, want) in [
            (
                entry("120000", "stacks"),
                "stacks is a symlink; git stores it as a link",
            ),
            (entry("120000", "stacks/web"), "stacks/web is a symlink"),
            (
                entry("160000", "stacks/web"),
                "stacks/web is a submodule; lst can't see the files",
            ),
            (
                entry("120000", "stacks/web/compose.yaml"),
                "stacks/web/compose.yaml is a symlink",
            ),
            (
                entry("160000", "stacks/web/compose.yaml"),
                "stacks/web/compose.yaml is a submodule",
            ),
        ] {
            let err = classify(&[file("stacks/ok/compose.yaml"), e]).unwrap_err();
            assert!(err.to_string().starts_with(want), "{err}");
        }
        // Dot-entries are not stacks, links or not.
        let roles = classify(&[
            entry("120000", "stacks/.cache"),
            entry("120000", "stacks/.x/compose.yaml"),
        ])
        .unwrap();
        assert_eq!(roles, [Role::Skip, Role::Skip]);
    }

    #[test]
    fn classify_refuses_bad_stack_names() {
        for (path, want) in [
            (
                "stacks/has space/compose.yaml",
                "invalid stack name \"has space\"",
            ),
            (
                "stacks/Shared/compose.yaml",
                "stack name \"Shared\" is reserved",
            ),
        ] {
            let err = classify(&[file(path)]).unwrap_err();
            assert!(err.to_string().starts_with(want), "{err}");
        }
        let err = classify(&[
            file("stacks/App/compose.yaml"),
            file("stacks/app/compose.yaml"),
        ])
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "stacks \"App\" and \"app\" differ only in case; rename one"
        );
        // Without a compose.yaml a bad name is just a directory.
        assert_eq!(
            classify(&[file("stacks/has space/x")]).unwrap(),
            [Role::Other]
        );
    }

    fn raw_names(r: &Rewrite) -> Vec<(&str, &str, &str)> {
        r.sets
            .iter()
            .map(|s| (s.name.as_str(), s.raw.expose(), s.value.expose()))
            .collect()
    }

    #[test]
    fn rewrite_replaces_only_set_spans() {
        let text =
            "a: <<gen:db>>\nb: \"<<set:cf:to\\>>k:en>>\" <<secret:x>>\nü <<set:shared/m:v>>!\n";
        let rw = rewrite_sets("p", text.as_bytes()).unwrap().unwrap();
        assert_eq!(
            rw.text.expose(),
            "a: <<gen:db>>\nb: \"<<secret:cf>>\" <<secret:x>>\nü <<secret:shared/m>>!\n"
        );
        assert_eq!(
            raw_names(&rw),
            [
                ("cf", "<<set:cf:to\\>>k:en>>", "to>>k:en"),
                ("shared/m", "<<set:shared/m:v>>", "v"),
            ]
        );
        // One-byte values make the text longer; still within the reserve.
        let rw = rewrite_sets("p", b"<<set:a:1>><<set:b:2>>")
            .unwrap()
            .unwrap();
        assert_eq!(rw.text.expose(), "<<secret:a>><<secret:b>>");
        assert!(!format!("{rw:?}").contains("to>>k"));
    }

    #[test]
    fn rewrite_skips_files_without_sets() {
        assert!(
            rewrite_sets("p", b"<<gen:db>> <<secret:x>>")
                .unwrap()
                .is_none()
        );
        assert!(rewrite_sets("p", b"").unwrap().is_none());
        assert!(rewrite_sets("p", b"\xff<<set:x:v>>").unwrap().is_none());
        let err = rewrite_sets("stacks/w/c", b"ok\n<<set:x:a\\b>>").unwrap_err();
        assert_eq!(
            err.to_string(),
            "stacks/w/c:2:10: invalid escape in value (only `\\\\` and `\\>` are allowed)"
        );
    }

    fn set_file(path: &str, stack: &str, text: &str) -> SetFile {
        SetFile {
            path: path.into(),
            stack: stack.into(),
            mode: "100644".into(),
            rewrite: rewrite_sets(path, text.as_bytes()).unwrap().unwrap(),
        }
    }

    #[test]
    fn values_dedupe_by_full_name() {
        let files = [
            set_file(
                "stacks/a/compose.yaml",
                "a",
                "<<set:x:1>> <<set:shared/s:z>> <<set:x:1>>",
            ),
            set_file(
                "stacks/b/compose.yaml",
                "b",
                "<<set:x:2>> <<set:shared/s:z>>",
            ),
        ];
        let got = values_to_store(&files).unwrap();
        let got: Vec<_> = got
            .iter()
            .map(|t| (t.stack, t.name, t.full_name.as_str(), t.value.expose()))
            .collect();
        assert_eq!(
            got,
            [
                ("a", "x", "a/x", "1"),
                ("a", "shared/s", "shared/s", "z"),
                ("b", "x", "b/x", "2"),
            ]
        );
        assert!(values_to_store(&[]).unwrap().is_empty());
    }

    #[test]
    fn conflicting_values_are_refused_without_the_values() {
        let files = [
            set_file("stacks/a/x.env", "a", "<<set:shared/s:hunter2>>"),
            set_file("stacks/b/y.env", "b", "<<set:shared/s:hunter3>>"),
        ];
        let err = values_to_store(&files).unwrap_err();
        let msg = err.to_string();
        assert_eq!(
            msg,
            "`shared/s`: <<set:…>> is used with different values in stacks/a/x.env and \
             stacks/b/y.env; give it one value (or use different names)"
        );
        assert!(!format!("{msg} {err:?}").contains("hunter"));
        let files = [set_file("stacks/a/c", "a", "<<set:k:1>>\n<<set:k:2>>")];
        assert!(
            values_to_store(&files)
                .unwrap_err()
                .to_string()
                .contains("`a/k`: <<set:…>> is used with different values in stacks/a/c; give")
        );
        // An invalid name can't come out of the parser; scope still checks.
        let mut bad = set_file("stacks/a/c", "a", "<<set:k:1>>");
        bad.stack = "no such/stack".into();
        assert!(matches!(
            values_to_store(&[bad]).unwrap_err(),
            HookError::Store(StoreError::InvalidStack(_))
        ));
    }

    #[test]
    fn set_uses_become_secret_uses() {
        let rw = rewrite_sets("p", b"<<set:cf:v>>").unwrap().unwrap();
        let mut uses = Uses::new();
        uses.insert(
            "web".into(),
            vec![
                MarkerKind::Gen {
                    name: "db".into(),
                    format: Format::default(),
                },
                MarkerKind::Set {
                    name: "cf".into(),
                    value: rw.sets[0].value.clone(),
                },
                MarkerKind::Secret { name: "x".into() },
            ],
        );
        uses.insert("empty".into(), vec![]);
        let got = secret_uses(uses);
        assert_eq!(got.keys().collect::<Vec<_>>(), ["empty", "web"]);
        assert!(
            matches!(
                got["web"].as_slice(),
                [
                    MarkerKind::Gen { name: a, .. },
                    MarkerKind::Secret { name: b },
                    MarkerKind::Secret { name: c },
                ] if a == "db" && b == "cf" && c == "x"
            ),
            "{got:?}"
        );
    }

    #[test]
    fn unset_secrets_block() {
        check_unset(&SyncReport::default()).unwrap();
        let report = SyncReport {
            unset: vec!["shared/smtp".into(), "web/cf".into(), "web/a/b".into()],
            ..SyncReport::default()
        };
        let err = check_unset(&report).unwrap_err();
        assert_eq!(
            err.to_string(),
            "cannot commit: 3 secrets not set:\n  \
             `shared/smtp` is not set; write <<set:shared/smtp:VALUE>> to set it\n  \
             `web/cf` is not set; write <<set:cf:VALUE>> to set it\n  \
             `web/a/b` is not set; write <<set:a/b:VALUE>> to set it"
        );
        let one = SyncReport {
            unset: vec!["web/cf".into()],
            ..SyncReport::default()
        };
        assert!(
            check_unset(&one)
                .unwrap_err()
                .to_string()
                .starts_with("cannot commit: 1 secret not set:\n")
        );
        let bad = SyncReport {
            unset: vec!["nope".into()],
            ..SyncReport::default()
        };
        assert!(matches!(
            check_unset(&bad).unwrap_err(),
            HookError::Store(StoreError::InvalidFullName(_))
        ));
    }

    fn sets(text: &str) -> Vec<RawSet> {
        rewrite_sets("p", text.as_bytes()).unwrap().unwrap().sets
    }

    #[test]
    fn replace_raw_in_the_working_tree() {
        let s = sets("<<set:a:1>> <<set:b:x\\\\y>> <<set:a:1>>");
        // Partial staging: an extra unstaged line survives; every
        // occurrence is replaced.
        let wt = b"<<set:a:1>>\n<<set:b:x\\\\y>> wip <<set:a:1>><<set:a:1>>\n";
        let (out, missing) = replace_raw(wt, &s);
        assert_eq!(
            &**out.unwrap(),
            b"<<secret:a>>\n<<secret:b>> wip <<secret:a>><<secret:a>>\n"
        );
        assert!(missing.is_empty());

        // A marker edited since `git add` is left alone and reported once.
        let (out, missing) = replace_raw(b"<<set:a:2>> <<set:b:x\\\\y>>", &s);
        assert_eq!(&**out.unwrap(), b"<<set:a:2>> <<secret:b>>");
        assert_eq!(missing, ["a"]);
        let (out, missing) = replace_raw(b"nothing here", &s);
        assert!(out.is_none());
        assert_eq!(missing, ["a", "b"]);
        // Non-UTF-8 bytes around it are fine.
        let (out, _) = replace_raw(b"\xff<<set:a:1>>\xfe", &s);
        assert_eq!(&**out.unwrap(), b"\xff<<secret:a>>\xfe");
        let (out, missing) = replace_raw(b"", &[]);
        assert!(out.is_none() && missing.is_empty());
    }

    #[test]
    fn temporary_index_detection() {
        let t = |s: Option<&str>| is_temporary_index(s.map(OsStr::new));
        assert!(!t(None));
        assert!(!t(Some(".git/index")));
        assert!(!t(Some("/r/.git/index.lock")));
        assert!(!t(Some("/r/.git/worktrees/wt/index")));
        assert!(t(Some("/r/.git/next-index-123.lock")));
        assert!(t(Some("/tmp/custom")));
        assert!(t(Some("")));
    }

    #[test]
    fn sec_in_sync_compares_store_files() {
        let files: BTreeMap<String, String> = [
            ("meta.toml".to_owned(), "m".to_owned()),
            ("web.toml".to_owned(), "w".to_owned()),
        ]
        .into();
        let staged = |list: &[(&str, &str)]| -> BTreeMap<String, Vec<u8>> {
            list.iter()
                .map(|(k, v)| ((*k).to_owned(), v.as_bytes().to_vec()))
                .collect()
        };
        assert!(sec_in_sync(
            &files,
            &staged(&[("meta.toml", "m"), ("web.toml", "w"), ("extra", "x")])
        ));
        assert!(!sec_in_sync(&files, &staged(&[("meta.toml", "m")])));
        assert!(!sec_in_sync(
            &files,
            &staged(&[("meta.toml", "m"), ("web.toml", "old")])
        ));
    }
}
