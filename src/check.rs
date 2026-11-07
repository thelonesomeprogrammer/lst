//! `lst check`: everything that would make a deploy wrong, collected rather
//! than stopping at the first. Pure: `cli` loads `.sec/`, the working-tree
//! stack files and the committed blobs; this module decides what is wrong.
//!
//! # What is checked
//! - **`.sec/` is current** ([`working_tree`]): a dry-run [`Store::sync`]
//!   on a copy of the store, over the same files `lst sync` reads, changes
//!   nothing (no new name, format change, orphan or un-orphan), and the
//!   store would write exactly the bytes that are on disk. A `<<set:…>>` in
//!   the working tree is a problem too (it isn't committed yet); for the
//!   dry run it counts as the `<<secret:…>>` the hook will turn it into.
//! - **Every `<<secret:…>>` has a value** ([`working_tree`]), except names
//!   that a working-tree `<<set:…>>` is about to set (already reported).
//! - **No `<<set:` in any committed blob** ([`committed_set`]; `cli` feeds
//!   it every regular file of the `HEAD` tree, inside `stacks/` or not):
//!   such a value is in git history and must be rotated.
//! - **With a seed** ([`resolution`]): it is the store's seed, and every
//!   marker of every scanned file resolves (every ciphertext decrypts).
//!   Values are dropped (zeroized) as soon as they are computed. Failures
//!   that the structural checks already report (a missing gen entry, a
//!   pending format change, an unset secret, a `<<set:…>>`) are not
//!   repeated.
//!
//! - **`x-deploy` is valid** ([`xdeploy`]): every stack that uses it
//!   passes [`crate::xdeploy::check`] (structural: YAML, the model, its
//!   service and file references, labels); none hides the key where
//!   [`crate::xdeploy::detect`] can't see it.
//!
//! Every [`Problem`] names files and secrets only, never a value.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::crypto::Seed;
use crate::hook;
use crate::scan::{self, ScanError, StackFiles};
use crate::stack::{COMPOSE_FILE, STACKS_DIR};
use crate::store::{FormatChange, META, ResolveError, SHARED, Store, StoreError};
use crate::xdeploy::{self, Detected, XDeployError};

/// The hint for every "`.sec/` is not current" problem.
const SYNC_HINT: &str = "run `lst sync` and commit .sec/ (the pre-commit hook does this when \
     you commit)";

/// One thing `lst check` found wrong.
#[derive(Debug)]
pub enum Problem {
    /// A `<<set:…>>` in a working-tree stack file.
    SetInWorkingTree { path: String, name: String },
    /// The markers can't be synced at all (e.g. one name with two formats).
    Conflict(StoreError),
    /// A gen name with no entry in `.sec/`.
    New { name: String },
    /// A gen name used with another format than the stored one.
    FormatChanged(FormatChange),
    /// An entry no longer used but not marked as an orphan.
    Orphaned { name: String },
    /// An entry marked as an orphan but used again.
    Unorphaned { name: String },
    /// A `.sec/` file whose bytes differ from what lst would write.
    NotCanonical { file: String },
    /// A `<<secret:…>>` with no stored value.
    Unset { name: String, marker_name: String },
    /// A committed blob containing `<<set:`.
    CommittedSet { path: String },
    /// The seed is not the one `.sec/` was made with.
    WrongSeed,
    /// A marker of `path` that does not resolve.
    Unresolvable { path: String, error: ResolveError },
    /// A stack's `x-deploy` section (or its YAML) is invalid.
    XDeploy(XDeployError),
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Problem::SetInWorkingTree { path, name } => write!(
                f,
                "{path}: <<set:{name}:…>> is not committed yet; commit the file, and the \
                 pre-commit hook encrypts the value into .sec/ and rewrites the marker to \
                 <<secret:{name}>>"
            ),
            Problem::Conflict(e) => write!(f, "{e}"),
            Problem::New { name } => {
                write!(f, ".sec/ is not current: {name} is new; {SYNC_HINT}")
            }
            Problem::FormatChanged(c) => write!(
                f,
                ".sec/ is not current: {} changed format ({} -> {}); {SYNC_HINT}",
                c.name, c.from, c.to
            ),
            Problem::Orphaned { name } => write!(
                f,
                ".sec/ is not current: {name} is no longer used but not marked as an orphan; \
                 {SYNC_HINT}"
            ),
            Problem::Unorphaned { name } => write!(
                f,
                ".sec/ is not current: {name} is used again but marked as an orphan; \
                 {SYNC_HINT}"
            ),
            Problem::NotCanonical { file } => write!(
                f,
                "{file} is not as lst writes it (edited by hand?); run `lst sync` to rewrite \
                 it and commit it"
            ),
            Problem::Unset { name, marker_name } => {
                let e = ResolveError::SecretUnset {
                    name: name.clone(),
                    marker_name: marker_name.clone(),
                };
                write!(f, "{e}")
            }
            Problem::CommittedSet { path } => write!(
                f,
                "{path}: a <<set:…>> value is in git history; rotate the secret (set a new \
                 value), the old one must be considered leaked"
            ),
            Problem::WrongSeed => write!(f, "{}", StoreError::FingerprintMismatch),
            Problem::Unresolvable { path, error } => write!(f, "{path}: {error}"),
            Problem::XDeploy(e) => write!(f, "{e}"),
        }
    }
}

/// `.sec/` as [`Store::read_files`] returned it, keyed like
/// [`Store::to_files`] (`meta.toml`, `<stem>.toml`).
pub fn loaded_files(meta: &str, stacks: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    out.insert(format!("{META}.toml"), meta.to_owned());
    for (stem, text) in stacks {
        out.insert(format!("{stem}.toml"), text.clone());
    }
    out
}

/// The full name of marker name `name` used in `stack` (`shared/…` names
/// are their own full name). Names come from the marker parser, so no
/// validation is needed for comparing.
fn full_name(stack: &str, name: &str) -> String {
    if name.starts_with("shared/") {
        name.to_owned()
    } else {
        format!("{stack}/{name}")
    }
}

/// The marker name a user writes for full name `full` (`web/cf` → `cf`,
/// `shared/x` → `shared/x`).
fn marker_name(full: &str) -> &str {
    match full.split_once('/') {
        Some((file, key)) if file != SHARED => key,
        _ => full,
    }
}

/// The working-tree checks: `<<set:…>>` markers, whether `.sec/` is
/// current (`loaded`: the files as they are on disk, see
/// [`loaded_files`]), and unset secrets. `files` are the stack files `lst
/// sync` reads. A malformed marker is an error, not a problem: nothing
/// about the files can be decided then.
pub fn working_tree<B: AsRef<[u8]>>(
    store: &Store,
    loaded: &BTreeMap<String, String>,
    files: &StackFiles<B>,
) -> Result<Vec<Problem>, ScanError> {
    let scan = scan::collect(files)?;
    let mut problems = Vec::new();
    let mut being_set = BTreeSet::new();
    for s in scan.sets {
        being_set.insert(full_name(&s.stack, &s.name));
        problems.push(Problem::SetInWorkingTree {
            path: s.path,
            name: s.name,
        });
    }

    let mut dry = store.clone();
    let report = match dry.sync(&hook::secret_uses(scan.uses)) {
        Ok(report) => report,
        Err(e) => {
            problems.push(Problem::Conflict(e));
            return Ok(problems);
        }
    };
    let changed = !(report.added.is_empty()
        && report.format_changed.is_empty()
        && report.orphaned.is_empty()
        && report.unorphaned.is_empty());
    problems.extend(report.added.into_iter().map(|name| Problem::New { name }));
    problems.extend(
        report
            .format_changed
            .into_iter()
            .map(Problem::FormatChanged),
    );
    problems.extend(
        report
            .orphaned
            .into_iter()
            .map(|name| Problem::Orphaned { name }),
    );
    problems.extend(
        report
            .unorphaned
            .into_iter()
            .map(|name| Problem::Unorphaned { name }),
    );
    // With pending changes every touched file differs anyway; only an
    // otherwise current store is compared byte for byte.
    if !changed {
        for (file, text) in dry.to_files() {
            if loaded.get(&file) != Some(&text) {
                let file = format!(".sec/{file}");
                problems.push(Problem::NotCanonical { file });
            }
        }
    }
    for name in report.unset {
        if !being_set.contains(&name) {
            let marker_name = marker_name(&name).to_owned();
            problems.push(Problem::Unset { name, marker_name });
        }
    }
    Ok(problems)
}

/// The problem with committed blob `path`, if it contains `<<set:`
/// (anywhere, valid marker or not, in any file).
pub fn committed_set(path: &str, blob: &[u8]) -> Option<Problem> {
    scan::contains_set(blob).then(|| Problem::CommittedSet {
        path: path.to_owned(),
    })
}

/// The `x-deploy` checks: one problem per stack whose `compose.yaml` takes
/// the YAML path and fails [`xdeploy::check`], or hides the key
/// ([`Detected::Hidden`]). `files` are the stack files `lst sync` reads
/// (the scope a `render:` `from` must be in). A stack whose `compose.yaml`
/// isn't among them or isn't UTF-8 is skipped: [`working_tree`] reports
/// the latter.
pub fn xdeploy<B: AsRef<[u8]>>(files: &StackFiles<B>) -> Vec<Problem> {
    let mut problems = Vec::new();
    for (stack, list) in files {
        let compose = format!("{STACKS_DIR}/{stack}/{COMPOSE_FILE}");
        let text = list
            .iter()
            .find(|(p, _)| *p == compose)
            .and_then(|(_, b)| std::str::from_utf8(b.as_ref()).ok());
        let result = match text.map(|t| (t, xdeploy::detect(t))) {
            None | Some((_, Detected::Raw)) => continue,
            Some((_, Detected::Hidden)) => Err(XDeployError::Hidden { path: compose }),
            Some((t, Detected::XDeploy)) => xdeploy::check(stack, t, list).map(drop),
        };
        if let Err(e) = result {
            problems.push(Problem::XDeploy(e));
        }
    }
    problems
}

/// The seed checks: `seed` is the store's, and every marker of every file
/// resolves (at most one problem per file and marker name). Failures the
/// structural checks report are skipped (see the module docs). A malformed
/// marker is an error, as in [`working_tree`].
pub fn resolution<B: AsRef<[u8]>>(
    store: &Store,
    seed: &Seed,
    files: &StackFiles<B>,
) -> Result<Vec<Problem>, ScanError> {
    if store.verify_seed(seed).is_err() {
        return Ok(vec![Problem::WrongSeed]);
    }
    let mut problems = Vec::new();
    for (stack, list) in files {
        let mut list: Vec<_> = list.iter().collect();
        list.sort_by(|a, b| a.0.cmp(&b.0));
        for (path, bytes) in list {
            let mut reported = BTreeSet::new();
            for m in scan::scan_file(stack, path, bytes.as_ref())? {
                let error = match store.resolve(seed, stack, &m) {
                    // The value is dropped (zeroized) right here.
                    Ok(_) => continue,
                    Err(
                        ResolveError::GenMissing { .. }
                        | ResolveError::FormatMismatch { .. }
                        | ResolveError::SecretUnset { .. }
                        | ResolveError::SetMarker { .. },
                    ) => continue,
                    Err(error) => error,
                };
                if reported.insert(m.name().to_owned()) {
                    let path = path.clone();
                    problems.push(Problem::Unresolvable { path, error });
                }
            }
        }
    }
    Ok(problems)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SEED_LEN;

    fn seed(b: u8) -> Seed {
        Seed::from_bytes([b; SEED_LEN])
    }

    type Files = StackFiles<Vec<u8>>;

    fn files(list: &[(&str, &[(&str, &str)])]) -> Files {
        list.iter()
            .map(|(stack, fs)| {
                let fs = fs
                    .iter()
                    .map(|(p, t)| ((*p).to_owned(), t.as_bytes().to_vec()))
                    .collect();
                ((*stack).to_owned(), fs)
            })
            .collect()
    }

    /// A store synced to `files`, with `secrets` (stack, name, value) set.
    fn store_for(files: &Files, secrets: &[(&str, &str, &str)]) -> Store {
        let mut store = Store::init(&seed(1));
        for (stack, name, value) in secrets {
            store.set_secret(&seed(1), stack, name, value).unwrap();
        }
        let uses = scan::collect(files).unwrap().uses;
        store.sync(&hook::secret_uses(uses)).unwrap();
        store
    }

    /// The store's files as they would be on disk.
    fn on_disk(store: &Store) -> BTreeMap<String, String> {
        store.to_files()
    }

    fn messages(problems: &[Problem]) -> Vec<String> {
        problems.iter().map(ToString::to_string).collect()
    }

    const WEB: &str = "stacks/web/compose.yaml";

    #[test]
    fn a_current_store_has_no_problems() {
        let f = files(&[
            (
                "web",
                &[
                    (
                        WEB,
                        "a: <<gen:db>>\nb: <<secret:cf>>\nc: <<gen:shared/m:hex32>>\n",
                    ),
                    ("stacks/web/conf", "<<secret:shared/s>>"),
                ],
            ),
            ("empty", &[]),
        ]);
        let store = store_for(&f, &[("web", "cf", "v1"), ("web", "shared/s", "v2")]);
        assert!(
            working_tree(&store, &on_disk(&store), &f)
                .unwrap()
                .is_empty()
        );
        assert!(resolution(&store, &seed(1), &f).unwrap().is_empty());
    }

    #[test]
    fn pending_sync_changes_are_listed() {
        let before = files(&[(
            "web",
            &[(WEB, "a: <<gen:db>>\nb: <<gen:api>>\nc: <<gen:old>>\n")],
        )]);
        let mut store = store_for(&before, &[]);
        // `old` becomes an orphan in the store, then comes back.
        let without_old = files(&[("web", &[(WEB, "a: <<gen:db>>\nb: <<gen:api>>\n")])]);
        store
            .sync(&scan::collect(&without_old).unwrap().uses)
            .unwrap();
        let now = files(&[(
            "web",
            &[(WEB, "a: <<gen:db:hex32>>\nc: <<gen:old>>\nd: <<gen:new>>\n")],
        )]);
        let disk = on_disk(&store);
        let problems = working_tree(&store, &disk, &now).unwrap();
        assert_eq!(
            messages(&problems),
            [
                ".sec/ is not current: web/new is new; run `lst sync` and commit .sec/ (the \
                 pre-commit hook does this when you commit)",
                ".sec/ is not current: web/db changed format (alnum32 -> hex32); run `lst \
                 sync` and commit .sec/ (the pre-commit hook does this when you commit)",
                ".sec/ is not current: web/api is no longer used but not marked as an orphan; \
                 run `lst sync` and commit .sec/ (the pre-commit hook does this when you commit)",
                ".sec/ is not current: web/old is used again but marked as an orphan; run `lst \
                 sync` and commit .sec/ (the pre-commit hook does this when you commit)",
            ]
        );
        // Dry run: the store itself is untouched.
        assert_eq!(store.to_files(), disk);
        // Pending changes are not resolution problems as well.
        assert!(resolution(&store, &seed(1), &now).unwrap().is_empty());
    }

    #[test]
    fn hand_edited_or_missing_files_are_not_canonical() {
        let f = files(&[("web", &[(WEB, "a: <<gen:db>>\n")])]);
        let store = store_for(&f, &[]);
        let mut disk = on_disk(&store);
        disk.insert(
            "web.toml".into(),
            disk["web.toml"].replace("orphan = false", "orphan=false"),
        );
        disk.remove("meta.toml");
        assert_eq!(
            messages(&working_tree(&store, &disk, &f).unwrap()),
            [
                ".sec/meta.toml is not as lst writes it (edited by hand?); run `lst sync` to \
                 rewrite it and commit it",
                ".sec/web.toml is not as lst writes it (edited by hand?); run `lst sync` to \
                 rewrite it and commit it",
            ]
        );
    }

    #[test]
    fn sets_in_the_working_tree_and_unset_secrets() {
        let f = files(&[
            (
                "web",
                &[(
                    WEB,
                    "a: <<set:cf:hunter2>>\nb: <<secret:tok>>\nc: <<set:shared/m:hunter3>>\n",
                )],
            ),
            (
                "db",
                &[("stacks/db/compose.yaml", "<<secret:shared/smtp>>")],
            ),
        ]);
        // `web/cf` already has a value (it is being replaced), `shared/m`
        // has none yet: neither is reported as unset.
        let used = files(&[("web", &[(WEB, "<<secret:cf>>")])]);
        let store = store_for(&used, &[("web", "cf", "old")]);
        let problems = working_tree(&store, &on_disk(&store), &f).unwrap();
        let msgs = messages(&problems);
        assert_eq!(
            msgs,
            [
                "stacks/web/compose.yaml: <<set:cf:…>> is not committed yet; commit the file, \
                 and the pre-commit hook encrypts the value into .sec/ and rewrites the marker \
                 to <<secret:cf>>",
                "stacks/web/compose.yaml: <<set:shared/m:…>> is not committed yet; commit the \
                 file, and the pre-commit hook encrypts the value into .sec/ and rewrites the \
                 marker to <<secret:shared/m>>",
                "`shared/smtp` is not set; write <<set:shared/smtp:VALUE>> to set it",
                "`web/tok` is not set; write <<set:tok:VALUE>> to set it",
            ]
        );
        let all = format!("{msgs:?} {problems:?}");
        assert!(!all.contains("hunter"), "{all}");
        // Resolution skips them too (the structural problems cover them).
        assert!(resolution(&store, &seed(1), &f).unwrap().is_empty());
    }

    #[test]
    fn conflicts_stop_the_sync_checks() {
        let f = files(&[(
            "web",
            &[(
                WEB,
                "<<set:x:v>> <<gen:db>> <<gen:db:uuid>> <<secret:unset>>",
            )],
        )]);
        let store = store_for(&files(&[]), &[]);
        let problems = working_tree(&store, &on_disk(&store), &f).unwrap();
        assert!(matches!(
            problems.as_slice(),
            [
                Problem::SetInWorkingTree { .. },
                Problem::Conflict(StoreError::FormatConflict { .. })
            ]
        ));
        assert_eq!(
            problems[1].to_string(),
            "`web/db` is used with two different formats: alnum32 and uuid"
        );
    }

    #[test]
    fn malformed_markers_are_errors() {
        let f = files(&[("web", &[(WEB, "a: <<gen:db\n")])]);
        let store = store_for(&files(&[]), &[]);
        let want = "stacks/web/compose.yaml:1:4: unterminated marker (missing `>>`)";
        let err = working_tree(&store, &on_disk(&store), &f).unwrap_err();
        assert_eq!(err.to_string(), want);
        let err = resolution(&store, &seed(1), &f).unwrap_err();
        assert_eq!(err.to_string(), want);
    }

    #[test]
    fn committed_sets_anywhere() {
        assert!(committed_set("README.md", b"no marker <<set").is_none());
        let p = committed_set("docs/x.bin", b"\xff<<set:cf:hunter2").unwrap();
        assert_eq!(
            p.to_string(),
            "docs/x.bin: a <<set:…>> value is in git history; rotate the secret (set a new \
             value), the old one must be considered leaked"
        );
        assert!(!format!("{p:?}").contains("hunter2"));
    }

    #[test]
    fn wrong_seed_is_one_problem() {
        let f = files(&[("web", &[(WEB, "<<gen:db>>")])]);
        let store = store_for(&f, &[]);
        let problems = resolution(&store, &seed(2), &f).unwrap();
        assert_eq!(
            messages(&problems),
            ["wrong seed: its fingerprint does not match .sec/meta.toml"]
        );
    }

    /// `store` with the first ciphertext hex digit of `stem`/`key` changed.
    fn corrupt(store: &Store, stem: &str, key: &str) -> Store {
        let mut files = store.to_files();
        let meta = files.remove("meta.toml").unwrap();
        let mut stems: BTreeMap<String, String> = files
            .into_iter()
            .map(|(k, v)| (k.trim_end_matches(".toml").to_owned(), v))
            .collect();
        let text = &stems[stem];
        let at = text.find(&format!("[secret.{key}]")).unwrap();
        let at = at + text[at..].find("ciphertext = \"").unwrap() + "ciphertext = \"".len();
        let digit = u8::from_str_radix(&text[at..=at], 16).unwrap() ^ 1;
        let text = format!("{}{digit:x}{}", &text[..at], &text[at + 1..]);
        stems.insert(stem.to_owned(), text);
        Store::from_files(&meta, &stems).unwrap()
    }

    #[test]
    fn undecryptable_secrets_are_reported_per_file() {
        let f = files(&[
            (
                "web",
                &[
                    ("stacks/web/z.conf", "<<secret:shared/s>>"),
                    (WEB, "<<secret:cf>> <<secret:cf>> <<secret:ok>> <<gen:db>>"),
                ],
            ),
            ("db", &[("stacks/db/compose.yaml", "<<secret:shared/s>>")]),
        ]);
        let good = store_for(
            &f,
            &[
                ("web", "cf", "hunter2"),
                ("web", "ok", "v"),
                ("web", "shared/s", "x"),
            ],
        );
        let bad = corrupt(&corrupt(&good, "web", "cf"), "shared", "s");
        // Structurally fine: the files are what lst writes for this store.
        assert!(working_tree(&bad, &on_disk(&bad), &f).unwrap().is_empty());
        let problems = resolution(&bad, &seed(1), &f).unwrap();
        let msgs = messages(&problems);
        let decrypt = "decryption failed (wrong seed, wrong name, or corrupted ciphertext)";
        assert_eq!(
            msgs,
            [
                format!("stacks/db/compose.yaml: `shared/s`: {decrypt}"),
                format!("stacks/web/compose.yaml: `web/cf`: {decrypt}"),
                format!("stacks/web/z.conf: `shared/s`: {decrypt}"),
            ]
        );
        assert!(!format!("{msgs:?} {problems:?}").contains("hunter2"));
    }

    #[test]
    fn x_deploy_problems_per_stack() {
        let f = files(&[
            // Valid, with a render: file in scope.
            (
                "ok",
                &[
                    (
                        "stacks/ok/compose.yaml",
                        "services: {a: {}}\nx-deploy:\n  render: [{from: c.conf, to: /x}]\n",
                    ),
                    ("stacks/ok/c.conf", "<<gen:x>>"),
                ],
            ),
            // The file is another stack's.
            (
                "web",
                &[(
                    WEB,
                    "x-deploy:\n  render: [{from: c.conf, to: /x}]\na: <<set:x:hunter2>>\n",
                )],
            ),
            (
                "hidden",
                &[("stacks/hidden/compose.yaml", "{x-deploy: {}}\n")],
            ),
            (
                "yaml",
                &[("stacks/yaml/compose.yaml", "x-deploy: {}\na: [\n")],
            ),
            // Not checked: no x-deploy, invalid YAML on the raw path, no
            // compose.yaml in scope, not UTF-8.
            ("raw", &[("stacks/raw/compose.yaml", "a: [x-deploy\n")]),
            ("none", &[("stacks/none/other", "x-deploy: 1\n")]),
        ]);
        let mut f = f;
        f.insert(
            "bin".into(),
            vec![(
                "stacks/bin/compose.yaml".into(),
                b"x-deploy: 1\n\xff".to_vec(),
            )],
        );
        let problems = xdeploy(&f);
        let msgs = messages(&problems);
        assert_eq!(
            msgs,
            [
                "stacks/hidden/compose.yaml: write the top-level x-deploy key at the start of a \
                 line (`x-deploy:`); lst decides which stacks use x-deploy from that line",
                "stacks/web/compose.yaml: x-deploy.render[0].from: no such file in stacks/web/ \
                 (it must be a regular file that git would commit: not gitignored, not a \
                 symlink)",
                "stacks/yaml/compose.yaml:3:1: invalid YAML (lst does not show the parser's \
                 message: it can quote the file, and so a secret)",
            ]
        );
        assert!(!format!("{msgs:?} {problems:?}").contains("hunter2"));
    }

    #[test]
    fn helpers() {
        assert_eq!(full_name("web", "db"), "web/db");
        assert_eq!(full_name("web", "shared/x"), "shared/x");
        assert_eq!(full_name("web", "a/b"), "web/a/b");
        assert_eq!(marker_name("web/cf"), "cf");
        assert_eq!(marker_name("web/a/b"), "a/b");
        assert_eq!(marker_name("shared/x"), "shared/x");
        assert_eq!(marker_name("odd"), "odd");
        let stacks: BTreeMap<String, String> = [("web".to_owned(), "w".to_owned())].into();
        let got = loaded_files("m", &stacks);
        assert_eq!(
            got.into_iter().collect::<Vec<_>>(),
            [
                ("meta.toml".to_owned(), "m".to_owned()),
                ("web.toml".to_owned(), "w".to_owned()),
            ]
        );
    }
}
