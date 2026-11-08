//! Which markers a set of files uses: the input of [`Store::sync`].
//!
//! Pure (no filesystem): the caller supplies `(path, bytes)` per stack.
//! `lst sync` passes the working-tree files of every stack; the pre-commit
//! hook passes the staged blobs of the same paths, so both see the same
//! scope (every file under `stacks/<stack>/`).
//!
//! # Rules
//! - A file that is valid UTF-8 is parsed for markers; a malformed marker
//!   is an error at `path:line:col`.
//! - A file that is not valid UTF-8 can't be parsed, so it is skipped,
//!   unless its bytes contain `<<set:`: that may be a plaintext value lst
//!   can't process, so it is an error (fail closed).
//! - The stack's compose files (any of [`COMPOSE_FILES`] directly in its
//!   directory, shadowed ones included) must be valid UTF-8 (skipping one
//!   would orphan everything it uses).
//! - Files are processed in byte order of their paths, whatever order the
//!   caller passes them in, so results and the first error reported are
//!   deterministic.
//!
//! `<<set:…>>` markers are kept in [`Scan::uses`] (with their values,
//! zeroized on drop) and also listed by location in [`Scan::sets`]; callers
//! must store them (hook) or refuse them (`lst sync`) before calling
//! [`Store::sync`], which refuses them.
//!
//! [`Store::sync`]: crate::store::Store::sync

use std::collections::BTreeMap;

use crate::marker::{self, MarkerKind, ParseError, ParseErrorKind};
use crate::stack::{COMPOSE_FILES, Layout};

/// Stack name → every marker used in its files, in file order.
pub type Uses = BTreeMap<String, Vec<MarkerKind>>;

/// Stack name → `(repo-relative path, contents)` of its files: the input of
/// [`collect`]. `B` is any byte buffer (`Vec<u8>`, `Zeroizing<Vec<u8>>`).
pub type StackFiles<B> = BTreeMap<String, Vec<(String, B)>>;

/// The bytes that open a `<<set:…>>` marker.
const SET_OPEN: &[u8] = b"<<set:";

/// Where a `<<set:…>>` marker was found. Holds no value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetSite {
    /// Repo-relative path, as passed in.
    pub path: String,
    pub stack: String,
    /// The marker name as written (`cf`, `shared/smtp`).
    pub name: String,
}

/// What [`collect`] found.
#[derive(Debug, Default)]
pub struct Scan {
    /// One entry per stack passed in, also for stacks without markers.
    pub uses: Uses,
    /// Every `<<set:…>>`, in file and text order.
    pub sets: Vec<SetSite>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScanError {
    #[error("{path}:{line}:{col}: {kind}")]
    Parse {
        path: String,
        line: usize,
        col: usize,
        kind: ParseErrorKind,
    },
    #[error("{path}: not valid UTF-8; convert the file to UTF-8")]
    ComposeNotUtf8 { path: String },
    #[error(
        "{path}: not valid UTF-8 but contains `<<set:`; lst only processes markers in UTF-8 \
         text, so a value there would be committed as plaintext. Convert the file to UTF-8"
    )]
    SetInNonUtf8 { path: String },
}

/// A marker parse error in `text` (the contents of `path`), located as
/// `path:line:col`.
pub fn parse_error(path: &str, text: &str, e: ParseError) -> ScanError {
    let (line, col) = marker::line_col(text, e.pos);
    ScanError::Parse {
        path: path.to_owned(),
        line,
        col,
        kind: e.kind,
    }
}

/// Whether `bytes` contain `<<set:` anywhere, valid marker or not (a value
/// lst would have to keep out of a commit).
pub fn contains_set(bytes: &[u8]) -> bool {
    bytes.windows(SET_OPEN.len()).any(|w| w == SET_OPEN)
}

/// The markers in one file of `stack` (see the module docs for the rules).
pub fn scan_file(
    layout: &Layout,
    stack: &str,
    path: &str,
    bytes: &[u8],
) -> Result<Vec<MarkerKind>, ScanError> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        let path = path.to_owned();
        if contains_set(bytes) {
            return Err(ScanError::SetInNonUtf8 { path });
        }
        let name = path.strip_prefix(&layout.stack_prefix(stack));
        if name.is_some_and(|n| COMPOSE_FILES.contains(&n)) {
            return Err(ScanError::ComposeNotUtf8 { path });
        }
        return Ok(Vec::new());
    };
    let markers = marker::parse(text).map_err(|e| parse_error(path, text, e))?;
    Ok(markers.into_iter().map(|m| m.kind).collect())
}

/// Scans every file of every stack: stack name → `(repo-relative path,
/// contents)`. Returns the first error, in stack and path order.
pub fn collect<B: AsRef<[u8]>>(layout: &Layout, stacks: &StackFiles<B>) -> Result<Scan, ScanError> {
    let mut scan = Scan::default();
    for (stack, files) in stacks {
        let mut files: Vec<_> = files.iter().collect();
        files.sort_by(|a, b| a.0.cmp(&b.0));
        let used = scan.uses.entry(stack.clone()).or_default();
        for (path, bytes) in files {
            for kind in scan_file(layout, stack, path, bytes.as_ref())? {
                if let MarkerKind::Set { name, .. } = &kind {
                    scan.sets.push(SetSite {
                        path: path.clone(),
                        stack: stack.clone(),
                        name: name.clone(),
                    });
                }
                used.push(kind);
            }
        }
    }
    Ok(scan)
}

#[cfg(test)]
mod tests {
    use super::*;

    type Files = StackFiles<Vec<u8>>;
    type FileList<'a> = &'a [(&'a str, &'a [u8])];

    fn files(list: &[(&str, FileList<'_>)]) -> Files {
        list.iter()
            .map(|(stack, fs)| {
                let fs = fs
                    .iter()
                    .map(|(p, b)| ((*p).to_owned(), b.to_vec()))
                    .collect();
                ((*stack).to_owned(), fs)
            })
            .collect()
    }

    fn names(markers: &[MarkerKind]) -> Vec<&str> {
        markers.iter().map(MarkerKind::name).collect()
    }

    #[test]
    fn collects_every_file_in_path_order() {
        let input = files(&[
            (
                "web",
                &[
                    ("stacks/web/config/app.conf", b"x=<<gen:conf>>"),
                    (
                        "stacks/web/compose.yaml",
                        b"a: <<gen:db>>\nb: <<secret:cf>>",
                    ),
                    ("stacks/web/bin.dat", b"\xff\xfe<<gen:x>>"),
                    ("stacks/web/a.b", b"<<gen:first>>"),
                ],
            ),
            ("empty", &[]),
            ("plain", &[("stacks/plain/compose.yaml", b"a: 1\n")]),
        ]);
        let scan = collect(&Layout::default(), &input).unwrap();
        assert_eq!(
            scan.uses.keys().collect::<Vec<_>>(),
            ["empty", "plain", "web"]
        );
        assert!(scan.uses["empty"].is_empty() && scan.uses["plain"].is_empty());
        // a.b < bin.dat (skipped: not UTF-8) < compose.yaml < config/…
        assert_eq!(names(&scan.uses["web"]), ["first", "db", "cf", "conf"]);
        assert!(scan.sets.is_empty());
        // Zeroizing buffers work as input too.
        let z: StackFiles<zeroize::Zeroizing<Vec<u8>>> = input
            .into_iter()
            .map(|(s, fs)| (s, fs.into_iter().map(|(p, b)| (p, b.into())).collect()))
            .collect();
        assert_eq!(
            names(&collect(&Layout::default(), &z).unwrap().uses["web"]),
            ["first", "db", "cf", "conf"]
        );
    }

    #[test]
    fn set_markers_are_kept_and_located() {
        let input = files(&[(
            "web",
            &[
                ("stacks/web/z.env", b"<<set:shared/smtp:pw>>"),
                ("stacks/web/compose.yaml", b"<<set:cf:hunter2>> <<gen:db>>"),
            ],
        )]);
        let scan = collect(&Layout::default(), &input).unwrap();
        assert_eq!(names(&scan.uses["web"]), ["cf", "db", "shared/smtp"]);
        assert_eq!(
            scan.sets,
            [
                SetSite {
                    path: "stacks/web/compose.yaml".into(),
                    stack: "web".into(),
                    name: "cf".into(),
                },
                SetSite {
                    path: "stacks/web/z.env".into(),
                    stack: "web".into(),
                    name: "shared/smtp".into(),
                },
            ]
        );
        assert!(!format!("{scan:?}").contains("hunter2"));
    }

    #[test]
    fn errors_name_the_file() {
        let err = scan_file(
            &Layout::default(),
            "web",
            "stacks/web/config/x",
            "ä\n  <<gen:bad name>>".as_bytes(),
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "stacks/web/config/x:2:12: invalid character in secret name (allowed: A-Z a-z 0-9 \
             . _ - and single `/` separators)"
        );

        let err = scan_file(
            &Layout::default(),
            "web",
            "stacks/web/x",
            b"<<gen:a:hex9999>>\n<<gen:b:zz>>",
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "stacks/web/x:1:9: format length must be between 32 and 256"
        );
        let err = scan_file(
            &Layout::default(),
            "web",
            "stacks/web/x",
            b"\n <<gen:b:zz>>",
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "stacks/web/x:2:10: unknown format (expected alnumN, hexN, base64-N or uuid)"
        );

        let err = scan_file(
            &Layout::default(),
            "web",
            "stacks/web/bin",
            b"\xff<<set:cf:hunter2>>",
        )
        .unwrap_err();
        assert_eq!(
            err,
            ScanError::SetInNonUtf8 {
                path: "stacks/web/bin".into()
            }
        );
        let msg = err.to_string();
        assert!(
            msg.contains("contains `<<set:`") && !msg.contains("hunter2"),
            "{msg}"
        );

        let err = scan_file(
            &Layout::default(),
            "web",
            "stacks/web/compose.yaml",
            b"a: \xff",
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "stacks/web/compose.yaml: not valid UTF-8; convert the file to UTF-8"
        );
        // Every compose file name counts, shadowed or not.
        for name in COMPOSE_FILES {
            let path = format!("stacks/web/{name}");
            let err = scan_file(&Layout::default(), "web", &path, b"\xff").unwrap_err();
            assert_eq!(err, ScanError::ComposeNotUtf8 { path });
        }
        // Only the stack's own compose files must be UTF-8.
        assert!(
            scan_file(
                &Layout::default(),
                "web",
                "stacks/web/sub/compose.yaml",
                b"\xff"
            )
            .unwrap()
            .is_empty()
        );
        assert!(
            scan_file(&Layout::default(), "web", "stacks/db/compose.yaml", b"\xff")
                .unwrap()
                .is_empty()
        );
        // `<<set` without the colon is no marker.
        assert!(
            scan_file(
                &Layout::default(),
                "web",
                "stacks/web/bin",
                b"\xff<<set<<se"
            )
            .unwrap()
            .is_empty()
        );

        // collect stops at the first error in path order.
        let input = files(&[(
            "web",
            &[
                ("stacks/web/b", b"<<gen:"),
                ("stacks/web/a", b"\xff<<set:x:y>>"),
            ],
        )]);
        assert!(matches!(
            collect(&Layout::default(), &input).unwrap_err(),
            ScanError::SetInNonUtf8 { path } if path == "stacks/web/a"
        ));
    }
}
