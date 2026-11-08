//! The `.sec/` store: names → generated-secret ids and sealed manual secrets.
//!
//! # Layout
//! - `.sec/meta.toml`: `version = 1` and the seed `fingerprint`.
//! - `.sec/<stack>.toml` per stack, and `.sec/shared.toml` for `shared/…`
//!   names:
//!   ```toml
//!   # Managed by lst. Do not edit by hand.
//!
//!   [gen.db]
//!   id = "<32 lowercase hex>"
//!   format = "alnum32"
//!   orphan = false
//!
//!   [secret.cloudflare]
//!   nonce = "<48 lowercase hex>"
//!   ciphertext = "<lowercase hex>"
//!   orphan = false
//!   ```
//!
//! Output is deterministic: keys are sorted, every field is always written,
//! and the same state always serialises to byte-identical files.
//!
//! # Scoping
//! A marker name `shared/x` lives in file `shared` under key `x`; any other
//! name `n` used in stack `s` lives in file `s` under key `n` (so `foo/bar`
//! is an ordinary stack-local key). The full name (`s/n` or `shared/x`) is
//! what errors show and what manual secrets are bound to (AEAD associated
//! data).
//!
//! Everything except [`Store::load`] and [`Store::save`] is pure (no
//! filesystem; the only side effect is the OS random generator for new ids
//! and nonces).
//!
//! Nothing in `.sec/` is secret (ids, nonces, ciphertexts and the
//! fingerprint are committed), but errors still never quote field values,
//! only file names, secret names and field names.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::crypto::{self, CryptoError, GenId, NONCE_LEN, Sealed, SecretString, Seed};
use crate::format::{self, Format};
use crate::marker::{self, MarkerKind};

/// The `.sec/` format version this build reads and writes.
pub const VERSION: i64 = 1;
/// File stem of the store file for `shared/…` names.
pub const SHARED: &str = "shared";
/// File stem of the metadata file.
pub const META: &str = "meta";
/// First line of every file written to `.sec/`.
pub const HEADER: &str = "# Managed by lst. Do not edit by hand.\n";

const SHARED_PREFIX: &str = "shared/";
/// Length of the Poly1305 tag; a ciphertext is never shorter.
const TAG_LEN: usize = 16;
const FINGERPRINT_HEX_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("{}: not initialised (no meta.toml); run `lst init`", .dir.display())]
    NotInitialized { dir: PathBuf },
    #[error("{}: {source}", .path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{file}: invalid TOML at line {line}: {message}")]
    Toml {
        file: String,
        line: usize,
        message: String,
    },
    /// A structural problem in a `.sec/` file. `what` names the table or the
    /// secret; `problem` names the field. Never contains a field value.
    #[error("{file}: {what}: {problem}")]
    Invalid {
        file: String,
        what: String,
        problem: String,
    },
    #[error("{file}: unsupported .sec format version {version} (this lst supports version 1)")]
    Version { file: String, version: i64 },
    #[error(
        "invalid file name {name:?} in .sec/ (expected meta.toml, shared.toml or <stack>.toml)"
    )]
    InvalidFileName { name: String },
    #[error(
        "invalid stack name {0:?} (allowed: A-Z a-z 0-9 . _ -, not starting with `.`; \
         `shared` and `meta` are reserved)"
    )]
    InvalidStack(String),
    #[error("invalid secret name {0:?} (allowed: A-Z a-z 0-9 . _ - and single `/` separators)")]
    InvalidName(String),
    #[error(
        "invalid full secret name {0:?} (expected <stack>/<name> or shared/<name>; a name \
         allows A-Z a-z 0-9 . _ - and single `/` separators)"
    )]
    InvalidFullName(String),
    #[error(
        "wrong seed: its fingerprint does not match .sec/meta.toml; use this repository's seed \
         (from your password manager) in .env or the LST_SEED environment variable"
    )]
    FingerprintMismatch,
    #[error("`{name}` is used with two different formats: {first} and {second}")]
    FormatConflict {
        name: String,
        first: Format,
        second: Format,
    },
    #[error("`{name}` is used both as <<gen:…>> and as <<secret:…>>")]
    KindConflict { name: String },
    #[error(
        "`{name}`: <<set:…>> is processed by the pre-commit hook (it stores the value first); \
         sync does not take values"
    )]
    SetUnsupported { name: String },
    #[error("`{name}` has no entry in .sec/ to rename")]
    RenameSourceMissing { name: String },
    #[error(
        "`{name}` exists both as <<gen:…>> and as <<secret:…>> in .sec/, so lst cannot tell \
         which one to rename"
    )]
    RenameAmbiguous { name: String },
    #[error("cannot rename `{name}` to itself")]
    RenameToItself { name: String },
    #[error(
        "`{name}` already exists in .sec/; pass --replace to overwrite it with the renamed entry"
    )]
    RenameTargetExists { name: String },
    #[error(
        "`{to}` exists in .sec/ as {existing}, but `{from}` is {moving}; lst rename only \
         replaces an entry of the same kind"
    )]
    RenameKindMismatch {
        from: String,
        to: String,
        moving: EntryKind,
        existing: EntryKind,
    },
    #[error(
        "`{name}` has no entry in .sec/ to rotate (if a <<gen:…>> marker uses it, run `lst sync` \
         first)"
    )]
    RotateMissing { name: String },
    #[error(
        "`{name}` is a manual secret, and lst rotate only gives generated secrets a new value; \
         write <<set:{marker_name}:VALUE>> to replace it"
    )]
    RotateManual { name: String, marker_name: String },
    #[error(
        "`{name}` is an orphan (no marker uses it), so there is nothing to rotate; `lst gc \
         --remove {name}` removes it"
    )]
    RotateOrphan { name: String },
    #[error("`{name}` has no entry in .sec/")]
    GcMissing { name: String },
    #[error(
        "`{name}` has no entry in .sec/ (if a marker uses it, run `lst sync` first); {file} has: {}",
        if known.is_empty() { "no entries".to_owned() } else { known.join(", ") }
    )]
    GetMissing {
        name: String,
        file: String,
        known: Vec<String>,
    },
    #[error(
        "`{name}` exists both as <<gen:…>> and as <<secret:…>> in .sec/ and neither or both \
         are in use, so lst cannot tell which one to show; run `lst sync` first"
    )]
    GetAmbiguous { name: String },
    #[error("`{name}` is in use, not an orphan; lst gc only removes orphans")]
    GcNotOrphan { name: String },
    #[error("`{name}`: {source}")]
    Crypto {
        name: String,
        #[source]
        source: CryptoError,
    },
}

/// Errors from [`Store::resolve`].
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("`{name}` has no entry in .sec/; run `lst sync`")]
    GenMissing { name: String },
    #[error("`{name}` is stored as {stored} but used as {used}; run `lst sync`")]
    FormatMismatch {
        name: String,
        stored: Format,
        used: Format,
    },
    #[error("`{name}` is not set; write <<set:{marker_name}:VALUE>> to set it")]
    SecretUnset { name: String, marker_name: String },
    #[error(
        "`{name}`: <<set:…>> cannot be rendered; commit the file first, the pre-commit hook \
         stores the value and rewrites the marker"
    )]
    SetMarker { name: String },
    #[error("`{name}`: {source}")]
    Decrypt {
        name: String,
        #[source]
        source: CryptoError,
    },
}

// ---------------------------------------------------------------------------
// Names and scoping
// ---------------------------------------------------------------------------

/// Where a name used in a stack lives in the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    /// File stem: the stack name, or [`SHARED`].
    pub file: String,
    /// Key within the file.
    pub key: String,
    /// `file/key`: shown in errors and bound into manual-secret ciphertexts.
    pub full_name: String,
}

/// Resolves the scope of marker name `name` used in stack `stack`.
pub fn scope(stack: &str, name: &str) -> Result<Scope, StoreError> {
    if !is_valid_stack(stack) {
        return Err(StoreError::InvalidStack(stack.to_owned()));
    }
    if !is_valid_name(name) {
        return Err(StoreError::InvalidName(name.to_owned()));
    }
    let (file, key) = match name.strip_prefix(SHARED_PREFIX) {
        Some(key) => (SHARED, key),
        None => (stack, name),
    };
    Ok(Scope {
        file: file.to_owned(),
        key: key.to_owned(),
        full_name: full_name(file, key),
    })
}

fn full_name(file: &str, key: &str) -> String {
    format!("{file}/{key}")
}

/// The name a marker for `sc` is written with: the key in a stack
/// (`web/cf` → `cf`), the full name for `shared/…`.
fn marker_name(sc: &Scope) -> &str {
    if sc.file == SHARED {
        &sc.full_name
    } else {
        &sc.key
    }
}

/// Parses a full name as errors and reports print it: `<stack>/<name>` or
/// `shared/<name>`. The first `/` separates the file from the key, so
/// `web/foo/bar` is key `foo/bar` of stack `web`. A stack key starting
/// with `shared/` is refused (such names live in `shared`).
pub fn parse_full_name(full: &str) -> Result<Scope, StoreError> {
    let invalid = || StoreError::InvalidFullName(full.to_owned());
    let (file, key) = full.split_once('/').ok_or_else(invalid)?;
    let valid_file = file == SHARED || is_valid_stack(file);
    let valid_key = is_valid_name(key) && (file == SHARED || !key.starts_with(SHARED_PREFIX));
    if !(valid_file && valid_key) {
        return Err(invalid());
    }
    Ok(Scope {
        file: file.to_owned(),
        key: key.to_owned(),
        full_name: full.to_owned(),
    })
}

/// A stack name usable as a `.sec/` file stem: `[A-Za-z0-9._-]+`, not
/// starting with `.`, and not one of the reserved stems (in any case).
/// [`crate::stack::validate_name`] is the single source of truth for these
/// rules, so discovery and the store can never disagree.
pub fn is_valid_stack(stack: &str) -> bool {
    crate::stack::validate_name(stack).is_ok()
}

/// A secret name as the marker grammar defines it. Checked with the marker
/// parser itself so the two can never disagree.
fn is_valid_name(name: &str) -> bool {
    let text = format!("<<secret:{name}>>");
    match marker::parse(&text).as_deref() {
        Ok([m]) => m.span == (0..text.len()) && m.kind.name() == name,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

/// `.sec/meta.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    /// Seed fingerprint, 32 lowercase hex characters.
    pub fingerprint: String,
}

/// A generated secret: its value is derived from `seed || id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenEntry {
    pub id: GenId,
    pub format: Format,
    pub orphan: bool,
}

/// A manual secret, sealed under the seed's encryption key and bound to its
/// full name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretEntry {
    pub sealed: Sealed,
    pub orphan: bool,
}

/// One `.sec/<stack>.toml` (or `shared.toml`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StackFile {
    /// The `[gen.*]` tables.
    pub generated: BTreeMap<String, GenEntry>,
    /// The `[secret.*]` tables.
    pub secrets: BTreeMap<String, SecretEntry>,
}

/// The whole `.sec/` directory in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Store {
    meta: Meta,
    /// File stem → contents. Holds only files that exist (or will be
    /// written); entries are never removed.
    files: BTreeMap<String, StackFile>,
}

/// A generated secret whose format changed (so its value changed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatChange {
    pub name: String,
    pub from: Format,
    pub to: Format,
}

/// What [`Store::sync`] changed. All lists hold full names, sorted.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SyncReport {
    /// New generated secrets (fresh ids).
    pub added: Vec<String>,
    /// Generated secrets whose format changed.
    pub format_changed: Vec<FormatChange>,
    /// Entries no longer used anywhere in their scope.
    pub orphaned: Vec<String>,
    /// Orphaned entries that are used again.
    pub unorphaned: Vec<String>,
    /// `<<secret:…>>` names with no stored value (not an error in sync).
    pub unset: Vec<String>,
    /// Likely renames, `(old, new)` full names: within one file (a stack or
    /// `shared`) and one kind, exactly one entry was orphaned and exactly
    /// one name appeared in this sync. For gen names "appeared" means
    /// [`added`](Self::added); for manual secrets it means exactly one
    /// [`unset`](Self::unset) name. Only a hint: both names are also in the
    /// other lists, so [`is_empty`](Self::is_empty) ignores this list.
    pub rename_candidates: Vec<(String, String)>,
}

impl SyncReport {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty()
            && self.format_changed.is_empty()
            && self.orphaned.is_empty()
            && self.unorphaned.is_empty()
            && self.unset.is_empty()
    }

    fn sort(&mut self) {
        self.added.sort();
        self.format_changed.sort_by(|a, b| a.name.cmp(&b.name));
        self.orphaned.sort();
        self.unorphaned.sort();
        self.unset.sort();
        self.rename_candidates.sort();
    }
}

/// Names that left and entered one file and kind during a sync, for
/// [`SyncReport::rename_candidates`].
#[derive(Default)]
struct Moves {
    out: Vec<String>,
    into: Vec<String>,
}

/// The two kinds of `.sec/` entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EntryKind {
    /// A `[gen.*]` entry (generated secret).
    Gen,
    /// A `[secret.*]` entry (manual secret).
    Secret,
}

impl std::fmt::Display for EntryKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            EntryKind::Gen => "<<gen:…>>",
            EntryKind::Secret => "<<secret:…>>",
        })
    }
}

/// What [`Store::rename`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenameOutcome {
    /// Full name before the rename.
    pub from: String,
    /// Full name after the rename.
    pub to: String,
    pub kind: EntryKind,
    /// Whether an existing entry of `to` was overwritten.
    pub replaced: bool,
}

/// What [`Store::rotate`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotateOutcome {
    /// The full name of the rotated generated secret.
    pub name: String,
    /// Its format (unchanged).
    pub format: Format,
}

/// An orphaned entry, as [`Store::orphans`] lists it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Orphan {
    /// Full name (`web/old`, `shared/x`).
    pub name: String,
    pub kind: EntryKind,
}

/// What [`Store::get`] found. `Debug` never shows the value
/// ([`SecretString`] redacts it).
#[derive(Debug)]
pub struct Got {
    /// The full name.
    pub name: String,
    pub kind: EntryKind,
    /// Whether no marker uses it any more.
    pub orphan: bool,
    pub value: SecretString,
}

/// An entry on its way to its new name.
enum Moved {
    Gen(GenEntry),
    Secret(SecretEntry),
}

#[derive(Clone, Copy)]
enum Use {
    Gen(Format),
    Secret,
}

fn crypto_err(name: &str) -> impl FnOnce(CryptoError) -> StoreError + '_ {
    move |source| StoreError::Crypto {
        name: name.to_owned(),
        source,
    }
}

impl Store {
    /// A fresh, empty store for `seed`.
    pub fn init(seed: &Seed) -> Store {
        Store {
            meta: Meta {
                fingerprint: crypto::fingerprint(seed),
            },
            files: BTreeMap::new(),
        }
    }

    pub fn meta(&self) -> &Meta {
        &self.meta
    }

    /// File stem → contents.
    pub fn files(&self) -> &BTreeMap<String, StackFile> {
        &self.files
    }

    fn seed_matches(&self, seed: &Seed) -> bool {
        crypto::fingerprint(seed) == self.meta.fingerprint
    }

    /// Fails if `seed` is not the seed this store was created with.
    pub fn verify_seed(&self, seed: &Seed) -> Result<(), StoreError> {
        if self.seed_matches(seed) {
            Ok(())
        } else {
            Err(StoreError::FingerprintMismatch)
        }
    }

    /// Updates the store from the markers used in every stack (`uses` must
    /// cover all stacks, so `shared/…` orphans can be decided).
    ///
    /// Creates ids for new gen names, updates changed formats, marks unused
    /// entries as orphans (never deletes) and un-orphans used ones. Atomic:
    /// on error the store is unchanged.
    pub fn sync(
        &mut self,
        uses: &BTreeMap<String, Vec<MarkerKind>>,
    ) -> Result<SyncReport, StoreError> {
        // 1. Collect and check every use: file → key → use.
        let mut used: BTreeMap<String, BTreeMap<String, Use>> = BTreeMap::new();
        for (stack, markers) in uses {
            if !is_valid_stack(stack) {
                return Err(StoreError::InvalidStack(stack.clone()));
            }
            for m in markers {
                let sc = scope(stack, m.name())?;
                let u = match m {
                    MarkerKind::Gen { format, .. } => Use::Gen(*format),
                    MarkerKind::Secret { .. } => Use::Secret,
                    MarkerKind::Set { .. } => {
                        return Err(StoreError::SetUnsupported { name: sc.full_name });
                    }
                };
                match used.entry(sc.file).or_default().entry(sc.key) {
                    Entry::Vacant(v) => {
                        v.insert(u);
                    }
                    Entry::Occupied(o) => match (*o.get(), u) {
                        (Use::Gen(first), Use::Gen(second)) if first != second => {
                            return Err(StoreError::FormatConflict {
                                name: sc.full_name,
                                first,
                                second,
                            });
                        }
                        (Use::Gen(_), Use::Secret) | (Use::Secret, Use::Gen(_)) => {
                            return Err(StoreError::KindConflict { name: sc.full_name });
                        }
                        _ => {}
                    },
                }
            }
        }

        // 2. Apply to a copy, so a failure leaves `self` untouched.
        let mut files = self.files.clone();
        let mut report = SyncReport::default();
        let mut moves: BTreeMap<(String, EntryKind), Moves> = BTreeMap::new();
        let mut moved = |stem: &str, kind, name: &str, out: bool| {
            let m = moves.entry((stem.to_owned(), kind)).or_default();
            let list = if out { &mut m.out } else { &mut m.into };
            list.push(name.to_owned());
        };
        for (stem, keys) in &used {
            for (key, u) in keys {
                let name = full_name(stem, key);
                match *u {
                    Use::Gen(format) => {
                        let file = files.entry(stem.clone()).or_default();
                        match file.generated.entry(key.clone()) {
                            Entry::Occupied(mut o) => {
                                let e = o.get_mut();
                                if e.format != format {
                                    report.format_changed.push(FormatChange {
                                        name: name.clone(),
                                        from: e.format,
                                        to: format,
                                    });
                                    e.format = format;
                                }
                                if e.orphan {
                                    e.orphan = false;
                                    report.unorphaned.push(name);
                                }
                            }
                            Entry::Vacant(v) => {
                                let id = GenId::generate().map_err(crypto_err(&name))?;
                                v.insert(GenEntry {
                                    id,
                                    format,
                                    orphan: false,
                                });
                                moved(stem, EntryKind::Gen, &name, false);
                                report.added.push(name);
                            }
                        }
                    }
                    Use::Secret => {
                        let entry = files.get_mut(stem).and_then(|f| f.secrets.get_mut(key));
                        match entry {
                            Some(e) if e.orphan => {
                                e.orphan = false;
                                report.unorphaned.push(name);
                            }
                            Some(_) => {}
                            None => {
                                moved(stem, EntryKind::Secret, &name, false);
                                report.unset.push(name);
                            }
                        }
                    }
                }
            }
        }

        // 3. Orphan everything not used in its scope (including whole files
        //    of stacks that are gone).
        for (stem, file) in &mut files {
            let keys = used.get(stem);
            let use_of = |key: &str| keys.and_then(|k| k.get(key)).copied();
            for (key, e) in &mut file.generated {
                if !e.orphan && !matches!(use_of(key), Some(Use::Gen(_))) {
                    e.orphan = true;
                    let name = full_name(stem, key);
                    moved(stem, EntryKind::Gen, &name, true);
                    report.orphaned.push(name);
                }
            }
            for (key, e) in &mut file.secrets {
                if !e.orphan && !matches!(use_of(key), Some(Use::Secret)) {
                    e.orphan = true;
                    let name = full_name(stem, key);
                    moved(stem, EntryKind::Secret, &name, true);
                    report.orphaned.push(name);
                }
            }
        }
        for m in moves.into_values() {
            if let ([old], [new]) = (m.out.as_slice(), m.into.as_slice()) {
                report.rename_candidates.push((old.clone(), new.clone()));
            }
        }

        report.sort();
        self.files = files;
        Ok(report)
    }

    /// Stores `value` as the manual secret `name` of `stack`, sealed under
    /// `seed`. Only re-seals if the stored value differs (random nonces
    /// would otherwise change the file on every write). Returns whether the
    /// store changed. A new entry is not an orphan; an existing entry keeps
    /// its orphan flag ([`Store::sync`] owns that).
    pub fn set_secret(
        &mut self,
        seed: &Seed,
        stack: &str,
        name: &str,
        value: &str,
    ) -> Result<bool, StoreError> {
        self.verify_seed(seed)?;
        let sc = scope(stack, name)?;
        let key = crypto::encryption_key(seed);
        let existing = self
            .files
            .get(&sc.file)
            .and_then(|f| f.secrets.get(&sc.key));
        if let Some(e) = existing {
            // A value we can't decrypt is never silently overwritten.
            let current =
                crypto::open(&key, &sc.full_name, &e.sealed).map_err(crypto_err(&sc.full_name))?;
            if current.expose() == value {
                return Ok(false);
            }
        }
        let sealed = crypto::seal(&key, &sc.full_name, value).map_err(crypto_err(&sc.full_name))?;
        let file = self.files.entry(sc.file).or_default();
        match file.secrets.entry(sc.key) {
            Entry::Occupied(mut o) => o.get_mut().sealed = sealed,
            Entry::Vacant(v) => {
                v.insert(SecretEntry {
                    sealed,
                    orphan: false,
                });
            }
        }
        Ok(true)
    }

    /// Renames the entry `from` to `to` (full names, see
    /// [`parse_full_name`]), across files if needed (`web/db` →
    /// `shared/db`).
    ///
    /// - A gen entry keeps its id and format, so its value is unchanged.
    /// - A manual secret is decrypted under `from` and sealed under `to`
    ///   (the ciphertext is bound to its name) with a fresh nonce.
    ///
    /// The moved entry is not an orphan. An existing `to` of the same kind
    /// is only overwritten with `replace`; one of the other kind is never
    /// overwritten (that would leave a gen and a secret of one name). A
    /// source that exists as both kinds is refused as ambiguous. Other
    /// entries are never touched. Atomic: on error the store is unchanged.
    /// The source file stays in the store even if it becomes empty.
    pub fn rename(
        &mut self,
        seed: &Seed,
        from: &str,
        to: &str,
        replace: bool,
    ) -> Result<RenameOutcome, StoreError> {
        self.verify_seed(seed)?;
        let from = parse_full_name(from)?;
        let to = parse_full_name(to)?;
        if from.full_name == to.full_name {
            return Err(StoreError::RenameToItself {
                name: from.full_name,
            });
        }

        // Work on a copy, so a failure leaves `self` untouched.
        let mut files = self.files.clone();
        let src = files.entry(from.file.clone()).or_default();
        let (kind, entry) = match (
            src.generated.remove(&from.key),
            src.secrets.remove(&from.key),
        ) {
            (Some(_), Some(_)) => {
                return Err(StoreError::RenameAmbiguous {
                    name: from.full_name,
                });
            }
            (None, None) => {
                return Err(StoreError::RenameSourceMissing {
                    name: from.full_name,
                });
            }
            (Some(g), None) => (EntryKind::Gen, Moved::Gen(g)),
            (None, Some(s)) => (EntryKind::Secret, Moved::Secret(s)),
        };

        let dst = files.entry(to.file.clone()).or_default();
        let has_gen = dst.generated.contains_key(&to.key);
        let has_secret = dst.secrets.contains_key(&to.key);
        let (same, other) = match kind {
            EntryKind::Gen => (has_gen, has_secret.then_some(EntryKind::Secret)),
            EntryKind::Secret => (has_secret, has_gen.then_some(EntryKind::Gen)),
        };
        if let Some(existing) = other {
            return Err(StoreError::RenameKindMismatch {
                from: from.full_name,
                to: to.full_name,
                moving: kind,
                existing,
            });
        }
        if same && !replace {
            return Err(StoreError::RenameTargetExists { name: to.full_name });
        }

        match entry {
            Moved::Gen(g) => {
                let moved = GenEntry { orphan: false, ..g };
                dst.generated.insert(to.key, moved);
            }
            Moved::Secret(s) => {
                let key = crypto::encryption_key(seed);
                let value = crypto::open(&key, &from.full_name, &s.sealed)
                    .map_err(crypto_err(&from.full_name))?;
                let sealed = crypto::seal(&key, &to.full_name, value.expose())
                    .map_err(crypto_err(&to.full_name))?;
                let moved = SecretEntry {
                    sealed,
                    orphan: false,
                };
                dst.secrets.insert(to.key, moved);
            }
        }
        self.files = files;
        Ok(RenameOutcome {
            from: from.full_name,
            to: to.full_name,
            kind,
            replaced: same,
        })
    }

    /// Gives the generated secret `name` (a full name, see
    /// [`parse_full_name`]) a fresh random id, keeping its format: its value
    /// changes. Needs no seed (nothing is derived).
    ///
    /// Only an entry in use is rotated: a manual secret is refused (its
    /// value comes from `<<set:…>>`), and so is an orphan (nothing uses it).
    /// A gen entry in use is rotated even if an orphaned manual entry of the
    /// same name exists (left over from a marker that switched kind). Other
    /// entries are never touched. Atomic: on error the store is unchanged.
    pub fn rotate(&mut self, name: &str) -> Result<RotateOutcome, StoreError> {
        let sc = parse_full_name(name)?;
        let (generated, secret) = match self.files.get_mut(&sc.file) {
            Some(f) => (f.generated.get_mut(&sc.key), f.secrets.get(&sc.key)),
            None => (None, None),
        };
        match (generated, secret) {
            (Some(e), _) if !e.orphan => {
                e.id = GenId::generate().map_err(crypto_err(&sc.full_name))?;
                Ok(RotateOutcome {
                    name: sc.full_name,
                    format: e.format,
                })
            }
            (_, Some(s)) if !s.orphan => Err(StoreError::RotateManual {
                marker_name: marker_name(&sc).to_owned(),
                name: sc.full_name,
            }),
            (None, None) => Err(StoreError::RotateMissing { name: sc.full_name }),
            _ => Err(StoreError::RotateOrphan { name: sc.full_name }),
        }
    }

    /// Every orphaned entry, sorted by full name (then kind: one name can
    /// be an orphan of both kinds after its marker switched kind).
    pub fn orphans(&self) -> Vec<Orphan> {
        let mut out = Vec::new();
        for (stem, file) in &self.files {
            let gens = file.generated.iter().filter(|(_, e)| e.orphan);
            let secrets = file.secrets.iter().filter(|(_, e)| e.orphan);
            let all = gens
                .map(|(k, _)| (k, EntryKind::Gen))
                .chain(secrets.map(|(k, _)| (k, EntryKind::Secret)));
            out.extend(all.map(|(key, kind)| Orphan {
                name: full_name(stem, key),
                kind,
            }));
        }
        out.sort();
        out
    }

    /// Deletes orphaned entries: all of them (`names` `None`), or the
    /// orphaned entries of each full name in `names` (duplicates are fine).
    /// Each named entry must exist and be an orphan, otherwise nothing is
    /// removed (atomic). Entries in use are never removed. A file that loses
    /// its last entry stays in the store and is written as just the header,
    /// as after [`Store::rename`]. Returns what was removed, sorted like
    /// [`Store::orphans`].
    pub fn remove_orphans(&mut self, names: Option<&[String]>) -> Result<Vec<Orphan>, StoreError> {
        let wanted = match names {
            None => None,
            Some(names) => {
                let orphans: BTreeSet<String> =
                    self.orphans().into_iter().map(|o| o.name).collect();
                let mut wanted = BTreeSet::new();
                for name in names {
                    let sc = parse_full_name(name)?;
                    if !orphans.contains(&sc.full_name) {
                        let exists = self.files.get(&sc.file).is_some_and(|f| {
                            f.generated.contains_key(&sc.key) || f.secrets.contains_key(&sc.key)
                        });
                        return Err(if exists {
                            StoreError::GcNotOrphan { name: sc.full_name }
                        } else {
                            StoreError::GcMissing { name: sc.full_name }
                        });
                    }
                    wanted.insert(sc.full_name);
                }
                Some(wanted)
            }
        };
        // Nothing below fails, so the store is only changed once every name
        // has been checked.
        let mut removed = Vec::new();
        for (stem, file) in &mut self.files {
            let mut take = |key: &str, orphan: bool, kind| {
                let name = full_name(stem, key);
                let go = orphan && wanted.as_ref().is_none_or(|w| w.contains(&name));
                if go {
                    removed.push(Orphan { name, kind });
                }
                !go
            };
            file.generated
                .retain(|key, e| take(key, e.orphan, EntryKind::Gen));
            file.secrets
                .retain(|key, e| take(key, e.orphan, EntryKind::Secret));
        }
        removed.sort();
        Ok(removed)
    }

    /// The value of `marker` as used in `stack`. Read-only. Orphaned
    /// entries still resolve.
    pub fn resolve(
        &self,
        seed: &Seed,
        stack: &str,
        marker: &MarkerKind,
    ) -> Result<SecretString, ResolveError> {
        self.verify_seed(seed)?;
        let sc = scope(stack, marker.name())?;
        let file = self.files.get(&sc.file);
        match marker {
            MarkerKind::Gen { format, .. } => {
                let Some(e) = file.and_then(|f| f.generated.get(&sc.key)) else {
                    return Err(ResolveError::GenMissing { name: sc.full_name });
                };
                if e.format != *format {
                    return Err(ResolveError::FormatMismatch {
                        name: sc.full_name,
                        stored: e.format,
                        used: *format,
                    });
                }
                Ok(format::generate(
                    *format,
                    &mut crypto::derive_gen(seed, &e.id),
                ))
            }
            MarkerKind::Secret { name } => {
                let Some(e) = file.and_then(|f| f.secrets.get(&sc.key)) else {
                    return Err(ResolveError::SecretUnset {
                        name: sc.full_name,
                        marker_name: name.clone(),
                    });
                };
                let key = crypto::encryption_key(seed);
                crypto::open(&key, &sc.full_name, &e.sealed).map_err(|source| {
                    ResolveError::Decrypt {
                        name: sc.full_name.clone(),
                        source,
                    }
                })
            }
            MarkerKind::Set { .. } => Err(ResolveError::SetMarker { name: sc.full_name }),
        }
    }

    /// The value of the entry with full name `name` (`web/db`,
    /// `shared/mq`), for `lst get`: derived for a generated secret,
    /// decrypted for a manual one. Read-only; the raw value, exactly what a
    /// `render:` file gets (no `$$` escaping).
    ///
    /// Orphans resolve too (an app may still use the old value). When the
    /// name has both a gen and a secret entry (its marker switched kind),
    /// the one in use is taken; if neither or both are, it is ambiguous.
    pub fn get(&self, seed: &Seed, name: &str) -> Result<Got, ResolveError> {
        self.verify_seed(seed)?;
        let sc = parse_full_name(name)?;
        let file = self.files.get(&sc.file);
        let generated = file.and_then(|f| f.generated.get(&sc.key));
        let secret = file.and_then(|f| f.secrets.get(&sc.key));
        let pick = match (generated, secret) {
            (Some(g), Some(s)) if g.orphan == s.orphan => {
                return Err(StoreError::GetAmbiguous { name: sc.full_name }.into());
            }
            (Some(g), Some(_)) if !g.orphan => Moved::Gen(g.clone()),
            (_, Some(s)) => Moved::Secret(s.clone()),
            (Some(g), None) => Moved::Gen(g.clone()),
            (None, None) => {
                let mut known: Vec<String> = file
                    .map(|f| {
                        f.generated
                            .keys()
                            .chain(f.secrets.keys())
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default();
                known.sort();
                known.dedup();
                return Err(StoreError::GetMissing {
                    name: sc.full_name,
                    file: format!(".sec/{}.toml", sc.file),
                    known,
                }
                .into());
            }
        };
        let (value, kind, orphan) = match pick {
            Moved::Gen(e) => (
                format::generate(e.format, &mut crypto::derive_gen(seed, &e.id)),
                EntryKind::Gen,
                e.orphan,
            ),
            Moved::Secret(e) => {
                let key = crypto::encryption_key(seed);
                let value = crypto::open(&key, &sc.full_name, &e.sealed).map_err(|source| {
                    ResolveError::Decrypt {
                        name: sc.full_name.clone(),
                        source,
                    }
                })?;
                (value, EntryKind::Secret, e.orphan)
            }
        };
        Ok(Got {
            name: sc.full_name,
            kind,
            orphan,
            value,
        })
    }

    // -----------------------------------------------------------------------
    // Pure (de)serialisation of the whole store
    // -----------------------------------------------------------------------

    /// File name (`meta.toml`, `<stem>.toml`) → contents.
    pub fn to_files(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        out.insert(format!("{META}.toml"), self.meta.to_toml());
        for (stem, file) in &self.files {
            out.insert(format!("{stem}.toml"), file.to_toml());
        }
        out
    }

    /// Builds a store from `meta.toml` and the stack files (stem → text).
    pub fn from_files(meta: &str, files: &BTreeMap<String, String>) -> Result<Store, StoreError> {
        let meta = Meta::parse(meta)?;
        let mut parsed = BTreeMap::new();
        for (stem, text) in files {
            if stem != SHARED && !is_valid_stack(stem) {
                return Err(StoreError::InvalidFileName {
                    name: format!("{stem}.toml"),
                });
            }
            parsed.insert(stem.clone(), StackFile::parse(stem, text)?);
        }
        Ok(Store {
            meta,
            files: parsed,
        })
    }

    // -----------------------------------------------------------------------
    // Filesystem
    // -----------------------------------------------------------------------

    /// Reads `.sec/`. Files not ending in `.toml` are ignored.
    pub fn load(sec_dir: &Path) -> Result<Store, StoreError> {
        let (meta, files) = Store::read_files(sec_dir)?;
        Store::from_files(&meta, &files)
    }

    /// The text [`Store::load`] parses: `meta.toml`, and every other
    /// `.toml` file of `sec_dir` by stem. (`lst check` compares it with
    /// what [`Store::to_files`] would write.)
    pub fn read_files(sec_dir: &Path) -> Result<(String, BTreeMap<String, String>), StoreError> {
        let meta_path = sec_dir.join(format!("{META}.toml"));
        let meta = match fs::read_to_string(&meta_path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(StoreError::NotInitialized {
                    dir: sec_dir.to_owned(),
                });
            }
            Err(e) => return Err(io_err(&meta_path)(e)),
        };
        let mut files = BTreeMap::new();
        for entry in fs::read_dir(sec_dir).map_err(io_err(sec_dir))? {
            let path = entry.map_err(io_err(sec_dir))?.path();
            if path.extension().is_none_or(|ext| ext != "toml") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                return Err(StoreError::InvalidFileName {
                    name: path.to_string_lossy().into_owned(),
                });
            };
            if stem == META {
                continue;
            }
            let text = fs::read_to_string(&path).map_err(io_err(&path))?;
            files.insert(stem.to_owned(), text);
        }
        Ok((meta, files))
    }

    /// Writes `.sec/` (creating the directory if needed). Only writes files
    /// whose bytes changed; never deletes files. Returns the paths written,
    /// sorted.
    pub fn save(&self, sec_dir: &Path) -> Result<Vec<PathBuf>, StoreError> {
        fs::create_dir_all(sec_dir).map_err(io_err(sec_dir))?;
        let mut written = Vec::new();
        for (name, contents) in self.to_files() {
            let path = sec_dir.join(&name);
            match fs::read(&path) {
                Ok(old) if old == contents.as_bytes() => continue,
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(io_err(&path)(e)),
            }
            // Write-then-rename, so a crash never leaves a half-written file.
            let tmp = sec_dir.join(format!(".{name}.tmp"));
            fs::write(&tmp, contents)
                .and_then(|()| fs::rename(&tmp, &path))
                .map_err(io_err(&path))?;
            written.push(path);
        }
        Ok(written)
    }
}

fn io_err(path: &Path) -> impl FnOnce(io::Error) -> StoreError + '_ {
    move |source| StoreError::Io {
        path: path.to_owned(),
        source,
    }
}

// ---------------------------------------------------------------------------
// TOML: serialisation through private raw structs, parsing by hand from a
// `toml::Table` (exact control over unknown/missing fields, and errors that
// name the secret but never quote a value).
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct RawMeta {
    version: i64,
    fingerprint: String,
}

#[derive(Serialize)]
struct RawStackFile {
    #[serde(rename = "gen", skip_serializing_if = "BTreeMap::is_empty")]
    generated: BTreeMap<String, RawGen>,
    #[serde(rename = "secret", skip_serializing_if = "BTreeMap::is_empty")]
    secrets: BTreeMap<String, RawSecret>,
}

#[derive(Serialize)]
struct RawGen {
    id: String,
    format: String,
    orphan: bool,
}

#[derive(Serialize)]
struct RawSecret {
    nonce: String,
    ciphertext: String,
    orphan: bool,
}

fn to_toml_with_header<T: Serialize>(raw: &T) -> String {
    // Invariant: the raw structs are string-keyed maps of structs holding
    // only strings, integers and bools, which the TOML serializer always
    // accepts.
    let body = toml::to_string(raw).expect("raw .sec structs always serialise");
    if body.is_empty() {
        HEADER.to_owned()
    } else {
        format!("{HEADER}\n{body}")
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    crypto::push_hex(&mut s, bytes);
    s
}

/// Decodes lowercase hex. `None` on odd length or any other character.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    }
    let s = s.as_bytes();
    if s.len() % 2 != 0 {
        return None;
    }
    s.chunks_exact(2)
        .map(|p| Some((nibble(p[0])? << 4) | nibble(p[1])?))
        .collect()
}

fn line_of(text: &str, pos: usize) -> usize {
    let end = pos.min(text.len());
    text.as_bytes()[..end]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        + 1
}

/// Parses `text` as a TOML document. Only the parser's message and the line
/// are kept, never the source snippet the full error would quote.
fn parse_top_level<'a>(file: &'a str, text: &str) -> Result<Fields<'a>, StoreError> {
    let table = toml::from_str::<toml::Table>(text).map_err(|e| StoreError::Toml {
        file: file.to_owned(),
        line: e.span().map_or(1, |s| line_of(text, s.start)),
        message: e.message().to_owned(),
    })?;
    Ok(Fields {
        file,
        what: "top level".to_owned(),
        table,
    })
}

/// Takes typed fields out of one TOML table, naming `what` in errors.
struct Fields<'a> {
    file: &'a str,
    what: String,
    table: toml::Table,
}

impl<'a> Fields<'a> {
    fn new(file: &'a str, what: String, value: toml::Value) -> Result<Fields<'a>, StoreError> {
        match value {
            toml::Value::Table(table) => Ok(Fields { file, what, table }),
            _ => Err(invalid(file, what, "expected a table".to_owned())),
        }
    }

    fn err(&self, problem: String) -> StoreError {
        invalid(self.file, self.what.clone(), problem)
    }

    fn take(&mut self, field: &str, ty: &str) -> Result<toml::Value, StoreError> {
        self.table
            .remove(field)
            .ok_or_else(|| self.err(format!("missing field `{field}` ({ty})")))
    }

    fn string(&mut self, field: &str) -> Result<String, StoreError> {
        match self.take(field, "string")? {
            toml::Value::String(s) => Ok(s),
            _ => Err(self.err(format!("field `{field}` must be a string"))),
        }
    }

    fn bool(&mut self, field: &str) -> Result<bool, StoreError> {
        match self.take(field, "boolean")? {
            toml::Value::Boolean(b) => Ok(b),
            _ => Err(self.err(format!("field `{field}` must be a boolean"))),
        }
    }

    fn integer(&mut self, field: &str) -> Result<i64, StoreError> {
        match self.take(field, "integer")? {
            toml::Value::Integer(i) => Ok(i),
            _ => Err(self.err(format!("field `{field}` must be an integer"))),
        }
    }

    /// Fails if any field is left over.
    fn finish(self) -> Result<(), StoreError> {
        match self.table.keys().next() {
            Some(k) => Err(self.err(format!("unknown field {k:?}"))),
            None => Ok(()),
        }
    }
}

fn invalid(file: &str, what: String, problem: String) -> StoreError {
    StoreError::Invalid {
        file: file.to_owned(),
        what,
        problem,
    }
}

impl Meta {
    pub fn to_toml(&self) -> String {
        to_toml_with_header(&RawMeta {
            version: VERSION,
            fingerprint: self.fingerprint.clone(),
        })
    }

    pub fn parse(text: &str) -> Result<Meta, StoreError> {
        let file = ".sec/meta.toml";
        let mut f = parse_top_level(file, text)?;
        let version = f.integer("version")?;
        if version != VERSION {
            return Err(StoreError::Version {
                file: file.to_owned(),
                version,
            });
        }
        let fingerprint = f.string("fingerprint")?;
        if fingerprint.len() != FINGERPRINT_HEX_LEN || decode_hex(&fingerprint).is_none() {
            return Err(f.err(format!(
                "field `fingerprint` must be {FINGERPRINT_HEX_LEN} lowercase hex characters"
            )));
        }
        f.finish()?;
        Ok(Meta { fingerprint })
    }
}

impl StackFile {
    pub fn to_toml(&self) -> String {
        let raw = RawStackFile {
            generated: self
                .generated
                .iter()
                .map(|(k, e)| {
                    let raw = RawGen {
                        id: e.id.to_hex(),
                        format: e.format.to_string(),
                        orphan: e.orphan,
                    };
                    (k.clone(), raw)
                })
                .collect(),
            secrets: self
                .secrets
                .iter()
                .map(|(k, e)| {
                    let raw = RawSecret {
                        nonce: hex(&e.sealed.nonce),
                        ciphertext: hex(&e.sealed.ciphertext),
                        orphan: e.orphan,
                    };
                    (k.clone(), raw)
                })
                .collect(),
        };
        to_toml_with_header(&raw)
    }

    /// Parses `.sec/<stem>.toml`. `stem` decides the scope of the keys
    /// (`shared` or a stack) and is used in errors.
    pub fn parse(stem: &str, text: &str) -> Result<StackFile, StoreError> {
        let file = format!(".sec/{stem}.toml");
        let file = file.as_str();
        let mut top = parse_top_level(file, text)?;
        let mut out = StackFile::default();

        if let Some(gens) = top.table.remove("gen") {
            let gens = Fields::new(file, "table `gen`".to_owned(), gens)?;
            for (key, value) in gens.table {
                let name = entry_name(file, stem, "gen", &key)?;
                let mut f = Fields::new(file, format!("gen `{name}`"), value)?;
                let id = GenId::from_hex(&f.string("id")?)
                    .map_err(|_| f.err("field `id` must be 32 lowercase hex characters".into()))?;
                let format = f
                    .string("format")?
                    .parse::<Format>()
                    .map_err(|e| f.err(format!("field `format`: {e}")))?;
                let orphan = f.bool("orphan")?;
                f.finish()?;
                out.generated.insert(key, GenEntry { id, format, orphan });
            }
        }

        if let Some(secrets) = top.table.remove("secret") {
            let secrets = Fields::new(file, "table `secret`".to_owned(), secrets)?;
            for (key, value) in secrets.table {
                let name = entry_name(file, stem, "secret", &key)?;
                let mut f = Fields::new(file, format!("secret `{name}`"), value)?;
                let nonce = decode_hex(&f.string("nonce")?)
                    .and_then(|n| <[u8; NONCE_LEN]>::try_from(n).ok())
                    .ok_or_else(|| {
                        f.err(format!(
                            "field `nonce` must be {} lowercase hex characters",
                            NONCE_LEN * 2
                        ))
                    })?;
                let ciphertext = decode_hex(&f.string("ciphertext")?)
                    .filter(|c| c.len() >= TAG_LEN)
                    .ok_or_else(|| {
                        f.err(format!(
                            "field `ciphertext` must be lowercase hex of at least {TAG_LEN} bytes"
                        ))
                    })?;
                let orphan = f.bool("orphan")?;
                f.finish()?;
                let sealed = Sealed { nonce, ciphertext };
                out.secrets.insert(key, SecretEntry { sealed, orphan });
            }
        }

        top.finish()?;
        Ok(out)
    }
}

/// Validates a key of file `stem` and returns its full name.
fn entry_name(file: &str, stem: &str, table: &str, key: &str) -> Result<String, StoreError> {
    // In a stack file, a `shared/…` key could never be reached: such names
    // live in shared.toml.
    if !is_valid_name(key) || (stem != SHARED && key.starts_with(SHARED_PREFIX)) {
        return Err(invalid(
            file,
            format!("table `{table}`"),
            format!("invalid secret name {key:?}"),
        ));
    }
    Ok(full_name(stem, key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{ID_LEN, SEED_LEN};
    use proptest::prelude::*;

    fn seed(b: u8) -> Seed {
        Seed::from_bytes([b; SEED_LEN])
    }

    fn gen_m(name: &str, format: &str) -> MarkerKind {
        MarkerKind::Gen {
            name: name.to_owned(),
            format: format.parse().unwrap(),
        }
    }

    fn secret_m(name: &str) -> MarkerKind {
        MarkerKind::Secret {
            name: name.to_owned(),
        }
    }

    fn set_m(name: &str, value: &str) -> MarkerKind {
        MarkerKind::Set {
            name: name.to_owned(),
            value: SecretString::new(value.to_owned()),
        }
    }

    fn uses(list: &[(&str, Vec<MarkerKind>)]) -> BTreeMap<String, Vec<MarkerKind>> {
        list.iter()
            .map(|(s, m)| ((*s).to_owned(), m.clone()))
            .collect()
    }

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    fn gen_entry<'a>(store: &'a Store, file: &str, key: &str) -> &'a GenEntry {
        &store.files[file].generated[key]
    }

    const FP: &str = "00112233445566778899aabbccddeeff";
    const ID_A: &str = "0123456789abcdef0123456789abcdef";
    const ID_B: &str = "fedcba9876543210fedcba9876543210";
    const NONCE: &str = "000102030405060708090a0b0c0d0e0f1011121314151617";
    const CT: &str = "00112233445566778899aabbccddeeff0011";

    fn canonical_stack() -> String {
        format!(
            "{HEADER}
[gen.\"a.b\"]
id = \"{ID_B}\"
format = \"uuid\"
orphan = true

[gen.db]
id = \"{ID_A}\"
format = \"alnum32\"
orphan = false

[gen.\"foo/bar\"]
id = \"{ID_B}\"
format = \"base64-22\"
orphan = false

[secret.cloudflare]
nonce = \"{NONCE}\"
ciphertext = \"{CT}\"
orphan = false
"
        )
    }

    // --- scoping ---------------------------------------------------------

    #[test]
    fn scope_splits_shared_and_stack_names() {
        let s = scope("web", "db").unwrap();
        assert_eq!((s.file.as_str(), s.key.as_str()), ("web", "db"));
        assert_eq!(s.full_name, "web/db");
        let s = scope("web", "shared/mqtt").unwrap();
        assert_eq!((s.file.as_str(), s.key.as_str()), ("shared", "mqtt"));
        assert_eq!(s.full_name, "shared/mqtt");
        let s = scope("web", "foo/bar").unwrap();
        assert_eq!((s.file.as_str(), s.key.as_str()), ("web", "foo/bar"));
        assert_eq!(s.full_name, "web/foo/bar");
        // `shared` alone is an ordinary name.
        assert_eq!(scope("web", "shared").unwrap().file, "web");
    }

    #[test]
    fn scope_rejects_bad_stacks_and_names() {
        for stack in [
            "", ".hidden", "shared", "meta", "Shared", "META", "a b", "a/b", "ü",
        ] {
            assert!(matches!(scope(stack, "x"), Err(StoreError::InvalidStack(s)) if s == stack));
        }
        for stack in ["web", "Web-1", "a.b", "a_b", "x."] {
            assert!(is_valid_stack(stack), "{stack}");
        }
        for name in [
            "",
            "a:b",
            "a>>b",
            "/a",
            "a/",
            "a//b",
            "x>><<secret:y",
            "a b",
            "a\0b",
        ] {
            assert!(matches!(scope("web", name), Err(StoreError::InvalidName(n)) if n == name));
        }
    }

    // --- seed ------------------------------------------------------------

    #[test]
    fn init_and_verify_seed() {
        let store = Store::init(&seed(1));
        assert_eq!(store.meta().fingerprint, crypto::fingerprint(&seed(1)));
        assert!(store.files().is_empty());
        store.verify_seed(&seed(1)).unwrap();
        let err = store.verify_seed(&seed(2)).unwrap_err();
        assert!(matches!(err, StoreError::FingerprintMismatch));
        assert!(err.to_string().contains("wrong seed"));
    }

    // --- serialisation -----------------------------------------------------

    #[test]
    fn canonical_stack_file_round_trips_byte_for_byte() {
        let text = canonical_stack();
        let file = StackFile::parse("web", &text).unwrap();
        assert_eq!(file.generated.len(), 3);
        let db = &file.generated["db"];
        assert_eq!(db.id.to_hex(), ID_A);
        assert_eq!(db.format, Format::Alnum(32));
        assert!(!db.orphan);
        assert!(file.generated["a.b"].orphan);
        assert_eq!(file.generated["foo/bar"].format, Format::Base64(22));
        let cf = &file.secrets["cloudflare"];
        assert_eq!(hex(&cf.sealed.nonce), NONCE);
        assert_eq!(hex(&cf.sealed.ciphertext), CT);
        assert_eq!(file.to_toml(), text);
    }

    #[test]
    fn only_gen_or_only_secret_or_nothing() {
        let only_secret = format!(
            "{HEADER}\n[secret.x]\nnonce = \"{NONCE}\"\nciphertext = \"{CT}\"\norphan = true\n"
        );
        let f = StackFile::parse("web", &only_secret).unwrap();
        assert!(f.generated.is_empty());
        assert_eq!(f.to_toml(), only_secret);

        let only_gen =
            format!("{HEADER}\n[gen.x]\nid = \"{ID_A}\"\nformat = \"hex64\"\norphan = false\n");
        let f = StackFile::parse("web", &only_gen).unwrap();
        assert!(f.secrets.is_empty());
        assert_eq!(f.to_toml(), only_gen);

        assert_eq!(StackFile::default().to_toml(), HEADER);
        assert_eq!(
            StackFile::parse("web", HEADER).unwrap(),
            StackFile::default()
        );
        assert_eq!(StackFile::parse("web", "").unwrap(), StackFile::default());
    }

    #[test]
    fn canonical_meta_round_trips() {
        let text = format!("{HEADER}\nversion = 1\nfingerprint = \"{FP}\"\n");
        let meta = Meta::parse(&text).unwrap();
        assert_eq!(meta.fingerprint, FP);
        assert_eq!(meta.to_toml(), text);
    }

    #[test]
    fn shared_file_allows_shared_prefixed_keys_stack_files_do_not() {
        let text =
            format!("[gen.\"shared/x\"]\nid = \"{ID_A}\"\nformat = \"uuid\"\norphan = false\n");
        StackFile::parse("shared", &text).unwrap();
        let err = StackFile::parse("web", &text).unwrap_err();
        assert_eq!(
            err.to_string(),
            ".sec/web.toml: table `gen`: invalid secret name \"shared/x\""
        );
    }

    fn parse_err(text: &str) -> String {
        StackFile::parse("web", text).unwrap_err().to_string()
    }

    fn gen_table(id: &str, format: &str, extra: &str) -> String {
        format!("[gen.db]\nid = {id}\nformat = {format}\n{extra}")
    }

    #[test]
    fn stack_file_rejects_bad_gen_entries() {
        let id = format!("\"{ID_A}\"");
        let bad_id = ".sec/web.toml: gen `web/db`: field `id` must be 32 lowercase hex characters";
        let cases: Vec<(String, &str)> = vec![
            ("[gen\n".into(), ".sec/web.toml: invalid TOML at line 1:"),
            (
                "x = 1\n\n= 2\n".into(),
                ".sec/web.toml: invalid TOML at line 3:",
            ),
            (
                "other = 1\n".into(),
                ".sec/web.toml: top level: unknown field \"other\"",
            ),
            (
                "gen = 1\n".into(),
                ".sec/web.toml: table `gen`: expected a table",
            ),
            (
                "[gen]\ndb = 1\n".into(),
                ".sec/web.toml: gen `web/db`: expected a table",
            ),
            (
                "[gen.\"a:b\"]\n".into(),
                ".sec/web.toml: table `gen`: invalid secret name \"a:b\"",
            ),
            (
                "[gen.db]\nformat = \"uuid\"\norphan = false\n".into(),
                ".sec/web.toml: gen `web/db`: missing field `id` (string)",
            ),
            (
                gen_table("1", "\"uuid\"", "orphan = false\n"),
                ".sec/web.toml: gen `web/db`: field `id` must be a string",
            ),
            (
                gen_table("\"0123\"", "\"uuid\"", "orphan = false\n"),
                bad_id,
            ),
            (
                gen_table(&id.to_uppercase(), "\"uuid\"", "orphan = false\n"),
                bad_id,
            ),
            (
                format!("[gen.db]\nid = {id}\norphan = false\n"),
                ".sec/web.toml: gen `web/db`: missing field `format` (string)",
            ),
            (
                gen_table(&id, "\"alnum\"", "orphan = false\n"),
                ".sec/web.toml: gen `web/db`: field `format`: unknown format",
            ),
            (
                gen_table(&id, "\"hex8\"", "orphan = false\n"),
                ".sec/web.toml: gen `web/db`: field `format`: format length must be between 32 and 256",
            ),
            (
                gen_table(&id, "\"uuid\"", ""),
                ".sec/web.toml: gen `web/db`: missing field `orphan` (boolean)",
            ),
            (
                gen_table(&id, "\"uuid\"", "orphan = \"no\"\n"),
                ".sec/web.toml: gen `web/db`: field `orphan` must be a boolean",
            ),
            (
                gen_table(&id, "\"uuid\"", "orphan = false\nvalue = \"x\"\n"),
                ".sec/web.toml: gen `web/db`: unknown field \"value\"",
            ),
        ];
        for (text, want) in cases {
            let got = parse_err(&text);
            assert!(got.starts_with(want), "{text:?}: {got}");
        }
    }

    fn secret_table(nonce: &str, ct: &str, extra: &str) -> String {
        format!("[secret.cf]\nnonce = \"{nonce}\"\nciphertext = \"{ct}\"\n{extra}")
    }

    #[test]
    fn stack_file_rejects_bad_secret_entries() {
        let bad_nonce =
            ".sec/web.toml: secret `web/cf`: field `nonce` must be 48 lowercase hex characters";
        let bad_ct = ".sec/web.toml: secret `web/cf`: field `ciphertext` must be lowercase hex \
                      of at least 16 bytes";
        let ok = "orphan = false\n";
        let cases: Vec<(String, &str)> = vec![
            (
                "secret = []\n".into(),
                ".sec/web.toml: table `secret`: expected a table",
            ),
            (
                "[secret]\ncf = \"x\"\n".into(),
                ".sec/web.toml: secret `web/cf`: expected a table",
            ),
            (
                "[secret.\"a b\"]\n".into(),
                ".sec/web.toml: table `secret`: invalid secret name \"a b\"",
            ),
            (
                "[secret.cf]\nciphertext = \"\"\norphan = false\n".into(),
                ".sec/web.toml: secret `web/cf`: missing field `nonce` (string)",
            ),
            (
                format!("[secret.cf]\nnonce = \"{NONCE}\"\norphan = false\n"),
                ".sec/web.toml: secret `web/cf`: missing field `ciphertext` (string)",
            ),
            (
                format!("[secret.cf]\nnonce = \"{NONCE}\"\nciphertext = 1\norphan = false\n"),
                ".sec/web.toml: secret `web/cf`: field `ciphertext` must be a string",
            ),
            (secret_table(&NONCE[2..], CT, ok), bad_nonce),
            (secret_table(&format!("{NONCE}00"), CT, ok), bad_nonce),
            (secret_table(&NONCE[1..], CT, ok), bad_nonce),
            (secret_table(&NONCE.replace('a', "A"), CT, ok), bad_nonce),
            (secret_table(NONCE, &CT[1..], ok), bad_ct),
            (secret_table(NONCE, &CT[..30], ok), bad_ct),
            (secret_table(NONCE, &CT.replace('a', "g"), ok), bad_ct),
            (
                secret_table(NONCE, CT, ""),
                ".sec/web.toml: secret `web/cf`: missing field `orphan` (boolean)",
            ),
            (
                secret_table(NONCE, CT, "orphan = false\nplain = 1\n"),
                ".sec/web.toml: secret `web/cf`: unknown field \"plain\"",
            ),
        ];
        for (text, want) in cases {
            let got = parse_err(&text);
            assert!(got.starts_with(want), "{text:?}: {got}");
        }
        // Exactly 16 bytes (an empty plaintext) is fine.
        StackFile::parse("web", &secret_table(NONCE, &CT[..32], ok)).unwrap();
    }

    #[test]
    fn parse_errors_never_quote_values() {
        let marker_value = "deadbeefcafe0000deadbeefcafe000X";
        let err = parse_err(&gen_table(
            &format!("\"{marker_value}\""),
            "\"uuid\"",
            "orphan = false\n",
        ));
        assert!(!err.contains(marker_value), "{err}");
        let err = parse_err(&secret_table("hunter2hunter2", CT, "orphan = false\n"));
        assert!(!err.contains("hunter2"), "{err}");
        let err = Meta::parse("version = 1\nfingerprint = \"hunter2\"\n")
            .unwrap_err()
            .to_string();
        assert!(!err.contains("hunter2"), "{err}");
    }

    #[test]
    fn meta_rejects_bad_input() {
        let fp = format!("fingerprint = \"{FP}\"\n");
        let bad_fp =
            ".sec/meta.toml: top level: field `fingerprint` must be 32 lowercase hex characters";
        let cases: Vec<(String, &str)> = vec![
            (
                "version =\n".into(),
                ".sec/meta.toml: invalid TOML at line 1:",
            ),
            (
                fp.clone(),
                ".sec/meta.toml: top level: missing field `version` (integer)",
            ),
            (
                format!("version = \"1\"\n{fp}"),
                ".sec/meta.toml: top level: field `version` must be an integer",
            ),
            (
                format!("version = 2\n{fp}"),
                ".sec/meta.toml: unsupported .sec format version 2 (this lst supports version 1)",
            ),
            (
                format!("version = 0\n{fp}"),
                ".sec/meta.toml: unsupported .sec format version 0",
            ),
            (
                "version = 1\n".into(),
                ".sec/meta.toml: top level: missing field `fingerprint` (string)",
            ),
            (
                "version = 1\nfingerprint = 5\n".into(),
                ".sec/meta.toml: top level: field `fingerprint` must be a string",
            ),
            (
                format!("version = 1\nfingerprint = \"{}\"\n", FP.to_uppercase()),
                bad_fp,
            ),
            (format!("version = 1\nfingerprint = \"{FP}00\"\n"), bad_fp),
            (
                format!("version = 1\n{fp}extra = true\n"),
                ".sec/meta.toml: top level: unknown field \"extra\"",
            ),
        ];
        for (text, want) in cases {
            let got = Meta::parse(&text).unwrap_err().to_string();
            assert!(got.starts_with(want), "{text:?}: {got}");
        }
    }

    #[test]
    fn from_files_rejects_bad_stems() {
        let meta = Store::init(&seed(1)).meta().to_toml();
        for stem in ["meta", "Meta", "SHARED", ".x", "a b", ""] {
            let files = BTreeMap::from([(stem.to_owned(), String::new())]);
            let err = Store::from_files(&meta, &files).unwrap_err();
            assert!(
                matches!(&err, StoreError::InvalidFileName { name } if *name == format!("{stem}.toml")),
                "{err}"
            );
        }
        let files = BTreeMap::from([("shared".to_owned(), String::new())]);
        let store = Store::from_files(&meta, &files).unwrap();
        assert_eq!(store.files()["shared"], StackFile::default());
    }

    fn stems_of(files: &BTreeMap<String, String>) -> BTreeMap<String, String> {
        files
            .iter()
            .filter(|(k, _)| *k != "meta.toml")
            .map(|(k, v)| (k.trim_end_matches(".toml").to_owned(), v.clone()))
            .collect()
    }

    #[test]
    fn to_files_names_and_contents() {
        let mut store = Store::init(&seed(1));
        store
            .sync(&uses(&[(
                "web",
                vec![gen_m("db", "alnum32"), gen_m("shared/m", "uuid")],
            )]))
            .unwrap();
        let files = store.to_files();
        assert_eq!(
            files.keys().collect::<Vec<_>>(),
            ["meta.toml", "shared.toml", "web.toml"]
        );
        assert_eq!(files["meta.toml"], store.meta().to_toml());
        assert_eq!(files["web.toml"], store.files()["web"].to_toml());
        let back = Store::from_files(&files["meta.toml"], &stems_of(&files)).unwrap();
        assert_eq!(back, store);
    }

    // --- sync --------------------------------------------------------------

    #[test]
    fn sync_adds_new_gen_names_then_is_idempotent() {
        let mut store = Store::init(&seed(1));
        let u = uses(&[
            (
                "web",
                vec![
                    gen_m("db", "alnum32"),
                    gen_m("db", "alnum32"),
                    gen_m("api", "hex64"),
                ],
            ),
            ("db", vec![gen_m("db", "alnum32")]),
        ]);
        let report = store.sync(&u).unwrap();
        assert_eq!(report.added, names(&["db/db", "web/api", "web/db"]));
        assert!(report.format_changed.is_empty() && report.orphaned.is_empty());
        assert_eq!(gen_entry(&store, "web", "api").format, Format::Hex(64));
        assert!(!gen_entry(&store, "web", "db").orphan);
        // Fresh random ids per name.
        assert_ne!(
            gen_entry(&store, "web", "db").id,
            gen_entry(&store, "db", "db").id
        );

        let before = store.clone();
        let report = store.sync(&u).unwrap();
        assert!(report.is_empty(), "{report:?}");
        assert_eq!(store, before);
    }

    #[test]
    fn sync_updates_changed_formats_and_keeps_ids() {
        let mut store = Store::init(&seed(1));
        store
            .sync(&uses(&[("web", vec![gen_m("db", "alnum32")])]))
            .unwrap();
        let id = gen_entry(&store, "web", "db").id;
        let report = store
            .sync(&uses(&[("web", vec![gen_m("db", "hex64")])]))
            .unwrap();
        assert_eq!(
            report.format_changed,
            vec![FormatChange {
                name: "web/db".into(),
                from: Format::Alnum(32),
                to: Format::Hex(64),
            }]
        );
        assert!(report.added.is_empty());
        let e = gen_entry(&store, "web", "db");
        assert_eq!((e.id, e.format), (id, Format::Hex(64)));
    }

    #[test]
    fn sync_rejects_conflicting_formats_in_one_scope() {
        let mut store = Store::init(&seed(1));
        let err = store
            .sync(&uses(&[(
                "web",
                vec![gen_m("db", "alnum32"), gen_m("db", "hex64")],
            )]))
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "`web/db` is used with two different formats: alnum32 and hex64"
        );
        // shared/ across stacks.
        let err = store
            .sync(&uses(&[
                ("a", vec![gen_m("shared/mqtt", "uuid")]),
                ("b", vec![gen_m("shared/mqtt", "alnum32")]),
            ]))
            .unwrap_err();
        assert!(matches!(
            err,
            StoreError::FormatConflict { ref name, first: Format::Uuid, second: Format::Alnum(32) }
                if name == "shared/mqtt"
        ));
        // The same stack-local name in two stacks is two secrets.
        let report = store
            .sync(&uses(&[
                ("a", vec![gen_m("db", "uuid")]),
                ("b", vec![gen_m("db", "alnum32")]),
            ]))
            .unwrap();
        assert_eq!(report.added, names(&["a/db", "b/db"]));
    }

    #[test]
    fn sync_shares_shared_names_across_stacks() {
        let mut store = Store::init(&seed(1));
        let report = store
            .sync(&uses(&[
                ("a", vec![gen_m("shared/mqtt", "uuid")]),
                ("b", vec![gen_m("shared/mqtt", "uuid")]),
            ]))
            .unwrap();
        assert_eq!(report.added, names(&["shared/mqtt"]));
        assert_eq!(store.files().keys().collect::<Vec<_>>(), ["shared"]);
        // Still used by b → not an orphan.
        let report = store
            .sync(&uses(&[
                ("a", vec![]),
                ("b", vec![gen_m("shared/mqtt", "uuid")]),
            ]))
            .unwrap();
        assert!(report.is_empty());
        // Used by nobody → orphan.
        let report = store.sync(&uses(&[("a", vec![]), ("b", vec![])])).unwrap();
        assert_eq!(report.orphaned, names(&["shared/mqtt"]));
    }

    #[test]
    fn sync_rejects_gen_and_secret_with_the_same_key() {
        let mut store = Store::init(&seed(1));
        for markers in [
            vec![gen_m("x", "uuid"), secret_m("x")],
            vec![secret_m("x"), gen_m("x", "uuid")],
        ] {
            let err = store.sync(&uses(&[("web", markers)])).unwrap_err();
            assert_eq!(
                err.to_string(),
                "`web/x` is used both as <<gen:…>> and as <<secret:…>>"
            );
        }
        let err = store
            .sync(&uses(&[
                ("a", vec![gen_m("shared/x", "uuid")]),
                ("b", vec![secret_m("shared/x")]),
            ]))
            .unwrap_err();
        assert!(matches!(err, StoreError::KindConflict { ref name } if name == "shared/x"));
    }

    #[test]
    fn sync_rejects_set_markers_bad_stacks_and_bad_names() {
        let mut store = Store::init(&seed(1));
        let err = store
            .sync(&uses(&[("web", vec![set_m("cf", "hunter2")])]))
            .unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, StoreError::SetUnsupported { ref name } if name == "web/cf"));
        assert!(
            msg.contains("pre-commit hook") && !msg.contains("hunter2"),
            "{msg}"
        );
        assert!(!format!("{err:?}").contains("hunter2"));

        let err = store.sync(&uses(&[("shared", vec![])])).unwrap_err();
        assert!(matches!(err, StoreError::InvalidStack(ref s) if s == "shared"));
        let err = store
            .sync(&uses(&[("web", vec![secret_m("a:b")])]))
            .unwrap_err();
        assert!(matches!(err, StoreError::InvalidName(ref s) if s == "a:b"));
    }

    #[test]
    fn sync_is_atomic_on_error() {
        let mut store = Store::init(&seed(1));
        store
            .sync(&uses(&[("web", vec![gen_m("db", "uuid")])]))
            .unwrap();
        let before = store.clone();
        // `a` would add an entry and orphan web/db, but `z` fails.
        let err = store.sync(&uses(&[
            ("a", vec![gen_m("new", "uuid")]),
            ("z", vec![set_m("x", "v")]),
        ]));
        assert!(err.is_err());
        assert_eq!(store, before);
    }

    #[test]
    fn sync_orphans_and_unorphans_never_deletes() {
        let s1 = seed(1);
        let mut store = Store::init(&s1);
        store
            .sync(&uses(&[
                ("web", vec![gen_m("db", "uuid"), gen_m("api", "uuid")]),
                ("old", vec![gen_m("db", "uuid")]),
            ]))
            .unwrap();
        store.set_secret(&s1, "web", "cf", "token").unwrap();
        let id = gen_entry(&store, "web", "db").id;

        // `old` is gone entirely; web/api and web/cf are unused.
        let only_db = uses(&[("web", vec![gen_m("db", "uuid")])]);
        let report = store.sync(&only_db).unwrap();
        assert_eq!(report.orphaned, names(&["old/db", "web/api", "web/cf"]));
        assert!(store.files().contains_key("old"));
        assert!(gen_entry(&store, "old", "db").orphan);
        assert!(store.files()["web"].secrets["cf"].orphan);
        // Orphaning is reported once.
        assert!(store.sync(&only_db).unwrap().is_empty());

        // Coming back keeps the id (so the value).
        let report = store
            .sync(&uses(&[
                (
                    "web",
                    vec![gen_m("db", "uuid"), gen_m("api", "uuid"), secret_m("cf")],
                ),
                ("old", vec![gen_m("db", "uuid")]),
            ]))
            .unwrap();
        assert_eq!(report.unorphaned, names(&["old/db", "web/api", "web/cf"]));
        assert!(report.added.is_empty() && report.orphaned.is_empty());
        assert_eq!(gen_entry(&store, "web", "db").id, id);
        assert!(!store.files()["web"].secrets["cf"].orphan);

        // Un-orphan and format change at once.
        store.sync(&uses(&[("web", vec![])])).unwrap();
        let report = store
            .sync(&uses(&[("web", vec![gen_m("db", "hex32")])]))
            .unwrap();
        assert_eq!(report.unorphaned, names(&["web/db"]));
        assert_eq!(report.format_changed.len(), 1);
    }

    #[test]
    fn sync_reports_unset_secrets_without_creating_files() {
        let mut store = Store::init(&seed(1));
        let report = store
            .sync(&uses(&[(
                "web",
                vec![secret_m("cf"), secret_m("shared/smtp")],
            )]))
            .unwrap();
        assert_eq!(report.unset, names(&["shared/smtp", "web/cf"]));
        assert!(!report.is_empty());
        assert!(store.files().is_empty());
        // A used, stored secret is neither unset nor reported.
        store.set_secret(&seed(1), "web", "cf", "v").unwrap();
        let report = store.sync(&uses(&[("web", vec![secret_m("cf")])])).unwrap();
        assert!(report.is_empty(), "{report:?}");
    }

    #[test]
    fn sync_switching_kind_orphans_the_old_entry() {
        let s1 = seed(1);
        let mut store = Store::init(&s1);
        store.set_secret(&s1, "web", "x", "v").unwrap();
        let report = store
            .sync(&uses(&[("web", vec![gen_m("x", "uuid")])]))
            .unwrap();
        assert_eq!(report.added, names(&["web/x"]));
        assert_eq!(report.orphaned, names(&["web/x"]));
        let f = &store.files()["web"];
        assert!(f.secrets["x"].orphan && !f.generated["x"].orphan);
        // And back.
        let report = store.sync(&uses(&[("web", vec![secret_m("x")])])).unwrap();
        assert_eq!(report.unorphaned, names(&["web/x"]));
        assert_eq!(report.orphaned, names(&["web/x"]));
    }

    #[test]
    fn sync_report_is_sorted_by_full_name() {
        let mut store = Store::init(&seed(1));
        // File order would be "a" < "a-b"; full-name order is "a-b/c" < "a/z".
        let report = store
            .sync(&uses(&[
                ("a", vec![gen_m("z", "uuid"), secret_m("z2")]),
                ("a-b", vec![gen_m("c", "uuid"), secret_m("c2")]),
            ]))
            .unwrap();
        assert_eq!(report.added, names(&["a-b/c", "a/z"]));
        assert_eq!(report.unset, names(&["a-b/c2", "a/z2"]));
        let hex32 = uses(&[
            ("a", vec![gen_m("z", "hex32")]),
            ("a-b", vec![gen_m("c", "hex32")]),
        ]);
        let report = store.sync(&hex32).unwrap();
        let changed: Vec<_> = report
            .format_changed
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(changed, ["a-b/c", "a/z"]);
        let report = store.sync(&BTreeMap::new()).unwrap();
        assert_eq!(report.orphaned, names(&["a-b/c", "a/z"]));
        let report = store.sync(&hex32).unwrap();
        assert_eq!(report.unorphaned, names(&["a-b/c", "a/z"]));
    }

    #[test]
    fn sync_report_is_empty_only_when_every_list_is() {
        assert!(SyncReport::default().is_empty());
        let one = || vec!["x".to_owned()];
        let change = vec![FormatChange {
            name: "x".into(),
            from: Format::Uuid,
            to: Format::Hex(32),
        }];
        for r in [
            SyncReport {
                added: one(),
                ..Default::default()
            },
            SyncReport {
                format_changed: change,
                ..Default::default()
            },
            SyncReport {
                orphaned: one(),
                ..Default::default()
            },
            SyncReport {
                unorphaned: one(),
                ..Default::default()
            },
            SyncReport {
                unset: one(),
                ..Default::default()
            },
        ] {
            assert!(!r.is_empty(), "{r:?}");
        }
    }

    // --- set_secret --------------------------------------------------------

    fn secret_entry_mut<'a>(store: &'a mut Store, file: &str, key: &str) -> &'a mut SecretEntry {
        store
            .files
            .get_mut(file)
            .unwrap()
            .secrets
            .get_mut(key)
            .unwrap()
    }

    #[test]
    fn set_secret_only_reseals_changed_values() {
        let s1 = seed(1);
        let mut store = Store::init(&s1);
        assert!(store.set_secret(&s1, "web", "cf", "token-1").unwrap());
        let sealed = store.files()["web"].secrets["cf"].clone();
        assert!(!sealed.orphan);
        // Same value: nothing changes (no fresh nonce).
        assert!(!store.set_secret(&s1, "web", "cf", "token-1").unwrap());
        assert_eq!(store.files()["web"].secrets["cf"], sealed);
        // New value: re-sealed, orphan flag kept.
        secret_entry_mut(&mut store, "web", "cf").orphan = true;
        assert!(store.set_secret(&s1, "web", "cf", "token-2").unwrap());
        let e = &store.files()["web"].secrets["cf"];
        assert_ne!(e.sealed, sealed.sealed);
        assert!(e.orphan);
        let v = store.resolve(&s1, "web", &secret_m("cf")).unwrap();
        assert_eq!(v.expose(), "token-2");
        // shared/ scoping and binding to the full name.
        store.set_secret(&s1, "a", "shared/smtp", "pw").unwrap();
        let e = &store.files()["shared"].secrets["smtp"];
        let key = crypto::encryption_key(&s1);
        let opened = crypto::open(&key, "shared/smtp", &e.sealed).unwrap();
        assert_eq!(opened.expose(), "pw");
    }

    #[test]
    fn set_secret_errors() {
        let s1 = seed(1);
        let mut store = Store::init(&s1);
        assert!(matches!(
            store.set_secret(&seed(2), "web", "cf", "v"),
            Err(StoreError::FingerprintMismatch)
        ));
        assert!(matches!(
            store.set_secret(&s1, "web", "a:b", "v"),
            Err(StoreError::InvalidName(_))
        ));
        assert!(matches!(
            store.set_secret(&s1, "shared", "x", "v"),
            Err(StoreError::InvalidStack(_))
        ));
        assert!(store.files().is_empty());

        // An existing value that doesn't decrypt is never overwritten.
        store.set_secret(&s1, "web", "cf", "hunter2").unwrap();
        let e = secret_entry_mut(&mut store, "web", "cf");
        e.sealed.ciphertext[0] ^= 1;
        let tampered = e.clone();
        let err = store.set_secret(&s1, "web", "cf", "new").unwrap_err();
        assert!(matches!(
            err,
            StoreError::Crypto { ref name, source: CryptoError::Decrypt } if name == "web/cf"
        ));
        assert!(err.to_string().starts_with("`web/cf`: decryption failed"));
        assert_eq!(store.files()["web"].secrets["cf"], tampered);
    }

    // --- rename candidates -------------------------------------------------

    fn pairs(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter()
            .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
            .collect()
    }

    #[test]
    fn sync_reports_one_out_one_in_as_rename_candidates() {
        let s1 = seed(1);
        let mut store = Store::init(&s1);
        store
            .sync(&uses(&[
                ("web", vec![gen_m("db", "uuid"), gen_m("keep", "uuid")]),
                ("app", vec![gen_m("shared/mqtt", "uuid")]),
            ]))
            .unwrap();
        store.set_secret(&s1, "web", "cf", "v").unwrap();
        store.set_secret(&s1, "app", "shared/smtp", "v").unwrap();
        let report = store
            .sync(&uses(&[
                (
                    "web",
                    vec![
                        gen_m("database", "uuid"),
                        gen_m("keep", "uuid"),
                        secret_m("cloudflare"),
                    ],
                ),
                (
                    "app",
                    vec![gen_m("shared/broker", "uuid"), secret_m("shared/mail")],
                ),
            ]))
            .unwrap();
        assert_eq!(
            report.rename_candidates,
            pairs(&[
                ("shared/mqtt", "shared/broker"),
                ("shared/smtp", "shared/mail"),
                ("web/cf", "web/cloudflare"),
                ("web/db", "web/database"),
            ])
        );
        // Reported once: the next sync orphans nothing.
        let report = store
            .sync(&uses(&[(
                "web",
                vec![gen_m("database", "uuid"), gen_m("keep", "uuid")],
            )]))
            .unwrap();
        assert!(report.rename_candidates.is_empty(), "{report:?}");
    }

    #[test]
    fn rename_candidates_need_exactly_one_of_each_in_one_file_and_kind() {
        let base = || {
            let s1 = seed(1);
            let mut store = Store::init(&s1);
            store
                .sync(&uses(&[(
                    "web",
                    vec![gen_m("a", "uuid"), gen_m("b", "uuid")],
                )]))
                .unwrap();
            store.set_secret(&s1, "web", "s", "v").unwrap();
            store
        };
        let none = |u: BTreeMap<String, Vec<MarkerKind>>| {
            let report = base().sync(&u).unwrap();
            assert!(report.rename_candidates.is_empty(), "{report:?}");
            report
        };
        // Two out, one in.
        none(uses(&[("web", vec![gen_m("c", "uuid"), secret_m("s")])]));
        // One out, two in.
        none(uses(&[(
            "web",
            vec![
                gen_m("a", "uuid"),
                gen_m("c", "uuid"),
                gen_m("d", "uuid"),
                secret_m("s"),
            ],
        )]));
        // Cross-kind: a gen leaves and a secret appears, or the reverse.
        let r = none(uses(&[(
            "web",
            vec![gen_m("a", "uuid"), secret_m("s"), secret_m("t")],
        )]));
        assert_eq!(r.orphaned, names(&["web/b"]));
        let r = none(uses(&[(
            "web",
            vec![gen_m("a", "uuid"), gen_m("b", "uuid"), gen_m("t", "uuid")],
        )]));
        assert_eq!(r.orphaned, names(&["web/s"]));
        // Cross-file: web/b leaves, other/b appears.
        none(uses(&[
            ("web", vec![gen_m("a", "uuid"), secret_m("s")]),
            ("other", vec![gen_m("b", "uuid")]),
        ]));
        // Cross-file into shared.
        none(uses(&[(
            "web",
            vec![gen_m("a", "uuid"), gen_m("shared/b", "uuid"), secret_m("s")],
        )]));
        // Candidates alone never make a report non-empty.
        let only = SyncReport {
            rename_candidates: pairs(&[("web/a", "web/b")]),
            ..Default::default()
        };
        assert!(only.is_empty());
    }

    // --- rename --------------------------------------------------------------

    #[test]
    fn parse_full_name_rules() {
        for (full, file, key) in [
            ("web/db", "web", "db"),
            ("shared/x", "shared", "x"),
            ("web/foo/bar", "web", "foo/bar"),
            ("shared/shared/x", "shared", "shared/x"),
            ("web/shared", "web", "shared"),
        ] {
            let s = parse_full_name(full).unwrap();
            assert_eq!((s.file.as_str(), s.key.as_str()), (file, key), "{full}");
            assert_eq!(s.full_name, full);
        }
        for bad in [
            "",
            "db",
            "web/",
            "/db",
            "web//db",
            "web/a:b",
            "meta/x",
            "Shared/x",
            ".x/y",
            "web/shared/x",
            "a b/c",
        ] {
            let err = parse_full_name(bad).unwrap_err();
            assert!(
                matches!(&err, StoreError::InvalidFullName(n) if n == bad),
                "{bad:?}: {err:?}"
            );
            assert!(
                err.to_string()
                    .contains("expected <stack>/<name> or shared/<name>")
            );
        }
    }

    fn renamable() -> (Seed, Store) {
        let s1 = seed(1);
        let mut store = Store::init(&s1);
        store
            .sync(&uses(&[
                (
                    "web",
                    vec![
                        gen_m("db", "hex64"),
                        gen_m("other", "uuid"),
                        gen_m("shared/x", "alnum32"),
                    ],
                ),
                ("api", vec![gen_m("db", "uuid")]),
            ]))
            .unwrap();
        store.set_secret(&s1, "web", "cf", "t0ken:value").unwrap();
        (s1, store)
    }

    fn resolved(store: &Store, seed: &Seed, stack: &str, m: &MarkerKind) -> String {
        store.resolve(seed, stack, m).unwrap().expose().to_owned()
    }

    #[test]
    fn rename_gen_keeps_id_and_value_and_unorphans() {
        let (s1, mut store) = renamable();
        let before = resolved(&store, &s1, "web", &gen_m("db", "hex64"));
        let id = gen_entry(&store, "web", "db").id;
        store
            .files
            .get_mut("web")
            .unwrap()
            .generated
            .get_mut("db")
            .unwrap()
            .orphan = true;
        let other = store.files()["api"].clone();

        let out = store.rename(&s1, "web/db", "web/database", false).unwrap();
        assert_eq!(
            out,
            RenameOutcome {
                from: "web/db".into(),
                to: "web/database".into(),
                kind: EntryKind::Gen,
                replaced: false,
            }
        );
        let e = gen_entry(&store, "web", "database");
        assert_eq!((e.id, e.format, e.orphan), (id, Format::Hex(64), false));
        assert!(!store.files()["web"].generated.contains_key("db"));
        assert_eq!(
            resolved(&store, &s1, "web", &gen_m("database", "hex64")),
            before
        );
        // Other entries untouched.
        assert_eq!(store.files()["api"], other);
        assert!(store.files()["web"].generated.contains_key("other"));
        assert!(store.files()["web"].secrets.contains_key("cf"));
    }

    #[test]
    fn rename_gen_across_scopes() {
        let (s1, mut store) = renamable();
        let db = resolved(&store, &s1, "web", &gen_m("db", "hex64"));
        let x = resolved(&store, &s1, "web", &gen_m("shared/x", "alnum32"));

        // stack → shared.
        store.rename(&s1, "web/db", "shared/db", false).unwrap();
        assert_eq!(
            resolved(&store, &s1, "api", &gen_m("shared/db", "hex64")),
            db
        );
        // shared → stack; shared.toml is left empty but kept.
        store.rename(&s1, "shared/x", "api/x", false).unwrap();
        assert_eq!(resolved(&store, &s1, "api", &gen_m("x", "alnum32")), x);
        assert!(store.files()["shared"].generated.contains_key("db"));
        store.rename(&s1, "shared/db", "web/db", false).unwrap();
        assert_eq!(store.files()["shared"], StackFile::default());
        assert_eq!(store.to_files()["shared.toml"], HEADER);
        // Into a file that doesn't exist yet.
        store.rename(&s1, "web/db", "new/db", false).unwrap();
        assert_eq!(resolved(&store, &s1, "new", &gen_m("db", "hex64")), db);
    }

    #[test]
    fn rename_secret_reseals_under_the_new_name() {
        let (s1, mut store) = renamable();
        let old = store.files()["web"].secrets["cf"].clone();
        let mut orphaned = store.clone();
        let key = crypto::encryption_key(&s1);

        let out = store
            .rename(&s1, "web/cf", "web/cloudflare", false)
            .unwrap();
        assert_eq!((out.kind, out.replaced), (EntryKind::Secret, false));
        let e = &store.files()["web"].secrets["cloudflare"];
        assert!(!e.orphan);
        assert_ne!(e.sealed.nonce, old.sealed.nonce);
        assert!(!store.files()["web"].secrets.contains_key("cf"));
        // Bound to the new name only.
        assert_eq!(
            crypto::open(&key, "web/cloudflare", &e.sealed)
                .unwrap()
                .expose(),
            "t0ken:value"
        );
        assert!(crypto::open(&key, "web/cf", &e.sealed).is_err());
        assert_eq!(
            resolved(&store, &s1, "web", &secret_m("cloudflare")),
            "t0ken:value"
        );

        // Across scopes, from an orphaned entry.
        secret_entry_mut(&mut orphaned, "web", "cf").orphan = true;
        orphaned.rename(&s1, "web/cf", "shared/cf", false).unwrap();
        assert!(!orphaned.files()["shared"].secrets["cf"].orphan);
        assert_eq!(
            resolved(&orphaned, &s1, "any", &secret_m("shared/cf")),
            "t0ken:value"
        );
        orphaned.rename(&s1, "shared/cf", "api/cf", false).unwrap();
        assert_eq!(
            resolved(&orphaned, &s1, "api", &secret_m("cf")),
            "t0ken:value"
        );
    }

    #[test]
    fn rename_replace_overwrites_an_entry_of_the_same_kind() {
        let (s1, mut store) = renamable();
        let db = resolved(&store, &s1, "web", &gen_m("db", "hex64"));
        let id = gen_entry(&store, "web", "db").id;

        let before = store.clone();
        let err = store.rename(&s1, "web/db", "web/other", false).unwrap_err();
        assert!(matches!(err, StoreError::RenameTargetExists { ref name } if name == "web/other"));
        assert_eq!(
            err.to_string(),
            "`web/other` already exists in .sec/; pass --replace to overwrite it with the \
             renamed entry"
        );
        assert_eq!(store, before);

        let out = store.rename(&s1, "web/db", "web/other", true).unwrap();
        assert!(out.replaced);
        // The source's id and format win.
        let e = gen_entry(&store, "web", "other");
        assert_eq!((e.id, e.format), (id, Format::Hex(64)));
        assert_eq!(resolved(&store, &s1, "web", &gen_m("other", "hex64")), db);

        // --replace without an existing target is just a rename.
        let out = store.rename(&s1, "web/other", "web/db", true).unwrap();
        assert!(!out.replaced);

        // Secrets too.
        store.set_secret(&s1, "web", "cf2", "second").unwrap();
        let before = store.clone();
        assert!(matches!(
            store.rename(&s1, "web/cf", "web/cf2", false),
            Err(StoreError::RenameTargetExists { .. })
        ));
        assert_eq!(store, before);
        assert!(
            store
                .rename(&s1, "web/cf", "web/cf2", true)
                .unwrap()
                .replaced
        );
        assert_eq!(
            resolved(&store, &s1, "web", &secret_m("cf2")),
            "t0ken:value"
        );
    }

    #[test]
    fn rename_errors_leave_the_store_unchanged() {
        let (s1, mut store) = renamable();
        store.set_secret(&s1, "web", "other", "v").unwrap();
        store.set_secret(&s1, "web", "lone", "v").unwrap();
        let before = store.clone();
        let check = |store: &mut Store, from: &str, to: &str, replace: bool| {
            let err = store.rename(&s1, from, to, replace).unwrap_err();
            assert_eq!(*store, before);
            err
        };

        let err = store.rename(&seed(2), "web/db", "web/x", true).unwrap_err();
        assert!(matches!(err, StoreError::FingerprintMismatch));
        assert_eq!(store, before);
        let err = check(&mut store, "db", "web/x", false);
        assert!(matches!(err, StoreError::InvalidFullName(ref n) if n == "db"));
        let err = check(&mut store, "web/db", "web/a:b", false);
        assert!(matches!(err, StoreError::InvalidFullName(ref n) if n == "web/a:b"));

        let err = check(&mut store, "web/nope", "web/x", true);
        assert_eq!(
            err.to_string(),
            "`web/nope` has no entry in .sec/ to rename"
        );
        let err = check(&mut store, "gone/db", "web/x", true);
        assert!(matches!(err, StoreError::RenameSourceMissing { ref name } if name == "gone/db"));

        let err = check(&mut store, "web/db", "web/db", true);
        assert_eq!(err.to_string(), "cannot rename `web/db` to itself");

        // web/other exists as gen and as secret.
        let err = check(&mut store, "web/other", "web/x", true);
        assert!(matches!(err, StoreError::RenameAmbiguous { ref name } if name == "web/other"));
        assert!(err.to_string().contains("cannot tell which one to rename"));

        // Other kind at the target: refused even with --replace.
        let err = check(&mut store, "web/db", "web/lone", true);
        assert_eq!(
            err.to_string(),
            "`web/lone` exists in .sec/ as <<secret:…>>, but `web/db` is <<gen:…>>; lst rename \
             only replaces an entry of the same kind"
        );
        let err = check(&mut store, "web/lone", "api/db", true);
        assert!(matches!(
            err,
            StoreError::RenameKindMismatch {
                moving: EntryKind::Secret,
                existing: EntryKind::Gen,
                ..
            }
        ));
        assert!(
            err.to_string()
                .contains("as <<gen:…>>, but `web/lone` is <<secret:…>>")
        );

        // A ciphertext that doesn't decrypt is never moved.
        secret_entry_mut(&mut store, "web", "cf").sealed.ciphertext[0] ^= 1;
        let before = store.clone();
        let err = store.rename(&s1, "web/cf", "web/x", false).unwrap_err();
        assert!(matches!(
            err,
            StoreError::Crypto { ref name, source: CryptoError::Decrypt } if name == "web/cf"
        ));
        assert_eq!(store, before);
        assert!(!format!("{err:?}").contains("t0ken"));
    }

    // --- rotate --------------------------------------------------------------

    #[test]
    fn rotate_gives_a_gen_entry_a_new_id_and_keeps_everything_else() {
        let (s1, mut store) = renamable();
        let before = store.clone();
        let old = resolved(&store, &s1, "web", &gen_m("db", "hex64"));

        let out = store.rotate("web/db").unwrap();
        assert_eq!(
            out,
            RotateOutcome {
                name: "web/db".into(),
                format: Format::Hex(64),
            }
        );
        let e = gen_entry(&store, "web", "db");
        assert_ne!(e.id, gen_entry(&before, "web", "db").id);
        assert_eq!((e.format, e.orphan), (Format::Hex(64), false));
        let new = resolved(&store, &s1, "web", &gen_m("db", "hex64"));
        assert_ne!(new, old);
        assert_eq!(new.len(), 64);

        // Only that entry changed.
        let mut back = store.clone();
        back.files
            .get_mut("web")
            .unwrap()
            .generated
            .get_mut("db")
            .unwrap()
            .id = gen_entry(&before, "web", "db").id;
        assert_eq!(back, before);
        let (old_files, new_files) = (before.to_files(), store.to_files());
        for (name, text) in &old_files {
            if name != "web.toml" {
                assert_eq!(&new_files[name], text, "{name}");
            }
        }

        // Shared names too.
        let x = gen_entry(&store, SHARED, "x").id;
        store.rotate("shared/x").unwrap();
        assert_ne!(gen_entry(&store, SHARED, "x").id, x);
    }

    #[test]
    fn rotate_refuses_manual_orphaned_and_unknown_entries() {
        let (_, mut store) = renamable();
        let mut shared_secret = store.clone();
        shared_secret
            .files
            .entry(SHARED.into())
            .or_default()
            .secrets
            .insert("cf".into(), store.files()["web"].secrets["cf"].clone());
        gen_entry_mut(&mut store, "web", "other").orphan = true;
        let before = store.clone();
        let check = |store: &mut Store, name: &str| {
            let err = store.rotate(name).unwrap_err();
            assert_eq!(*store, before);
            err.to_string()
        };

        assert_eq!(
            check(&mut store, "web/cf"),
            "`web/cf` is a manual secret, and lst rotate only gives generated secrets a new \
             value; write <<set:cf:VALUE>> to replace it"
        );
        assert_eq!(
            check(&mut store, "web/other"),
            "`web/other` is an orphan (no marker uses it), so there is nothing to rotate; \
             `lst gc --remove web/other` removes it"
        );
        assert_eq!(
            check(&mut store, "web/nope"),
            "`web/nope` has no entry in .sec/ to rotate (if a <<gen:…>> marker uses it, run \
             `lst sync` first)"
        );
        assert!(matches!(
            store.rotate("gone/db"),
            Err(StoreError::RotateMissing { ref name }) if name == "gone/db"
        ));
        assert!(matches!(
            store.rotate("db"),
            Err(StoreError::InvalidFullName(ref n)) if n == "db"
        ));
        assert_eq!(store, before);

        // An orphaned manual secret is an orphan too.
        secret_entry_mut(&mut store, "web", "cf").orphan = true;
        assert!(matches!(
            store.rotate("web/cf"),
            Err(StoreError::RotateOrphan { .. })
        ));
        // The hint for a shared secret uses the shared marker name.
        let err = shared_secret.rotate("shared/cf").unwrap_err();
        assert!(
            err.to_string()
                .ends_with("write <<set:shared/cf:VALUE>> to replace it"),
            "{err}"
        );
    }

    #[test]
    fn rotate_a_gen_entry_in_use_next_to_an_orphaned_secret() {
        let (s1, mut store) = renamable();
        store.set_secret(&s1, "web", "db", "v").unwrap();
        secret_entry_mut(&mut store, "web", "db").orphan = true;
        let id = gen_entry(&store, "web", "db").id;
        store.rotate("web/db").unwrap();
        assert_ne!(gen_entry(&store, "web", "db").id, id);
        // Used as a secret, with an orphaned gen entry left over.
        secret_entry_mut(&mut store, "web", "db").orphan = false;
        gen_entry_mut(&mut store, "web", "db").orphan = true;
        assert!(matches!(
            store.rotate("web/db"),
            Err(StoreError::RotateManual { .. })
        ));
    }

    // --- get -----------------------------------------------------------------

    fn got(store: &Store, seed: &Seed, name: &str) -> (String, EntryKind, bool) {
        let g = store.get(seed, name).unwrap();
        assert_eq!(g.name, name);
        (g.value.expose().to_owned(), g.kind, g.orphan)
    }

    #[test]
    fn get_returns_what_resolve_returns() {
        let (s1, store) = renamable();
        let db = resolved(&store, &s1, "web", &gen_m("db", "hex64"));
        assert_eq!(got(&store, &s1, "web/db"), (db, EntryKind::Gen, false));
        let api = resolved(&store, &s1, "api", &gen_m("db", "uuid"));
        assert_eq!(got(&store, &s1, "api/db"), (api, EntryKind::Gen, false));
        let x = resolved(&store, &s1, "web", &gen_m("shared/x", "alnum32"));
        assert_eq!(got(&store, &s1, "shared/x"), (x, EntryKind::Gen, false));
        assert_eq!(
            got(&store, &s1, "web/cf"),
            ("t0ken:value".into(), EntryKind::Secret, false)
        );
    }

    #[test]
    fn get_shows_orphans() {
        let (s1, mut store) = renamable();
        let other = resolved(&store, &s1, "web", &gen_m("other", "uuid"));
        gen_entry_mut(&mut store, "web", "other").orphan = true;
        assert_eq!(got(&store, &s1, "web/other"), (other, EntryKind::Gen, true));
    }

    #[test]
    fn get_picks_the_entry_in_use_when_a_name_has_both_kinds() {
        let (s1, mut store) = renamable();
        let db = resolved(&store, &s1, "web", &gen_m("db", "hex64"));
        store.set_secret(&s1, "web", "db", "v").unwrap();
        secret_entry_mut(&mut store, "web", "db").orphan = true;
        assert_eq!(got(&store, &s1, "web/db"), (db, EntryKind::Gen, false));
        secret_entry_mut(&mut store, "web", "db").orphan = false;
        gen_entry_mut(&mut store, "web", "db").orphan = true;
        assert_eq!(
            got(&store, &s1, "web/db"),
            ("v".into(), EntryKind::Secret, false)
        );
        for orphan in [true, false] {
            secret_entry_mut(&mut store, "web", "db").orphan = orphan;
            gen_entry_mut(&mut store, "web", "db").orphan = orphan;
            let err = store.get(&s1, "web/db").unwrap_err();
            assert!(
                matches!(err, ResolveError::Store(StoreError::GetAmbiguous { ref name }) if name == "web/db"),
                "{err:?}"
            );
        }
    }

    #[test]
    fn get_refuses_unknown_and_invalid_names_and_a_wrong_seed() {
        let (s1, store) = renamable();
        let err = store.get(&s1, "web/nope").unwrap_err();
        assert_eq!(
            err.to_string(),
            "`web/nope` has no entry in .sec/ (if a marker uses it, run `lst sync` first); \
             .sec/web.toml has: cf, db, other"
        );
        let err = store.get(&s1, "ghost/db").unwrap_err();
        assert!(
            err.to_string().ends_with(".sec/ghost.toml has: no entries"),
            "{err}"
        );
        for bad in ["db", "/db", "web/", "web/a:b"] {
            let err = store.get(&s1, bad).unwrap_err();
            assert!(
                matches!(err, ResolveError::Store(StoreError::InvalidFullName(_))),
                "{bad}: {err:?}"
            );
        }
        assert!(store.get(&seed(2), "web/db").is_err());
    }

    // --- orphans -------------------------------------------------------------

    fn gen_entry_mut<'a>(store: &'a mut Store, file: &str, key: &str) -> &'a mut GenEntry {
        store
            .files
            .get_mut(file)
            .unwrap()
            .generated
            .get_mut(key)
            .unwrap()
    }

    fn orphan(name: &str, kind: EntryKind) -> Orphan {
        Orphan {
            name: name.into(),
            kind,
        }
    }

    /// web: db, old (orphan), cf (secret), gone (secret orphan);
    /// web-x: y (orphan); shared: x (orphan); api: db.
    fn with_orphans() -> (Seed, Store) {
        let (s1, mut store) = renamable();
        store.set_secret(&s1, "web", "gone", "v").unwrap();
        store
            .sync(&uses(&[
                ("web", vec![gen_m("db", "hex64"), secret_m("cf")]),
                ("web-x", vec![gen_m("y", "uuid")]),
                ("api", vec![gen_m("db", "uuid")]),
            ]))
            .unwrap();
        store
            .sync(&uses(&[
                ("web", vec![gen_m("db", "hex64"), secret_m("cf")]),
                ("api", vec![gen_m("db", "uuid")]),
            ]))
            .unwrap();
        (s1, store)
    }

    #[test]
    fn orphans_are_listed_sorted_by_full_name() {
        let (_, store) = with_orphans();
        // `web-x/…` sorts before `web/…` ('-' < '/'), though the files sort
        // the other way round.
        assert_eq!(
            store.orphans(),
            vec![
                orphan("shared/x", EntryKind::Gen),
                orphan("web-x/y", EntryKind::Gen),
                orphan("web/gone", EntryKind::Secret),
                orphan("web/other", EntryKind::Gen),
            ]
        );
        assert!(renamable().1.orphans().is_empty());
    }

    #[test]
    fn remove_all_orphans_keeps_entries_in_use_and_empty_files() {
        let (s1, mut store) = with_orphans();
        let api = store.files()["api"].clone();
        let removed = store.remove_orphans(None).unwrap();
        assert_eq!(removed.len(), 4);
        assert_eq!(removed, {
            let mut v = removed.clone();
            v.sort();
            v
        });
        assert!(store.orphans().is_empty());
        let web = &store.files()["web"];
        assert_eq!(web.generated.keys().collect::<Vec<_>>(), ["db"]);
        assert_eq!(web.secrets.keys().collect::<Vec<_>>(), ["cf"]);
        assert_eq!(store.files()["api"], api);
        // Emptied files stay, written as just the header.
        assert_eq!(store.files()[SHARED], StackFile::default());
        assert_eq!(store.to_files()["shared.toml"], HEADER);
        assert_eq!(store.to_files()["web-x.toml"], HEADER);
        assert_eq!(resolved(&store, &s1, "web", &secret_m("cf")), "t0ken:value");
        // Nothing left: removing again is a no-op.
        let before = store.clone();
        assert!(store.remove_orphans(None).unwrap().is_empty());
        assert_eq!(store, before);
    }

    #[test]
    fn remove_named_orphans_only() {
        let (_, mut store) = with_orphans();
        let names = names(&["web/other", "shared/x", "web/other"]);
        let removed = store.remove_orphans(Some(&names)).unwrap();
        assert_eq!(
            removed,
            vec![
                orphan("shared/x", EntryKind::Gen),
                orphan("web/other", EntryKind::Gen),
            ]
        );
        assert_eq!(
            store.orphans(),
            vec![
                orphan("web-x/y", EntryKind::Gen),
                orphan("web/gone", EntryKind::Secret),
            ]
        );
        assert!(store.remove_orphans(Some(&[])).unwrap().is_empty());
    }

    #[test]
    fn remove_named_orphans_is_all_or_nothing() {
        let (_, mut store) = with_orphans();
        let before = store.clone();
        for (list, want) in [
            (
                &["web/other", "web/db"][..],
                "`web/db` is in use, not an orphan; lst gc only removes orphans",
            ),
            (
                &["web/other", "web/cf"],
                "`web/cf` is in use, not an orphan; lst gc only removes orphans",
            ),
            (
                &["shared/x", "web/nope"],
                "`web/nope` has no entry in .sec/",
            ),
            (&["gone/x"], "`gone/x` has no entry in .sec/"),
            (
                &["web/other", "other"],
                "invalid full secret name \"other\"",
            ),
        ] {
            let err = store.remove_orphans(Some(&names(list))).unwrap_err();
            assert!(err.to_string().starts_with(want), "{list:?}: {err}");
            assert_eq!(store, before, "{list:?}");
        }
    }

    #[test]
    fn remove_orphans_of_both_kinds_of_one_name() {
        let (s1, mut store) = with_orphans();
        store.set_secret(&s1, "web", "other", "v").unwrap();
        secret_entry_mut(&mut store, "web", "other").orphan = true;
        let removed = store.remove_orphans(Some(&names(&["web/other"]))).unwrap();
        assert_eq!(
            removed,
            vec![
                orphan("web/other", EntryKind::Gen),
                orphan("web/other", EntryKind::Secret),
            ]
        );
        // An orphaned gen entry next to a secret in use: only the orphan goes.
        store.set_secret(&s1, "web", "db", "v").unwrap();
        gen_entry_mut(&mut store, "web", "db").orphan = true;
        let removed = store.remove_orphans(Some(&names(&["web/db"]))).unwrap();
        assert_eq!(removed, vec![orphan("web/db", EntryKind::Gen)]);
        assert!(store.files()["web"].secrets.contains_key("db"));
    }

    // --- resolve -----------------------------------------------------------

    fn expected_gen(seed: &Seed, id: GenId, format: Format) -> String {
        format::generate(format, &mut crypto::derive_gen(seed, &id))
            .expose()
            .to_owned()
    }

    #[test]
    fn resolve_gen_derives_from_seed_and_id() {
        let s1 = seed(1);
        let mut store = Store::init(&s1);
        store
            .sync(&uses(&[
                (
                    "a",
                    vec![gen_m("db", "alnum32"), gen_m("shared/m", "hex64")],
                ),
                ("b", vec![gen_m("shared/m", "hex64")]),
            ]))
            .unwrap();
        let db = gen_entry(&store, "a", "db").id;
        let v = store.resolve(&s1, "a", &gen_m("db", "alnum32")).unwrap();
        assert_eq!(v.expose(), expected_gen(&s1, db, Format::Alnum(32)));
        // shared/ resolves identically from every stack.
        let a = store
            .resolve(&s1, "a", &gen_m("shared/m", "hex64"))
            .unwrap();
        let b = store
            .resolve(&s1, "b", &gen_m("shared/m", "hex64"))
            .unwrap();
        assert_eq!(a.expose(), b.expose());
        assert_eq!(a.expose().len(), 64);
        // A fixed id gives a fixed value.
        let zero = GenId([0; ID_LEN]);
        store
            .files
            .get_mut("a")
            .unwrap()
            .generated
            .get_mut("db")
            .unwrap()
            .id = zero;
        let v = store.resolve(&s1, "a", &gen_m("db", "alnum32")).unwrap();
        assert_eq!(v.expose(), expected_gen(&s1, zero, Format::Alnum(32)));
        // Orphans still resolve.
        store.sync(&BTreeMap::new()).unwrap();
        assert!(gen_entry(&store, "a", "db").orphan);
        let v2 = store.resolve(&s1, "a", &gen_m("db", "alnum32")).unwrap();
        assert_eq!(v2.expose(), v.expose());
    }

    #[test]
    fn resolve_errors_carry_hints_not_values() {
        let s1 = seed(1);
        let mut store = Store::init(&s1);
        store
            .sync(&uses(&[("web", vec![gen_m("db", "alnum32")])]))
            .unwrap();
        store.set_secret(&s1, "web", "cf", "hunter2").unwrap();

        let err = store
            .resolve(&s1, "web", &gen_m("nope", "uuid"))
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "`web/nope` has no entry in .sec/; run `lst sync`"
        );
        let err = store
            .resolve(&s1, "other", &gen_m("db", "uuid"))
            .unwrap_err();
        assert!(matches!(err, ResolveError::GenMissing { ref name } if name == "other/db"));
        let err = store
            .resolve(&s1, "web", &gen_m("db", "hex64"))
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "`web/db` is stored as alnum32 but used as hex64; run `lst sync`"
        );
        let err = store
            .resolve(&s1, "web", &secret_m("shared/smtp"))
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "`shared/smtp` is not set; write <<set:shared/smtp:VALUE>> to set it"
        );
        let err = store.resolve(&s1, "nosuch", &secret_m("cf")).unwrap_err();
        assert!(matches!(err, ResolveError::SecretUnset { ref name, .. } if name == "nosuch/cf"));
        let err = store
            .resolve(&s1, "web", &set_m("cf", "hunter2"))
            .unwrap_err();
        assert!(matches!(err, ResolveError::SetMarker { ref name } if name == "web/cf"));
        assert!(err.to_string().contains("pre-commit hook"));
        let err = store.resolve(&seed(2), "web", &secret_m("cf")).unwrap_err();
        assert!(matches!(
            err,
            ResolveError::Store(StoreError::FingerprintMismatch)
        ));
        assert!(err.to_string().contains("wrong seed"));
        let err = store.resolve(&s1, ".bad", &secret_m("cf")).unwrap_err();
        assert!(matches!(
            err,
            ResolveError::Store(StoreError::InvalidStack(_))
        ));

        // A ciphertext moved under another name doesn't decrypt.
        let mut moved = store.clone();
        let web = moved.files.get_mut("web").unwrap();
        let e = web.secrets.remove("cf").unwrap();
        web.secrets.insert("other".into(), e);
        let err = moved.resolve(&s1, "web", &secret_m("other")).unwrap_err();
        assert!(matches!(
            err,
            ResolveError::Decrypt { ref name, source: CryptoError::Decrypt } if name == "web/other"
        ));
        assert!(
            err.to_string()
                .starts_with("`web/other`: decryption failed")
        );
        let set_err = store
            .resolve(&s1, "web", &set_m("cf", "hunter2"))
            .unwrap_err();
        for e in [err, set_err] {
            assert!(!e.to_string().contains("hunter2"));
            assert!(!format!("{e:?}").contains("hunter2"));
        }
        assert!(!format!("{store:?}").contains("hunter2"));
    }

    // --- filesystem --------------------------------------------------------

    fn populated() -> (Seed, Store) {
        let s1 = seed(1);
        let mut store = Store::init(&s1);
        store
            .sync(&uses(&[
                (
                    "web",
                    vec![gen_m("db", "alnum32"), gen_m("shared/m", "uuid")],
                ),
                ("db", vec![gen_m("db", "alnum32")]),
            ]))
            .unwrap();
        store.set_secret(&s1, "web", "cf", "token").unwrap();
        (s1, store)
    }

    fn file_names(paths: &[PathBuf]) -> Vec<String> {
        paths
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn save_load_round_trip_and_minimal_writes() {
        let dir = tempfile::tempdir().unwrap();
        let sec = dir.path().join(".sec");
        let (s1, mut store) = populated();

        let written = store.save(&sec).unwrap();
        assert_eq!(
            file_names(&written),
            ["db.toml", "meta.toml", "shared.toml", "web.toml"]
        );
        for (name, contents) in store.to_files() {
            assert_eq!(fs::read_to_string(sec.join(name)).unwrap(), contents);
        }
        let loaded = Store::load(&sec).unwrap();
        assert_eq!(loaded, store);
        loaded.verify_seed(&s1).unwrap();

        // Second save: nothing to do.
        assert!(store.save(&sec).unwrap().is_empty());
        assert!(loaded.save(&sec).unwrap().is_empty());
        // No temp files left behind.
        assert_eq!(fs::read_dir(&sec).unwrap().count(), 4);

        // One changed entry → only its file.
        store
            .sync(&uses(&[
                ("web", vec![gen_m("db", "hex64"), gen_m("shared/m", "uuid")]),
                ("db", vec![gen_m("db", "alnum32")]),
            ]))
            .unwrap();
        assert_eq!(file_names(&store.save(&sec).unwrap()), ["web.toml"]);
        // Same value via set_secret → no rewrite.
        assert!(!store.set_secret(&s1, "web", "cf", "token").unwrap());
        assert!(store.save(&sec).unwrap().is_empty());
        assert_eq!(Store::load(&sec).unwrap(), store);
    }

    #[test]
    fn save_never_deletes_and_load_ignores_other_files() {
        let dir = tempfile::tempdir().unwrap();
        let sec = dir.path();
        let (_, store) = populated();
        store.save(sec).unwrap();
        fs::write(sec.join("extra.toml"), "").unwrap();
        fs::write(sec.join("README"), "not toml").unwrap();
        fs::write(sec.join(".web.toml.tmp"), "junk").unwrap();
        fs::create_dir(sec.join("subdir")).unwrap();
        assert!(Store::init(&seed(1)).save(sec).unwrap().is_empty());
        assert!(sec.join("web.toml").exists());

        let loaded = Store::load(sec).unwrap();
        assert_eq!(loaded.files()["extra"], StackFile::default());
        assert_eq!(loaded.files().len(), store.files().len() + 1);
    }

    #[test]
    fn read_files_returns_the_text_load_parses() {
        let dir = tempfile::tempdir().unwrap();
        let sec = dir.path();
        let (_, store) = populated();
        store.save(sec).unwrap();
        // Not as lst writes it, but valid: read as is, byte for byte.
        let web = fs::read_to_string(sec.join("web.toml")).unwrap();
        let edited = web.replace("orphan = false", "orphan=false");
        fs::write(sec.join("web.toml"), &edited).unwrap();
        fs::write(sec.join("notes.txt"), "ignored").unwrap();
        let (meta, files) = Store::read_files(sec).unwrap();
        let written = store.to_files();
        assert_eq!(meta, written["meta.toml"]);
        assert_eq!(files["web"], edited);
        assert_eq!(files.len(), written.len() - 1);
        assert!(!files.contains_key("meta") && !files.contains_key("notes"));
        assert_eq!(Store::from_files(&meta, &files).unwrap(), store);
        assert!(matches!(
            Store::read_files(&sec.join("missing")).unwrap_err(),
            StoreError::NotInitialized { .. }
        ));
    }

    #[test]
    fn load_errors() {
        let dir = tempfile::tempdir().unwrap();
        let sec = dir.path().join(".sec");

        // Missing directory or missing meta.toml.
        let err = Store::load(&sec).unwrap_err();
        assert!(matches!(&err, StoreError::NotInitialized { dir } if *dir == sec));
        assert!(
            err.to_string()
                .ends_with("not initialised (no meta.toml); run `lst init`")
        );
        fs::create_dir(&sec).unwrap();
        fs::write(sec.join("web.toml"), "").unwrap();
        assert!(matches!(
            Store::load(&sec),
            Err(StoreError::NotInitialized { .. })
        ));

        // meta.toml unreadable (a directory).
        fs::create_dir(sec.join("meta.toml")).unwrap();
        let err = Store::load(&sec).unwrap_err();
        assert!(matches!(&err, StoreError::Io { path, .. } if path.ends_with("meta.toml")));
        assert!(err.to_string().contains("meta.toml"));
        fs::remove_dir(sec.join("meta.toml")).unwrap();

        // Bad meta.toml content.
        fs::write(sec.join("meta.toml"), "version = 2\n").unwrap();
        assert!(matches!(
            Store::load(&sec),
            Err(StoreError::Version { version: 2, .. })
        ));
        let meta = Store::init(&seed(1)).meta().to_toml();
        fs::write(sec.join("meta.toml"), meta).unwrap();
        Store::load(&sec).unwrap();

        // A stack file that is a directory.
        fs::create_dir(sec.join("dir.toml")).unwrap();
        assert!(matches!(
            Store::load(&sec),
            Err(StoreError::Io { path, .. }) if path.ends_with("dir.toml")
        ));
        fs::remove_dir(sec.join("dir.toml")).unwrap();

        // Bad stack file content and bad file names.
        fs::write(sec.join("web.toml"), "[gen.x]\n").unwrap();
        let err = Store::load(&sec).unwrap_err();
        assert!(
            err.to_string()
                .starts_with(".sec/web.toml: gen `web/x`: missing field"),
            "{err}"
        );
        fs::write(sec.join("web.toml"), "").unwrap();
        fs::write(sec.join("bad name.toml"), "").unwrap();
        assert!(matches!(
            Store::load(&sec),
            Err(StoreError::InvalidFileName { name }) if name == "bad name.toml"
        ));
        fs::remove_file(sec.join("bad name.toml")).unwrap();

        #[cfg(unix)]
        {
            use std::ffi::OsStr;
            use std::os::unix::ffi::OsStrExt;
            let bad = sec.join(OsStr::from_bytes(b"\xff.toml"));
            fs::write(&bad, "").unwrap();
            let err = Store::load(&sec).unwrap_err();
            assert!(matches!(err, StoreError::InvalidFileName { .. }), "{err}");
            assert!(err.to_string().contains("invalid file name"));
            fs::remove_file(&bad).unwrap();
        }
        Store::load(&sec).unwrap();
    }

    #[test]
    fn save_errors() {
        let dir = tempfile::tempdir().unwrap();
        let (_, store) = populated();

        // sec_dir is a regular file.
        let file = dir.path().join("file");
        fs::write(&file, "").unwrap();
        let err = store.save(&file).unwrap_err();
        assert!(matches!(&err, StoreError::Io { path, .. } if *path == file));

        // An existing target that can't be read (a directory).
        let sec = dir.path().join("a");
        fs::create_dir_all(sec.join("web.toml")).unwrap();
        let err = store.save(&sec).unwrap_err();
        assert!(matches!(&err, StoreError::Io { path, .. } if path.ends_with("web.toml")));

        // The temp file can't be written (a directory in its place).
        let sec = dir.path().join("b");
        fs::create_dir_all(sec.join(".db.toml.tmp")).unwrap();
        let err = store.save(&sec).unwrap_err();
        assert!(matches!(&err, StoreError::Io { path, .. } if path.ends_with("db.toml")));
        assert!(!sec.join("db.toml").exists());
    }

    #[test]
    fn remaining_error_messages() {
        let io = StoreError::Io {
            path: "/x/.sec/web.toml".into(),
            source: io::Error::other("boom"),
        };
        assert_eq!(io.to_string(), "/x/.sec/web.toml: boom");
        assert_eq!(
            StoreError::InvalidStack("a b".into()).to_string(),
            "invalid stack name \"a b\" (allowed: A-Z a-z 0-9 . _ -, not starting with `.`; \
             `shared` and `meta` are reserved)"
        );
        assert_eq!(
            StoreError::InvalidName("a:b".into()).to_string(),
            "invalid secret name \"a:b\" (allowed: A-Z a-z 0-9 . _ - and single `/` separators)"
        );
        assert_eq!(
            StoreError::InvalidFileName {
                name: "x y.toml".into()
            }
            .to_string(),
            "invalid file name \"x y.toml\" in .sec/ (expected meta.toml, shared.toml or \
             <stack>.toml)"
        );
    }

    // --- property tests ----------------------------------------------------

    fn any_format() -> impl Strategy<Value = Format> {
        prop_oneof![
            (format::ALNUM_MIN..=format::MAX_LEN).prop_map(Format::Alnum),
            (format::HEX_MIN..=format::MAX_LEN).prop_map(Format::Hex),
            (format::BASE64_MIN..=format::MAX_LEN).prop_map(Format::Base64),
            Just(Format::Uuid),
        ]
    }

    fn any_key() -> impl Strategy<Value = String> {
        "[A-Za-z0-9._-]{1,6}(/[A-Za-z0-9._-]{1,6}){0,2}"
            .prop_filter("not shared/", |k| !k.starts_with(SHARED_PREFIX))
    }

    fn any_stack_file() -> impl Strategy<Value = StackFile> {
        let gen_entry = (any::<[u8; ID_LEN]>(), any_format(), any::<bool>()).prop_map(
            |(id, format, orphan)| GenEntry {
                id: GenId(id),
                format,
                orphan,
            },
        );
        let secret_entry = (
            any::<[u8; NONCE_LEN]>(),
            proptest::collection::vec(any::<u8>(), TAG_LEN..80),
            any::<bool>(),
        )
            .prop_map(|(nonce, ciphertext, orphan)| SecretEntry {
                sealed: Sealed { nonce, ciphertext },
                orphan,
            });
        (
            proptest::collection::btree_map(any_key(), gen_entry, 0..5),
            proptest::collection::btree_map(any_key(), secret_entry, 0..5),
        )
            .prop_map(|(generated, secrets)| StackFile { generated, secrets })
    }

    fn any_stem() -> impl Strategy<Value = String> {
        prop_oneof![
            Just(SHARED.to_owned()),
            "[a-z][a-z0-9_.-]{0,5}".prop_filter("reserved", |s| is_valid_stack(s)),
        ]
    }

    proptest! {
        #[test]
        fn stack_file_round_trips(file in any_stack_file()) {
            let text = file.to_toml();
            prop_assert!(text.starts_with(HEADER));
            let parsed = StackFile::parse("web", &text).unwrap();
            prop_assert_eq!(&parsed, &file);
            prop_assert_eq!(parsed.to_toml(), text);
        }

        #[test]
        fn store_round_trips_through_files(
            fp in any::<[u8; 16]>(),
            files in proptest::collection::btree_map(any_stem(), any_stack_file(), 0..4),
        ) {
            let store = Store { meta: Meta { fingerprint: hex(&fp) }, files };
            let out = store.to_files();
            let back = Store::from_files(&out["meta.toml"], &stems_of(&out)).unwrap();
            prop_assert_eq!(back.to_files(), out);
            prop_assert_eq!(back, store);
        }

        #[test]
        fn parse_never_panics(text in "\\PC*") {
            let _ = StackFile::parse("web", &text);
            let _ = Meta::parse(&text);
        }
    }
}
