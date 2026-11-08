//! `lst import`: turn a stack's existing `.env` / `env_file:` values into
//! manual secrets. Pure: compose text and env-file texts in, a [`Plan`] out
//! (the new compose text, the values to seal, the env-file edits). `cli`
//! does the I/O and the sealing.
//!
//! # What gets rewritten
//! - **Interpolation:** `$VAR`, `${VAR}`, `${VAR:-…}`, `${VAR-…}`,
//!   `${VAR:?…}` and `${VAR?…}` in `compose.yaml`, for a `VAR` defined in
//!   the stack's `.env` (compose's interpolation file; lst deploys with
//!   `--project-directory stacks/<stack>`), become `<<secret:var>>`.
//!   `${VAR:+…}`/`${VAR+…}` don't evaluate to the value and are left alone.
//! - **`env_file:`:** the key and its block are replaced, as text, by an
//!   `environment:` block with one `KEY: '<<secret:key>>'` per variable of
//!   those files. If the service already has a block-style `environment:`,
//!   the entries are appended to it instead (keys it already sets are left
//!   out: they override the file anyway).
//!
//! The secret name is the variable name in lowercase.
//!
//! # Every edit is checked
//! The edits are made blindly on the raw text, so each one is kept only if
//! the stack still means the same thing to compose afterwards: the text is
//! rendered in memory the way `lst render` would (with the values that are
//! about to be sealed), parsed as YAML, interpolated as compose would, and
//! every `env_file:` it can read is merged into `environment` (which is
//! normalised to a map). That document must equal the one from the
//! original text. Edits are tried one at a time, in text order; one that
//! fails is reported and left out. A failed `env_file:` block comes with a
//! snippet for the user to apply by hand.
//!
//! Neither the plan nor any error contains a value: only variable names,
//! secret names, file names and line numbers.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use serde_yaml_ng::{Mapping, Value};
use zeroize::Zeroize;

use crate::crypto::SecretString;
use crate::dotenv::{self, DotenvError, Skip};
use crate::marker::{self, MarkerKind};
use crate::render;
use crate::stack::STACKS_DIR;
use crate::store::{self, StoreError};
use crate::xdeploy::{self, Detected};

/// Compose's interpolation file, relative to the stack directory.
pub const DOT_ENV: &str = ".env";

/// A file `lst import` was asked to look at, by its path relative to the
/// stack directory.
#[derive(Debug)]
pub enum FileState {
    /// It doesn't exist.
    Missing,
    /// It exists but lst won't use it (a symlink, not UTF-8, …): the reason.
    Unusable(String),
    Text(SecretString),
}

/// Everything [`plan`] needs.
pub struct Input<'a> {
    pub stack: &'a str,
    /// The text of `stacks/<stack>/compose.yaml`.
    pub compose: &'a str,
    /// Stack-relative path → state, for [`DOT_ENV`] and every path
    /// [`env_file_paths`] returned.
    pub files: &'a BTreeMap<String, FileState>,
    /// Variable names not to import.
    pub exclude: &'a BTreeSet<String>,
}

/// What to do.
#[derive(Debug)]
pub struct Plan {
    /// The new compose text (equal to the input if nothing was replaced).
    pub compose: String,
    /// The values to seal, sorted by name.
    pub secrets: Vec<Import>,
    /// Every `${VAR}` that could be replaced, in text order.
    pub sites: Vec<Site>,
    /// Every `env_file:` block, in text order.
    pub blocks: Vec<Block>,
    /// Variables that stay where they are, and why.
    pub not_imported: Vec<NotImported>,
    /// Env files that lose lines (or are deleted), sorted by path.
    pub env_files: Vec<EnvFileEdit>,
}

/// One value to seal as the manual secret `name` of the stack.
#[derive(Debug)]
pub struct Import {
    pub var: String,
    /// The secret's name in the stack (`postgres_password`).
    pub name: String,
    pub value: SecretString,
    /// Stack-relative files it was read from.
    pub files: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    pub var: String,
    pub line: usize,
    pub col: usize,
    pub replaced: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    /// The service the block belongs to, if lst could tell.
    pub service: Option<String>,
    /// 1-based line of the `env_file:` key.
    pub line: usize,
    pub outcome: BlockOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockOutcome {
    /// Replaced by a new `environment:` block.
    Replaced,
    /// Removed; its entries were appended to the existing `environment:`.
    Merged,
    /// Not replaced; `snippet` holds the `environment:` entries to use
    /// instead (markers only, never values).
    Manual { why: String, snippet: String },
    /// Not touched, and nothing from it is imported.
    LeftAlone { why: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotImported {
    pub var: String,
    pub file: String,
    pub why: String,
}

/// Lines removed from one env file.
#[derive(Debug)]
pub struct EnvFileEdit {
    /// Stack-relative path.
    pub file: String,
    /// The variables whose lines were removed, sorted.
    pub removed: Vec<String>,
    /// The new contents; `None` if nothing but blank and comment lines
    /// would be left (delete the file).
    pub contents: Option<SecretString>,
}

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("{path}: {source}")]
    Dotenv { path: String, source: DotenvError },
    #[error("{path}: {why}; fix it before importing")]
    Compose { path: String, why: Why },
    #[error(
        "{var} has different values in {} and {}; import can store only one value as \
         `{name}`: pass --exclude {var} and set it by hand",
        files[0], files[1]
    )]
    Conflict {
        var: String,
        name: String,
        files: [String; 2],
    },
    #[error(
        "{a} and {b} would both become the secret `{name}`; pass --exclude for one of them and \
         set it by hand"
    )]
    Collision { a: String, b: String, name: String },
    #[error("{var}: {source}; pass --exclude {var} and set it by hand")]
    Name { var: String, source: StoreError },
}

/// Why a compose text has no meaning lst can compare (shown to the user,
/// so it never quotes the text).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Why {
    #[error(
        "{line}:{col}: invalid YAML (lst does not show the parser's message: it can quote the \
         file, and so a secret)"
    )]
    Yaml { line: usize, col: usize },
    #[error("invalid YAML")]
    YamlUnlocated,
    #[error("a merge key (`<<: *anchor`) can't be applied")]
    Merge,
    #[error("a malformed <<…>> marker")]
    Marker,
    #[error("a `$` compose can't interpolate (write `$$` for a literal `$`)")]
    Interpolation,
    #[error("a top-level x-deploy key that no line starts with")]
    Hidden,
}

// ---------------------------------------------------------------------------
// Env files
// ---------------------------------------------------------------------------

/// The definitions of one env file: the last definition of each key wins,
/// keys in order of first appearance.
struct Defs {
    vars: Vec<(String, Result<SecretString, Skip>)>,
    /// Key → every line that defines it.
    lines: BTreeMap<String, Vec<usize>>,
}

enum Parsed {
    Missing,
    Unusable(String),
    Defs(Defs),
}

fn parse_files(
    stack: &str,
    files: &BTreeMap<String, FileState>,
) -> Result<BTreeMap<String, Parsed>, ImportError> {
    let mut out = BTreeMap::new();
    for (rel, state) in files {
        let parsed = match state {
            FileState::Missing => Parsed::Missing,
            FileState::Unusable(why) => Parsed::Unusable(why.clone()),
            FileState::Text(text) => {
                let defs = dotenv::parse(text.expose()).map_err(|source| ImportError::Dotenv {
                    path: stack_path(stack, rel),
                    source,
                })?;
                let mut vars: Vec<(String, Result<SecretString, Skip>)> = Vec::new();
                let mut lines: BTreeMap<String, Vec<usize>> = BTreeMap::new();
                for d in defs {
                    lines.entry(d.key.clone()).or_default().push(d.line);
                    let v = match d.value {
                        dotenv::Value::Ok(s) => Ok(s),
                        dotenv::Value::Skip(s) => Err(s),
                    };
                    match vars.iter_mut().find(|(k, _)| *k == d.key) {
                        Some(slot) => slot.1 = v,
                        None => vars.push((d.key, v)),
                    }
                }
                Parsed::Defs(Defs { vars, lines })
            }
        };
        out.insert(rel.clone(), parsed);
    }
    Ok(out)
}

/// `stacks/<stack>/<rel>`, for messages.
pub fn stack_path(stack: &str, rel: &str) -> String {
    format!("{STACKS_DIR}/{stack}/{rel}")
}

/// A stack-relative `env_file` path in normal form (`./a/./b.env` →
/// `a/b.env`), or `None` for one lst doesn't follow: absolute, with `..`,
/// with `$` (compose interpolates it), or empty.
pub fn normalize_path(raw: &str) -> Option<String> {
    if raw.starts_with('/') || raw.contains('$') || raw.contains('\0') {
        return None;
    }
    let mut parts = Vec::new();
    for p in raw.split('/') {
        match p {
            "" | "." => {}
            ".." => return None,
            p => parts.push(p),
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

/// One entry of an `env_file:` value.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EnvRef {
    raw: String,
    required: bool,
}

/// The entries of an `env_file:` value (a string, or a list of strings or
/// `{path, required}` maps), or `None` for any other shape (e.g. a
/// `format:` key, which changes how compose reads the file).
fn env_refs(v: &Value) -> Option<Vec<EnvRef>> {
    let one = |v: &Value| -> Option<EnvRef> {
        match v {
            Value::String(s) => Some(EnvRef {
                raw: s.clone(),
                required: true,
            }),
            Value::Mapping(m) => {
                let mut raw = None;
                let mut required = true;
                for (k, v) in m {
                    match (k.as_str()?, v) {
                        ("path", Value::String(s)) => raw = Some(s.clone()),
                        ("required", Value::Bool(b)) => required = *b,
                        _ => return None,
                    }
                }
                Some(EnvRef {
                    raw: raw?,
                    required,
                })
            }
            _ => None,
        }
    };
    match v {
        Value::Sequence(seq) => seq.iter().map(one).collect(),
        v => one(v).map(|r| vec![r]),
    }
}

/// Every stack-relative path the `env_file:` entries of `compose` name
/// (normalised; paths lst doesn't follow are left out), so `cli` knows
/// which files to read. Empty if the text isn't valid YAML ([`plan`]
/// reports that).
pub fn env_file_paths(compose: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Ok(doc) = serde_yaml_ng::from_str::<Value>(compose).map(Doc) else {
        return out;
    };
    for svc in services(&doc.0) {
        if let Some(refs) = svc.get("env_file").and_then(env_refs) {
            out.extend(refs.iter().filter_map(|r| normalize_path(&r.raw)));
        }
    }
    out
}

fn services(doc: &Value) -> impl Iterator<Item = &Mapping> {
    doc.get("services")
        .and_then(Value::as_mapping)
        .into_iter()
        .flat_map(|m| m.values())
        .filter_map(Value::as_mapping)
}

// ---------------------------------------------------------------------------
// Interpolation (compose's `$` rules)
// ---------------------------------------------------------------------------

/// Variable → value for interpolation; `None`: defined, but lst doesn't
/// know the value it has for compose (a [`Skip`]).
type Env = BTreeMap<String, Option<SecretString>>;

fn is_name_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn is_name(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// The end of the name starting at `i`.
fn name_end(s: &[u8], i: usize) -> usize {
    let mut j = i;
    while j < s.len() && is_name(s[j]) {
        j += 1;
    }
    j
}

/// The index of the `}` closing the `${` whose content starts at `from`.
fn closing_brace(s: &[u8], from: usize) -> Option<usize> {
    let mut depth = 1;
    let mut i = from;
    while i < s.len() {
        match (s[i], s.get(i + 1)) {
            (b'$', Some(b'$' | b'{')) => {
                if s[i + 1] == b'{' {
                    depth += 1;
                }
                i += 2;
                continue;
            }
            (b'}', _) => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

const MODIFIERS: [&str; 6] = [":-", ":?", ":+", "-", "?", "+"];

/// A `${…}` body split into name and modifier (`""` for none) and argument.
fn split_braced(inner: &str) -> Option<(&str, &str, &str)> {
    let b = inner.as_bytes();
    if b.is_empty() || !is_name_start(b[0]) {
        return None;
    }
    let end = name_end(b, 0);
    let (name, rest) = inner.split_at(end);
    if rest.is_empty() {
        return Some((name, "", ""));
    }
    let m = MODIFIERS.iter().find(|m| rest.starts_with(**m))?;
    Some((name, m, &rest[m.len()..]))
}

/// Stands for a value lst doesn't know: the same on both sides of a
/// comparison as long as the text it came from is unchanged.
fn unknown(raw: &str) -> String {
    format!("\0{raw}\0")
}

/// `s` interpolated as compose does it: `$$` → `$`, `$VAR`, `${VAR}` and
/// the six modifiers. A `$` compose would refuse is an error.
fn interpolate(s: &str, env: &Env) -> Result<String, ()> {
    if !s.contains('$') {
        return Ok(s.to_owned());
    }
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    let mut copied = 0;
    while i < b.len() {
        if b[i] != b'$' {
            i += 1;
            continue;
        }
        out.push_str(&s[copied..i]);
        match b.get(i + 1) {
            Some(b'$') => {
                out.push('$');
                i += 2;
            }
            Some(b'{') => {
                let close = closing_brace(b, i + 2).ok_or(())?;
                let raw = &s[i..=close];
                let (name, m, arg) = split_braced(&s[i + 2..close]).ok_or(())?;
                match env.get(name) {
                    Some(Some(v)) => {
                        let v = v.expose();
                        match m {
                            "" | "-" | "?" => out.push_str(v),
                            ":-" if v.is_empty() => out.push_str(&interpolate(arg, env)?),
                            ":-" => out.push_str(v),
                            ":?" if v.is_empty() => return Err(()),
                            ":?" => out.push_str(v),
                            ":+" if v.is_empty() => {}
                            _ => out.push_str(&interpolate(arg, env)?),
                        }
                    }
                    _ => out.push_str(&unknown(raw)),
                }
                i = close + 1;
            }
            Some(&c) if is_name_start(c) => {
                let end = name_end(b, i + 1);
                match env.get(&s[i + 1..end]) {
                    Some(Some(v)) => out.push_str(v.expose()),
                    _ => out.push_str(&unknown(&s[i..end])),
                }
                i = end;
            }
            _ => return Err(()),
        }
        copied = i;
    }
    out.push_str(&s[copied..]);
    Ok(out)
}

/// A `$` reference in raw text.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Ref {
    span: Range<usize>,
    var: String,
    /// Whether it evaluates to the variable's value when that is set and
    /// not empty (no modifier, `-`, `:-`, `?`, `:?`).
    value: bool,
    /// Variables referenced inside its argument (`${A:-${B}}` → `B`).
    nested: Vec<String>,
}

/// Every `$VAR` / `${VAR…}` in `text` (not `$$`). Malformed `$` are
/// skipped (the comparison catches them).
fn refs(text: &str) -> Vec<Ref> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'$' {
            i += 1;
            continue;
        }
        match b.get(i + 1) {
            Some(b'$') => i += 2,
            Some(b'{') => match closing_brace(b, i + 2) {
                Some(close) => {
                    if let Some((name, m, arg)) = split_braced(&text[i + 2..close]) {
                        out.push(Ref {
                            span: i..close + 1,
                            var: name.to_owned(),
                            value: matches!(m, "" | "-" | ":-" | "?" | ":?"),
                            nested: refs(arg).into_iter().flat_map(Ref::all).collect(),
                        });
                    }
                    i = close + 1;
                }
                None => i += 2,
            },
            Some(&c) if is_name_start(c) => {
                let end = name_end(b, i + 1);
                out.push(Ref {
                    span: i..end,
                    var: text[i + 1..end].to_owned(),
                    value: true,
                    nested: Vec::new(),
                });
                i = end;
            }
            _ => i += 1,
        }
    }
    out
}

impl Ref {
    fn all(self) -> Vec<String> {
        let mut v = self.nested;
        v.push(self.var);
        v
    }
}

// ---------------------------------------------------------------------------
// What a compose text means
// ---------------------------------------------------------------------------

/// A YAML tree whose strings are zeroized on drop (it holds values).
#[derive(Debug, PartialEq)]
struct Doc(Value);

impl Drop for Doc {
    fn drop(&mut self) {
        xdeploy::wipe(&mut self.0);
    }
}

fn yaml(text: &str) -> Result<Doc, Why> {
    let v = serde_yaml_ng::from_str::<Value>(text).map_err(|e| match e.location() {
        Some(l) => Why::Yaml {
            line: l.line(),
            col: l.column(),
        },
        None => Why::YamlUnlocated,
    })?;
    let mut doc = Doc(v);
    doc.0.apply_merge().map_err(|_| Why::Merge)?;
    Ok(doc)
}

/// What compose (after lst's rendering) sees in `text`: rendered with
/// `values` for the imported names (other markers stay as they are),
/// parsed, merge keys applied, interpolated with `env`, readable
/// `env_file:`s merged into a normalised `environment`.
fn meaning(
    text: &str,
    values: &BTreeMap<String, SecretString>,
    env: &Env,
    files: &BTreeMap<String, Parsed>,
) -> Result<Doc, Why> {
    let resolve = |m: &MarkerKind| -> Result<SecretString, ()> {
        Ok(match m {
            MarkerKind::Secret { name } if values.contains_key(name) => values[name].clone(),
            m => SecretString::new(m.to_string()),
        })
    };
    let mut doc = match xdeploy::detect(text) {
        Detected::Hidden => return Err(Why::Hidden),
        Detected::Raw => {
            let rendered = render::render_compose(text, resolve).map_err(|_| Why::Marker)?;
            let mut doc = yaml(rendered.expose())?;
            interpolate_values(&mut doc.0, env)?;
            doc
        }
        Detected::XDeploy => {
            let mut doc = yaml(text)?;
            if let Value::Mapping(top) = &mut doc.0 {
                for (k, v) in top.iter_mut() {
                    if k.as_str() == Some(xdeploy::KEY) {
                        // lst strips x-deploy and uses its strings raw.
                        substitute(v, &|s| render::render(s, resolve))?;
                    } else {
                        substitute(v, &|s| render::render_compose(s, resolve))?;
                        interpolate_values(v, env)?;
                    }
                }
            }
            doc
        }
    };
    merge_env_files(&mut doc.0, files);
    Ok(doc)
}

/// Renders the markers in every string of `v` (values only: keys are
/// compared as written).
fn substitute(
    v: &mut Value,
    r: &dyn Fn(&str) -> Result<SecretString, render::RenderError<()>>,
) -> Result<(), Why> {
    match v {
        Value::String(s) if s.contains("<<") => {
            let new = r(s).map_err(|_| Why::Marker)?;
            let mut old = std::mem::replace(s, new.expose().to_owned());
            old.zeroize();
            Ok(())
        }
        Value::Sequence(seq) => seq.iter_mut().try_for_each(|v| substitute(v, r)),
        Value::Mapping(m) => m.values_mut().try_for_each(|v| substitute(v, r)),
        Value::Tagged(t) => substitute(&mut t.value, r),
        _ => Ok(()),
    }
}

fn interpolate_values(v: &mut Value, env: &Env) -> Result<(), Why> {
    match v {
        Value::String(s) if s.contains('$') => {
            let new = interpolate(s, env).map_err(|()| Why::Interpolation)?;
            let mut old = std::mem::replace(s, new);
            old.zeroize();
            Ok(())
        }
        Value::Sequence(seq) => seq.iter_mut().try_for_each(|v| interpolate_values(v, env)),
        Value::Mapping(m) => m.values_mut().try_for_each(|v| interpolate_values(v, env)),
        Value::Tagged(t) => interpolate_values(&mut t.value, env),
        _ => Ok(()),
    }
}

/// `environment` as a map sorted by key (`KEY=VAL` → `VAL`, `KEY` → null),
/// or `None` for a shape lst doesn't know.
fn env_map(v: &Value) -> Option<BTreeMap<String, Value>> {
    let mut out = BTreeMap::new();
    match v {
        Value::Mapping(m) => {
            for (k, v) in m {
                out.insert(k.as_str()?.to_owned(), v.clone());
            }
        }
        Value::Sequence(seq) => {
            for item in seq {
                let s = item.as_str()?;
                match s.split_once('=') {
                    Some((k, v)) => out.insert(k.to_owned(), Value::String(v.to_owned())),
                    None => out.insert(s.to_owned(), Value::Null),
                };
            }
        }
        Value::Null => {}
        _ => return None,
    }
    Some(out)
}

fn to_mapping(map: BTreeMap<String, Value>) -> Value {
    Value::Mapping(
        map.into_iter()
            .map(|(k, v)| (Value::String(k), v))
            .collect(),
    )
}

/// The variables of the env files `refs` names, later files winning, or
/// `None` if one can't be read (then compose's view of the service can't
/// be known, and it is compared as written).
fn env_file_vars(
    refs: &[EnvRef],
    files: &BTreeMap<String, Parsed>,
) -> Option<BTreeMap<String, Value>> {
    let mut out = BTreeMap::new();
    for r in refs {
        let path = normalize_path(&r.raw)?;
        match files.get(&path)? {
            Parsed::Missing if !r.required => {}
            Parsed::Missing | Parsed::Unusable(_) => return None,
            Parsed::Defs(d) => {
                for (k, v) in &d.vars {
                    let v = match v {
                        Ok(v) => v.expose().to_owned(),
                        Err(_) => unknown(&format!("{path}:{k}")),
                    };
                    out.insert(k.clone(), Value::String(v));
                }
            }
        }
    }
    Some(out)
}

fn merge_env_files(doc: &mut Value, files: &BTreeMap<String, Parsed>) {
    let Some(services) = doc.get_mut("services").and_then(Value::as_mapping_mut) else {
        return;
    };
    for svc in services.values_mut().filter_map(Value::as_mapping_mut) {
        let environment = match svc.get("environment") {
            Some(e) => env_map(e),
            None => Some(BTreeMap::new()),
        };
        let Some(mut environment) = environment else {
            continue;
        };
        if let Some(ef) = svc.get("env_file") {
            let Some(mut vars) = env_refs(ef).and_then(|r| env_file_vars(&r, files)) else {
                // Compared as written, environment included.
                continue;
            };
            vars.append(&mut environment);
            environment = vars;
            if let Some(mut old) = svc.remove("env_file") {
                xdeploy::wipe(&mut old);
            }
        }
        if environment.is_empty() && !svc.contains_key("environment") {
            continue;
        }
        if let Some(mut old) = svc.insert(Value::from("environment"), to_mapping(environment)) {
            xdeploy::wipe(&mut old);
        }
    }
}

/// What an ambiguous value is replaced with for the typing check: an
/// integer to serde_yaml_ng as a plain scalar, a string anywhere else.
const PROBE: &str = "1";

/// Whether `v`, as a whole plain YAML scalar, might not be a string for
/// some YAML parser (1.1 or 1.2): empty, a null or bool spelling (`~`,
/// `null`, `yes`, `off`, …), or something shaped like a number, timestamp
/// or special float: after an optional sign it starts with a digit or `.`
/// and holds nothing but hex digits, `x o . _ : + - t z n i` (either case)
/// and spaces (`0777`, `0x1F`, `1e3`, `12:30`, `2001-12-14`, `.NaN`).
/// Conservative: a false positive only costs the probe check; `0ld-pw`
/// or `9lives` are plain strings everywhere and pass.
fn type_ambiguous(v: &str) -> bool {
    const WORDS: &[&str] = &[
        "", "~", "null", "Null", "NULL", "y", "Y", "yes", "Yes", "YES", "n", "N", "no", "No", "NO",
        "true", "True", "TRUE", "false", "False", "FALSE", "on", "On", "ON", "off", "Off", "OFF",
        "=",
    ];
    let t = v.trim();
    if WORDS.contains(&t) {
        return true;
    }
    let t = t.strip_prefix(['-', '+']).unwrap_or(t);
    t.starts_with(|c: char| c.is_ascii_digit() || c == '.')
        && t.chars()
            .all(|c| c.is_ascii_hexdigit() || "xXoO._:+-tTzZnNiI ".contains(c))
}

/// `files` with the values of the variables in `vars` replaced by [`PROBE`].
fn probe_files(
    files: &BTreeMap<String, Parsed>,
    vars: &BTreeSet<String>,
) -> BTreeMap<String, Parsed> {
    files
        .iter()
        .map(|(rel, p)| {
            let p = match p {
                Parsed::Missing => Parsed::Missing,
                Parsed::Unusable(why) => Parsed::Unusable(why.clone()),
                Parsed::Defs(d) => Parsed::Defs(Defs {
                    vars: d
                        .vars
                        .iter()
                        .map(|(k, v)| {
                            let v = match v {
                                Ok(_) if vars.contains(k) => {
                                    Ok(SecretString::new(PROBE.to_owned()))
                                }
                                v => v.clone(),
                            };
                            (k.clone(), v)
                        })
                        .collect(),
                    lines: d.lines.clone(),
                }),
            };
            (rel.clone(), p)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The text of env_file: blocks
// ---------------------------------------------------------------------------

struct Line<'a> {
    /// Byte range, including the `\n` if there is one.
    span: Range<usize>,
    text: &'a str,
}

fn lines(text: &str) -> Vec<Line<'_>> {
    let mut out = Vec::new();
    let mut start = 0;
    for l in text.split_inclusive('\n') {
        let end = start + l.len();
        let t = l.strip_suffix('\n').unwrap_or(l);
        let t = t.strip_suffix('\r').unwrap_or(t);
        out.push(Line {
            span: start..end,
            text: t,
        });
        start = end;
    }
    out
}

fn indent(l: &str) -> usize {
    l.len() - l.trim_start_matches(' ').len()
}

fn is_filler(l: &str) -> bool {
    let t = l.trim();
    t.is_empty() || t.starts_with('#')
}

/// If line `l` is the key `key` (plain or quoted), what follows its `:`
/// with any comment removed, trimmed.
fn key_rest<'a>(l: &'a str, key: &str) -> Option<&'a str> {
    let t = l.trim_start();
    let after = [key.to_owned(), format!("\"{key}\""), format!("'{key}'")]
        .iter()
        .find_map(|k| t.strip_prefix(k.as_str()))?;
    let after = after.trim_start_matches([' ', '\t']).strip_prefix(':')?;
    if !(after.is_empty() || after.starts_with([' ', '\t'])) {
        return None;
    }
    let after = match after.find(" #") {
        Some(i) => &after[..i],
        None => after,
    };
    Some(after.trim())
}

/// The index of the last line of the block that starts at key line `i`
/// (indented at `ind`): deeper lines and same-indent `- ` items, without
/// trailing blank or comment lines.
fn block_end(ls: &[Line<'_>], i: usize, ind: usize) -> usize {
    let mut last = i;
    for (j, l) in ls.iter().enumerate().skip(i + 1) {
        if is_filler(l.text) {
            continue;
        }
        let k = indent(l.text);
        let t = l.text.trim_start();
        if k > ind || (k == ind && (t.starts_with("- ") || t == "-")) {
            last = j;
        } else {
            break;
        }
    }
    last
}

/// The plain or quoted name of a `name:` key line with nothing after it.
fn bare_key(l: &str) -> Option<String> {
    let t = l.trim();
    let t = match t.find(" #") {
        Some(i) => t[..i].trim_end(),
        None => t,
    };
    let k = t.strip_suffix(':')?.trim_end();
    let k = k
        .strip_prefix('"')
        .and_then(|k| k.strip_suffix('"'))
        .or_else(|| k.strip_prefix('\'').and_then(|k| k.strip_suffix('\'')))
        .unwrap_or(k);
    (!k.is_empty()).then(|| k.to_owned())
}

/// The nearest line before `i` indented less than `ind`.
fn parent(ls: &[Line<'_>], i: usize, ind: usize) -> Option<usize> {
    (0..i)
        .rev()
        .find(|&j| !is_filler(ls[j].text) && indent(ls[j].text) < ind)
}

/// The service of the key at line `i`: its parent is `<name>:`, whose
/// parent is the top-level `services:`.
fn service_of(ls: &[Line<'_>], i: usize, ind: usize) -> Option<(usize, String)> {
    let s = parent(ls, i, ind)?;
    let name = bare_key(ls[s].text)?;
    let top = parent(ls, s, indent(ls[s].text))?;
    (indent(ls[top].text) == 0 && bare_key(ls[top].text).as_deref() == Some("services"))
        .then_some((s, name))
}

/// One `env_file:` block as found in the text.
struct TextBlock {
    /// Index of the key line.
    line: usize,
    span: Range<usize>,
    indent: usize,
    service: Option<(usize, String)>,
    /// The entries, if the block parses on its own.
    refs: Option<Vec<EnvRef>>,
}

fn text_blocks(text: &str, ls: &[Line<'_>]) -> Vec<TextBlock> {
    let mut out = Vec::new();
    for (i, l) in ls.iter().enumerate() {
        debug_assert!(l.span.end <= text.len());
        let Some(rest) = key_rest(l.text, "env_file") else {
            continue;
        };
        let ind = indent(l.text);
        let last = if rest.is_empty() {
            block_end(ls, i, ind)
        } else {
            i
        };
        let span = l.span.start..ls[last].span.end;
        let dedented: String = ls[i..=last]
            .iter()
            .map(|l| {
                let t = if indent(l.text) >= ind {
                    &l.text[ind..]
                } else {
                    l.text.trim_start()
                };
                format!("{t}\n")
            })
            .collect();
        let refs = serde_yaml_ng::from_str::<Value>(&dedented)
            .ok()
            .and_then(|v| v.get("env_file").and_then(env_refs));
        out.push(TextBlock {
            line: i,
            span,
            indent: ind,
            service: service_of(ls, i, ind),
            refs,
        });
    }
    out
}

/// The `environment:` block of the service whose name line is `s`, at
/// indent `ind`: (insert offset, entry indent, list form?). `None` if
/// there is none or it isn't a non-empty block-style map or list.
fn environment_block(ls: &[Line<'_>], s: usize, ind: usize) -> Option<(usize, usize, bool)> {
    let svc_ind = indent(ls[s].text);
    for i in s + 1..ls.len() {
        let t = ls[i].text;
        if is_filler(t) {
            continue;
        }
        if indent(t) <= svc_ind {
            return None;
        }
        if indent(t) != ind {
            continue;
        }
        let Some(rest) = key_rest(t, "environment") else {
            continue;
        };
        if !rest.is_empty() {
            return None;
        }
        let last = block_end(ls, i, ind);
        let first = (i + 1..=last).find(|&j| !is_filler(ls[j].text))?;
        let list = ls[first].text.trim_start().starts_with('-');
        return Some((ls[last].span.end, indent(ls[first].text), list));
    }
    None
}

fn entry(list: bool, ind: &str, var: &str, name: &str, value: &str) -> String {
    let marker = format!("<<secret:{name}>>");
    match (list, value.contains('\'')) {
        (false, false) => format!("{ind}{var}: '{marker}'\n"),
        (false, true) => format!("{ind}{var}: |-\n{ind}  {marker}\n"),
        (true, false) => format!("{ind}- '{var}={marker}'\n"),
        (true, true) => format!("{ind}- |-\n{ind}  {var}={marker}\n"),
    }
}

// ---------------------------------------------------------------------------
// The plan
// ---------------------------------------------------------------------------

struct Edit {
    pieces: Vec<(Range<usize>, String)>,
    what: EditOf,
}

#[derive(Clone, Copy)]
enum EditOf {
    Site(usize),
    Block(usize),
}

fn apply<'e>(text: &str, edits: impl Iterator<Item = &'e Edit>) -> Option<String> {
    let mut pieces: Vec<&(Range<usize>, String)> = edits.flat_map(|e| &e.pieces).collect();
    pieces.sort_by_key(|(r, _)| (r.start, r.end));
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    for (r, s) in pieces {
        if r.start < copied {
            return None; // overlapping edits
        }
        out.push_str(&text[copied..r.start]);
        out.push_str(s);
        copied = r.end;
    }
    out.push_str(&text[copied..]);
    Some(out)
}

/// What one variable would be imported from.
struct Candidate {
    value: SecretString,
    files: Vec<String>,
}

/// Plans the import of one stack. See the module docs.
pub fn plan(input: &Input<'_>) -> Result<Plan, ImportError> {
    let stack = input.stack;
    let compose_path = stack_path(stack, crate::stack::COMPOSE_FILE);
    let text = input.compose;
    let files = parse_files(stack, input.files)?;
    let dot = match files.get(DOT_ENV) {
        Some(Parsed::Defs(d)) => Some(d),
        _ => None,
    };
    let excluded = |v: &str| input.exclude.contains(v);
    let mut not_imported = Vec::new();

    // Interpolation env: every variable of .env (skips stay unknown).
    let env: Env = dot
        .map(|d| {
            d.vars
                .iter()
                .map(|(k, v)| (k.clone(), v.as_ref().ok().cloned()))
                .collect()
        })
        .unwrap_or_default();

    // Candidates, and the reasons for everything else.
    let mut cands: BTreeMap<String, Candidate> = BTreeMap::new();
    let mut add = |var: &str, value: &SecretString, file: &str| -> Result<(), ImportError> {
        match cands.get_mut(var) {
            Some(c) if c.value.expose() != value.expose() => Err(ImportError::Conflict {
                var: var.to_owned(),
                name: var.to_lowercase(),
                files: [stack_path(stack, &c.files[0]), stack_path(stack, file)],
            }),
            Some(c) => {
                if !c.files.iter().any(|f| f == file) {
                    c.files.push(file.to_owned());
                }
                Ok(())
            }
            None => {
                cands.insert(
                    var.to_owned(),
                    Candidate {
                        value: value.clone(),
                        files: vec![file.to_owned()],
                    },
                );
                Ok(())
            }
        }
    };
    let why_not = |v: &Result<SecretString, Skip>, var: &str| -> Option<String> {
        match v {
            _ if excluded(var) => Some("excluded".to_owned()),
            Err(s) => Some(s.to_string()),
            Ok(_) => None,
        }
    };

    let all_refs = refs(text);
    if let Some(d) = dot {
        for (var, v) in &d.vars {
            let used: Vec<&Ref> = all_refs.iter().filter(|r| r.var == *var).collect();
            let nested = all_refs.iter().any(|r| r.nested.contains(var));
            if used.is_empty() && !nested {
                continue;
            }
            if let Some(why) = why_not(v, var) {
                not_imported.push(NotImported {
                    var: var.clone(),
                    file: DOT_ENV.to_owned(),
                    why,
                });
            } else if let Ok(value) = v {
                if used.iter().any(|r| r.value) {
                    add(var, value, DOT_ENV)?;
                }
            }
        }
    }

    let ls = lines(text);
    let tblocks = text_blocks(text, &ls);
    let base_doc = yaml(text).ok();
    let mut blocks: Vec<Block> = Vec::new();
    // Per block: the variables it would bring in, or why it can't.
    let mut block_vars: Vec<Option<Vec<String>>> = Vec::new();
    for tb in &tblocks {
        let service = tb.service.as_ref().map(|(_, n)| n.clone());
        let line = tb.line + 1;
        let left_alone = |why: String| Block {
            service: service.clone(),
            line,
            outcome: BlockOutcome::LeftAlone { why },
        };
        let Some(refs) = &tb.refs else {
            blocks.push(left_alone(
                "lst can't read this env_file value (only a path, a list of paths, or \
                 `- path:` / `required:` entries)"
                    .to_owned(),
            ));
            block_vars.push(None);
            continue;
        };
        let mut problem = None;
        let mut vars: Vec<String> = Vec::new();
        for r in refs {
            let Some(path) = normalize_path(&r.raw) else {
                problem = Some(format!(
                    "{:?} is not a path inside the stack directory",
                    r.raw
                ));
                break;
            };
            match files.get(&path) {
                Some(Parsed::Missing) if !r.required => {}
                Some(Parsed::Missing) | None => {
                    problem = Some(format!("{} does not exist", stack_path(stack, &path)));
                    break;
                }
                Some(Parsed::Unusable(why)) => {
                    problem = Some(format!("{}: {why}", stack_path(stack, &path)));
                    break;
                }
                Some(Parsed::Defs(d)) => {
                    for (var, v) in &d.vars {
                        if let Some(why) = why_not(v, var) {
                            not_imported.push(NotImported {
                                var: var.clone(),
                                file: path.clone(),
                                why,
                            });
                        } else if let Ok(value) = v {
                            add(var, value, &path)?;
                        }
                        if !vars.contains(var) {
                            vars.push(var.clone());
                        }
                    }
                }
            }
        }
        if let Some(why) = problem {
            blocks.push(left_alone(why));
            block_vars.push(None);
            continue;
        }
        blocks.push(Block {
            service,
            line,
            outcome: BlockOutcome::Replaced, // decided below
        });
        block_vars.push(Some(vars));
    }

    // Names.
    let mut names: BTreeMap<String, String> = BTreeMap::new(); // name → var
    for var in cands.keys() {
        let name = var.to_lowercase();
        store::scope(stack, &name).map_err(|source| ImportError::Name {
            var: var.clone(),
            source,
        })?;
        if let Some(a) = names.insert(name.clone(), var.clone()) {
            return Err(ImportError::Collision {
                a,
                b: var.clone(),
                name,
            });
        }
    }
    let values: BTreeMap<String, SecretString> = cands
        .iter()
        .map(|(var, c)| (var.to_lowercase(), c.value.clone()))
        .collect();
    let importable = |var: &str| cands.contains_key(var);

    // Edits.
    let mut sites = Vec::new();
    let mut edits = Vec::new();
    for r in &all_refs {
        if r.value && importable(&r.var) {
            let (line, col) = marker::line_col(text, r.span.start);
            edits.push(Edit {
                pieces: vec![(
                    r.span.clone(),
                    format!("<<secret:{}>>", r.var.to_lowercase()),
                )],
                what: EditOf::Site(sites.len()),
            });
            sites.push(Site {
                var: r.var.clone(),
                line,
                col,
                replaced: false,
            });
        }
    }
    let crlf = text.contains("\r\n");
    let mut snippets: Vec<String> = vec![String::new(); tblocks.len()];
    // Per block: the variables its replacement (or snippet) uses.
    let mut block_used: Vec<Vec<String>> = vec![Vec::new(); tblocks.len()];
    for (bi, tb) in tblocks.iter().enumerate() {
        let Some(vars) = &block_vars[bi] else {
            continue;
        };
        let service = tb.service.as_ref();
        // Keys the service's own environment sets win over the file.
        let overridden: BTreeSet<String> = service
            .and_then(|(_, name)| {
                let svc = base_doc.as_ref()?.0.get("services")?.get(name.as_str())?;
                env_map(svc.get("environment")?)
            })
            .map(|m| m.into_keys().collect())
            .unwrap_or_default();
        let has_env = service.is_some_and(|(_, name)| {
            base_doc
                .as_ref()
                .and_then(|d| d.0.get("services")?.get(name.as_str()))
                .is_some_and(|s| s.get("environment").is_some())
        });
        let mut snippet = String::from("environment:\n");
        let mut entries = Vec::new();
        let mut missing = Vec::new();
        for var in vars {
            if overridden.contains(var) {
                not_imported.push(NotImported {
                    var: var.clone(),
                    file: format!("env_file of {}", service.map_or("?", |(_, n)| n.as_str())),
                    why: "the service's environment: sets it too, and wins".to_owned(),
                });
                continue;
            }
            match cands.get(var) {
                Some(c) => {
                    let name = var.to_lowercase();
                    snippet.push_str(&entry(false, "  ", var, &name, c.value.expose()));
                    entries.push((var.clone(), name));
                }
                None => {
                    snippet.push_str(&format!("  # {var}: not imported, set it by hand\n"));
                    missing.push(var.clone());
                }
            }
        }
        snippets[bi] = snippet;
        block_used[bi] = entries.iter().map(|(v, _)| v.clone()).collect();
        let manual = |why: String| BlockOutcome::Manual {
            why,
            snippet: snippets[bi].clone(),
        };
        if !missing.is_empty() {
            blocks[bi].outcome = manual(format!(
                "not every variable of it is imported ({})",
                missing.join(", ")
            ));
            continue;
        }
        let Some((svc_line, _)) = service else {
            blocks[bi].outcome = manual("lst couldn't tell which service it belongs to".into());
            continue;
        };
        let ind = " ".repeat(tb.indent);
        let ends_nl = text[..tb.span.end].ends_with('\n');
        let mut pieces = Vec::new();
        if has_env {
            let Some((at, ei, list)) = environment_block(&ls, *svc_line, tb.indent) else {
                blocks[bi].outcome = manual(
                    "the service has an environment: lst can't add to (not a block-style map \
                     or list)"
                        .into(),
                );
                continue;
            };
            let ei = " ".repeat(ei);
            let mut add: String = entries
                .iter()
                .map(|(var, name)| entry(list, &ei, var, name, cands[var].value.expose()))
                .collect();
            if !text[..at].ends_with('\n') {
                add.insert(0, '\n');
                add.pop();
            }
            pieces.push((tb.span.clone(), String::new()));
            pieces.push((at..at, add));
            blocks[bi].outcome = BlockOutcome::Merged;
        } else {
            // An env file without variables: the block just goes.
            let mut new = String::new();
            if !entries.is_empty() {
                new = format!("{ind}environment:\n");
                let child = format!("{ind}  ");
                for (var, name) in &entries {
                    new.push_str(&entry(false, &child, var, name, cands[var].value.expose()));
                }
                if !ends_nl {
                    new.pop();
                }
            }
            pieces.push((tb.span.clone(), new));
        }
        if crlf {
            // New lines follow the file's line ending.
            for (_, s) in &mut pieces {
                *s = s.replace('\n', "\r\n");
            }
        }
        edits.push(Edit {
            pieces,
            what: EditOf::Block(bi),
        });
    }

    // Try each edit, in text order.
    let compose_err = |why| ImportError::Compose {
        path: compose_path.clone(),
        why,
    };
    let base = meaning(text, &values, &env, &files).map_err(compose_err)?;
    // A value some YAML parser could read as something other than a string
    // when it is a whole plain scalar (`0777` is octal to compose's parser,
    // a string to serde_yaml_ng) gets a second check, with a probe value
    // that serde_yaml_ng itself types as an integer there: the edit is kept
    // only where the marker ends up inside a string either way.
    let ambiguous: BTreeSet<String> = cands
        .iter()
        .filter(|(_, c)| type_ambiguous(c.value.expose()))
        .map(|(v, _)| v.clone())
        .collect();
    let probe = if ambiguous.is_empty() {
        None
    } else {
        let p = SecretString::new(PROBE.to_owned());
        let p_values: BTreeMap<String, SecretString> = values
            .iter()
            .map(|(name, v)| {
                let probed = names.get(name).is_some_and(|var| ambiguous.contains(var));
                (name.clone(), if probed { p.clone() } else { v.clone() })
            })
            .collect();
        let p_env: Env = env
            .iter()
            .map(|(k, v)| {
                let probed = ambiguous.contains(k) && v.is_some();
                (k.clone(), if probed { Some(p.clone()) } else { v.clone() })
            })
            .collect();
        let p_files = probe_files(&files, &ambiguous);
        let p_base = meaning(text, &p_values, &p_env, &p_files).map_err(compose_err)?;
        Some((p_values, p_env, p_files, p_base))
    };
    edits.sort_by_key(|e| e.pieces[0].0.start);
    let mut accepted: Vec<usize> = Vec::new();
    for i in 0..edits.len() {
        let ok = apply(text, accepted.iter().chain([&i]).map(|&j| &edits[j])).is_some_and(|cand| {
            meaning(&cand, &values, &env, &files).is_ok_and(|d| d == base)
                && probe.as_ref().is_none_or(|(pv, pe, pf, pb)| {
                    meaning(&cand, pv, pe, pf).is_ok_and(|d| d == *pb)
                })
        });
        if ok {
            accepted.push(i);
        }
        match edits[i].what {
            EditOf::Site(s) => sites[s].replaced = ok,
            EditOf::Block(b) if !ok => {
                blocks[b].outcome = BlockOutcome::Manual {
                    why: "the replaced text didn't mean the same to compose (indentation, \
                          quoting or a duplicate key)"
                        .into(),
                    snippet: snippets[b].clone(),
                };
            }
            EditOf::Block(_) => {}
        }
    }
    // `apply` of accepted edits can't overlap: each was checked with the
    // ones before it.
    let compose = apply(text, accepted.iter().map(|&j| &edits[j])).unwrap_or_else(|| text.into());

    // What gets sealed: every variable an accepted edit or a snippet uses.
    let mut sealed: BTreeSet<String> = BTreeSet::new();
    for s in sites.iter().filter(|s| s.replaced) {
        sealed.insert(s.var.clone());
    }
    for (bi, b) in blocks.iter().enumerate() {
        let used = matches!(
            b.outcome,
            BlockOutcome::Replaced | BlockOutcome::Merged | BlockOutcome::Manual { .. }
        );
        if used {
            sealed.extend(block_used[bi].iter().cloned());
        }
    }
    // Env files: drop the lines of sealed variables nothing reads any more.
    let still_refs: BTreeSet<String> = refs(&compose).into_iter().flat_map(Ref::all).collect();
    let final_files: Option<BTreeSet<String>> = env_file_refs_all(&compose);
    let mut env_files = Vec::new();
    for (rel, state) in input.files {
        let (FileState::Text(contents), Some(Parsed::Defs(d))) = (state, files.get(rel)) else {
            continue;
        };
        let Some(final_files) = &final_files else {
            break; // an env_file lst can't follow may be any file
        };
        if final_files.contains(rel) {
            continue;
        }
        let mut removed: Vec<String> = Vec::new();
        let mut drop_lines: BTreeSet<usize> = BTreeSet::new();
        for (var, _) in &d.vars {
            let Some(c) = cands.get(var) else { continue };
            if !sealed.contains(var) || !c.files.contains(rel) {
                continue;
            }
            if rel == DOT_ENV && still_refs.contains(var) {
                continue;
            }
            removed.push(var.clone());
            drop_lines.extend(d.lines[var].iter().copied());
        }
        if removed.is_empty() {
            continue;
        }
        removed.sort();
        let kept: String = contents
            .expose()
            .split_inclusive('\n')
            .enumerate()
            .filter(|(i, _)| !drop_lines.contains(&(i + 1)))
            .map(|(_, l)| l)
            .collect();
        let empty = kept.split('\n').all(is_filler);
        env_files.push(EnvFileEdit {
            file: rel.clone(),
            removed,
            contents: (!empty).then(|| SecretString::new(kept)),
        });
    }

    let mut secrets = cands
        .into_iter()
        .filter(|(var, _)| sealed.contains(var))
        .map(|(var, c)| Import {
            name: var.to_lowercase(),
            var,
            value: c.value,
            files: c.files,
        })
        .collect::<Vec<_>>();
    secrets.sort_by(|a, b| a.name.cmp(&b.name));
    not_imported.sort_by(|a, b| (&a.file, &a.var).cmp(&(&b.file, &b.var)));
    not_imported.dedup();

    Ok(Plan {
        compose,
        secrets,
        sites,
        blocks,
        not_imported,
        env_files,
    })
}

/// Every stack-relative file an `env_file:` key anywhere in `compose` names
/// (services, but also anchors and extension fields that merge keys bring
/// into services), or `None` if one of them can't be followed (it might
/// name any file).
fn env_file_refs_all(compose: &str) -> Option<BTreeSet<String>> {
    fn walk(v: &Value, out: &mut BTreeSet<String>) -> Option<()> {
        match v {
            Value::Mapping(m) => {
                for (k, v) in m {
                    if k.as_str() == Some("env_file") {
                        for r in env_refs(v)? {
                            if r.raw.contains('$') {
                                return None;
                            }
                            if let Some(p) = normalize_path(&r.raw) {
                                out.insert(p);
                            }
                        }
                    } else {
                        walk(v, out)?;
                    }
                }
                Some(())
            }
            Value::Sequence(seq) => seq.iter().try_for_each(|v| walk(v, out)),
            Value::Tagged(t) => walk(&t.value, out),
            _ => Some(()),
        }
    }
    let doc = serde_yaml_ng::from_str::<Value>(compose).ok().map(Doc)?;
    let mut out = BTreeSet::new();
    walk(&doc.0, &mut out)?;
    Some(out)
}

#[cfg(test)]
mod tests;
