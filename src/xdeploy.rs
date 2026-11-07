//! `x-deploy` (M4): the model, its validation, and the YAML rendering path
//! for stacks that use it. Pure: text, file contents, a key and a resolver
//! in; rendered text and the model out. See `docs/design.md`, "x-deploy
//! details".
//!
//! # Which stacks take the YAML path ([`detect`])
//! A stack whose `compose.yaml` has a line starting with `x-deploy:`
//! (quoted `"x-deploy":` / `'x-deploy':` too, spaces before the `:`
//! allowed) takes the YAML path. Every other stack keeps the raw-text
//! rendering of M1–M3 byte for byte, and its YAML is never parsed, so a
//! compose file that isn't valid YAML keeps working there. The one
//! exception: if the text contains `x-deploy` somewhere else and parses as
//! YAML with a top-level `x-deploy` key (flow style, `? x-deploy`, …), that
//! is an error ([`Detected::Hidden`]) rather than deploy steps silently not
//! running. On the YAML path, a parse error is an error, and so is a line
//! starting with `x-deploy:` that isn't the top-level key.
//!
//! # The YAML path ([`render`])
//! 1. Malformed markers are reported at their place in the raw text, as on
//!    the raw path.
//! 2. The raw (unrendered) text is parsed, so a YAML error can never hold a
//!    secret value. Errors show line and column only: the parser's own
//!    messages can quote the file (`duplicate entry with key "…"`), and the
//!    raw text may hold a `<<set:…>>` value.
//! 3. Merge keys (`<<: *anchor`) are applied (anchors are expanded anyway),
//!    so `volumes:` and `labels:` from a merged mapping count, and an
//!    injected `labels:` never hides merged ones. Key order within a
//!    mapping may change; compose doesn't care.
//! 4. `x-deploy` is removed and validated ([`check`] does steps 2–4 only:
//!    structural, no seed needed).
//! 5. Markers are substituted in every string scalar, mapping keys
//!    included, with the caller's resolver; every unresolved name in the
//!    compose file, the commands and the `render:` files is collected. The
//!    serializer quotes the values, so `"`, `'`, `: `, `#` and newlines in a
//!    manual secret are safe here.
//! 6. Each service with inputs gets an `lst.render-hash` label
//!    ([`service_hash`]).
//! 7. The document is serialized. Comments and formatting are not kept.
//!
//! Markers are only substituted in string scalars *after* YAML has decoded
//! them, while `lst sync` and the hook read markers from the raw text. A
//! marker that only appears through YAML escapes (`"\x3c<gen:a>>"`) is
//! therefore not synced and fails to resolve; write markers literally. A
//! marker in a comment is synced but dropped from the output.
//!
//! # `render:` files
//! `from` is relative to the stack directory and must be a file `lst sync`
//! reads (git would commit it: not gitignored, not a symlink), so its
//! markers are in `.sec/`; its contents must be UTF-8. It is rendered as
//! raw text with [`render::render`] (it is an arbitrary config file, not
//! YAML). `to` is absolute; `.` and empty components are dropped, `..` is
//! refused. `mode` is an octal string, default `"0600"`, at most `"0777"`.
//!
//! # Mounts
//! A service mounts a `to:` file if one of its `volumes:` is a bind mount
//! whose host source is the file or a parent directory of it, compared by
//! path components (`/srv/app` covers `/srv/app/x`, not `/srv/apple/x`).
//! Short syntax `SOURCE:TARGET[:MODE]` with an absolute `SOURCE`, and long
//! syntax with `type: bind` and an absolute `source:`. Ignored: named
//! volumes, relative sources (`./data`, `~/x`: they resolve against the
//! project directory, which in CI is not where the files are written),
//! sources with `$` (compose interpolates them later; lst can't know the
//! value), sources with `..`, and top-level `volumes:` with bind driver
//! options.
//!
//! # Secrets in memory
//! The parsed document is a `serde_yaml_ng::Value` tree, which holds plain
//! `String`s; rendered values have to be copied into it. Every string in
//! the tree is zeroized when the tree is dropped, and the serialized output
//! is written into a zeroizing buffer, but the YAML crate's own parser and
//! emitter buffers are not under lst's control: zeroizing is best effort
//! here, as for the M2 hook's git pipes.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde_yaml_ng::{Mapping, Value};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{KeyedHasher, RenderHashKey, SecretString};
use crate::marker::{self, MarkerKind, ParseError, ParseErrorKind};
use crate::render::{self, RenderError, Unresolved};
use crate::scan::{self, ScanError};
use crate::stack::{COMPOSE_FILE, STACKS_DIR};

/// The top-level compose key.
pub const KEY: &str = "x-deploy";
/// The label lst injects; users may not set it themselves.
pub const HASH_LABEL: &str = "lst.render-hash";
/// The mode of a rendered file without `mode:`.
pub const DEFAULT_MODE: u32 = 0o600;

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

/// The `x-deploy` section of one stack.
#[derive(Debug, Clone, Default)]
pub struct XDeploy {
    pub render: Vec<RenderFile>,
    pub pre: Vec<Step>,
    pub post: Vec<Step>,
}

/// One `render:` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderFile {
    /// Relative to the stack directory, normalised (`a/b`, no `.` or empty
    /// components).
    pub from: String,
    /// Absolute and normalised.
    pub to: PathBuf,
    /// Permission bits, at most `0o777`.
    pub mode: u32,
}

/// One `pre:` (`with:`) or `post:` (`exec:`) step.
#[derive(Debug, Clone)]
pub struct Step {
    /// The service it runs with (`pre`) or in (`post`).
    pub service: String,
    pub run: Run,
    pub when: When,
}

/// A step's command. In the model it is the raw text (it may hold
/// markers); in [`Rendered`] it is rendered. Either way it is secret.
#[derive(Debug, Clone)]
pub enum Run {
    /// `run: <string>`: run as `sh -c <string>`.
    Shell(SecretString),
    /// `run: [<arg>, …]`: exec form, no shell. Never empty.
    Exec(Vec<SecretString>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum When {
    Always,
    OnChange,
}

impl When {
    /// As written in `when:` (and hashed).
    pub fn as_str(self) -> &'static str {
        match self {
            When::Always => "always",
            When::OnChange => "on-change",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Pre,
    Post,
}

impl Phase {
    /// The section name (and what is hashed).
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Pre => "pre",
            Phase::Post => "post",
        }
    }
}

/// A rendered `render:` file.
#[derive(Debug)]
pub struct RenderedFile {
    pub from: String,
    pub to: PathBuf,
    pub mode: u32,
    pub contents: SecretString,
}

/// Everything a deploy of an `x-deploy` stack needs. For a stack without
/// `x-deploy` (the raw path) only `compose` is set.
#[derive(Debug, Default)]
pub struct Rendered {
    /// The final compose file: rendered, `x-deploy` stripped, labelled.
    pub compose: SecretString,
    /// The `render:` files, in `x-deploy` order.
    pub files: Vec<RenderedFile>,
    /// The steps with rendered commands, in `x-deploy` order.
    pub pre: Vec<Step>,
    pub post: Vec<Step>,
    /// Service → its `lst.render-hash` (only services with inputs).
    pub hashes: BTreeMap<String, String>,
}

#[derive(Debug, thiserror::Error)]
pub enum XDeployError {
    #[error(
        "{path}:{line}:{col}: invalid YAML (lst does not show the parser's message: it can quote \
         the file, and so a secret)"
    )]
    Yaml {
        path: String,
        line: usize,
        col: usize,
    },
    #[error("{path}: invalid YAML (more than one document, or too many aliases)")]
    YamlUnlocated { path: String },
    #[error("{path}: invalid merge key: `<<` must be a mapping or a list of mappings")]
    Merge { path: String },
    #[error(
        "{path}: a line starts with `x-deploy:`, but the document has no top-level x-deploy key"
    )]
    NotTopLevel { path: String },
    #[error(
        "{path}: write the top-level x-deploy key at the start of a line (`x-deploy:`); lst \
         decides which stacks use x-deploy from that line"
    )]
    Hidden { path: String },
    /// A structural problem: `at` is a key path such as
    /// `x-deploy.render[0].to` (indices from 0) or `services.web.labels`.
    /// Never contains a value.
    #[error("{path}: {at}: {problem}")]
    Invalid {
        path: String,
        at: String,
        problem: String,
    },
    #[error(
        "{path}: a marker in a YAML string is malformed once YAML quoting and escapes are \
         applied ({kind}); write markers literally"
    )]
    ScalarMarker { path: String, kind: ParseErrorKind },
    #[error("{path}: two keys of one mapping render to the same text")]
    KeyCollision { path: String },
    #[error("{path}: could not serialize the rendered compose file (is a mapping used as a key?)")]
    Serialize { path: String },
    /// A malformed marker in the raw compose text or a `render:` file, at
    /// `path:line:col`.
    #[error(transparent)]
    Marker(#[from] ScanError),
}

/// Why [`render`] failed.
#[derive(Debug)]
pub enum Failure<E> {
    XDeploy(XDeployError),
    /// Every marker name that didn't resolve, in the compose file, the
    /// commands and the `render:` files together: sorted by name and
    /// deduplicated (the first failure of each name is kept). Never empty.
    Unresolved(Vec<Unresolved<E>>),
}

impl<E> From<XDeployError> for Failure<E> {
    fn from(e: XDeployError) -> Self {
        Failure::XDeploy(e)
    }
}

impl<E> From<ScanError> for Failure<E> {
    fn from(e: ScanError) -> Self {
        Failure::XDeploy(e.into())
    }
}

fn compose_path(stack: &str) -> String {
    format!("{STACKS_DIR}/{stack}/{COMPOSE_FILE}")
}

fn invalid(path: &str, at: impl Into<String>, problem: impl Into<String>) -> XDeployError {
    XDeployError::Invalid {
        path: path.to_owned(),
        at: at.into(),
        problem: problem.into(),
    }
}

// ---------------------------------------------------------------------------
// Detection and parsing
// ---------------------------------------------------------------------------

/// Which rendering path a compose file takes (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detected {
    /// No `x-deploy`: the raw-text path of M1–M3.
    Raw,
    /// A line starts with `x-deploy:`: the YAML path.
    XDeploy,
    /// A top-level `x-deploy` key that isn't written at the start of a
    /// line: an error ([`XDeployError::Hidden`]).
    Hidden,
}

/// Whether a line of `text` starts with the `x-deploy` key and a `:`.
fn has_key_line(text: &str) -> bool {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    text.split('\n').any(|line| {
        ["x-deploy", "\"x-deploy\"", "'x-deploy'"].iter().any(|k| {
            line.strip_prefix(k)
                .is_some_and(|rest| rest.trim_start_matches([' ', '\t']).starts_with(':'))
        })
    })
}

/// Decides the rendering path of a compose file. Parses YAML only if the
/// text contains `x-deploy` but no line starts with it; a parse error then
/// means [`Detected::Raw`] (as in M1–M3).
pub fn detect(text: &str) -> Detected {
    if has_key_line(text) {
        return Detected::XDeploy;
    }
    if !text.contains(KEY) {
        return Detected::Raw;
    }
    let doc = serde_yaml_ng::from_str::<Value>(text).map(Doc);
    if doc.is_ok_and(|d| d.0.as_mapping().is_some_and(|m| m.contains_key(KEY))) {
        Detected::Hidden
    } else {
        Detected::Raw
    }
}

/// A parsed YAML value whose strings are zeroized on drop.
struct Doc(Value);

impl Drop for Doc {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// Zeroizes every string in `v` (keys included) and empties it.
fn wipe(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Sequence(seq) => seq.iter_mut().for_each(wipe),
        Value::Mapping(m) => {
            for (mut k, mut v) in std::mem::take(m) {
                wipe(&mut k);
                wipe(&mut v);
            }
        }
        Value::Tagged(t) => wipe(&mut t.value),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Parses the raw compose text and applies merge keys. Errors carry the
/// location only.
fn parse_yaml(path: &str, text: &str) -> Result<Doc, XDeployError> {
    let value = serde_yaml_ng::from_str::<Value>(text).map_err(|e| match e.location() {
        Some(l) => XDeployError::Yaml {
            path: path.to_owned(),
            line: l.line(),
            col: l.column(),
        },
        None => XDeployError::YamlUnlocated {
            path: path.to_owned(),
        },
    })?;
    let mut doc = Doc(value);
    doc.0.apply_merge().map_err(|_| XDeployError::Merge {
        path: path.to_owned(),
    })?;
    Ok(doc)
}

/// What [`parse`] found: the document without `x-deploy`, the model, and
/// the text of each `render:` file (in `model.render` order).
struct Parsed<'f> {
    doc: Doc,
    model: XDeploy,
    sources: Vec<&'f str>,
}

/// Whether `s` holds no marker (and nothing that looks like a broken one).
fn is_plain(s: &str) -> bool {
    marker::parse(s).is_ok_and(|m| m.is_empty())
}

fn parse<'f, B: AsRef<[u8]>>(
    stack: &str,
    text: &str,
    files: &'f [(String, B)],
) -> Result<Parsed<'f>, XDeployError> {
    let path = compose_path(stack);
    let mut doc = parse_yaml(&path, text)?;
    let Some(top) = doc.0.as_mapping_mut() else {
        return Err(invalid(&path, "the document", "must be a mapping"));
    };
    let Some(section) = top.shift_remove(KEY) else {
        return Err(XDeployError::NotTopLevel { path });
    };
    let section = Doc(section);
    let services = service_names(&path, top)?;
    let prefix = format!("{STACKS_DIR}/{stack}/");
    let stack_files: BTreeMap<&str, &[u8]> = files
        .iter()
        .filter_map(|(p, b)| Some((p.strip_prefix(&prefix)?, b.as_ref())))
        .collect();
    let mut sources = Vec::new();
    let model = parse_model(
        &path,
        &prefix,
        &section.0,
        &services,
        &stack_files,
        &mut sources,
    )?;
    Ok(Parsed {
        doc,
        model,
        sources,
    })
}

/// The service names under `services:`, checked: names hold no markers,
/// and no service sets the label lst injects.
fn service_names(path: &str, top: &Mapping) -> Result<BTreeSet<String>, XDeployError> {
    let services = match top.get("services") {
        None | Some(Value::Null) => return Ok(BTreeSet::new()),
        Some(Value::Mapping(m)) => m,
        Some(_) => return Err(invalid(path, "services", "must be a mapping")),
    };
    let mut names = BTreeSet::new();
    for (k, svc) in services {
        let Value::String(name) = k else {
            return Err(invalid(path, "services", "service names must be strings"));
        };
        if !is_plain(name) {
            return Err(invalid(
                path,
                "services",
                "a service name contains a marker; markers are not allowed in service names",
            ));
        }
        if svc.get("labels").is_some_and(has_hash_label) {
            return Err(invalid(
                path,
                format!("services.{name}.labels"),
                format!("{HASH_LABEL} is set by lst; remove it"),
            ));
        }
        names.insert(name.clone());
    }
    Ok(names)
}

/// Whether a `labels:` value (mapping, or list of `key=value`) sets
/// [`HASH_LABEL`].
fn has_hash_label(labels: &Value) -> bool {
    match labels {
        Value::Mapping(m) => m.contains_key(HASH_LABEL),
        Value::Sequence(items) => items.iter().filter_map(Value::as_str).any(|s| {
            s.strip_prefix(HASH_LABEL)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('='))
        }),
        _ => false,
    }
}

/// Errors on any key of `m` not in `allowed`.
fn check_keys(path: &str, at: &str, m: &Mapping, allowed: &[&str]) -> Result<(), XDeployError> {
    let known = |k: &Value| k.as_str().is_some_and(|k| allowed.contains(&k));
    if m.keys().all(known) {
        Ok(())
    } else {
        Err(invalid(
            path,
            at,
            format!("unknown key (allowed: {})", allowed.join(", ")),
        ))
    }
}

fn mapping<'v>(
    path: &str,
    at: &str,
    v: &'v Value,
    what: &str,
) -> Result<&'v Mapping, XDeployError> {
    v.as_mapping()
        .ok_or_else(|| invalid(path, at, format!("must be a mapping with {what}")))
}

fn list<'v>(path: &str, at: &str, v: &'v Value) -> Result<&'v [Value], XDeployError> {
    match v {
        Value::Sequence(s) => Ok(s),
        _ => Err(invalid(path, at, "must be a list")),
    }
}

/// The string at `m[key]`, required, without markers (it is used as is,
/// never rendered).
fn plain_field<'v>(
    path: &str,
    at: &str,
    m: &'v Mapping,
    key: &str,
) -> Result<&'v str, XDeployError> {
    let at = format!("{at}.{key}");
    match m.get(key) {
        None => Err(invalid(path, at, "is missing")),
        Some(Value::String(s)) if is_plain(s) && !s.contains('\0') => Ok(s),
        Some(Value::String(_)) => Err(invalid(
            path,
            at,
            "must not contain markers or NUL characters (markers are only rendered in run)",
        )),
        Some(_) => Err(invalid(path, at, "must be a string")),
    }
}

fn parse_model<'f>(
    path: &str,
    prefix: &str,
    section: &Value,
    services: &BTreeSet<String>,
    files: &BTreeMap<&str, &'f [u8]>,
    sources: &mut Vec<&'f str>,
) -> Result<XDeploy, XDeployError> {
    let m = mapping(path, KEY, section, "render, pre and/or post")?;
    check_keys(path, KEY, m, &["render", "pre", "post"])?;
    let mut model = XDeploy::default();
    if let Some(v) = m.get("render") {
        for (i, e) in list(path, "x-deploy.render", v)?.iter().enumerate() {
            let at = format!("x-deploy.render[{i}]");
            let f = render_entry(path, prefix, &at, e, files, sources)?;
            if let Some(j) = model.render.iter().position(|g| g.to == f.to) {
                return Err(invalid(
                    path,
                    format!("{at}.to"),
                    format!("same target as x-deploy.render[{j}].to"),
                ));
            }
            model.render.push(f);
        }
    }
    for phase in [Phase::Pre, Phase::Post] {
        let Some(v) = m.get(phase.as_str()) else {
            continue;
        };
        let name = phase.as_str();
        for (i, e) in list(path, &format!("x-deploy.{name}"), v)?
            .iter()
            .enumerate()
        {
            let step = step_entry(path, phase, &format!("x-deploy.{name}[{i}]"), e, services)?;
            match phase {
                Phase::Pre => model.pre.push(step),
                Phase::Post => model.post.push(step),
            }
        }
    }
    Ok(model)
}

fn render_entry<'f>(
    path: &str,
    prefix: &str,
    at: &str,
    e: &Value,
    files: &BTreeMap<&str, &'f [u8]>,
    sources: &mut Vec<&'f str>,
) -> Result<RenderFile, XDeployError> {
    let m = mapping(path, at, e, "from, to and mode")?;
    check_keys(path, at, m, &["from", "to", "mode"])?;
    let from_at = format!("{at}.from");
    let from =
        relative_path(plain_field(path, at, m, "from")?).map_err(|p| invalid(path, &from_at, p))?;
    let Some(bytes) = files.get(from.as_str()) else {
        return Err(invalid(
            path,
            from_at,
            format!(
                "no such file in {prefix} (it must be a regular file that git would commit: not \
                 gitignored, not a symlink)"
            ),
        ));
    };
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Err(invalid(
            path,
            from_at,
            "is not UTF-8 text; lst only renders text files",
        ));
    };
    sources.push(text);
    let to = absolute_path(plain_field(path, at, m, "to")?)
        .map_err(|p| invalid(path, format!("{at}.to"), p))?;
    let mode = match m.get("mode") {
        None => DEFAULT_MODE,
        Some(v) => parse_mode(v).map_err(|p| invalid(path, format!("{at}.mode"), p))?,
    };
    Ok(RenderFile { from, to, mode })
}

/// `from`, normalised: relative, inside the stack directory.
fn relative_path(s: &str) -> Result<String, &'static str> {
    if s.starts_with('/') {
        return Err("must be relative to the stack directory, not absolute");
    }
    let mut parts = Vec::new();
    for c in s.split('/') {
        match c {
            "" | "." => {}
            ".." => return Err("must stay inside the stack directory (no `..`)"),
            c => parts.push(c),
        }
    }
    if parts.is_empty() {
        return Err("must name a file");
    }
    Ok(parts.join("/"))
}

/// `to`, normalised: absolute, naming a file.
fn absolute_path(s: &str) -> Result<PathBuf, &'static str> {
    let Some(rest) = s.strip_prefix('/') else {
        return Err("must be an absolute path");
    };
    if rest.ends_with('/') {
        return Err("must name a file, not end with `/`");
    }
    let mut parts = Vec::new();
    for c in rest.split('/') {
        match c {
            "" | "." => {}
            ".." => return Err("must not contain `..`"),
            c => parts.push(c),
        }
    }
    if parts.is_empty() {
        return Err("must name a file");
    }
    Ok(PathBuf::from(format!("/{}", parts.join("/"))))
}

/// `mode: "0640"`: 3 or 4 octal digits, at most `0777`.
fn parse_mode(v: &Value) -> Result<u32, &'static str> {
    let Value::String(s) = v else {
        return Err("must be a quoted octal string such as \"0640\"");
    };
    if !(3..=4).contains(&s.len()) || !s.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        return Err("must be an octal string such as \"0640\"");
    }
    let mode = s.bytes().fold(0, |acc, b| acc * 8 + u32::from(b - b'0'));
    if mode > 0o777 {
        return Err("must be at most \"0777\" (setuid, setgid and sticky bits are not supported)");
    }
    Ok(mode)
}

fn step_entry(
    path: &str,
    phase: Phase,
    at: &str,
    e: &Value,
    services: &BTreeSet<String>,
) -> Result<Step, XDeployError> {
    let target = match phase {
        Phase::Pre => "with",
        Phase::Post => "exec",
    };
    let m = mapping(path, at, e, &format!("{target}, run and when"))?;
    check_keys(path, at, m, &[target, "run", "when"])?;
    let service = plain_field(path, at, m, target)?;
    if !services.contains(service) {
        return Err(invalid(
            path,
            format!("{at}.{target}"),
            "no service with that name under services:",
        ));
    }
    let run = match m.get("run") {
        None => return Err(invalid(path, format!("{at}.run"), "is missing")),
        Some(v) => parse_run(path, &format!("{at}.run"), v)?,
    };
    let when = match m.get("when") {
        None => When::Always,
        Some(Value::String(s)) if s == "always" => When::Always,
        Some(Value::String(s)) if s == "on-change" => When::OnChange,
        Some(_) => {
            return Err(invalid(
                path,
                format!("{at}.when"),
                "must be always or on-change",
            ));
        }
    };
    Ok(Step {
        service: service.to_owned(),
        run,
        when,
    })
}

fn parse_run(path: &str, at: &str, v: &Value) -> Result<Run, XDeployError> {
    match v {
        Value::String(s) if s.trim().is_empty() => Err(invalid(path, at, "must not be empty")),
        Value::String(s) => Ok(Run::Shell(SecretString::new(s.clone()))),
        Value::Sequence(items) if items.is_empty() => {
            Err(invalid(path, at, "must not be an empty list"))
        }
        Value::Sequence(items) => {
            let mut args = Vec::with_capacity(items.len());
            for (j, item) in items.iter().enumerate() {
                let Value::String(a) = item else {
                    return Err(invalid(
                        path,
                        format!("{at}[{j}]"),
                        "must be a string (quote numbers and booleans)",
                    ));
                };
                args.push(SecretString::new(a.clone()));
            }
            Ok(Run::Exec(args))
        }
        _ => Err(invalid(
            path,
            at,
            "must be a string (run with sh -c) or a list of strings (exec form)",
        )),
    }
}

/// Validates the `x-deploy` section of a stack's `compose.yaml` (`text`,
/// raw) without rendering anything: YAML, the model, service references,
/// `render:` sources and labels. `files` are the stack's files as `lst
/// sync` reads them (repo-relative path, contents), the scope `from:` must
/// be in. For `lst check`; [`render`] runs the same checks.
pub fn check<B: AsRef<[u8]>>(
    stack: &str,
    text: &str,
    files: &[(String, B)],
) -> Result<XDeploy, XDeployError> {
    Ok(parse(stack, text, files)?.model)
}

/// `s` normalised as a `from:` path, for comparing a `from` given on the
/// command line with the model's.
pub fn normalize_from(s: &str) -> Option<String> {
    relative_path(s).ok()
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// The caller's resolver plus every failure so far (by name, first kept).
struct Resolver<E, F> {
    resolve: F,
    failures: BTreeMap<String, E>,
}

impl<E, F: FnMut(&MarkerKind) -> Result<SecretString, E>> Resolver<E, F> {
    /// `s` with its markers substituted. Unresolved names are recorded and
    /// rendering goes on (with an empty placeholder) so that all of them
    /// are reported; a malformed marker is returned as an error.
    /// With `compose`, each substituted value is escaped for compose's `$`
    /// interpolation ([`render::escape_compose`]); `render:` files and `run:`
    /// commands don't pass through compose and are rendered as they are.
    fn text(&mut self, s: &str, compose: bool) -> Result<SecretString, ParseError> {
        let rendered = if compose {
            render::render_compose(s, &mut self.resolve)
        } else {
            render::render(s, &mut self.resolve)
        };
        match rendered {
            Ok(v) => Ok(v),
            Err(RenderError::Parse(e)) => Err(e),
            Err(RenderError::Unresolved(list)) => {
                for u in list {
                    self.failures.entry(u.name).or_insert(u.error);
                }
                Ok(SecretString::default())
            }
        }
    }

    /// A YAML scalar's text (decoded by YAML, so no raw-text location).
    /// `compose`: the scalar is part of the compose document (escape `$`),
    /// not a `run:` command.
    fn scalar(&mut self, path: &str, s: &str, compose: bool) -> Result<SecretString, XDeployError> {
        self.text(s, compose)
            .map_err(|e| XDeployError::ScalarMarker {
                path: path.to_owned(),
                kind: e.kind,
            })
    }
}

/// Substitutes markers in every string of `v`, mapping keys included.
/// Every entry is put back into the tree even after an error, so it is
/// still wiped when the tree is dropped.
fn render_value<E, F: FnMut(&MarkerKind) -> Result<SecretString, E>>(
    path: &str,
    v: &mut Value,
    r: &mut Resolver<E, F>,
) -> Result<(), XDeployError> {
    match v {
        Value::String(s) if s.contains("<<") => {
            let rendered = r.scalar(path, s, true)?;
            let mut old = std::mem::replace(s, rendered.expose().to_owned());
            old.zeroize();
            Ok(())
        }
        Value::Sequence(seq) => seq.iter_mut().try_for_each(|v| render_value(path, v, r)),
        Value::Mapping(m) => {
            let mut result = Ok(());
            for (mut k, mut val) in std::mem::take(m) {
                if result.is_ok() {
                    result = render_value(path, &mut k, r)
                        .and_then(|()| render_value(path, &mut val, r));
                }
                if let Some(mut lost) = m.insert(k, val) {
                    wipe(&mut lost);
                    if result.is_ok() {
                        result = Err(XDeployError::KeyCollision {
                            path: path.to_owned(),
                        });
                    }
                }
            }
            result
        }
        Value::Tagged(t) => render_value(path, &mut t.value, r),
        _ => Ok(()),
    }
}

fn render_steps<E, F: FnMut(&MarkerKind) -> Result<SecretString, E>>(
    path: &str,
    steps: &[Step],
    r: &mut Resolver<E, F>,
) -> Result<Vec<Step>, XDeployError> {
    let mut out = Vec::with_capacity(steps.len());
    for s in steps {
        let run = match &s.run {
            Run::Shell(c) => Run::Shell(r.scalar(path, c.expose(), false)?),
            Run::Exec(args) => Run::Exec(
                args.iter()
                    .map(|a| r.scalar(path, a.expose(), false))
                    .collect::<Result<_, _>>()?,
            ),
        };
        out.push(Step {
            service: s.service.clone(),
            run,
            when: s.when,
        });
    }
    Ok(out)
}

/// Renders an `x-deploy` stack: `text` is its raw `compose.yaml`, `files`
/// its files as `lst sync` reads them (repo-relative path, contents), `key`
/// the render-hash key and `resolve` the same resolver as for
/// [`render::render`]. See the module docs for the steps.
pub fn render<B, E, F>(
    stack: &str,
    text: &str,
    files: &[(String, B)],
    key: &RenderHashKey,
    resolve: F,
) -> Result<Rendered, Failure<E>>
where
    B: AsRef<[u8]>,
    F: FnMut(&MarkerKind) -> Result<SecretString, E>,
{
    let path = compose_path(stack);
    marker::parse(text).map_err(|e| scan::parse_error(&path, text, e))?;
    let Parsed {
        mut doc,
        model,
        sources,
    } = parse(stack, text, files)?;

    let mut r = Resolver {
        resolve,
        failures: BTreeMap::new(),
    };
    render_value(&path, &mut doc.0, &mut r)?;
    let pre = render_steps(&path, &model.pre, &mut r)?;
    let post = render_steps(&path, &model.post, &mut r)?;
    let mut rendered_files = Vec::with_capacity(model.render.len());
    for (f, source) in model.render.into_iter().zip(sources) {
        let contents = r.text(source, false).map_err(|e| {
            scan::parse_error(&format!("{STACKS_DIR}/{stack}/{}", f.from), source, e)
        })?;
        rendered_files.push(RenderedFile {
            from: f.from,
            to: f.to,
            mode: f.mode,
            contents,
        });
    }
    if !r.failures.is_empty() {
        let list = r
            .failures
            .into_iter()
            .map(|(name, error)| Unresolved { name, error })
            .collect();
        return Err(Failure::Unresolved(list));
    }

    let mut hashes = BTreeMap::new();
    if let Some(Value::Mapping(services)) = doc.0.get_mut("services") {
        // `parse` checked that every service name is a string.
        let named = services
            .iter_mut()
            .filter_map(|(k, v)| Some((k.as_str()?, v)));
        for (name, svc) in named {
            let Some(hash) = hash_service(key, name, svc, &rendered_files, &pre, &post) else {
                continue;
            };
            add_label(&path, name, svc, &hash)?;
            hashes.insert(name.to_owned(), hash);
        }
    }

    let compose = serialize(&path, &doc.0)?;
    Ok(Rendered {
        compose,
        files: rendered_files,
        pre,
        post,
        hashes,
    })
}

/// The render hash of service `name` (`svc`, rendered), or `None` if it
/// has no inputs: no mounted `render:` file and no step.
fn hash_service(
    key: &RenderHashKey,
    name: &str,
    svc: &Value,
    files: &[RenderedFile],
    pre: &[Step],
    post: &[Step],
) -> Option<String> {
    let volumes = svc
        .get("volumes")
        .and_then(Value::as_sequence)
        .map_or(&[][..], Vec::as_slice);
    let mounted: Vec<(&Path, &[u8])> = files
        .iter()
        .filter(|f| volumes.iter().any(|v| mounts(v, &f.to)))
        .map(|f| (f.to.as_path(), f.contents.expose().as_bytes()))
        .collect();
    let steps: Vec<(Phase, &Step)> = pre
        .iter()
        .map(|s| (Phase::Pre, s))
        .chain(post.iter().map(|s| (Phase::Post, s)))
        .filter(|(_, s)| s.service == name)
        .collect();
    if mounted.is_empty() && steps.is_empty() {
        return None;
    }
    Some(service_hash(key, &mounted, &steps))
}

/// The host source of a bind mount, if `volume` is one.
fn bind_source(volume: &Value) -> Option<&str> {
    match volume {
        Value::String(s) => s.split_once(':').map(|(src, _)| src),
        Value::Mapping(m) => {
            if m.get("type")?.as_str()? != "bind" {
                return None;
            }
            m.get("source")?.as_str()
        }
        _ => None,
    }
}

/// Whether `volume` bind-mounts `file` or a parent directory of it (see
/// the module docs for what is ignored).
fn mounts(volume: &Value, file: &Path) -> bool {
    let Some(src) = bind_source(volume) else {
        return false;
    };
    if !src.starts_with('/') || src.contains('$') {
        return false;
    }
    let mut parts = Vec::new();
    for c in src.split('/') {
        match c {
            "" | "." => {}
            ".." => return false,
            c => parts.push(c),
        }
    }
    file.starts_with(format!("/{}", parts.join("/")))
}

/// Feeds `bytes` length-prefixed: 8-byte little-endian length, then the
/// bytes.
fn put(h: &mut KeyedHasher, bytes: &[u8]) {
    put_count(h, bytes.len());
    h.update(bytes);
}

fn put_count(h: &mut KeyedHasher, n: usize) {
    // usize is at most 64 bits on every supported target.
    h.update(&(n as u64).to_le_bytes());
}

/// The `lst.render-hash` of a service: keyed BLAKE3 (key:
/// [`crate::crypto::render_hash_key`]) over this encoding of its inputs,
/// where `lp(x)` is `x`'s length as a little-endian u64 followed by `x`,
/// and `u64(n)` is `n` as a little-endian u64:
///
/// ```text
/// lp("files") u64(#files)
///   per file, sorted by the bytes of `to`:  lp(to) lp(rendered contents)
/// lp("steps") u64(#steps)
///   per step, pre steps then post steps, each in x-deploy order:
///     lp("pre" | "post") lp("always" | "on-change")
///     then  lp("shell") lp(command)             for run: <string>
///     or    lp("exec") u64(#args) lp(arg)…      for run: [<arg>, …]
/// ```
///
/// Result: 64 lowercase hex characters. `files` are the `render:` files
/// the service mounts (any order), `steps` the steps that target it (in
/// order). Changing this encoding changes every hash, so every labelled
/// container is recreated once: treat it as frozen (pinned in
/// `tests/vectors.rs`).
pub fn service_hash(
    key: &RenderHashKey,
    files: &[(&Path, &[u8])],
    steps: &[(Phase, &Step)],
) -> String {
    let mut files = files.to_vec();
    files.sort_by(|a, b| {
        a.0.as_os_str()
            .as_encoded_bytes()
            .cmp(b.0.as_os_str().as_encoded_bytes())
    });
    let mut h = key.hasher();
    put(&mut h, b"files");
    put_count(&mut h, files.len());
    for (to, contents) in &files {
        put(&mut h, to.as_os_str().as_encoded_bytes());
        put(&mut h, contents);
    }
    put(&mut h, b"steps");
    put_count(&mut h, steps.len());
    for (phase, step) in steps {
        put(&mut h, phase.as_str().as_bytes());
        put(&mut h, step.when.as_str().as_bytes());
        match &step.run {
            Run::Shell(c) => {
                put(&mut h, b"shell");
                put(&mut h, c.expose().as_bytes());
            }
            Run::Exec(args) => {
                put(&mut h, b"exec");
                put_count(&mut h, args.len());
                for a in args {
                    put(&mut h, a.expose().as_bytes());
                }
            }
        }
    }
    h.finalize_hex()
}

/// Adds `lst.render-hash: <hash>` to service `name`'s labels: a mapping
/// entry, or a `key=value` item if `labels:` is a list.
fn add_label(path: &str, name: &str, svc: &mut Value, hash: &str) -> Result<(), XDeployError> {
    let Value::Mapping(svc) = svc else {
        return Err(invalid(
            path,
            format!("services.{name}"),
            "must be a mapping",
        ));
    };
    match svc.get_mut("labels") {
        None | Some(Value::Null) => {
            let mut labels = Mapping::new();
            labels.insert(HASH_LABEL.into(), hash.into());
            svc.insert("labels".into(), Value::Mapping(labels));
        }
        Some(Value::Mapping(labels)) => {
            labels.insert(HASH_LABEL.into(), hash.into());
        }
        Some(Value::Sequence(labels)) => labels.push(format!("{HASH_LABEL}={hash}").into()),
        Some(_) => {
            return Err(invalid(
                path,
                format!("services.{name}.labels"),
                "must be a mapping or a list",
            ));
        }
    }
    Ok(())
}

/// A `Write` into a buffer that is zeroized on drop and whenever it grows
/// (the old allocation is zeroized, not just freed).
#[derive(Default)]
struct ZeroizingWriter(Zeroizing<Vec<u8>>);

impl Write for ZeroizingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let need = self.0.len() + buf.len();
        if need > self.0.capacity() {
            let cap = need.max(self.0.capacity() * 2).max(4096);
            let mut grown = Zeroizing::new(Vec::with_capacity(cap));
            grown.extend_from_slice(&self.0);
            self.0 = grown;
        }
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// `bytes` as a [`SecretString`]; `None` (and zeroized) if not UTF-8.
fn secret_utf8(mut bytes: Zeroizing<Vec<u8>>) -> Option<SecretString> {
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(s) => Some(SecretString::new(s)),
        Err(e) => {
            e.into_bytes().zeroize();
            None
        }
    }
}

fn serialize(path: &str, v: &Value) -> Result<SecretString, XDeployError> {
    let err = || XDeployError::Serialize {
        path: path.to_owned(),
    };
    let mut w = ZeroizingWriter::default();
    serde_yaml_ng::to_writer(&mut w, v).map_err(|_| err())?;
    secret_utf8(w.0).ok_or_else(err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{SEED_LEN, Seed, render_hash_key};

    const STACK: &str = "web";
    const COMPOSE: &str = "stacks/web/compose.yaml";
    /// A manual secret with everything YAML cares about.
    const TRICKY: &str = "q\"uo'te: #hash\n  next: line \\ - [x] {y} & *z ! % @ ` 🔑";
    /// Plaintexts in test inputs; never in any error.
    const PLAINTEXTS: &[&str] = &["hunter2", "G-", "S-", "q\"uo'te"];

    fn key(b: u8) -> RenderHashKey {
        render_hash_key(&Seed::from_bytes([b; SEED_LEN]))
    }

    /// gen → `G-name`, secret → `S-name` (`tricky` → [`TRICKY`]); names
    /// starting with `bad` and every set marker fail.
    fn resolve(m: &MarkerKind) -> Result<SecretString, String> {
        if m.name().starts_with("bad") {
            return Err(format!("`{}` failed", m.name()));
        }
        match m {
            MarkerKind::Gen { name, .. } => Ok(SecretString::new(format!("G-{name}"))),
            MarkerKind::Secret { name } if name == "tricky" => Ok(SecretString::new(TRICKY.into())),
            MarkerKind::Secret { name } => Ok(SecretString::new(format!("S-{name}"))),
            MarkerKind::Set { name, .. } => Err(format!("`{name}` is a set marker")),
        }
    }

    type Files = Vec<(String, Vec<u8>)>;

    /// Stack files (repo-relative paths under `stacks/web/`).
    fn files(list: &[(&str, &[u8])]) -> Files {
        list.iter()
            .map(|(p, b)| (format!("stacks/{STACK}/{p}"), b.to_vec()))
            .collect()
    }

    /// `extra` plus `compose.yaml` holding `text`.
    fn with_compose(text: &str, extra: &Files) -> Files {
        let mut all = files(&[("compose.yaml", text.as_bytes())]);
        all.extend(extra.iter().cloned());
        all
    }

    fn render_with(
        text: &str,
        extra: &Files,
        k: &RenderHashKey,
    ) -> Result<Rendered, Failure<String>> {
        render(STACK, text, &with_compose(text, extra), k, resolve)
    }

    #[track_caller]
    fn render_ok(text: &str, extra: &Files) -> Rendered {
        render_with(text, extra, &key(1)).unwrap()
    }

    fn as_error(f: Failure<String>) -> Option<XDeployError> {
        match f {
            Failure::XDeploy(e) => Some(e),
            Failure::Unresolved(_) => None,
        }
    }

    fn as_unresolved(f: Failure<String>) -> Option<Vec<Unresolved<String>>> {
        match f {
            Failure::XDeploy(_) => None,
            Failure::Unresolved(list) => Some(list),
        }
    }

    /// A step's command: `Some` for the matching form only.
    fn shell(run: &Run) -> Option<&str> {
        match run {
            Run::Shell(c) => Some(c.expose()),
            Run::Exec(_) => None,
        }
    }

    fn exec(run: &Run) -> Option<Vec<&str>> {
        match run {
            Run::Shell(_) => None,
            Run::Exec(args) => Some(args.iter().map(SecretString::expose).collect()),
        }
    }

    fn yaml(r: &Rendered) -> Value {
        serde_yaml_ng::from_str(r.compose.expose()).unwrap()
    }

    /// The error `render` fails with; asserts that no plaintext is in it.
    #[track_caller]
    fn fails(text: &str, extra: &Files) -> String {
        let err = as_error(render_with(text, extra, &key(1)).unwrap_err()).unwrap();
        let msg = err.to_string();
        let all = format!("{msg} {err:?}");
        for p in PLAINTEXTS {
            assert!(!all.contains(p), "{p} in {all}");
        }
        msg
    }

    /// Like [`fails`], and `check` reports the same.
    #[track_caller]
    fn invalid_model(text: &str, extra: &Files) -> String {
        let msg = fails(text, extra);
        let checked = check(STACK, text, &with_compose(text, extra)).unwrap_err();
        assert_eq!(checked.to_string(), msg);
        msg
    }

    fn conf() -> Files {
        let mut list = files(&[
            (
                "config/app.conf",
                b"user=<<gen:user>>\npass: <<secret:tricky>>\n",
            ),
            ("config/other.conf", b"plain\n"),
            ("bin.dat", b"\xff\xfe"),
        ]);
        // Another stack's file is never a `from:` of this one.
        list.push(("stacks/db/config/app.conf".into(), b"x".to_vec()));
        list
    }

    // -- detection ------------------------------------------------------------

    #[test]
    fn detect_by_line() {
        for text in [
            "x-deploy:\n  pre: []\n",
            "services: {}\nx-deploy: {}\n",
            "a: 1\r\nx-deploy :\r\n",
            "\"x-deploy\": {}\n",
            "'x-deploy'\t: {}\n",
            "\u{feff}x-deploy: {}\n",
            // A line starting with it decides, valid YAML or not.
            "x-deploy: [\n",
        ] {
            assert_eq!(detect(text), Detected::XDeploy, "{text:?}");
        }
        for text in [
            "",
            "services: {}\n",
            "x-deployment: {}\n",
            "x-deploy-x: 1\n",
            "services:\n  a:\n    x-deploy: 1\n",
            "a: x-deploy\n",
            "# x-deploy: in a comment\n",
            // Not valid YAML: can't tell, so the M1–M3 path.
            "{x-deploy: [\n",
            "- x-deploy: 1\n",
        ] {
            assert_eq!(detect(text), Detected::Raw, "{text:?}");
        }
        for text in [
            "{x-deploy: {}, services: {}}\n",
            "? x-deploy\n: {}\n",
            " x-deploy: {}\n",
        ] {
            assert_eq!(detect(text), Detected::Hidden, "{text:?}");
        }
    }

    // -- the YAML path --------------------------------------------------------

    const BASIC: &str = "\
x-common: &common
  restart: unless-stopped
services:
  app:
    <<: *common
    image: example/app
    environment:
      DB: postgres://app:<<gen:db>>@db/app
      TOKEN: '<<secret:tricky>>'
      OTHER: <<secret:other>>
      <<gen:keyname>>: in-a-key
    command: [\"--pw\", <<gen:db:hex64>>]
  db:
    image: postgres:17
    environment:
      POSTGRES_PASSWORD: <<gen:db>>
x-deploy:
  render:
    - from: config/app.conf
      to: /srv/app/app.conf
";

    #[test]
    fn renders_scalars_and_keys_and_strips_x_deploy() {
        let r = render_ok(BASIC, &conf());
        let v = yaml(&r);
        assert!(v.get(KEY).is_none());
        // Other x- keys stay (compose ignores them).
        assert_eq!(v["x-common"]["restart"], "unless-stopped");
        let app = &v["services"]["app"];
        // Merge keys are applied.
        assert_eq!(app["restart"], "unless-stopped");
        assert!(app.get("<<").is_none());
        assert_eq!(app["environment"]["DB"], "postgres://app:G-db@db/app");
        assert_eq!(app["environment"]["TOKEN"], TRICKY);
        assert_eq!(app["environment"]["OTHER"], "S-other");
        assert_eq!(app["environment"]["G-keyname"], "in-a-key");
        assert_eq!(app["command"][1], "G-db");
        let db = &v["services"]["db"];
        assert_eq!(db["environment"]["POSTGRES_PASSWORD"], "G-db");
        // Nothing mounts the file and there are no steps: no labels.
        assert!(r.hashes.is_empty());
        assert!(app.get("labels").is_none());
        // The file is rendered as raw text, not as YAML.
        assert_eq!(r.files.len(), 1);
        let f = &r.files[0];
        assert_eq!(
            (f.from.as_str(), f.to.as_path(), f.mode),
            (
                "config/app.conf",
                Path::new("/srv/app/app.conf"),
                DEFAULT_MODE
            )
        );
        assert_eq!(
            f.contents.expose(),
            format!("user=G-user\npass: {TRICKY}\n")
        );
        assert!(r.pre.is_empty() && r.post.is_empty());
        // Deterministic.
        assert_eq!(
            render_ok(BASIC, &conf()).compose.expose(),
            r.compose.expose()
        );
        // Nothing secret in Debug output.
        let dbg = format!("{r:?}");
        assert!(!dbg.contains("G-") && !dbg.contains("uo'te"), "{dbg}");
    }

    #[test]
    fn tricky_values_round_trip_through_the_serializer() {
        let at = |v: &Value, path: &[&str]| -> String {
            let mut v = v;
            for k in path {
                v = match k.parse::<usize>() {
                    Ok(i) => &v[i],
                    Err(_) => &v[*k],
                };
            }
            v.as_str().unwrap().to_owned()
        };
        let cases: &[(&str, &[&str], String)] = &[
            ("a: <<secret:tricky>>\n", &["a"], TRICKY.to_owned()),
            (
                "a: \"pre <<secret:tricky>> post\"\n",
                &["a"],
                format!("pre {TRICKY} post"),
            ),
            (
                "a:\n  - b: |\n      <<secret:tricky>>\n",
                &["a", "0", "b"],
                format!("{TRICKY}\n"),
            ),
            ("<<secret:tricky>>: k\n", &[TRICKY], "k".to_owned()),
        ];
        for (body, path, want) in cases {
            let r = render_ok(&format!("x-deploy: {{}}\n{body}"), &Files::new());
            assert_eq!(at(&yaml(&r), path), *want, "{body}");
        }
    }

    #[test]
    fn tags_and_other_scalars_are_kept() {
        let text = "x-deploy: {}\nservices:\n  a:\n    environment: !override\n      \
                    A: <<gen:a>>\n    ports: !reset []\n    n: 5\n    f: 1.5\n    b: true\n    \
                    z: null\n    s: '0640'\n";
        let v = yaml(&render_ok(text, &Files::new()));
        let a = &v["services"]["a"];
        assert!(matches!(&a["environment"], Value::Tagged(env)
            if env.tag == "override" && env.value["A"] == "G-a"));
        assert!(matches!(&a["ports"], Value::Tagged(t) if t.tag == "reset"));
        assert_eq!(a["n"], 5);
        assert_eq!(a["f"], 1.5);
        assert_eq!(a["b"], true);
        assert!(a["z"].is_null());
        assert_eq!(a["s"], "0640");
    }

    #[test]
    fn every_unresolved_name_is_reported_once_sorted() {
        let text = "\
services:
  a:
    image: x
    environment:
      A: <<gen:bad-z>>
      <<secret:bad-key>>: v
      B: <<gen:ok>>
      C: <<set:the-set:hunter2>>
x-deploy:
  render:
    - {from: f.conf, to: /x/f.conf}
  pre:
    - {with: a, run: \"echo <<gen:bad-cmd>> <<gen:bad-z>>\"}
  post:
    - {exec: a, run: [\"x\", \"<<secret:bad-arg>>\"]}
";
        let extra = files(&[("f.conf", b"<<gen:bad-file>> <<gen:bad-a>>")]);
        let list = as_unresolved(render_with(text, &extra, &key(1)).unwrap_err()).unwrap();
        // (The helpers only match their own variant.)
        assert!(as_error(Failure::Unresolved(Vec::new())).is_none());
        let hidden = XDeployError::Hidden {
            path: COMPOSE.into(),
        };
        assert!(as_unresolved(Failure::XDeploy(hidden)).is_none());
        let names: Vec<_> = list.iter().map(|u| u.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "bad-a", "bad-arg", "bad-cmd", "bad-file", "bad-key", "bad-z", "the-set"
            ]
        );
        assert_eq!(list[6].error, "`the-set` is a set marker");
        let all = format!("{:?}", Failure::<String>::Unresolved(list));
        assert!(
            all.contains("Unresolved") && !all.contains("hunter2"),
            "{all}"
        );
    }

    #[test]
    fn malformed_markers() {
        // In the raw text: located as on the raw path.
        assert_eq!(
            fails("x-deploy: {}\na: <<gen:db\n", &Files::new()),
            format!("{COMPOSE}:2:4: unterminated marker (missing `>>`)")
        );
        // Only after YAML decoding (an escape): no raw-text location.
        let scalar = format!(
            "{COMPOSE}: a marker in a YAML string is malformed once YAML quoting and escapes \
             are applied (invalid character in secret name (allowed: A-Z a-z 0-9 . _ - and \
             single `/` separators)); write markers literally"
        );
        for text in [
            "x-deploy: {}\na: \"\\x3c<gen:bad name>>\"\n",
            "services:\n  a: {}\nx-deploy:\n  pre:\n    - {with: a, run: \"\\x3c<gen:x y>>\"}\n",
            "services:\n  a: {}\nx-deploy:\n  post:\n    - {exec: a, run: [\"\\x3c<gen:x y>>\"]}\n",
        ] {
            assert_eq!(fails(text, &Files::new()), scalar, "{text}");
        }
        // In a render: file: located in that file.
        let text = "x-deploy:\n  render:\n    - {from: f.conf, to: /x/f}\n";
        let extra = files(&[("f.conf", b"ok\nv=<<set:x:hunter2\\q>>\n")]);
        assert_eq!(
            fails(text, &extra),
            "stacks/web/f.conf:2:18: invalid escape in value (only `\\\\` and `\\>` are allowed)"
        );
    }

    #[test]
    fn keys_rendering_to_the_same_text_collide() {
        let collide = format!("{COMPOSE}: two keys of one mapping render to the same text");
        let text = "x-deploy: {}\na:\n  <<gen:x>>: 1\n  G-x: 2\n  later: <<gen:y>>\n";
        assert_eq!(fails(text, &Files::new()), collide);
        // Only the first error of a mapping is reported.
        let text = "x-deploy: {}\na:\n  <<gen:x>>: 1\n  G-x: 2\n  <<gen:y>>: 1\n  G-y: 2\n";
        assert_eq!(fails(text, &Files::new()), collide);
        let text = "x-deploy: {}\na:\n  b: \"\\x3c<gen:x y>>\"\n  <<gen:x>>: 1\n  G-x: 2\n";
        assert!(fails(text, &Files::new()).contains("malformed"));
        // After an error the rest isn't rendered, but every entry is kept
        // (to be wiped), even one that now equals a rendered key.
        let text = "x-deploy: {}\na:\n  <<gen:x>>: 1\n  b: \"\\x3c<gen:x y>>\"\n  G-x: 2\n";
        assert!(fails(text, &Files::new()).contains("malformed"));
    }

    #[test]
    fn unserializable_documents() {
        assert_eq!(
            fails("x-deploy: {}\n? {a: 1}\n: 1\n", &Files::new()),
            format!(
                "{COMPOSE}: could not serialize the rendered compose file (is a mapping used \
                 as a key?)"
            )
        );
        assert!(secret_utf8(Zeroizing::new(vec![b'a', 0xff])).is_none());
        let ok = secret_utf8(Zeroizing::new(b"ok".to_vec())).unwrap();
        assert_eq!(ok.expose(), "ok");
    }

    #[test]
    fn zeroizing_writer_grows_and_keeps_everything() {
        let mut w = ZeroizingWriter::default();
        let chunk = [7u8; 3000];
        for _ in 0..5 {
            assert_eq!(w.write(&chunk).unwrap(), chunk.len());
        }
        w.flush().unwrap();
        assert_eq!(w.0.len(), 15_000);
        assert!(w.0.capacity() >= 15_000);
        assert!(w.0.iter().all(|&b| b == 7));
    }

    #[test]
    fn wipe_empties_every_string() {
        let mut v: Value =
            serde_yaml_ng::from_str("k: v\nl: [a, !t b, 1, true, null]\nm: {x: y}\n").unwrap();
        wipe(&mut v);
        assert_eq!(v, Value::Mapping(Mapping::new()));
        let mut v: Value = serde_yaml_ng::from_str("[a, !t {b: c}]").unwrap();
        wipe(&mut v);
        assert_eq!(serde_yaml_ng::to_string(&v).unwrap(), "- ''\n- !t {}\n");
    }

    #[test]
    fn yaml_errors_show_the_location_only() {
        let at = |line, col| {
            format!(
                "{COMPOSE}:{line}:{col}: invalid YAML (lst does not show the parser's message: \
                 it can quote the file, and so a secret)"
            )
        };
        // The parser's own message would quote the duplicate key.
        let text = "x-deploy: {}\nservices:\n  hunter2: {}\n  hunter2: {}\n";
        assert_eq!(invalid_model(text, &Files::new()), at(3, 3));
        let text = "x-deploy: {}\na: <<set:x:hunter2>>: b\n";
        assert_eq!(invalid_model(text, &Files::new()), at(2, 21));
        assert_eq!(
            invalid_model("x-deploy: {}\n---\na: 1\n", &Files::new()),
            format!("{COMPOSE}: invalid YAML (more than one document, or too many aliases)")
        );
        assert_eq!(
            invalid_model("x-deploy: {}\na:\n  <<: 1\n", &Files::new()),
            format!("{COMPOSE}: invalid merge key: `<<` must be a mapping or a list of mappings")
        );
        assert_eq!(
            invalid_model("\"one\nx-deploy: two\"\n", &Files::new()),
            format!("{COMPOSE}: the document: must be a mapping")
        );
        assert_eq!(
            invalid_model("a: \"one\nx-deploy: two\"\n", &Files::new()),
            format!(
                "{COMPOSE}: a line starts with `x-deploy:`, but the document has no top-level \
                 x-deploy key"
            )
        );
        let hidden = XDeployError::Hidden {
            path: COMPOSE.into(),
        };
        assert_eq!(
            hidden.to_string(),
            format!(
                "{COMPOSE}: write the top-level x-deploy key at the start of a line \
                 (`x-deploy:`); lst decides which stacks use x-deploy from that line"
            )
        );
    }

    // -- the model ------------------------------------------------------------

    const SERVICES: &str = "services:\n  mosquitto: {image: eclipse-mosquitto}\n  \
                            mongo: {image: mongo}\n";

    /// `SERVICES` plus `x-deploy:` with `section` (indented by the caller).
    fn stack(section: &str) -> String {
        format!("{SERVICES}x-deploy:\n{section}")
    }

    /// The error for `section`, which must be the same from `check`.
    #[track_caller]
    fn model_err(section: &str) -> String {
        let msg = invalid_model(&stack(section), &conf());
        msg.strip_prefix(&format!("{COMPOSE}: "))
            .unwrap()
            .to_owned()
    }

    #[test]
    fn a_full_model() {
        let text = stack(
            "  render:
    - from: ./config//app.conf
      to: /srv//mosquitto/./config/app.conf
      mode: \"0640\"
    - {from: config/other.conf, to: /srv/other, mode: '444'}
    - {from: config/other.conf, to: /srv/default}
  pre:
    - with: mosquitto
      run: mosquitto_passwd -b -c /c/passwd z2m <<gen:shared/mqtt>>
  post:
    - exec: mongo
      run: [mongosh, --eval, 'createUser(\"a\", \"<<gen:mongo-a>>\")']
      when: on-change
    - {exec: mongo, run: echo hi, when: always}
",
        );
        let model = check(STACK, &text, &with_compose(&text, &conf())).unwrap();
        assert_eq!(
            model.render,
            [
                RenderFile {
                    from: "config/app.conf".into(),
                    to: "/srv/mosquitto/config/app.conf".into(),
                    mode: 0o640,
                },
                RenderFile {
                    from: "config/other.conf".into(),
                    to: "/srv/other".into(),
                    mode: 0o444,
                },
                RenderFile {
                    from: "config/other.conf".into(),
                    to: "/srv/default".into(),
                    mode: 0o600,
                },
            ]
        );
        assert_eq!(model.pre.len(), 1);
        let pre = &model.pre[0];
        assert_eq!(
            (pre.service.as_str(), pre.when),
            ("mosquitto", When::Always)
        );
        // The model holds the raw command; rendering substitutes it.
        assert!(matches!(&pre.run, Run::Shell(c)
            if c.expose() == "mosquitto_passwd -b -c /c/passwd z2m <<gen:shared/mqtt>>"));
        let post = &model.post[0];
        assert_eq!(
            (post.service.as_str(), post.when),
            ("mongo", When::OnChange)
        );
        assert_eq!(
            exec(&post.run).unwrap(),
            [
                "mongosh",
                "--eval",
                "createUser(\"a\", \"<<gen:mongo-a>>\")"
            ]
        );
        assert_eq!(model.post[1].when, When::Always);
        let dbg = format!("{model:?}");
        assert!(
            !dbg.contains("mosquitto_passwd") && !dbg.contains("createUser"),
            "{dbg}"
        );

        let r = render_ok(&text, &conf());
        assert_eq!(
            shell(&r.pre[0].run).unwrap(),
            "mosquitto_passwd -b -c /c/passwd z2m G-shared/mqtt"
        );
        assert_eq!(
            exec(&r.post[0].run).unwrap()[2],
            "createUser(\"a\", \"G-mongo-a\")"
        );
        assert!(shell(&r.post[0].run).is_none() && exec(&r.pre[0].run).is_none());
        assert_eq!(
            (r.post[0].service.as_str(), r.post[0].when),
            ("mongo", When::OnChange)
        );
        assert_eq!(r.files.len(), 3);
        assert_eq!(r.files[1].mode, 0o444);

        // Empty sections are fine.
        for section in ["  {}\n", "  render: []\n  pre: []\n  post: []\n"] {
            let text = stack(section);
            let m = check(STACK, &text, &with_compose(&text, &Files::new())).unwrap();
            assert!(m.render.is_empty() && m.pre.is_empty() && m.post.is_empty());
        }
        assert_eq!(When::OnChange.as_str(), "on-change");
        assert_eq!(Phase::Post.as_str(), "post");
    }

    #[test]
    fn section_and_entry_shapes() {
        let cases: &[(&str, &str)] = &[
            (
                "  1\n",
                "x-deploy: must be a mapping with render, pre and/or post",
            ),
            (
                "  null\n",
                "x-deploy: must be a mapping with render, pre and/or post",
            ),
            (
                "  renderr: []\n",
                "x-deploy: unknown key (allowed: render, pre, post)",
            ),
            (
                "  1: x\n",
                "x-deploy: unknown key (allowed: render, pre, post)",
            ),
            ("  render: {}\n", "x-deploy.render: must be a list"),
            ("  pre: x\n", "x-deploy.pre: must be a list"),
            ("  post: ~\n", "x-deploy.post: must be a list"),
            (
                "  render: [x]\n",
                "x-deploy.render[0]: must be a mapping with from, to and mode",
            ),
            (
                "  pre: [[]]\n",
                "x-deploy.pre[0]: must be a mapping with with, run and when",
            ),
            (
                "  post: [1]\n",
                "x-deploy.post[0]: must be a mapping with exec, run and when",
            ),
            (
                "  render: [{from: config/app.conf, to: /a, owner: x}]\n",
                "x-deploy.render[0]: unknown key (allowed: from, to, mode)",
            ),
            (
                "  pre: [{exec: mongo, run: x}]\n",
                "x-deploy.pre[0]: unknown key (allowed: with, run, when)",
            ),
            (
                "  post: [{with: mongo, run: x}]\n",
                "x-deploy.post[0]: unknown key (allowed: exec, run, when)",
            ),
        ];
        for (section, want) in cases {
            assert_eq!(model_err(section), *want, "{section}");
        }
    }

    #[test]
    fn render_entry_rules() {
        let entry = |fields: &str| {
            format!("  render:\n    - {{to: /ok, from: config/app.conf}}\n    - {{{fields}}}\n")
        };
        let cases: &[(&str, &str)] = &[
            ("to: /x", "x-deploy.render[1].from: is missing"),
            (
                "from: 5, to: /x",
                "x-deploy.render[1].from: must be a string",
            ),
            (
                "from: '<<gen:x>>', to: /x",
                "x-deploy.render[1].from: must not contain markers or NUL characters (markers \
                 are only rendered in run)",
            ),
            (
                "from: \"a\\0b\", to: /x",
                "x-deploy.render[1].from: must not contain markers or NUL characters (markers \
                 are only rendered in run)",
            ),
            (
                "from: /etc/passwd, to: /x",
                "x-deploy.render[1].from: must be relative to the stack directory, not absolute",
            ),
            (
                "from: config/../../x, to: /x",
                "x-deploy.render[1].from: must stay inside the stack directory (no `..`)",
            ),
            (
                "from: ./, to: /x",
                "x-deploy.render[1].from: must name a file",
            ),
            (
                "from: '', to: /x",
                "x-deploy.render[1].from: must name a file",
            ),
            (
                "from: config/missing.conf, to: /x",
                "x-deploy.render[1].from: no such file in stacks/web/ (it must be a regular \
                 file that git would commit: not gitignored, not a symlink)",
            ),
            (
                "from: config, to: /x",
                "x-deploy.render[1].from: no such file in stacks/web/ (it must be a regular \
                 file that git would commit: not gitignored, not a symlink)",
            ),
            (
                "from: bin.dat, to: /x",
                "x-deploy.render[1].from: is not UTF-8 text; lst only renders text files",
            ),
            ("from: config/app.conf", "x-deploy.render[1].to: is missing"),
            (
                "from: config/app.conf, to: [x]",
                "x-deploy.render[1].to: must be a string",
            ),
            (
                "from: config/app.conf, to: srv/x",
                "x-deploy.render[1].to: must be an absolute path",
            ),
            (
                "from: config/app.conf, to: /srv/../etc/x",
                "x-deploy.render[1].to: must not contain `..`",
            ),
            (
                "from: config/app.conf, to: /srv/x/",
                "x-deploy.render[1].to: must name a file, not end with `/`",
            ),
            (
                "from: config/app.conf, to: /",
                "x-deploy.render[1].to: must name a file",
            ),
            (
                "from: config/app.conf, to: /.",
                "x-deploy.render[1].to: must name a file",
            ),
            (
                "from: config/app.conf, to: '/srv/<<gen:x>>'",
                "x-deploy.render[1].to: must not contain markers or NUL characters (markers are \
                 only rendered in run)",
            ),
            (
                "from: config/app.conf, to: //ok",
                "x-deploy.render[1].to: same target as x-deploy.render[0].to",
            ),
        ];
        for (fields, want) in cases {
            assert_eq!(model_err(&entry(fields)), *want, "{fields}");
        }
    }

    #[test]
    fn modes() {
        let with_mode = |mode: &str| {
            entry_mode(&format!(
                "  render:\n    - {{from: config/app.conf, to: /x, mode: {mode}}}\n"
            ))
        };
        fn entry_mode(section: &str) -> Result<u32, String> {
            let text = stack(section);
            match check(STACK, &text, &with_compose(&text, &conf())) {
                Ok(m) => Ok(m.render[0].mode),
                Err(e) => Err(e.to_string()),
            }
        }
        for (mode, want) in [
            ("'0640'", 0o640),
            ("0640", 0o640), // plain 0640 is a string to the YAML crate
            ("\"640\"", 0o640),
            ("'0777'", 0o777),
            ("'000'", 0),
            ("'0600'", 0o600),
        ] {
            assert_eq!(with_mode(mode), Ok(want), "{mode}");
        }
        let at = format!("{COMPOSE}: x-deploy.render[0].mode: ");
        for (mode, want) in [
            ("640", "must be a quoted octal string such as \"0640\""),
            ("0o640", "must be a quoted octal string such as \"0640\""),
            ("[1]", "must be a quoted octal string such as \"0640\""),
            ("'0o640'", "must be an octal string such as \"0640\""),
            ("'64'", "must be an octal string such as \"0640\""),
            ("'06400'", "must be an octal string such as \"0640\""),
            ("'0680'", "must be an octal string such as \"0640\""),
            ("''", "must be an octal string such as \"0640\""),
            (
                "'1777'",
                "must be at most \"0777\" (setuid, setgid and sticky bits are not supported)",
            ),
            (
                "'4755'",
                "must be at most \"0777\" (setuid, setgid and sticky bits are not supported)",
            ),
        ] {
            assert_eq!(with_mode(mode), Err(format!("{at}{want}")), "{mode}");
        }
    }

    #[test]
    fn step_rules() {
        let cases: &[(&str, &str)] = &[
            ("  pre: [{run: x}]\n", "x-deploy.pre[0].with: is missing"),
            ("  post: [{run: x}]\n", "x-deploy.post[0].exec: is missing"),
            (
                "  pre: [{with: 1, run: x}]\n",
                "x-deploy.pre[0].with: must be a string",
            ),
            (
                "  pre: [{with: nope, run: x}]\n",
                "x-deploy.pre[0].with: no service with that name under services:",
            ),
            (
                "  post: [{exec: mongo, run: x}, {exec: Mongo, run: x}]\n",
                "x-deploy.post[1].exec: no service with that name under services:",
            ),
            (
                "  pre: [{with: '<<gen:mongo>>', run: x}]\n",
                "x-deploy.pre[0].with: must not contain markers or NUL characters (markers are \
                 only rendered in run)",
            ),
            (
                "  pre: [{with: mongo}]\n",
                "x-deploy.pre[0].run: is missing",
            ),
            (
                "  pre: [{with: mongo, run: ''}]\n",
                "x-deploy.pre[0].run: must not be empty",
            ),
            (
                "  pre: [{with: mongo, run: '  '}]\n",
                "x-deploy.pre[0].run: must not be empty",
            ),
            (
                "  pre: [{with: mongo, run: []}]\n",
                "x-deploy.pre[0].run: must not be an empty list",
            ),
            (
                "  post: [{exec: mongo, run: [sleep, 5]}]\n",
                "x-deploy.post[0].run[1]: must be a string (quote numbers and booleans)",
            ),
            (
                "  post: [{exec: mongo, run: {a: b}}]\n",
                "x-deploy.post[0].run: must be a string (run with sh -c) or a list of strings \
                 (exec form)",
            ),
            (
                "  post: [{exec: mongo, run: 5}]\n",
                "x-deploy.post[0].run: must be a string (run with sh -c) or a list of strings \
                 (exec form)",
            ),
            (
                "  pre: [{with: mongo, run: x, when: sometimes}]\n",
                "x-deploy.pre[0].when: must be always or on-change",
            ),
            (
                "  pre: [{with: mongo, run: x, when: true}]\n",
                "x-deploy.pre[0].when: must be always or on-change",
            ),
        ];
        for (section, want) in cases {
            assert_eq!(model_err(section), *want, "{section}");
        }
        // Without services: no service to run a step with.
        let text = "x-deploy:\n  pre: [{with: a, run: x}]\n";
        assert_eq!(
            invalid_model(text, &Files::new()),
            format!("{COMPOSE}: x-deploy.pre[0].with: no service with that name under services:")
        );
        let text = "services: ~\nx-deploy:\n  pre: [{with: a, run: x}]\n";
        assert!(invalid_model(text, &Files::new()).contains("no service with that name"));
    }

    #[test]
    fn services_rules() {
        let cases: &[(&str, &str)] = &[
            ("services: []\n", "services: must be a mapping"),
            (
                "services:\n  1: {}\n",
                "services: service names must be strings",
            ),
            (
                "services:\n  <<gen:hunter2>>: {}\n",
                "services: a service name contains a marker; markers are not allowed in service \
                 names",
            ),
            (
                "services:\n  a:\n    labels: {lst.render-hash: x}\n",
                "services.a.labels: lst.render-hash is set by lst; remove it",
            ),
            (
                "services:\n  a:\n    labels: [a=b, lst.render-hash=x]\n",
                "services.a.labels: lst.render-hash is set by lst; remove it",
            ),
            (
                "services:\n  a:\n    labels: [lst.render-hash]\n",
                "services.a.labels: lst.render-hash is set by lst; remove it",
            ),
        ];
        for (services, want) in cases {
            let text = format!("x-deploy: {{}}\n{services}");
            assert_eq!(
                invalid_model(&text, &Files::new()),
                format!("{COMPOSE}: {want}"),
                "{services}"
            );
        }
        // Similar labels are fine, also on services with no inputs.
        let text = "x-deploy: {}\nservices:\n  a:\n    labels: [lst.render-hashes=1, 5, x]\n  \
                    b:\n    labels: {lst.render-hash.x: 1}\n  c:\n    labels: x\n  d: ~\n";
        check(STACK, text, &with_compose(text, &Files::new())).unwrap();
        render_ok(text, &Files::new());
        assert_eq!(normalize_from("./a//b/./c"), Some("a/b/c".into()));
        assert_eq!(normalize_from("../a"), None);
    }

    #[test]
    fn no_secret_in_any_model_error() {
        // `fails` asserts it for every case above; this one has a set value
        // next to each kind of field.
        for section in [
            "  pre: [{with: '<<set:x:hunter2>>', run: x}]\n",
            "  render: [{from: '<<set:x:hunter2>>', to: /x}]\n",
            "  render: [{from: config/app.conf, to: '/<<set:x:hunter2>>'}]\n",
            "  render: [{from: config/app.conf, to: /x, mode: '<<set:x:hunter2>>'}]\n",
            "  post: [{exec: mongo, run: '<<set:x:hunter2>>', when: '<<set:y:hunter2>>'}]\n",
            "  <<set:x:hunter2>>: 1\n",
        ] {
            model_err(section);
        }
    }

    // -- mounts, labels and hashes --------------------------------------------

    #[test]
    fn mount_matching() {
        let file = Path::new("/srv/app/config/app.conf");
        let short = |s: &str| mounts(&Value::String(s.into()), file);
        let long = |y: &str| mounts(&serde_yaml_ng::from_str(y).unwrap(), file);
        for yes in [
            "/srv/app/config/app.conf:/etc/app.conf",
            "/srv/app/config/app.conf:/etc/app.conf:ro",
            "/srv/app/config:/config",
            "/srv/app/config/:/config:rw,z",
            "/srv//app/./config:/config",
            "/srv:/srv",
            "/:/host",
        ] {
            assert!(short(yes), "{yes}");
        }
        for no in [
            "/srv/app/conf:/config",         // a sibling, not a parent
            "/srv/app/config/app.conf.d:/x", // a longer name
            "/srv/app/config/app.conf/x:/x", // below the file
            "/srv/apple:/x",
            "data:/srv/app/config", // named volume
            "./config:/config",     // relative
            "config:/config",
            "~/app/config:/config",
            "${APPDATA}/app/config:/config", // interpolated
            "/srv/$X/config:/config",
            "/srv/x/../app/config:/config", // `..`: not compared
            "/srv/app/config",              // anonymous volume (container path)
        ] {
            assert!(!short(no), "{no}");
        }
        assert!(long("{type: bind, source: /srv/app/config, target: /c}"));
        assert!(long(
            "{type: bind, source: /srv/app/config/app.conf, target: /c, read_only: true}"
        ));
        assert!(!long("{type: volume, source: /srv/app/config, target: /c}"));
        assert!(!long("{source: /srv/app/config, target: /c}"));
        assert!(!long("{type: bind, target: /c}"));
        assert!(!long("{type: [bind], source: /srv/app/config}"));
        assert!(!long("{type: bind, source: ./config, target: /c}"));
        assert!(!long("{type: bind, source: [x], target: /c}"));
        assert!(!long("5"));
    }

    /// Two services mounting the rendered file in different ways, one with
    /// steps only, and one without inputs.
    const LABELLED: &str = "\
x-base: &base
  volumes:
    - /srv/app:/data
services:
  app:
    <<: *base
    image: example/app
    labels:
      keep: me
  sidecar:
    image: example/sidecar
    volumes:
      - data:/var/lib/x
      - type: bind
        source: /srv/app/app.conf
        target: /etc/app.conf
    labels: [a=b]
  worker:
    image: example/worker
  idle:
    image: example/idle
    volumes: [/srv/other:/x]
    labels: [a=b]
x-deploy:
  render:
    - {from: config/app.conf, to: /srv/app/app.conf}
  pre:
    - {with: worker, run: \"echo <<gen:w>>\"}
";

    #[test]
    fn labels_go_to_services_with_inputs_only() {
        let r = render_ok(LABELLED, &conf());
        let v = yaml(&r);
        let s = &v["services"];
        let label = |svc: &str| r.hashes[svc].clone();
        assert_eq!(
            r.hashes.keys().collect::<Vec<_>>(),
            ["app", "sidecar", "worker"]
        );
        // Map form: added to the existing labels (also when they come from
        // a merge key).
        assert_eq!(s["app"]["labels"]["keep"], "me");
        assert_eq!(s["app"]["labels"][HASH_LABEL], label("app"));
        // List form: a `key=value` item.
        assert_eq!(s["sidecar"]["labels"][0], "a=b");
        assert_eq!(
            s["sidecar"]["labels"][1],
            format!("{HASH_LABEL}={}", label("sidecar"))
        );
        // No labels yet: a new mapping.
        assert_eq!(s["worker"]["labels"][HASH_LABEL], label("worker"));
        // No inputs: untouched.
        assert_eq!(
            s["idle"]["labels"],
            serde_yaml_ng::from_str::<Value>("[a=b]").unwrap()
        );
        // Mounting the same file and no steps: the same hash.
        assert_eq!(label("app"), label("sidecar"));
        assert_ne!(label("app"), label("worker"));
        assert!(r.hashes.values().all(|h| h.len() == 64));
        // labels: null counts as none.
        let text = LABELLED.replace("  worker:\n", "  worker:\n    labels: ~\n");
        let v = yaml(&render_ok(&text, &conf()));
        assert_eq!(
            v["services"]["worker"]["labels"][HASH_LABEL],
            label("worker")
        );
    }

    #[test]
    fn labels_that_cant_take_the_hash() {
        let text = LABELLED.replace("    image: example/worker\n", "    labels: x\n");
        assert_eq!(
            fails(&text, &conf()),
            format!("{COMPOSE}: services.worker.labels: must be a mapping or a list")
        );
        let text = LABELLED.replace("  worker:\n    image: example/worker\n", "  worker: ~\n");
        assert_eq!(
            fails(&text, &conf()),
            format!("{COMPOSE}: services.worker: must be a mapping")
        );
    }

    #[test]
    fn hashes_follow_the_inputs() {
        let hashes =
            |text: &str, extra: &Files, k: u8| render_with(text, extra, &key(k)).unwrap().hashes;
        let base = hashes(LABELLED, &conf(), 1);
        assert_eq!(hashes(LABELLED, &conf(), 1), base);
        // Another seed: every hash changes.
        let other = hashes(LABELLED, &conf(), 2);
        assert!(base.iter().all(|(s, h)| other[s] != *h));

        // The file's rendered contents.
        let changed = files(&[("config/app.conf", b"user=<<gen:user>>\npass: changed\n")]);
        let h = hashes(LABELLED, &changed, 1);
        assert_ne!(h["app"], base["app"]);
        assert_eq!(h["worker"], base["worker"]);
        // The command, its `when`, its phase.
        for text in [
            LABELLED.replace("echo <<gen:w>>", "echo  <<gen:w>>"),
            LABELLED.replace("echo <<gen:w>>\"}", "echo <<gen:w>>\", when: on-change}"),
            LABELLED.replace(
                "  pre:\n    - {with: worker",
                "  post:\n    - {exec: worker",
            ),
            LABELLED.replace("\"echo <<gen:w>>\"", "[echo, \"<<gen:w>>\"]"),
        ] {
            let h = hashes(&text, &conf(), 1);
            assert_ne!(h["worker"], base["worker"], "{text}");
            assert_eq!(h["app"], base["app"]);
        }
        // Only the rendered value counts, not how it was written.
        let text = LABELLED.replace("echo <<gen:w>>", "echo G-w");
        assert_eq!(hashes(&text, &conf(), 1)["worker"], base["worker"]);
        // A mode change alone doesn't (the design hashes contents and
        // commands).
        let text = LABELLED.replace(
            "to: /srv/app/app.conf}",
            "to: /srv/app/app.conf, mode: '0644'}",
        );
        assert_eq!(hashes(&text, &conf(), 1), base);
        // Order of render: entries and volumes doesn't matter.
        let two = LABELLED.replace(
            "  render:\n    - {from: config/app.conf, to: /srv/app/app.conf}\n",
            "  render:\n    - {from: config/app.conf, to: /srv/app/app.conf}\n    - {from: \
             config/other.conf, to: /srv/app/b.conf}\n",
        );
        let swapped = LABELLED.replace(
            "  render:\n    - {from: config/app.conf, to: /srv/app/app.conf}\n",
            "  render:\n    - {from: config/other.conf, to: /srv/app/b.conf}\n    - {from: \
             config/app.conf, to: /srv/app/app.conf}\n",
        );
        let h2 = hashes(&two, &conf(), 1);
        assert_ne!(h2["app"], base["app"]);
        assert_eq!(hashes(&swapped, &conf(), 1), h2);
        // The second file is only under /srv/app, not app.conf itself.
        assert_eq!(h2["sidecar"], base["sidecar"]);
        // The order of steps does.
        let steps = LABELLED.replace(
            "    - {with: worker, run: \"echo <<gen:w>>\"}\n",
            "    - {with: worker, run: a}\n    - {with: worker, run: b}\n",
        );
        let reversed = LABELLED.replace(
            "    - {with: worker, run: \"echo <<gen:w>>\"}\n",
            "    - {with: worker, run: b}\n    - {with: worker, run: a}\n",
        );
        assert_ne!(
            hashes(&steps, &conf(), 1)["worker"],
            hashes(&reversed, &conf(), 1)["worker"]
        );
    }

    #[test]
    fn service_hash_encoding_is_unambiguous() {
        let k = key(1);
        let shell = |c: &str| Step {
            service: "s".into(),
            run: Run::Shell(SecretString::new(c.into())),
            when: When::Always,
        };
        let exec = |args: &[&str]| Step {
            service: "s".into(),
            run: Run::Exec(
                args.iter()
                    .map(|a| SecretString::new((*a).into()))
                    .collect(),
            ),
            when: When::Always,
        };
        let (a, b) = (Path::new("/a"), Path::new("/b"));
        let h = |files: &[(&Path, &[u8])], steps: &[(Phase, &Step)]| service_hash(&k, files, steps);
        // Files are sorted; steps are not.
        assert_eq!(
            h(&[(a, b"1"), (b, b"2")], &[]),
            h(&[(b, b"2"), (a, b"1")], &[])
        );
        assert_ne!(
            h(&[(a, b"1"), (b, b"2")], &[]),
            h(&[(a, b"2"), (b, b"1")], &[])
        );
        let (x, y) = (shell("x"), shell("y"));
        assert_ne!(
            h(&[], &[(Phase::Pre, &x), (Phase::Pre, &y)]),
            h(&[], &[(Phase::Pre, &y), (Phase::Pre, &x)])
        );
        // Lengths are prefixed: moving bytes between fields changes it.
        assert_ne!(h(&[(a, b"bc")], &[]), h(&[(Path::new("/ab"), b"c")], &[]));
        assert_ne!(
            h(&[], &[(Phase::Post, &exec(&["a", "b"]))]),
            h(&[], &[(Phase::Post, &exec(&["ab"]))])
        );
        assert_ne!(
            h(&[], &[(Phase::Post, &exec(&["a b"]))]),
            h(&[], &[(Phase::Post, &shell("a b"))])
        );
        // Not the same as no inputs at all.
        assert_ne!(h(&[], &[]), h(&[(a, b"")], &[]));
    }
}
