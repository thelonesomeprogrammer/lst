//! The `lst` commands. `main.rs` only parses arguments, calls [`run`] and
//! maps the result to an exit code.
//!
//! Every command works on the git repository containing the current
//! directory. Output rules:
//! - stdout carries nothing but `lst render`'s rendered text;
//! - diagnostics go to stderr, prefixed `lst: `;
//! - no secret value and never the seed appear in any message: errors name
//!   secrets (`stack/name`) and files (`path:line:col`), nothing else.
//!
//! `.env` is only read or written after the gitignore guard has passed
//! (`git::ensure_env_ignored` for `init`, `git::require_env_ignored` for
//! everything else).

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use crate::crypto::{CryptoError, Seed};
use crate::envfile::{self, EnvError};
use crate::git::{self, ENV_FILE, GitError, IgnoreOutcome};
use crate::marker::{self, ParseError, ParseErrorKind};
use crate::render::{self, RenderError};
use crate::stack::{self, COMPOSE_FILE, STACKS_DIR, Stack, StackError};
use crate::store::{META, ResolveError, Store, StoreError, SyncReport};

/// The store directory, relative to the repository root.
pub const SEC_DIR: &str = ".sec";

const BACKUP_REMINDER: &str = "IMPORTANT: back up the seed now. Copy the LST_SEED line from .env \
     into your password manager: it is the only way to recover your generated secrets, and how \
     you set up another machine. (lst never prints the seed.)";

/// Lazy Secret Tool: fill secret markers in Docker Compose files.
#[derive(Debug, Parser)]
#[command(name = "lst", version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create the seed in .env (gitignored) and write .sec/meta.toml.
    ///
    /// On a second machine, put the seed from your password manager into
    /// .env as LST_SEED=… instead; `lst init` then only checks it.
    Init,
    /// Update .sec/ from the compose files in the working tree.
    ///
    /// Gives new <<gen:…>> names an id, marks names that are no longer used
    /// as orphans (never deletes them) and un-orphans names that come back.
    Sync,
    /// Print the resolved compose file of a stack to stdout.
    ///
    /// Read-only: never writes .sec/ or .env.
    Render {
        /// The stack: stacks/<STACK>/compose.yaml.
        stack: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error(transparent)]
    Git(#[from] GitError),
    #[error(transparent)]
    Stack(#[from] StackError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Env(#[from] EnvError),
    #[error("{}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(".env is not valid UTF-8")]
    EnvNotUtf8,
    #[error(
        "no .env file. In a new repository run `lst init`; on another machine put the seed \
         from your password manager into .env as LST_SEED=…"
    )]
    NoEnv,
    #[error(
        ".env has no LST_SEED line. In a new repository run `lst init`; on another machine \
         put the seed from your password manager into .env as LST_SEED=…"
    )]
    NoSeed,
    #[error(
        "this repo is already initialised; put the seed from your password manager into .env \
         as LST_SEED=… (lst will not create a new seed for an existing .sec/)"
    )]
    InitialisedWithoutSeed,
    #[error(
        ".sec/ exists but has no meta.toml; restore it (e.g. `git checkout -- .sec/meta.toml`) \
         instead of initialising again"
    )]
    SecWithoutMeta,
    #[error("could not create a seed: {0}")]
    Seed(CryptoError),
    #[error("{path}:{line}:{col}: {kind}")]
    Parse {
        path: String,
        line: usize,
        col: usize,
        kind: ParseErrorKind,
    },
    #[error("{path}: {source}")]
    Render {
        path: String,
        source: RenderError<ResolveError>,
    },
    #[error("could not write to stdout: {0}")]
    Stdout(io::Error),
}

fn io_err(path: &Path) -> impl FnOnce(io::Error) -> CliError + '_ {
    move |source| CliError::Io {
        path: path.to_owned(),
        source,
    }
}

/// Runs `cli` in the repository containing `cwd`. Only `render` writes to
/// `stdout`; diagnostics go to `stderr`.
pub fn run(
    cli: Cli,
    cwd: &Path,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<(), CliError> {
    let root = git::repo_root(cwd)?;
    match cli.command {
        Command::Init => init(&root, stderr),
        Command::Sync => sync(&root, stderr),
        Command::Render { stack } => render_stack(&root, &stack, stdout),
    }
}

/// Writes one diagnostic line. A failing stderr is not worth failing the
/// command over.
fn note(stderr: &mut dyn Write, msg: &str) {
    let _ = writeln!(stderr, "lst: {msg}");
}

// ---------------------------------------------------------------------------
// .env
// ---------------------------------------------------------------------------

/// The raw bytes of `.env` (zeroized on drop: they hold the seed), or `None`
/// if it doesn't exist.
fn read_env(path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, CliError> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_err(path)(e)),
    }
}

/// `.env` as text; a missing file reads as empty.
fn env_text(bytes: Option<&[u8]>) -> Result<&str, CliError> {
    match bytes {
        None => Ok(""),
        Some(b) => std::str::from_utf8(b).map_err(|_| CliError::EnvNotUtf8),
    }
}

/// Appends `suffix` to an existing `.env` (keeping its permissions), or
/// creates `.env` with mode 0600 holding just `suffix`.
fn write_env(path: &Path, exists: bool, suffix: &str) -> Result<(), CliError> {
    let mut opts = OpenOptions::new();
    if exists {
        opts.append(true);
    } else {
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
    }
    opts.open(path)
        .and_then(|mut f| {
            f.write_all(suffix.as_bytes())?;
            f.sync_all()
        })
        .map_err(io_err(path))
}

/// The seed from `.env`. The caller must have run the ignore guard.
fn read_seed(path: &Path) -> Result<Seed, CliError> {
    let Some(bytes) = read_env(path)? else {
        return Err(CliError::NoEnv);
    };
    envfile::parse_seed(env_text(Some(&bytes))?)?.ok_or(CliError::NoSeed)
}

/// The guards and checks every command but `init` starts with: `.env` is
/// ignored, holds a seed, `.sec/` exists and was made with that seed.
fn open_store(root: &Path) -> Result<(Seed, Store), CliError> {
    git::require_env_ignored(root)?;
    let seed = read_seed(&root.join(ENV_FILE))?;
    let store = Store::load(&root.join(SEC_DIR))?;
    store.verify_seed(&seed)?;
    Ok((seed, store))
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

/// `.sec/` as it exists: `None` if there is no `meta.toml` and nothing else
/// in `.sec/` either. Stack files without `meta.toml` are refused: a new
/// seed would silently give every existing id a different value.
fn existing_store(sec: &Path) -> Result<Option<Store>, CliError> {
    match Store::load(sec) {
        Ok(store) => Ok(Some(store)),
        Err(StoreError::NotInitialized { .. }) => {
            let has_entries = fs::read_dir(sec).is_ok_and(|mut e| e.next().is_some());
            if has_entries {
                Err(CliError::SecWithoutMeta)
            } else {
                Ok(None)
            }
        }
        Err(e) => Err(e.into()),
    }
}

fn init(root: &Path, stderr: &mut dyn Write) -> Result<(), CliError> {
    if git::ensure_env_ignored(root)? == IgnoreOutcome::Added {
        note(stderr, "added `/.env` to .gitignore");
    }
    let env_path = root.join(ENV_FILE);
    let sec = root.join(SEC_DIR);
    let env = read_env(&env_path)?;
    let text = env_text(env.as_deref().map(Vec::as_slice))?;
    let seed = envfile::parse_seed(text)?;

    match (existing_store(&sec)?, seed) {
        (Some(_), None) => Err(CliError::InitialisedWithoutSeed),
        (Some(store), Some(seed)) => {
            store.verify_seed(&seed)?;
            note(
                stderr,
                "already initialised (the seed in .env matches .sec/meta.toml)",
            );
            Ok(())
        }
        (None, Some(seed)) => {
            Store::init(&seed).save(&sec)?;
            note(
                stderr,
                &format!("wrote {SEC_DIR}/{META}.toml for the seed already in .env; commit it"),
            );
            note(stderr, BACKUP_REMINDER);
            Ok(())
        }
        (None, None) => {
            let seed = Seed::generate().map_err(CliError::Seed)?;
            let new = envfile::with_seed(text, &seed)?;
            // with_seed keeps `text` as a prefix; only the seed line is new.
            write_env(&env_path, env.is_some(), &new.expose()[text.len()..])?;
            Store::init(&seed).save(&sec)?;
            note(
                stderr,
                &format!(
                    "generated a new seed in .env and wrote {SEC_DIR}/{META}.toml; commit .sec/"
                ),
            );
            note(stderr, BACKUP_REMINDER);
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// sync and render
// ---------------------------------------------------------------------------

/// The compose file of `stack` (zeroized on drop: an uncommitted
/// `<<set:…>>` may hold a plaintext value) and its repo-relative path for
/// messages.
fn read_compose(stack: &Stack) -> Result<(String, Zeroizing<String>), CliError> {
    let path = format!("{STACKS_DIR}/{}/{COMPOSE_FILE}", stack.name);
    let text = fs::read_to_string(&stack.compose).map_err(io_err(Path::new(&path)))?;
    Ok((path, Zeroizing::new(text)))
}

fn parse_err(path: &str, text: &str, e: ParseError) -> CliError {
    let (line, col) = marker::line_col(text, e.pos);
    CliError::Parse {
        path: path.to_owned(),
        line,
        col,
        kind: e.kind,
    }
}

fn sync(root: &Path, stderr: &mut dyn Write) -> Result<(), CliError> {
    let (_seed, mut store) = open_store(root)?;
    let mut uses = BTreeMap::new();
    for s in stack::discover(root)? {
        let (path, text) = read_compose(&s)?;
        let markers = marker::parse(&text).map_err(|e| parse_err(&path, &text, e))?;
        uses.insert(s.name, markers.into_iter().map(|m| m.kind).collect());
    }
    let report = store.sync(&uses)?;
    store.save(&root.join(SEC_DIR))?;
    print_report(stderr, &report);
    Ok(())
}

/// One line per change, names only. Prints nothing for an empty report.
fn print_report(stderr: &mut dyn Write, r: &SyncReport) {
    for name in &r.added {
        note(stderr, &format!("new: {name}"));
    }
    for c in &r.format_changed {
        note(
            stderr,
            &format!(
                "format changed: {} ({} -> {}), so its value changes",
                c.name, c.from, c.to
            ),
        );
    }
    for name in &r.orphaned {
        note(
            stderr,
            &format!("orphaned: {name} (no longer used; kept in .sec/)"),
        );
    }
    for name in &r.unorphaned {
        note(stderr, &format!("in use again: {name}"));
    }
    for name in &r.unset {
        note(
            stderr,
            &format!("not set: {name} (render fails until it has a value)"),
        );
    }
}

fn render_stack(root: &Path, name: &str, stdout: &mut dyn Write) -> Result<(), CliError> {
    let (seed, store) = open_store(root)?;
    let s = stack::find(root, name)?;
    let (path, text) = read_compose(&s)?;
    let rendered =
        render::render(&text, |m| store.resolve(&seed, &s.name, m)).map_err(|e| match e {
            RenderError::Parse(p) => parse_err(&path, &text, p),
            source => CliError::Render {
                path: path.clone(),
                source,
            },
        })?;
    stdout
        .write_all(rendered.expose().as_bytes())
        .and_then(|()| stdout.flush())
        .map_err(CliError::Stdout)
}
