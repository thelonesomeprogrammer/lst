//! The `lst` commands. `main.rs` only parses arguments, calls [`run`] and
//! maps the result to an exit code.
//!
//! Every command works on the git repository containing the current
//! directory. Output rules:
//! - stdout carries nothing but `lst render`'s rendered text and `lst gc`'s
//!   list of orphans (`lst deploy` sends compose's own output to stderr
//!   too, see [`crate::deploy`]);
//! - diagnostics go to stderr, prefixed `lst: `;
//! - no secret value and never the seed appear in any message: errors name
//!   secrets (`stack/name`) and files (`path:line:col`), nothing else.
//!
//! `.env` is only read or written after the gitignore guard has passed
//! (`git::ensure_env_ignored` for `init`, `git::require_env_ignored` for
//! everything else).
//!
//! The seed comes from `.env` or the `LST_SEED` environment variable (CI),
//! see [`find_seed`]; lst never writes the variable's value anywhere, and
//! `lst init` refuses to run while it is set.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use crate::check::{self, Problem};
use crate::crypto::{self, CryptoError, Seed};
use crate::deploy::{self, DeployError, Phase, StepCommand, WriteOutcome};
use crate::envfile::{self, EnvError};
use crate::git::{self, ENV_FILE, GitError, IgnoreOutcome};
use crate::hook::{self, HookError, Role};
use crate::marker::MarkerKind;
use crate::render::{self, RenderError};
use crate::scan::{self, ScanError};
use crate::stack::{self, COMPOSE_FILE, STACKS_DIR, Stack, StackError};
use crate::store::{
    self, EntryKind, META, ResolveError, SHARED, StackFile, Store, StoreError, SyncReport,
};
use crate::xdeploy::{self, Detected, Failure, Rendered, When, XDeployError};

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
    /// Update .sec/ from the stack files in the working tree.
    ///
    /// Reads every file under stacks/<stack>/ that git would stage (not only
    /// compose.yaml; gitignored files and symlinks are skipped). Gives
    /// new <<gen:…>> names an id, marks names that are no longer used as
    /// orphans (never deletes them) and un-orphans names that come back.
    Sync,
    /// Rename a secret in .sec/, keeping its value.
    ///
    /// A generated secret keeps its id; a manual secret is re-encrypted under
    /// the new name. Does not edit your files: change the markers yourself.
    Rename {
        /// The current full name: <stack>/<name> or shared/<name>.
        from: String,
        /// The new name: a full name (<stack>/<name> or shared/<name>), or a
        /// name without `/` for the same stack (or shared) as FROM.
        to: String,
        /// Overwrite an existing entry of the new name (e.g. the fresh id a
        /// sync or commit just gave it).
        #[arg(long)]
        replace: bool,
    },
    /// Give a generated secret a new value (a fresh random id).
    ///
    /// Only for a <<gen:…>> secret in use; it keeps its format. (A manual
    /// secret gets a new value from <<set:name:VALUE>>.) Commit .sec/ and
    /// deploy the stacks that use it afterwards. An app that only reads the
    /// value on first start (e.g. a database's initial password) keeps the
    /// old one: change it inside the app too.
    Rotate {
        /// The full name: <stack>/<name> or shared/<name>.
        name: String,
    },
    /// List orphaned secrets (no marker uses them any more), or remove them.
    ///
    /// Without --remove, read-only: prints the full name of every orphan on
    /// stdout, one per line, sorted. With --remove, deletes every orphan
    /// from .sec/, or only the NAMEs given (each must be an orphan, otherwise
    /// nothing is removed). A removed generated secret that comes back gets
    /// a new id, so a new value. Refuses while .sec/ is not current for the
    /// working tree's orphans (run `lst sync` first).
    Gc {
        /// Delete the orphans (all of them, or only the NAMEs) from .sec/.
        #[arg(long)]
        remove: bool,
        /// Full names (<stack>/<name> or shared/<name>) of the orphans to
        /// remove; needs --remove.
        #[arg(value_name = "NAME", requires = "remove")]
        names: Vec<String>,
    },
    /// Print the resolved compose file of a stack to stdout.
    ///
    /// Read-only: never writes .sec/, .env or any x-deploy render: target.
    /// A stack with a top-level x-deploy key is rendered through YAML:
    /// x-deploy is removed and services with rendered inputs get an
    /// lst.render-hash label.
    Render {
        /// The stack: stacks/<STACK>/compose.yaml.
        stack: String,
        /// Print the rendered x-deploy render: file whose `from` is FROM
        /// (relative to stacks/<STACK>/) instead of the compose file.
        #[arg(long, value_name = "FROM")]
        file: Option<String>,
    },
    /// Check that the repository is ready to deploy, listing every problem.
    ///
    /// .sec/ is current for the working tree (`lst sync` would change
    /// nothing), no <<set:…>> is in the working tree or in any file
    /// committed in HEAD (a committed value must be rotated), and every
    /// <<secret:…>> has a value. With a seed (LST_SEED or .env) also: it is
    /// the seed of .sec/ and every marker resolves. Without one the check
    /// is structural only. Read-only; exits 1 if anything is wrong.
    Check,
    /// Deploy stacks: check, render, x-deploy steps, `docker compose up`.
    ///
    /// Give the stacks, --changed-since REV or --all (exactly one). Needs
    /// the seed (LST_SEED or .env). Runs the full `lst check` first and
    /// deploys nothing if it finds a problem. Then, per stack in sorted
    /// order, renders compose.yaml (as `lst render` does) and pipes it into
    /// `docker compose -p <stack> --project-directory stacks/<stack> -f -
    /// up -d --wait --remove-orphans`, run in the repository root. Stops at
    /// the first failure and says which stacks were deployed.
    ///
    /// For a stack with x-deploy, before `up`: reads the lst.render-hash of
    /// the existing containers of services with `when: on-change` steps,
    /// writes the changed render: files to their `to:` paths, and runs the
    /// pre steps (`docker compose run --rm --no-deps`); after `up`, runs
    /// the post steps (`docker compose exec`). An on-change step is skipped
    /// when its service's hash is unchanged. A failing pre step stops
    /// before `up` (files already written stay). Apart from render:
    /// targets, nothing is written; the compose file only goes through the
    /// pipe.
    ///
    /// With --dry-run, goes as far as it can without changing anything and
    /// prints the plan: it needs the seed, runs the full check, picks and
    /// renders the stacks (so every error a deploy would meet before
    /// running docker shows up), and compares each render: file with its
    /// target. It never runs docker, never writes a file, and never shows
    /// a secret value or a step's command (they contain secrets). Because
    /// docker isn't asked for the existing containers' lst.render-hash, it
    /// can't tell whether an on-change step would be skipped, and says so.
    #[command(group(
        clap::ArgGroup::new("target")
            .required(true)
            .args(["stacks", "changed_since", "all"])
    ))]
    Deploy {
        /// The stacks to deploy (stacks/<STACK>/compose.yaml).
        #[arg(value_name = "STACK")]
        stacks: Vec<String>,
        /// Deploy the stacks affected by the commits REV..HEAD instead: a
        /// change under stacks/<s>/ or in .sec/<s>.toml deploys <s>; a
        /// changed entry in .sec/shared.toml deploys the stacks using that
        /// name; a change in .sec/meta.toml deploys every stack. Deleted
        /// stacks are reported, not torn down.
        #[arg(long, value_name = "REV")]
        changed_since: Option<String>,
        /// Deploy every stack instead (every stacks/<STACK>/compose.yaml), in
        /// sorted order.
        #[arg(long)]
        all: bool,
        /// Only show what would be done: run nothing, write nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Install or run the pre-commit hook.
    Hook {
        #[command(subcommand)]
        action: HookAction,
    },
}

#[derive(Debug, Subcommand)]
pub enum HookAction {
    /// Install the pre-commit hook in this clone (`lst init` does it too).
    ///
    /// Goes where git looks for hooks (`git rev-parse --git-path hooks`, so
    /// core.hooksPath is respected). An existing pre-commit hook that isn't
    /// lst's is never replaced without --force.
    Install {
        /// Replace an existing pre-commit hook that isn't lst's.
        #[arg(long)]
        force: bool,
    },
    /// Run the pre-commit checks on the staged files (git runs this).
    ///
    /// Updates .sec/ from every staged stack file and stages it, stores
    /// <<set:…>> values and rewrites them to <<secret:…>> in the index and
    /// the working tree. Any problem exits non-zero, which blocks the commit.
    Run,
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
         from your password manager into .env as LST_SEED=… (in CI, set the LST_SEED \
         environment variable instead)"
    )]
    NoEnv,
    #[error(
        ".env has no LST_SEED line. In a new repository run `lst init`; on another machine \
         put the seed from your password manager into .env as LST_SEED=… (in CI, set the \
         LST_SEED environment variable instead)"
    )]
    NoSeed,
    #[error(
        "the LST_SEED environment variable is set but empty; set it to the seed (64 lowercase \
         hex characters) or unset it"
    )]
    EnvVarEmpty,
    #[error(
        "the LST_SEED environment variable is not 64 lowercase hex characters (no spaces, \
         quotes or trailing newline)"
    )]
    EnvVarInvalid,
    #[error(
        "LST_SEED and .env disagree: the LST_SEED environment variable and the LST_SEED line in \
         .env hold different seeds. Unset the variable or fix .env"
    )]
    SeedMismatch,
    #[error(
        "the LST_SEED environment variable is set: unset LST_SEED; init manages .env (it \
         creates the seed there, or checks the one you put there)"
    )]
    InitWithEnvVar,
    #[error(
        "check failed: {count} problem{}{}",
        if *count == 1 { "" } else { "s" },
        if *structural { " (structural only: no seed)" } else { "" }
    )]
    CheckFailed { count: usize, structural: bool },
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
    #[error(transparent)]
    Scan(#[from] ScanError),
    #[error(
        "{path}: <<set:{name}:…>> is stored by the pre-commit hook, not by `lst sync`: commit \
         the file, and the hook encrypts the value into .sec/ and rewrites the marker to \
         <<secret:{name}>>"
    )]
    SetInWorkingTree { path: String, name: String },
    #[error("{path}: {source}")]
    Render {
        path: String,
        source: RenderError<ResolveError>,
    },
    #[error(transparent)]
    XDeploy(#[from] XDeployError),
    #[error(
        "stack {stack:?} has no x-deploy render: entry with from: {file:?} (its entries: {})",
        list_or_none(known)
    )]
    UnknownRenderFile {
        stack: String,
        file: String,
        known: Vec<String>,
    },
    #[error("could not write to stdout: {0}")]
    Stdout(io::Error),
    #[error(transparent)]
    Hook(#[from] HookError),
    #[error(transparent)]
    Deploy(#[from] DeployError),
    #[error("{source}, so `docker compose up` did not run for this stack")]
    PreFailed { source: DeployError },
    #[error(
        "{source}; the stack is up (`docker compose up` succeeded), but its remaining post steps \
         did not run"
    )]
    PostFailed { source: DeployError },
    #[error(
        "{source} (deployed: {}; failed: {failed}; not attempted: {})",
        list_or_none(deployed),
        list_or_none(not_attempted)
    )]
    DeployFailed {
        failed: String,
        deployed: Vec<String>,
        not_attempted: Vec<String>,
        source: Box<CliError>,
    },
    #[error("{source} (dry run: stopped at stack {stack}; nothing was run or written)")]
    DryRunFailed {
        stack: String,
        source: Box<CliError>,
    },
    #[error(
        "--changed-since: unknown revision {rev:?} (not a commit in this repository). Is this a \
         shallow clone? Fetch more history (in Woodpecker: a larger `clone: depth`), or deploy \
         the stacks explicitly"
    )]
    UnknownDeployRev { rev: String },
    #[error("--changed-since {rev}: in that revision, {source}")]
    OldShared { rev: String, source: StoreError },
    #[error("--changed-since {rev}: in that revision, .sec/{SHARED}.toml is not valid UTF-8")]
    OldSharedNotUtf8 { rev: String },
    #[error(
        ".sec/ is not current for the working tree ({}: orphaned or used again since the last \
         sync); run `lst sync` first, so lst gc sees what is really unused",
        names.join(", ")
    )]
    GcStale { names: Vec<String> },
    #[error(
        "{path} already exists and is not lst's hook (or was changed); lst won't overwrite it. \
         Run `lst hook install --force` to replace it (move what it does elsewhere first if you \
         still need it)"
    )]
    ForeignHook { path: String },
}

fn io_err(path: &Path) -> impl FnOnce(io::Error) -> CliError + '_ {
    move |source| CliError::Io {
        path: path.to_owned(),
        source,
    }
}

/// The value of the `LST_SEED` environment variable, if it is set
/// (zeroized on drop). `main` reads the variable and passes it to [`run`],
/// so nothing below `run` looks at the process environment for it.
type EnvSeed<'a> = Option<&'a [u8]>;

/// Runs `cli` in the repository containing `cwd`. Only `render` and `gc`
/// write to `stdout`; diagnostics go to `stderr`.
///
/// `env_seed` is the value of the `LST_SEED` environment variable, if set
/// (`std::env::var_os("LST_SEED")`): commands that need the seed use it,
/// alongside `.env` (see [`find_seed`]). It is never written anywhere.
pub fn run(
    cli: Cli,
    cwd: &Path,
    env_seed: Option<OsString>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<(), CliError> {
    let env_seed = env_seed.map(|v| Zeroizing::new(v.into_encoded_bytes()));
    let env_seed: EnvSeed<'_> = env_seed.as_deref().map(Vec::as_slice);
    let root = git::repo_root(cwd)?;
    match cli.command {
        Command::Init if env_seed.is_some() => Err(CliError::InitWithEnvVar),
        Command::Init => init(&root, stderr),
        Command::Sync => sync(&root, env_seed, stderr),
        Command::Rename { from, to, replace } => {
            rename(&root, env_seed, &from, &to, replace, stderr)
        }
        Command::Rotate { name } => rotate(&root, env_seed, &name, stderr),
        Command::Gc { remove, names } => gc(&root, env_seed, remove, &names, stdout, stderr),
        Command::Render { stack, file } => {
            render_stack(&root, env_seed, &stack, file.as_deref(), stdout)
        }
        Command::Check => check(&root, env_seed, stderr),
        Command::Deploy {
            stacks,
            changed_since,
            all,
            dry_run,
        } => {
            let targets = match (changed_since, all) {
                (Some(rev), _) => Targets::ChangedSince(rev),
                (None, true) => Targets::All,
                (None, false) => Targets::Stacks(stacks),
            };
            let mode = if dry_run { Mode::DryRun } else { Mode::Deploy };
            deploy(&root, env_seed, targets, mode, stderr)
        }
        Command::Hook {
            action: HookAction::Install { force },
        } => hook_install(&root, force, stderr),
        Command::Hook {
            action: HookAction::Run,
        } => hook_run(&root, env_seed, stderr),
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

/// The seed in the `LST_SEED` environment variable: exactly 64 lowercase
/// hex characters, like the `.env` line. Errors never contain the value.
fn parse_env_seed(value: &[u8]) -> Result<Seed, CliError> {
    if value.is_empty() {
        return Err(CliError::EnvVarEmpty);
    }
    let text = std::str::from_utf8(value).map_err(|_| CliError::EnvVarInvalid)?;
    Seed::from_hex(text).map_err(|_| CliError::EnvVarInvalid)
}

/// What [`find_seed`] found.
pub(crate) struct SeedLookup {
    /// The seed, from `LST_SEED` or `.env`.
    pub seed: Option<Seed>,
    /// Whether `.env` exists (for the "no seed" message).
    pub env_file: bool,
}

/// The seed, from the `LST_SEED` environment variable (`env_seed`) and/or
/// `.env`. The ignore guard always runs first, so `.env` is only read once
/// it has passed (also when the variable is set and `.env` doesn't exist:
/// a fresh clone still has the committed `/.env` rule). If both hold a
/// seed they must be the same seed. `.env` is never written.
pub(crate) fn find_seed(root: &Path, env_seed: EnvSeed<'_>) -> Result<SeedLookup, CliError> {
    git::require_env_ignored(root)?;
    let from_var = env_seed.map(parse_env_seed).transpose()?;
    let bytes = read_env(&root.join(ENV_FILE))?;
    let from_file = match &bytes {
        Some(b) => envfile::parse_seed(env_text(Some(b))?)?,
        None => None,
    };
    let seed = match (from_var, from_file) {
        (Some(v), Some(f)) if v.as_bytes() != f.as_bytes() => return Err(CliError::SeedMismatch),
        (Some(v), _) => Some(v),
        (None, f) => f,
    };
    Ok(SeedLookup {
        seed,
        env_file: bytes.is_some(),
    })
}

/// The seed for commands that need one ([`find_seed`]); none is an error.
pub(crate) fn require_seed(root: &Path, env_seed: EnvSeed<'_>) -> Result<Seed, CliError> {
    match find_seed(root, env_seed)? {
        SeedLookup { seed: Some(s), .. } => Ok(s),
        SeedLookup { env_file: true, .. } => Err(CliError::NoSeed),
        SeedLookup {
            env_file: false, ..
        } => Err(CliError::NoEnv),
    }
}

/// The guards and checks every command but `init` starts with: `.env` is
/// ignored, there is a seed (`LST_SEED` or `.env`), `.sec/` exists and was
/// made with that seed.
fn open_store(root: &Path, env_seed: EnvSeed<'_>) -> Result<(Seed, Store), CliError> {
    let seed = require_seed(root, env_seed)?;
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

/// `lst init`: the seed and `.sec/`, then the pre-commit hook. The hook is
/// installed on every successful path, also "already initialised" (that is
/// how a fresh clone with the seed in `.env` gets it). A pre-commit hook
/// that isn't lst's is left alone with a warning: init has done its main
/// job, and replacing someone else's hook needs an explicit `--force`.
fn init(root: &Path, stderr: &mut dyn Write) -> Result<(), CliError> {
    init_store(root, stderr)?;
    match install_hook(root, false) {
        Ok((path, HookInstall::Installed { .. })) => {
            note(stderr, &format!("installed the pre-commit hook: {path}"));
        }
        Ok((_, HookInstall::AlreadyInstalled)) => {}
        Err(CliError::ForeignHook { path }) => note(
            stderr,
            &format!(
                "warning: {path} is not lst's pre-commit hook, so it was left alone. Until you \
                 run `lst hook install --force` (which replaces it), commits are not checked \
                 and <<set:…>> values are not kept out of them"
            ),
        ),
        Err(e) => return Err(e),
    }
    Ok(())
}

fn init_store(root: &Path, stderr: &mut dyn Write) -> Result<(), CliError> {
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
    let bytes = Zeroizing::new(fs::read(&stack.compose).map_err(io_err(Path::new(&path)))?);
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return Err(ScanError::ComposeNotUtf8 { path }.into());
    };
    let text = Zeroizing::new(text.to_owned());
    Ok((path, text))
}

/// The contents of a stack file (zeroized on drop: an uncommitted
/// `<<set:…>>` may hold a plaintext value).
type Contents = Zeroizing<Vec<u8>>;

/// Every file of every stack in the working tree that git would stage,
/// keyed by stack name (the scope of [`scan::collect`], the same files the
/// pre-commit hook sees once they are staged). Gitignored files (bind-mounted
/// data, say) are not read. Symlinks are skipped, not followed: git commits
/// them as links, so the hook never sees what they point to
/// ([`stack::discover`] already refused a symlinked `compose.yaml`).
/// Directories (an untracked nested repository) are skipped too.
fn read_stack_files(root: &Path) -> Result<scan::StackFiles<Contents>, CliError> {
    let mut out = BTreeMap::new();
    for s in stack::discover(root)? {
        let files = read_one_stack(root, &s)?;
        out.insert(s.name, files);
    }
    Ok(out)
}

/// The files of one stack, as [`read_stack_files`] reads them.
fn read_one_stack(root: &Path, s: &Stack) -> Result<Vec<(String, Contents)>, CliError> {
    let mut files = Vec::new();
    for path in git::worktree_files(root, &format!("{STACKS_DIR}/{}/", s.name))? {
        let full = root.join(&path);
        let meta = fs::symlink_metadata(&full).map_err(io_err(Path::new(&path)))?;
        if meta.is_file() {
            let bytes = fs::read(&full).map_err(io_err(Path::new(&path)))?;
            files.push((path, Zeroizing::new(bytes)));
        }
    }
    Ok(files)
}

fn sync(root: &Path, env_seed: EnvSeed<'_>, stderr: &mut dyn Write) -> Result<(), CliError> {
    let (_seed, mut store) = open_store(root, env_seed)?;
    let scan = scan::collect(&read_stack_files(root)?)?;
    if let Some(site) = scan.sets.into_iter().next() {
        return Err(CliError::SetInWorkingTree {
            path: site.path,
            name: site.name,
        });
    }
    let report = store.sync(&scan.uses)?;
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
    for (old, new) in &r.rename_candidates {
        note(
            stderr,
            &format!(
                "looks like a rename: run `lst rename {old} {new} --replace` to keep the old value"
            ),
        );
    }
}

/// `lst rename FROM TO [--replace]`. TO without `/` is a name in FROM's
/// file (its stack, or `shared`); with `/` it is a full name. A target
/// stack must exist (catches typos); the source stack may be gone (e.g.
/// after renaming the stack directory).
fn rename(
    root: &Path,
    env_seed: EnvSeed<'_>,
    from: &str,
    to: &str,
    replace: bool,
    stderr: &mut dyn Write,
) -> Result<(), CliError> {
    let (seed, mut store) = open_store(root, env_seed)?;
    let source = store::parse_full_name(from)?;
    let to = if to.contains('/') {
        to.to_owned()
    } else {
        format!("{}/{to}", source.file)
    };
    let target = store::parse_full_name(&to)?;
    if target.file != SHARED {
        stack::find(root, &target.file)?;
    }
    let done = store.rename(&seed, &source.full_name, &target.full_name, replace)?;
    store.save(&root.join(SEC_DIR))?;
    let how = match done.kind {
        EntryKind::Gen => "generated secret; same id, so the value is unchanged",
        EntryKind::Secret => "manual secret; re-encrypted under the new name",
    };
    note(
        stderr,
        &format!("renamed {} -> {} ({how})", done.from, done.to),
    );
    if done.replaced {
        note(
            stderr,
            &format!("replaced the previous entry of {}", done.to),
        );
    }
    note(
        stderr,
        "lst rename does not edit your files: change the markers to the new name if you \
         haven't yet, then commit .sec/",
    );
    Ok(())
}

/// `lst rotate NAME`: a fresh id for a generated secret in use (see
/// [`Store::rotate`]). The stacks named in the message are those whose
/// working-tree files use the name as `<<gen:…>>` (for `shared/…`, every
/// such stack).
fn rotate(
    root: &Path,
    env_seed: EnvSeed<'_>,
    name: &str,
    stderr: &mut dyn Write,
) -> Result<(), CliError> {
    let (_seed, mut store) = open_store(root, env_seed)?;
    let uses = scan::collect(&read_stack_files(root)?)?.uses;
    let done = store.rotate(name)?;
    store.save(&root.join(SEC_DIR))?;
    let users: Vec<&str> = uses
        .iter()
        .filter(|(stack, markers)| {
            markers.iter().any(|m| {
                matches!(m, MarkerKind::Gen { .. })
                    && store::scope(stack, m.name()).is_ok_and(|sc| sc.full_name == done.name)
            })
        })
        .map(|(stack, _)| stack.as_str())
        .collect();
    let stacks = if users.is_empty() {
        "the stacks that use it".to_owned()
    } else {
        users.join(", ")
    };
    note(
        stderr,
        &format!(
            "rotated {} (new id, same format {}, so a new value); commit .sec/, then deploy \
             {stacks}",
            done.name, done.format
        ),
    );
    note(
        stderr,
        "note: an app that only reads it on first start (e.g. a database's initial password) \
         keeps the old value; change it inside the app too",
    );
    Ok(())
}

/// `lst gc [--remove [NAME…]]` (clap makes NAME need `--remove`). Lists
/// the orphans on `stdout`, or removes them ([`Store::remove_orphans`]).
///
/// The orphan flags must be current for the working tree first (a dry-run
/// sync over the files `lst sync` reads orphans and un-orphans nothing):
/// otherwise a name whose marker came back since the last sync could be
/// deleted, and its next sync would give it a new value.
fn gc(
    root: &Path,
    env_seed: EnvSeed<'_>,
    remove: bool,
    names: &[String],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<(), CliError> {
    let (_seed, mut store) = open_store(root, env_seed)?;
    let uses = scan::collect(&read_stack_files(root)?)?.uses;
    let report = store.clone().sync(&hook::secret_uses(uses))?;
    let mut stale: Vec<String> = report
        .orphaned
        .into_iter()
        .chain(report.unorphaned)
        .collect();
    if !stale.is_empty() {
        stale.sort();
        return Err(CliError::GcStale { names: stale });
    }
    if !remove {
        let orphans: BTreeSet<String> = store.orphans().into_iter().map(|o| o.name).collect();
        if orphans.is_empty() {
            note(stderr, "no orphans");
        }
        for name in orphans {
            writeln!(stdout, "{name}").map_err(CliError::Stdout)?;
        }
        return stdout.flush().map_err(CliError::Stdout);
    }
    let removed = store.remove_orphans((!names.is_empty()).then_some(names))?;
    if removed.is_empty() {
        note(stderr, "no orphans");
        return Ok(());
    }
    store.save(&root.join(SEC_DIR))?;
    let removed: BTreeSet<String> = removed.into_iter().map(|o| o.name).collect();
    for name in &removed {
        note(stderr, &format!("removed {name}"));
    }
    note(stderr, "commit .sec/");
    Ok(())
}

/// `lst render STACK [--file FROM]`: the rendered compose file, or one
/// rendered `render:` file, on stdout. Writes no file.
fn render_stack(
    root: &Path,
    env_seed: EnvSeed<'_>,
    name: &str,
    file: Option<&str>,
    stdout: &mut dyn Write,
) -> Result<(), CliError> {
    let (seed, store) = open_store(root, env_seed)?;
    let s = stack::find(root, name)?;
    let rendered = render_full(root, &seed, &store, &s)?;
    let out = match file {
        None => &rendered.compose,
        Some(file) => {
            let from = xdeploy::normalize_from(file);
            let found = rendered
                .files
                .iter()
                .find(|f| Some(&f.from) == from.as_ref());
            match found {
                Some(f) => &f.contents,
                None => {
                    return Err(CliError::UnknownRenderFile {
                        stack: s.name,
                        file: file.to_owned(),
                        known: rendered.files.iter().map(|f| f.from.clone()).collect(),
                    });
                }
            }
        }
    };
    stdout
        .write_all(out.expose().as_bytes())
        .and_then(|()| stdout.flush())
        .map_err(CliError::Stdout)
}

/// Everything rendered for stack `s`: its compose file (what `lst render`
/// prints and `lst deploy` pipes into compose, the same bytes) and, for a
/// stack with `x-deploy`, its `render:` files, steps and render hashes.
///
/// A stack without `x-deploy` takes the raw-text path of M1–M3
/// ([`render::render`], byte for byte; only `compose` is set). One with it
/// takes the YAML path ([`xdeploy::render`]), with the stack's files as
/// `lst sync` reads them. Writes nothing. For `lst deploy`'s x-deploy steps.
pub(crate) fn render_full(
    root: &Path,
    seed: &Seed,
    store: &Store,
    s: &Stack,
) -> Result<Rendered, CliError> {
    let (path, text) = read_compose(s)?;
    let resolve = |m: &MarkerKind| store.resolve(seed, &s.name, m);
    match xdeploy::detect(&text) {
        Detected::Raw => {
            let compose = render::render_compose(&text, resolve).map_err(|e| match e {
                RenderError::Parse(p) => scan::parse_error(&path, &text, p).into(),
                source => CliError::Render {
                    path: path.clone(),
                    source,
                },
            })?;
            Ok(Rendered {
                compose,
                ..Rendered::default()
            })
        }
        Detected::Hidden => Err(XDeployError::Hidden { path }.into()),
        Detected::XDeploy => {
            let files = read_one_stack(root, s)?;
            let key = crypto::render_hash_key(seed);
            xdeploy::render(&s.name, &text, &files, &key, resolve).map_err(|e| match e {
                Failure::XDeploy(e) => e.into(),
                Failure::Unresolved(list) => CliError::Render {
                    path,
                    source: RenderError::Unresolved(list),
                },
            })
        }
    }
}

// ---------------------------------------------------------------------------
// check
// ---------------------------------------------------------------------------

/// `lst check`: [`check_repo`] with the seed from `LST_SEED` / `.env`, if
/// there is one, and a success line.
fn check(root: &Path, env_seed: EnvSeed<'_>, stderr: &mut dyn Write) -> Result<(), CliError> {
    let seed = find_seed(root, env_seed)?.seed;
    check_repo(root, seed.as_ref(), stderr)?;
    let msg = match seed {
        Some(_) => "check ok",
        None => "check ok (structural only: no seed)",
    };
    note(stderr, msg);
    Ok(())
}

/// What [`check_repo`] read and found consistent, for `lst deploy` to go
/// on with (rather than read it all again).
struct Checked {
    /// `.sec/`; with a seed, one made with that seed.
    store: Store,
    /// Every stack file in the working tree ([`read_stack_files`]), keyed
    /// by stack: every existing stack is a key.
    files: scan::StackFiles<Contents>,
}

/// Every problem `lst check` looks for (see [`crate::check`]), each
/// printed as one line on `stderr`; `Err(CheckFailed)` if there is any.
/// Prints nothing else on success, so `lst deploy` can run it first. With
/// `seed` `None` only the structural checks run.
///
/// Problems are collected, not returned at the first; hard errors (an
/// unreadable or invalid `.sec/`, a malformed marker, a failing git) still
/// stop it, because nothing can be decided then.
fn check_repo(
    root: &Path,
    seed: Option<&Seed>,
    stderr: &mut dyn Write,
) -> Result<Checked, CliError> {
    let (meta, sec_files) = Store::read_files(&root.join(SEC_DIR))?;
    let store = Store::from_files(&meta, &sec_files)?;
    let loaded = check::loaded_files(&meta, &sec_files);
    let files = read_stack_files(root)?;

    let mut problems = check::working_tree(&store, &loaded, &files)?;
    problems.extend(check::xdeploy(&files));
    problems.extend(committed_sets(root, stderr)?);
    if let Some(seed) = seed {
        problems.extend(check::resolution(&store, seed, &files)?);
    }

    for p in &problems {
        note(stderr, &p.to_string());
    }
    if problems.is_empty() {
        Ok(Checked { store, files })
    } else {
        Err(CliError::CheckFailed {
            count: problems.len(),
            structural: seed.is_none(),
        })
    }
}

/// A problem for every regular file committed in `HEAD` that contains
/// `<<set:` (any path). Without a commit yet there is nothing to scan.
fn committed_sets(root: &Path, stderr: &mut dyn Write) -> Result<Vec<Problem>, CliError> {
    if !git::rev_exists(root, "HEAD")? {
        note(
            stderr,
            "no commit yet, so there is no committed <<set:…>> to look for",
        );
        return Ok(Vec::new());
    }
    let mut problems = Vec::new();
    for e in git::tree_entries(root, "HEAD")? {
        if e.is_file() {
            let blob = git::read_blob(root, &e.oid)?;
            problems.extend(check::committed_set(&e.path, &blob));
        }
    }
    Ok(problems)
}

// ---------------------------------------------------------------------------
// deploy
// ---------------------------------------------------------------------------

/// `a, b` or `none`.
fn list_or_none(names: &[String]) -> String {
    if names.is_empty() {
        "none".to_owned()
    } else {
        names.join(", ")
    }
}

/// Which stacks `lst deploy` deploys (clap makes sure exactly one form is
/// given).
enum Targets {
    /// `lst deploy STACK…`.
    Stacks(Vec<String>),
    /// `lst deploy --changed-since REV`: [`changed_stacks`].
    ChangedSince(String),
    /// `lst deploy --all`: every existing stack.
    All,
}

/// Whether `lst deploy` deploys or only shows what it would do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Deploy,
    /// `--dry-run`: [`plan_stack`] instead of [`deploy_stack`].
    DryRun,
}

/// `lst deploy STACK…` / `--changed-since REV` / `--all`. See
/// [`crate::deploy`] for how compose runs.
///
/// Everything that can be decided before running compose is decided first:
/// the full check, the set of stacks (deduplicated and sorted), each stack
/// exists, each name is a valid compose project name. Then each stack is
/// rendered and deployed in turn ([`deploy_stack`]); the first failure
/// stops it, and the error says which stacks were deployed and which were
/// not attempted. Only `x-deploy` `render:` targets are written to disk:
/// the rendered compose text only goes into compose's stdin.
///
/// [`Mode::DryRun`] goes the same way, with [`plan_stack`] in place of
/// [`deploy_stack`]: nothing before it runs docker or writes anything, so
/// the dry run never does either.
fn deploy(
    root: &Path,
    env_seed: EnvSeed<'_>,
    targets: Targets,
    mode: Mode,
    stderr: &mut dyn Write,
) -> Result<(), CliError> {
    let seed = require_seed(root, env_seed)?;
    // With the seed, a passing check includes `store.verify_seed`.
    let checked = check_repo(root, Some(&seed), stderr)?;
    let store = &checked.store;
    let names = match targets {
        Targets::ChangedSince(rev) => changed_stacks(root, &rev, &checked, stderr)?,
        // Every existing stack is a key of the files just checked.
        Targets::All => checked.files.keys().cloned().collect(),
        Targets::Stacks(stacks) => stacks.into_iter().collect(),
    };
    if names.is_empty() {
        note(stderr, "nothing to deploy");
        return Ok(());
    }
    let mut targets = Vec::with_capacity(names.len());
    for name in &names {
        let s = stack::find(root, name)?;
        deploy::validate_project_name(&s.name)?;
        targets.push(s);
    }
    let names_of = |ts: &[Stack]| ts.iter().map(|t| t.name.clone()).collect();
    for (i, s) in targets.iter().enumerate() {
        let result = render_full(root, &seed, store, s).and_then(|rendered| match mode {
            Mode::Deploy => deploy_stack(root, &s.name, rendered, stderr),
            Mode::DryRun => plan_stack(&s.name, &rendered, stderr),
        });
        match (result, mode) {
            (Ok(()), Mode::Deploy) => note(stderr, &format!("deployed {}", s.name)),
            (Ok(()), Mode::DryRun) => note(stderr, &format!("dry run: would deploy {}", s.name)),
            (Err(e), Mode::Deploy) => {
                return Err(CliError::DeployFailed {
                    failed: s.name.clone(),
                    deployed: names_of(&targets[..i]),
                    not_attempted: names_of(&targets[i + 1..]),
                    source: Box::new(e),
                });
            }
            (Err(e), Mode::DryRun) => {
                return Err(CliError::DryRunFailed {
                    stack: s.name.clone(),
                    source: Box::new(e),
                });
            }
        }
    }
    Ok(())
}

/// Checks every service a step of `stack` targets as a compose service
/// name ([`deploy::validate_service_name`]).
fn validate_step_services(
    stack: &str,
    pre: &[xdeploy::Step],
    post: &[xdeploy::Step],
) -> Result<(), DeployError> {
    for step in pre.iter().chain(post) {
        deploy::validate_service_name(stack, &step.service)?;
    }
    Ok(())
}

/// Deploys one rendered stack, in the order of `docs/design.md` ("Deploy
/// order"):
/// 1. every service a step targets is checked as a compose service name,
///    before anything runs;
/// 2. for each service with a `when: on-change` step, the `lst.render-hash`
///    of its existing container is read (`docker ps`), before anything is
///    changed;
/// 3. every `render:` file is written ([`deploy::write_rendered`]: only if
///    its content or mode differs), with a `wrote <to>` / `mode fixed <to>`
///    line;
/// 4. the `pre` steps, in order;
/// 5. `docker compose up` ([`deploy::run_compose`]);
/// 6. the `post` steps, in order.
///
/// An `on-change` step is skipped, with a note, when the hash read in 2
/// equals the stack's new hash for its service; no container (or no label)
/// counts as changed. A failing `pre` step stops before `up` (the files
/// written in 3 stay written); a failing `post` step fails the deploy with
/// the stack already up.
///
/// A stack without `x-deploy` has no files and no steps, so this is just
/// step 5, exactly as in M3.
fn deploy_stack(
    root: &Path,
    stack: &str,
    rendered: Rendered,
    stderr: &mut dyn Write,
) -> Result<(), CliError> {
    let Rendered {
        compose,
        files,
        pre,
        post,
        hashes,
    } = rendered;
    validate_step_services(stack, &pre, &post)?;
    let on_change: BTreeSet<&str> = pre
        .iter()
        .chain(&post)
        .filter(|step| step.when == When::OnChange)
        .map(|step| step.service.as_str())
        .collect();
    let mut unchanged = BTreeSet::new();
    for service in on_change {
        let before = deploy::existing_hash(root, stack, service)?;
        if before.is_some() && before.as_ref() == hashes.get(service) {
            unchanged.insert(service.to_owned());
        }
    }
    for f in &files {
        let to = f.to.display();
        match deploy::write_rendered(&f.to, &f.contents, f.mode)? {
            WriteOutcome::Written => note(stderr, &format!("wrote {to}")),
            WriteOutcome::ModeFixed => note(stderr, &format!("mode fixed {to}")),
            WriteOutcome::Unchanged => {}
        }
    }
    let steps = |phase, steps, stderr: &mut dyn Write| {
        run_steps(root, stack, &compose, phase, steps, &unchanged, stderr)
    };
    steps(Phase::Pre, pre, stderr).map_err(|source| CliError::PreFailed { source })?;
    deploy::run_compose(root, stack, &compose)?;
    steps(Phase::Post, post, stderr).map_err(|source| CliError::PostFailed { source })
}

/// `lst deploy --dry-run` for one rendered stack: what [`deploy_stack`]
/// would do, one `would …` line per action, in the same order, changing
/// nothing:
/// 1. the step services are checked as in [`deploy_stack`];
/// 2. no `docker ps`: an `on-change` step is reported as conditional;
/// 3. each `render:` file is compared with its target, read-only
///    ([`deploy::plan_rendered`]): `would write <to>` /
///    `would fix the mode of <to>`, nothing if it is up to date; a target
///    the deploy would refuse is the same error;
/// 4. the `pre` steps, by index and service (never the command: it holds
///    secrets);
/// 5. the `docker compose … up` arguments (the compose file, which holds
///    the secrets, goes to stdin, so they don't);
/// 6. the `post` steps, like the `pre` steps.
///
/// Never runs docker and writes nothing.
fn plan_stack(stack: &str, rendered: &Rendered, stderr: &mut dyn Write) -> Result<(), CliError> {
    validate_step_services(stack, &rendered.pre, &rendered.post)?;
    for f in &rendered.files {
        let to = f.to.display();
        match deploy::plan_rendered(&f.to, &f.contents, f.mode)? {
            WriteOutcome::Written => note(stderr, &format!("would write {to}")),
            WriteOutcome::ModeFixed => note(stderr, &format!("would fix the mode of {to}")),
            WriteOutcome::Unchanged => {}
        }
    }
    plan_steps(Phase::Pre, &rendered.pre, stderr);
    let args = deploy::compose_args(stack, &Path::new(STACKS_DIR).join(stack));
    let args: Vec<_> = args.iter().map(|a| a.to_string_lossy()).collect();
    note(stderr, &format!("would run docker {}", args.join(" ")));
    plan_steps(Phase::Post, &rendered.post, stderr);
    Ok(())
}

/// The `would run` lines of the `phase` steps, for [`plan_stack`].
fn plan_steps(phase: Phase, steps: &[xdeploy::Step], stderr: &mut dyn Write) {
    for (index, step) in steps.iter().enumerate() {
        let service = &step.service;
        let condition = match step.when {
            When::Always => "",
            When::OnChange => {
                " unless its inputs are unchanged (when: on-change; a dry run doesn't check)"
            }
        };
        note(
            stderr,
            &format!("would run x-deploy.{phase}[{index}] ({service}){condition}"),
        );
    }
}

/// Runs the `phase` steps of `stack` in order (see [`deploy_stack`]);
/// `unchanged` are the services whose `on-change` steps are skipped. The
/// rendered commands are moved into the runner, not copied.
fn run_steps(
    root: &Path,
    stack: &str,
    compose: &crypto::SecretString,
    phase: Phase,
    steps: Vec<xdeploy::Step>,
    unchanged: &BTreeSet<String>,
    stderr: &mut dyn Write,
) -> Result<(), DeployError> {
    for (index, step) in steps.into_iter().enumerate() {
        let service = step.service;
        if step.when == When::OnChange && unchanged.contains(&service) {
            note(
                stderr,
                &format!("skipped x-deploy.{phase}[{index}] ({service}): inputs unchanged"),
            );
            continue;
        }
        let command = StepCommand::from(step.run);
        match phase {
            Phase::Pre => deploy::run_pre(root, stack, compose, index, &service, &command)?,
            Phase::Post => deploy::run_post(root, stack, compose, index, &service, &command)?,
        }
    }
    Ok(())
}

/// The stacks `--changed-since REV` deploys ([`deploy::affected_stacks`]
/// over `REV..HEAD`), with a note for each affected stack that no longer
/// exists and each changed path that can't belong to a stack.
///
/// `.sec/shared.toml` is compared between `REV` and the working tree (the
/// store just checked, which in CI is `HEAD`), and the markers and the
/// existing stacks are the working tree's: the same files `lst check` just
/// found consistent.
fn changed_stacks(
    root: &Path,
    rev: &str,
    checked: &Checked,
    stderr: &mut dyn Write,
) -> Result<BTreeSet<String>, CliError> {
    let changed = git::diff_names(root, rev).map_err(|e| match e {
        GitError::UnknownRev { .. } => CliError::UnknownDeployRev {
            rev: rev.to_owned(),
        },
        e => e.into(),
    })?;
    let rev_err = |source| CliError::OldShared {
        rev: rev.to_owned(),
        source,
    };
    let before = match git::show_file(root, rev, &format!("{SEC_DIR}/{SHARED}.toml"))? {
        None => StackFile::default(),
        Some(bytes) => {
            let text = std::str::from_utf8(&bytes).map_err(|_| CliError::OldSharedNotUtf8 {
                rev: rev.to_owned(),
            })?;
            StackFile::parse(SHARED, text).map_err(rev_err)?
        }
    };
    let empty = StackFile::default();
    let after = checked.store.files().get(SHARED).unwrap_or(&empty);
    let uses = scan::collect(&checked.files)?.uses;
    let existing = checked.files.keys().cloned().collect();
    let affected = deploy::affected_stacks(&changed, &before, after, &uses, &existing);
    for s in &affected.deleted {
        note(
            stderr,
            &format!(
                "not deploying {s}: it changed but has no {STACKS_DIR}/{s}/{COMPOSE_FILE} any \
                 more (lst does not tear stacks down; run `docker compose -p {s} down` if it \
                 should go)"
            ),
        );
    }
    for p in &affected.ignored {
        note(
            stderr,
            &format!("ignoring {p}: not a valid stack name, so it belongs to no stack"),
        );
    }
    Ok(affected.deploy)
}

// ---------------------------------------------------------------------------
// hook
// ---------------------------------------------------------------------------

const LEFTOVER_BLOB_HINT: &str = "note: `git add` already stored the plaintext as a blob in \
     .git/objects. No commit references it and it is never pushed, but it stays on this machine \
     until git prunes it; run `git gc --prune=now` to delete it now";

/// What [`install_hook`] did.
enum HookInstall {
    /// Wrote the hook; `replaced` if another pre-commit hook was there.
    Installed { replaced: bool },
    /// lst's hook was already there (same bytes, executable).
    AlreadyInstalled,
}

/// `path` for messages: relative to `root` if it is inside it.
fn shown_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

#[cfg(unix)]
fn is_executable(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 == 0o111
}

#[cfg(not(unix))]
fn is_executable(_meta: &fs::Metadata) -> bool {
    true
}

#[cfg(unix)]
fn make_executable(perms: &mut fs::Permissions) {
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o755);
}

#[cfg(not(unix))]
fn make_executable(_perms: &mut fs::Permissions) {}

/// Writes `bytes` to `path` through a new temporary file in the same
/// directory and a rename, so `path` is never half-written and a symlink
/// at `path` is replaced rather than written through. `perms` sets the
/// new file's permissions. The temporary file is removed on failure.
fn write_atomic(
    path: &Path,
    bytes: &[u8],
    perms: impl FnOnce(&mut fs::Permissions),
) -> io::Result<()> {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let tmp = path.with_file_name(format!(".{name}.lst-{}.tmp", std::process::id()));
    let result = (|| {
        let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        f.write_all(bytes)?;
        let mut p = f.metadata()?.permissions();
        perms(&mut p);
        f.set_permissions(p)?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Installs [`hook::SCRIPT`] as the pre-commit hook. Returns the hook's
/// path for messages and what was done.
fn install_hook(root: &Path, force: bool) -> Result<(String, HookInstall), CliError> {
    let dir = git::hooks_dir(root)?;
    let path = dir.join(hook::HOOK_FILE);
    let shown = shown_path(root, &path);
    fs::create_dir_all(&dir).map_err(io_err(&dir))?;
    let existing = git::lstat(&path).map_err(io_err(&path))?;
    if let Some(meta) = &existing {
        let ours = meta.is_file()
            && is_executable(meta)
            && fs::read(&path).map_err(io_err(&path))? == hook::SCRIPT.as_bytes();
        if ours {
            return Ok((shown, HookInstall::AlreadyInstalled));
        }
        if !force {
            return Err(CliError::ForeignHook { path: shown });
        }
    }
    write_atomic(&path, hook::SCRIPT.as_bytes(), make_executable).map_err(io_err(&path))?;
    let replaced = existing.is_some();
    Ok((shown, HookInstall::Installed { replaced }))
}

fn hook_install(root: &Path, force: bool, stderr: &mut dyn Write) -> Result<(), CliError> {
    let msg = match install_hook(root, force)? {
        (path, HookInstall::Installed { replaced: false }) => {
            format!("installed the pre-commit hook: {path}")
        }
        (path, HookInstall::Installed { replaced: true }) => {
            format!("replaced {path} with lst's pre-commit hook (--force)")
        }
        (path, HookInstall::AlreadyInstalled) => {
            format!("the pre-commit hook is already installed: {path}")
        }
    };
    note(stderr, &msg);
    Ok(())
}

/// A staged stack file: its blob (zeroized on drop: it may hold a
/// `<<set:…>>` value) and its index mode.
struct Staged {
    bytes: Contents,
    mode: String,
}

impl AsRef<[u8]> for Staged {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// `lst hook run`: the pre-commit hook. See [`hook`] for what it reads and
/// when it blocks. Nothing is written until every check has passed; then
/// `.sec/` is saved and staged, rewritten files are staged, and last the
/// working tree is rewritten.
fn hook_run(root: &Path, env_seed: EnvSeed<'_>, stderr: &mut dyn Write) -> Result<(), CliError> {
    let (seed, mut store) = open_store(root, env_seed)?;
    let temporary = hook::is_temporary_index(std::env::var_os("GIT_INDEX_FILE").as_deref());
    let entries = git::staged_entries(root, "")?;
    let roles = hook::classify(&entries)?;

    // 1. Read the staged files.
    let mut stack_files: scan::StackFiles<Staged> = BTreeMap::new();
    let mut staged_sec = BTreeMap::new();
    for (e, role) in entries.iter().zip(roles) {
        match role {
            Role::Skip => {}
            Role::Stack(stack) => {
                let bytes = git::read_blob(root, &e.oid)?;
                let mode = e.mode.clone();
                let files = stack_files.entry(stack).or_default();
                files.push((e.path.clone(), Staged { bytes, mode }));
            }
            Role::Other => {
                if scan::contains_set(&git::read_blob(root, &e.oid)?) {
                    let path = e.path.clone();
                    return Err(HookError::SetOutsideStacks { path }.into());
                }
            }
            Role::Sec(name) => {
                staged_sec.insert(name, git::read_blob(root, &e.oid)?);
            }
        }
    }

    // 2. Markers, and the <<set:…>> values to store.
    let scan = scan::collect(&stack_files)?;
    let mut set_files = Vec::new();
    for (stack, files) in &stack_files {
        for (path, staged) in files {
            if let Some(rewrite) = hook::rewrite_sets(path, &staged.bytes)? {
                set_files.push(hook::SetFile {
                    path: path.clone(),
                    stack: stack.clone(),
                    mode: staged.mode.clone(),
                    rewrite,
                });
            }
        }
    }
    if temporary && !set_files.is_empty() {
        return Err(HookError::TemporaryIndex.into());
    }

    // 3. Update the store in memory (nothing is saved until all of it
    //    worked).
    let mut stored = Vec::new();
    for s in hook::values_to_store(&set_files)? {
        let changed = store.set_secret(&seed, s.stack, s.name, s.value.expose())?;
        stored.push((s.full_name, changed));
    }
    let report = store.sync(&hook::secret_uses(scan.uses))?;
    hook::check_unset(&report)?;
    if temporary {
        // No <<set:…>> (refused above): fine only if .sec/ is staged as is.
        return if hook::sec_in_sync(&store.to_files(), &staged_sec) {
            Ok(())
        } else {
            Err(HookError::TemporaryIndex.into())
        };
    }

    // 4. Persist: .sec/, then the rewritten files in the index.
    store.save(&root.join(SEC_DIR))?;
    git::add(root, Path::new(SEC_DIR))?;
    for f in &set_files {
        let oid = git::write_blob(root, f.rewrite.text.expose().as_bytes())?;
        git::update_index(root, &f.mode, &oid, &f.path)?;
    }

    // 5. The working tree.
    let mut warnings = Vec::new();
    for f in &set_files {
        rewrite_worktree(root, f, &mut warnings)?;
    }

    // 6. Report (silent if nothing changed).
    print_report(stderr, &report);
    for (name, changed) in &stored {
        let msg = if *changed {
            format!("stored {name}")
        } else {
            format!("stored {name} (unchanged: it already had this value)")
        };
        note(stderr, &msg);
    }
    for w in &warnings {
        note(stderr, w);
    }
    if !stored.is_empty() {
        note(stderr, LEFTOVER_BLOB_HINT);
    }
    Ok(())
}

/// Replaces the staged `<<set:…>>` markers of `f` in its working-tree file
/// (exact text only, see [`hook::replace_raw`]), keeping its permissions.
/// A file that is gone, not a regular file, or no longer has a marker is
/// left alone with a warning (names only): the commit is right either way.
fn rewrite_worktree(
    root: &Path,
    f: &hook::SetFile,
    warnings: &mut Vec<String>,
) -> Result<(), CliError> {
    let full = root.join(&f.path);
    let shown = Path::new(&f.path);
    let meta = git::lstat(&full).map_err(io_err(shown))?;
    let Some(meta) = meta.filter(fs::Metadata::is_file) else {
        warnings.push(format!(
            "{}: not a file in the working tree, so it was left alone (the commit has \
             <<secret:…>>)",
            f.path
        ));
        return Ok(());
    };
    let bytes = Zeroizing::new(fs::read(&full).map_err(io_err(shown))?);
    let (rewritten, missing) = hook::replace_raw(&bytes, &f.rewrite.sets);
    for name in missing {
        warnings.push(format!(
            "{}: the working tree no longer has the staged <<set:{name}:…>>, so it was left \
             as is (the commit has <<secret:{name}>>)",
            f.path
        ));
    }
    if let Some(rewritten) = rewritten {
        let perms = meta.permissions();
        write_atomic(&full, &rewritten, |p| *p = perms).map_err(io_err(shown))?;
    }
    Ok(())
}
