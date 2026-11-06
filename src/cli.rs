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
use crate::hook::{self, HookError, Role};
use crate::render::{self, RenderError};
use crate::scan::{self, ScanError};
use crate::stack::{self, COMPOSE_FILE, STACKS_DIR, Stack, StackError};
use crate::store::{self, EntryKind, META, ResolveError, SHARED, Store, StoreError, SyncReport};

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
    /// Print the resolved compose file of a stack to stdout.
    ///
    /// Read-only: never writes .sec/ or .env.
    Render {
        /// The stack: stacks/<STACK>/compose.yaml.
        stack: String,
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
    #[error("could not write to stdout: {0}")]
    Stdout(io::Error),
    #[error(transparent)]
    Hook(#[from] HookError),
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
        Command::Rename { from, to, replace } => rename(&root, &from, &to, replace, stderr),
        Command::Render { stack } => render_stack(&root, &stack, stdout),
        Command::Hook {
            action: HookAction::Install { force },
        } => hook_install(&root, force, stderr),
        Command::Hook {
            action: HookAction::Run,
        } => hook_run(&root, stderr),
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
    let text = fs::read_to_string(&stack.compose).map_err(io_err(Path::new(&path)))?;
    Ok((path, Zeroizing::new(text)))
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
        let mut files = Vec::new();
        for path in git::worktree_files(root, &format!("{STACKS_DIR}/{}/", s.name))? {
            let full = root.join(&path);
            let meta = fs::symlink_metadata(&full).map_err(io_err(Path::new(&path)))?;
            if meta.is_file() {
                let bytes = fs::read(&full).map_err(io_err(Path::new(&path)))?;
                files.push((path, Zeroizing::new(bytes)));
            }
        }
        out.insert(s.name, files);
    }
    Ok(out)
}

fn sync(root: &Path, stderr: &mut dyn Write) -> Result<(), CliError> {
    let (_seed, mut store) = open_store(root)?;
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
    from: &str,
    to: &str,
    replace: bool,
    stderr: &mut dyn Write,
) -> Result<(), CliError> {
    let (seed, mut store) = open_store(root)?;
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

fn render_stack(root: &Path, name: &str, stdout: &mut dyn Write) -> Result<(), CliError> {
    let (seed, store) = open_store(root)?;
    let s = stack::find(root, name)?;
    let (path, text) = read_compose(&s)?;
    let rendered =
        render::render(&text, |m| store.resolve(&seed, &s.name, m)).map_err(|e| match e {
            RenderError::Parse(p) => scan::parse_error(&path, &text, p).into(),
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
fn hook_run(root: &Path, stderr: &mut dyn Write) -> Result<(), CliError> {
    let (seed, mut store) = open_store(root)?;
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
