//! `lst deploy`: running `docker compose up` on a rendered stack, the
//! `x-deploy` steps around it, writing rendered extra files, and working
//! out which stacks `--changed-since REV` affects.
//!
//! [`validate_project_name`], [`validate_service_name`], [`compose_args`],
//! [`step_args`], [`hash_query_args`], [`parse_hash_query`] and
//! [`affected_stacks`] are pure. [`run_compose`], [`run_pre`], [`run_post`],
//! [`existing_hash`] and [`write_rendered`] are the thin runners around
//! them.
//!
//! # Running compose
//! Per stack, lst runs (an argument vector, never a shell string)
//!
//! ```text
//! docker compose -p <stack> --project-directory stacks/<stack> -f - up -d --wait --remove-orphans
//! ```
//!
//! in the repository root, with the rendered `compose.yaml` on stdin:
//! - The project directory is passed **relative** (`stacks/<stack>`) and
//!   the child runs with the repository root as its working directory, as
//!   `docs/design.md` writes it. Compose resolves it against its working
//!   directory, so bind mounts and build contexts resolve exactly as with
//!   an absolute path, and the arguments don't depend on where the
//!   checkout lives.
//! - The rendered text holds every secret of the stack. It goes into the
//!   pipe straight from the caller's [`SecretString`]; it is never written
//!   to disk and never part of an error.
//! - Compose's stdout **and** stderr go to lst's stderr, so lst's own
//!   stdout stays clean for machine-readable output.
//! - `LST_SEED` is removed from compose's environment: compose interpolates
//!   `${VAR}` from its environment, and the seed must never be able to end
//!   up in a container that way.
//! - The project name is validated again before anything runs, so a name
//!   that could be read as an option or a path never reaches compose.
//!
//! # `x-deploy` steps
//! A `pre` step runs before `up`, in a throwaway container of the service's
//! image; a `post` step after `up --wait`, in the running container
//! ([`step_args`] has the exact arguments). Both get the rendered compose
//! file on stdin exactly like `up` (same project name, project directory,
//! working directory, output handling and `LST_SEED` removal), so the
//! step's container sees the same configuration, volumes included.
//!
//! The commands hold rendered secrets. They are passed as arguments (never
//! through a shell on the host), are wiped from lst's own buffers when
//! dropped, and never appear in errors: a failing step is reported by stack,
//! phase, step index and service only. (`std::process::Command` keeps its
//! own copy until it is dropped, and the arguments are visible in `ps` while
//! docker runs; both accepted in `docs/design.md`.)
//!
//! # Reading `lst.render-hash`
//! See [`hash_query_args`] and [`parse_hash_query`]: one `docker ps` that
//! filters by compose's own labels, so it needs neither the compose file
//! nor a project directory.
//!
//! # Rendered files
//! See [`write_rendered`].
//!
//! # Affected stacks (`--changed-since REV`)
//! See [`affected_stacks`].

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use zeroize::Zeroizing;

use crate::crypto::SecretString;
use crate::scan::Uses;
use crate::stack::STACKS_DIR;
use crate::store::{self, META, SHARED, StackFile};

const DOCKER: &str = "docker";
/// The environment variable that may carry the seed (CI); never passed on
/// to compose.
const SEED_ENV: &str = "LST_SEED";
/// The store directory, relative to the repository root.
const SEC_DIR: &str = ".sec";

#[derive(Debug, thiserror::Error)]
pub enum DeployError {
    #[error(
        "stack name {stack:?} is not a valid docker compose project name (only a-z, 0-9, `_` \
         and `-`, starting with a letter or digit); rename the directory stacks/{stack}"
    )]
    InvalidProjectName { stack: String },
    #[error("could not run docker (is it installed and on PATH?)")]
    Spawn(#[source] io::Error),
    #[error("could not send the rendered compose file of stack {stack:?} to docker compose")]
    Stdin {
        stack: String,
        #[source]
        source: io::Error,
    },
    #[error("could not wait for docker compose to finish")]
    Wait(#[source] io::Error),
    #[error("`docker compose up` for stack {stack:?} failed ({status})")]
    Compose { stack: String, status: ExitStatus },
    #[error(
        "service name {service:?} of stack {stack:?} is not a valid docker compose service name \
         (only a-z, A-Z, 0-9, `.`, `_` and `-`)"
    )]
    InvalidServiceName { stack: String, service: String },
    /// A `pre`/`post` step exited non-zero. `index` is the step's position
    /// in its list (from 0), as in `x-deploy.pre[0]`. Never the command.
    #[error("x-deploy.{phase}[{index}] (service {service:?}) of stack {stack:?} failed ({status})")]
    Step {
        stack: String,
        phase: Phase,
        index: usize,
        service: String,
        status: ExitStatus,
    },
    #[error("`docker ps` for service {service:?} of stack {stack:?} failed ({status})")]
    HashQuery {
        stack: String,
        service: String,
        status: ExitStatus,
    },
    #[error(
        "`docker ps` for service {service:?} of stack {stack:?} printed something that isn't UTF-8"
    )]
    HashQueryOutput { stack: String, service: String },
}

/// Checks that `stack` is usable as a compose project name as it is:
/// `[a-z0-9][a-z0-9_-]*`. A name that isn't (uppercase, `.`, a leading `_`
/// or `-`) is an error with a hint to rename the stack directory; it is
/// never lowercased silently, which would make two stacks share a project
/// or deploy one under a name the user never wrote.
pub fn validate_project_name(stack: &str) -> Result<(), DeployError> {
    let first_ok = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let valid = match stack.as_bytes() {
        [first, rest @ ..] => {
            first_ok(*first)
                && rest
                    .iter()
                    .all(|&b| first_ok(b) || matches!(b, b'_' | b'-'))
        }
        [] => false,
    };
    if valid {
        Ok(())
    } else {
        Err(DeployError::InvalidProjectName {
            stack: stack.to_owned(),
        })
    }
}

/// The arguments after `docker`:
/// `compose -p <stack> --project-directory <stack_dir_rel> -f - up -d --wait --remove-orphans`.
/// `stack_dir_rel` is relative to the repository root, where compose runs.
/// Doesn't validate `stack`; [`run_compose`] does.
pub fn compose_args(stack: &str, stack_dir_rel: &Path) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec!["compose".into(), "-p".into(), stack.into()];
    args.push("--project-directory".into());
    args.push(stack_dir_rel.into());
    args.extend(["-f", "-", "up", "-d", "--wait", "--remove-orphans"].map(OsString::from));
    args
}

/// `stacks/<stack>`, relative to the repository root.
fn stack_dir_rel(stack: &str) -> PathBuf {
    Path::new(STACKS_DIR).join(stack)
}

/// Deploys `stack`: runs `docker compose … up` (see the module docs) in
/// `root` with `rendered` (the stack's rendered `compose.yaml`) on stdin,
/// and waits for it.
///
/// A non-zero exit is `Compose`; docker not being runnable at all is
/// `Spawn`. Compose's output goes to lst's stderr as it is produced.
pub fn run_compose(root: &Path, stack: &str, rendered: &SecretString) -> Result<(), DeployError> {
    run_compose_with(OsStr::new(DOCKER), root, stack, rendered)
}

fn run_compose_with(
    program: &OsStr,
    root: &Path,
    stack: &str,
    rendered: &SecretString,
) -> Result<(), DeployError> {
    validate_project_name(stack)?;
    let (status, written) = run_piped(
        program,
        compose_args(stack, &stack_dir_rel(stack)),
        root,
        rendered,
    )?;
    if !status.success() {
        return Err(DeployError::Compose {
            stack: stack.to_owned(),
            status,
        });
    }
    stdin_taken(stack, written)
}

/// Compose exited 0 without taking all of the input (`written` failed):
/// whatever it ran is not what lst rendered.
fn stdin_taken(stack: &str, written: io::Result<()>) -> Result<(), DeployError> {
    written.map_err(|source| DeployError::Stdin {
        stack: stack.to_owned(),
        source,
    })
}

/// Runs `program args` in `root` with `input` on stdin, the child's stdout
/// and stderr on lst's stderr and `LST_SEED` removed, and waits for it.
/// Returns its exit status and the result of writing stdin; callers check
/// the status first (a child that fails without reading its input reports
/// its own error, not lst's broken pipe).
fn run_piped<I, S>(
    program: &OsStr,
    args: I,
    root: &Path,
    input: &SecretString,
) -> Result<(ExitStatus, io::Result<()>), DeployError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut child = Command::new(program)
        .args(args)
        .current_dir(root)
        .env_remove(SEED_ENV)
        .stdin(Stdio::piped())
        .stdout(Stdio::from(io::stderr()))
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(DeployError::Spawn)?;
    // Writing all of stdin before waiting can't deadlock: the only pipe is
    // stdin. Compose's stdout and stderr go straight to our stderr file
    // descriptor, not into a pipe lst would have to drain, so compose can
    // print as much as it likes before (or instead of) reading its input.
    // If it exits without reading everything, the write ends with EPIPE
    // (Rust ignores SIGPIPE), not a hang. Dropping the handle closes the
    // pipe so compose sees EOF.
    let written = {
        // Invariant: stdin was configured as `Stdio::piped()` above, so
        // `spawn` populated the handle and nothing has taken it yet.
        let mut stdin = child.stdin.take().expect("stdin is piped");
        stdin.write_all(input.expose().as_bytes())
    };
    let status = child.wait().map_err(DeployError::Wait)?;
    Ok((status, written))
}

// ---- x-deploy steps --------------------------------------------------------

/// When an `x-deploy` step runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Before `up`: `docker compose run --rm --no-deps -T`.
    Pre,
    /// After `up --wait`: `docker compose exec -T`.
    Post,
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Phase::Pre => "pre",
            Phase::Post => "post",
        })
    }
}

/// A step's rendered `run:`. It holds secrets, hence [`SecretString`]
/// (whose `Debug` is redacted).
#[derive(Debug)]
pub enum StepCommand {
    /// `run: <string>`: runs as `sh -c <string>` in the container.
    Shell(SecretString),
    /// `run: [program, args…]`: exec form, no shell. An empty list can't be
    /// represented; see [`StepCommand::from_argv`].
    Exec {
        program: SecretString,
        args: Vec<SecretString>,
    },
}

impl StepCommand {
    /// Exec form from a list; `None` for an empty list (the model must
    /// reject `run: []`).
    pub fn from_argv(argv: Vec<SecretString>) -> Option<StepCommand> {
        let mut argv = argv.into_iter();
        let program = argv.next()?;
        Some(StepCommand::Exec {
            program,
            args: argv.collect(),
        })
    }
}

/// Checks that `service` is a compose service name: non-empty, only
/// `[a-zA-Z0-9._-]` (the compose specification's pattern). The model checks
/// that it names a service of the stack; this is the runners' own guard, so
/// nothing else ever reaches docker's argument list or a `--filter`.
pub fn validate_service_name(stack: &str, service: &str) -> Result<(), DeployError> {
    let ok = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-');
    if !service.is_empty() && service.bytes().all(ok) {
        Ok(())
    } else {
        Err(DeployError::InvalidServiceName {
            stack: stack.to_owned(),
            service: service.to_owned(),
        })
    }
}

/// The arguments after `docker` for a step of `service` in `stack`:
///
/// ```text
/// pre:  compose -p <stack> --project-directory stacks/<stack> -f - run --rm --no-deps -T -- <service> <command>
/// post: compose -p <stack> --project-directory stacks/<stack> -f - exec -T -- <service> <command>
/// ```
///
/// with `<command>` = `sh -c <string>` (shell form) or `<program> <args…>`
/// (exec form).
/// - `run` and `exec` stop parsing their own options at the service name
///   (compose sets `SetInterspersed(false)` on both), so a command or
///   argument starting with `-` reaches the container as it is. The `--`
///   before the service also keeps a service name starting with `-` from
///   being read as an option. (Checked against Docker Compose v5.6.1.)
/// - `sh` itself would read a command string starting with `-` or `+` as
///   options, so for such a string the shell form is `sh -c -- <string>`
///   (POSIX; dash, bash and busybox ash all accept it). Every other string
///   gets the plain `sh -c <string>`.
/// - `run` uses the image's entrypoint, like the service would.
///
/// The result holds the rendered command and is wiped on drop. Doesn't
/// validate `stack` or `service`; the runners do.
pub fn step_args(
    phase: Phase,
    stack: &str,
    service: &str,
    command: &StepCommand,
) -> Zeroizing<Vec<String>> {
    let mut args = Zeroizing::new(Vec::new());
    let mut push = |a: &str| args.push(a.to_owned());
    for a in ["compose", "-p", stack, "--project-directory"] {
        push(a);
    }
    push(&format!("{STACKS_DIR}/{stack}"));
    push("-f");
    push("-");
    let sub: &[&str] = match phase {
        Phase::Pre => &["run", "--rm", "--no-deps", "-T"],
        Phase::Post => &["exec", "-T"],
    };
    for a in sub.iter().chain(&["--", service]) {
        push(a);
    }
    match command {
        StepCommand::Shell(script) => {
            let script = script.expose();
            push("sh");
            push("-c");
            if script.starts_with(['-', '+']) {
                push("--");
            }
            push(script);
        }
        StepCommand::Exec { program, args } => {
            for a in std::iter::once(program).chain(args) {
                push(a.expose());
            }
        }
    }
    args
}

/// Runs step `index` of the `pre` list: `command` in a throwaway container
/// of `service` (see [`step_args`]), with `compose` (the stack's rendered
/// compose file) on stdin, in `root`, and waits for it. A non-zero exit is
/// [`DeployError::Step`]; the step's output goes to lst's stderr.
pub fn run_pre(
    root: &Path,
    stack: &str,
    compose: &SecretString,
    index: usize,
    service: &str,
    command: &StepCommand,
) -> Result<(), DeployError> {
    let step = StepRef {
        phase: Phase::Pre,
        index,
        service,
    };
    run_step_with(OsStr::new(DOCKER), root, stack, compose, step, command)
}

/// Runs step `index` of the `post` list in the running container of
/// `service`; otherwise like [`run_pre`].
pub fn run_post(
    root: &Path,
    stack: &str,
    compose: &SecretString,
    index: usize,
    service: &str,
    command: &StepCommand,
) -> Result<(), DeployError> {
    let step = StepRef {
        phase: Phase::Post,
        index,
        service,
    };
    run_step_with(OsStr::new(DOCKER), root, stack, compose, step, command)
}

/// Which step is running, for its arguments and errors.
#[derive(Debug, Clone, Copy)]
struct StepRef<'a> {
    phase: Phase,
    index: usize,
    service: &'a str,
}

fn run_step_with(
    program: &OsStr,
    root: &Path,
    stack: &str,
    compose: &SecretString,
    step: StepRef<'_>,
    command: &StepCommand,
) -> Result<(), DeployError> {
    validate_project_name(stack)?;
    validate_service_name(stack, step.service)?;
    let args = step_args(step.phase, stack, step.service, command);
    let (status, written) = run_piped(program, args.iter(), root, compose)?;
    if !status.success() {
        return Err(DeployError::Step {
            stack: stack.to_owned(),
            phase: step.phase,
            index: step.index,
            service: step.service.to_owned(),
            status,
        });
    }
    stdin_taken(stack, written)
}

// ---- lst.render-hash of the existing container -------------------------------

/// The label lst puts the render hash in.
pub const RENDER_HASH_LABEL: &str = "lst.render-hash";

/// The arguments after `docker` that list the existing containers of
/// `service` in project `stack`, one line `<id> <lst.render-hash>` each:
///
/// ```text
/// ps --all --no-trunc --filter label=com.docker.compose.project=<stack>
///    --filter label=com.docker.compose.service=<service>
///    --filter label=com.docker.compose.oneoff=False
///    --format {{.ID}} {{.Label "lst.render-hash"}}
/// ```
///
/// Why plain `docker ps` and not `docker compose ps`: it filters by the
/// labels compose itself puts on every container, so it needs no compose
/// file on stdin and no project directory, and its `--format` with `.Label`
/// has been stable for far longer than compose's `ps --format json` (whose
/// shape changed across v2 releases). `--all` includes stopped containers
/// (compose reuses those too); `oneoff=False` leaves out `compose run`
/// containers, such as one a failed `pre` step left behind.
pub fn hash_query_args(stack: &str, service: &str) -> Vec<String> {
    let mut args: Vec<String> = ["ps", "--all", "--no-trunc"].map(String::from).into();
    for filter in [
        format!("label=com.docker.compose.project={stack}"),
        format!("label=com.docker.compose.service={service}"),
        "label=com.docker.compose.oneoff=False".to_owned(),
    ] {
        args.push("--filter".to_owned());
        args.push(filter);
    }
    args.push("--format".to_owned());
    args.push(format!(
        "{{{{.ID}}}} {{{{.Label \"{RENDER_HASH_LABEL}\"}}}}"
    ));
    args
}

/// The render hash of the existing container(s), from the output of
/// [`hash_query_args`]:
/// - no container → `None` (counts as changed);
/// - one container → its label, or `None` if it has none (empty);
/// - several (`scale`/`replicas`) → their label if all carry the same
///   non-empty one, otherwise `None`: a half-updated set of replicas counts
///   as changed, so an `on-change` step runs rather than being skipped.
pub fn parse_hash_query(output: &str) -> Option<String> {
    let mut labels = output
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| line.split_once(' ').map_or("", |(_id, label)| label));
    let first = labels.next()?;
    let same = labels.all(|label| label == first);
    (same && !first.is_empty()).then(|| first.to_owned())
}

/// The `lst.render-hash` label of the existing container of `service` in
/// project `stack` (see [`hash_query_args`] and [`parse_hash_query`]), read
/// before `up`. `None` means "treat as changed". Runs `docker ps` in `root`
/// with `LST_SEED` removed; its stderr goes to lst's stderr.
pub fn existing_hash(
    root: &Path,
    stack: &str,
    service: &str,
) -> Result<Option<String>, DeployError> {
    existing_hash_with(OsStr::new(DOCKER), root, stack, service)
}

fn existing_hash_with(
    program: &OsStr,
    root: &Path,
    stack: &str,
    service: &str,
) -> Result<Option<String>, DeployError> {
    validate_project_name(stack)?;
    validate_service_name(stack, service)?;
    let out = Command::new(program)
        .args(hash_query_args(stack, service))
        .current_dir(root)
        .env_remove(SEED_ENV)
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .map_err(DeployError::Spawn)?;
    if !out.status.success() {
        return Err(DeployError::HashQuery {
            stack: stack.to_owned(),
            service: service.to_owned(),
            status: out.status,
        });
    }
    let text = String::from_utf8(out.stdout).map_err(|_| DeployError::HashQueryOutput {
        stack: stack.to_owned(),
        service: service.to_owned(),
    })?;
    Ok(parse_hash_query(&text))
}

/// The stacks a change set affects; see [`affected_stacks`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Affected {
    /// Affected stacks that exist now (are in `existing`): deploy these.
    pub deploy: BTreeSet<String>,
    /// Affected stacks that have no `compose.yaml` now: reported, not
    /// deployed and not torn down (that's M5).
    pub deleted: BTreeSet<String>,
    /// Changed paths under `stacks/<name>/` or of the form
    /// `.sec/<name>.toml` whose `<name>` isn't a valid stack name (or is
    /// reserved, in any case other than the exact `shared`/`meta` store
    /// files). They can't belong to a stack, so they affect nothing; listed
    /// so the caller can say so.
    pub ignored: BTreeSet<String>,
}

/// What a changed path means for deployment.
#[derive(Debug, PartialEq, Eq)]
enum PathClass<'a> {
    /// `stacks/<s>/…` or `.sec/<s>.toml`, `<s>` a valid stack name.
    Stack(&'a str),
    /// `.sec/shared.toml`.
    Shared,
    /// `.sec/meta.toml`.
    Meta,
    /// Shaped like a stack path, but `<s>` isn't a valid stack name.
    Invalid,
    /// Anything else (README, docs, CI config, other files in `.sec/`).
    Other,
}

fn stack_class(name: &str) -> PathClass<'_> {
    if store::is_valid_stack(name) {
        PathClass::Stack(name)
    } else {
        PathClass::Invalid
    }
}

fn classify(path: &str) -> PathClass<'_> {
    if let Some(rest) = path
        .strip_prefix(STACKS_DIR)
        .and_then(|r| r.strip_prefix('/'))
    {
        return match rest.split_once('/') {
            // A file directly in stacks/ (or a bare `stacks/<s>/`) is no
            // stack's file.
            Some((name, inner)) if !inner.is_empty() => stack_class(name),
            _ => PathClass::Other,
        };
    }
    if let Some(file) = path.strip_prefix(SEC_DIR).and_then(|r| r.strip_prefix('/')) {
        return match file.strip_suffix(".toml") {
            Some(SHARED) => PathClass::Shared,
            Some(META) => PathClass::Meta,
            Some(name) if !name.contains('/') => stack_class(name),
            _ => PathClass::Other,
        };
    }
    PathClass::Other
}

/// The keys of `shared.toml` whose entry differs between `before` and
/// `after` in anything that changes a rendered value: added, removed, or a
/// changed id or format (gen) or nonce or ciphertext (secret). Only the
/// `orphan` flag changing doesn't count: no rendered value changes, and a
/// name only becomes (un)orphaned when some stack stops (starts) using it,
/// which changes that stack's own files, so it is deployed anyway.
fn changed_shared_keys<'a>(before: &'a StackFile, after: &'a StackFile) -> BTreeSet<&'a str> {
    let gen_value = |f: &'a StackFile, k: &str| f.generated.get(k).map(|e| (e.id, e.format));
    let secret_value = |f: &'a StackFile, k: &str| f.secrets.get(k).map(|e| &e.sealed);
    let gens = before.generated.keys().chain(after.generated.keys());
    let secrets = before.secrets.keys().chain(after.secrets.keys());
    gens.filter(|k| gen_value(before, k) != gen_value(after, k))
        .chain(secrets.filter(|k| secret_value(before, k) != secret_value(after, k)))
        .map(String::as_str)
        .collect()
}

/// The stacks of `uses` that use a `shared/<key>` name for one of `keys`.
/// Matched by name whatever the marker kind: a stack using
/// `<<gen:shared/x>>` is affected when `secret.x` changes too, erring on
/// the side of deploying.
fn users_of(keys: &BTreeSet<&str>, uses: &Uses) -> Vec<String> {
    uses.iter()
        .filter(|(stack, markers)| {
            markers.iter().any(|m| {
                store::scope(stack, m.name())
                    .is_ok_and(|s| s.file == SHARED && keys.contains(s.key.as_str()))
            })
        })
        .map(|(stack, _)| stack.clone())
        .collect()
}

/// The stacks affected by the changed paths `changed` (repo-relative, as
/// [`crate::git::diff_names`] lists them for `REV..HEAD`):
/// - `stacks/<s>/…` → `s`.
/// - `.sec/<s>.toml` → `s` (any change, orphan flags included: the stack's
///   own store file only changes along with the stack, or by an explicit
///   command).
/// - `.sec/shared.toml` → the stacks in `uses` (the markers of the stacks
///   at `HEAD`) that use a `shared/<name>` whose entry differs between
///   `shared_before` (at `REV`) and `shared_after` (at `HEAD`); see
///   `changed_shared_keys` for what counts as different. Pass an empty
///   [`StackFile`] for a side where the file doesn't exist.
/// - `.sec/meta.toml` → every stack in `existing` (the seed fingerprint or
///   the format version changed, so every value may have).
/// - `stacks/<s>/…` or `.sec/<s>.toml` where `<s>` isn't a valid stack
///   name → nothing, but listed in [`Affected::ignored`]. Such a directory
///   can't be a stack (stack discovery refuses a `compose.yaml` there, so a
///   deploy fails in its checks anyway if one exists), and erroring would
///   block every deploy over, say, a notes directory under `stacks/`.
/// - Anything else → nothing.
///
/// Affected stacks in `existing` (the stacks that have a `compose.yaml` at
/// `HEAD`) go to [`Affected::deploy`], the others to
/// [`Affected::deleted`]. That includes a directory under `stacks/` that
/// never had a `compose.yaml`: from the paths alone lst can't tell it from
/// a deleted stack.
pub fn affected_stacks(
    changed: &[String],
    shared_before: &StackFile,
    shared_after: &StackFile,
    uses: &Uses,
    existing: &BTreeSet<String>,
) -> Affected {
    let mut out = Affected::default();
    let mut stacks = BTreeSet::new();
    for path in changed {
        match classify(path) {
            PathClass::Stack(s) => {
                stacks.insert(s.to_owned());
            }
            PathClass::Shared => {
                let keys = changed_shared_keys(shared_before, shared_after);
                stacks.extend(users_of(&keys, uses));
            }
            PathClass::Meta => stacks.extend(existing.iter().cloned()),
            PathClass::Invalid => {
                out.ignored.insert(path.clone());
            }
            PathClass::Other => {}
        }
    }
    for s in stacks {
        if existing.contains(&s) {
            out.deploy.insert(s);
        } else {
            out.deleted.insert(s);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{GenId, NONCE_LEN, Sealed};
    use crate::format::Format;
    use crate::marker::MarkerKind;
    use crate::store::{GenEntry, SecretEntry};
    use std::env;
    use std::fs;
    use std::process::Output;

    // ---- project names and arguments --------------------------------------

    #[test]
    fn valid_project_names() {
        for name in ["web", "a", "0", "9lives", "my-app_2", "a-", "a_", "x--y__z"] {
            assert!(validate_project_name(name).is_ok(), "{name:?}");
        }
    }

    #[test]
    fn invalid_project_names() {
        for name in [
            "", "Web", "WEB", "webA", "my.app", ".web", "-web", "_web", "a b", "a/b", "../x",
            "ünï", "web\n", "a:b", "😀",
        ] {
            let err = validate_project_name(name).unwrap_err();
            assert!(
                matches!(&err, DeployError::InvalidProjectName { stack } if stack == name),
                "{name:?}: {err:?}"
            );
        }
        let err = validate_project_name("My.App").unwrap_err();
        assert_eq!(
            err.to_string(),
            "stack name \"My.App\" is not a valid docker compose project name (only a-z, 0-9, \
             `_` and `-`, starting with a letter or digit); rename the directory stacks/My.App"
        );
    }

    #[test]
    fn exact_compose_args() {
        let args = compose_args("web", &stack_dir_rel("web"));
        assert_eq!(
            args,
            [
                "compose",
                "-p",
                "web",
                "--project-directory",
                "stacks/web",
                "-f",
                "-",
                "up",
                "-d",
                "--wait",
                "--remove-orphans",
            ]
            .map(OsString::from)
        );
        // The directory is passed through as given.
        assert_eq!(
            compose_args("x", Path::new("/abs/stacks/x"))[4],
            OsString::from("/abs/stacks/x")
        );
    }

    // ---- runner, in this process ------------------------------------------

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }

    /// Rendered text: multi-byte UTF-8, quotes, backslashes and newlines,
    /// `repeat` times.
    fn payload(repeat: usize) -> String {
        "services:\n  app:\n    environment:\n      PW: \"ü€😀 \\ <<x>> 'q'\"\n".repeat(repeat)
    }

    /// Repeats of [`payload`] that make it larger than any pipe buffer.
    const LARGE: usize = 60_000;

    #[test]
    fn large_payload_is_large() {
        assert!(payload(LARGE).len() > 3 * 1024 * 1024);
    }

    #[test]
    fn invalid_name_is_refused_before_running_anything() {
        let dir = tempfile::tempdir().unwrap();
        // Through the public entry point: never reaches a real docker.
        let err = run_compose(dir.path(), "Web", &SecretString::new(payload(1))).unwrap_err();
        assert!(
            matches!(err, DeployError::InvalidProjectName { .. }),
            "{err:?}"
        );
        // A program that would fail to spawn is never tried.
        let missing = dir.path().join("no-such-docker");
        let err = run_compose_with(
            missing.as_os_str(),
            dir.path(),
            "-p",
            &SecretString::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, DeployError::InvalidProjectName { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn spawn_failure_is_distinct() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no-such-docker");
        let err = run_compose_with(
            missing.as_os_str(),
            dir.path(),
            "web",
            &SecretString::default(),
        )
        .unwrap_err();
        assert!(
            matches!(&err, DeployError::Spawn(e) if e.kind() == io::ErrorKind::NotFound),
            "{err:?}"
        );
        assert_eq!(
            err.to_string(),
            "could not run docker (is it installed and on PATH?)"
        );
        // A repository root that doesn't exist can't be the working
        // directory either.
        let err = run_compose_with(
            OsStr::new("true"),
            &dir.path().join("gone"),
            "web",
            &SecretString::default(),
        )
        .unwrap_err();
        assert!(matches!(err, DeployError::Spawn(_)), "{err:?}");
    }

    #[test]
    fn nonzero_exit_is_compose_error() {
        let dir = tempfile::tempdir().unwrap();
        // Small input, and input `false` never reads (the status wins over
        // the broken pipe).
        for rendered in [payload(1), payload(LARGE)] {
            let rendered = SecretString::new(rendered);
            let err =
                run_compose_with(OsStr::new("false"), dir.path(), "web", &rendered).unwrap_err();
            assert!(
                matches!(&err, DeployError::Compose { stack, status }
                    if stack == "web" && status.code() == Some(1)),
                "{err:?}"
            );
            assert_eq!(
                err.to_string(),
                "`docker compose up` for stack \"web\" failed (exit status: 1)"
            );
            assert!(!format!("{err:?}").contains("PW:"));
        }
    }

    #[test]
    fn success_without_reading_input_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let t = OsStr::new("true");
        // Nothing to send: fine.
        run_compose_with(t, dir.path(), "web", &SecretString::default()).unwrap();
        // `true` exits 0 without reading: compose never saw the file.
        let err =
            run_compose_with(t, dir.path(), "web", &SecretString::new(payload(LARGE))).unwrap_err();
        assert!(
            matches!(&err, DeployError::Stdin { stack, source }
                if stack == "web" && source.kind() == io::ErrorKind::BrokenPipe),
            "{err:?}"
        );
        assert_eq!(
            err.to_string(),
            "could not send the rendered compose file of stack \"web\" to docker compose"
        );
        assert!(!format!("{err:?}").contains("PW:"));
    }

    // ---- runner with the fake docker, in a child process -------------------
    //
    // The fake docker is configured through environment variables, and a
    // test can't set those in its own (multi-threaded) process. Checking
    // that compose's stdout never reaches lst's stdout also needs a process
    // whose stdout we can capture. So these tests run `child_run_compose`
    // in a child copy of this test binary, with the environment set there,
    // and inspect the child's stdout/stderr and the fake's records.

    const CHILD_ROOT: &str = "LST_TEST_DEPLOY_ROOT";
    const CHILD_STACK: &str = "LST_TEST_DEPLOY_STACK";
    const CHILD_REPEAT: &str = "LST_TEST_DEPLOY_REPEAT";
    /// `ok`, or `exit:<code>` for the expected `Compose` error.
    const CHILD_EXPECT: &str = "LST_TEST_DEPLOY_EXPECT";
    const FAKE_SEED: &str = "seed-that-must-not-reach-docker";

    /// The child's side: does nothing in a normal test run.
    #[test]
    fn child_run_compose() {
        let Some(root) = env::var_os(CHILD_ROOT) else {
            return;
        };
        let stack = env::var(CHILD_STACK).unwrap();
        let repeat: usize = env::var(CHILD_REPEAT).unwrap().parse().unwrap();
        let rendered = SecretString::new(payload(repeat));
        let fake = fixture("fake-docker");
        let result = run_compose_with(fake.as_os_str(), Path::new(&root), &stack, &rendered);
        let expect = env::var(CHILD_EXPECT).unwrap();
        match expect.strip_prefix("exit:") {
            None => result.unwrap(),
            Some(code) => {
                let err = result.unwrap_err();
                assert!(
                    matches!(&err, DeployError::Compose { stack: s, status }
                        if *s == stack && status.code() == code.parse().ok()),
                    "{err:?}"
                );
            }
        }
    }

    /// Runs `child_run_compose` in a child process with the fake docker
    /// recording into `record`, plus `extra` environment variables.
    fn in_child(
        root: &Path,
        record: &Path,
        stack: &str,
        repeat: usize,
        expect: &str,
        extra: &[(&str, &str)],
    ) -> Output {
        let repeat = repeat.to_string();
        let mut envs = vec![
            (CHILD_ROOT, root.to_str().unwrap()),
            (CHILD_STACK, stack),
            (CHILD_REPEAT, &repeat),
            (CHILD_EXPECT, expect),
        ];
        envs.extend(extra.iter().copied());
        in_child_test("deploy::tests::child_run_compose", record, &envs)
    }

    /// Runs the test `test` in a child copy of this test binary, with the
    /// fake docker recording into `record`, `LST_SEED` set and `envs`, and
    /// checks that it ran and passed.
    fn in_child_test(test: &str, record: &Path, envs: &[(&str, &str)]) -> Output {
        let mut cmd = Command::new(env::current_exe().unwrap());
        cmd.args(["--exact", test, "--nocapture", "--test-threads=1", "-q"]);
        child_output(cmd, record, envs)
    }

    fn child_output(mut cmd: Command, record: &Path, envs: &[(&str, &str)]) -> Output {
        let out = cmd
            .env("LST_FAKE_DOCKER_DIR", record)
            .env(SEED_ENV, FAKE_SEED)
            .env_remove("LST_FAKE_DOCKER_EXIT")
            .env_remove("LST_FAKE_DOCKER_FAIL_PROJECT")
            .env_remove("LST_FAKE_DOCKER_FAIL_SUBCOMMAND")
            .envs(envs.iter().copied())
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "child failed:\n{stdout}\n{stderr}");
        // The child really ran the test (and didn't just filter it out).
        assert!(stdout.contains("1 passed"), "{stdout}");
        out
    }

    /// What the fake docker recorded for call `n`.
    struct Call {
        args: Vec<OsString>,
        stdin: Vec<u8>,
        cwd: PathBuf,
        seed: String,
    }

    fn call(record: &Path, n: usize) -> Call {
        let read = |ext: &str| fs::read(record.join(format!("call-{n}.{ext}"))).unwrap();
        let args = read("args");
        let args = args
            .strip_suffix(b"\0")
            .unwrap()
            .split(|&b| b == 0)
            .map(|a| OsString::from(String::from_utf8(a.to_vec()).unwrap()))
            .collect();
        let cwd = String::from_utf8(read("cwd")).unwrap();
        Call {
            args,
            stdin: read("stdin"),
            cwd: PathBuf::from(cwd.strip_suffix('\n').unwrap()),
            seed: String::from_utf8(read("seed")).unwrap(),
        }
    }

    fn calls(record: &Path) -> usize {
        fs::read_dir(record)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n.to_str().unwrap().ends_with(".args"))
            .count()
    }

    #[test]
    fn runner_pipes_rendered_text_with_exact_args() {
        let root = tempfile::tempdir().unwrap();
        let record = tempfile::tempdir().unwrap();
        let out = in_child(root.path(), record.path(), "web", 1, "ok", &[]);
        assert_eq!(calls(record.path()), 1);
        let c = call(record.path(), 1);
        assert_eq!(c.args, compose_args("web", Path::new("stacks/web")));
        assert_eq!(c.stdin, payload(1).as_bytes());
        assert_eq!(c.cwd, root.path().canonicalize().unwrap());
        // The seed is in lst's environment but not passed on.
        assert_eq!(c.seed, "<unset>");

        // Compose's stdout and stderr both end up on lst's stderr; lst's
        // stdout only has the test harness's own lines.
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!stdout.contains("fake-docker"), "{stdout}");
        assert!(
            stderr.contains("fake-docker: stdout of call 1 (web)\n"),
            "{stderr}"
        );
        assert!(
            stderr.contains("fake-docker: stderr of call 1 (web)\n"),
            "{stderr}"
        );
    }

    #[test]
    fn runner_streams_large_and_empty_input() {
        for repeat in [LARGE, 0] {
            let root = tempfile::tempdir().unwrap();
            let record = tempfile::tempdir().unwrap();
            in_child(root.path(), record.path(), "big", repeat, "ok", &[]);
            let c = call(record.path(), 1);
            assert!(c.stdin == payload(repeat).as_bytes(), "{repeat}");
        }
    }

    #[test]
    fn runner_maps_exit_status() {
        let root = tempfile::tempdir().unwrap();
        let record = tempfile::tempdir().unwrap();
        let exit = [("LST_FAKE_DOCKER_EXIT", "3")];
        in_child(root.path(), record.path(), "web", 1, "exit:3", &exit);
        // It still got the whole input.
        assert_eq!(call(record.path(), 1).stdin, payload(1).as_bytes());
    }

    #[test]
    fn fake_docker_fails_only_the_named_project() {
        let root = tempfile::tempdir().unwrap();
        let record = tempfile::tempdir().unwrap();
        let fail = [("LST_FAKE_DOCKER_FAIL_PROJECT", "db")];
        in_child(root.path(), record.path(), "web", 1, "ok", &fail);
        in_child(root.path(), record.path(), "db", 2, "exit:1", &fail);
        let fail_with = [
            ("LST_FAKE_DOCKER_FAIL_PROJECT", "db"),
            ("LST_FAKE_DOCKER_EXIT", "7"),
        ];
        in_child(root.path(), record.path(), "db", 0, "exit:7", &fail_with);
        // Every call is recorded separately, in order.
        assert_eq!(calls(record.path()), 3);
        let projects: Vec<_> = (1..=3)
            .map(|n| call(record.path(), n).args[2].clone())
            .collect();
        assert_eq!(projects, ["web", "db", "db"]);
        assert_eq!(call(record.path(), 2).stdin, payload(2).as_bytes());
    }

    // ---- x-deploy step arguments -------------------------------------------

    fn secret(s: &str) -> SecretString {
        SecretString::new(s.to_owned())
    }

    fn shell(s: &str) -> StepCommand {
        StepCommand::Shell(secret(s))
    }

    fn exec(argv: &[&str]) -> StepCommand {
        StepCommand::from_argv(argv.iter().map(|a| secret(a)).collect()).unwrap()
    }

    /// `compose -p <stack> --project-directory stacks/<stack> -f -` + `rest`.
    fn compose_prefix(stack: &str, rest: &[&str]) -> Vec<String> {
        let dir = format!("stacks/{stack}");
        [
            "compose",
            "-p",
            stack,
            "--project-directory",
            &dir,
            "-f",
            "-",
        ]
        .iter()
        .chain(rest)
        .map(|s| s.to_string())
        .collect()
    }

    fn args_of(phase: Phase, stack: &str, service: &str, command: &StepCommand) -> Vec<String> {
        step_args(phase, stack, service, command).to_vec()
    }

    #[test]
    fn exact_pre_args() {
        let cmd = "mosquitto_passwd -b -c /mosquitto/config/passwd z2m 's3cr\"t'";
        assert_eq!(
            args_of(Phase::Pre, "mqtt", "mosquitto", &shell(cmd)),
            compose_prefix(
                "mqtt",
                &[
                    "run",
                    "--rm",
                    "--no-deps",
                    "-T",
                    "--",
                    "mosquitto",
                    "sh",
                    "-c",
                    cmd
                ]
            )
        );
        assert_eq!(
            args_of(
                Phase::Pre,
                "mqtt",
                "mosquitto",
                &exec(&["chown", "1883:1883", "/x"])
            ),
            compose_prefix(
                "mqtt",
                &[
                    "run",
                    "--rm",
                    "--no-deps",
                    "-T",
                    "--",
                    "mosquitto",
                    "chown",
                    "1883:1883",
                    "/x"
                ]
            )
        );
    }

    #[test]
    fn exact_post_args() {
        let cmd = "mongosh --eval 'db.createUser({user: \"app\"})'";
        assert_eq!(
            args_of(Phase::Post, "db", "mongo", &shell(cmd)),
            compose_prefix("db", &["exec", "-T", "--", "mongo", "sh", "-c", cmd])
        );
        assert_eq!(
            args_of(Phase::Post, "db", "mongo", &exec(&["mongosh", "--quiet"])),
            compose_prefix("db", &["exec", "-T", "--", "mongo", "mongosh", "--quiet"])
        );
        // A single-element exec form is just the program.
        assert_eq!(
            args_of(Phase::Post, "db", "mongo", &exec(&["true"])),
            compose_prefix("db", &["exec", "-T", "--", "mongo", "true"])
        );
    }

    #[test]
    fn shell_strings_starting_like_options_get_double_dash() {
        let tail = |phase, cmd: &str| {
            let args = args_of(phase, "s", "svc", &shell(cmd));
            let at = args.iter().position(|a| a == "sh").unwrap();
            args[at..].to_vec()
        };
        for phase in [Phase::Pre, Phase::Post] {
            for cmd in ["-x", "--help", "- echo", "+e; echo ok", "+"] {
                assert_eq!(tail(phase, cmd), ["sh", "-c", "--", cmd], "{cmd:?}");
            }
            for cmd in ["echo -x", " -x", "", "x-", "\u{2212}x", "ü"] {
                assert_eq!(tail(phase, cmd), ["sh", "-c", cmd], "{cmd:?}");
            }
        }
    }

    #[test]
    fn exec_args_pass_through_verbatim() {
        // Leading dashes, `--`, empty strings, unicode and whitespace are
        // separate arguments, untouched.
        let argv = [
            "-x",
            "--",
            "",
            "ü€😀",
            "a b\nc",
            "--rm",
            "-T",
            "$HOME",
            "'q'",
        ];
        let args = args_of(Phase::Pre, "s", "svc", &exec(&argv));
        let at = args.iter().position(|a| a == "svc").unwrap();
        assert_eq!(args[at + 1..], argv.map(String::from));
        // A service starting with `-` stays after `--`.
        let args = args_of(Phase::Post, "s", "-svc", &exec(&["true"]));
        assert_eq!(args[9..], ["--", "-svc", "true"].map(String::from));
    }

    #[test]
    fn unicode_and_multiline_shell_strings_are_one_argument() {
        let cmd = "printf '%s\\n' 'ü€😀' \\\n && echo \"$X\"";
        let args = args_of(Phase::Pre, "s", "svc", &shell(cmd));
        assert_eq!(args.last().unwrap(), cmd);
        assert_eq!(args.len(), 16);
    }

    #[test]
    fn empty_exec_form_is_unrepresentable() {
        assert!(StepCommand::from_argv(Vec::new()).is_none());
        let StepCommand::Exec { program, args } =
            StepCommand::from_argv(vec![secret("a"), secret("b"), secret("c")]).unwrap()
        else {
            panic!("not exec form");
        };
        assert_eq!(program.expose(), "a");
        assert_eq!(
            args.iter().map(SecretString::expose).collect::<Vec<_>>(),
            ["b", "c"]
        );
    }

    #[test]
    fn step_commands_debug_redacted() {
        let shown = format!("{:?} {:?}", shell("pw-1"), exec(&["x", "pw-2"]));
        assert!(!shown.contains("pw-"), "{shown}");
        assert!(shown.contains("redacted"), "{shown}");
    }

    #[test]
    fn phase_names() {
        assert_eq!(Phase::Pre.to_string(), "pre");
        assert_eq!(Phase::Post.to_string(), "post");
    }

    #[test]
    fn service_names() {
        for s in ["web", "a", "My.Svc_2", "-x", "_x", ".x", "0"] {
            validate_service_name("st", s).unwrap();
        }
        for s in ["", "a b", "a=b", "a/b", "ü", "a:b", "a\n", "a\0"] {
            let err = validate_service_name("st", s).unwrap_err();
            assert!(
                matches!(&err, DeployError::InvalidServiceName { stack, service }
                    if stack == "st" && service == s),
                "{s:?}: {err:?}"
            );
        }
        assert_eq!(
            validate_service_name("st", "a b").unwrap_err().to_string(),
            "service name \"a b\" of stack \"st\" is not a valid docker compose service name \
             (only a-z, A-Z, 0-9, `.`, `_` and `-`)"
        );
    }

    // ---- x-deploy step runners, in this process -----------------------------

    fn step(phase: Phase, index: usize, service: &str) -> StepRef<'_> {
        StepRef {
            phase,
            index,
            service,
        }
    }

    #[test]
    fn step_runners_validate_before_running_anything() {
        let dir = tempfile::tempdir().unwrap();
        let c = secret("services: {}\n");
        let cmd = shell("true");
        // Through the public entry points: never reaches a real docker.
        for run in [run_pre, run_post] {
            let err = run(dir.path(), "Web", &c, 0, "svc", &cmd).unwrap_err();
            assert!(
                matches!(err, DeployError::InvalidProjectName { .. }),
                "{err:?}"
            );
            let err = run(dir.path(), "web", &c, 0, "a b", &cmd).unwrap_err();
            assert!(
                matches!(err, DeployError::InvalidServiceName { .. }),
                "{err:?}"
            );
        }
        let err = existing_hash(dir.path(), "-p", "svc").unwrap_err();
        assert!(
            matches!(err, DeployError::InvalidProjectName { .. }),
            "{err:?}"
        );
        let err = existing_hash(dir.path(), "web", "").unwrap_err();
        assert!(
            matches!(err, DeployError::InvalidServiceName { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn step_runner_spawn_failure() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no-such-docker");
        for phase in [Phase::Pre, Phase::Post] {
            let err = run_step_with(
                missing.as_os_str(),
                dir.path(),
                "web",
                &secret(""),
                step(phase, 0, "svc"),
                &shell("true"),
            )
            .unwrap_err();
            assert!(
                matches!(&err, DeployError::Spawn(e) if e.kind() == io::ErrorKind::NotFound),
                "{err:?}"
            );
        }
        let err = existing_hash_with(missing.as_os_str(), dir.path(), "web", "svc").unwrap_err();
        assert!(
            matches!(&err, DeployError::Spawn(e) if e.kind() == io::ErrorKind::NotFound),
            "{err:?}"
        );
    }

    #[test]
    fn failing_step_names_stack_phase_index_and_service_only() {
        let dir = tempfile::tempdir().unwrap();
        for (phase, index, rendered) in [
            (Phase::Pre, 2, payload(1)),
            (Phase::Post, 0, payload(LARGE)),
        ] {
            let err = run_step_with(
                OsStr::new("false"),
                dir.path(),
                "web",
                &SecretString::new(rendered),
                step(phase, index, "db"),
                &shell("echo PW-in-command"),
            )
            .unwrap_err();
            assert!(
                matches!(&err, DeployError::Step { stack, phase: p, index: i, service, status }
                    if stack == "web" && *p == phase && *i == index && service == "db"
                        && status.code() == Some(1)),
                "{err:?}"
            );
            let shown = format!("{err} {err:?}");
            assert!(!shown.contains("PW"), "{shown}");
        }
        let err = run_step_with(
            OsStr::new("false"),
            dir.path(),
            "web",
            &secret(""),
            step(Phase::Pre, 3, "mosquitto"),
            &exec(&["x"]),
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "x-deploy.pre[3] (service \"mosquitto\") of stack \"web\" failed (exit status: 1)"
        );
    }

    #[test]
    fn step_success_without_reading_input_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let t = OsStr::new("true");
        let s = step(Phase::Post, 0, "svc");
        run_step_with(t, dir.path(), "web", &secret(""), s, &shell("x")).unwrap();
        let big = SecretString::new(payload(LARGE));
        let err = run_step_with(t, dir.path(), "web", &big, s, &shell("x")).unwrap_err();
        assert!(
            matches!(&err, DeployError::Stdin { stack, source }
                if stack == "web" && source.kind() == io::ErrorKind::BrokenPipe),
            "{err:?}"
        );
    }

    // ---- render-hash query --------------------------------------------------

    #[test]
    fn exact_hash_query_args() {
        assert_eq!(
            hash_query_args("mqtt", "mosquitto"),
            [
                "ps",
                "--all",
                "--no-trunc",
                "--filter",
                "label=com.docker.compose.project=mqtt",
                "--filter",
                "label=com.docker.compose.service=mosquitto",
                "--filter",
                "label=com.docker.compose.oneoff=False",
                "--format",
                "{{.ID}} {{.Label \"lst.render-hash\"}}",
            ]
        );
    }

    #[test]
    fn parse_hash_query_cases() {
        let h = |s: &str| Some(s.to_owned());
        // No container.
        assert_eq!(parse_hash_query(""), None);
        assert_eq!(parse_hash_query("\n\n"), None);
        // One container, with and without the label (docker prints the
        // separator space either way; tolerate it missing too).
        assert_eq!(parse_hash_query("c0ffee 9a8b7c\n"), h("9a8b7c"));
        assert_eq!(parse_hash_query("c0ffee 9a8b7c"), h("9a8b7c"));
        assert_eq!(parse_hash_query("c0ffee \n"), None);
        assert_eq!(parse_hash_query("c0ffee\n"), None);
        // Several containers: the same label, or treat as changed.
        assert_eq!(parse_hash_query("a 1f\nb 1f\nc 1f\n"), h("1f"));
        assert_eq!(parse_hash_query("a 1f\nb 2f\n"), None);
        assert_eq!(parse_hash_query("a 1f\nb \n"), None);
        assert_eq!(parse_hash_query("a \nb \n"), None);
        assert_eq!(parse_hash_query("a \nb 1f\n"), None);
        // Line endings as `str::lines` takes them (CRLF too).
        assert_eq!(parse_hash_query("a 1f\r\nb 1f\n"), Some("1f".to_owned()));
    }

    #[test]
    fn hash_query_failure_and_empty_output() {
        let dir = tempfile::tempdir().unwrap();
        let err = existing_hash_with(OsStr::new("false"), dir.path(), "web", "db").unwrap_err();
        assert!(
            matches!(&err, DeployError::HashQuery { stack, service, status }
                if stack == "web" && service == "db" && status.code() == Some(1)),
            "{err:?}"
        );
        assert_eq!(
            err.to_string(),
            "`docker ps` for service \"db\" of stack \"web\" failed (exit status: 1)"
        );
        // Success with no output: no container.
        assert_eq!(
            existing_hash_with(OsStr::new("true"), dir.path(), "web", "db").unwrap(),
            None
        );
    }

    // ---- step runners and hash query with the fake docker, in a child ------

    const CHILD_OP: &str = "LST_TEST_DEPLOY_OP";
    const CHILD_SERVICE: &str = "LST_TEST_DEPLOY_SERVICE";
    const CHILD_INDEX: &str = "LST_TEST_DEPLOY_INDEX";
    /// A shell-form command; or with CHILD_EXEC, the exec form's arguments
    /// separated by U+001F.
    const CHILD_SHELL: &str = "LST_TEST_DEPLOY_SHELL";
    const CHILD_EXEC: &str = "LST_TEST_DEPLOY_EXEC";

    /// The child's side of the step and hash tests: does nothing in a
    /// normal test run. CHILD_OP is `pre`, `post` or `hash`; CHILD_EXPECT
    /// is `ok` or `step:<code>` (steps), `none`, `some:<hash>`,
    /// `query:<code>` or `output` (hash).
    #[test]
    fn child_step_or_hash() {
        let Some(op) = env::var_os(CHILD_OP) else {
            return;
        };
        let root = PathBuf::from(env::var_os(CHILD_ROOT).unwrap());
        let stack = env::var(CHILD_STACK).unwrap();
        let service = env::var(CHILD_SERVICE).unwrap();
        let expect = env::var(CHILD_EXPECT).unwrap();
        let fake = fixture("fake-docker");
        let program = fake.as_os_str();
        if op == "hash" {
            let result = existing_hash_with(program, &root, &stack, &service);
            match expect.split_once(':') {
                None if expect == "none" => assert_eq!(result.unwrap(), None),
                None => {
                    let err = result.unwrap_err();
                    assert!(
                        matches!(&err, DeployError::HashQueryOutput { stack: s, service: v }
                            if *s == stack && *v == service),
                        "{err:?}"
                    );
                }
                Some(("some", hash)) => assert_eq!(result.unwrap().as_deref(), Some(hash)),
                Some((_query, code)) => {
                    let err = result.unwrap_err();
                    assert!(
                        matches!(&err, DeployError::HashQuery { status, .. }
                            if status.code() == code.parse().ok()),
                        "{err:?}"
                    );
                }
            }
            return;
        }
        let phase = if op == "pre" { Phase::Pre } else { Phase::Post };
        let index: usize = env::var(CHILD_INDEX).unwrap().parse().unwrap();
        let repeat: usize = env::var(CHILD_REPEAT).unwrap().parse().unwrap();
        let command = match env::var(CHILD_EXEC) {
            Ok(argv) => exec(&argv.split('\u{1f}').collect::<Vec<_>>()),
            Err(_) => shell(&env::var(CHILD_SHELL).unwrap()),
        };
        let compose = SecretString::new(payload(repeat));
        let s = step(phase, index, &service);
        let result = run_step_with(program, &root, &stack, &compose, s, &command);
        match expect.strip_prefix("step:") {
            None => result.unwrap(),
            Some(code) => {
                let err = result.unwrap_err();
                assert!(
                    matches!(&err, DeployError::Step { phase: p, index: i, service: v, status, .. }
                        if *p == phase && *i == index && *v == service
                            && status.code() == code.parse().ok()),
                    "{err:?}"
                );
            }
        }
    }

    /// Runs `child_step_or_hash` with `op` for `stack`/`service`, plus
    /// `extra`.
    fn in_child_op(
        op: &str,
        root: &Path,
        record: &Path,
        stack: &str,
        service: &str,
        expect: &str,
        extra: &[(&str, &str)],
    ) -> Output {
        let mut envs = vec![
            (CHILD_OP, op),
            (CHILD_ROOT, root.to_str().unwrap()),
            (CHILD_STACK, stack),
            (CHILD_SERVICE, service),
            (CHILD_EXPECT, expect),
        ];
        envs.extend(extra.iter().copied());
        in_child_test("deploy::tests::child_step_or_hash", record, &envs)
    }

    #[test]
    fn pre_step_pipes_compose_with_exact_args() {
        let root = tempfile::tempdir().unwrap();
        let record = tempfile::tempdir().unwrap();
        let cmd = "mosquitto_passwd -b /c/passwd z2m 'pw ü€'";
        let extra = [(CHILD_INDEX, "0"), (CHILD_REPEAT, "1"), (CHILD_SHELL, cmd)];
        let out = in_child_op(
            "pre",
            root.path(),
            record.path(),
            "mqtt",
            "mosquitto",
            "ok",
            &extra,
        );
        assert_eq!(calls(record.path()), 1);
        let c = call(record.path(), 1);
        let want = args_of(Phase::Pre, "mqtt", "mosquitto", &shell(cmd));
        assert_eq!(c.args, want.iter().map(OsString::from).collect::<Vec<_>>());
        assert_eq!(c.stdin, payload(1).as_bytes());
        assert_eq!(c.cwd, root.path().canonicalize().unwrap());
        assert_eq!(c.seed, "<unset>");
        // The step's stdout and stderr go to lst's stderr.
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!stdout.contains("fake-docker"), "{stdout}");
        assert!(
            stderr.contains("fake-docker: stdout of call 1 (mqtt)\n"),
            "{stderr}"
        );
        assert!(
            stderr.contains("fake-docker: stderr of call 1 (mqtt)\n"),
            "{stderr}"
        );
    }

    #[test]
    fn post_step_exec_form_with_large_input() {
        let root = tempfile::tempdir().unwrap();
        let record = tempfile::tempdir().unwrap();
        let argv = "mongosh\u{1f}--eval\u{1f}-x\u{1f}\u{1f}ü 😀";
        let repeat = LARGE.to_string();
        let extra = [
            (CHILD_INDEX, "1"),
            (CHILD_REPEAT, &repeat),
            (CHILD_EXEC, argv),
        ];
        in_child_op(
            "post",
            root.path(),
            record.path(),
            "db",
            "mongo",
            "ok",
            &extra,
        );
        let c = call(record.path(), 1);
        let want = args_of(
            Phase::Post,
            "db",
            "mongo",
            &exec(&["mongosh", "--eval", "-x", "", "ü 😀"]),
        );
        assert_eq!(c.args, want.iter().map(OsString::from).collect::<Vec<_>>());
        assert!(c.stdin == payload(LARGE).as_bytes());
        assert_eq!(c.seed, "<unset>");
    }

    #[test]
    fn failing_steps_by_subcommand() {
        let root = tempfile::tempdir().unwrap();
        let record = tempfile::tempdir().unwrap();
        let (r, rec) = (root.path(), record.path());
        let base = [(CHILD_REPEAT, "1"), (CHILD_SHELL, "x")];
        let with = |more: &[(&'static str, &'static str)]| {
            let mut v = base.to_vec();
            v.extend_from_slice(more);
            v
        };
        // `run` fails: the pre step fails with the exit code, `exec` doesn't.
        let fail_run = with(&[
            (CHILD_INDEX, "4"),
            ("LST_FAKE_DOCKER_FAIL_SUBCOMMAND", "run"),
            ("LST_FAKE_DOCKER_EXIT", "5"),
        ]);
        in_child_op("pre", r, rec, "web", "app", "step:5", &fail_run);
        in_child_op("post", r, rec, "web", "app", "ok", &fail_run);
        // `exec` fails (default code 1); `run` doesn't.
        let fail_exec = with(&[
            (CHILD_INDEX, "0"),
            ("LST_FAKE_DOCKER_FAIL_SUBCOMMAND", "exec"),
        ]);
        in_child_op("post", r, rec, "web", "app", "step:1", &fail_exec);
        in_child_op("pre", r, rec, "web", "app", "ok", &fail_exec);
        // Both a project and a subcommand: only calls matching both fail.
        let both = with(&[
            (CHILD_INDEX, "0"),
            ("LST_FAKE_DOCKER_FAIL_SUBCOMMAND", "run"),
            ("LST_FAKE_DOCKER_FAIL_PROJECT", "db"),
        ]);
        in_child_op("pre", r, rec, "web", "app", "ok", &both);
        in_child_op("post", r, rec, "db", "app", "ok", &both);
        in_child_op("pre", r, rec, "db", "app", "step:1", &both);
        // A plain non-zero exit fails every step.
        let exit = with(&[(CHILD_INDEX, "0"), ("LST_FAKE_DOCKER_EXIT", "9")]);
        in_child_op("post", r, rec, "web", "app", "step:9", &exit);
        assert_eq!(calls(rec), 8);
        // Every failing call still got the whole compose file.
        for n in 1..=8 {
            assert_eq!(call(rec, n).stdin, payload(1).as_bytes(), "call {n}");
        }
    }

    #[test]
    fn fake_docker_fail_subcommand_spares_up() {
        // The subcommand matcher skips compose's global options and their
        // values (`-f -` included).
        let root = tempfile::tempdir().unwrap();
        let record = tempfile::tempdir().unwrap();
        let fail = [("LST_FAKE_DOCKER_FAIL_SUBCOMMAND", "run")];
        in_child(root.path(), record.path(), "web", 1, "ok", &fail);
        let fail = [("LST_FAKE_DOCKER_FAIL_SUBCOMMAND", "up")];
        in_child(root.path(), record.path(), "web", 1, "exit:1", &fail);
    }

    /// Writes the fake docker's `ps` answer for `stack`/`service`.
    fn ps_answer(record: &Path, stack: &str, service: &str, answer: &[u8]) {
        fs::write(record.join(format!("ps.{stack}.{service}")), answer).unwrap();
    }

    #[test]
    fn existing_hash_via_fake_docker() {
        let root = tempfile::tempdir().unwrap();
        let record = tempfile::tempdir().unwrap();
        let (r, rec) = (root.path(), record.path());
        let id = "c".repeat(64);
        ps_answer(
            rec,
            "mqtt",
            "mosquitto",
            format!("{id} 0123abcd\n").as_bytes(),
        );
        ps_answer(rec, "mqtt", "nolabel", format!("{id} \n").as_bytes());
        ps_answer(rec, "mqtt", "scaled", b"a 77\nb 77\n");
        ps_answer(rec, "mqtt", "mixed", b"a 77\nb 78\n");
        ps_answer(rec, "mqtt", "half", b"a 77\nb \n");
        ps_answer(rec, "mqtt", "bad", b"a \xff\xfe\n");
        // The same service in another project is a different answer.
        ps_answer(rec, "other", "mosquitto", b"a ffff\n");
        let cases = [
            ("mqtt", "mosquitto", "some:0123abcd"),
            ("mqtt", "nolabel", "none"),
            ("mqtt", "absent", "none"),
            ("mqtt", "scaled", "some:77"),
            ("mqtt", "mixed", "none"),
            ("mqtt", "half", "none"),
            ("mqtt", "bad", "output"),
            ("other", "mosquitto", "some:ffff"),
        ];
        for (stack, service, expect) in cases {
            let out = in_child_op("hash", r, rec, stack, service, expect, &[]);
            // Docker's stderr reaches lst's stderr; the answer isn't echoed.
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(stderr.contains("fake-docker: stderr of call"), "{stderr}");
            assert!(!String::from_utf8_lossy(&out.stdout).contains("fake-docker"));
        }
        assert_eq!(calls(rec), cases.len());
        for (n, (stack, service, _)) in cases.iter().enumerate() {
            let c = call(rec, n + 1);
            let want: Vec<OsString> = hash_query_args(stack, service)
                .into_iter()
                .map(OsString::from)
                .collect();
            assert_eq!(c.args, want);
            assert!(c.stdin.is_empty());
            assert_eq!(c.cwd, r.canonicalize().unwrap());
            assert_eq!(c.seed, "<unset>");
        }
        let err = DeployError::HashQueryOutput {
            stack: "mqtt".into(),
            service: "bad".into(),
        };
        assert_eq!(
            err.to_string(),
            "`docker ps` for service \"bad\" of stack \"mqtt\" printed something that isn't UTF-8"
        );
    }

    #[test]
    fn existing_hash_query_failure_via_fake_docker() {
        let root = tempfile::tempdir().unwrap();
        let record = tempfile::tempdir().unwrap();
        ps_answer(record.path(), "web", "app", b"a 11\n");
        let fail_ps = [
            ("LST_FAKE_DOCKER_FAIL_SUBCOMMAND", "ps"),
            ("LST_FAKE_DOCKER_EXIT", "2"),
        ];
        in_child_op(
            "hash",
            root.path(),
            record.path(),
            "web",
            "app",
            "query:2",
            &fail_ps,
        );
        // Failing `run` doesn't affect `ps`.
        let fail_run = [("LST_FAKE_DOCKER_FAIL_SUBCOMMAND", "run")];
        in_child_op(
            "hash",
            root.path(),
            record.path(),
            "web",
            "app",
            "some:11",
            &fail_run,
        );
    }

    // ---- affected stacks ---------------------------------------------------

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn paths(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn gen_entry(id: u8, format: Format, orphan: bool) -> GenEntry {
        GenEntry {
            id: GenId([id; 16]),
            format,
            orphan,
        }
    }

    fn secret_entry(nonce: u8, ct: u8, orphan: bool) -> SecretEntry {
        SecretEntry {
            sealed: Sealed {
                nonce: [nonce; NONCE_LEN],
                ciphertext: vec![ct; 20],
            },
            orphan,
        }
    }

    /// A shared.toml with gen `mqtt` and secret `smtp`.
    fn shared_base() -> StackFile {
        let mut f = StackFile::default();
        f.generated
            .insert("mqtt".into(), gen_entry(1, Format::default(), false));
        f.secrets.insert("smtp".into(), secret_entry(2, 3, false));
        f
    }

    fn uses() -> Uses {
        let gen_marker = |name: &str| MarkerKind::Gen {
            name: name.into(),
            format: Format::default(),
        };
        let secret = |name: &str| MarkerKind::Secret { name: name.into() };
        let mut u = Uses::new();
        u.insert(
            "z2m".into(),
            vec![gen_marker("db"), gen_marker("shared/mqtt")],
        );
        u.insert("mosquitto".into(), vec![gen_marker("shared/mqtt")]);
        u.insert("mail".into(), vec![secret("shared/smtp"), secret("local")]);
        // Stack-local keys that happen to be called like the shared ones.
        u.insert("web".into(), vec![gen_marker("mqtt"), secret("smtp")]);
        u.insert("empty".into(), vec![]);
        u
    }

    fn existing() -> BTreeSet<String> {
        set(&["empty", "mail", "mosquitto", "web", "z2m"])
    }

    fn affected(changed: &[&str], before: &StackFile, after: &StackFile) -> Affected {
        affected_stacks(&paths(changed), before, after, &uses(), &existing())
    }

    fn deploys(changed: &[&str]) -> BTreeSet<String> {
        let a = affected(changed, &shared_base(), &shared_base());
        assert!(a.deleted.is_empty() && a.ignored.is_empty(), "{a:?}");
        a.deploy
    }

    #[test]
    fn nothing_changed() {
        assert_eq!(deploys(&[]), set(&[]));
    }

    #[test]
    fn stack_files_affect_their_stack() {
        assert_eq!(deploys(&["stacks/web/compose.yaml"]), set(&["web"]));
        assert_eq!(
            deploys(&["stacks/web/config/deep/x.conf", "stacks/z2m/README"]),
            set(&["web", "z2m"])
        );
        assert_eq!(deploys(&[".sec/mail.toml"]), set(&["mail"]));
        assert_eq!(
            deploys(&[".sec/mail.toml", "stacks/mail/compose.yaml"]),
            set(&["mail"])
        );
    }

    #[test]
    fn unrelated_paths_affect_nothing() {
        let a = affected(
            &[
                "README.md",
                ".gitignore",
                "docs/plan.md",
                ".woodpecker.yml",
                "stacks",
                "stacks/web",
                "stacks/notes.md",
                "stacks/web/",
                "stacksweb/compose.yaml",
                "stacks.d/web/compose.yaml",
                "x/stacks/web/compose.yaml",
                ".sec",
                ".sec/README",
                ".sec/web.json",
                ".sec/web.toml.bak",
                ".sec/sub/web.toml",
                ".secret/web.toml",
                "sec/web.toml",
            ],
            &StackFile::default(),
            &shared_base(),
        );
        assert_eq!(a, Affected::default());
    }

    #[test]
    fn invalid_stack_names_are_ignored_and_listed() {
        let changed = [
            "stacks/Bad Name/compose.yaml",
            "stacks/.hidden/x",
            "stacks/shared/compose.yaml",
            "stacks/META/compose.yaml",
            "stacks/ünï/compose.yaml",
            ".sec/Shared.toml",
            ".sec/.toml",
            ".sec/bad name.toml",
            "stacks/web/compose.yaml",
        ];
        let a = affected(&changed, &shared_base(), &shared_base());
        assert_eq!(a.deploy, set(&["web"]));
        assert!(a.deleted.is_empty());
        assert_eq!(a.ignored, set(&changed[..8]));
    }

    #[test]
    fn names_valid_for_the_store_but_not_compose_are_affected() {
        // Uppercase and dots are fine stack names; the deploy itself
        // refuses them with `validate_project_name`.
        let mut ex = existing();
        ex.insert("My.App".into());
        let a = affected_stacks(
            &paths(&["stacks/My.App/compose.yaml"]),
            &shared_base(),
            &shared_base(),
            &uses(),
            &ex,
        );
        assert_eq!(a.deploy, set(&["My.App"]));
    }

    #[test]
    fn deleted_stacks_are_reported_not_deployed() {
        let a = affected(
            &[
                "stacks/old/compose.yaml",
                ".sec/old.toml",
                ".sec/gone.toml",
                "stacks/notes/todo.md",
                "stacks/web/compose.yaml",
            ],
            &shared_base(),
            &shared_base(),
        );
        assert_eq!(a.deploy, set(&["web"]));
        assert_eq!(a.deleted, set(&["gone", "notes", "old"]));
        assert!(a.ignored.is_empty());
    }

    #[test]
    fn meta_affects_every_existing_stack() {
        assert_eq!(deploys(&[".sec/meta.toml"]), existing());
        let a = affected_stacks(
            &paths(&[".sec/meta.toml", "stacks/old/compose.yaml"]),
            &shared_base(),
            &shared_base(),
            &uses(),
            &set(&["web"]),
        );
        assert_eq!(a.deploy, set(&["web"]));
        assert_eq!(a.deleted, set(&["old"]));
        // No stacks at all.
        let a = affected_stacks(
            &paths(&[".sec/meta.toml"]),
            &shared_base(),
            &shared_base(),
            &uses(),
            &set(&[]),
        );
        assert_eq!(a, Affected::default());
    }

    /// The stacks deployed for a `.sec/shared.toml` change from `before`
    /// to `after`.
    fn shared_change(before: &StackFile, after: &StackFile) -> BTreeSet<String> {
        let a = affected(&[".sec/shared.toml"], before, after);
        assert!(a.deleted.is_empty() && a.ignored.is_empty(), "{a:?}");
        a.deploy
    }

    #[test]
    fn shared_unchanged_entries_affect_nothing() {
        assert_eq!(shared_change(&shared_base(), &shared_base()), set(&[]));
    }

    #[test]
    fn shared_gen_changes() {
        let base = shared_base();
        let users = set(&["mosquitto", "z2m"]);
        // Rotated (new id).
        let mut after = shared_base();
        after.generated.get_mut("mqtt").unwrap().id = GenId([9; 16]);
        assert_eq!(shared_change(&base, &after), users);
        // Format changed.
        let mut after = shared_base();
        after.generated.get_mut("mqtt").unwrap().format = Format::Hex(64);
        assert_eq!(shared_change(&base, &after), users);
        // Removed, and added.
        let mut after = shared_base();
        after.generated.remove("mqtt");
        assert_eq!(shared_change(&base, &after), users);
        assert_eq!(shared_change(&after, &base), users);
        // Missing file on one side.
        assert_eq!(
            shared_change(&StackFile::default(), &base),
            set(&["mail", "mosquitto", "z2m"])
        );
    }

    #[test]
    fn shared_secret_changes() {
        let base = shared_base();
        let users = set(&["mail"]);
        let mut after = shared_base();
        after.secrets.get_mut("smtp").unwrap().sealed.nonce = [7; NONCE_LEN];
        assert_eq!(shared_change(&base, &after), users);
        let mut after = shared_base();
        after.secrets.get_mut("smtp").unwrap().sealed.ciphertext = vec![7; 20];
        assert_eq!(shared_change(&base, &after), users);
        let mut after = shared_base();
        after.secrets.remove("smtp");
        assert_eq!(shared_change(&base, &after), users);
        assert_eq!(shared_change(&after, &base), users);
    }

    #[test]
    fn shared_orphan_flag_alone_redeploys_nothing() {
        let base = shared_base();
        let mut after = shared_base();
        after.generated.get_mut("mqtt").unwrap().orphan = true;
        after.secrets.get_mut("smtp").unwrap().orphan = true;
        assert_eq!(shared_change(&base, &after), set(&[]));
        assert_eq!(shared_change(&after, &base), set(&[]));
        // But an orphan flag together with a value change does.
        after.generated.get_mut("mqtt").unwrap().id = GenId([9; 16]);
        assert_eq!(shared_change(&base, &after), set(&["mosquitto", "z2m"]));
    }

    #[test]
    fn shared_change_to_a_name_no_stack_uses() {
        let base = shared_base();
        let mut after = shared_base();
        after
            .generated
            .insert("unused".into(), gen_entry(5, Format::Uuid, false));
        after
            .secrets
            .insert("other".into(), secret_entry(5, 5, false));
        // `web` uses stack-local `mqtt`/`smtp`, never the shared ones.
        assert_eq!(shared_change(&base, &after), set(&[]));
    }

    #[test]
    fn shared_matches_by_name_whatever_the_kind() {
        // `shared/smtp` is used as a secret by `mail`; a gen entry of the
        // same key appearing still redeploys it (conservative).
        let base = shared_base();
        let mut after = shared_base();
        after
            .generated
            .insert("smtp".into(), gen_entry(5, Format::default(), false));
        assert_eq!(shared_change(&base, &after), set(&["mail"]));
    }

    #[test]
    fn shared_and_stack_changes_combine() {
        let mut after = shared_base();
        after.secrets.remove("smtp");
        let a = affected(
            &[
                ".sec/shared.toml",
                "stacks/web/compose.yaml",
                "stacks/old/x",
            ],
            &shared_base(),
            &after,
        );
        assert_eq!(a.deploy, set(&["mail", "web"]));
        assert_eq!(a.deleted, set(&["old"]));
        // shared.toml not in the change set: before/after aren't compared.
        let a = affected(&["stacks/web/compose.yaml"], &shared_base(), &after);
        assert_eq!(a.deploy, set(&["web"]));
    }

    #[test]
    fn users_with_unscopable_stack_names_are_skipped() {
        // A stack name the store can't scope never matches (it can't come
        // out of discovery, but `uses` is the caller's input).
        let mut u = Uses::new();
        u.insert(
            "Bad Name".into(),
            vec![MarkerKind::Secret {
                name: "shared/smtp".into(),
            }],
        );
        let mut after = shared_base();
        after.secrets.remove("smtp");
        let a = affected_stacks(
            &paths(&[".sec/shared.toml"]),
            &shared_base(),
            &after,
            &u,
            &set(&["Bad Name"]),
        );
        assert_eq!(a, Affected::default());
    }

    #[test]
    fn classify_paths() {
        assert_eq!(classify("stacks/web/compose.yaml"), PathClass::Stack("web"));
        assert_eq!(classify(".sec/web.toml"), PathClass::Stack("web"));
        assert_eq!(classify(".sec/shared.toml"), PathClass::Shared);
        assert_eq!(classify(".sec/meta.toml"), PathClass::Meta);
        assert_eq!(classify("stacks/shared/x"), PathClass::Invalid);
        assert_eq!(classify("stacks/web"), PathClass::Other);
        assert_eq!(classify("README"), PathClass::Other);
    }
}
