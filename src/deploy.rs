//! `lst deploy`: running `docker compose up` on a rendered stack, and
//! working out which stacks `--changed-since REV` affects.
//!
//! [`validate_project_name`], [`compose_args`] and [`affected_stacks`] are
//! pure. [`run_compose`] is the thin runner around them.
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
//! # Affected stacks (`--changed-since REV`)
//! See [`affected_stacks`].

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

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
    let mut child = Command::new(program)
        .args(compose_args(stack, &stack_dir_rel(stack)))
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
        stdin.write_all(rendered.expose().as_bytes())
    };
    let status = child.wait().map_err(DeployError::Wait)?;
    if !status.success() {
        return Err(DeployError::Compose {
            stack: stack.to_owned(),
            status,
        });
    }
    // Compose exited 0 without taking all of the input: whatever it
    // deployed is not what lst rendered.
    if let Err(source) = written {
        return Err(DeployError::Stdin {
            stack: stack.to_owned(),
            source,
        });
    }
    Ok(())
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
        let out = Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "deploy::tests::child_run_compose",
                "--nocapture",
                "--test-threads=1",
                "-q",
            ])
            .env(CHILD_ROOT, root)
            .env(CHILD_STACK, stack)
            .env(CHILD_REPEAT, repeat.to_string())
            .env(CHILD_EXPECT, expect)
            .env("LST_FAKE_DOCKER_DIR", record)
            .env(SEED_ENV, FAKE_SEED)
            .env_remove("LST_FAKE_DOCKER_EXIT")
            .env_remove("LST_FAKE_DOCKER_FAIL_PROJECT")
            .envs(extra.iter().copied())
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
