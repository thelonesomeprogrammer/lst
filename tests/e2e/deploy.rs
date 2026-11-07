//! `lst deploy`, against the fake docker (`tests/fixtures/fake-docker`):
//! what compose is run with, in which order, what stops a deploy before
//! anything runs, and which stacks `--changed-since` picks.
//!
//! The fake is put on `PATH` as `docker` through a temp dir holding a
//! symlink to it, in front of the inherited `PATH`, so a real docker on the
//! machine is never run.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use tempfile::TempDir;

use crate::support::{Repo, Run, lst_cmd};

/// Plaintext values these tests set; never in lst's output.
const PLAINTEXTS: &[&str] = &[
    "d3pl0y-t0k",
    "5mtp-v4l",
    "n3w-t0k",
    "n3w-5mtp",
    "l34k-v4l",
    "n0te-v4l",
];

const OTHER_SEED: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/// A temp dir with `docker` → the fake, and a temp dir it records into.
struct Fake {
    bin: TempDir,
    record: TempDir,
}

/// What the fake recorded for one call.
#[derive(Debug)]
struct Call {
    args: Vec<String>,
    stdin: Vec<u8>,
    cwd: PathBuf,
    seed: String,
}

impl Fake {
    fn new() -> Fake {
        let bin = tempfile::tempdir().unwrap();
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-docker");
        symlink(fixture, bin.path().join("docker")).unwrap();
        Fake {
            bin,
            record: tempfile::tempdir().unwrap(),
        }
    }

    /// The fake's directory in front of the inherited `PATH`.
    fn path(&self) -> OsString {
        let mut dirs = vec![self.bin.path().to_owned()];
        dirs.extend(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        ));
        std::env::join_paths(dirs).unwrap()
    }

    /// Every recorded call, in order.
    fn calls(&self) -> Vec<Call> {
        let dir = self.record.path();
        let mut out = Vec::new();
        for n in 1.. {
            let base = dir.join(format!("call-{n}"));
            let read = |ext: &str| fs::read(base.with_extension(ext)).unwrap();
            if !base.with_extension("args").exists() {
                break;
            }
            let args = read("args");
            let args = args
                .strip_suffix(b"\0")
                .unwrap()
                .split(|&b| b == 0)
                .map(|a| String::from_utf8(a.to_vec()).unwrap())
                .collect();
            let cwd = String::from_utf8(read("cwd")).unwrap();
            out.push(Call {
                args,
                stdin: read("stdin"),
                cwd: PathBuf::from(cwd.strip_suffix('\n').unwrap()),
                seed: String::from_utf8(read("seed")).unwrap(),
            });
        }
        // Nothing else was recorded (`ps.*` are a test's scripted answers).
        let files = fs::read_dir(dir)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_str()
                    .unwrap()
                    .starts_with("call-")
            })
            .count();
        assert_eq!(files, out.len() * 4);
        out
    }

    /// The stacks deployed, in order.
    fn projects(&self) -> Vec<String> {
        self.calls()
            .into_iter()
            .map(|c| c.args[2].clone())
            .collect()
    }
}

/// The exact compose arguments for `stack`.
fn compose_args(stack: &str) -> Vec<String> {
    let dir = format!("stacks/{stack}");
    [
        "compose",
        "-p",
        stack,
        "--project-directory",
        &dir,
        "-f",
        "-",
        "up",
        "-d",
        "--wait",
        "--remove-orphans",
    ]
    .map(String::from)
    .to_vec()
}

/// How to run one `lst deploy`.
struct Opts<'a> {
    /// `LST_SEED`, if set.
    seed: Option<&'a str>,
    /// `PATH`; the fake's [`Fake::path`] if `None`.
    path: Option<OsString>,
    /// More environment variables for lst (and so the fake).
    env: &'a [(&'a str, &'a str)],
    /// The umask lst runs with, if not the inherited one.
    umask: Option<&'a str>,
}

const DEFAULT: Opts<'static> = Opts {
    seed: None,
    path: None,
    env: &[],
    umask: None,
};

/// `lst deploy <args>` in `repo` with the fake docker. Asserts that it
/// wrote nothing outside `.git/`, printed nothing on stdout, and that no
/// plaintext and no part of `seed_hex` (the repo's seed) or `OTHER_SEED`
/// is in its output.
#[track_caller]
fn deploy(repo: &Repo, fake: &Fake, args: &[&str], seed_hex: &str, opts: Opts<'_>) -> Run {
    let before = repo.snapshot();
    let mut all = vec!["deploy"];
    all.extend_from_slice(args);
    let mut cmd = match opts.umask {
        None => lst_cmd(repo.path(), &all),
        Some(umask) => {
            // `sh` sets the umask, then becomes lst, with lst_cmd's
            // environment.
            let mut c = Command::new("sh");
            c.args(["-c", "umask \"$0\" && exec \"$@\"", umask])
                .arg(env!("CARGO_BIN_EXE_lst"))
                .args(&all)
                .current_dir(repo.path())
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env_remove("LST_SEED")
                .stdin(Stdio::null());
            c
        }
    };
    cmd.env("PATH", opts.path.unwrap_or_else(|| fake.path()))
        .env("LST_FAKE_DOCKER_DIR", fake.record.path())
        .env_remove("LST_FAKE_DOCKER_EXIT")
        .env_remove("LST_FAKE_DOCKER_FAIL_PROJECT")
        .env_remove("LST_FAKE_DOCKER_FAIL_SUBCOMMAND")
        .envs(opts.env.iter().copied());
    if let Some(s) = opts.seed {
        cmd.env("LST_SEED", s);
    }
    let run = Run::from_output(cmd.output().unwrap());
    assert_eq!(run.stdout, "", "{run:#?}");
    let out = format!("{}{}", run.stdout, run.stderr);
    for seed in [seed_hex, OTHER_SEED] {
        for half in [&seed[..32], &seed[32..]] {
            assert!(!out.contains(half), "seed leaked: {run:#?}");
        }
    }
    for p in PLAINTEXTS {
        assert!(!out.contains(p), "{p} leaked: {run:#?}");
    }
    assert_eq!(repo.snapshot(), before, "deploy wrote something");
    run
}

/// `lst deploy` that must succeed, with the fake's default behaviour.
#[track_caller]
fn deploy_ok(repo: &Repo, fake: &Fake, args: &[&str]) -> Run {
    let run = deploy(repo, fake, args, &repo.seed_hex(), DEFAULT);
    run.ok();
    run
}

/// The stderr of a successful deploy of `stacks` as calls `first..` of
/// the fake: its two lines, then lst's `deployed` line, per stack.
fn deployed_stderr(stacks: &[&str], first: usize) -> String {
    stacks
        .iter()
        .zip(first..)
        .map(|(s, n)| {
            format!(
                "fake-docker: stdout of call {n} ({s})\nfake-docker: stderr of call {n} ({s})\n\
                 lst: deployed {s}\n"
            )
        })
        .collect()
}

/// Commits everything through the hook.
#[track_caller]
fn commit_all(repo: &Repo, msg: &str) {
    repo.git(&["add", "-A"]);
    let run = repo.commit(&["-m", msg]);
    assert_eq!(run.code, Some(0), "{run:#?}");
}

/// Commits everything without the hook.
#[track_caller]
fn commit_all_no_verify(repo: &Repo, msg: &str) {
    repo.git(&["add", "-A"]);
    let run = repo.commit(&["--no-verify", "-m", msg]);
    assert_eq!(run.code, Some(0), "{run:#?}");
}

fn svc(lines: &str) -> String {
    format!("services:\n  app:\n    image: busybox\n    environment:\n{lines}")
}

/// Four stacks committed through the hook:
/// - `a`: `a/db`, `shared/mqtt`;
/// - `b`: `b/tok` (manual), `shared/mqtt`;
/// - `c`: `c/c1`, `shared/smtp` (manual, set here);
/// - `d`: `shared/smtp`.
fn repo() -> Repo {
    let repo = Repo::initialised();
    repo.compose(
        "a",
        &svc("      PW: <<gen:db>>\n      MQTT: <<gen:shared/mqtt:hex64>>\n"),
    );
    repo.compose(
        "b",
        &svc("      TOK: '<<set:tok:d3pl0y-t0k>>'\n      MQTT: <<gen:shared/mqtt:hex64>>\n"),
    );
    repo.compose(
        "c",
        &svc("      C1: <<gen:c1:uuid>>\n      SMTP: '<<set:shared/smtp:5mtp-v4l>>'\n"),
    );
    repo.compose("d", &svc("      SMTP: '<<secret:shared/smtp>>'\n"));
    commit_all(&repo, "stacks");
    repo
}

/// `lst render <stack>` (with `.env`).
fn render(repo: &Repo, stack: &str) -> String {
    repo.lst(&["render", stack]).ok().to_owned()
}

// ---------------------------------------------------------------------------
// explicit stacks
// ---------------------------------------------------------------------------

#[test]
fn deploys_one_stack_with_exact_args_and_rendered_stdin() {
    let repo = repo();
    let fake = Fake::new();
    let run = deploy_ok(&repo, &fake, &["b"]);
    assert_eq!(run.stderr, deployed_stderr(&["b"], 1));

    let calls = fake.calls();
    assert_eq!(calls.len(), 1);
    let c = &calls[0];
    assert_eq!(c.args, compose_args("b"));
    assert_eq!(c.cwd, repo.path().canonicalize().unwrap());
    assert_eq!(c.seed, "<unset>");
    // Byte for byte what `lst render` prints, with the values in it.
    let rendered = render(&repo, "b");
    assert_eq!(String::from_utf8(c.stdin.clone()).unwrap(), rendered);
    assert!(rendered.contains("TOK: 'd3pl0y-t0k'\n"), "{rendered}");
    let mqtt = repo.expected_gen("shared", "mqtt", "hex64".parse().unwrap());
    assert!(rendered.contains(&format!("MQTT: {mqtt}\n")), "{rendered}");
}

#[test]
fn deploys_several_stacks_sorted_and_deduplicated() {
    let repo = repo();
    let fake = Fake::new();
    let run = deploy_ok(&repo, &fake, &["d", "a", "c", "a", "d", "b"]);
    assert_eq!(run.stderr, deployed_stderr(&["a", "b", "c", "d"], 1));
    let calls = fake.calls();
    for (c, s) in calls.iter().zip(["a", "b", "c", "d"]) {
        assert_eq!(c.args, compose_args(s));
        assert_eq!(c.stdin, render(&repo, s).as_bytes());
        assert_eq!(c.seed, "<unset>");
        assert_eq!(c.cwd, repo.path().canonicalize().unwrap());
    }
    assert_eq!(calls.len(), 4);
}

#[test]
fn deploys_from_a_subdirectory() {
    let repo = repo();
    let fake = Fake::new();
    let before = repo.snapshot();
    let out = lst_cmd(&repo.path().join("stacks/a"), &["deploy", "a"])
        .env("PATH", fake.path())
        .env("LST_FAKE_DOCKER_DIR", fake.record.path())
        .output()
        .unwrap();
    let run = Run::from_output(out);
    assert_eq!(run.ok(), "");
    assert_eq!(run.stderr, deployed_stderr(&["a"], 1));
    assert_eq!(repo.snapshot(), before);
    // Still run in the repository root.
    let calls = fake.calls();
    assert_eq!(calls[0].cwd, repo.path().canonicalize().unwrap());
    assert_eq!(calls[0].args, compose_args("a"));
}

#[test]
fn a_fresh_clone_deploys_with_only_lst_seed() {
    let origin = repo();
    let seed = origin.seed_hex();
    let clone = origin.clone_repo();
    assert!(!clone.exists(".env"));
    let fake = Fake::new();

    // No seed at all: nothing runs.
    let run = deploy(&clone, &fake, &["a"], &seed, DEFAULT);
    run.fails_with(&["no .env file", "LST_SEED environment variable"]);
    assert!(fake.calls().is_empty());

    let opts = Opts {
        seed: Some(&seed),
        ..DEFAULT
    };
    let run = deploy(&clone, &fake, &["a", "c"], &seed, opts);
    assert_eq!(run.ok(), "");
    assert_eq!(run.stderr, deployed_stderr(&["a", "c"], 1));
    let calls = fake.calls();
    assert_eq!(calls.len(), 2);
    for (c, s) in calls.iter().zip(["a", "c"]) {
        assert_eq!(c.args, compose_args(s));
        // The same bytes the origin (seed in .env) renders.
        assert_eq!(c.stdin, render(&origin, s).as_bytes());
        // The seed is in lst's environment, but never in compose's.
        assert_eq!(c.seed, "<unset>");
        assert_eq!(c.cwd, clone.path().canonicalize().unwrap());
    }
}

#[test]
fn an_unknown_stack_deploys_nothing() {
    let repo = repo();
    let fake = Fake::new();
    let seed = repo.seed_hex();
    deploy(&repo, &fake, &["a", "nope"], &seed, DEFAULT)
        .fails_with(&["unknown stack \"nope\" (known stacks: a, b, c, d)"]);
    deploy(&repo, &fake, &["../a"], &seed, DEFAULT).fails_with(&["invalid stack name \"../a\""]);
    deploy(&repo, &fake, &["shared"], &seed, DEFAULT).fails_with(&["\"shared\" is reserved"]);
    assert!(fake.calls().is_empty());
}

#[test]
fn an_invalid_project_name_deploys_nothing() {
    let repo = repo();
    repo.compose("MyApp", &svc("      X: <<gen:x>>\n"));
    repo.compose("my.app", &svc("      X: <<gen:x>>\n"));
    commit_all(&repo, "bad names");
    let fake = Fake::new();
    let seed = repo.seed_hex();
    for (args, name) in [
        (&["a", "MyApp"][..], "MyApp"),
        (&["my.app", "a"][..], "my.app"),
    ] {
        let run = deploy(&repo, &fake, args, &seed, DEFAULT);
        run.fails_with(&[&format!(
            "stack name {name:?} is not a valid docker compose project name"
        )]);
        assert!(
            run.stderr
                .contains(&format!("rename the directory stacks/{name}"))
        );
    }
    // Picked by --changed-since: the same.
    deploy(&repo, &fake, &["--changed-since", "HEAD~1"], &seed, DEFAULT)
        .fails_with(&["stack name \"MyApp\" is not a valid docker compose project name"]);
    assert!(fake.calls().is_empty());
}

#[test]
fn usage_errors_exit_2_and_deploy_nothing() {
    let repo = repo();
    let fake = Fake::new();
    let seed = repo.seed_hex();
    for args in [&[][..], &["a", "--changed-since", "HEAD"][..]] {
        let run = deploy(&repo, &fake, args, &seed, DEFAULT);
        assert_eq!(run.code, Some(2), "{run:#?}");
        assert!(run.stderr.contains("Usage: lst deploy"), "{run:#?}");
    }
    // --changed-since needs a value.
    let run = deploy(&repo, &fake, &["--changed-since"], &seed, DEFAULT);
    assert_eq!(run.code, Some(2), "{run:#?}");
    assert!(fake.calls().is_empty());
}

// ---------------------------------------------------------------------------
// failures
// ---------------------------------------------------------------------------

#[test]
fn a_compose_failure_stops_the_deploy() {
    let repo = repo();
    let fake = Fake::new();
    let opts = Opts {
        env: &[("LST_FAKE_DOCKER_FAIL_PROJECT", "b")],
        ..DEFAULT
    };
    let run = deploy(&repo, &fake, &["c", "b", "a"], &repo.seed_hex(), opts);
    // stderr starts with compose's output, so not `fails_with`.
    assert_eq!(run.code, Some(1), "{run:#?}");
    let mut want = deployed_stderr(&["a"], 1);
    want.push_str(
        "fake-docker: stdout of call 2 (b)\nfake-docker: stderr of call 2 (b)\n\
         lst: `docker compose up` for stack \"b\" failed (exit status: 1) (deployed: a; \
         failed: b; not attempted: c)\n",
    );
    assert_eq!(run.stderr, want);
    // b got its whole input; c was never run.
    assert_eq!(fake.projects(), ["a", "b"]);
    assert_eq!(fake.calls()[1].stdin, render(&repo, "b").as_bytes());

    // The first stack failing: nothing deployed.
    let fake = Fake::new();
    let opts = Opts {
        env: &[("LST_FAKE_DOCKER_EXIT", "4")],
        ..DEFAULT
    };
    let run = deploy(&repo, &fake, &["a", "b"], &repo.seed_hex(), opts);
    assert_eq!(run.code, Some(1), "{run:#?}");
    assert!(
        run.stderr.ends_with(
            "\nlst: `docker compose up` for stack \"a\" failed (exit status: 4) (deployed: none; \
             failed: a; not attempted: b)\n"
        ),
        "{run:#?}"
    );
    assert_eq!(fake.projects(), ["a"]);
}

#[test]
fn docker_missing_from_path_is_a_clear_error() {
    let repo = repo();
    let fake = Fake::new();
    // A PATH with git and nothing else.
    let git_only = tempfile::tempdir().unwrap();
    let path = std::env::var_os("PATH").unwrap_or_default();
    let git = std::env::split_paths(&path)
        .map(|d| d.join("git"))
        .find(|g| g.is_file())
        .unwrap();
    symlink(git, git_only.path().join("git")).unwrap();
    let opts = Opts {
        path: Some(git_only.path().as_os_str().to_owned()),
        ..DEFAULT
    };
    let run = deploy(&repo, &fake, &["b", "a"], &repo.seed_hex(), opts);
    assert_eq!(
        run.fails_with(&[]),
        "lst: could not run docker (is it installed and on PATH?) (deployed: none; failed: a; \
         not attempted: b)\n"
    );
    assert!(fake.calls().is_empty());
}

#[test]
fn a_stale_store_deploys_nothing() {
    let repo = repo();
    let fake = Fake::new();
    repo.compose("a", &svc("      PW: <<gen:db>>\n      NEW: <<gen:new>>\n"));
    let run = deploy(&repo, &fake, &["b"], &repo.seed_hex(), DEFAULT);
    run.fails_with(&["a/new is new", "check failed: 1 problem"]);
    assert!(fake.calls().is_empty());
}

#[test]
fn a_committed_set_deploys_nothing() {
    let repo = repo();
    let fake = Fake::new();
    repo.compose(
        "a",
        &svc("      PW: <<gen:db>>\n      X: <<set:x:l34k-v4l>>\n"),
    );
    commit_all_no_verify(&repo, "no hook");
    // Even when the working tree is fixed again: it is in history.
    repo.compose(
        "a",
        &svc("      PW: <<gen:db>>\n      MQTT: <<gen:shared/mqtt:hex64>>\n"),
    );
    let run = deploy(&repo, &fake, &["b"], &repo.seed_hex(), DEFAULT);
    run.fails_with(&["stacks/a/compose.yaml", "rotate", "check failed: 1 problem"]);
    assert!(fake.calls().is_empty());
}

#[test]
fn a_wrong_seed_deploys_nothing() {
    let repo = repo();
    let clone = repo.clone_repo();
    let fake = Fake::new();
    let opts = Opts {
        seed: Some(OTHER_SEED),
        ..DEFAULT
    };
    let run = deploy(&clone, &fake, &["a"], &repo.seed_hex(), opts);
    run.fails_with(&["wrong seed", "check failed: 1 problem"]);
    let opts = Opts {
        seed: Some(OTHER_SEED),
        ..DEFAULT
    };
    deploy(
        &clone,
        &fake,
        &["--changed-since", "HEAD"],
        &repo.seed_hex(),
        opts,
    )
    .fails_with(&["wrong seed"]);
    assert!(fake.calls().is_empty());
}

// ---------------------------------------------------------------------------
// --changed-since
// ---------------------------------------------------------------------------

/// `lst deploy --changed-since <rev>` that must succeed; returns stderr.
#[track_caller]
fn changed_since(repo: &Repo, fake: &Fake, rev: &str) -> String {
    deploy_ok(repo, fake, &["--changed-since", rev])
        .stderr
        .clone()
}

#[test]
fn changed_since_nothing_changed() {
    let repo = repo();
    let fake = Fake::new();
    assert_eq!(
        changed_since(&repo, &fake, "HEAD"),
        "lst: nothing to deploy\n"
    );
    // A change outside any stack.
    repo.write("README.md", "docs\n");
    commit_all(&repo, "docs");
    assert_eq!(
        changed_since(&repo, &fake, "HEAD~1"),
        "lst: nothing to deploy\n"
    );
    assert!(fake.calls().is_empty());
}

#[test]
fn changed_since_a_stack_file() {
    let repo = repo();
    let fake = Fake::new();
    repo.write("stacks/c/config/app.conf", "x = 1\n");
    repo.compose(
        "a",
        &svc("      PW: <<gen:db>>\n      MQTT: <<gen:shared/mqtt:hex64>>\n      Y: 1\n"),
    );
    commit_all(&repo, "a and c");
    assert_eq!(
        changed_since(&repo, &fake, "HEAD~1"),
        deployed_stderr(&["a", "c"], 1)
    );
    let calls = fake.calls();
    assert_eq!(calls[0].args, compose_args("a"));
    assert_eq!(calls[0].stdin, render(&repo, "a").as_bytes());
    assert_eq!(calls[1].args, compose_args("c"));
    assert_eq!(calls.len(), 2);
    // A range of several commits, given as a full commit id.
    repo.write("stacks/d/config/d.conf", "d\n");
    commit_all(&repo, "d");
    let fake = Fake::new();
    let rev = repo.git_stdout(&["rev-parse", "HEAD~2"]);
    changed_since(&repo, &fake, rev.trim());
    assert_eq!(fake.projects(), ["a", "c", "d"]);
}

#[test]
fn changed_since_a_store_file() {
    let repo = repo();
    let fake = Fake::new();
    // A new value for b/tok: the hook rewrites the marker back, so only
    // .sec/b.toml changes.
    repo.compose(
        "b",
        &svc("      TOK: '<<set:tok:n3w-t0k>>'\n      MQTT: <<gen:shared/mqtt:hex64>>\n"),
    );
    commit_all(&repo, "new tok");
    assert_eq!(
        repo.git_stdout(&["diff", "--name-only", "HEAD~1", "HEAD"]),
        ".sec/b.toml\n"
    );
    assert_eq!(
        changed_since(&repo, &fake, "HEAD~1"),
        deployed_stderr(&["b"], 1)
    );
    let rendered = String::from_utf8(fake.calls()[0].stdin.clone()).unwrap();
    assert!(rendered.contains("TOK: 'n3w-t0k'\n"));
}

#[test]
fn changed_since_a_shared_entry_deploys_only_its_users() {
    let repo = repo();
    let fake = Fake::new();
    // A new value for shared/smtp, set from c: c's file ends up as before,
    // so only .sec/shared.toml changes; c and d use the name, a and b
    // (which use shared/mqtt from the same file) don't.
    repo.compose(
        "c",
        &svc("      C1: <<gen:c1:uuid>>\n      SMTP: '<<set:shared/smtp:n3w-5mtp>>'\n"),
    );
    commit_all(&repo, "new smtp");
    assert_eq!(
        repo.git_stdout(&["diff", "--name-only", "HEAD~1", "HEAD"]),
        ".sec/shared.toml\n"
    );
    assert_eq!(
        changed_since(&repo, &fake, "HEAD~1"),
        deployed_stderr(&["c", "d"], 1)
    );
    for c in fake.calls() {
        assert!(
            String::from_utf8(c.stdin)
                .unwrap()
                .contains("SMTP: 'n3w-5mtp'\n")
        );
    }
}

#[test]
fn changed_since_a_shared_file_that_did_not_exist() {
    let repo = Repo::initialised();
    repo.compose("a", &svc("      X: <<gen:x>>\n"));
    repo.compose("b", &svc("      X: <<gen:x>>\n"));
    commit_all(&repo, "no shared");
    assert!(!repo.exists(".sec/shared.toml"));
    repo.compose("b", &svc("      X: <<gen:shared/x>>\n"));
    commit_all(&repo, "shared");
    let fake = Fake::new();
    // b changed and uses the new name; a doesn't.
    assert_eq!(
        changed_since(&repo, &fake, "HEAD~1"),
        deployed_stderr(&["b"], 1)
    );
}

#[test]
fn changed_since_a_deleted_stack_with_an_orphaned_shared_name() {
    let repo = repo();
    let fake = Fake::new();
    // c and d are the only users of shared/smtp: deleting both orphans it
    // (its entry's orphan flag is the only change in shared.toml). d has
    // no entries of its own, so there is no .sec/d.toml.
    fs::remove_dir_all(repo.path().join("stacks/c")).unwrap();
    fs::remove_dir_all(repo.path().join("stacks/d")).unwrap();
    commit_all(&repo, "rm c d");
    let diff = repo.git_stdout(&["diff", "--name-only", "HEAD~1", "HEAD"]);
    assert_eq!(
        diff,
        ".sec/c.toml\n.sec/shared.toml\nstacks/c/compose.yaml\nstacks/d/compose.yaml\n"
    );
    let shared = repo.git_stdout(&["diff", "-U0", "HEAD~1", "HEAD", "--", ".sec/shared.toml"]);
    let changed: Vec<_> = shared
        .lines()
        .filter(|l| l.starts_with(['+', '-']) && !l.starts_with("+++") && !l.starts_with("---"))
        .collect();
    assert_eq!(changed, ["-orphan = false", "+orphan = true"], "{shared}");
    // shared.toml only changed in orphan flags: nobody is redeployed.
    assert_eq!(
        changed_since(&repo, &fake, "HEAD~1"),
        "lst: not deploying c: it changed but has no stacks/c/compose.yaml any more (lst does \
         not tear stacks down; run `docker compose -p c down` if it should go)\n\
         lst: not deploying d: it changed but has no stacks/d/compose.yaml any more (lst does \
         not tear stacks down; run `docker compose -p d down` if it should go)\n\
         lst: nothing to deploy\n"
    );
    assert!(fake.calls().is_empty());
}

#[test]
fn changed_since_meta_deploys_every_stack() {
    let repo = repo();
    let fake = Fake::new();
    let meta = repo.read(".sec/meta.toml");
    // An older meta.toml (anything: it isn't read at REV), then back.
    repo.write(".sec/meta.toml", format!("{meta}# old\n"));
    commit_all_no_verify(&repo, "old meta");
    repo.write(".sec/meta.toml", &meta);
    commit_all_no_verify(&repo, "meta");
    assert_eq!(
        changed_since(&repo, &fake, "HEAD~1"),
        deployed_stderr(&["a", "b", "c", "d"], 1)
    );
}

#[test]
fn changed_since_an_ignored_path() {
    let repo = repo();
    let fake = Fake::new();
    repo.write("stacks/Bad Name/notes.md", "no stack\n");
    repo.write("stacks/a/notes.md", "a's notes\n");
    commit_all(&repo, "notes");
    assert_eq!(
        changed_since(&repo, &fake, "HEAD~1"),
        format!(
            "lst: ignoring stacks/Bad Name/notes.md: not a valid stack name, so it belongs to no \
             stack\n{}",
            deployed_stderr(&["a"], 1)
        )
    );
}

#[test]
fn changed_since_an_unknown_rev() {
    let repo = repo();
    let fake = Fake::new();
    let seed = repo.seed_hex();
    for rev in [
        "nope",
        "0123456789abcdef0123456789abcdef01234567",
        "HEAD~5",
        "HEAD^{tree}",
    ] {
        let run = deploy(&repo, &fake, &["--changed-since", rev], &seed, DEFAULT);
        assert_eq!(
            run.fails_with(&[]),
            format!(
                "lst: --changed-since: unknown revision {rev:?} (not a commit in this \
                 repository). Is this a shallow clone? Fetch more history (in Woodpecker: a \
                 larger `clone: depth`), or deploy the stacks explicitly\n"
            )
        );
    }
    assert!(fake.calls().is_empty());
}

#[test]
fn changed_since_a_bad_shared_file_at_rev() {
    let repo = repo();
    let fake = Fake::new();
    let seed = repo.seed_hex();
    let shared = repo.read(".sec/shared.toml");
    for (old, want) in [
        (
            b"[gen\n".to_vec(),
            "--changed-since HEAD~1: in that revision, .sec/shared.toml: invalid TOML at line 1",
        ),
        (
            b"\xff\xfe".to_vec(),
            "--changed-since HEAD~1: in that revision, .sec/shared.toml is not valid UTF-8",
        ),
    ] {
        repo.write(".sec/shared.toml", old);
        commit_all_no_verify(&repo, "broken");
        repo.write(".sec/shared.toml", &shared);
        commit_all_no_verify(&repo, "fixed");
        deploy(&repo, &fake, &["--changed-since", "HEAD~1"], &seed, DEFAULT).fails_with(&[want]);
    }
    assert!(fake.calls().is_empty());
}

#[test]
fn changed_since_a_non_utf8_path() {
    let repo = repo();
    let fake = Fake::new();
    let name = OsStr::from_bytes(b"notes-\xff.md");
    fs::write(repo.path().join(name), "x\n").unwrap();
    commit_all_no_verify(&repo, "non-utf8 path");
    fs::remove_file(repo.path().join(name)).unwrap();
    commit_all_no_verify(&repo, "gone");
    deploy(
        &repo,
        &fake,
        &["--changed-since", "HEAD~1"],
        &repo.seed_hex(),
        DEFAULT,
    )
    .fails_with(&["changed path \"notes-\u{fffd}.md\" is not valid UTF-8"]);
    assert!(fake.calls().is_empty());
}

#[test]
fn changed_since_with_lst_seed_in_a_fresh_clone() {
    let origin = repo();
    repo_change_a(&origin);
    let seed = origin.seed_hex();
    let clone = origin.clone_repo();
    let fake = Fake::new();
    let opts = Opts {
        seed: Some(&seed),
        ..DEFAULT
    };
    let run = deploy(&clone, &fake, &["--changed-since", "HEAD~1"], &seed, opts);
    assert_eq!(run.ok(), "");
    assert_eq!(run.stderr, deployed_stderr(&["a"], 1));
    let calls = fake.calls();
    assert_eq!(calls[0].stdin, render(&origin, "a").as_bytes());
    assert_eq!(calls[0].seed, "<unset>");
}

/// Changes and commits stack `a` only.
fn repo_change_a(repo: &Repo) {
    repo.compose(
        "a",
        &svc("      PW: <<gen:db>>\n      MQTT: <<gen:shared/mqtt:hex64>>\n      Z: 2\n"),
    );
    commit_all(repo, "a");
}

// ---------------------------------------------------------------------------
// x-deploy: render: files, pre/post steps, on-change
// ---------------------------------------------------------------------------

/// The manual secret of the x-deploy stack: `"`, `#` and `: ` (in
/// PLAINTEXTS through its prefix).
const NOTE: &str = "n0te-v4l\"ue #1: x";

const MOSQUITTO_CONF: &str =
    "listener 1883\npassword_file /mosquitto/config/passwd\n# z2m <<gen:shared/mqtt-z2m>>\n";
const EXTRA: &str = "note=<<secret:note>>\n";

/// The compose file of the `mq` stack, its `to:` paths under `out`.
fn mq_compose(out: &Path) -> String {
    let d = out.display();
    format!(
        "\
services:
  mosquitto:
    image: eclipse-mosquitto:2
    ports:
      - \"18883:1883\"
    volumes:
      - {d}/mosquitto:/mosquitto/config
  db:
    image: postgres:17-alpine
    environment:
      NOTE: '<<set:note:{NOTE}>>'
  app:
    image: busybox
    environment:
      PW: <<gen:app-pw>>
x-deploy:
  render:
    - from: config/mosquitto.conf
      to: {d}/mosquitto/mosquitto.conf
      mode: \"0644\"
    - from: ./config//extra.txt
      to: {d}/extra/extra.txt
  pre:
    - with: mosquitto
      run: mosquitto_passwd -b -c /mosquitto/config/passwd z2m <<gen:shared/mqtt-z2m>>
    - with: mosquitto
      run: [chown, \"1883:1883\", /mosquitto/config/passwd]
      when: on-change
  post:
    - exec: db
      run: psql -U postgres -c \"ALTER ROLE app1 PASSWORD '<<gen:pg-app1>>'\"
      when: on-change
    - exec: app
      run: [echo, <<gen:app-pw>>]
"
    )
}

/// A repository with the x-deploy stack `mq` (render targets under a temp
/// dir) and the plain stacks `a` and `z`, committed through the hook.
struct XRepo {
    repo: Repo,
    out: TempDir,
}

/// What one call of the fake should have been, for stack `mq`.
enum Want {
    Ps(&'static str),
    Pre(usize),
    Up,
    Post(usize),
}

/// Every call of a full deploy of `mq` with nothing skipped.
const ALL: [Want; 7] = [
    Want::Ps("db"),
    Want::Ps("mosquitto"),
    Want::Pre(0),
    Want::Pre(1),
    Want::Up,
    Want::Post(0),
    Want::Post(1),
];

impl XRepo {
    fn new() -> XRepo {
        let repo = Repo::initialised();
        let out = tempfile::tempdir().unwrap();
        repo.compose("mq", &mq_compose(out.path()));
        repo.write("stacks/mq/config/mosquitto.conf", MOSQUITTO_CONF);
        repo.write("stacks/mq/config/extra.txt", EXTRA);
        repo.compose("a", &svc("      X: <<gen:x>>\n"));
        repo.compose("z", &svc("      X: <<gen:x>>\n"));
        commit_all(&repo, "stacks");
        assert!(
            repo.read("stacks/mq/compose.yaml")
                .contains("'<<secret:note>>'")
        );
        XRepo { repo, out }
    }

    fn conf(&self) -> PathBuf {
        self.out.path().join("mosquitto/mosquitto.conf")
    }

    fn extra(&self) -> PathBuf {
        self.out.path().join("extra/extra.txt")
    }

    fn gen_value(&self, file: &str, key: &str) -> String {
        self.repo
            .expected_gen(file, key, "alnum32".parse().unwrap())
    }

    /// Every generated value of the repo; none may be in lst's output.
    fn gens(&self) -> Vec<String> {
        vec![
            self.gen_value("shared", "mqtt-z2m"),
            self.gen_value("mq", "pg-app1"),
            self.gen_value("mq", "app-pw"),
            self.gen_value("a", "x"),
        ]
    }

    /// The `lst.render-hash` `lst render mq` gives `service`.
    fn hash(&self, service: &str) -> String {
        let rendered = render(&self.repo, "mq");
        let v: serde_yaml_ng::Value = serde_yaml_ng::from_str(&rendered).unwrap();
        v["services"][service]["labels"]["lst.render-hash"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// `lst deploy <args>` (see [`deploy`]), also asserting that no
    /// generated value is in its output.
    #[track_caller]
    fn deploy(&self, fake: &Fake, args: &[&str], opts: Opts<'_>) -> Run {
        let run = deploy(&self.repo, fake, args, &self.repo.seed_hex(), opts);
        for g in self.gens() {
            assert!(
                !run.stderr.contains(&g),
                "a generated value leaked: {run:#?}"
            );
        }
        run
    }

    /// The exact arguments of `want`.
    fn args(&self, want: &Want) -> Vec<String> {
        let run = ["run", "--rm", "--no-deps", "-T"];
        let exec = ["exec", "-T"];
        match want {
            Want::Ps(service) => ps_args("mq", service),
            Want::Pre(0) => {
                let z2m = self.gen_value("shared", "mqtt-z2m");
                let cmd = format!("mosquitto_passwd -b -c /mosquitto/config/passwd z2m {z2m}");
                step_args(&run, "mosquitto", &["sh", "-c", &cmd])
            }
            Want::Pre(_) => step_args(
                &run,
                "mosquitto",
                &["chown", "1883:1883", "/mosquitto/config/passwd"],
            ),
            Want::Up => compose_args("mq"),
            Want::Post(0) => {
                let pg = self.gen_value("mq", "pg-app1");
                let cmd = format!("psql -U postgres -c \"ALTER ROLE app1 PASSWORD '{pg}'\"");
                step_args(&exec, "db", &["sh", "-c", &cmd])
            }
            Want::Post(_) => step_args(&exec, "app", &["echo", &self.gen_value("mq", "app-pw")]),
        }
    }

    /// Asserts that `calls` are exactly `wants`: arguments, the compose
    /// file on stdin (nothing for `ps`), the repository root as working
    /// directory and no seed.
    #[track_caller]
    fn assert_calls(&self, calls: &[Call], wants: &[Want]) {
        let rendered = render(&self.repo, "mq");
        assert_eq!(calls.len(), wants.len(), "{calls:#?}");
        for (c, w) in calls.iter().zip(wants) {
            assert_eq!(c.args, self.args(w));
            let stdin: &[u8] = match w {
                Want::Ps(_) => b"",
                _ => rendered.as_bytes(),
            };
            assert!(c.stdin == stdin, "{c:#?}");
            assert_eq!(c.cwd, self.repo.path().canonicalize().unwrap());
            assert_eq!(c.seed, "<unset>");
        }
    }
}

/// Scripts the fake's `docker ps` answer for `service` of `mq`.
fn ps_answer(fake: &Fake, service: &str, answer: &str) {
    let file = fake.record.path().join(format!("ps.mq.{service}"));
    fs::write(file, answer).unwrap();
}

/// The exact `docker ps` arguments for the render hash of `service`.
fn ps_args(stack: &str, service: &str) -> Vec<String> {
    let project = format!("label=com.docker.compose.project={stack}");
    let svc = format!("label=com.docker.compose.service={service}");
    [
        "ps",
        "--all",
        "--no-trunc",
        "--filter",
        &project,
        "--filter",
        &svc,
        "--filter",
        "label=com.docker.compose.oneoff=False",
        "--format",
        "{{.ID}} {{.Label \"lst.render-hash\"}}",
    ]
    .map(String::from)
    .to_vec()
}

/// `compose -p mq --project-directory stacks/mq -f - <sub> -- <service> <cmd>`.
fn step_args(sub: &[&str], service: &str, cmd: &[&str]) -> Vec<String> {
    let mut args = compose_args("mq")[..7].to_vec();
    args.extend(sub.iter().map(|s| s.to_string()));
    args.push("--".into());
    args.push(service.into());
    args.extend(cmd.iter().map(|s| s.to_string()));
    args
}

fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

/// The fake's two lines for call `n` of `mq` that prints to stdout (`run`,
/// `up`, `exec`).
fn noisy(n: usize) -> String {
    format!("fake-docker: stdout of call {n} (mq)\nfake-docker: stderr of call {n} (mq)\n")
}

/// The fake's line for `ps` call `n` (its stdout is lst's to read).
fn quiet(n: usize) -> String {
    format!("fake-docker: stderr of call {n} (mq)\n")
}

/// `lst render mq --file <from>`.
fn render_file(repo: &Repo, from: &str) -> String {
    repo.lst(&["render", "mq", "--file", from]).ok().to_owned()
}

#[test]
fn x_deploy_first_deploy_runs_everything_in_order() {
    let x = XRepo::new();
    let fake = Fake::new();
    let opts = Opts {
        umask: Some("077"),
        ..DEFAULT
    };
    let run = x.deploy(&fake, &["mq"], opts);
    run.ok();
    // The on-change services' hashes are read first (sorted), then the
    // files are written, then pre, up, post.
    let (conf, extra) = (x.conf(), x.extra());
    let want = format!(
        "{}{}lst: wrote {}\nlst: wrote {}\n{}{}{}{}{}lst: deployed mq\n",
        quiet(1),
        quiet(2),
        conf.display(),
        extra.display(),
        noisy(3),
        noisy(4),
        noisy(5),
        noisy(6),
        noisy(7),
    );
    assert_eq!(run.stderr, want);
    x.assert_calls(&fake.calls(), &ALL);

    // The files: what `lst render --file` prints, with the requested mode
    // whatever the umask (077 would have made 0644 into 0600).
    assert_eq!(
        fs::read_to_string(&conf).unwrap(),
        render_file(&x.repo, "config/mosquitto.conf")
    );
    assert_eq!(
        fs::read_to_string(&extra).unwrap(),
        render_file(&x.repo, "config/extra.txt")
    );
    assert_eq!(
        fs::read_to_string(&extra).unwrap(),
        format!("note={NOTE}\n")
    );
    assert_eq!(mode_of(&conf), 0o644);
    assert_eq!(mode_of(&extra), 0o600);
    // Nothing else was written there (no temporary files left).
    let names = |dir: &Path| -> Vec<_> {
        fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect()
    };
    assert_eq!(names(x.out.path()).len(), 2);
    assert_eq!(names(conf.parent().unwrap()), ["mosquitto.conf"]);
    assert_eq!(names(extra.parent().unwrap()), ["extra.txt"]);
}

#[test]
fn x_deploy_again_skips_on_change_steps_when_the_hash_is_unchanged() {
    let x = XRepo::new();
    x.deploy(&Fake::new(), &["mq"], DEFAULT).ok();
    let (conf, extra) = (x.conf(), x.extra());
    let written = |p: &Path| fs::symlink_metadata(p).unwrap().modified().unwrap();
    let before = (written(&conf), written(&extra));

    // The containers carry the new hashes: on-change steps are skipped,
    // the files are left alone, always steps run.
    let fake = Fake::new();
    ps_answer(&fake, "db", &format!("0123abc {}\n", x.hash("db")));
    let mosquitto = format!("4567def {}\n", x.hash("mosquitto"));
    ps_answer(&fake, "mosquitto", &mosquitto);
    let run = x.deploy(&fake, &["mq"], DEFAULT);
    run.ok();
    assert_eq!(
        run.stderr,
        format!(
            "{}{}{}lst: skipped x-deploy.pre[1] (mosquitto): inputs unchanged\n{}lst: skipped \
             x-deploy.post[0] (db): inputs unchanged\n{}lst: deployed mq\n",
            quiet(1),
            quiet(2),
            noisy(3),
            noisy(4),
            noisy(5),
        )
    );
    x.assert_calls(
        &fake.calls(),
        &[
            Want::Ps("db"),
            Want::Ps("mosquitto"),
            Want::Pre(0),
            Want::Up,
            Want::Post(1),
        ],
    );
    assert_eq!((written(&conf), written(&extra)), before);

    // Another hash, no label, no container, or replicas that disagree:
    // changed, so the step runs.
    let other = "0".repeat(64);
    for (db, mosquitto) in [
        (format!("0123abc {other}\n"), "4567def \n".to_owned()),
        (
            String::new(),
            format!("a {}\nb {other}\n", x.hash("mosquitto")),
        ),
    ] {
        let fake = Fake::new();
        ps_answer(&fake, "db", &db);
        ps_answer(&fake, "mosquitto", &mosquitto);
        let run = x.deploy(&fake, &["mq"], DEFAULT);
        run.ok();
        assert!(!run.stderr.contains("skipped"), "{run:#?}");
        x.assert_calls(&fake.calls(), &ALL);
    }
    // One unchanged, one without a container: only that one is skipped.
    let fake = Fake::new();
    ps_answer(&fake, "db", &format!("0123abc {}\n", x.hash("db")));
    let run = x.deploy(&fake, &["mq"], DEFAULT);
    run.ok();
    assert!(
        run.stderr.contains("skipped x-deploy.post[0] (db)"),
        "{run:#?}"
    );
    assert!(!run.stderr.contains("skipped x-deploy.pre"), "{run:#?}");
    x.assert_calls(
        &fake.calls(),
        &[
            Want::Ps("db"),
            Want::Ps("mosquitto"),
            Want::Pre(0),
            Want::Pre(1),
            Want::Up,
            Want::Post(1),
        ],
    );
}

#[test]
fn x_deploy_rewrites_changed_files_and_fixes_modes() {
    use std::os::unix::fs::PermissionsExt;
    let x = XRepo::new();
    x.deploy(&Fake::new(), &["mq"], DEFAULT).ok();
    let (conf, extra) = (x.conf(), x.extra());

    // A changed file is rewritten, a wrong mode fixed, the rest left alone.
    fs::write(&conf, "edited by hand\n").unwrap();
    fs::set_permissions(&extra, fs::Permissions::from_mode(0o666)).unwrap();
    let run = x.deploy(&Fake::new(), &["mq"], DEFAULT);
    run.ok();
    assert!(
        run.stderr.contains(&format!(
            "\nlst: wrote {}\nlst: mode fixed {}\n",
            conf.display(),
            extra.display()
        )),
        "{run:#?}"
    );
    assert_eq!(
        fs::read_to_string(&conf).unwrap(),
        render_file(&x.repo, "config/mosquitto.conf")
    );
    assert_eq!(mode_of(&extra), 0o600);

    // A target lst refuses: nothing runs after the hash reads.
    fs::remove_file(&extra).unwrap();
    fs::create_dir(&extra).unwrap();
    let fake = Fake::new();
    let run = x.deploy(&fake, &["mq"], DEFAULT);
    assert_eq!(run.code, Some(1), "{run:#?}");
    assert!(
        run.stderr.ends_with(&format!(
            "lst: refusing to write the rendered file {}: it is not a regular file (deployed: \
             none; failed: mq; not attempted: none)\n",
            extra.display()
        )),
        "{run:#?}"
    );
    x.assert_calls(&fake.calls(), &[Want::Ps("db"), Want::Ps("mosquitto")]);
}

#[test]
fn x_deploy_pre_failure_stops_before_up() {
    let x = XRepo::new();
    let fake = Fake::new();
    let opts = Opts {
        env: &[("LST_FAKE_DOCKER_FAIL_SUBCOMMAND", "run")],
        ..DEFAULT
    };
    let run = x.deploy(&fake, &["mq", "z", "a"], opts);
    assert_eq!(run.code, Some(1), "{run:#?}");
    assert!(
        run.stderr.ends_with(
            "lst: x-deploy.pre[0] (service \"mosquitto\") of stack \"mq\" failed (exit status: \
             1), so `docker compose up` did not run for this stack (deployed: a; failed: mq; not \
             attempted: z)\n"
        ),
        "{run:#?}"
    );
    let calls = fake.calls();
    assert_eq!(calls[0].args, compose_args("a"));
    x.assert_calls(
        &calls[1..],
        &[Want::Ps("db"), Want::Ps("mosquitto"), Want::Pre(0)],
    );
    // The files written before the failing step stay.
    assert!(x.conf().is_file() && x.extra().is_file());
}

#[test]
fn x_deploy_post_failure_is_an_error_after_up() {
    let x = XRepo::new();
    let fake = Fake::new();
    let opts = Opts {
        env: &[("LST_FAKE_DOCKER_FAIL_SUBCOMMAND", "exec")],
        ..DEFAULT
    };
    let run = x.deploy(&fake, &["mq"], opts);
    assert_eq!(run.code, Some(1), "{run:#?}");
    assert!(
        run.stderr.ends_with(
            "lst: x-deploy.post[0] (service \"db\") of stack \"mq\" failed (exit status: 1); the \
             stack is up (`docker compose up` succeeded), but its remaining post steps did not \
             run (deployed: none; failed: mq; not attempted: none)\n"
        ),
        "{run:#?}"
    );
    x.assert_calls(&fake.calls(), &ALL[..6]);
}

#[test]
fn x_deploy_failure_in_the_second_of_three_stacks() {
    let x = XRepo::new();
    let fake = Fake::new();
    let opts = Opts {
        env: &[
            ("LST_FAKE_DOCKER_FAIL_PROJECT", "mq"),
            ("LST_FAKE_DOCKER_FAIL_SUBCOMMAND", "exec"),
        ],
        ..DEFAULT
    };
    let run = x.deploy(&fake, &["z", "mq", "a"], opts);
    assert_eq!(run.code, Some(1), "{run:#?}");
    assert!(
        run.stderr.starts_with(&deployed_stderr(&["a"], 1)),
        "{run:#?}"
    );
    assert!(
        run.stderr.ends_with(
            "remaining post steps did not run (deployed: a; failed: mq; not attempted: z)\n"
        ),
        "{run:#?}"
    );
    let calls = fake.calls();
    // a: exactly the M3 call; z never ran.
    assert_eq!(calls[0].args, compose_args("a"));
    assert_eq!(calls[0].stdin, render(&x.repo, "a").as_bytes());
    x.assert_calls(&calls[1..], &ALL[..6]);
}

#[test]
fn x_deploy_next_to_plain_stacks() {
    let x = XRepo::new();
    let fake = Fake::new();
    let run = x.deploy(&fake, &["z", "mq", "a"], DEFAULT);
    run.ok();
    let calls = fake.calls();
    assert_eq!(calls.len(), 9);
    // The plain stacks: one `up` each, exactly as in M3.
    for (c, s) in [(&calls[0], "a"), (&calls[8], "z")] {
        assert_eq!(c.args, compose_args(s));
        assert_eq!(c.stdin, render(&x.repo, s).as_bytes());
        assert_eq!(c.seed, "<unset>");
    }
    assert!(
        run.stderr.starts_with(&deployed_stderr(&["a"], 1)),
        "{run:#?}"
    );
    assert!(
        run.stderr.ends_with(&deployed_stderr(&["z"], 9)),
        "{run:#?}"
    );
    x.assert_calls(&calls[1..8], &ALL);
}

#[test]
fn x_deploy_hash_query_failure_changes_nothing() {
    let x = XRepo::new();
    let fake = Fake::new();
    let opts = Opts {
        env: &[("LST_FAKE_DOCKER_FAIL_SUBCOMMAND", "ps")],
        ..DEFAULT
    };
    let run = x.deploy(&fake, &["mq"], opts);
    assert_eq!(run.code, Some(1), "{run:#?}");
    assert!(
        run.stderr.ends_with(
            "lst: `docker ps` for service \"db\" of stack \"mq\" failed (exit status: 1) \
             (deployed: none; failed: mq; not attempted: none)\n"
        ),
        "{run:#?}"
    );
    x.assert_calls(&fake.calls(), &[Want::Ps("db")]);
    assert!(!x.out.path().join("mosquitto").exists());
}

#[test]
fn x_deploy_checks_service_names_before_anything_runs() {
    let x = XRepo::new();
    // A service name YAML and the model accept, but compose doesn't.
    let text = x
        .repo
        .read("stacks/mq/compose.yaml")
        .replace("  app:\n", "  \"my app\":\n")
        .replace("    - exec: app\n", "    - exec: my app\n");
    x.repo.compose("mq", &text);
    commit_all(&x.repo, "bad service name");
    let fake = Fake::new();
    let run = x.deploy(&fake, &["mq"], DEFAULT);
    run.fails_with(&[
        "service name \"my app\" of stack \"mq\" is not a valid docker compose service name",
        "(deployed: none; failed: mq; not attempted: none)",
    ]);
    assert!(fake.calls().is_empty());
    assert!(!x.out.path().join("mosquitto").exists());
}

#[test]
fn x_deploy_without_on_change_steps_queries_nothing() {
    let x = XRepo::new();
    let text = x
        .repo
        .read("stacks/mq/compose.yaml")
        .replace("      when: on-change\n", "");
    x.repo.compose("mq", &text);
    commit_all(&x.repo, "always");
    let fake = Fake::new();
    // Even with containers carrying the new hashes: `always` runs.
    ps_answer(&fake, "db", &format!("0123abc {}\n", x.hash("db")));
    let run = x.deploy(&fake, &["mq"], DEFAULT);
    run.ok();
    x.assert_calls(&fake.calls(), &ALL[2..]);
}

// ---------------------------------------------------------------------------
// `$` in values (compose interpolation)
// ---------------------------------------------------------------------------

/// A manual secret with `$` in it, as stored and as compose must see it.
const DOLLAR: &str = "pa$wo$$rd";
const DOLLAR_COMPOSE: &str = "pa$$wo$$$$rd";

/// Every `$` of a substituted value is doubled in the compose text lst
/// produces (both render paths), so compose's interpolation turns it back
/// into the stored value; `$` the user wrote is left alone; values that
/// don't go through compose (`render:` files, `run:` commands) are raw.
#[test]
fn dollar_in_values_is_escaped_only_where_compose_reads_it() {
    let repo = Repo::initialised();
    let out = tempfile::tempdir().unwrap();
    let d = out.path().display();
    repo.compose(
        "raw",
        &format!(
            "services:\n  app:\n    image: busybox\n    environment:\n      \
             PW: '<<set:shared/pw:{DOLLAR}>>'\n      LIT: $$HOME\n"
        ),
    );
    repo.write("stacks/x/conf.txt", "pw=<<secret:shared/pw>>\n");
    repo.compose(
        "x",
        &format!(
            "services:\n  app:\n    image: busybox\n    environment:\n      \
             PW: '<<secret:shared/pw>>'\n      LIT: $$HOME\n    volumes:\n      \
             - {d}:/cfg\nx-deploy:\n  render:\n    - from: conf.txt\n      \
             to: {d}/conf.txt\n  pre:\n    - with: app\n      \
             run: echo <<secret:shared/pw>>\n"
        ),
    );
    commit_all(&repo, "dollar");

    // Raw path: the value doubled, the user's `$$HOME` untouched.
    let raw = render(&repo, "raw");
    assert!(raw.contains(&format!("PW: '{DOLLAR_COMPOSE}'\n")), "{raw}");
    assert!(raw.contains("LIT: $$HOME\n"), "{raw}");

    // YAML path: same in the compose document.
    let x = render(&repo, "x");
    assert!(x.contains(DOLLAR_COMPOSE), "{x}");
    assert!(!x.contains("$$$$HOME"), "{x}");
    assert!(x.contains("$$HOME"), "{x}");
    // `render:` files are not read by compose: raw value.
    assert_eq!(
        repo.lst(&["render", "x", "--file", "conf.txt"]).ok(),
        format!("pw={DOLLAR}\n")
    );

    let fake = Fake::new();
    let run = deploy_ok(&repo, &fake, &["raw", "x"]);
    for v in [DOLLAR, DOLLAR_COMPOSE] {
        assert!(!run.stderr.contains(v), "{v} leaked: {run:#?}");
    }
    let calls = fake.calls();
    assert_eq!(calls.len(), 3, "{calls:#?}");
    // raw: up, with the escaped compose text.
    assert_eq!(calls[0].stdin, raw.as_bytes());
    // x: the pre step gets the raw value as argv (no interpolation there),
    assert_eq!(
        calls[1].args.last().map(String::as_str),
        Some(format!("echo {DOLLAR}").as_str())
    );
    // then up with the escaped compose text; the written file is raw.
    assert_eq!(calls[2].stdin, x.as_bytes());
    assert_eq!(
        fs::read_to_string(out.path().join("conf.txt")).unwrap(),
        format!("pw={DOLLAR}\n")
    );
}
