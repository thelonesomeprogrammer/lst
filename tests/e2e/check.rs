//! `lst check`: every problem at once, structural without a seed, and the
//! seed checks with one (from `.env` or `LST_SEED`).

use std::fs;

use crate::support::{Repo, Run};

/// Plaintext values these tests set; never in any output.
const PLAINTEXTS: &[&str] = &[
    "ch3ck-v4l",
    "wt-s3t-v4l",
    "l34k3d-v4l",
    "0uts1d3-l34k",
    "b1n-l34k",
];

const OTHER_SEED: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/// The success lines.
const OK: &str = "lst: check ok\n";
const OK_STRUCTURAL: &str = "lst: check ok (structural only: no seed)\n";

/// Asserts that no plaintext and no part of `seed_hex` is in `run`.
#[track_caller]
fn assert_clean(run: &Run, seed_hex: &str) {
    let out = format!("{}{}", run.stdout, run.stderr);
    for half in [&seed_hex[..32], &seed_hex[32..]] {
        assert!(!out.contains(half), "seed leaked: {run:#?}");
    }
    for p in PLAINTEXTS {
        assert!(!out.contains(p), "{p} leaked: {run:#?}");
    }
}

/// `lst check` with the repository's `.env` (if any). Read-only: nothing
/// outside `.git/` changes.
#[track_caller]
fn check(repo: &Repo, seed_hex: &str) -> Run {
    let before = repo.snapshot();
    let run = repo.lst(&["check"]);
    assert_clean(&run, seed_hex);
    assert_eq!(repo.snapshot(), before, "check wrote something");
    run
}

/// `lst check` with `LST_SEED=<value>`.
#[track_caller]
fn check_env(repo: &Repo, value: &str, seed_hex: &str) -> Run {
    let before = repo.snapshot();
    let run = repo.lst_env(&["check"], value);
    assert_clean(&run, seed_hex);
    assert_clean(&run, value.get(..64).unwrap_or(OTHER_SEED));
    assert_eq!(repo.snapshot(), before, "check wrote something");
    run
}

/// Asserts the exit code 1 and that stderr is exactly `lines` (each
/// prefixed `lst: `) followed by the summary line.
#[track_caller]
fn fails_exactly(run: &Run, lines: &[&str], summary: &str) {
    let mut want: String = lines.iter().map(|l| format!("lst: {l}\n")).collect();
    want.push_str(&format!("lst: {summary}\n"));
    run.fails_with(&[]);
    assert_eq!(run.stderr, want, "{run:#?}");
}

/// A repository whose stack is committed through the hook: `web/db` and
/// `shared/m` (generated), `web/cf` (manual).
fn clean() -> Repo {
    let repo = Repo::initialised();
    repo.compose(
        "web",
        "a: <<gen:db>>\nb: <<set:cf:ch3ck-v4l>>\nc: <<gen:shared/m>>\n",
    );
    repo.write("README.md", "docs\n");
    repo.git(&["add", "-A"]);
    let run = repo.commit(&["-m", "web"]);
    assert_eq!(run.code, Some(0), "{run:#?}");
    repo
}

/// Commits the staged changes without the hook (`--no-verify`).
fn commit_no_verify(repo: &Repo) {
    let run = repo.commit(&["--no-verify", "-m", "no hook"]);
    assert_eq!(run.code, Some(0), "{run:#?}");
}

/// Changes the first ciphertext hex digit in `.sec/web.toml` (`web/cf`):
/// still valid TOML and hex, but it no longer decrypts.
fn corrupt_ciphertext(repo: &Repo) {
    let sec = repo.read(".sec/web.toml");
    let at = sec.find("ciphertext = \"").unwrap() + "ciphertext = \"".len();
    let digit = u8::from_str_radix(&sec[at..=at], 16).unwrap() ^ 1;
    repo.write(
        ".sec/web.toml",
        format!("{}{digit:x}{}", &sec[..at], &sec[at + 1..]),
    );
}

const NOT_CURRENT: &str = "run `lst sync` and commit .sec/ (the pre-commit hook does this when \
     you commit)";

#[test]
fn a_clean_repository_passes() {
    let repo = clean();
    let seed = repo.seed_hex();
    let run = check(&repo, &seed);
    assert_eq!((run.ok(), run.stderr.as_str()), ("", OK));
    // The same seed in the variable too.
    let run = check_env(&repo, &seed, &seed);
    assert_eq!((run.ok(), run.stderr.as_str()), ("", OK));

    // A fresh clone (CI): with the variable, and structural without it.
    let clone = repo.clone_repo();
    let run = check_env(&clone, &seed, &seed);
    assert_eq!((run.ok(), run.stderr.as_str()), ("", OK));
    let run = check(&clone, &seed);
    assert_eq!((run.ok(), run.stderr.as_str()), ("", OK_STRUCTURAL));
    // .env without a seed line is structural too.
    clone.write(".env", "OTHER=1\n");
    let run = check(&clone, &seed);
    assert_eq!((run.ok(), run.stderr.as_str()), ("", OK_STRUCTURAL));
}

#[test]
fn a_repository_without_commits_skips_the_history_check() {
    let repo = Repo::initialised();
    repo.compose("web", "a: <<gen:db>>\n");
    repo.lst(&["sync"]).ok();
    let run = check(&repo, &repo.seed_hex());
    assert_eq!(
        (run.ok(), run.stderr.as_str()),
        (
            "",
            "lst: no commit yet, so there is no committed <<set:…>> to look for\nlst: check ok\n"
        )
    );
}

#[test]
fn a_stale_store_is_reported() {
    let repo = clean();
    let seed = repo.seed_hex();
    // A new name that was never synced.
    repo.compose(
        "web",
        "a: <<gen:db>>\nb: <<secret:cf>>\nc: <<gen:shared/m>>\nd: <<gen:new>>\n",
    );
    fails_exactly(
        &check(&repo, &seed),
        &[&format!(
            ".sec/ is not current: web/new is new; {NOT_CURRENT}"
        )],
        "check failed: 1 problem",
    );

    // A pending orphan and a pending format change.
    repo.compose("web", "a: <<gen:db:hex32>>\nb: <<secret:cf>>\n");
    fails_exactly(
        &check(&repo, &seed),
        &[
            &format!(
                ".sec/ is not current: web/db changed format (alnum32 -> hex32); {NOT_CURRENT}"
            ),
            &format!(
                ".sec/ is not current: shared/m is no longer used but not marked as an orphan; \
                 {NOT_CURRENT}"
            ),
        ],
        "check failed: 2 problems",
    );

    // After a sync (orphaned), using it again is pending too.
    repo.compose("web", "a: <<gen:db>>\nb: <<secret:cf>>\n");
    repo.lst(&["sync"]).ok();
    repo.compose(
        "web",
        "a: <<gen:db>>\nb: <<secret:cf>>\nc: <<gen:shared/m>>\n",
    );
    fails_exactly(
        &check(&repo, &seed),
        &[&format!(
            ".sec/ is not current: shared/m is used again but marked as an orphan; {NOT_CURRENT}"
        )],
        "check failed: 1 problem",
    );
    repo.lst(&["sync"]).ok();
    assert_eq!(check(&repo, &seed).stderr, OK);

    // A hand-edited .sec/ file.
    let web = repo.read(".sec/web.toml");
    repo.write(
        ".sec/web.toml",
        web.replace("orphan = false", "orphan=false"),
    );
    fails_exactly(
        &check(&repo, &seed),
        &[
            ".sec/web.toml is not as lst writes it (edited by hand?); run `lst sync` to rewrite \
           it and commit it",
        ],
        "check failed: 1 problem",
    );
}

#[test]
fn a_set_in_the_working_tree_is_reported() {
    let repo = clean();
    let seed = repo.seed_hex();
    repo.write("stacks/web/app.env", "TOKEN=<<set:tok:wt-s3t-v4l>>\n");
    fails_exactly(
        &check(&repo, &seed),
        &[
            "stacks/web/app.env: <<set:tok:…>> is not committed yet; commit the file, and the \
           pre-commit hook encrypts the value into .sec/ and rewrites the marker to \
           <<secret:tok>>",
        ],
        "check failed: 1 problem",
    );
}

#[test]
fn a_committed_set_must_be_rotated() {
    let repo = clean();
    let seed = repo.seed_hex();
    // Committed past the hook, then processed by hand: the working tree,
    // the index and .sec/ are fine, but HEAD holds the plaintext.
    repo.compose(
        "web",
        "a: <<gen:db>>\nb: <<secret:cf>>\nc: <<gen:shared/m>>\nd: <<set:leak:l34k3d-v4l>>\n",
    );
    repo.git(&["add", "-A"]);
    commit_no_verify(&repo);
    let run = repo.lst(&["hook", "run"]);
    run.ok();
    assert_clean(&run, &seed);
    let rotate = "a <<set:…>> value is in git history; rotate the secret (set a new value), the \
         old one must be considered leaked";
    let committed = format!("stacks/web/compose.yaml: {rotate}");
    fails_exactly(
        &check(&repo, &seed),
        &[&committed],
        "check failed: 1 problem",
    );
    // The structural check (a fresh clone without the seed) catches it
    // too; the clone's working tree is HEAD, so it has the marker as well.
    let clone = repo.clone_repo();
    fails_exactly(
        &check(&clone, &seed),
        &[
            "stacks/web/compose.yaml: <<set:leak:…>> is not committed yet; commit the file, \
             and the pre-commit hook encrypts the value into .sec/ and rewrites the marker to \
             <<secret:leak>>",
            &committed,
        ],
        "check failed: 2 problems (structural only: no seed)",
    );

    // Outside stacks/, in any file, binary or not. (This commit also
    // takes the hook's rewritten compose.yaml, so that one is fixed.)
    repo.write("README.md", "pw <<set:x:0uts1d3-l34k>>\n");
    repo.write("docs/blob.bin", b"\xff\xfe<<set:y:b1n-l34k>>");
    repo.git(&["add", "-A"]);
    commit_no_verify(&repo);
    fails_exactly(
        &check(&repo, &seed),
        &[
            &format!("README.md: {rotate}"),
            &format!("docs/blob.bin: {rotate}"),
        ],
        "check failed: 2 problems",
    );

    // Only HEAD's tree is checked (as designed): once the files are fixed
    // and committed, check passes, although the values stay in history.
    repo.write("README.md", "docs\n");
    repo.remove("docs/blob.bin");
    repo.git(&["add", "-A"]);
    assert_eq!(repo.commit(&["-m", "fix"]).code, Some(0));
    assert_eq!(check(&repo, &seed).stderr, OK);
}

#[test]
fn committed_links_and_submodules_are_not_read() {
    let repo = clean();
    let seed = repo.seed_hex();
    // Only regular files are scanned: a symlink's blob is its target, a
    // submodule's oid is a commit in another repository.
    std::os::unix::fs::symlink("README.md", repo.path().join("link")).unwrap();
    repo.git(&["add", "link"]);
    let head = repo.git_stdout(&["rev-parse", "HEAD"]);
    repo.git(&[
        "update-index",
        "--add",
        "--cacheinfo",
        "160000",
        head.trim(),
        "vendor/sub",
    ]);
    commit_no_verify(&repo);
    let tree = repo.git_stdout(&["ls-tree", "-r", "HEAD"]);
    assert!(
        tree.contains("120000 blob") && tree.contains("160000 commit"),
        "{tree}"
    );
    assert_eq!(check(&repo, &seed).stderr, OK);
}

#[test]
fn unset_secrets_are_reported() {
    let repo = clean();
    let seed = repo.seed_hex();
    repo.compose(
        "web",
        "a: <<gen:db>>\nb: <<secret:cf>>\nc: <<gen:shared/m>>\nd: <<secret:tok>>\n\
         e: <<secret:shared/smtp>>\n",
    );
    fails_exactly(
        &check(&repo, &seed),
        &[
            "`shared/smtp` is not set; write <<set:shared/smtp:VALUE>> to set it",
            "`web/tok` is not set; write <<set:tok:VALUE>> to set it",
        ],
        "check failed: 2 problems",
    );
}

#[test]
fn the_seed_must_match() {
    let repo = clean();
    let seed = repo.seed_hex();
    // A clone with the wrong seed in the variable: one problem.
    let clone = repo.clone_repo();
    fails_exactly(
        &check_env(&clone, OTHER_SEED, &seed),
        &["wrong seed: its fingerprint does not match .sec/meta.toml"],
        "check failed: 1 problem",
    );
    // With .env as well, a different variable is an error before checking.
    check_env(&repo, OTHER_SEED, &seed).fails_with(&["LST_SEED and .env disagree"]);
    // So is a malformed value; it is never echoed.
    let bad = format!("{seed} ");
    let run = check_env(&clone, &bad, &seed);
    run.fails_with(&["the LST_SEED environment variable is not 64 lowercase hex characters"]);
    check_env(&clone, "", &seed).fails_with(&["is set but empty"]);
}

#[test]
fn an_undecryptable_secret_is_reported() {
    let repo = clean();
    let seed = repo.seed_hex();
    corrupt_ciphertext(&repo);
    fails_exactly(
        &check(&repo, &seed),
        &[
            "stacks/web/compose.yaml: `web/cf`: decryption failed (wrong seed, wrong name, or \
           corrupted ciphertext)",
        ],
        "check failed: 1 problem",
    );
    // Structurally nothing is wrong: without a seed it can't be seen.
    repo.remove(".env");
    assert_eq!(check(&repo, &seed).stderr, OK_STRUCTURAL);
}

#[test]
fn without_a_seed_the_structural_checks_still_run() {
    let repo = clean();
    let seed = repo.seed_hex();
    repo.remove(".env");
    assert_eq!(check(&repo, &seed).stderr, OK_STRUCTURAL);
    repo.compose(
        "web",
        "a: <<gen:db>>\nb: <<secret:cf>>\nc: <<gen:shared/m>>\nd: <<gen:new>>\n\
         e: <<secret:tok>>\nf: <<set:x:wt-s3t-v4l>>\n",
    );
    fails_exactly(
        &check(&repo, &seed),
        &[
            "stacks/web/compose.yaml: <<set:x:…>> is not committed yet; commit the file, and \
             the pre-commit hook encrypts the value into .sec/ and rewrites the marker to \
             <<secret:x>>",
            &format!(".sec/ is not current: web/new is new; {NOT_CURRENT}"),
            "`web/tok` is not set; write <<set:tok:VALUE>> to set it",
        ],
        "check failed: 3 problems (structural only: no seed)",
    );
    // The ignore guard still applies to a .env that exists.
    repo.write(".env", format!("LST_SEED={seed}\n"));
    repo.remove(".gitignore");
    check(&repo, &seed).fails_with(&[".env is not gitignored"]);
}

#[test]
fn every_problem_is_listed_in_one_run() {
    let repo = clean();
    let seed = repo.seed_hex();
    repo.write("README.md", "<<set:x:0uts1d3-l34k>>\n");
    repo.git(&["add", "-A"]);
    commit_no_verify(&repo);
    corrupt_ciphertext(&repo);
    repo.compose(
        "web",
        "a: <<gen:db:hex32>>\nb: <<secret:cf>>\nd: <<gen:new>>\ne: <<secret:tok>>\n",
    );
    repo.write("stacks/web/x.conf", "<<set:y:wt-s3t-v4l>>\n");
    fails_exactly(
        &check(&repo, &seed),
        &[
            "stacks/web/x.conf: <<set:y:…>> is not committed yet; commit the file, and the \
             pre-commit hook encrypts the value into .sec/ and rewrites the marker to \
             <<secret:y>>",
            &format!(".sec/ is not current: web/new is new; {NOT_CURRENT}"),
            &format!(
                ".sec/ is not current: web/db changed format (alnum32 -> hex32); {NOT_CURRENT}"
            ),
            &format!(
                ".sec/ is not current: shared/m is no longer used but not marked as an orphan; \
                 {NOT_CURRENT}"
            ),
            "`web/tok` is not set; write <<set:tok:VALUE>> to set it",
            "README.md: a <<set:…>> value is in git history; rotate the secret (set a new \
             value), the old one must be considered leaked",
            "stacks/web/compose.yaml: `web/cf`: decryption failed (wrong seed, wrong name, or \
             corrupted ciphertext)",
        ],
        "check failed: 7 problems",
    );
}

#[test]
fn hard_errors_stop_the_check() {
    let repo = clean();
    let seed = repo.seed_hex();
    repo.compose("web", "a: <<gen:db\n");
    check(&repo, &seed).fails_with(&["lst: stacks/web/compose.yaml:1:4: unterminated marker"]);
    repo.compose("web", "a: <<gen:db>>\n");
    repo.write(".sec/web.toml", "nope = \n");
    check(&repo, &seed).fails_with(&["lst: .sec/web.toml: invalid TOML at line 1"]);
    fs::remove_dir_all(repo.path().join(".sec")).unwrap();
    check(&repo, &seed).fails_with(&["not initialised (no meta.toml); run `lst init`"]);

    // Stack discovery errors, as in sync.
    let repo = clean();
    std::os::unix::fs::symlink("web", repo.path().join("stacks/link")).unwrap();
    check(&repo, &seed).fails_with(&["stacks/link is a symlink"]);

    // A committed object that can't be read (a damaged repository) is an
    // error, never a silently skipped file.
    let repo = clean();
    let drop_object = |rev: &str| {
        let oid = repo.git_stdout(&["rev-parse", rev]);
        let oid = oid.trim();
        repo.remove(&format!(".git/objects/{}/{}", &oid[..2], &oid[2..]));
    };
    drop_object("HEAD:README.md");
    check(&repo, &seed).fails_with(&["lst: `git cat-file blob "]);
    drop_object("HEAD^{tree}");
    check(&repo, &seed).fails_with(&["lst: `git ls-tree -r -z --full-tree HEAD` failed"]);

    // Outside a repository, like every command.
    let dir = tempfile::tempdir().unwrap();
    repo.lst_in(dir.path(), &["check"])
        .fails_with(&["is not inside a git repository"]);
}
