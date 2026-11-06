//! The pre-commit hook end to end: `lst hook install` / `lst init` put it
//! in place, and real `git commit`s run it (with the `lst` under test on
//! `PATH`).

use std::fs;
use std::os::unix::fs::PermissionsExt;

use crate::support::{Repo, Run, path_without_lst};

/// Every plaintext value these tests set. None of them may ever show up in
/// a run's output, a commit or `.sec/`.
const PLAINTEXTS: &[&str] = &[
    "s3cr3t-pl41n",
    "n3w-v4lu3",
    "p4rt14l-v4l",
    "unst4g3d-v4l",
    "3x3c-v4l",
    "c0mm1t-4ll",
    "only-p4th",
    "h00ks-p4th",
    "0uts1d3-v4l",
    "b1n4ry-v4l",
    "c0nfl1ct-0ne",
    "c0nfl1ct-tw0",
    "3sc4p3-v4l",
    "n0-l5t-v4l",
    "s33d-v4l",
    "3nv-v4l",
    "g0ne-v4l",
    "3d1t3d-0ld",
    "3d1t3d-n3w",
    "d1r3ct-v4l",
];

/// Asserts that no plaintext value appears in `run`'s output.
#[track_caller]
fn assert_no_plaintext(run: &Run) {
    for p in PLAINTEXTS {
        assert!(
            !run.stdout.contains(p) && !run.stderr.contains(p),
            "{p} leaked: {run:#?}"
        );
    }
}

/// `git commit -q <args>`, checked for leaks.
#[track_caller]
fn commit(repo: &Repo, args: &[&str]) -> Run {
    let run = repo.commit(args);
    assert_no_plaintext(&run);
    run
}

/// `lst <args>`, checked for leaks.
#[track_caller]
fn lst(repo: &Repo, args: &[&str]) -> Run {
    let run = repo.lst(args);
    assert_no_plaintext(&run);
    run
}

/// Asserts that a commit succeeded and returns its stderr (the hook's).
#[track_caller]
fn ok(run: &Run) -> &str {
    assert_eq!(run.code, Some(0), "{run:#?}");
    assert_eq!(run.stdout, "", "{run:#?}");
    &run.stderr
}

/// Asserts that `plaintext` is in no commit, no tree and no `.sec/`, and
/// not in the working tree outside `exempt` (paths that legitimately hold
/// it, if any).
#[track_caller]
fn assert_nowhere(repo: &Repo, plaintext: &str) {
    let revs = repo.git_stdout(&["rev-list", "--all"]);
    let mut args = vec!["grep", "-F", "-q", plaintext];
    args.extend(revs.lines());
    let run = repo.git_run(&args, None);
    assert_eq!(run.code, Some(1), "found in history: {run:#?}");
    // Nor in the index.
    let run = repo.git_run(&["grep", "--cached", "-F", "-q", plaintext], None);
    assert_eq!(run.code, Some(1), "found in the index: {run:#?}");
    for (path, bytes) in repo.snapshot() {
        assert!(
            !String::from_utf8_lossy(&bytes).contains(plaintext),
            "{plaintext} in {}",
            path.display()
        );
    }
}

/// An initialised repository with its first commit made through the hook.
fn hooked() -> Repo {
    let repo = Repo::initialised();
    repo.git(&["add", "-A"]);
    assert_eq!(ok(&commit(&repo, &["-m", "init"])), "");
    repo
}

/// Asserts that a commit was blocked: exit code 1, every needle in stderr,
/// no new commit, no leak, and nothing outside `.git/` changed.
#[track_caller]
fn blocked(repo: &Repo, args: &[&str], needles: &[&str]) -> Run {
    let commits = repo.commit_count();
    let before = repo.snapshot();
    let run = commit(repo, args);
    run.fails_with(needles);
    assert_eq!(repo.commit_count(), commits, "a commit was created");
    assert_eq!(repo.snapshot(), before, "the working tree changed");
    run
}

fn status(repo: &Repo) -> String {
    repo.git_stdout(&["status", "--porcelain"])
}

// ---------------------------------------------------------------------------
// install
// ---------------------------------------------------------------------------

const SCRIPT: &str = "#!/bin/sh\n# Installed by lst. Do not edit.\ncommand -v lst >/dev/null 2>&1 \
     || { echo \"lst: not on PATH; commit blocked\" >&2; exit 1; }\nexec lst hook run\n";

fn hook_mode(repo: &Repo, rel: &str) -> u32 {
    fs::metadata(repo.path().join(rel))
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

#[test]
fn init_installs_the_hook() {
    let repo = Repo::new();
    let run = lst(&repo, &["init"]);
    run.ok();
    assert!(
        run.stderr
            .contains("lst: installed the pre-commit hook: .git/hooks/pre-commit\n"),
        "{run:#?}"
    );
    assert_eq!(repo.read(".git/hooks/pre-commit"), SCRIPT);
    assert_eq!(hook_mode(&repo, ".git/hooks/pre-commit"), 0o755);
    // Initialising again is quiet about the hook.
    let run = lst(&repo, &["init"]);
    assert_eq!(
        run.stderr,
        "lst: already initialised (the seed in .env matches .sec/meta.toml)\n"
    );
}

#[test]
fn init_on_a_second_machine_installs_the_hook() {
    // A clone without hooks, with the seed copied into .env.
    let repo = Repo::initialised();
    repo.remove(".git/hooks/pre-commit");
    let run = lst(&repo, &["init"]);
    run.ok();
    assert!(run.stderr.contains("already initialised"), "{run:#?}");
    assert!(
        run.stderr.contains("installed the pre-commit hook"),
        "{run:#?}"
    );
    assert_eq!(repo.read(".git/hooks/pre-commit"), SCRIPT);
}

#[test]
fn init_leaves_a_foreign_hook_alone_with_a_warning() {
    let repo = Repo::new();
    repo.write(".git/hooks/pre-commit", "#!/bin/sh\nexit 0\n");
    let run = lst(&repo, &["init"]);
    run.ok();
    assert!(
        run.stderr.contains(
            "lst: warning: .git/hooks/pre-commit is not lst's pre-commit hook, so it was left \
             alone. Until you run `lst hook install --force`"
        ),
        "{run:#?}"
    );
    assert!(repo.exists(".sec/meta.toml"));
    assert_eq!(repo.read(".git/hooks/pre-commit"), "#!/bin/sh\nexit 0\n");
}

#[test]
fn init_fails_if_the_hook_cannot_be_installed() {
    let repo = Repo::new();
    repo.write("not-a-dir", "");
    repo.git(&["config", "core.hooksPath", "not-a-dir"]);
    lst(&repo, &["init"]).fails_with(&["not-a-dir: "]);
    // The store was written first; running init again retries the hook.
    assert!(repo.exists(".sec/meta.toml"));
}

#[test]
fn hook_install_twice_foreign_and_force() {
    let repo = Repo::new();
    let run = lst(&repo, &["hook", "install"]);
    assert_eq!(run.ok(), "");
    assert_eq!(
        run.stderr,
        "lst: installed the pre-commit hook: .git/hooks/pre-commit\n"
    );
    assert_eq!(repo.read(".git/hooks/pre-commit"), SCRIPT);
    assert_eq!(hook_mode(&repo, ".git/hooks/pre-commit"), 0o755);

    let before = fs::metadata(repo.path().join(".git/hooks/pre-commit"))
        .unwrap()
        .modified()
        .unwrap();
    let run = lst(&repo, &["hook", "install"]);
    run.ok();
    assert_eq!(
        run.stderr,
        "lst: the pre-commit hook is already installed: .git/hooks/pre-commit\n"
    );
    let after = fs::metadata(repo.path().join(".git/hooks/pre-commit"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(before, after, "a no-op must not rewrite the file");

    // Foreign hooks: other content, an edited lst hook, lst's hook without
    // the exec bit (git would skip it), a symlink to lst's script.
    let foreign = [
        "#!/bin/sh\nexec other-tool\n".to_owned(),
        SCRIPT.replace("exec lst hook run", "exec lst hook run --x"),
    ];
    for content in &foreign {
        repo.write(".git/hooks/pre-commit", content);
        lst(&repo, &["hook", "install"]).fails_with(&[
            ".git/hooks/pre-commit already exists and is not lst's hook (or was changed); lst \
             won't overwrite it. Run `lst hook install --force`",
        ]);
        assert_eq!(&repo.read(".git/hooks/pre-commit"), content);
    }
    repo.write(".git/hooks/pre-commit", SCRIPT);
    fs::set_permissions(
        repo.path().join(".git/hooks/pre-commit"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    lst(&repo, &["hook", "install"]).fails_with(&["is not lst's hook"]);
    repo.write("script", SCRIPT);
    fs::set_permissions(
        repo.path().join("script"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    repo.remove(".git/hooks/pre-commit");
    std::os::unix::fs::symlink(
        repo.path().join("script"),
        repo.path().join(".git/hooks/pre-commit"),
    )
    .unwrap();
    lst(&repo, &["hook", "install"]).fails_with(&["is not lst's hook"]);

    // --force replaces the symlink itself, not its target.
    let run = lst(&repo, &["hook", "install", "--force"]);
    run.ok();
    assert_eq!(
        run.stderr,
        "lst: replaced .git/hooks/pre-commit with lst's pre-commit hook (--force)\n"
    );
    let meta = fs::symlink_metadata(repo.path().join(".git/hooks/pre-commit")).unwrap();
    assert!(meta.is_file());
    assert_eq!(meta.permissions().mode() & 0o777, 0o755);
    assert_eq!(repo.read(".git/hooks/pre-commit"), SCRIPT);
    assert_eq!(repo.read("script"), SCRIPT);
    // No temporary files are left behind.
    let names: Vec<_> = fs::read_dir(repo.path().join(".git/hooks"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.contains("lst"))
        .collect();
    assert_eq!(names, Vec::<String>::new());
}

#[test]
fn hook_install_failures() {
    // A directory where the hook goes: refused, and with --force the
    // rename fails and the temporary file is removed.
    let repo = Repo::new();
    fs::create_dir_all(repo.path().join(".git/hooks/pre-commit")).unwrap();
    lst(&repo, &["hook", "install"]).fails_with(&["is not lst's hook"]);
    lst(&repo, &["hook", "install", "--force"]).fails_with(&[".git/hooks/pre-commit: "]);
    let names: Vec<_> = fs::read_dir(repo.path().join(".git/hooks"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.contains("lst"))
        .collect();
    assert_eq!(names, Vec::<String>::new());
    // Outside a repository.
    let dir = tempfile::tempdir().unwrap();
    repo.lst_in(dir.path(), &["hook", "install"])
        .fails_with(&["is not inside a git repository"]);
}

#[test]
fn hook_install_respects_core_hooks_path() {
    let repo = Repo::initialised();
    repo.git(&["config", "core.hooksPath", "tools/hooks"]);
    let run = lst(&repo, &["hook", "install"]);
    run.ok();
    assert_eq!(
        run.stderr,
        "lst: installed the pre-commit hook: tools/hooks/pre-commit\n"
    );
    assert_eq!(hook_mode(&repo, "tools/hooks/pre-commit"), 0o755);
    // git runs it from there: a new name gets its id in the commit.
    repo.git(&["add", "-A"]);
    ok(&commit(&repo, &["-m", "init"]));
    repo.compose("web", "a: <<set:cf:h00ks-p4th>>\n");
    repo.git(&["add", "stacks"]);
    let run = commit(&repo, &["-m", "web"]);
    assert!(ok(&run).contains("lst: stored web/cf\n"), "{run:#?}");
    assert_eq!(
        repo.show("HEAD:stacks/web/compose.yaml"),
        "a: <<secret:cf>>\n"
    );
    assert_nowhere(&repo, "h00ks-p4th");
}

// ---------------------------------------------------------------------------
// run: generated secrets, orphans, renames
// ---------------------------------------------------------------------------

#[test]
fn new_gen_names_get_ids_in_the_same_commit() {
    let repo = hooked();
    repo.compose("web", "a: <<gen:db>>\nb: <<gen:api:hex64>>\n");
    repo.write("stacks/web/config/app.conf", "k=<<gen:conf>>\n");
    repo.git(&["add", "stacks"]);
    let run = commit(&repo, &["-m", "web"]);
    assert_eq!(
        ok(&run),
        "lst: new: web/api\nlst: new: web/conf\nlst: new: web/db\n"
    );
    let sec = repo.show("HEAD:.sec/web.toml");
    for key in ["[gen.api]", "[gen.conf]", "[gen.db]", "format = \"hex64\""] {
        assert!(sec.contains(key), "{sec}");
    }
    assert_eq!(sec, repo.read(".sec/web.toml"));
    // The real index and the working tree match the commit.
    assert_eq!(status(&repo), "");
    let rendered = repo.lst(&["render", "web"]);
    assert!(rendered.ok().starts_with("a: "), "{rendered:#?}");
}

#[test]
fn no_op_commit_is_silent() {
    let repo = hooked();
    repo.compose("web", "a: <<gen:db>>\n");
    repo.git(&["add", "-A"]);
    ok(&commit(&repo, &["-m", "web"]));
    repo.write("README.md", "hello\n");
    repo.git(&["add", "README.md"]);
    let run = commit(&repo, &["-m", "readme"]);
    assert_eq!(ok(&run), "");
    // And so is the hook run by hand on a clean index.
    let run = lst(&repo, &["hook", "run"]);
    assert_eq!((run.ok(), run.stderr.as_str()), ("", ""));
}

#[test]
fn deleted_markers_are_orphaned() {
    let repo = hooked();
    repo.compose("web", "a: <<gen:db>>\nb: <<gen:api>>\n");
    repo.git(&["add", "-A"]);
    ok(&commit(&repo, &["-m", "web"]));
    repo.compose("web", "a: <<gen:db>>\n");
    let run = commit(&repo, &["-am", "drop api"]);
    assert_eq!(
        ok(&run),
        "lst: orphaned: web/api (no longer used; kept in .sec/)\n"
    );
    let sec = repo.show("HEAD:.sec/web.toml");
    assert!(sec.contains("[gen.api]"), "{sec}");
    let api = sec.split("[gen.api]").nth(1).unwrap();
    assert!(api.contains("orphan = true"), "{sec}");
    // Deleting a whole file of the stack does the same.
    repo.write("stacks/web/extra.env", "X=<<gen:extra>>\n");
    repo.git(&["add", "-A"]);
    ok(&commit(&repo, &["-m", "extra"]));
    repo.git(&["rm", "-q", "stacks/web/extra.env"]);
    let run = commit(&repo, &["-m", "rm extra"]);
    assert_eq!(
        ok(&run),
        "lst: orphaned: web/extra (no longer used; kept in .sec/)\n"
    );
}

#[test]
fn rename_hint_then_rename_restores_the_old_value() {
    let repo = hooked();
    repo.compose("web", "pw: <<gen:db>>\n");
    repo.git(&["add", "-A"]);
    ok(&commit(&repo, &["-m", "web"]));
    let old = repo.lst(&["render", "web"]).ok().to_owned();

    repo.compose("web", "pw: <<gen:database>>\n");
    let run = commit(&repo, &["-am", "rename"]);
    assert_eq!(
        ok(&run),
        "lst: new: web/database\n\
         lst: orphaned: web/db (no longer used; kept in .sec/)\n\
         lst: looks like a rename: run `lst rename web/db web/database --replace` to keep the \
         old value\n"
    );
    assert_ne!(repo.lst(&["render", "web"]).ok(), old);

    lst(&repo, &["rename", "web/db", "web/database", "--replace"]).ok();
    let run = commit(&repo, &["-am", "keep the old value"]);
    assert_eq!(ok(&run), "");
    assert_eq!(repo.lst(&["render", "web"]).ok(), old);
    let sec = repo.show("HEAD:.sec/web.toml");
    assert!(
        sec.contains("[gen.database]") && !sec.contains("[gen.db]"),
        "{sec}"
    );
}

// ---------------------------------------------------------------------------
// run: <<set:…>>
// ---------------------------------------------------------------------------

#[test]
fn set_round_trip() {
    let repo = hooked();
    repo.compose(
        "web",
        "a: <<gen:db>>\ntoken: \"<<set:cf:s3cr3t-pl41n>>\"\nagain: <<set:cf:s3cr3t-pl41n>>\n",
    );
    repo.git(&["add", "stacks"]);
    let run = commit(&repo, &["-m", "web"]);
    let stderr = ok(&run);
    assert_eq!(
        stderr,
        "lst: new: web/db\nlst: stored web/cf\n\
         lst: note: `git add` already stored the plaintext as a blob in .git/objects. No commit \
         references it and it is never pushed, but it stays on this machine until git prunes \
         it; run `git gc --prune=now` to delete it now\n"
    );
    let committed = "a: <<gen:db>>\ntoken: \"<<secret:cf>>\"\nagain: <<secret:cf>>\n";
    assert_eq!(repo.show("HEAD:stacks/web/compose.yaml"), committed);
    assert_eq!(repo.read("stacks/web/compose.yaml"), committed);
    let sec = repo.show("HEAD:.sec/web.toml");
    assert!(sec.contains("[secret.cf]\nnonce = \""), "{sec}");
    assert!(sec.contains("ciphertext = \""), "{sec}");
    assert_eq!(status(&repo), "");
    assert_nowhere(&repo, "s3cr3t-pl41n");
    let render = repo.lst(&["render", "web"]);
    let out = render.ok();
    assert!(
        out.contains("token: \"s3cr3t-pl41n\"\nagain: s3cr3t-pl41n\n"),
        "{render:#?}"
    );

    // The plaintext blob `git add` wrote is unreachable, and gc removes it.
    let unreachable = |repo: &Repo| -> Vec<String> {
        let out = repo.git_stdout(&["fsck", "--unreachable", "--no-reflogs", "--no-progress"]);
        out.lines()
            .filter_map(|l| l.strip_prefix("unreachable blob "))
            .map(str::to_owned)
            .collect()
    };
    let blobs = unreachable(&repo);
    assert!(
        blobs.iter().any(|b| repo
            .git_stdout(&["cat-file", "blob", b])
            .contains("s3cr3t-pl41n")),
        "{blobs:?}"
    );
    repo.git(&["gc", "-q", "--prune=now"]);
    for b in unreachable(&repo) {
        assert!(
            !repo
                .git_stdout(&["cat-file", "blob", &b])
                .contains("s3cr3t-pl41n")
        );
    }

    // The same value again: nothing re-encrypted.
    let sec_before = repo.read(".sec/web.toml");
    repo.compose("web", "a: <<gen:db>>\ntoken: \"<<set:cf:s3cr3t-pl41n>>\"\n");
    let run = commit(&repo, &["-am", "same"]);
    assert!(
        ok(&run).starts_with("lst: stored web/cf (unchanged: it already had this value)\n"),
        "{run:#?}"
    );
    assert_eq!(repo.read(".sec/web.toml"), sec_before);

    // A new value replaces it.
    repo.compose("web", "token: \"<<set:cf:n3w-v4lu3>>\"\n");
    let run = commit(&repo, &["-am", "new value"]);
    assert!(
        ok(&run).starts_with(
            "lst: orphaned: web/db (no longer used; kept in .sec/)\nlst: stored web/cf\n"
        ),
        "{run:#?}"
    );
    assert_eq!(repo.lst(&["render", "web"]).ok(), "token: \"n3w-v4lu3\"\n");
    assert_nowhere(&repo, "n3w-v4lu3");
}

#[test]
fn shared_sets_and_escapes() {
    let repo = hooked();
    repo.compose(
        "web",
        "m: '<<set:shared/mqtt:a\\>>b\\\\c>>'\nx: <<secret:shared/mqtt>>\n",
    );
    repo.compose("worker", "m: <<secret:shared/mqtt>>\n");
    repo.git(&["add", "-A"]);
    let run = commit(&repo, &["-m", "shared"]);
    assert!(
        ok(&run).starts_with("lst: stored shared/mqtt\n"),
        "{run:#?}"
    );
    assert_eq!(
        repo.show("HEAD:stacks/web/compose.yaml"),
        "m: '<<secret:shared/mqtt>>'\nx: <<secret:shared/mqtt>>\n"
    );
    assert!(repo.show("HEAD:.sec/shared.toml").contains("[secret.mqtt]"));
    assert_eq!(repo.lst(&["render", "worker"]).ok(), "m: a>>b\\c\n");
}

#[test]
fn partial_staging_is_preserved() {
    let repo = hooked();
    repo.compose("web", "a: 1\n");
    repo.git(&["add", "-A"]);
    ok(&commit(&repo, &["-m", "web"]));
    repo.compose("web", "a: 1\nt: <<set:cf:p4rt14l-v4l>>\n");
    repo.git(&["add", "stacks"]);
    // An unstaged edit on top, with a marker the commit doesn't contain.
    repo.compose(
        "web",
        "a: 1\nt: <<set:cf:p4rt14l-v4l>>\nwip: <<gen:later>>\n",
    );
    let run = commit(&repo, &["-m", "partial"]);
    assert!(ok(&run).starts_with("lst: stored web/cf\n"), "{run:#?}");
    assert_eq!(
        repo.show("HEAD:stacks/web/compose.yaml"),
        "a: 1\nt: <<secret:cf>>\n"
    );
    assert_eq!(
        repo.read("stacks/web/compose.yaml"),
        "a: 1\nt: <<secret:cf>>\nwip: <<gen:later>>\n"
    );
    assert!(!repo.show("HEAD:.sec/web.toml").contains("later"));
    // Only the unstaged line differs from the index.
    let diff = repo.git_stdout(&["diff", "--no-color", "-U0"]);
    assert!(diff.contains("\n+wip: <<gen:later>>\n"), "{diff}");
    let added: Vec<_> = diff
        .lines()
        .filter(|l| l.starts_with('+') && !l.starts_with("+++"))
        .collect();
    assert_eq!(added, ["+wip: <<gen:later>>"], "{diff}");
    assert_eq!(repo.git_stdout(&["diff", "--cached"]), "");
    assert_nowhere(&repo, "p4rt14l-v4l");
}

#[test]
fn a_set_only_in_the_working_tree_is_left_alone() {
    let repo = hooked();
    repo.compose("web", "a: <<gen:db>>\n");
    repo.git(&["add", "-A"]);
    ok(&commit(&repo, &["-m", "web"]));
    // Unstaged in a tracked file, and in an untracked file of the stack.
    repo.compose("web", "a: <<gen:db>>\nb: <<set:cf:unst4g3d-v4l>>\n");
    repo.write("stacks/web/new.env", "X=<<set:x:unst4g3d-v4l>>\n");
    repo.write("README.md", "r\n");
    repo.git(&["add", "README.md"]);
    let run = commit(&repo, &["-m", "readme"]);
    assert_eq!(ok(&run), "");
    assert_eq!(
        repo.read("stacks/web/compose.yaml"),
        "a: <<gen:db>>\nb: <<set:cf:unst4g3d-v4l>>\n"
    );
    assert_eq!(
        repo.read("stacks/web/new.env"),
        "X=<<set:x:unst4g3d-v4l>>\n"
    );
    let store = repo.store();
    assert!(store.files()["web"].secrets.is_empty());
}

#[test]
fn exec_bit_is_preserved() {
    let repo = hooked();
    repo.compose("web", "services: {}\n");
    repo.write(
        "stacks/web/run.sh",
        "#!/bin/sh\nTOKEN='<<set:tok:3x3c-v4l>>'\n",
    );
    let script = repo.path().join("stacks/web/run.sh");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o750)).unwrap();
    repo.git(&["add", "-A"]);
    ok(&commit(&repo, &["-m", "script"]));
    let tree = repo.git_stdout(&["ls-tree", "HEAD", "stacks/web/run.sh"]);
    assert!(tree.starts_with("100755 blob "), "{tree}");
    let index = repo.git_stdout(&["ls-files", "-s", "stacks/web/run.sh"]);
    assert!(index.starts_with("100755 "), "{index}");
    assert_eq!(
        fs::metadata(&script).unwrap().permissions().mode() & 0o777,
        0o750
    );
    assert_eq!(
        repo.read("stacks/web/run.sh"),
        "#!/bin/sh\nTOKEN='<<secret:tok>>'\n"
    );
    assert_eq!(status(&repo), "");
    assert_nowhere(&repo, "3x3c-v4l");
}

#[test]
fn links_inside_a_stack_are_skipped() {
    let repo = hooked();
    repo.compose("web", "a: <<gen:db>>\n");
    // A symlink to a file with markers (git commits the link, not the
    // target), and a submodule entry.
    repo.write("outside.conf", "<<gen:via-link>>\n");
    std::os::unix::fs::symlink("../../outside.conf", repo.path().join("stacks/web/link")).unwrap();
    repo.git(&["add", "stacks"]);
    let head = repo.git_stdout(&["rev-parse", "HEAD"]);
    repo.git(&[
        "update-index",
        "--add",
        "--cacheinfo",
        "160000",
        head.trim(),
        "stacks/web/sub",
    ]);
    let run = commit(&repo, &["-m", "links"]);
    assert_eq!(ok(&run), "lst: new: web/db\n");
    let tree = repo.git_stdout(&["ls-tree", "HEAD", "stacks/web/"]);
    assert!(
        tree.contains("120000 blob ") && tree.contains("160000 commit "),
        "{tree}"
    );
    // sync agrees: the symlink is skipped there too.
    let run = lst(&repo, &["sync"]);
    assert_eq!((run.ok(), run.stderr.as_str()), ("", ""));
}

#[test]
fn working_tree_edits_since_git_add_are_kept() {
    let repo = hooked();
    repo.compose("web", "a: <<set:cf:3d1t3d-0ld>>\n");
    repo.git(&["add", "-A"]);
    // Edited again after `git add`: the staged marker is gone from the
    // working tree, so the file is left as is.
    repo.compose("web", "a: <<set:cf:3d1t3d-n3w>>\n");
    let run = commit(&repo, &["-m", "web"]);
    let stderr = ok(&run);
    assert!(
        stderr.contains(
            "lst: stacks/web/compose.yaml: the working tree no longer has the staged \
             <<set:cf:…>>, so it was left as is (the commit has <<secret:cf>>)\n"
        ),
        "{run:#?}"
    );
    assert_eq!(
        repo.read("stacks/web/compose.yaml"),
        "a: <<set:cf:3d1t3d-n3w>>\n"
    );
    assert_eq!(
        repo.show("HEAD:stacks/web/compose.yaml"),
        "a: <<secret:cf>>\n"
    );
    // The next commit stores the new value.
    let run = commit(&repo, &["-am", "new"]);
    assert!(ok(&run).starts_with("lst: stored web/cf\n"), "{run:#?}");
    assert_eq!(repo.lst(&["render", "web"]).ok(), "a: 3d1t3d-n3w\n");
    for p in ["3d1t3d-0ld", "3d1t3d-n3w"] {
        assert_nowhere(&repo, p);
    }
}

#[test]
fn a_staged_file_deleted_from_the_working_tree_is_skipped() {
    let repo = hooked();
    repo.compose("web", "services: {}\n");
    repo.write("stacks/web/a.env", "A=<<set:a:g0ne-v4l>>\n");
    repo.git(&["add", "-A"]);
    repo.remove("stacks/web/a.env");
    let run = commit(&repo, &["-m", "web"]);
    assert!(
        ok(&run).contains(
            "lst: stacks/web/a.env: not a file in the working tree, so it was left alone (the \
             commit has <<secret:…>>)\n"
        ),
        "{run:#?}"
    );
    assert_eq!(repo.show("HEAD:stacks/web/a.env"), "A=<<secret:a>>\n");
    assert!(!repo.exists("stacks/web/a.env"));
    assert_nowhere(&repo, "g0ne-v4l");
}

// ---------------------------------------------------------------------------
// run: other indexes
// ---------------------------------------------------------------------------

#[test]
fn commit_all() {
    let repo = hooked();
    repo.compose("web", "a: 1\n");
    repo.git(&["add", "-A"]);
    ok(&commit(&repo, &["-m", "web"]));
    // Nothing staged: `git commit -a` stages it into index.lock.
    repo.compose("web", "a: <<gen:db>>\nb: <<set:cf:c0mm1t-4ll>>\n");
    let run = commit(&repo, &["-am", "all"]);
    assert!(
        ok(&run).starts_with("lst: new: web/db\nlst: stored web/cf\n"),
        "{run:#?}"
    );
    assert_eq!(
        repo.show("HEAD:stacks/web/compose.yaml"),
        "a: <<gen:db>>\nb: <<secret:cf>>\n"
    );
    assert!(repo.show("HEAD:.sec/web.toml").contains("[secret.cf]"));
    // The real index got the hook's changes too.
    assert_eq!(status(&repo), "");
    assert_nowhere(&repo, "c0mm1t-4ll");
}

#[test]
fn commit_with_paths_blocks_when_lst_has_changes() {
    let repo = hooked();
    repo.compose("web", "a: <<gen:db>>\n");
    repo.git(&["add", "-A"]);
    ok(&commit(&repo, &["-m", "web"]));

    // Nothing for lst to do: `git commit <path>` works.
    repo.write("README.md", "1\n");
    repo.git(&["add", "README.md"]);
    repo.write("README.md", "2\n");
    let run = commit(&repo, &["-m", "readme", "README.md"]);
    assert_eq!(ok(&run), "");
    assert_eq!(repo.show("HEAD:README.md"), "2\n");

    // A <<set:…>>, or a new name, can't be committed this way.
    let msg = "this commit uses a temporary index (as `git commit <paths>` does), and lst has \
               changes to make";
    repo.compose("web", "a: <<gen:db>>\nb: <<set:cf:only-p4th>>\n");
    let run = blocked(
        &repo,
        &["-m", "set", "stacks/web/compose.yaml"],
        &[msg, "Stage the files with `git add`"],
    );
    assert!(!run.stderr.contains("only-p4th"));
    // git rolled the real index back: nothing staged.
    assert_eq!(repo.git_stdout(&["diff", "--cached"]), "");
    repo.compose("web", "a: <<gen:db>>\nb: <<gen:api>>\n");
    blocked(&repo, &["-m", "gen", "stacks/web/compose.yaml"], &[msg]);
    // .sec/ changed in the working tree but not staged: also blocked.
    repo.compose("web", "a: <<gen:db>>\n");
    repo.write(
        ".sec/old.toml",
        "# Managed by lst. Do not edit by hand.\n\n[gen.x]\n\
         id = \"000102030405060708090a0b0c0d0e0f\"\nformat = \"alnum32\"\norphan = true\n",
    );
    repo.write("README.md", "3\n");
    blocked(&repo, &["-m", "sec", "README.md"], &[msg]);
    repo.remove(".sec/old.toml");
    repo.write("README.md", "2\n");

    // Staged and committed without paths, it goes through.
    repo.compose("web", "a: <<gen:db>>\nb: <<set:cf:only-p4th>>\n");
    repo.git(&["add", "stacks"]);
    let run = commit(&repo, &["-m", "set"]);
    assert!(ok(&run).starts_with("lst: stored web/cf\n"), "{run:#?}");
    assert_eq!(status(&repo), "");
    assert_nowhere(&repo, "only-p4th");
}

// ---------------------------------------------------------------------------
// run: blocked commits
// ---------------------------------------------------------------------------

#[test]
fn unset_secret_blocks() {
    let repo = hooked();
    repo.compose("web", "a: <<secret:cf>>\nb: <<secret:shared/smtp>>\n");
    repo.git(&["add", "-A"]);
    blocked(
        &repo,
        &["-m", "web"],
        &["lst: cannot commit: 2 secrets not set:\n  \
             `shared/smtp` is not set; write <<set:shared/smtp:VALUE>> to set it\n  \
             `web/cf` is not set; write <<set:cf:VALUE>> to set it\n"],
    );
}

#[test]
fn malformed_markers_block() {
    let repo = hooked();
    repo.compose("web", "a: <<gen:db\n");
    repo.git(&["add", "-A"]);
    blocked(
        &repo,
        &["-m", "web"],
        &["lst: stacks/web/compose.yaml:1:4: unterminated marker"],
    );
    repo.compose("web", "a: ok\n");
    repo.write("stacks/web/conf/x.ini", "p=<<set:k:3sc4p3-v4l\\n>>\n");
    repo.git(&["add", "-A"]);
    blocked(
        &repo,
        &["-m", "web"],
        &["lst: stacks/web/conf/x.ini:1:21: invalid escape in value"],
    );
}

#[test]
fn set_outside_a_stack_blocks() {
    let repo = hooked();
    repo.compose("web", "a: 1\n");
    for path in [
        "README.md",
        "stacks/notes.txt",
        "stacks/nocompose/x.env",
        "stacks/.hidden/compose.yaml",
        "docs/deep/x",
    ] {
        repo.write(path, "token: <<set:cf:0uts1d3-v4l>>\n");
        repo.git(&["add", "-A"]);
        blocked(
            &repo,
            &["-m", "x"],
            &[&format!(
                "lst: {path}: contains `<<set:` but is not a file of a stack"
            )],
        );
        repo.git(&["rm", "-q", "--cached", path]);
        repo.remove(path);
    }
    // A broken one is caught too (the bytes are checked, not markers).
    repo.write("x.bin", b"\xff<<set:");
    repo.git(&["add", "-A"]);
    blocked(&repo, &["-m", "x"], &["lst: x.bin: contains `<<set:`"]);
}

#[test]
fn set_in_a_non_utf8_stack_file_blocks() {
    let repo = hooked();
    repo.compose("web", "a: 1\n");
    repo.write("stacks/web/blob.bin", b"\xff\xfe<<set:k:b1n4ry-v4l>>");
    repo.git(&["add", "-A"]);
    blocked(
        &repo,
        &["-m", "x"],
        &["lst: stacks/web/blob.bin: not valid UTF-8 but contains `<<set:`"],
    );
    // Without <<set: a binary file is fine.
    repo.write("stacks/web/blob.bin", b"\xff\xfe<<gen:x>>");
    repo.git(&["add", "-A"]);
    assert_eq!(ok(&commit(&repo, &["-m", "x"])), "");
}

#[test]
fn conflicting_set_values_block() {
    let repo = hooked();
    repo.compose("web", "a: <<set:shared/cf:c0nfl1ct-0ne>>\n");
    repo.compose("worker", "a: <<set:shared/cf:c0nfl1ct-tw0>>\n");
    repo.git(&["add", "-A"]);
    blocked(
        &repo,
        &["-m", "x"],
        &[
            "lst: `shared/cf`: <<set:…>> is used with different values in \
             stacks/web/compose.yaml and stacks/worker/compose.yaml",
        ],
    );
}

#[test]
fn set_and_gen_of_one_name_block() {
    let repo = hooked();
    repo.compose("web", "a: <<set:cf:c0nfl1ct-0ne>>\nb: <<gen:cf>>\n");
    repo.git(&["add", "-A"]);
    blocked(
        &repo,
        &["-m", "x"],
        &["`web/cf` is used both as <<gen:…>> and as <<secret:…>>"],
    );
}

#[test]
fn missing_lst_blocks() {
    let repo = hooked();
    repo.compose("web", "a: <<set:cf:n0-l5t-v4l>>\n");
    repo.git(&["add", "-A"]);
    let commits = repo.commit_count();
    let path = path_without_lst();
    let run = repo.git_run(&["commit", "-q", "-m", "x"], Some(&path));
    assert_no_plaintext(&run);
    assert_eq!(run.code, Some(1), "{run:#?}");
    assert_eq!(run.stderr, "lst: not on PATH; commit blocked\n");
    assert_eq!(repo.commit_count(), commits);
}

#[test]
fn wrong_seed_blocks() {
    let repo = hooked();
    repo.compose("web", "a: <<set:cf:s33d-v4l>>\n");
    repo.git(&["add", "-A"]);
    let seed = repo.read(".env");
    repo.write(
        ".env",
        "LST_SEED=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n",
    );
    blocked(&repo, &["-m", "x"], &["lst: wrong seed"]);
    repo.remove(".env");
    blocked(&repo, &["-m", "x"], &["lst: no .env file"]);
    repo.write(".env", seed);
}

#[test]
fn env_not_ignored_blocks() {
    let repo = hooked();
    repo.compose("web", "a: <<set:cf:3nv-v4l>>\n");
    repo.write(".gitignore", "");
    repo.git(&["add", "-A", "stacks", ".gitignore"]);
    blocked(&repo, &["-m", "x"], &["lst: .env is not gitignored"]);
}

#[test]
fn symlinked_stacks_block() {
    let repo = hooked();
    repo.compose("web", "a: 1\n");
    fs::create_dir_all(repo.path().join("elsewhere/db")).unwrap();
    repo.write("elsewhere/db/compose.yaml", "a: <<gen:x>>\n");
    std::os::unix::fs::symlink("../elsewhere/db", repo.path().join("stacks/db")).unwrap();
    repo.git(&["add", "-A"]);
    blocked(
        &repo,
        &["-m", "x"],
        &["lst: stacks/db is a symlink; git stores it as a link, so lst can't see its files"],
    );
}

/// Deletes the loose object of the staged `path`, as a corrupt repository
/// would lack it.
fn drop_staged_object(repo: &Repo, path: &str) {
    let oid = repo.git_stdout(&["rev-parse", &format!(":{path}")]);
    let oid = oid.trim();
    repo.remove(&format!(".git/objects/{}/{}", &oid[..2], &oid[2..]));
}

#[test]
fn unreadable_staged_files_block() {
    for path in ["stacks/web/compose.yaml", "README.md", ".sec/meta.toml"] {
        let repo = hooked();
        repo.compose("web", "a: <<gen:db>>\n");
        repo.write("README.md", "r\n");
        repo.git(&["add", "-A"]);
        drop_staged_object(&repo, path);
        let commits = repo.commit_count();
        let run = commit(&repo, &["-m", "x"]);
        // git may complain about the object itself first.
        assert_eq!(run.code, Some(1), "{path}: {run:#?}");
        assert!(
            run.stderr.contains("\nlst: `git cat-file blob ")
                || run.stderr.starts_with("lst: `git cat-file blob "),
            "{path}: {run:#?}"
        );
        assert_eq!(repo.commit_count(), commits);
    }
}

#[test]
fn undecryptable_stored_secret_blocks() {
    let repo = hooked();
    repo.compose("web", "a: <<set:cf:s3cr3t-pl41n>>\n");
    repo.git(&["add", "-A"]);
    ok(&commit(&repo, &["-m", "web"]));
    // A bad merge or hand edit: the stored ciphertext no longer opens.
    let sec = repo.read(".sec/web.toml");
    let at = sec.find("ciphertext = \"").unwrap() + "ciphertext = \"".len();
    let flipped = if &sec[at..=at] == "0" { "1" } else { "0" };
    repo.write(
        ".sec/web.toml",
        format!("{}{flipped}{}", &sec[..at], &sec[at + 1..]),
    );
    repo.compose("web", "a: <<set:cf:n3w-v4lu3>>\n");
    repo.git(&["add", "stacks"]);
    blocked(&repo, &["-m", "x"], &["lst: `web/cf`: "]);
}

#[test]
fn failing_store_writes_block() {
    // .sec/ can't be saved.
    let repo = hooked();
    repo.compose("web", "a: <<gen:db>>\n");
    repo.git(&["add", "-A"]);
    fs::create_dir(repo.path().join(".sec/.web.toml.tmp")).unwrap();
    blocked(&repo, &["-m", "x"], &["lst: ", ".sec/web.toml: "]);
    fs::remove_dir(repo.path().join(".sec/.web.toml.tmp")).unwrap();

    // .sec/ is gitignored, so `git add .sec` refuses the new file: blocked,
    // not committed without it. (.sec/web.toml was written; the commit was
    // not made.)
    let repo = hooked();
    repo.write(".gitignore", "/.env\n.sec/\n");
    repo.compose("web", "a: <<gen:db>>\n");
    repo.git(&["add", "-A"]);
    let commits = repo.commit_count();
    let run = commit(&repo, &["-m", "x"]);
    run.fails_with(&["lst: `git --literal-pathspecs add -A -- .sec` failed"]);
    assert_eq!(repo.commit_count(), commits);
}

#[test]
fn unmerged_index_blocks() {
    let repo = hooked();
    repo.compose("web", "a: base\n");
    repo.git(&["add", "-A"]);
    ok(&commit(&repo, &["-m", "base"]));
    repo.git(&["checkout", "-q", "-b", "side"]);
    repo.compose("web", "a: side\n");
    ok(&commit(&repo, &["-am", "side"]));
    repo.git(&["checkout", "-q", "-"]);
    repo.compose("web", "a: main\n");
    ok(&commit(&repo, &["-am", "main"]));
    let merge = repo.git_run(&["merge", "-q", "side"], None);
    assert_ne!(merge.code, Some(0), "{merge:#?}");
    // git itself refuses to commit an unmerged index before running the
    // hook, so run the hook directly.
    lst(&repo, &["hook", "run"]).fails_with(&[
        "lst: stacks/web/compose.yaml has unresolved merge conflicts; resolve them before \
         committing",
    ]);
}

// ---------------------------------------------------------------------------
// run, invoked directly
// ---------------------------------------------------------------------------

#[test]
fn hook_run_by_hand_processes_the_index() {
    let repo = hooked();
    repo.compose("web", "a: <<set:cf:d1r3ct-v4l>>\n");
    repo.git(&["add", "-A"]);
    let run = lst(&repo, &["hook", "run"]);
    run.ok();
    assert!(run.stderr.starts_with("lst: stored web/cf\n"), "{run:#?}");
    assert_eq!(repo.show(":stacks/web/compose.yaml"), "a: <<secret:cf>>\n");
    assert!(repo.show(":.sec/web.toml").contains("[secret.cf]"));
    assert_eq!(repo.read("stacks/web/compose.yaml"), "a: <<secret:cf>>\n");
    // Outside a repository it fails like every command.
    let dir = tempfile::tempdir().unwrap();
    repo.lst_in(dir.path(), &["hook", "run"])
        .fails_with(&["is not inside a git repository"]);
    assert_eq!(ok(&commit(&repo, &["-m", "x"])), "");
    assert_nowhere(&repo, "d1r3ct-v4l");
}
