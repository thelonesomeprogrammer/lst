//! Repository layouts: every compose file name Docker knows, and Docker's
//! precedence when a stack has several.

use crate::support::{Repo, Run};

const PLAINTEXTS: &[&str] = &["l4y0ut-v4l", "sh4d0w-v4l"];

#[track_caller]
fn no_leak(run: &Run) {
    for p in PLAINTEXTS {
        assert!(
            !run.stdout.contains(p) && !run.stderr.contains(p),
            "{p} leaked: {run:#?}"
        );
    }
}

fn hooked() -> Repo {
    let repo = Repo::initialised();
    repo.git(&["add", "-A"]);
    let run = repo.commit(&["-m", "init"]);
    assert_eq!(run.code, Some(0), "{run:#?}");
    repo
}

#[test]
fn every_compose_file_name_is_a_stack() {
    for name in [
        "compose.yaml",
        "compose.yml",
        "docker-compose.yaml",
        "docker-compose.yml",
    ] {
        let repo = hooked();
        let path = format!("stacks/web/{name}");
        repo.write(&path, "a: <<gen:db>>\ntoken: <<set:cf:l4y0ut-v4l>>\n");
        repo.git(&["add", "stacks"]);
        let run = repo.commit(&["-m", "web"]);
        no_leak(&run);
        assert_eq!(run.code, Some(0), "{name}: {run:#?}");
        assert!(
            run.stderr
                .starts_with("lst: new: web/db\nlst: stored web/cf\n"),
            "{run:#?}"
        );
        let committed = "a: <<gen:db>>\ntoken: <<secret:cf>>\n";
        assert_eq!(repo.show(&format!("HEAD:{path}")), committed, "{name}");
        assert_eq!(repo.read(&path), committed, "{name}");

        let run = repo.lst(&["render", "web"]);
        let db = repo.expected_gen("web", "db", "alnum32".parse().unwrap());
        assert_eq!(run.ok(), format!("a: {db}\ntoken: l4y0ut-v4l\n"), "{name}");
        assert_eq!(run.stderr, "", "{name}");
        repo.lst(&["sync"]).ok();
        repo.lst(&["check"]).ok();
    }
}

#[test]
fn several_compose_files_follow_docker_precedence_and_warn() {
    let repo = hooked();
    repo.write("stacks/web/compose.yaml", "used: <<gen:db>>\n");
    // Shadowed, but still a stack file: its <<set:…>> is stored, not committed.
    repo.write(
        "stacks/web/docker-compose.yml",
        "ignored: <<set:cf:sh4d0w-v4l>>\n",
    );
    repo.git(&["add", "stacks"]);
    let run = repo.commit(&["-m", "web"]);
    no_leak(&run);
    assert_eq!(run.code, Some(0), "{run:#?}");
    let warning = "lst: stack web: using stacks/web/compose.yaml, ignoring \
                   stacks/web/docker-compose.yml (Docker's precedence); merge it into the first \
                   or remove it\n";
    assert!(run.stderr.starts_with(warning), "{run:#?}");
    assert_eq!(
        repo.show("HEAD:stacks/web/docker-compose.yml"),
        "ignored: <<secret:cf>>\n"
    );
    assert!(repo.show("HEAD:.sec/web.toml").contains("[secret.cf]"));

    let run = repo.lst(&["render", "web"]);
    let db = repo.expected_gen("web", "db", "alnum32".parse().unwrap());
    assert_eq!(run.ok(), format!("used: {db}\n"));
    assert_eq!(run.stderr, warning);
    let run = repo.lst(&["sync"]);
    run.ok();
    assert!(run.stderr.starts_with(warning), "{run:#?}");
}

// ---------------------------------------------------------------------------
// The stacks directory (`lst stacks-dir`, `stacks_dir` in .sec/meta.toml)
// ---------------------------------------------------------------------------

fn stacks_dir(repo: &Repo) -> String {
    repo.lst(&["stacks-dir"]).ok().to_owned()
}

#[test]
fn stacks_dir_defaults_to_stacks_and_is_not_written() {
    let repo = Repo::initialised();
    assert_eq!(stacks_dir(&repo), "stacks\n");
    let meta = repo.read(".sec/meta.toml");
    let run = repo.lst(&["stacks-dir", "stacks"]);
    run.ok();
    assert_eq!(
        run.stderr,
        "lst: the stacks directory is already stacks (0 stacks there)\n"
    );
    assert_eq!(repo.read(".sec/meta.toml"), meta);
}

#[test]
fn stacks_dir_refuses_bad_dirs_and_changes_nothing() {
    let repo = Repo::initialised();
    let before = repo.snapshot();
    for bad in ["../x", "/abs", ".sec", "a b", ""] {
        repo.lst(&["stacks-dir", bad])
            .fails_with(&[&format!("invalid stacks directory {bad:?}")]);
    }
    // A broken stack under the new root: refused before anything is written.
    repo.write("Bad Name/compose.yaml", "");
    repo.lst(&["stacks-dir", "."])
        .fails_with(&["invalid stack name \"Bad Name\""]);
    repo.remove("Bad Name/compose.yaml");
    std::fs::remove_dir(repo.path().join("Bad Name")).unwrap();
    assert_eq!(repo.snapshot(), before);
}

#[test]
fn a_nested_stacks_dir_works_end_to_end() {
    let repo = hooked();
    repo.write(
        "apps/web/docker-compose.yml",
        "a: <<gen:db>>\ntoken: <<set:cf:l4y0ut-v4l>>\n",
    );
    let run = repo.lst(&["stacks-dir", "apps"]);
    run.ok();
    assert_eq!(
        run.stderr,
        "lst: the stacks directory is now apps (1 stack there); commit .sec/meta.toml\n"
    );
    assert_eq!(stacks_dir(&repo), "apps\n");
    assert!(
        repo.read(".sec/meta.toml")
            .ends_with("stacks_dir = \"apps\"\n")
    );

    repo.git(&["add", "-A"]);
    let run = repo.commit(&["-m", "apps"]);
    no_leak(&run);
    assert_eq!(run.code, Some(0), "{run:#?}");
    assert!(
        repo.show("HEAD:.sec/meta.toml")
            .contains("stacks_dir = \"apps\"")
    );
    assert_eq!(
        repo.show("HEAD:apps/web/docker-compose.yml"),
        "a: <<gen:db>>\ntoken: <<secret:cf>>\n"
    );

    let db = repo.expected_gen("web", "db", "alnum32".parse().unwrap());
    let run = repo.lst(&["render", "web"]);
    assert_eq!(run.ok(), format!("a: {db}\ntoken: l4y0ut-v4l\n"));
    repo.lst(&["check"]).ok();
    let run = repo.lst(&["deploy", "--dry-run", "--all"]);
    run.ok();
    assert!(
        run.stderr.contains("--project-directory apps/web -f - up"),
        "{run:#?}"
    );
    // A <<set:…>> in the old default root is outside every stack now.
    repo.write("stacks/old/compose.yaml", "x: <<set:cf:sh4d0w-v4l>>\n");
    repo.git(&["add", "-A"]);
    let run = repo.commit(&["-m", "old"]);
    no_leak(&run);
    assert_eq!(run.code, Some(1), "{run:#?}");
    assert!(
        run.stderr
            .contains("stacks/old/compose.yaml: contains `<<set:` but is not a file of a stack"),
        "{run:#?}"
    );
}

#[test]
fn a_flat_layout_works_end_to_end() {
    let repo = hooked();
    repo.lst(&["stacks-dir", "."]).ok();
    repo.write(
        "web/compose.yml",
        "a: <<gen:db>>\ntoken: <<set:cf:l4y0ut-v4l>>\n",
    );
    repo.write("docs/notes.md", "nothing here\n");
    repo.write("README.md", "readme\n");
    repo.git(&["add", "-A"]);
    let run = repo.commit(&["-m", "flat"]);
    no_leak(&run);
    assert_eq!(run.code, Some(0), "{run:#?}");
    assert_eq!(
        repo.show("HEAD:web/compose.yml"),
        "a: <<gen:db>>\ntoken: <<secret:cf>>\n"
    );
    let db = repo.expected_gen("web", "db", "alnum32".parse().unwrap());
    assert_eq!(
        repo.lst(&["render", "web"]).ok(),
        format!("a: {db}\ntoken: l4y0ut-v4l\n")
    );
    repo.lst(&["check"]).ok();

    // Changes outside stacks deploy nothing and say nothing.
    repo.write("docs/notes.md", "changed\n");
    repo.write(".github/ci.yml", "x\n");
    repo.git(&["add", "-A"]);
    assert_eq!(repo.commit(&["-m", "docs"]).code, Some(0));
    let run = repo.lst(&["deploy", "--dry-run", "--changed-since", "HEAD~1"]);
    run.ok();
    assert_eq!(run.stderr, "lst: nothing to deploy\n");
    let run = repo.lst(&["deploy", "--dry-run", "--changed-since", "HEAD~2"]);
    run.ok();
    assert!(
        run.stderr.contains("--project-directory web -f - up"),
        "{run:#?}"
    );

    // A <<set:…>> in a top-level file that is no stack's still blocks.
    repo.write("README.md", "<<set:cf:sh4d0w-v4l>>\n");
    repo.git(&["add", "-A"]);
    let run = repo.commit(&["-m", "leak"]);
    no_leak(&run);
    assert_eq!(run.code, Some(1), "{run:#?}");
    assert!(
        run.stderr
            .contains("README.md: contains `<<set:` but is not a file of a stack"),
        "{run:#?}"
    );
}
