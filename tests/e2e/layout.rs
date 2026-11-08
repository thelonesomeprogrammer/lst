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
