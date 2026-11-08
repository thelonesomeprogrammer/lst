//! `lst rotate` and `lst gc`: a new value for a generated secret, and
//! listing / removing orphans.

use crate::support::{Repo, Run};

/// The manual secret these tests store; never in any output.
const VALUE: &str = "r0t4t3-m4nu4l";

const HEADER: &str = "# Managed by lst. Do not edit by hand.\n";

const WEB: &str = "\
a: <<gen:db>>
b: <<gen:api:hex64>>
c: <<gen:shared/mq>>
d: <<secret:cf>>
";
const API: &str = "m: <<gen:shared/mq>>\n";

/// `lst <args>`, checked for leaks of the manual value (only `render` may
/// print it, on stdout).
#[track_caller]
fn lst(repo: &Repo, args: &[&str]) -> Run {
    let run = repo.lst(args);
    let rendered = args.first() == Some(&"render");
    assert!(
        (rendered || !run.stdout.contains(VALUE)) && !run.stderr.contains(VALUE),
        "{run:#?}"
    );
    run
}

/// Stacks `web` and `api` synced, with `web/cf` set.
fn repo() -> Repo {
    let repo = Repo::initialised();
    repo.compose("web", WEB);
    repo.compose("api", API);
    repo.lst(&["sync"]).ok();
    let mut store = repo.store();
    store.set_secret(&repo.seed(), "web", "cf", VALUE).unwrap();
    store.save(&repo.path().join(".sec")).unwrap();
    repo
}

/// [`repo`] plus orphans `web/old` (gen), `web/tok` (secret), `shared/gone`
/// and every entry of a removed stack `extra`.
fn with_orphans() -> Repo {
    let repo = repo();
    repo.compose("web", &format!("{WEB}e: <<gen:old>>\nf: <<secret:tok>>\n"));
    repo.compose("extra", "x: <<gen:shared/gone>>\ny: <<gen:only>>\n");
    repo.lst(&["sync"]).ok();
    let mut store = repo.store();
    store.set_secret(&repo.seed(), "web", "tok", "t0k").unwrap();
    store.save(&repo.path().join(".sec")).unwrap();
    repo.compose("web", WEB);
    repo.remove("stacks/extra/compose.yaml");
    repo.lst(&["sync"]).ok();
    repo
}

/// The lines of `a` and `b` that differ (same number of lines).
fn changed_lines<'a>(a: &'a str, b: &'a str) -> Vec<(&'a str, &'a str)> {
    assert_eq!(a.lines().count(), b.lines().count());
    a.lines().zip(b.lines()).filter(|(x, y)| x != y).collect()
}

// ---------------------------------------------------------------------------
// rotate
// ---------------------------------------------------------------------------

#[test]
fn rotate_changes_the_value_and_keeps_the_format() {
    let repo = repo();
    let before = lst(&repo, &["render", "web"]).ok().to_owned();
    let snapshot = repo.snapshot();
    let web_toml = repo.read(".sec/web.toml");

    let run = lst(&repo, &["rotate", "web/api"]);
    assert_eq!(run.ok(), "");
    assert_eq!(
        run.stderr,
        "lst: rotated web/api (new id, same format hex64, so a new value); commit .sec/, then \
         deploy web\n\
         lst: note: an app that only reads it on first start (e.g. a database's initial \
         password) keeps the old value; change it inside the app too\n"
    );

    // Only the `b:` line renders differently, still as 64 lowercase hex.
    let after = lst(&repo, &["render", "web"]).ok().to_owned();
    let changed = changed_lines(&before, &after);
    assert_eq!(changed.len(), 1, "{changed:?}");
    let (old, new) = changed[0];
    assert!(old.starts_with("b: ") && new.starts_with("b: "));
    let new = &new[3..];
    assert_eq!(new.len(), 64);
    assert!(
        new.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    assert_eq!(
        new,
        repo.expected_gen("web", "api", "hex64".parse().unwrap())
    );

    // Only the id line of web/api changed; every other file is identical.
    let mut now = repo.snapshot();
    let mut was = snapshot;
    assert!(now.remove(std::path::Path::new(".sec/web.toml")).is_some());
    was.remove(std::path::Path::new(".sec/web.toml"));
    assert_eq!(now, was);
    let web_now = repo.read(".sec/web.toml");
    let changed = changed_lines(&web_toml, &web_now);
    assert_eq!(changed.len(), 1, "{changed:?}");
    assert!(changed[0].1.starts_with("id = "));
    let api_section = web_now.split("[gen.api]\n").nth(1).unwrap();
    assert!(api_section.starts_with(changed[0].1), "{web_now}");

    // .sec/ is still current.
    let run = lst(&repo, &["sync"]);
    assert_eq!((run.ok(), run.stderr.as_str()), ("", ""));
}

#[test]
fn rotate_a_shared_name_names_every_stack_using_it() {
    let repo = repo();
    let web = lst(&repo, &["render", "web"]).ok().to_owned();
    let api = lst(&repo, &["render", "api"]).ok().to_owned();
    let web_toml = repo.read(".sec/web.toml");

    let run = lst(&repo, &["rotate", "shared/mq"]);
    run.ok();
    assert!(
        run.stderr.starts_with(
            "lst: rotated shared/mq (new id, same format alnum32, so a new value); commit \
             .sec/, then deploy api, web\n"
        ),
        "{run:#?}"
    );
    let (web2, api2) = (
        lst(&repo, &["render", "web"]).ok().to_owned(),
        lst(&repo, &["render", "api"]).ok().to_owned(),
    );
    let changed = changed_lines(&web, &web2);
    assert_eq!(changed.len(), 1, "{changed:?}");
    assert!(changed[0].1.starts_with("c: "));
    assert_ne!(api, api2);
    // The same new value in both stacks.
    assert_eq!(api2, format!("m: {}\n", &changed[0].1[3..]));
    // Only shared.toml changed (api uses no stack-local name: no api.toml).
    assert_eq!(repo.read(".sec/web.toml"), web_toml);
    assert!(!repo.exists(".sec/api.toml"));
}

#[test]
fn rotate_without_a_working_tree_use_says_deploy_the_users() {
    let repo = repo();
    // The marker is gone but no sync ran yet: the entry is still in use.
    repo.compose("web", "d: <<secret:cf>>\n");
    let run = lst(&repo, &["rotate", "web/db"]);
    run.ok();
    assert!(
        run.stderr.starts_with(
            "lst: rotated web/db (new id, same format alnum32, so a new value); commit .sec/, \
             then deploy the stacks that use it\n"
        ),
        "{run:#?}"
    );
}

#[test]
fn rotate_errors_change_nothing() {
    let repo = with_orphans();
    let before = repo.snapshot();
    for (args, needle) in [
        (
            &["rotate", "web/cf"][..],
            "lst: `web/cf` is a manual secret, and lst rotate only gives generated secrets a new \
             value; write <<set:cf:VALUE>> to replace it\n",
        ),
        (
            &["rotate", "web/old"],
            "lst: `web/old` is an orphan (no marker uses it), so there is nothing to rotate; \
             `lst gc --remove web/old` removes it\n",
        ),
        (
            &["rotate", "web/tok"],
            "lst: `web/tok` is an orphan (no marker uses it), so there is nothing to rotate; \
             `lst gc --remove web/tok` removes it\n",
        ),
        (
            &["rotate", "web/nope"],
            "lst: `web/nope` has no entry in .sec/ to rotate (if a <<gen:…>> marker uses it, \
             run `lst sync` first)\n",
        ),
        (
            &["rotate", "db"],
            "lst: invalid full secret name \"db\" (expected <stack>/<name> or shared/<name>; a \
             name allows A-Z a-z 0-9 . _ - and single `/` separators)\n",
        ),
    ] {
        let run = lst(&repo, args);
        assert_eq!(run.fails_with(&[]), needle, "{args:?}");
        assert_eq!(repo.snapshot(), before, "{args:?}");
    }

    // A new marker without an entry yet: same hint.
    repo.compose("web", &format!("{WEB}n: <<gen:fresh>>\n"));
    lst(&repo, &["rotate", "web/fresh"]).fails_with(&["run `lst sync` first"]);

    // The usual guards apply.
    repo.remove(".env");
    lst(&repo, &["rotate", "web/db"]).fails_with(&["no .env file"]);
    for args in [&["rotate"][..], &["rotate", "a/b", "c/d"]] {
        let run = lst(&repo, args);
        assert_eq!(run.code, Some(2), "{args:?}: {run:#?}");
        assert!(run.stderr.contains("Usage: lst rotate"), "{run:#?}");
    }
}

#[test]
fn rotate_then_commit_keeps_the_hook_silent_and_check_passing() {
    let repo = repo();
    repo.git(&["add", "-A"]);
    assert_eq!(repo.commit(&["-m", "stacks"]).ok(), "");
    let run = lst(&repo, &["check"]);
    assert_eq!((run.ok(), run.stderr.as_str()), ("", "lst: check ok\n"));
    let before = repo.show("HEAD:.sec/web.toml");

    lst(&repo, &["rotate", "web/db"]).ok();
    let run = repo.commit(&["-a", "-m", "rotate web/db"]);
    assert_eq!((run.ok(), run.stderr.as_str()), ("", ""));
    let after = repo.show("HEAD:.sec/web.toml");
    assert_ne!(after, before);
    assert_eq!(after, repo.read(".sec/web.toml"));
    let run = lst(&repo, &["check"]);
    assert_eq!((run.ok(), run.stderr.as_str()), ("", "lst: check ok\n"));
}

// ---------------------------------------------------------------------------
// gc
// ---------------------------------------------------------------------------

#[test]
fn gc_lists_orphans_read_only() {
    let repo = with_orphans();
    let before = repo.snapshot();
    let run = lst(&repo, &["gc"]);
    assert_eq!(
        run.ok(),
        "extra/only\nshared/gone\nweb/old\nweb/tok\n",
        "{run:#?}"
    );
    assert_eq!(run.stderr, "");
    assert_eq!(repo.snapshot(), before);
}

#[test]
fn gc_without_orphans_is_a_note() {
    let repo = repo();
    let before = repo.snapshot();
    for args in [&["gc"][..], &["gc", "--remove"]] {
        let run = lst(&repo, args);
        assert_eq!((run.ok(), run.stderr.as_str()), ("", "lst: no orphans\n"));
        assert_eq!(repo.snapshot(), before, "{args:?}");
    }
}

#[test]
fn gc_remove_deletes_every_orphan() {
    let repo = with_orphans();
    let rendered = lst(&repo, &["render", "web"]).ok().to_owned();
    let mq = repo.lst(&["render", "api"]).ok().to_owned();

    let run = lst(&repo, &["gc", "--remove"]);
    assert_eq!(run.ok(), "");
    assert_eq!(
        run.stderr,
        "lst: removed extra/only\n\
         lst: removed shared/gone\n\
         lst: removed web/old\n\
         lst: removed web/tok\n\
         lst: commit .sec/\n"
    );
    let run = lst(&repo, &["gc"]);
    assert_eq!((run.ok(), run.stderr.as_str()), ("", "lst: no orphans\n"));

    // Entries in use are untouched; an emptied file is just the header.
    assert_eq!(lst(&repo, &["render", "web"]).ok(), rendered);
    assert_eq!(repo.lst(&["render", "api"]).ok(), mq);
    assert_eq!(repo.read(".sec/extra.toml"), HEADER);
    let shared = repo.read(".sec/shared.toml");
    assert!(
        shared.contains("[gen.mq]") && !shared.contains("gone"),
        "{shared}"
    );
    let web = repo.read(".sec/web.toml");
    assert!(!web.contains("old") && !web.contains("tok"), "{web}");
    // .sec/ is current.
    let run = lst(&repo, &["sync"]);
    assert_eq!((run.ok(), run.stderr.as_str()), ("", ""));
}

#[test]
fn gc_remove_named_orphans_only() {
    let repo = with_orphans();
    let run = lst(&repo, &["gc", "--remove", "web/old", "shared/gone"]);
    run.ok();
    assert_eq!(
        run.stderr,
        "lst: removed shared/gone\nlst: removed web/old\nlst: commit .sec/\n"
    );
    assert_eq!(lst(&repo, &["gc"]).ok(), "extra/only\nweb/tok\n");
}

#[test]
fn gc_remove_named_is_all_or_nothing() {
    let repo = with_orphans();
    let before = repo.snapshot();
    for (args, needle) in [
        (
            &["gc", "--remove", "web/old", "web/db"][..],
            "lst: `web/db` is in use, not an orphan; lst gc only removes orphans\n",
        ),
        (
            &["gc", "--remove", "web/old", "shared/mq"],
            "lst: `shared/mq` is in use, not an orphan",
        ),
        (
            &["gc", "--remove", "web/old", "web/nope"],
            "lst: `web/nope` has no entry in .sec/\n",
        ),
        (
            &["gc", "--remove", "old"],
            "lst: invalid full secret name \"old\"",
        ),
    ] {
        let run = lst(&repo, args);
        assert!(
            run.fails_with(&[]).starts_with(needle),
            "{args:?}: {run:#?}"
        );
        assert_eq!(repo.snapshot(), before, "{args:?}");
    }

    // Names need --remove.
    let run = lst(&repo, &["gc", "web/old"]);
    assert_eq!(run.code, Some(2), "{run:#?}");
    assert!(run.stderr.contains("--remove"), "{run:#?}");
    assert_eq!(repo.snapshot(), before);
}

#[test]
fn gc_refuses_while_orphans_are_stale() {
    let repo = with_orphans();
    let before = repo.snapshot();
    // web/old is used again, and web/db is no longer used, without a sync.
    repo.compose(
        "web",
        "b: <<gen:api:hex64>>\nc: <<gen:shared/mq>>\nd: <<secret:cf>>\ne: <<gen:old>>\n",
    );
    let wanted = "lst: .sec/ is not current for the working tree (web/db, web/old: orphaned or \
                  used again since the last sync); run `lst sync` first, so lst gc sees what is \
                  really unused\n";
    for args in [
        &["gc"][..],
        &["gc", "--remove"],
        &["gc", "--remove", "web/old"],
    ] {
        let run = lst(&repo, args);
        assert_eq!(run.fails_with(&[]), wanted, "{args:?}");
    }
    repo.compose("web", WEB);
    assert_eq!(repo.snapshot(), before);
}

#[test]
fn a_removed_orphan_that_comes_back_gets_a_new_value() {
    let repo = with_orphans();
    repo.compose("web", &format!("{WEB}e: <<gen:old>>\n"));
    repo.lst(&["sync"]).ok();
    let old = lst(&repo, &["render", "web"]).ok().to_owned();

    repo.compose("web", WEB);
    repo.lst(&["sync"]).ok();
    lst(&repo, &["gc", "--remove", "web/old"]).ok();

    repo.compose("web", &format!("{WEB}e: <<gen:old>>\n"));
    let run = lst(&repo, &["sync"]);
    assert_eq!(run.stderr, "lst: new: web/old\n", "{run:#?}");
    let new = lst(&repo, &["render", "web"]).ok().to_owned();
    let changed = changed_lines(&old, &new);
    assert_eq!(changed.len(), 1, "{changed:?}");
    assert!(changed[0].0.starts_with("e: ") && changed[0].1.starts_with("e: "));
}
