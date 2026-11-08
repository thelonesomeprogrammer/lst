//! `lst get`: one secret's value on stdout, or in the clipboard.

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::support::{Repo, Run, lst_cmd};

/// The manual secret these tests store: only `get` may print it, on stdout.
const VALUE: &str = "g3t-$ecret";

const WEB: &str = "\
a: <<gen:db>>
b: <<gen:api:hex64>>
c: <<gen:shared/mq>>
d: <<secret:cf>>
";

#[track_caller]
fn lst(repo: &Repo, args: &[&str]) -> Run {
    let run = repo.lst(args);
    assert!(!run.stderr.contains(VALUE), "{run:#?}");
    run
}

/// Stack `web` synced, with `web/cf` set.
fn repo() -> Repo {
    let repo = Repo::initialised();
    repo.compose("web", WEB);
    repo.lst(&["sync"]).ok();
    let mut store = repo.store();
    store.set_secret(&repo.seed(), "web", "cf", VALUE).unwrap();
    store.save(&repo.path().join(".sec")).unwrap();
    repo
}

#[test]
fn get_prints_generated_and_manual_values() {
    let repo = repo();
    let snapshot = repo.snapshot();

    let db = repo.expected_gen("web", "db", "alnum32".parse().unwrap());
    let run = lst(&repo, &["get", "web/db"]);
    assert_eq!(run.ok(), format!("{db}\n"));
    assert_eq!(run.stderr, "");

    let api = repo.expected_gen("web", "api", "hex64".parse().unwrap());
    assert_eq!(lst(&repo, &["get", "web/api"]).ok(), format!("{api}\n"));
    let mq = repo.expected_gen("shared", "mq", "alnum32".parse().unwrap());
    assert_eq!(lst(&repo, &["get", "shared/mq"]).ok(), format!("{mq}\n"));

    // The raw value: `lst render` shows `$$` (compose's escaping), get doesn't.
    assert_eq!(lst(&repo, &["get", "web/cf"]).ok(), format!("{VALUE}\n"));
    assert!(
        lst(&repo, &["render", "web"])
            .ok()
            .contains("d: g3t-$$ecret\n")
    );
    assert_eq!(lst(&repo, &["get", "-n", "web/cf"]).ok(), VALUE);

    // Works from a subdirectory.
    let sub = repo.path().join("stacks/web");
    assert_eq!(
        repo.lst_in(&sub, &["get", "web/db"]).ok(),
        format!("{db}\n")
    );
    assert_eq!(repo.snapshot(), snapshot, "lst get must not write anything");

    // And in a clone with the seed from LST_SEED.
    repo.git(&["add", "-A"]);
    repo.commit(&["-q", "-m", "web"]).ok();
    let clone = repo.clone_repo();
    let run = clone.lst_env(&["get", "web/cf"], repo.seed_hex());
    assert_eq!(run.ok(), format!("{VALUE}\n"));
}

#[test]
fn get_an_orphan_notes_it() {
    let repo = repo();
    let db = repo.expected_gen("web", "db", "alnum32".parse().unwrap());
    repo.compose("web", "b: <<gen:api:hex64>>\n");
    repo.lst(&["sync"]).ok();
    let run = lst(&repo, &["get", "web/db"]);
    assert_eq!(run.ok(), format!("{db}\n"));
    assert_eq!(
        run.stderr,
        "lst: note: web/db is an orphan (no marker uses it any more; `lst gc` lists orphans)\n"
    );
}

#[test]
fn get_refuses_unknown_and_invalid_names() {
    let repo = repo();
    lst(&repo, &["get", "web/nope"]).fails_with(&[
        "`web/nope` has no entry in .sec/ (if a marker uses it, run `lst sync` first); \
         .sec/web.toml has: api, cf, db",
    ]);
    lst(&repo, &["get", "db"]).fails_with(&["\"db\""]);
    // A marker not synced yet.
    repo.compose("web", &format!("{WEB}e: <<gen:new>>\n"));
    lst(&repo, &["get", "web/new"]).fails_with(&["run `lst sync` first"]);
    // -n and --copy don't mix.
    assert_eq!(lst(&repo, &["get", "-n", "--copy", "web/db"]).code, Some(2));
}

#[test]
fn get_needs_the_seed() {
    let repo = repo();
    repo.git(&["add", "-A"]);
    repo.commit(&["-q", "-m", "web"]).ok();
    let clone = repo.clone_repo();
    clone.lst(&["get", "web/db"]).fails_with(&["no .env file"]);
}

/// A directory of fake clipboard tools: `wl-copy` (which `ok_tool` names)
/// stores its stdin in `clip`, every other tool exits 1.
fn fake_tools(dir: &Path, ok_tool: Option<&str>) -> OsString {
    for tool in ["wl-copy", "xclip", "xsel", "pbcopy"] {
        let body = if Some(tool) == ok_tool {
            format!("#!/bin/sh\ncat > '{}'\n", dir.join("clip").display())
        } else {
            "#!/bin/sh\ncat > /dev/null\nexit 1\n".to_owned()
        };
        let path = dir.join(tool);
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mut path = OsString::from(dir);
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap_or_default());
    path
}

fn get_copy(repo: &Repo, path: &OsString) -> Run {
    let out = lst_cmd(repo.path(), &["get", "--copy", "web/cf"])
        .env("PATH", path)
        .output()
        .unwrap();
    let run = Run::from_output(out);
    assert!(
        !run.stdout.contains(VALUE) && !run.stderr.contains(VALUE),
        "{run:#?}"
    );
    run
}

#[test]
fn get_copy_uses_the_first_working_tool() {
    let repo = repo();
    let tools = tempfile::tempdir().unwrap();
    let path = fake_tools(tools.path(), Some("xsel"));
    let run = get_copy(&repo, &path);
    assert_eq!(run.ok(), "");
    assert_eq!(run.stderr, "lst: copied web/cf to the clipboard (xsel)\n");
    // No trailing newline in the clipboard.
    assert_eq!(
        fs::read_to_string(tools.path().join("clip")).unwrap(),
        VALUE
    );
}

#[test]
fn get_copy_without_a_working_tool_fails() {
    let repo = repo();
    let tools = tempfile::tempdir().unwrap();
    let path = fake_tools(tools.path(), None);
    get_copy(&repo, &path)
        .fails_with(&["no clipboard tool worked (tried wl-copy, xclip, xsel, pbcopy)"]);
}
