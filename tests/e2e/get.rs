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

// ---------------------------------------------------------------------------
// Agreement with render, and with the other commands
// ---------------------------------------------------------------------------

/// The value after `key: ` on its own line of `text`.
fn line_value<'a>(text: &'a str, key: &str) -> &'a str {
    let prefix = format!("{key}: ");
    text.lines()
        .find_map(|l| l.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("no {key:?} line in {text:?}"))
}

#[test]
fn get_agrees_with_render_for_every_format() {
    let repo = Repo::initialised();
    let formats = [
        "alnum22",
        "alnum32",
        "alnum256",
        "hex32",
        "hex64",
        "hex256",
        "base64-22",
        "base64-43",
        "base64-256",
        "uuid",
    ];
    let compose: String = formats
        .iter()
        .enumerate()
        .map(|(i, f)| format!("k{i}: <<gen:s{i}:{f}>>\n"))
        .collect();
    repo.compose("web", &compose);
    repo.lst(&["sync"]).ok();
    let rendered = lst(&repo, &["render", "web"]).ok().to_owned();
    for (i, f) in formats.iter().enumerate() {
        let got = lst(&repo, &["get", &format!("web/s{i}")]).ok().to_owned();
        let want = line_value(&rendered, &format!("k{i}"));
        assert_eq!(got, format!("{want}\n"), "format {f}");
        let fmt = f.parse().unwrap();
        assert_eq!(want, repo.expected_gen("web", &format!("s{i}"), fmt));
    }
}

#[test]
fn the_same_name_in_two_stacks_has_two_values_and_shared_has_one() {
    let repo = repo();
    repo.compose("api", "a: <<gen:db>>\nm: <<gen:shared/mq>>\n");
    repo.lst(&["sync"]).ok();
    let web = lst(&repo, &["get", "web/db"]).ok().to_owned();
    let api = lst(&repo, &["get", "api/db"]).ok().to_owned();
    assert_ne!(web, api);
    let api_render = lst(&repo, &["render", "api"]).ok().to_owned();
    assert_eq!(api, format!("{}\n", line_value(&api_render, "a")));
    let mq = lst(&repo, &["get", "shared/mq"]).ok().to_owned();
    assert_eq!(mq, format!("{}\n", line_value(&api_render, "m")));
    // `web/mq` is not `shared/mq`: the stack file has no such key.
    lst(&repo, &["get", "web/mq"]).fails_with(&["`web/mq` has no entry"]);
}

#[test]
fn get_follows_rotate_and_rename() {
    let repo = repo();
    let before = lst(&repo, &["get", "web/api"]).ok().to_owned();
    lst(&repo, &["rotate", "web/api"]).ok();
    let after = lst(&repo, &["get", "web/api"]).ok().to_owned();
    assert_ne!(before, after);
    assert_eq!(after.len(), 65);

    // A rename keeps the value under the new name.
    repo.compose(
        "web",
        &WEB.replace("<<gen:api:hex64>>", "<<gen:key:hex64>>"),
    );
    repo.lst(&["sync"]).ok();
    lst(&repo, &["rename", "web/api", "key", "--replace"]).ok();
    assert_eq!(lst(&repo, &["get", "web/key"]).ok(), after);
    lst(&repo, &["get", "web/api"]).fails_with(&["`web/api` has no entry"]);

    // So does a renamed manual secret (re-encrypted under the new name).
    lst(&repo, &["rename", "web/cf", "token"]).ok();
    assert_eq!(lst(&repo, &["get", "web/token"]).ok(), format!("{VALUE}\n"));
}

#[test]
fn a_value_stored_by_the_hook_reads_back_unescaped() {
    let repo = Repo::initialised();
    // `\>` and `\\` are the marker escapes; the space, `:` and unicode are
    // taken as they are.
    repo.compose("web", "pw: \"<<set:pw:a b:c\\>d\\\\e ünï>>\"\n");
    repo.git(&["add", "-A"]);
    let run = repo.commit(&["-m", "set pw"]);
    assert_eq!(run.code, Some(0), "{run:#?}");
    assert_eq!(
        repo.read("stacks/web/compose.yaml"),
        "pw: \"<<secret:pw>>\"\n"
    );
    let run = repo.lst(&["get", "web/pw"]);
    assert_eq!(run.ok(), "a b:c>d\\e ünï\n");
    assert!(!run.stderr.contains("ünï"), "{run:#?}");
}

#[test]
fn a_marker_that_switches_kind_shows_the_entry_in_use() {
    let repo = repo();
    let gen_db = lst(&repo, &["get", "web/db"]).ok().to_owned();
    // gen → secret: the gen entry is an orphan and the secret is unset, so
    // get still shows the old generated value (the app may still use it).
    repo.compose("web", &WEB.replace("<<gen:db>>", "<<secret:db>>"));
    repo.lst(&["sync"]).ok();
    let run = lst(&repo, &["get", "web/db"]);
    assert_eq!(run.ok(), gen_db);
    assert!(run.stderr.contains("web/db is an orphan"), "{run:#?}");

    // Once the secret has a value, that's the entry in use.
    repo.compose("web", &WEB.replace("<<gen:db>>", "<<set:db:m4nual>>"));
    repo.git(&["add", "-A"]);
    assert_eq!(repo.commit(&["-m", "db"]).code, Some(0));
    let run = lst(&repo, &["get", "web/db"]);
    assert_eq!(run.ok(), "m4nual\n");
    assert_eq!(run.stderr, "");
}

#[test]
fn an_orphaned_manual_secret_is_shown_with_a_note() {
    let repo = repo();
    repo.compose("web", &WEB.replace("d: <<secret:cf>>\n", ""));
    repo.lst(&["sync"]).ok();
    let run = lst(&repo, &["get", "web/cf"]);
    assert_eq!(run.ok(), format!("{VALUE}\n"));
    assert!(run.stderr.contains("web/cf is an orphan"), "{run:#?}");
    // gc removes it, and then it's gone.
    lst(&repo, &["gc", "--remove", "web/cf"]).ok();
    lst(&repo, &["get", "web/cf"]).fails_with(&["`web/cf` has no entry"]);
}

// ---------------------------------------------------------------------------
// Guards: nothing is shown unless the seed checks out
// ---------------------------------------------------------------------------

/// [`repo`], committed.
fn committed() -> Repo {
    let repo = repo();
    repo.git(&["add", "-A"]);
    assert_eq!(repo.commit(&["-m", "web"]).code, Some(0));
    repo
}

#[test]
fn get_refuses_when_env_is_not_gitignored() {
    let repo = committed();
    repo.remove(".gitignore");
    lst(&repo, &["get", "web/cf"]).fails_with(&[".env is not gitignored"]);
    let clone = repo.clone_repo();
    clone.remove(".gitignore");
    let run = clone.lst_env(&["get", "web/cf"], repo.seed_hex());
    run.fails_with(&[".env is not gitignored"]);
}

#[test]
fn get_refuses_a_wrong_or_conflicting_seed() {
    let repo = committed();
    let other = Repo::initialised().seed_hex();
    let clone = repo.clone_repo();
    // A valid seed, but not the one of .sec/.
    let run = clone.lst_env(&["get", "web/cf"], &other);
    assert_eq!(run.code, Some(1), "{run:#?}");
    assert_eq!(run.stdout, "");
    assert!(!run.stderr.contains(VALUE));
    // Garbage in LST_SEED.
    clone
        .lst_env(&["get", "web/cf"], "nope")
        .fails_with(&["not 64 lowercase hex characters"]);
    // LST_SEED and .env disagree.
    repo.lst_env(&["get", "web/cf"], &other)
        .fails_with(&["LST_SEED and .env disagree"]);
}

#[test]
fn get_usage_errors() {
    let repo = repo();
    assert_eq!(repo.lst(&["get"]).code, Some(2));
    assert_eq!(repo.lst(&["get", "web/db", "web/api"]).code, Some(2));
    for bad in ["/db", "web/", "nosuch-stack-is-fine/../x", "web/a:b"] {
        let run = lst(&repo, &["get", bad]);
        assert_eq!(run.code, Some(1), "{bad}: {run:#?}");
        assert_eq!(run.stdout, "");
    }
}

// ---------------------------------------------------------------------------
// --copy
// ---------------------------------------------------------------------------

#[test]
fn get_copy_prefers_wl_copy_and_copies_generated_values_too() {
    let repo = repo();
    let tools = tempfile::tempdir().unwrap();
    let path = fake_tools(tools.path(), Some("wl-copy"));
    let out = lst_cmd(repo.path(), &["get", "--copy", "web/api"])
        .env("PATH", &path)
        .output()
        .unwrap();
    let run = Run::from_output(out);
    assert_eq!(run.ok(), "");
    assert_eq!(
        run.stderr,
        "lst: copied web/api to the clipboard (wl-copy)\n"
    );
    let want = repo.expected_gen("web", "api", "hex64".parse().unwrap());
    assert_eq!(fs::read_to_string(tools.path().join("clip")).unwrap(), want);
}

/// The absolute path of `program` on the inherited `PATH`.
fn which(program: &str) -> std::path::PathBuf {
    std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|d| d.join(program))
        .find(|p| p.is_file())
        .unwrap()
}

/// A `PATH` holding only `git` (a symlink) and the fake tools in `names`,
/// so no real clipboard tool on the machine can be reached.
fn only_these_tools(dir: &Path, names: &[&str]) -> OsString {
    std::os::unix::fs::symlink(which("git"), dir.join("git")).unwrap();
    let cat = which("cat");
    for name in names {
        let path = dir.join(name);
        let clip = dir.join("clip");
        let body = format!("#!/bin/sh\n'{}' > '{}'\n", cat.display(), clip.display());
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    dir.as_os_str().to_owned()
}

#[test]
fn get_copy_skips_tools_that_are_not_installed() {
    let repo = repo();
    let tools = tempfile::tempdir().unwrap();
    let path = only_these_tools(tools.path(), &["pbcopy"]);
    let run = get_copy(&repo, &path);
    assert_eq!(run.ok(), "");
    assert_eq!(run.stderr, "lst: copied web/cf to the clipboard (pbcopy)\n");
    assert_eq!(
        fs::read_to_string(tools.path().join("clip")).unwrap(),
        VALUE
    );

    let none = tempfile::tempdir().unwrap();
    let path = only_these_tools(none.path(), &[]);
    get_copy(&repo, &path).fails_with(&["no clipboard tool worked"]);
}

#[test]
fn get_copy_an_orphan_notes_it_and_copies() {
    let repo = repo();
    repo.compose("web", &WEB.replace("d: <<secret:cf>>\n", ""));
    repo.lst(&["sync"]).ok();
    let tools = tempfile::tempdir().unwrap();
    let run = get_copy(&repo, &fake_tools(tools.path(), Some("xclip")));
    assert_eq!(run.ok(), "");
    assert_eq!(
        run.stderr,
        "lst: note: web/cf is an orphan (no marker uses it any more; `lst gc` lists orphans)\n\
         lst: copied web/cf to the clipboard (xclip)\n"
    );
    assert_eq!(
        fs::read_to_string(tools.path().join("clip")).unwrap(),
        VALUE
    );
}
