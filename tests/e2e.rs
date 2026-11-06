//! End-to-end tests: the real `lst` binary in throwaway git repositories.
//!
//! Tests that need Docker are `#[ignore]`d; run them with
//! `cargo test --test e2e -- --ignored docker`.

#[path = "e2e/support.rs"]
mod support;

use std::fs::{self, File, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::process::Stdio;

use lst::crypto::{self, Seed};
use lst::format::Format;
use support::{Repo, Run, lst_cmd};

const OTHER_SEED: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

fn fmt(s: &str) -> Format {
    s.parse().unwrap()
}

fn mode(repo: &Repo, rel: &str) -> u32 {
    fs::metadata(repo.path().join(rel))
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

/// Asserts that no part of the seed shows up in either output stream.
#[track_caller]
fn assert_no_seed(run: &Run, seed_hex: &str) {
    for half in [&seed_hex[..32], &seed_hex[32..]] {
        assert!(!run.stdout.contains(half), "{run:#?}");
        assert!(!run.stderr.contains(half), "{run:#?}");
    }
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

#[test]
fn init_fresh_repo() {
    let repo = Repo::new();
    let run = repo.lst(&["init"]);
    assert_eq!(run.ok(), "");
    assert!(
        run.stderr.contains("added `/.env` to .gitignore"),
        "{run:#?}"
    );
    assert!(run.stderr.contains("generated a new seed"), "{run:#?}");
    assert!(run.stderr.contains("back up the seed"), "{run:#?}");

    let env = repo.read(".env");
    let seed_hex = repo.seed_hex();
    assert_eq!(env, format!("LST_SEED={seed_hex}\n"));
    assert_eq!(mode(&repo, ".env"), 0o600);
    assert_no_seed(&run, &seed_hex);

    assert_eq!(repo.read(".gitignore"), "/.env\n");
    let meta = repo.read(".sec/meta.toml");
    assert!(meta.contains(&crypto::fingerprint(&repo.seed())), "{meta}");
    assert_eq!(repo.store().files().len(), 0);
    // Two fresh repos never share a seed.
    assert_ne!(Repo::initialised().seed_hex(), seed_hex);
}

#[test]
fn init_twice_is_idempotent() {
    let repo = Repo::initialised();
    let before = repo.snapshot();
    let run = repo.lst(&["init"]);
    assert_eq!(run.ok(), "");
    assert_eq!(
        run.stderr,
        "lst: already initialised (the seed in .env matches .sec/meta.toml)\n"
    );
    assert_eq!(repo.snapshot(), before);
}

#[test]
fn init_keeps_existing_env_lines_and_permissions() {
    let repo = Repo::new();
    repo.write(".gitignore", "target");
    repo.write(".env", "A=1\r\nB=2");
    fs::set_permissions(repo.path().join(".env"), Permissions::from_mode(0o640)).unwrap();
    let run = repo.lst(&["init"]);
    run.ok();
    let seed_hex = repo.seed_hex();
    assert_eq!(
        repo.read(".env"),
        format!("A=1\r\nB=2\r\nLST_SEED={seed_hex}\r\n")
    );
    assert_eq!(mode(&repo, ".env"), 0o640);
    assert_eq!(repo.read(".gitignore"), "target\n/.env\n");
    assert_no_seed(&run, &seed_hex);
}

#[test]
fn init_with_already_ignored_env_does_not_touch_gitignore() {
    let repo = Repo::new();
    repo.write(".gitignore", ".env\n");
    let run = repo.lst(&["init"]);
    run.ok();
    assert!(!run.stderr.contains(".gitignore"), "{run:#?}");
    assert_eq!(repo.read(".gitignore"), ".env\n");
}

#[test]
fn init_refuses_a_tracked_env() {
    let repo = Repo::new();
    repo.write(".env", "A=1\n");
    repo.git(&["add", ".env"]);
    repo.lst(&["init"])
        .fails_with(&[".env is tracked by git", "git rm --cached .env"]);
    assert_eq!(repo.read(".env"), "A=1\n");
    assert!(!repo.exists(".sec"));
    assert!(!repo.exists(".gitignore"));
}

#[test]
fn init_with_sec_but_no_seed_refuses_and_creates_no_seed() {
    let repo = Repo::initialised();
    let meta = repo.read(".sec/meta.toml");

    // .env gone entirely.
    repo.remove(".env");
    repo.lst(&["init"]).fails_with(&[
        "this repo is already initialised; put the seed from your password manager into .env as LST_SEED=",
    ]);
    assert!(!repo.exists(".env"));

    // .env present but without a seed line.
    repo.write(".env", "OTHER=1\n");
    repo.lst(&["init"])
        .fails_with(&["already initialised", "LST_SEED="]);
    assert_eq!(repo.read(".env"), "OTHER=1\n");
    assert_eq!(repo.read(".sec/meta.toml"), meta);
}

#[test]
fn init_with_existing_seed_and_no_sec_writes_meta() {
    let repo = Repo::new();
    let env = format!("# mine\nPG_USER=app\nLST_SEED={OTHER_SEED}\n");
    repo.write(".env", &env);
    let run = repo.lst(&["init"]);
    run.ok();
    assert!(
        run.stderr.contains("for the seed already in .env"),
        "{run:#?}"
    );
    assert!(run.stderr.contains("back up the seed"), "{run:#?}");
    assert_no_seed(&run, OTHER_SEED);
    assert_eq!(repo.read(".env"), env);
    let seed = Seed::from_hex(OTHER_SEED).unwrap();
    repo.store().verify_seed(&seed).unwrap();
}

#[test]
fn init_with_wrong_seed_fails() {
    let repo = Repo::initialised();
    repo.write(".env", format!("LST_SEED={OTHER_SEED}\n"));
    let before = repo.snapshot();
    let run = repo.lst(&["init"]);
    run.fails_with(&["wrong seed", "fingerprint does not match .sec/meta.toml"]);
    assert_no_seed(&run, OTHER_SEED);
    assert_eq!(repo.snapshot(), before);
}

#[test]
fn init_refuses_sec_files_without_meta() {
    let repo = Repo::new();
    repo.write(".sec/web.toml", "# Managed by lst. Do not edit by hand.\n");
    repo.lst(&["init"])
        .fails_with(&[".sec/ exists but has no meta.toml"]);
    assert!(!repo.exists(".env"));
    assert!(!repo.exists(".sec/meta.toml"));

    // An empty .sec/ is fine.
    let repo = Repo::new();
    fs::create_dir(repo.path().join(".sec")).unwrap();
    repo.lst(&["init"]).ok();
    assert!(repo.exists(".sec/meta.toml"));
}

#[test]
fn init_reports_a_corrupt_meta_toml() {
    let repo = Repo::initialised();
    repo.write(".sec/meta.toml", "version = \n");
    let before = repo.snapshot();
    repo.lst(&["init"])
        .fails_with(&[".sec/meta.toml: invalid TOML at line 1"]);
    assert_eq!(repo.snapshot(), before);
}

#[test]
fn init_rejects_bad_env_files() {
    let repo = Repo::new();
    repo.write(".env", b"A=\xff\n");
    repo.lst(&["init"]).fails_with(&[".env is not valid UTF-8"]);

    repo.write(".env", "PASSWORD=hunter2\nexport LST_SEED=abc\n");
    let err = repo.lst(&["init"]);
    err.fails_with(&[".env line 2: the seed line must be exactly"]);
    assert!(!err.stderr.contains("hunter2"));

    // .env is a directory: reading it fails with the path in the message.
    let repo = Repo::new();
    fs::create_dir(repo.path().join(".env")).unwrap();
    repo.lst(&["init"]).fails_with(&[".env: "]);
    assert!(!repo.exists(".sec"));
}

#[test]
fn commands_outside_a_repo_fail() {
    let dir = tempfile::tempdir().unwrap();
    let repo = Repo::new();
    for cmd in [&["init"][..], &["sync"], &["render", "web"]] {
        repo.lst_in(dir.path(), cmd)
            .fails_with(&["is not inside a git repository"]);
    }
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn commands_work_from_a_subdirectory() {
    let repo = Repo::initialised();
    repo.compose("web", "pw: <<gen:db>>\n");
    let sub = repo.path().join("stacks/web");
    repo.lst_in(&sub, &["sync"]).ok();
    let out = repo.lst_in(&sub, &["render", "web"]);
    let expected = format!("pw: {}\n", repo.expected_gen("web", "db", fmt("alnum32")));
    assert_eq!(out.ok(), expected);
}

// ---------------------------------------------------------------------------
// sync
// ---------------------------------------------------------------------------

#[test]
fn sync_adds_ids_and_second_sync_changes_nothing() {
    let repo = Repo::initialised();
    repo.compose(
        "web",
        "a: <<gen:db>>\nb: <<gen:api:hex64>>\nc: <<secret:cf>>\nd: <<gen:db>>\n",
    );
    let run = repo.lst(&["sync"]);
    assert_eq!(run.ok(), "");
    assert_eq!(
        run.stderr,
        "lst: new: web/api\nlst: new: web/db\n\
         lst: not set: web/cf (render fails until it has a value)\n"
    );
    let store = repo.store();
    let web = &store.files()["web"];
    assert_eq!(web.generated.len(), 2);
    assert_eq!(web.generated["api"].format, fmt("hex64"));
    assert!(!web.generated["db"].orphan);
    assert!(web.secrets.is_empty());

    let before = repo.snapshot();
    let run = repo.lst(&["sync"]);
    assert_eq!(run.ok(), "");
    // Quiet when nothing changed, apart from the still-unset secret.
    assert_eq!(
        run.stderr,
        "lst: not set: web/cf (render fails until it has a value)\n"
    );
    assert_eq!(repo.snapshot(), before);
}

#[test]
fn sync_with_no_changes_is_silent() {
    let repo = Repo::initialised();
    let run = repo.lst(&["sync"]);
    assert_eq!((run.ok(), run.stderr.as_str()), ("", ""));
    repo.compose("web", "a: <<gen:db>>\n");
    repo.lst(&["sync"]).ok();
    let run = repo.lst(&["sync"]);
    assert_eq!((run.ok(), run.stderr.as_str()), ("", ""));
}

#[test]
fn sync_orphans_unorphans_and_changes_formats() {
    let repo = Repo::initialised();
    repo.compose("web", "a: <<gen:db>>\nb: <<gen:api>>\n");
    repo.compose("old", "a: <<gen:x>>\n");
    repo.lst(&["sync"]).ok();
    let api_id = repo.store().files()["web"].generated["api"].id;

    repo.compose("web", "a: <<gen:db:hex32>>\n");
    fs::remove_dir_all(repo.path().join("stacks/old")).unwrap();
    let run = repo.lst(&["sync"]);
    run.ok();
    assert_eq!(
        run.stderr,
        "lst: format changed: web/db (alnum32 -> hex32), so its value changes\n\
         lst: orphaned: old/x (no longer used; kept in .sec/)\n\
         lst: orphaned: web/api (no longer used; kept in .sec/)\n"
    );
    let store = repo.store();
    assert!(store.files()["web"].generated["api"].orphan);
    assert!(store.files()["old"].generated["x"].orphan);
    assert!(repo.read(".sec/web.toml").contains("orphan = true"));

    repo.compose("web", "a: <<gen:db:hex32>>\nb: <<gen:api>>\n");
    let run = repo.lst(&["sync"]);
    run.ok();
    assert_eq!(run.stderr, "lst: in use again: web/api\n");
    // Same id, so the same value as before it was orphaned.
    assert_eq!(repo.store().files()["web"].generated["api"].id, api_id);
}

#[test]
fn sync_and_render_share_shared_names_across_stacks() {
    let repo = Repo::initialised();
    repo.compose("web", "mqtt: <<gen:shared/mqtt>>\nown: <<gen:db>>\n");
    repo.compose("worker", "mqtt: <<gen:shared/mqtt>>\nown: <<gen:db>>\n");
    let run = repo.lst(&["sync"]);
    run.ok();
    assert_eq!(
        run.stderr,
        "lst: new: shared/mqtt\nlst: new: web/db\nlst: new: worker/db\n"
    );
    let store = repo.store();
    assert_eq!(store.files()["shared"].generated.len(), 1);

    let mqtt = repo.expected_gen("shared", "mqtt", Format::default());
    let web = repo.lst(&["render", "web"]);
    let worker = repo.lst(&["render", "worker"]);
    let web_db = repo.expected_gen("web", "db", Format::default());
    let worker_db = repo.expected_gen("worker", "db", Format::default());
    assert_ne!(web_db, worker_db);
    assert_eq!(web.ok(), format!("mqtt: {mqtt}\nown: {web_db}\n"));
    assert_eq!(worker.ok(), format!("mqtt: {mqtt}\nown: {worker_db}\n"));

    // Removing it from one stack doesn't orphan it.
    repo.compose("worker", "own: <<gen:db>>\n");
    let run = repo.lst(&["sync"]);
    assert_eq!((run.ok(), run.stderr.as_str()), ("", ""));
}

#[test]
fn sync_refuses_set_markers_without_leaking_the_value() {
    let repo = Repo::initialised();
    repo.compose("web", "a: <<gen:db>>\nb: <<set:cf:sup3r-s3cret>>\n");
    let before = repo.snapshot();
    let run = repo.lst(&["sync"]);
    run.fails_with(&["`web/cf`", "pre-commit hook"]);
    assert!(!run.stderr.contains("sup3r"), "{run:#?}");
    assert_eq!(repo.snapshot(), before);

    // render refuses it too, without the value.
    repo.compose("web", "b: <<set:cf:sup3r-s3cret>>\n");
    let run = repo.lst(&["render", "web"]);
    run.fails_with(&["`web/cf`", "cannot be rendered"]);
    assert!(!run.stderr.contains("sup3r"), "{run:#?}");
}

#[test]
fn marker_errors_report_path_line_and_column() {
    let repo = Repo::initialised();
    repo.compose("web", "services:\n  db:\n    pw: \"ä<<gen:bad name>>\"\n");
    let before = repo.snapshot();
    // Column 20 counts `ä` as one char (it is byte 21).
    let expected = "lst: stacks/web/compose.yaml:3:20: invalid character in secret name";
    let run = repo.lst(&["sync"]);
    run.fails_with(&[expected]);
    assert_eq!(repo.snapshot(), before);
    repo.lst(&["render", "web"]).fails_with(&[expected]);

    repo.compose("web", "a: <<gen:db\n");
    repo.lst(&["sync"])
        .fails_with(&["stacks/web/compose.yaml:1:4: unterminated marker"]);
}

#[test]
fn sync_and_render_report_unreadable_compose_files() {
    let repo = Repo::initialised();
    repo.compose("web", "a: 1\n");
    repo.write("stacks/web/compose.yaml", b"a: \xff\n");
    repo.lst(&["sync"])
        .fails_with(&["stacks/web/compose.yaml: stream did not contain valid UTF-8"]);
    repo.lst(&["render", "web"])
        .fails_with(&["stacks/web/compose.yaml: stream did not contain valid UTF-8"]);
}

#[test]
fn sync_reports_a_failing_save() {
    let repo = Repo::initialised();
    repo.compose("web", "a: <<gen:db>>\n");
    // save() writes .sec/.web.toml.tmp and renames it; make that impossible.
    fs::create_dir(repo.path().join(".sec/.web.toml.tmp")).unwrap();
    repo.lst(&["sync"]).fails_with(&[".sec/web.toml: "]);
    assert!(!repo.exists(".sec/web.toml"));
}

#[test]
fn sync_reports_bad_stacks_and_store_conflicts() {
    let repo = Repo::initialised();
    repo.compose("Shared", "a: 1\n");
    repo.lst(&["sync"])
        .fails_with(&["stack name \"Shared\" is reserved"]);
    fs::remove_dir_all(repo.path().join("stacks/Shared")).unwrap();

    repo.compose("web", "a: <<gen:db>>\nb: <<gen:db:uuid>>\n");
    repo.lst(&["sync"])
        .fails_with(&["`web/db` is used with two different formats"]);
}

// ---------------------------------------------------------------------------
// render
// ---------------------------------------------------------------------------

const TWO_SERVICES: &str = "\
services:
  db:
    image: postgres:17
    environment:
      POSTGRES_PASSWORD: <<gen:db>>
  app:
    image: example/app
    environment:
      DATABASE_URL: postgres://app:<<gen:db>>@db/app
      API_KEY: <<gen:api:hex64>>
      TOKEN: <<gen:token:base64-32>>
      INSTANCE: <<gen:inst:uuid>>
      SHORT: <<gen:short:alnum22>>
";

#[test]
fn render_two_services_sharing_a_generated_secret() {
    let repo = Repo::initialised();
    repo.compose("web", TWO_SERVICES);
    repo.lst(&["sync"]).ok();

    let before = repo.snapshot();
    let run = repo.lst(&["render", "web"]);
    let out = run.ok();
    assert_eq!(run.stderr, "");
    assert_eq!(repo.snapshot(), before, "render must not write anything");

    let db = repo.expected_gen("web", "db", fmt("alnum32"));
    let api = repo.expected_gen("web", "api", fmt("hex64"));
    let token = repo.expected_gen("web", "token", fmt("base64-32"));
    let inst = repo.expected_gen("web", "inst", fmt("uuid"));
    let short = repo.expected_gen("web", "short", fmt("alnum22"));
    let expected = TWO_SERVICES
        .replace("<<gen:db>>", &db)
        .replace("<<gen:api:hex64>>", &api)
        .replace("<<gen:token:base64-32>>", &token)
        .replace("<<gen:inst:uuid>>", &inst)
        .replace("<<gen:short:alnum22>>", &short);
    // stdout holds exactly the rendered text.
    assert_eq!(out, expected);
    assert_eq!(out.matches(db.as_str()).count(), 2);
    assert_eq!(
        (db.len(), api.len(), token.len(), inst.len(), short.len()),
        (32, 64, 32, 36, 22)
    );
    assert!(api.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(inst.as_bytes()[14], b'4');

    // Deterministic across runs.
    assert_eq!(repo.lst(&["render", "web"]).ok(), expected);
}

#[test]
fn render_text_without_markers_is_byte_identical() {
    let repo = Repo::initialised();
    let text = "x-a: &a\n  k: v\nservices:\r\n  s:\n    <<: *a\n    command: cat <<EOF\n\tü\n";
    repo.compose("plain", text);
    assert_eq!(repo.lst(&["render", "plain"]).ok(), text);
}

#[test]
fn render_resolves_stored_manual_secrets() {
    let repo = Repo::initialised();
    repo.compose(
        "web",
        "token: \"<<secret:cf>>\"\nmqtt: '<<secret:shared/mqtt>>'\n",
    );
    repo.lst(&["sync"]).ok();
    let seed = repo.seed();
    let mut store = repo.store();
    store
        .set_secret(&seed, "web", "cf", "tok:en #1 \"q\"")
        .unwrap();
    store.set_secret(&seed, "web", "shared/mqtt", "m").unwrap();
    store.save(&repo.path().join(".sec")).unwrap();

    let run = repo.lst(&["render", "web"]);
    assert_eq!(run.ok(), "token: \"tok:en #1 \"q\"\"\nmqtt: 'm'\n");
    // The value never reaches stderr.
    assert_eq!(run.stderr, "");
}

#[test]
fn render_reports_every_unresolvable_secret() {
    let repo = Repo::initialised();
    repo.compose("web", "a: <<gen:db>>\nb: <<secret:cf>>\n");
    repo.lst(&["sync"]).ok();
    repo.compose(
        "web",
        "a: <<gen:db>>\nb: <<secret:cf>>\nc: <<gen:new>>\nd: <<gen:db:hex32>>\ne: <<gen:new>>\n",
    );
    let before = repo.snapshot();
    let run = repo.lst(&["render", "web"]);
    run.fails_with(&[]);
    assert_eq!(
        run.stderr,
        "lst: stacks/web/compose.yaml: could not resolve 3 secrets:\n  \
         `web/cf` is not set; write <<set:cf:VALUE>> to set it\n  \
         `web/db` is stored as alnum32 but used as hex32; run `lst sync`\n  \
         `web/new` has no entry in .sec/; run `lst sync`\n"
    );
    assert_eq!(repo.snapshot(), before);

    repo.compose("web", "c: <<gen:new>>\n");
    repo.lst(&["render", "web"]).fails_with(&[
        "could not resolve 1 secret:\n  `web/new` has no entry in .sec/; run `lst sync`",
    ]);
}

#[test]
fn render_fails_with_the_wrong_seed() {
    let repo = Repo::initialised();
    repo.compose("web", "a: <<gen:db>>\n");
    repo.lst(&["sync"]).ok();
    repo.write(".env", format!("LST_SEED={OTHER_SEED}\n"));
    let before = repo.snapshot();
    for cmd in [&["render", "web"][..], &["sync"]] {
        let run = repo.lst(cmd);
        run.fails_with(&["wrong seed: its fingerprint does not match .sec/meta.toml"]);
        assert_no_seed(&run, OTHER_SEED);
    }
    assert_eq!(repo.snapshot(), before);
}

#[test]
fn render_and_sync_need_a_seed() {
    let repo = Repo::initialised();
    repo.compose("web", "a: <<gen:db>>\n");
    repo.lst(&["sync"]).ok();

    repo.remove(".env");
    for cmd in [&["render", "web"][..], &["sync"]] {
        repo.lst(cmd)
            .fails_with(&["no .env file", "lst init", "LST_SEED="]);
        assert!(!repo.exists(".env"));
    }

    repo.write(".env", "A=1\n");
    for cmd in [&["render", "web"][..], &["sync"]] {
        repo.lst(cmd)
            .fails_with(&[".env has no LST_SEED line", "lst init"]);
    }

    repo.write(".env", "LST_SEED=nothex\n");
    repo.lst(&["render", "web"])
        .fails_with(&[".env line 1: the LST_SEED value is not 64 lowercase hex characters"]);

    repo.write(".env", b"\xff");
    repo.lst(&["render", "web"])
        .fails_with(&[".env is not valid UTF-8"]);

    repo.remove(".env");
    fs::create_dir(repo.path().join(".env")).unwrap();
    for cmd in [&["render", "web"][..], &["sync"]] {
        repo.lst(cmd).fails_with(&[".env: "]);
    }
}

#[test]
fn render_and_sync_need_an_ignored_untracked_env() {
    let repo = Repo::initialised();
    repo.compose("web", "a: <<gen:db>>\n");
    repo.lst(&["sync"]).ok();

    repo.remove(".gitignore");
    let before = repo.snapshot();
    for cmd in [&["render", "web"][..], &["sync"]] {
        repo.lst(cmd)
            .fails_with(&[".env is not gitignored", "lst refuses to read or write it"]);
    }
    assert_eq!(repo.snapshot(), before);

    repo.write(".gitignore", "/.env\n");
    repo.git(&["add", "-f", ".env"]);
    for cmd in [&["render", "web"][..], &["sync"]] {
        repo.lst(cmd).fails_with(&[".env is tracked by git"]);
    }
}

#[test]
fn render_and_sync_need_an_initialised_store() {
    let repo = Repo::new();
    repo.write(".gitignore", "/.env\n");
    repo.write(".env", format!("LST_SEED={OTHER_SEED}\n"));
    repo.compose("web", "a: 1\n");
    for cmd in [&["render", "web"][..], &["sync"]] {
        repo.lst(cmd)
            .fails_with(&["not initialised (no meta.toml); run `lst init`"]);
    }
    assert!(!repo.exists(".sec"));
}

#[test]
fn render_unknown_or_invalid_stack() {
    let repo = Repo::initialised();
    repo.lst(&["render", "web"])
        .fails_with(&["unknown stack \"web\" (known stacks: none)"]);
    repo.compose("a", "x: 1\n");
    repo.compose("b", "x: 1\n");
    repo.lst(&["render", "web"])
        .fails_with(&["unknown stack \"web\" (known stacks: a, b)"]);
    repo.lst(&["render", "../a"])
        .fails_with(&["invalid stack name \"../a\""]);
}

#[test]
fn render_reports_a_failing_stdout() {
    let repo = Repo::initialised();
    repo.compose("web", "a: 1\n");
    let out = lst_cmd(repo.path(), &["render", "web"])
        .stdout(File::create("/dev/full").unwrap())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.starts_with("lst: could not write to stdout: "),
        "{stderr}"
    );
}

// ---------------------------------------------------------------------------
// exit codes and usage
// ---------------------------------------------------------------------------

#[test]
fn usage_errors_exit_with_2() {
    let repo = Repo::new();
    for args in [
        &[][..],
        &["bogus"],
        &["render"],
        &["render", "a", "b"],
        &["init", "x"],
    ] {
        let run = repo.lst(args);
        assert_eq!(run.code, Some(2), "{args:?}: {run:#?}");
        assert_eq!(run.stdout, "", "{args:?}");
        assert!(run.stderr.contains("Usage: lst"), "{args:?}: {run:#?}");
    }
    assert_eq!(repo.snapshot().len(), 0, "usage errors write nothing");
}

#[test]
fn help_and_version_exit_with_0() {
    let repo = Repo::new();
    let help = repo.lst(&["--help"]);
    let out = help.ok();
    for cmd in ["init", "sync", "render"] {
        assert!(out.contains(cmd), "{out}");
    }
    let help = repo.lst(&["render", "--help"]);
    assert!(help.ok().contains("Read-only"), "{help:#?}");
    let version = repo.lst(&["--version"]);
    assert_eq!(version.ok(), format!("lst {}\n", env!("CARGO_PKG_VERSION")));
}

#[test]
fn exit_codes_0_and_1() {
    let repo = Repo::new();
    assert_eq!(repo.lst(&["init"]).code, Some(0));
    assert_eq!(repo.lst(&["render", "nope"]).code, Some(1));
}
