//! The seed from the `LST_SEED` environment variable (CI): every command
//! that needs the seed takes it from there, alongside or instead of `.env`.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

use lst::format::Format;

use crate::support::{Repo, Run};

/// Plaintext values these tests set; never in any output.
const PLAINTEXTS: &[&str] = &["3nv-s33d-v4l", "cl0n3-v4l"];

/// Another valid seed, different from every repository's own.
const OTHER_SEED: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/// Asserts that the seed (either half) is in neither output stream and no
/// plaintext is in stderr (`render`'s stdout carries values by design;
/// every other command's stdout is checked to be empty).
#[track_caller]
fn assert_clean(run: &Run, seed_hex: &str) {
    let out = format!("{}{}", run.stdout, run.stderr);
    for half in [&seed_hex[..32], &seed_hex[32..]] {
        assert!(!out.contains(half), "seed leaked: {run:#?}");
    }
    for p in PLAINTEXTS {
        assert!(!run.stderr.contains(p), "{p} leaked: {run:#?}");
    }
}

/// An initialised repository with one stack committed through the hook:
/// `web/db` (generated) and `web/cf` (manual, stored by the hook).
fn committed() -> Repo {
    let repo = Repo::initialised();
    repo.compose("web", "a: <<gen:db>>\nb: <<set:cf:3nv-s33d-v4l>>\n");
    repo.git(&["add", "-A"]);
    let run = repo.commit(&["-m", "web"]);
    assert_eq!(run.code, Some(0), "{run:#?}");
    assert_eq!(
        repo.read("stacks/web/compose.yaml"),
        "a: <<gen:db>>\nb: <<secret:cf>>\n"
    );
    repo
}

#[test]
fn a_fresh_clone_works_with_only_the_env_var() {
    let origin = committed();
    let seed = origin.seed_hex();
    let db = origin.expected_gen("web", "db", Format::default());
    let rendered = format!("a: {db}\nb: 3nv-s33d-v4l\n");
    let clone = origin.clone_repo();
    assert!(!clone.exists(".env"));
    let check = |run: Run| {
        assert_clean(&run, &seed);
        run
    };

    // Without the variable there is no seed.
    check(clone.lst(&["render", "web"]))
        .fails_with(&["no .env file", "set the LST_SEED environment variable"]);

    // render, sync.
    assert_eq!(
        check(clone.lst_env(&["render", "web"], &seed)).ok(),
        rendered
    );
    let run = check(clone.lst_env(&["sync"], &seed));
    assert_eq!((run.ok(), run.stderr.as_str()), ("", ""));

    // rename (keeps the value).
    clone.compose("web", "a: <<gen:database>>\nb: <<secret:cf>>\n");
    check(clone.lst_env(&["rename", "web/db", "database"], &seed)).ok();
    assert_eq!(
        check(clone.lst_env(&["render", "web"], &seed)).ok(),
        rendered
    );

    // The pre-commit hook, from git and by hand.
    check(clone.lst(&["hook", "install"])).ok();
    clone.compose(
        "web",
        "a: <<gen:database>>\nb: <<secret:cf>>\nc: <<set:k:cl0n3-v4l>>\nd: <<gen:new>>\n",
    );
    clone.git(&["add", "-A"]);
    let run = check(clone.commit_env(&["-m", "clone"], &seed));
    assert_eq!(run.code, Some(0), "{run:#?}");
    assert!(run.stderr.contains("lst: new: web/new\n"), "{run:#?}");
    assert!(run.stderr.contains("lst: stored web/k\n"), "{run:#?}");
    assert!(clone.show("HEAD:.sec/web.toml").contains("[secret.k]"));
    let run = check(clone.lst_env(&["hook", "run"], &seed));
    assert_eq!((run.ok(), run.stderr.as_str()), ("", ""));
    let out = check(clone.lst_env(&["render", "web"], &seed))
        .ok()
        .to_owned();
    assert!(
        out.starts_with(&rendered) && out.contains("c: cl0n3-v4l\n"),
        "{out}"
    );

    // Without the variable the hook blocks (no seed), like every command.
    clone.compose("web", "a: <<gen:other>>\n");
    clone.git(&["add", "-A"]);
    let run = check(clone.commit(&["-m", "x"]));
    run.fails_with(&["no .env file"]);

    // lst never wrote the seed anywhere.
    assert!(!clone.exists(".env"));
    for (path, bytes) in clone.snapshot() {
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains(&seed[..32]), "{}", path.display());
    }
}

#[test]
fn env_var_and_env_file_must_agree() {
    let repo = committed();
    let seed = repo.seed_hex();
    // The same seed in both: fine.
    let run = repo.lst_env(&["render", "web"], &seed);
    assert!(run.ok().contains("3nv-s33d-v4l"));
    assert_clean(&run, &seed);

    // A different one: every command that needs the seed refuses.
    let before = repo.snapshot();
    for args in [
        &["sync"][..],
        &["render", "web"],
        &["rename", "web/db", "x"],
        &["hook", "run"],
    ] {
        let run = repo.lst_env(args, OTHER_SEED);
        run.fails_with(&["LST_SEED and .env disagree"]);
        assert_clean(&run, &seed);
        assert_clean(&run, OTHER_SEED);
    }
    assert_eq!(repo.snapshot(), before);

    // .env without a seed line: the variable alone counts.
    repo.write(".env", "OTHER=1\n");
    let run = repo.lst_env(&["render", "web"], &seed);
    assert!(run.ok().contains("3nv-s33d-v4l"));
    // .env with a broken seed line is still an error.
    repo.write(".env", "LST_SEED=nope\n");
    repo.lst_env(&["render", "web"], &seed)
        .fails_with(&[".env line 1: the LST_SEED value is not 64 lowercase hex"]);
}

#[test]
fn a_wrong_env_seed_fails_loudly() {
    let repo = committed();
    let clone = repo.clone_repo();
    let run = clone.lst_env(&["render", "web"], OTHER_SEED);
    run.fails_with(&["wrong seed: its fingerprint does not match .sec/meta.toml"]);
    assert_clean(&run, OTHER_SEED);
}

#[test]
fn malformed_env_values_are_refused_without_the_value() {
    let repo = committed();
    let seed = repo.seed_hex();
    let clone = repo.clone_repo();
    let before = clone.snapshot();
    let cases: Vec<(Vec<u8>, &str)> = vec![
        (
            Vec::new(),
            "the LST_SEED environment variable is set but empty",
        ),
        (format!("{seed}\n").into_bytes(), "is not 64 lowercase hex"),
        (format!(" {seed}").into_bytes(), "is not 64 lowercase hex"),
        (
            format!("\"{seed}\"").into_bytes(),
            "is not 64 lowercase hex",
        ),
        (seed.to_uppercase().into_bytes(), "is not 64 lowercase hex"),
        (seed.as_bytes()[..62].to_vec(), "is not 64 lowercase hex"),
        (b"\xff".repeat(64), "is not 64 lowercase hex"),
    ];
    for (value, needle) in &cases {
        for args in [&["render", "web"][..], &["sync"], &["hook", "run"]] {
            let run = clone.lst_env(args, OsStr::from_bytes(value));
            run.fails_with(&[needle]);
            assert_clean(&run, &seed);
            assert!(!run.stderr.contains(&seed.to_uppercase()[..32]), "{run:#?}");
        }
    }
    assert_eq!(clone.snapshot(), before);
}

#[test]
fn init_refuses_while_the_env_var_is_set() {
    // A new repository: nothing is created.
    let repo = Repo::new();
    let run = repo.lst_env(&["init"], OTHER_SEED);
    run.fails_with(&[
        "the LST_SEED environment variable is set: unset LST_SEED; init manages .env",
    ]);
    assert_clean(&run, OTHER_SEED);
    assert_eq!(repo.snapshot().len(), 0);

    // An initialised one, even with the matching seed (or an empty value).
    let repo = Repo::initialised();
    let seed = repo.seed_hex();
    let before = repo.snapshot();
    for value in [seed.as_str(), ""] {
        let run = repo.lst_env(&["init"], value);
        run.fails_with(&["unset LST_SEED"]);
        assert_clean(&run, &seed);
    }
    assert_eq!(repo.snapshot(), before);
}

#[test]
fn the_ignore_guard_still_runs_with_the_env_var() {
    let repo = committed();
    let seed = repo.seed_hex();
    let clone = repo.clone_repo();
    clone.remove(".gitignore");
    clone
        .lst_env(&["render", "web"], &seed)
        .fails_with(&[".env is not gitignored"]);
}
