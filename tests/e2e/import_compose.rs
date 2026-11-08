//! `lst import` against compose itself: what `docker compose config`
//! reads from a stack before the import must equal what it reads from
//! `lst render <stack>` afterwards.
//!
//! `docker compose config` needs the docker CLI with compose, but no
//! daemon. Like every Docker test these are `#[ignore]`d; CI runs them with
//! `cargo test --test e2e -- --ignored compose_config`.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use proptest::prelude::*;
use serde_yaml_ng::Value;

use crate::support::{Repo, Run};

/// `docker compose -p web --project-directory stacks/web -f <file> config
/// --format json`, run in the repository root with a clean environment (a
/// variable in compose's own environment overrides `.env`). `stdin`: the
/// compose file on stdin (`-f -`) instead of `stacks/web/compose.yaml`.
fn compose_config(root: &Path, stdin: Option<&str>) -> Result<Value, String> {
    let file = if stdin.is_some() {
        "-"
    } else {
        "stacks/web/compose.yaml"
    };
    let mut cmd = Command::new("docker");
    cmd.current_dir(root)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", root)
        .args(["compose", "-p", "web", "--project-directory", "stacks/web"])
        .args(["-f", file, "config", "--format", "json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("docker CLI not found");
    let mut input = child.stdin.take().unwrap();
    input.write_all(stdin.unwrap_or("").as_bytes()).unwrap();
    drop(input);
    let out: Output = child.wait_with_output().unwrap();
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).into_owned());
    }
    let mut v: Value = serde_yaml_ng::from_slice(&out.stdout).unwrap();
    normalize(&mut v);
    Ok(v)
}

/// Drops what lst changes on purpose: top-level `x-*` keys (`x-deploy` is
/// stripped by lst) and `lst.render-hash` labels.
fn normalize(v: &mut Value) {
    let Value::Mapping(top) = v else { return };
    top.retain(|k, _| !k.as_str().is_some_and(|k| k.starts_with("x-")));
    let Some(Value::Mapping(services)) = top.get_mut("services") else {
        return;
    };
    for svc in services.values_mut() {
        let Value::Mapping(svc) = svc else { continue };
        let mut empty = false;
        if let Some(Value::Mapping(labels)) = svc.get_mut("labels") {
            labels.remove("lst.render-hash");
            empty = labels.is_empty();
        }
        if empty {
            svc.remove("labels");
        }
    }
}

/// One stack to import.
struct Fixture<'a> {
    compose: &'a str,
    /// Stack-relative files (`.env`, env files).
    files: &'a [(&'a str, &'a str)],
    exclude: &'a [&'a str],
    /// Values that must never appear on lst's stderr.
    secrets: &'a [&'a str],
}

/// What happened, for fixture-specific assertions.
struct Outcome {
    repo: Repo,
    import: Run,
    compose: String,
}

#[track_caller]
fn no_values(run: &Run, secrets: &[&str]) {
    for s in secrets.iter().filter(|s| s.len() >= 3) {
        assert!(!run.stderr.contains(s), "value {s:?} on stderr: {run:#?}");
    }
}

/// Builds the stack, takes compose's view, imports (after a dry run that
/// must change nothing), renders and takes compose's view again: the two
/// must be equal. A second import must change nothing.
#[track_caller]
fn check(f: &Fixture<'_>) -> Outcome {
    let repo = Repo::initialised();
    repo.write(
        ".gitignore",
        "/.env\nstacks/*/*.env\nstacks/*/.env\nstacks/*/env/\n",
    );
    repo.compose("web", f.compose);
    for (rel, text) in f.files {
        repo.write(&format!("stacks/web/{rel}"), text);
    }
    // Before: what `lst deploy` feeds compose today (the original stack,
    // rendered: existing markers resolved, x-deploy stripped).
    repo.lst(&["sync"]).ok();
    let original = repo.lst(&["render", "web"]).ok().to_owned();
    let before = compose_config(repo.path(), Some(&original))
        .unwrap_or_else(|e| panic!("the fixture itself is invalid for compose: {e}"));
    // Without markers that is the file itself.
    if !f.compose.contains("<<") {
        assert_eq!(compose_config(repo.path(), None).as_ref(), Ok(&before));
    }

    let mut args = vec!["import", "web"];
    for x in f.exclude {
        args.extend(["--exclude", x]);
    }
    let snapshot = repo.snapshot();
    let mut dry = args.clone();
    dry.push("--dry-run");
    let run = repo.lst(&dry);
    no_values(&run, f.secrets);
    run.ok();
    assert_eq!(repo.snapshot(), snapshot, "--dry-run wrote something");

    let import = repo.lst(&args);
    no_values(&import, f.secrets);
    import.ok();

    let render = repo.lst(&["render", "web"]);
    no_values(&render, f.secrets);
    let rendered = render.ok().to_owned();
    let after = compose_config(repo.path(), Some(&rendered))
        .unwrap_or_else(|e| panic!("compose refuses the rendered stack: {e}\n{import:#?}"));
    assert_eq!(
        before,
        after,
        "compose reads something else after the import\n--- compose.yaml now:\n{}\n{import:#?}",
        repo.read("stacks/web/compose.yaml")
    );

    // Running it again changes nothing, and .sec/ is not re-sealed.
    let snapshot = repo.snapshot();
    let again = repo.lst(&args);
    no_values(&again, f.secrets);
    again.ok();
    assert_eq!(repo.snapshot(), snapshot, "a second import changed files");

    // The hook accepts it and lst check passes.
    repo.git(&["add", "-A"]);
    repo.commit(&["-m", "import"]).ok();
    repo.lst(&["check"]).ok();

    let compose = repo.read("stacks/web/compose.yaml");
    Outcome {
        repo,
        import,
        compose,
    }
}

// ---------------------------------------------------------------------------
// Shapes
// ---------------------------------------------------------------------------

#[test]
#[ignore = "needs docker compose; run with `cargo test --test e2e -- --ignored compose_config`"]
fn compose_config_interpolation_forms() {
    let o = check(&Fixture {
        compose: "\
services:
  a:
    image: x
    environment:
      A: $PW
      B: ${PW}
      C: ${PW:-dflt}
      D: ${PW-dflt}
      E: ${PW:?missing}
      F: ${PW?missing}
      G: ${PW:+alt}
      H: ${PW+alt}
      I: ${UNSET_X:-${PW}}
      J: $$PW
      K: pre-${PW}-post
      L: ${EMPTY:-fallback}
    command: [\"run\", \"--pw=${PW}\"]
",
        files: &[(".env", "PW=s3cret-pw\nEMPTY=\n")],
        exclude: &[],
        secrets: &["s3cret-pw"],
    });
    for k in ["A", "B", "C", "D", "E", "F", "K"] {
        assert!(
            o.compose.contains(&format!("{k}: ")) && !o.compose.contains(&format!("{k}: $")),
            "{k} not replaced:\n{}",
            o.compose
        );
    }
    assert!(o.compose.contains("G: ${PW:+alt}"));
    assert!(o.compose.contains("J: $$PW"));
    assert!(o.compose.contains("\"--pw=<<secret:pw>>\""));
    // PW is still used (G, H, I): its line stays.
    assert!(o.repo.read("stacks/web/.env").contains("PW=s3cret-pw"));
}

#[test]
#[ignore = "needs docker compose; run with `cargo test --test e2e -- --ignored compose_config`"]
fn compose_config_env_file_forms() {
    let o = check(&Fixture {
        compose: "\
services:
  a:
    image: x
    env_file: a.env
  b:
    image: x
    env_file:
      - ./a.env
      - env/b.env
  c:
    image: x
    env_file:
      - path: a.env
      - path: missing.env
        required: false
  d:
    image: x
    environment:
      KEEP: compose
      B1: from-compose
    env_file: [env/b.env]
  e:
    image: x
    environment:
      - LIST=1
    env_file:
      - env/b.env
",
        files: &[
            ("a.env", "# a\nA1=alpha-one\nA2='alpha two'\n"),
            ("env/b.env", "export B1=beta-one\nB2=\"beta two\" # c\n"),
        ],
        exclude: &[],
        secrets: &["alpha-one", "alpha two", "beta-one", "beta two"],
    });
    assert!(!o.compose.contains("env_file: a.env"), "{}", o.compose);
    // a.env and env/b.env are no longer read: deleted (the comment line
    // alone doesn't keep a file).
    assert!(!o.repo.exists("stacks/web/a.env"));
    assert!(!o.repo.exists("stacks/web/env/b.env"));
}

#[test]
#[ignore = "needs docker compose; run with `cargo test --test e2e -- --ignored compose_config`"]
fn compose_config_shared_and_dot_env_as_env_file() {
    let o = check(&Fixture {
        compose: "\
services:
  db:
    image: x
    env_file: .env
  app:
    image: x
    environment:
      URL: \"postgres://u:${DB_PW}@db/x\"
",
        files: &[(".env", "DB_PW=pg-pass-1\nTZ=UTC\n")],
        exclude: &[],
        secrets: &["pg-pass-1"],
    });
    assert!(
        o.compose
            .contains("URL: \"postgres://u:<<secret:db_pw>>@db/x\"")
    );
    assert!(!o.repo.exists("stacks/web/.env"));
}

#[test]
#[ignore = "needs docker compose; run with `cargo test --test e2e -- --ignored compose_config`"]
fn compose_config_partial_failures_keep_meaning() {
    // Flow-style environment (manual), an excluded variable, and a value
    // that breaks a plain scalar: compose still reads the same everywhere.
    let o = check(&Fixture {
        compose: "\
services:
  a:
    image: x
    environment: {TZ: UTC}
    env_file: a.env
  b:
    image: x
    env_file: b.env
  c:
    image: x
    environment:
      HASHY: ${HASHY}
      OK: ${OK}
",
        files: &[
            ("a.env", "A=aaa-val\n"),
            ("b.env", "B=bbb-val\nPLAIN=1\n"),
            (".env", "HASHY='x #y: z'\nOK=ok-val\n"),
        ],
        exclude: &["PLAIN"],
        secrets: &["aaa-val", "bbb-val", "x #y: z", "ok-val"],
    });
    assert!(
        o.import
            .stderr
            .contains("automatic replacement failed for the env_file of service a")
    );
    assert!(
        o.import
            .stderr
            .contains("automatic replacement failed for the env_file of service b")
    );
    assert!(o.import.stderr.contains("left ${HASHY} as it is"));
    assert!(o.compose.contains("OK: <<secret:ok>>"));
    assert_eq!(o.repo.read("stacks/web/a.env"), "A=aaa-val\n");
    assert_eq!(o.repo.read("stacks/web/b.env"), "B=bbb-val\nPLAIN=1\n");
    assert_eq!(o.repo.read("stacks/web/.env"), "HASHY='x #y: z'\n");
}

#[test]
#[ignore = "needs docker compose; run with `cargo test --test e2e -- --ignored compose_config`"]
fn compose_config_anchors_and_merge_keys() {
    let o = check(&Fixture {
        compose: "\
x-common: &common
  image: x
  env_file: common.env
  environment:
    SHARED: ${PW}
services:
  a:
    <<: *common
  b:
    <<: *common
    environment:
      OWN: ${PW}
",
        files: &[(".env", "PW=anchor-pw\n"), ("common.env", "C=common-val\n")],
        exclude: &[],
        secrets: &["anchor-pw", "common-val"],
    });
    // compose still reads common.env through the anchor.
    assert_eq!(o.repo.read("stacks/web/common.env"), "C=common-val\n");
}

#[test]
#[ignore = "needs docker compose; run with `cargo test --test e2e -- --ignored compose_config`"]
fn compose_config_x_deploy_stack() {
    let o = check(&Fixture {
        compose: "\
services:
  a:
    image: x
    environment:
      PW: ${PW}
      GEN: <<gen:other>>
    env_file: a.env
x-deploy:
  post:
    - exec: a
      run: echo ${PW}
",
        files: &[(".env", "PW='x-dep # pw: 1'\n"), ("a.env", "K=\"it's\"\n")],
        exclude: &[],
        secrets: &["x-dep # pw: 1"],
    });
    assert!(o.compose.contains("PW: <<secret:pw>>"));
    assert!(o.compose.contains("run: echo ${PW}"));
}

#[test]
#[ignore = "needs docker compose; run with `cargo test --test e2e -- --ignored compose_config`"]
fn compose_config_crlf_and_no_trailing_newline() {
    let o = check(&Fixture {
        compose: "services:\r\n  a:\r\n    image: x\r\n    environment:\r\n      P: ${PW}\r\n    \
                  env_file: a.env\r\n",
        files: &[(".env", "PW=crlf-pw\r\n"), ("a.env", "K=crlf-k\r\n")],
        exclude: &[],
        secrets: &["crlf-pw", "crlf-k"],
    });
    assert!(!o.compose.contains("${PW}"));
    assert!(!o.compose.contains("env_file"));
    check(&Fixture {
        compose: "services:\n  a:\n    image: x\n    environment:\n      - A=1\n    env_file: a.env",
        files: &[("a.env", "K=eof-k")],
        exclude: &[],
        secrets: &["eof-k"],
    });
    check(&Fixture {
        compose: "services:\n  a:\n    image: x\n    env_file: a.env",
        files: &[("a.env", "K=eof-k2")],
        exclude: &[],
        secrets: &["eof-k2"],
    });
}

// ---------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------

/// Values that are hard to carry through raw YAML, dotenv and compose's
/// interpolation.
const VALUES: &[&str] = &[
    "plain",
    "0ld-pw",
    "with space",
    " lead-and-trail ",
    "pa$word",
    "pa$$word",
    "${NOT_A_VAR}",
    "hash # comment",
    "hash#tight",
    "colon: space",
    "url://u:p@h:5432/db?x=1&y=2",
    "it\"s",
    "back\\slash",
    "tab\tinside",
    "ünïcødé ✓",
    "{curly}",
    "[square]",
    "*star",
    "&amp",
    "!bang",
    "%percent",
    "@at",
    "`tick`",
    "yes",
    "null",
    "1e3",
    "0777",
    "-dash",
    "? q",
    "|pipe",
    ">gt",
    "",
    "it's",
    "both ' and \"",
    "trailing\\",
    "~",
    "Off",
    ".5",
    "-1",
    "0x1F",
    "1_000",
    "12:30",
    "2001-12-14",
    ".inf",
];

/// A dotenv line that compose and lst both read as `key=value`: single
/// quotes where they are literal (no `'`, no trailing backslash), double
/// quotes with `\\`, `\"` and `\$` escapes otherwise.
fn dotenv_line(key: &str, value: &str) -> String {
    if !value.contains('\'') && !value.ends_with('\\') {
        return format!("{key}='{value}'\n");
    }
    let mut v = String::new();
    for c in value.chars() {
        if matches!(c, '\\' | '"' | '$') {
            v.push('\\');
        }
        v.push(c);
    }
    format!("{key}=\"{v}\"\n")
}

/// One compose fixture per placement of `${PW}`.
fn placements() -> Vec<(&'static str, String)> {
    let svc = |env: &str| format!("services:\n  a:\n    image: x\n    environment:\n{env}");
    vec![
        ("plain", svc("      P: ${PW}\n")),
        ("single", svc("      P: '${PW}'\n")),
        ("double", svc("      P: \"${PW}\"\n")),
        ("url", svc("      P: http://u:${PW}@h/x\n")),
        ("list", svc("      - P=${PW}\n")),
        ("block", svc("      P: |-\n        ${PW}\n")),
        (
            "env_file",
            "services:\n  a:\n    image: x\n    env_file: a.env\n".to_owned(),
        ),
    ]
}

/// Imports `value` placed as `placement`; whether lst replaced the
/// reference (the `${PW}`, or the env_file block).
fn value_case(placement: &str, compose: &str, value: &str) -> bool {
    let line = dotenv_line("PW", value);
    let file = if placement == "env_file" {
        "a.env"
    } else {
        ".env"
    };
    let files = [(file, line.as_str())];
    let secrets = [value];
    let o = check(&Fixture {
        compose,
        files: &files,
        exclude: &[],
        secrets: &secrets,
    });
    !o.compose.contains("${PW}") && !o.compose.contains("env_file")
}

#[test]
#[ignore = "needs docker compose; run with `cargo test --test e2e -- --ignored compose_config`"]
fn compose_config_value_corpus() {
    let mut refused: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (placement, compose) in placements() {
        for value in VALUES {
            if !value_case(placement, &compose, value) {
                refused.entry(placement).or_default().push(value);
            }
        }
    }
    eprintln!("left for the user to quote, by placement: {refused:#?}");
    // The check must not pass by refusing: env_file entries are always
    // quoted, so every value goes through there; ordinary values go
    // through everywhere.
    assert!(!refused.contains_key("env_file"), "{refused:#?}");
    for value in [
        "plain",
        "pa$word",
        "ünïcødé ✓",
        "url://u:p@h:5432/db?x=1&y=2",
        "0ld-pw",
    ] {
        for (placement, list) in &refused {
            assert!(!list.contains(&value), "{value:?} refused in {placement}");
        }
    }
}

proptest! {
    // Each case spawns compose twice: 48 by default, PROPTEST_CASES for a
    // longer run.
    #![proptest_config(ProptestConfig {
        cases: std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(48),
        ..ProptestConfig::default()
    })]

    /// A random value in a random placement: compose reads the same before
    /// and after, whether lst replaced the reference or left it alone.
    #[test]
    #[ignore = "needs docker compose; run with `cargo test --test e2e -- --ignored compose_config`"]
    fn compose_config_random_values(value in "[ -~]{0,24}", which in 0usize..7) {
        let (placement, compose) = placements().swap_remove(which);
        let replaced = value_case(placement, &compose, &value);
        prop_assert!(replaced || placement != "env_file", "{value:?} refused in an env_file");
    }
}
