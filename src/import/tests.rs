use super::*;

use proptest::prelude::*;

fn files(list: &[(&str, &str)]) -> BTreeMap<String, FileState> {
    list.iter()
        .map(|(k, v)| {
            (
                k.to_string(),
                FileState::Text(SecretString::new(v.to_string())),
            )
        })
        .collect()
}

fn run(compose: &str, list: &[(&str, &str)], exclude: &[&str]) -> Plan {
    try_run(compose, list, exclude).unwrap()
}

fn try_run(compose: &str, list: &[(&str, &str)], exclude: &[&str]) -> Result<Plan, ImportError> {
    let files = files(list);
    let exclude = exclude.iter().map(|s| s.to_string()).collect();
    plan(&Input {
        stack: "web",
        compose,
        files: &files,
        exclude: &exclude,
    })
}

fn sealed(p: &Plan) -> Vec<(&str, &str)> {
    p.secrets
        .iter()
        .map(|s| (s.name.as_str(), s.value.expose()))
        .collect()
}

fn env_edit<'p>(p: &'p Plan, file: &str) -> Option<&'p EnvFileEdit> {
    p.env_files.iter().find(|e| e.file == file)
}

#[test]
fn yaml_crate_assumptions() {
    // Duplicate keys are an error (a blind `environment:` next to an
    // existing one must fail the comparison).
    assert!(serde_yaml_ng::from_str::<Value>("a: 1\na: 2\n").is_err());
    // Map equality ignores order.
    let a: Value = serde_yaml_ng::from_str("{x: 1, y: 2}").unwrap();
    let b: Value = serde_yaml_ng::from_str("{y: 2, x: 1}").unwrap();
    assert_eq!(a, b);
}

#[test]
fn interpolation_rules() {
    let env: Env = [
        ("A".to_string(), Some(SecretString::new("va".into()))),
        ("E".to_string(), Some(SecretString::new(String::new()))),
        ("S".to_string(), None),
    ]
    .into_iter()
    .collect();
    let i = |s: &str| interpolate(s, &env);
    assert_eq!(i("x$A-${A}"), Ok("xva-va".into()));
    assert_eq!(i("$$A"), Ok("$A".into()));
    assert_eq!(i("${E:-d}|${E-d}|${A:-d}"), Ok("d||va".into()));
    assert_eq!(i("${A:+alt}|${E:+alt}|${E+alt}"), Ok("alt||alt".into()));
    assert_eq!(i("${E:?err}"), Err(()));
    assert_eq!(i("${E?err}"), Ok(String::new()));
    assert_eq!(i("${E:-${A}}"), Ok("va".into()));
    // Unknown values stay opaque, keyed by their text.
    assert_eq!(i("$U ${S}"), Ok("\0$U\0 \0${S}\0".into()));
    for bad in ["$", "a$ b", "${", "${1}", "${A!}", "${A"] {
        assert_eq!(i(bad), Err(()), "{bad:?}");
    }
}

#[test]
fn refs_in_text() {
    let r = refs("a: $A ${B:-x} $$C ${D:+y} ${E:-${F}} $");
    let got: Vec<(&str, bool, Vec<String>)> = r
        .iter()
        .map(|r| (r.var.as_str(), r.value, r.nested.clone()))
        .collect();
    assert_eq!(
        got,
        [
            ("A", true, vec![]),
            ("B", true, vec![]),
            ("D", false, vec![]),
            ("E", true, vec!["F".to_string()]),
        ]
    );
}

#[test]
fn paths() {
    assert_eq!(normalize_path("./a/./b.env").as_deref(), Some("a/b.env"));
    assert_eq!(normalize_path(".env").as_deref(), Some(".env"));
    for bad in ["/etc/x", "../x", "a/../b", "${X}.env", "", "."] {
        assert_eq!(normalize_path(bad), None, "{bad:?}");
    }
}

const SIMPLE: &str = "\
services:
  db:
    image: postgres
    environment:
      POSTGRES_PASSWORD: ${DB_PASSWORD}
  app:
    image: app
    environment:
      DATABASE_URL: \"postgres://app:${DB_PASSWORD}@db/app\"
      TZ: $TZ
";

#[test]
fn replaces_interpolation_from_dot_env() {
    let p = run(
        SIMPLE,
        &[(
            ".env",
            "DB_PASSWORD=s3cret\nTZ=Europe/Copenhagen\nUNUSED=1\n",
        )],
        &[],
    );
    assert_eq!(
        p.compose,
        SIMPLE
            .replace("${DB_PASSWORD}", "<<secret:db_password>>")
            .replace("$TZ", "<<secret:tz>>")
    );
    assert_eq!(
        sealed(&p),
        [("db_password", "s3cret"), ("tz", "Europe/Copenhagen")]
    );
    assert!(p.sites.iter().all(|s| s.replaced));
    assert_eq!(p.sites[0].line, 5);
    let e = env_edit(&p, ".env").unwrap();
    assert_eq!(e.removed, ["DB_PASSWORD", "TZ"]);
    assert_eq!(e.contents.as_ref().unwrap().expose(), "UNUSED=1\n");
}

#[test]
fn exclude_keeps_reference_and_line() {
    let p = run(SIMPLE, &[(".env", "DB_PASSWORD=s3cret\nTZ=UTC\n")], &["TZ"]);
    assert!(p.compose.contains("TZ: $TZ"));
    assert_eq!(sealed(&p), [("db_password", "s3cret")]);
    assert_eq!(p.not_imported[0].var, "TZ");
    assert_eq!(p.not_imported[0].why, "excluded");
    let e = env_edit(&p, ".env").unwrap();
    assert_eq!(e.contents.as_ref().unwrap().expose(), "TZ=UTC\n");
}

#[test]
fn all_lines_gone_deletes_the_file() {
    let p = run(
        SIMPLE,
        &[(".env", "# old\nDB_PASSWORD=s3cret\n\nTZ=UTC\n")],
        &[],
    );
    assert!(env_edit(&p, ".env").unwrap().contents.is_none());
}

#[test]
fn value_breaking_raw_yaml_is_not_replaced() {
    // Unquoted scalar: a value with ": " or " #" would change the YAML.
    let compose = "services:\n  a:\n    environment:\n      X: ${PW}\n      Y: \"${OK}\"\n";
    let p = run(compose, &[(".env", "PW='a: b #c'\nOK=fine\n")], &[]);
    assert!(p.compose.contains("X: ${PW}"));
    assert!(p.compose.contains("Y: \"<<secret:ok>>\""));
    assert_eq!(
        p.sites
            .iter()
            .map(|s| (s.var.as_str(), s.replaced))
            .collect::<Vec<_>>(),
        [("PW", false), ("OK", true)]
    );
    // PW is still read from .env: neither sealed nor removed.
    assert_eq!(sealed(&p), [("ok", "fine")]);
    assert_eq!(env_edit(&p, ".env").unwrap().removed, ["OK"]);
}

#[test]
fn dollar_and_quotes_in_values() {
    // `$` is escaped by render (`$$`) and unescaped by compose: same value.
    // A `"` breaks a double-quoted scalar on the raw path.
    let compose = "services:\n  a:\n    environment:\n      X: ${PW}\n      Y: \"${Q}\"\n";
    let p = run(compose, &[(".env", "PW='pa$word'\nQ='a\"b'\n")], &[]);
    assert!(p.compose.contains("X: <<secret:pw>>"));
    assert!(p.compose.contains("Y: \"${Q}\""));
}

#[test]
fn modifiers() {
    let compose = "services:\n  a:\n    environment:\n      \
                   A: ${PW:-x}\n      B: ${PW:+set}\n      C: ${EMPTY:-d}\n";
    let p = run(compose, &[(".env", "PW=v\nEMPTY=\n")], &[]);
    assert!(p.compose.contains("A: <<secret:pw>>"));
    assert!(p.compose.contains("B: ${PW:+set}"));
    // EMPTY is empty, so `:-` gives the default: replacing it would change it.
    assert!(p.compose.contains("C: ${EMPTY:-d}"));
    // PW is still used by ${PW:+set}: its line stays.
    assert!(env_edit(&p, ".env").is_none());
}

#[test]
fn skipped_values() {
    let compose = "services:\n  a:\n    environment:\n      A: ${X}\n";
    let p = run(compose, &[(".env", "X=\"has $Y\"\n")], &[]);
    assert_eq!(p.compose, compose);
    assert!(p.secrets.is_empty());
    assert!(p.not_imported[0].why.contains('$'));
}

const ENV_FILE: &str = "\
services:
  app:
    image: app
    env_file:
      - app.env
    ports: [\"80:80\"]
  other:
    image: other
    env_file: ./other.env
";

#[test]
fn replaces_env_file_blocks() {
    let p = run(
        ENV_FILE,
        &[
            ("app.env", "API_KEY=k1\nSMTP='m a#il'\n"),
            ("other.env", ""),
        ],
        &[],
    );
    assert_eq!(
        p.compose,
        "\
services:
  app:
    image: app
    environment:
      API_KEY: '<<secret:api_key>>'
      SMTP: '<<secret:smtp>>'
    ports: [\"80:80\"]
  other:
    image: other
"
    );
    assert_eq!(p.blocks[0].outcome, BlockOutcome::Replaced);
    assert_eq!(p.blocks[0].service.as_deref(), Some("app"));
    assert_eq!(sealed(&p), [("api_key", "k1"), ("smtp", "m a#il")]);
    assert!(env_edit(&p, "app.env").unwrap().contents.is_none());
}

#[test]
fn quote_in_value_uses_a_block_scalar() {
    let compose = "services:\n  app:\n    env_file: app.env\n";
    let p = run(compose, &[("app.env", "PW=\"it's\"\n")], &[]);
    assert_eq!(
        p.compose,
        "services:\n  app:\n    environment:\n      PW: |-\n        <<secret:pw>>\n"
    );
}

#[test]
fn merges_into_existing_environment() {
    let map = "services:\n  app:\n    env_file: [a.env]\n    environment:\n      \
               TZ: UTC\n      KEY: from-compose\n    image: x\n";
    let p = run(map, &[("a.env", "KEY=from-file\nPW=p\n")], &[]);
    assert_eq!(p.blocks[0].outcome, BlockOutcome::Merged);
    assert_eq!(
        p.compose,
        "services:\n  app:\n    environment:\n      TZ: UTC\n      KEY: from-compose\n      \
         PW: '<<secret:pw>>'\n    image: x\n"
    );
    assert_eq!(sealed(&p), [("pw", "p")]);
    assert!(p.not_imported.iter().any(|n| n.var == "KEY"));
    // KEY's line stays (never imported); the file isn't referenced any more.
    let e = env_edit(&p, "a.env").unwrap();
    assert_eq!(e.contents.as_ref().unwrap().expose(), "KEY=from-file\n");

    let list = "services:\n  app:\n    environment:\n      - TZ=UTC\n    env_file: a.env\n";
    let p = run(list, &[("a.env", "PW=p\n")], &[]);
    assert_eq!(p.blocks[0].outcome, BlockOutcome::Merged);
    assert_eq!(
        p.compose,
        "services:\n  app:\n    environment:\n      - TZ=UTC\n      - 'PW=<<secret:pw>>'\n"
    );
}

#[test]
fn failed_block_is_manual_with_snippet() {
    // Flow-style environment: lst can't add to it.
    let compose = "services:\n  app:\n    environment: {TZ: UTC}\n    env_file: a.env\n";
    let p = run(compose, &[("a.env", "PW=p\n")], &[]);
    assert_eq!(p.compose, compose);
    let BlockOutcome::Manual { snippet, .. } = &p.blocks[0].outcome else {
        panic!("{:?}", p.blocks[0]);
    };
    assert_eq!(snippet, "environment:\n  PW: '<<secret:pw>>'\n");
    // Sealed for the snippet, but a.env is still referenced: kept whole.
    assert_eq!(sealed(&p), [("pw", "p")]);
    assert!(p.env_files.is_empty());
    assert!(!snippet.contains("p\n") || snippet.contains("pw"));
}

#[test]
fn excluded_var_in_env_file_makes_the_block_manual() {
    let compose = "services:\n  app:\n    env_file: a.env\n";
    let p = run(compose, &[("a.env", "PW=p\nTZ=UTC\n")], &["TZ"]);
    assert_eq!(p.compose, compose);
    let BlockOutcome::Manual { snippet, why } = &p.blocks[0].outcome else {
        panic!();
    };
    assert!(why.contains("TZ"));
    assert!(snippet.contains("# TZ: not imported"));
}

#[test]
fn unreadable_env_file_is_left_alone() {
    let compose = "services:\n  app:\n    env_file: [a.env, /etc/b.env]\n";
    let p = run(compose, &[("a.env", "PW=p\n")], &[]);
    assert_eq!(p.compose, compose);
    assert!(matches!(
        p.blocks[0].outcome,
        BlockOutcome::LeftAlone { .. }
    ));
    assert!(p.secrets.is_empty());

    let mut fs = files(&[]);
    fs.insert("a.env".into(), FileState::Missing);
    let empty = BTreeSet::new();
    let p = plan(&Input {
        stack: "web",
        compose: "services:\n  app:\n    env_file: a.env\n",
        files: &fs,
        exclude: &empty,
    })
    .unwrap();
    assert!(matches!(
        p.blocks[0].outcome,
        BlockOutcome::LeftAlone { .. }
    ));
}

#[test]
fn env_file_that_is_also_dot_env() {
    let compose = "services:\n  app:\n    env_file: .env\n    environment:\n      \
                   - URL=http://u:${PW}@h\n";
    let p = run(compose, &[(".env", "PW=p\n")], &[]);
    assert_eq!(
        p.compose,
        "services:\n  app:\n    environment:\n      - URL=http://u:<<secret:pw>>@h\n      \
         - 'PW=<<secret:pw>>'\n"
    );
    assert!(env_edit(&p, ".env").unwrap().contents.is_none());
}

#[test]
fn x_deploy_commands_are_not_rewritten() {
    let compose = "services:\n  a:\n    environment:\n      X: ${PW}\n\
                   x-deploy:\n  post:\n    - exec: a\n      run: echo ${PW}\n";
    let p = run(compose, &[(".env", "PW='has # and: x'\n")], &[]);
    // The YAML path quotes for itself, so X works; the command isn't
    // interpolated by compose, so it stays.
    assert!(p.compose.contains("X: <<secret:pw>>"));
    assert!(p.compose.contains("run: echo ${PW}"));
    assert!(env_edit(&p, ".env").is_none());
}

#[test]
fn existing_markers_are_kept() {
    let compose = "services:\n  a:\n    environment:\n      G: <<gen:db>>\n      X: ${PW}\n";
    let p = run(compose, &[(".env", "PW=p\n")], &[]);
    assert!(p.compose.contains("G: <<gen:db>>\n      X: <<secret:pw>>"));
}

#[test]
fn errors() {
    let e = try_run(SIMPLE, &[(".env", "DB_PASSWORD=a\nTZ=b\n"), ("x", "")], &[]);
    assert!(e.is_ok());
    let compose = "services:\n  a:\n    env_file: a.env\n    environment:\n      X: ${PW}\n";
    let e = try_run(
        compose,
        &[(".env", "PW=v4lue1\n"), ("a.env", "PW=v4lue2\n")],
        &[],
    )
    .unwrap_err();
    assert!(matches!(e, ImportError::Conflict { .. }), "{e}");
    assert!(!e.to_string().contains("v4lue"));

    let compose = "services:\n  a:\n    environment:\n      X: ${PW} ${pw}\n";
    let e = try_run(compose, &[(".env", "PW=a\npw=b\n")], &[]).unwrap_err();
    assert!(matches!(e, ImportError::Collision { .. }), "{e}");

    let e = try_run("a: [\n", &[], &[]).unwrap_err();
    assert!(matches!(e, ImportError::Compose { .. }), "{e}");
    let e = try_run("a: $ x\n", &[], &[]).unwrap_err();
    assert!(e.to_string().contains("interpolate"), "{e}");

    let e = try_run(SIMPLE, &[(".env", "hunter2\n")], &[]).unwrap_err();
    assert_eq!(
        e.to_string(),
        "stacks/web/.env: line 1: not a KEY=VALUE line (lst import can't tell what compose \
         makes of it)"
    );
}

#[test]
fn second_run_does_nothing() {
    let p = run(SIMPLE, &[(".env", "DB_PASSWORD=s3cret\nTZ=UTC\n")], &[]);
    let again = run(&p.compose, &[], &[]);
    assert_eq!(again.compose, p.compose);
    assert!(again.secrets.is_empty() && again.sites.is_empty());
}

#[test]
fn env_file_paths_lists_followable_paths() {
    let compose = "services:\n  a:\n    env_file: [./x.env, {path: y.env, required: false}, \
                   /abs, \"${V}.env\"]\n  b:\n    env_file: .env\n";
    let got: Vec<String> = env_file_paths(compose).into_iter().collect();
    assert_eq!(got, [".env", "x.env", "y.env"]);
}

proptest! {
    /// Whatever the value, an accepted rewrite renders to what compose got
    /// before; a rejected one is left as written.
    #[test]
    fn rewrite_keeps_the_meaning(v in "[ -~]{0,20}", quoted in any::<bool>()) {
        let compose = if quoted {
            "services:\n  a:\n    environment:\n      X: \"${PW}\"\n".to_string()
        } else {
            "services:\n  a:\n    environment:\n      X: ${PW}\n".to_string()
        };
        let dot = format!("PW='{}'\n", v.replace('\'', ""));
        let value = v.replace('\'', "");
        let p = run(&compose, &[(".env", &dot)], &[]);
        if p.sites[0].replaced {
            let rendered = render::render_compose(&p.compose, |_| {
                Ok::<_, ()>(SecretString::new(value.clone()))
            })
            .unwrap();
            let doc: Value = serde_yaml_ng::from_str(rendered.expose()).unwrap();
            let x = doc["services"]["a"]["environment"]["X"].as_str().unwrap().replace("$$", "$");
            prop_assert_eq!(x, value);
        } else {
            prop_assert_eq!(p.compose, compose);
        }
    }
}
