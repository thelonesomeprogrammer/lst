//! `x-deploy` stacks (M4): `lst render` through YAML, `--file`, and what
//! `lst check` reports. Executing `render:`/`pre`/`post` is `lst deploy`'s
//! job and tested with it.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use lst::crypto::{SecretString, render_hash_key};
use lst::format::Format;
use lst::xdeploy::{self, Phase, Run as Cmd, Step, When};
use serde_yaml_ng::Value;

use crate::support::{Repo, Run, lst_cmd};

/// A manual secret with everything YAML quoting cares about.
const NOTE: &str = "x-pl41n\"t3xt: #1\n'q' {a} [b] & *c";
/// Plaintexts these tests set; never on stderr.
const PLAINTEXTS: &[&str] = &["x-pl41n", "hunt3r-v4l"];
/// Where the render: file would go. lst render never creates it.
const TARGET_DIR: &str = "/srv/lst-e2e-x-deploy/mosquitto/config";

fn compose() -> String {
    format!(
        "\
services:
  mosquitto:
    image: eclipse-mosquitto:2
    volumes:
      - {TARGET_DIR}:/mosquitto/config:ro
      - data:/mosquitto/data
    environment:
      NOTE: <<secret:note>>
  app:
    image: example/app
    environment:
      MQTT_PASSWORD: <<gen:shared/mqtt>>
  mongo:
    image: mongo:7
    labels: [tier=db]
volumes:
  data: {{}}
x-deploy:
  render:
    - from: config/mosquitto.conf
      to: {TARGET_DIR}/mosquitto.conf
      mode: \"0640\"
  pre:
    - with: mosquitto
      run: mosquitto_passwd -b -c /mosquitto/config/passwd app <<gen:shared/mqtt>>
  post:
    - exec: mongo
      run: [mongosh, --eval, \"createUser('app', '<<gen:mongo-app:hex32>>')\"]
      when: on-change
"
    )
}

const CONF: &str = "listener 1883\npassword_file /mosquitto/config/passwd\n# <<secret:note>>\n";

/// Asserts that no plaintext and no part of the seed is on stderr.
#[track_caller]
fn assert_clean_stderr(run: &Run, seed_hex: &str) {
    for half in [&seed_hex[..32], &seed_hex[32..]] {
        assert!(!run.stderr.contains(half), "seed leaked: {run:#?}");
        assert!(!run.stdout.contains(half), "seed leaked: {run:#?}");
    }
    for p in PLAINTEXTS {
        assert!(!run.stderr.contains(p), "{p} leaked: {run:#?}");
    }
}

/// An initialised repository with the `mq` stack synced and `note` set.
fn repo() -> Repo {
    let repo = Repo::initialised();
    repo.compose("mq", &compose());
    repo.write("stacks/mq/config/mosquitto.conf", CONF);
    repo.lst(&["sync"]).ok();
    let seed = repo.seed();
    let mut store = repo.store();
    store.set_secret(&seed, "mq", "note", NOTE).unwrap();
    store.save(&repo.path().join(".sec")).unwrap();
    repo
}

/// `lst <args>` that must not write anything (outside `.git/`).
#[track_caller]
fn read_only(repo: &Repo, args: &[&str]) -> Run {
    let before = repo.snapshot();
    let run = repo.lst(args);
    assert_eq!(repo.snapshot(), before, "{args:?} wrote something");
    assert_clean_stderr(&run, &repo.seed_hex());
    run
}

fn alnum32() -> Format {
    "alnum32".parse().unwrap()
}

#[test]
fn render_prints_the_final_compose_file() {
    let repo = repo();
    let run = read_only(&repo, &["render", "mq"]);
    let out = run.ok();
    assert_eq!(run.stderr, "");
    assert!(!Path::new(TARGET_DIR).exists());

    let v: Value = serde_yaml_ng::from_str(out).unwrap();
    assert!(v.get("x-deploy").is_none(), "{out}");
    let mqtt = repo.expected_gen("shared", "mqtt", alnum32());
    let mongo_app = repo.expected_gen("mq", "mongo-app", "hex32".parse().unwrap());
    let s = &v["services"];
    assert_eq!(s["app"]["environment"]["MQTT_PASSWORD"], mqtt.as_str());
    // A manual secret that raw substitution would have broken.
    assert_eq!(s["mosquitto"]["environment"]["NOTE"], NOTE);
    assert_eq!(v["volumes"]["data"], Value::Mapping(Default::default()));

    // The label: on mosquitto (mounts the file's directory, has a pre
    // step) and mongo (post step, list-form labels), not on app.
    assert!(s["app"].get("labels").is_none(), "{out}");
    assert_eq!(s["mongo"]["labels"][0], "tier=db");
    let mongo_label = s["mongo"]["labels"][1].as_str().unwrap();
    let mosquitto_label = s["mosquitto"]["labels"]["lst.render-hash"]
        .as_str()
        .unwrap();

    // Recomputed here from what the design says goes in.
    let key = render_hash_key(&repo.seed());
    let secret = |v: &str| SecretString::new(v.to_owned());
    let pre = Step {
        service: "mosquitto".into(),
        run: Cmd::Shell(secret(&format!(
            "mosquitto_passwd -b -c /mosquitto/config/passwd app {mqtt}"
        ))),
        when: When::Always,
    };
    let conf = CONF.replace("<<secret:note>>", NOTE);
    let target = format!("{TARGET_DIR}/mosquitto.conf");
    let files: [(&Path, &[u8]); 1] = [(Path::new(&target), conf.as_bytes())];
    assert_eq!(
        mosquitto_label,
        xdeploy::service_hash(&key, &files, &[(Phase::Pre, &pre)])
    );
    let post = Step {
        service: "mongo".into(),
        run: Cmd::Exec(vec![
            secret("mongosh"),
            secret("--eval"),
            secret(&format!("createUser('app', '{mongo_app}')")),
        ]),
        when: When::OnChange,
    };
    assert_eq!(
        mongo_label,
        format!(
            "lst.render-hash={}",
            xdeploy::service_hash(&key, &[], &[(Phase::Post, &post)])
        )
    );

    // Deterministic.
    assert_eq!(repo.lst(&["render", "mq"]).ok(), out);
}

#[test]
fn render_file_prints_one_rendered_file() {
    let repo = repo();
    let conf = CONF.replace("<<secret:note>>", NOTE);
    for from in ["config/mosquitto.conf", "./config//mosquitto.conf"] {
        let run = read_only(&repo, &["render", "mq", "--file", from]);
        assert_eq!(run.ok(), conf);
        assert_eq!(run.stderr, "");
    }
    for from in [
        "config/other.conf",
        "compose.yaml",
        "../mq/config/mosquitto.conf",
    ] {
        let run = read_only(&repo, &["render", "mq", "--file", from]);
        run.fails_with(&[&format!(
            "stack \"mq\" has no x-deploy render: entry with from: {from:?} (its entries: \
             config/mosquitto.conf)"
        )]);
    }
    // A stack without x-deploy has none.
    repo.compose("plain", "a: 1\n");
    read_only(&repo, &["render", "plain", "--file", "a"]).fails_with(&[
        "stack \"plain\" has no x-deploy render: entry with from: \"a\" (its entries: none)",
    ]);
}

#[test]
fn stacks_without_x_deploy_render_byte_for_byte() {
    let repo = Repo::initialised();
    // Mentions x-deploy, isn't valid YAML, has odd formatting: all kept.
    for text in [
        "a: x-deploy\r\n# x-deploy: in a comment\n  b:   'c'  \n",
        "services:\n  a:\n    x-deploy: [\n\t\"unterminated\n",
        "  x-deploy: [1\n",
    ] {
        repo.compose("raw", text);
        assert_eq!(read_only(&repo, &["render", "raw"]).ok(), text);
    }
    // But a top-level key lst can't see from the line is an error.
    repo.compose("raw", "{x-deploy: {}, services: {}}\n");
    let msg = "stacks/raw/compose.yaml: write the top-level x-deploy key at the start of a line \
               (`x-deploy:`); lst decides which stacks use x-deploy from that line";
    read_only(&repo, &["render", "raw"]).fails_with(&[msg]);
    let run = read_only(&repo, &["check"]);
    assert_eq!(
        run.stderr,
        format!(
            "lst: no commit yet, so there is no committed <<set:…>> to look for\nlst: {msg}\n\
             lst: check failed: 1 problem\n"
        )
    );
}

#[test]
fn render_errors_name_places_not_values() {
    let repo = repo();
    let base = compose();

    // A YAML error: location only (the parser would quote the key).
    let text = base.replace(
        "  app:\n",
        "  app:\n    labels:\n      <<set:x:hunt3r-v4l>>: 1\n      <<set:x:hunt3r-v4l>>: 2\n",
    );
    repo.compose("mq", &text);
    let run = read_only(&repo, &["render", "mq"]);
    run.fails_with(&["stacks/mq/compose.yaml:11:7: invalid YAML (lst does not show"]);

    // Model errors.
    for (from, to, want) in [
        (
            "    - with: mosquitto\n",
            "    - with: nope\n",
            "stacks/mq/compose.yaml: x-deploy.pre[0].with: no service with that name under \
             services:",
        ),
        (
            "      to: /srv",
            "      to: srv",
            "stacks/mq/compose.yaml: x-deploy.render[0].to: must be an absolute path",
        ),
        (
            "      mode: \"0640\"\n",
            "      mode: \"0640\"\n      owner: root\n",
            "stacks/mq/compose.yaml: x-deploy.render[0]: unknown key (allowed: from, to, mode)",
        ),
        (
            "    labels: [tier=db]\n",
            "    labels: [tier=db, lst.render-hash=x]\n",
            "stacks/mq/compose.yaml: services.mongo.labels: lst.render-hash is set by lst; \
             remove it",
        ),
    ] {
        repo.compose("mq", &base.replace(from, to));
        read_only(&repo, &["render", "mq"]).fails_with(&[want]);
    }

    // The render: file must be one lst sync reads: not gitignored, not a
    // symlink.
    repo.compose("mq", &base);
    repo.write(".gitignore", "/.env\nmosquitto.conf\n");
    let gone = "stacks/mq/compose.yaml: x-deploy.render[0].from: no such file in stacks/mq/ (it \
                must be a regular file that git would commit: not gitignored, not a symlink)";
    read_only(&repo, &["render", "mq"]).fails_with(&[gone]);
    repo.write(".gitignore", "/.env\n");
    let conf = repo.path().join("stacks/mq/config/mosquitto.conf");
    fs::rename(&conf, conf.with_extension("real")).unwrap();
    symlink("mosquitto.real", &conf).unwrap();
    read_only(&repo, &["render", "mq"]).fails_with(&[gone]);
    fs::remove_file(&conf).unwrap();
    fs::rename(conf.with_extension("real"), &conf).unwrap();

    // Every unresolved name at once, from the compose file, the commands
    // and the render: file.
    repo.compose(
        "mq",
        &base.replace("<<gen:shared/mqtt>>\n", "<<gen:new-one>>\n"),
    );
    repo.write(
        "stacks/mq/config/mosquitto.conf",
        format!("{CONF}<<secret:unset>> <<gen:mongo-app>>\n"),
    );
    let run = read_only(&repo, &["render", "mq"]);
    run.fails_with(&[]);
    assert_eq!(
        run.stderr,
        "lst: stacks/mq/compose.yaml: could not resolve 3 secrets:\n  \
         `mq/mongo-app` is stored as hex32 but used as alnum32; run `lst sync`\n  \
         `mq/new-one` has no entry in .sec/; run `lst sync`\n  \
         `mq/unset` is not set; write <<set:unset:VALUE>> to set it\n"
    );

    // A malformed marker in the render: file is located there.
    repo.compose("mq", &base);
    repo.write("stacks/mq/config/mosquitto.conf", "a\nb <<gen:x\n");
    read_only(&repo, &["render", "mq"])
        .fails_with(&["stacks/mq/config/mosquitto.conf:2:3: unterminated marker"]);
}

#[test]
fn check_reports_x_deploy_problems() {
    let repo = repo();
    repo.git(&["add", "-A"]);
    assert_eq!(repo.commit(&["-m", "mq"]).code, Some(0));
    let seed = repo.seed_hex();
    let run = read_only(&repo, &["check"]);
    assert_eq!((run.ok(), run.stderr.as_str()), ("", "lst: check ok\n"));

    let base = compose();
    repo.compose(
        "mq",
        &base
            .replace("    - exec: mongo\n", "    - exec: mongodb\n")
            .replace(
                "<<gen:shared/mqtt>>\n",
                "<<gen:shared/mqtt>>\n      when: sometimes\n",
            ),
    );
    // Another stack: invalid YAML near a plaintext.
    repo.compose(
        "web",
        "x-deploy: {}\nservices:\n  a: {image: <<set:x:hunt3r-v4l>>: b}\n",
    );
    let want = |summary: &str| {
        format!(
            "lst: stacks/web/compose.yaml: <<set:x:…>> is not committed yet; commit the file, \
             and the pre-commit hook encrypts the value into .sec/ and rewrites the marker to \
             <<secret:x>>\n\
             lst: stacks/mq/compose.yaml: x-deploy.pre[0].when: must be always or on-change\n\
             lst: stacks/web/compose.yaml:3:34: invalid YAML (lst does not show the parser's \
             message: it can quote the file, and so a secret)\n\
             lst: {summary}\n"
        )
    };
    let run = read_only(&repo, &["check"]);
    run.fails_with(&[]);
    assert_eq!(run.stderr, want("check failed: 3 problems"));
    assert_clean_stderr(&run, &seed);

    // Structural only (no seed): the same x-deploy problems.
    let env = repo.read(".env");
    repo.remove(".env");
    let before = repo.snapshot();
    let run = repo.lst(&["check"]);
    assert_eq!(repo.snapshot(), before);
    assert_clean_stderr(&run, &seed);
    assert_eq!(
        run.stderr,
        want("check failed: 3 problems (structural only: no seed)")
    );
    repo.write(".env", env);
}

/// `lst deploy` pipes the same YAML-path text `lst render` prints into
/// compose (the fake docker records it). The render: target goes into a
/// temp dir here, since deploy writes it (tests/e2e/deploy.rs has the
/// x-deploy deploy tests).
#[test]
fn deploy_pipes_the_rendered_yaml() {
    let repo = repo();
    let target = tempfile::tempdir().unwrap();
    let target_dir = target.path().to_str().unwrap();
    repo.compose("mq", &compose().replace(TARGET_DIR, target_dir));
    repo.git(&["add", "-A"]);
    assert_eq!(repo.commit(&["-m", "mq"]).code, Some(0));
    let rendered = repo.lst(&["render", "mq"]).ok().to_owned();

    let bin = tempfile::tempdir().unwrap();
    let record = tempfile::tempdir().unwrap();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-docker");
    symlink(fixture, bin.path().join("docker")).unwrap();
    let mut dirs = vec![bin.path().to_owned()];
    dirs.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let before = repo.snapshot();
    let out = lst_cmd(repo.path(), &["deploy", "mq"])
        .env("PATH", std::env::join_paths(dirs).unwrap())
        .env("LST_FAKE_DOCKER_DIR", record.path())
        .output()
        .unwrap();
    let run = Run::from_output(out);
    run.ok();
    assert_clean_stderr(&run, &repo.seed_hex());
    assert_eq!(repo.snapshot(), before);
    // Call 1 is the `docker ps` for mongo's on-change step, 2 the pre
    // step, 3 `up`.
    let stdin = fs::read_to_string(record.path().join("call-3.stdin")).unwrap();
    assert_eq!(stdin, rendered);
    assert!(stdin.contains("lst.render-hash"));
    assert!(target.path().join("mosquitto.conf").is_file());
}
