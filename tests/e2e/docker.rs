//! Against a real Docker daemon, a Postgres and a client sharing
//! `<<gen:db>>`:
//! - the M1 done criterion (docs/plan.md): `lst render test | docker
//!   compose -p … --project-directory stacks/test -f - up -d --wait`;
//! - `lst deploy` (M3): deploys, a second deploy recreates nothing, and
//!   `--changed-since` deploys only the stack that changed.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::support::{Repo, Run, lst_cmd};

/// `docker compose -p <project> --project-directory <dir> -f - <args>`.
fn compose(project: &str, dir: &Path, args: &[&str]) -> Command {
    let mut c = Command::new("docker");
    c.args(["compose", "-p", project, "--project-directory"])
        .arg(dir)
        .args(["-f", "-"])
        .args(args);
    c
}

/// Runs a compose command with `file` as the compose file on stdin.
fn compose_with(project: &str, dir: &Path, file: &str, args: &[&str]) -> Output {
    let mut child = compose(project, dir, args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(file.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

/// `docker compose … down -v` on drop, so a failing test still removes its
/// containers, network and volumes.
struct Down {
    project: String,
    dir: PathBuf,
    file: String,
}

impl Drop for Down {
    fn drop(&mut self) {
        let out = compose_with(
            &self.project,
            &self.dir,
            &self.file,
            &["down", "-v", "--remove-orphans"],
        );
        if !out.status.success() && !std::thread::panicking() {
            panic!(
                "compose down failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}

fn stack(image: &str) -> String {
    format!(
        "\
services:
  db:
    image: {image}
    environment:
      POSTGRES_USER: app
      POSTGRES_DB: app
      POSTGRES_PASSWORD: <<gen:db>>
    healthcheck:
      test: [\"CMD-SHELL\", \"pg_isready -h 127.0.0.1 -U app -d app\"]
      interval: 1s
      timeout: 5s
      retries: 60
  client:
    image: {image}
    depends_on:
      db:
        condition: service_healthy
    environment:
      DATABASE_URL: postgresql://app:<<gen:db>>@db:5432/app
    command: [\"sleep\", \"infinity\"]
"
    )
}

/// Panics unless a Docker daemon is reachable; returns the Postgres image
/// to use: `postgres:17-alpine`, or `LST_TEST_POSTGRES_IMAGE` (e.g. a
/// registry mirror when Docker Hub rate-limits).
fn docker_image() -> String {
    let info = Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .output()
        .expect("docker CLI not found");
    assert!(
        info.status.success(),
        "Docker daemon not reachable: {}",
        String::from_utf8_lossy(&info.stderr)
    );
    std::env::var("LST_TEST_POSTGRES_IMAGE").unwrap_or_else(|_| "postgres:17-alpine".into())
}

/// A compose project name no other run uses: `<prefix>-<pid>-<nanos>`.
fn unique(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{prefix}-{}-{nanos}", std::process::id())
}

/// Asserts that the client of `project` logs in with the password from
/// its rendered `DATABASE_URL` (the value shared with the db service).
fn assert_client_logs_in(project: &str, dir: &Path, rendered: &str) {
    let query = "psql \"$DATABASE_URL\" -tAc 'select current_user'";
    let good = compose_with(
        project,
        dir,
        rendered,
        &["exec", "-T", "client", "sh", "-c", query],
    );
    assert!(
        good.status.success(),
        "login with the rendered password failed: {}",
        String::from_utf8_lossy(&good.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&good.stdout).trim(), "app");
}

#[test]
#[ignore = "needs Docker; run with `cargo test --test e2e -- --ignored docker`"]
fn docker_postgres_and_client_share_gen_db() {
    let image = docker_image();
    let repo = Repo::initialised();
    repo.compose("test", &stack(&image));
    repo.lst(&["sync"]).ok();

    let dir = repo.path().join("stacks/test");
    let project = unique("lst-e2e");
    // The rendered file, kept for the later `exec` and `down` calls (compose
    // needs it each time when it is read from stdin).
    let rendered = repo.lst(&["render", "test"]).ok().to_owned();
    let _down = Down {
        project: project.clone(),
        dir: dir.clone(),
        file: rendered.clone(),
    };

    // The real pipe: lst's stdout is compose's stdin.
    let mut render = lst_cmd(repo.path(), &["render", "test"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let up = compose(&project, &dir, &["up", "-d", "--wait"])
        .stdin(Stdio::from(render.stdout.take().unwrap()))
        .output()
        .unwrap();
    assert!(render.wait().unwrap().success());
    assert!(
        up.status.success(),
        "compose up failed: {}",
        String::from_utf8_lossy(&up.stderr)
    );

    assert_client_logs_in(&project, &dir, &rendered);

    // And password authentication is really enforced.
    let bad = compose_with(
        &project,
        &dir,
        &rendered,
        &[
            "exec",
            "-T",
            "client",
            "psql",
            "postgresql://app:wrong@db:5432/app",
            "-tAc",
            "select 1",
        ],
    );
    assert!(!bad.status.success(), "a wrong password must not log in");
    assert!(
        String::from_utf8_lossy(&bad.stderr).contains("password authentication failed"),
        "{}",
        String::from_utf8_lossy(&bad.stderr)
    );
}

/// `id created started-at` of every container of compose project
/// `project`, sorted: changes if any container is recreated or restarted.
fn containers(project: &str) -> Vec<String> {
    let label = format!("label=com.docker.compose.project={project}");
    let ps = Command::new("docker")
        .args(["ps", "-aq", "--no-trunc", "--filter", &label])
        .output()
        .unwrap();
    assert!(ps.status.success());
    let ids: Vec<String> = String::from_utf8(ps.stdout)
        .unwrap()
        .lines()
        .map(String::from)
        .collect();
    if ids.is_empty() {
        return Vec::new();
    }
    let inspect = Command::new("docker")
        .args([
            "inspect",
            "--format",
            "{{.Id}} {{.Created}} {{.State.StartedAt}} {{.State.Status}}",
        ])
        .args(&ids)
        .output()
        .unwrap();
    assert!(inspect.status.success());
    let mut out: Vec<String> = String::from_utf8(inspect.stdout)
        .unwrap()
        .lines()
        .map(String::from)
        .collect();
    out.sort();
    out
}

/// `lst deploy <args>` against the real docker; must succeed. Its stdout
/// is empty and its output never holds the seed.
#[track_caller]
fn lst_deploy(repo: &Repo, args: &[&str]) -> Run {
    let mut all = vec!["deploy"];
    all.extend_from_slice(args);
    let run = Run::from_output(lst_cmd(repo.path(), &all).output().unwrap());
    assert_eq!(run.ok(), "");
    let seed = repo.seed_hex();
    assert!(!run.stderr.contains(&seed[..32]) && !run.stderr.contains(&seed[32..]));
    run
}

/// A second stack: one container of the same image, so nothing new has to
/// be pulled. The image's `VOLUME` gets a named volume: the test recreates
/// this container, and Docker hands an anonymous volume on to the new
/// container in a way `down -v` no longer removes, while a named volume
/// carries the project label `down -v` goes by.
fn idle_stack(image: &str) -> String {
    format!(
        "\
services:
  idle:
    image: {image}
    environment:
      TOKEN: <<gen:token>>
    command: [\"sleep\", \"infinity\"]
    volumes:
      - data:/var/lib/postgresql/data
volumes:
  data:
"
    )
}

#[test]
#[ignore = "needs Docker; run with `cargo test --test e2e -- --ignored docker`"]
fn docker_lst_deploy() {
    let image = docker_image();
    // The stack names are the compose project names.
    let main = unique("lst-e2e-deploy");
    let other = unique("lst-e2e-other");
    let repo = Repo::initialised();
    repo.compose(&main, &stack(&image));
    repo.git(&["add", "-A"]);
    assert_eq!(repo.commit(&["-m", "main"]).code, Some(0));

    let dir = repo.path().join("stacks").join(&main);
    let rendered = repo.lst(&["render", &main]).ok().to_owned();
    let _down = Down {
        project: main.clone(),
        dir: dir.clone(),
        file: rendered.clone(),
    };

    let run = lst_deploy(&repo, &[&main]);
    assert!(
        run.stderr.ends_with(&format!("lst: deployed {main}\n")),
        "{run:#?}"
    );
    assert_client_logs_in(&main, &dir, &rendered);
    let first = containers(&main);
    assert_eq!(first.len(), 2, "{first:?}");
    assert!(first.iter().all(|c| c.ends_with(" running")), "{first:?}");

    // Deploying again changes nothing: same containers, not restarted.
    lst_deploy(&repo, &[&main]);
    assert_eq!(containers(&main), first);

    // A new stack in the last commit: --changed-since deploys only it.
    repo.compose(&other, &idle_stack(&image));
    repo.git(&["add", "-A"]);
    assert_eq!(repo.commit(&["-m", "other"]).code, Some(0));
    let other_dir = repo.path().join("stacks").join(&other);
    let _down_other = Down {
        project: other.clone(),
        dir: other_dir,
        file: repo.lst(&["render", &other]).ok().to_owned(),
    };
    let run = lst_deploy(&repo, &["--changed-since", "HEAD~1"]);
    assert!(
        run.stderr.ends_with(&format!("lst: deployed {other}\n")),
        "{run:#?}"
    );
    assert!(
        !run.stderr.contains(&format!("deployed {main}")),
        "{run:#?}"
    );
    assert_eq!(containers(&main), first);
    let idle = containers(&other);
    assert_eq!(idle.len(), 1, "{idle:?}");
    assert!(idle[0].ends_with(" running"), "{idle:?}");

    // A change to the existing other stack: only it is deployed (and its
    // container recreated, since its configuration changed).
    repo.compose(
        &other,
        &idle_stack(&image).replace("      TOKEN:", "      MODE: changed\n      TOKEN:"),
    );
    repo.git(&["add", "-A"]);
    assert_eq!(repo.commit(&["-m", "other changed"]).code, Some(0));
    let run = lst_deploy(&repo, &["--changed-since", "HEAD~1"]);
    assert!(
        run.stderr.ends_with(&format!("lst: deployed {other}\n")),
        "{run:#?}"
    );
    assert!(
        !run.stderr.contains(&format!("deployed {main}")),
        "{run:#?}"
    );
    assert_eq!(containers(&main), first);
    let recreated = containers(&other);
    assert_eq!(recreated.len(), 1, "{recreated:?}");
    assert!(recreated[0].ends_with(" running"), "{recreated:?}");
    assert_ne!(recreated, idle, "the changed stack was not recreated");
    assert_client_logs_in(&main, &dir, &rendered);
}

/// The `x-deploy` step runners and the render-hash lookup of
/// `src/deploy.rs` against real compose: argument forms (shell, exec, a
/// leading `-`/`+`), the compose file on stdin for `run` and `exec`, the
/// label read with `docker ps` before and after `up`, and step failures.
#[test]
#[ignore = "needs Docker; run with `cargo test --test e2e -- --ignored docker`"]
fn docker_x_deploy_steps_and_render_hash() {
    use lst::crypto::SecretString;
    use lst::deploy::{self, DeployError, Phase, StepCommand};

    let image = docker_image();
    let project = unique("lst-steps");
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("stacks").join(&project);
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let file = format!(
        "\
services:
  app:
    image: {image}
    command: [\"sleep\", \"infinity\"]
    volumes:
      - ./out:/out
    labels:
      lst.render-hash: 0123abcd
  plain:
    image: {image}
    command: [\"sleep\", \"infinity\"]
"
    );
    let _down = Down {
        project: project.clone(),
        dir: dir.clone(),
        file: file.clone(),
    };
    let compose = SecretString::new(file.clone());
    let s = |v: &str| SecretString::new(v.to_owned());
    let argv = |v: &[&str]| StepCommand::from_argv(v.iter().map(|a| s(a)).collect()).unwrap();
    let read = |name: &str| std::fs::read_to_string(out.join(name)).unwrap();
    let r = root.path();

    // Nothing is up yet: no container, no hash.
    assert_eq!(deploy::existing_hash(r, &project, "app").unwrap(), None);

    // pre, shell form, with the volume of the service.
    let cmd = StepCommand::Shell(s("printf '%s' 'pw ü€' > /out/shell"));
    deploy::run_pre(r, &project, &compose, 0, "app", &cmd).unwrap();
    assert_eq!(read("shell"), "pw ü€");
    // pre, exec form, arguments starting with `-` passed through.
    let cmd = argv(&[
        "sh",
        "-c",
        "printf '%s|' \"$@\" > /out/exec",
        "x",
        "-d",
        "--rm",
        "",
    ]);
    deploy::run_pre(r, &project, &compose, 1, "app", &cmd).unwrap();
    assert_eq!(read("exec"), "-d|--rm||");
    // pre, a shell string starting with `+`: `sh -c --` keeps busybox from
    // reading it as options (`+e` is then just a command that isn't found).
    let cmd = StepCommand::Shell(s("+e; printf ok > /out/plus"));
    deploy::run_pre(r, &project, &compose, 2, "app", &cmd).unwrap();
    assert_eq!(read("plus"), "ok");
    // A failing pre step.
    let fail = StepCommand::Shell(s("exit 3"));
    let err = deploy::run_pre(r, &project, &compose, 3, "app", &fail).unwrap_err();
    assert!(
        matches!(&err, DeployError::Step { phase: Phase::Pre, index: 3, status, .. }
            if status.code() == Some(3)),
        "{err:?}"
    );
    // `run --rm` containers are gone, and never count as the service's.
    assert_eq!(deploy::existing_hash(r, &project, "app").unwrap(), None);

    deploy::run_compose(r, &project, &compose).unwrap();
    assert_eq!(
        deploy::existing_hash(r, &project, "app")
            .unwrap()
            .as_deref(),
        Some("0123abcd")
    );
    assert_eq!(deploy::existing_hash(r, &project, "plain").unwrap(), None);
    assert_eq!(deploy::existing_hash(r, &project, "nope").unwrap(), None);

    // post, in the running container.
    let cmd = argv(&["sh", "-c", "printf post > /out/post"]);
    deploy::run_post(r, &project, &compose, 0, "app", &cmd).unwrap();
    assert_eq!(read("post"), "post");
    let cmd = StepCommand::Shell(s("-x"));
    let err = deploy::run_post(r, &project, &compose, 1, "plain", &cmd).unwrap_err();
    // `-x` ran as a command (not found: 127), not as a shell option.
    assert!(
        matches!(&err, DeployError::Step { phase: Phase::Post, index: 1, status, .. }
            if status.code() == Some(127)),
        "{err:?}"
    );
}

// ---------------------------------------------------------------------------
// M4 done criterion: x-deploy against real Docker
// ---------------------------------------------------------------------------

/// The Mosquitto image: `eclipse-mosquitto:2`, or `LST_TEST_MOSQUITTO_IMAGE`
/// (e.g. `mirror.gcr.io/library/eclipse-mosquitto:2`).
fn mosquitto_image() -> String {
    std::env::var("LST_TEST_MOSQUITTO_IMAGE").unwrap_or_else(|_| "eclipse-mosquitto:2".into())
}

/// A manual secret with what YAML quoting cares about: `"`, `#`, `: `.
/// (Not `$`: compose interpolates `$` in any value, rendered or not.)
const MQ_NOTE: &str = "q\"uote #hash: colon [x] {y} & *z";

const MOSQUITTO_CONF: &str = "\
# lst e2e: rendered by lst deploy
listener 1883
allow_anonymous false
password_file /mosquitto/config/passwd
# z2m: <<gen:shared/mqtt-z2m>>
";

/// The Mosquitto stack: the rendered config and the password file go to
/// `config` (an absolute host directory, bind-mounted), a `pre` step
/// hashes the shared z2m password with the image's own mosquitto_passwd
/// (shell form; `-c` refuses an existing file since mosquitto 2.1, hence
/// the `rm -f`), and a second one (exec form) hands the file to the
/// `mosquitto` user the broker runs as: mosquitto_passwd runs as root and
/// creates it `0600`, and the image's entrypoint doesn't chown (2.1).
/// Data and log get named volumes (see [`idle_stack`] on why not
/// anonymous ones).
fn mosquitto_stack(image: &str, config: &Path) -> String {
    let c = config.display();
    format!(
        "\
services:
  mosquitto:
    image: {image}
    ports:
      - \"18883:1883\"
    volumes:
      - {c}:/mosquitto/config
      - data:/mosquitto/data
      - log:/mosquitto/log
    environment:
      NOTE: '<<set:note:{MQ_NOTE}>>'
volumes:
  data:
  log:
x-deploy:
  render:
    - from: config/mosquitto.conf
      to: {c}/mosquitto.conf
      mode: \"0644\"
  pre:
    - with: mosquitto
      run: rm -f /mosquitto/config/passwd && mosquitto_passwd -b -c /mosquitto/config/passwd z2m <<gen:shared/mqtt-z2m>>
    - with: mosquitto
      run: [chown, \"mosquitto:mosquitto\", /mosquitto/config/passwd]
"
    )
}

/// The SQL of the `post` step: creates role `app1` if needed and sets its
/// password, so it can run any number of times.
const APP1_SQL: &str = "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app1') \
     THEN CREATE ROLE app1 LOGIN; END IF; END $$; ALTER ROLE app1 LOGIN PASSWORD '<<gen:pg-app1>>';";

/// A Postgres whose `post` step (exec form: no shell, so `$$` stays) sets
/// up the `app1` user of another service.
fn postgres_stack(image: &str, sql: &str) -> String {
    format!(
        "\
services:
  db:
    image: {image}
    environment:
      POSTGRES_PASSWORD: <<gen:db>>
    healthcheck:
      test: [\"CMD-SHELL\", \"pg_isready -h 127.0.0.1 -U postgres\"]
      interval: 1s
      timeout: 5s
      retries: 60
    volumes:
      - data:/var/lib/postgresql/data
volumes:
  data:
x-deploy:
  post:
    - exec: db
      run: [psql, -v, ON_ERROR_STOP=1, -U, postgres, -c, \"{sql}\"]
      when: on-change
"
    )
}

/// `docker compose exec -T <service> <args>` in `project`.
fn exec(project: &str, dir: &Path, rendered: &str, service: &str, args: &[&str]) -> Output {
    let mut all = vec!["exec", "-T", service];
    all.extend_from_slice(args);
    compose_with(project, dir, rendered, &all)
}

/// Publishes to Mosquitto in `project` as `user`/`password`, from inside
/// the broker's container.
fn mqtt_pub(project: &str, dir: &Path, rendered: &str, user: &str, password: &str) -> Output {
    exec(
        project,
        dir,
        rendered,
        "mosquitto",
        &[
            "mosquitto_pub",
            "-h",
            "127.0.0.1",
            "-p",
            "1883",
            "-u",
            user,
            "-P",
            password,
            "-t",
            "lst/e2e",
            "-m",
            "hi",
        ],
    )
}

/// `select current_user` as `app1` with `password`, over the compose
/// network (the image trusts 127.0.0.1, but asks everyone else for a
/// password).
fn pg_login(project: &str, dir: &Path, rendered: &str, password: &str) -> Output {
    let url = format!("postgresql://app1:{password}@db:5432/postgres");
    exec(
        project,
        dir,
        rendered,
        "db",
        &["psql", &url, "-tAc", "select current_user"],
    )
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// `lst deploy <args>` against real Docker ([`lst_deploy`]), also
/// asserting that none of `secrets` is in its output.
#[track_caller]
fn lst_deploy_clean(repo: &Repo, args: &[&str], secrets: &[&str]) -> Run {
    let run = lst_deploy(repo, args);
    for s in secrets {
        assert!(!run.stderr.contains(s), "a secret leaked: {run:#?}");
    }
    run
}

/// Every compose project label, volume and network of `projects` Docker
/// still knows about.
fn leftovers(projects: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for p in projects {
        let label = format!("label=com.docker.compose.project={p}");
        for what in [
            &["ps", "-aq"][..],
            &["volume", "ls", "-q"],
            &["network", "ls", "-q"],
        ] {
            let o = Command::new("docker")
                .args(what)
                .args(["--filter", &label])
                .output()
                .unwrap();
            assert!(o.status.success());
            out.extend(
                String::from_utf8(o.stdout)
                    .unwrap()
                    .lines()
                    .map(String::from),
            );
        }
    }
    out
}

#[cfg(unix)]
fn owner(path: &Path) -> (u32, u32) {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path).unwrap();
    (m.uid(), m.gid())
}

/// The M4 done criterion (docs/plan.md): Mosquitto with a password file
/// made by a `pre` step and a shared Postgres user made by a `post` step
/// deploy correctly and only restart when their inputs change. Also: a
/// manual secret with `"`, `#` and `: ` and a quoted port mapping survive
/// the YAML path.
#[test]
#[ignore = "needs Docker; run with `cargo test --test e2e -- --ignored docker`"]
fn docker_x_deploy_mosquitto_and_postgres() {
    let pg_image = docker_image();
    let mq_image = mosquitto_image();
    let mq = unique("lst-mq");
    let pg = unique("lst-pg");
    let out = tempfile::tempdir().unwrap();
    let config = out.path().join("mosquitto/config");

    let repo = Repo::initialised();
    repo.compose(&mq, &mosquitto_stack(&mq_image, &config));
    repo.write(
        &format!("stacks/{mq}/config/mosquitto.conf"),
        MOSQUITTO_CONF,
    );
    repo.compose(&pg, &postgres_stack(&pg_image, APP1_SQL));
    repo.git(&["add", "-A"]);
    assert_eq!(repo.commit(&["-m", "mq and pg"]).code, Some(0));

    let alnum = "alnum32".parse().unwrap();
    let z2m = repo.expected_gen("shared", "mqtt-z2m", alnum);
    let app1 = repo.expected_gen(&pg, "pg-app1", alnum);
    let secrets = [
        z2m.as_str(),
        app1.as_str(),
        &repo.expected_gen(&pg, "db", alnum),
        "q\"uote",
    ];
    let mq_dir = repo.path().join("stacks").join(&mq);
    let pg_dir = repo.path().join("stacks").join(&pg);
    let mq_rendered = repo.lst(&["render", &mq]).ok().to_owned();
    let pg_rendered = repo.lst(&["render", &pg]).ok().to_owned();
    // Down with the latest rendered file is the same project; the first
    // one is enough for `down -v`.
    let _down_mq = Down {
        project: mq.clone(),
        dir: mq_dir.clone(),
        file: mq_rendered.clone(),
    };
    let _down_pg = Down {
        project: pg.clone(),
        dir: pg_dir.clone(),
        file: pg_rendered.clone(),
    };

    // 1. First deploy: everything runs.
    let run = lst_deploy_clean(&repo, &[&mq, &pg], &secrets);
    let conf = config.join("mosquitto.conf");
    assert!(
        run.stderr
            .contains(&format!("lst: wrote {}\n", conf.display())),
        "{run:#?}"
    );
    assert!(!run.stderr.contains("skipped"), "{run:#?}");
    assert!(
        run.stderr.ends_with(&format!("lst: deployed {pg}\n")),
        "{run:#?}"
    );
    let rendered_conf = repo
        .lst(&["render", &mq, "--file", "config/mosquitto.conf"])
        .ok()
        .to_owned();
    assert_eq!(std::fs::read_to_string(&conf).unwrap(), rendered_conf);
    assert!(rendered_conf.contains(&z2m));

    // Mosquitto: z2m with the derived password gets in, a wrong password
    // and no password don't.
    let good = mqtt_pub(&mq, &mq_dir, &mq_rendered, "z2m", &z2m);
    assert!(
        good.status.success(),
        "z2m login failed: {}",
        stderr_of(&good)
    );
    let bad = mqtt_pub(&mq, &mq_dir, &mq_rendered, "z2m", "wrong");
    assert!(!bad.status.success(), "a wrong password must not log in");
    assert!(
        stderr_of(&bad).contains("not authorised"),
        "{}",
        stderr_of(&bad)
    );
    let anon = exec(
        &mq,
        &mq_dir,
        &mq_rendered,
        "mosquitto",
        &["mosquitto_pub", "-h", "127.0.0.1", "-t", "x", "-m", "x"],
    );
    assert!(!anon.status.success(), "anonymous must not log in");

    // The quoting check: compose took the re-serialised YAML; the
    // container sees the manual secret exactly and the port is published.
    let env = exec(
        &mq,
        &mq_dir,
        &mq_rendered,
        "mosquitto",
        &["printenv", "NOTE"],
    );
    assert!(env.status.success(), "{}", stderr_of(&env));
    assert_eq!(
        String::from_utf8(env.stdout).unwrap(),
        format!("{MQ_NOTE}\n")
    );
    let port = compose_with(&mq, &mq_dir, &mq_rendered, &["port", "mosquitto", "1883"]);
    assert!(port.status.success(), "{}", stderr_of(&port));
    assert!(
        String::from_utf8(port.stdout)
            .unwrap()
            .trim()
            .ends_with(":18883"),
        "port not published"
    );

    // Postgres: the post step made app1 with the derived password.
    let login = pg_login(&pg, &pg_dir, &pg_rendered, &app1);
    assert!(
        login.status.success(),
        "app1 login failed: {}",
        stderr_of(&login)
    );
    assert_eq!(String::from_utf8_lossy(&login.stdout).trim(), "app1");
    let bad = pg_login(&pg, &pg_dir, &pg_rendered, "wrong");
    assert!(!bad.status.success(), "a wrong password must not log in");
    assert!(stderr_of(&bad).contains("password authentication failed"));

    let mq_first = containers(&mq);
    let pg_first = containers(&pg);
    assert_eq!(mq_first.len(), 1, "{mq_first:?}");
    assert_eq!(pg_first.len(), 1, "{pg_first:?}");
    // Hand the config to the broker's user, as a chown step would (needs
    // root): lst keeps the owner when it rewrites the file below.
    let chowned = std::os::unix::fs::chown(&conf, Some(1883), Some(1883)).is_ok();

    // 2. Again, nothing changed: no container recreated or restarted, the
    // on-change post step skipped, the file not rewritten.
    let run = lst_deploy_clean(&repo, &[&mq, &pg], &secrets);
    assert!(
        run.stderr
            .contains("lst: skipped x-deploy.post[0] (db): inputs unchanged\n"),
        "{run:#?}"
    );
    assert!(!run.stderr.contains("lst: wrote"), "{run:#?}");
    assert_eq!(containers(&mq), mq_first);
    assert_eq!(containers(&pg), pg_first);

    // 3. Only the mosquitto.conf template changes (a comment): mosquitto
    // is recreated, postgres untouched. The rewritten file keeps its owner.
    repo.write(
        &format!("stacks/{mq}/config/mosquitto.conf"),
        format!("{MOSQUITTO_CONF}# changed\n"),
    );
    repo.git(&["add", "-A"]);
    assert_eq!(repo.commit(&["-m", "conf comment"]).code, Some(0));
    let mq_rendered = repo.lst(&["render", &mq]).ok().to_owned();
    let run = lst_deploy_clean(&repo, &[&mq, &pg], &secrets);
    assert!(
        run.stderr
            .contains(&format!("lst: wrote {}\n", conf.display())),
        "{run:#?}"
    );
    assert!(
        run.stderr
            .contains("lst: skipped x-deploy.post[0] (db): inputs unchanged\n"),
        "{run:#?}"
    );
    let mq_second = containers(&mq);
    assert_eq!(mq_second.len(), 1, "{mq_second:?}");
    assert_ne!(mq_second, mq_first, "mosquitto was not recreated");
    assert!(mq_second[0].ends_with(" running"), "{mq_second:?}");
    assert_eq!(containers(&pg), pg_first, "postgres was touched");
    if chowned {
        assert_eq!(owner(&conf), (1883, 1883));
    }
    assert!(
        std::fs::read_to_string(&conf)
            .unwrap()
            .ends_with("# changed\n")
    );
    let good = mqtt_pub(&mq, &mq_dir, &mq_rendered, "z2m", &z2m);
    assert!(
        good.status.success(),
        "z2m login failed: {}",
        stderr_of(&good)
    );

    // 4. The post command changes: its on-change step runs, and since the
    // command is an input of db's render hash, db is recreated once (its
    // data volume, and so app1, stay). Mosquitto is untouched.
    let sql = APP1_SQL.replace("ALTER ROLE", "ALTER ROLE /* v2 */");
    repo.compose(&pg, &postgres_stack(&pg_image, &sql));
    repo.git(&["add", "-A"]);
    assert_eq!(repo.commit(&["-m", "post v2"]).code, Some(0));
    let pg_rendered = repo.lst(&["render", &pg]).ok().to_owned();
    let run = lst_deploy_clean(&repo, &[&mq, &pg], &secrets);
    assert!(!run.stderr.contains("skipped x-deploy.post"), "{run:#?}");
    let pg_second = containers(&pg);
    assert_eq!(pg_second.len(), 1, "{pg_second:?}");
    assert_ne!(pg_second, pg_first, "db was not recreated");
    assert_eq!(containers(&mq), mq_second, "mosquitto was touched");
    let login = pg_login(&pg, &pg_dir, &pg_rendered, &app1);
    assert!(
        login.status.success(),
        "app1 login failed: {}",
        stderr_of(&login)
    );

    // And once more: all quiet again.
    let run = lst_deploy_clean(&repo, &[&mq, &pg], &secrets);
    assert!(
        run.stderr
            .contains("lst: skipped x-deploy.post[0] (db): inputs unchanged\n"),
        "{run:#?}"
    );
    assert_eq!(containers(&pg), pg_second);
    assert_eq!(containers(&mq), mq_second);

    drop(_down_pg);
    drop(_down_mq);
    assert_eq!(leftovers(&[&mq, &pg]), Vec::<String>::new());
}
