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
