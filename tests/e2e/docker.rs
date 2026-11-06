//! The M1 done criterion (docs/plan.md), against a real Docker daemon:
//! `lst render test | docker compose -p … --project-directory stacks/test
//! -f - up -d --wait` for a Postgres and a client sharing `<<gen:db>>`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::support::{Repo, lst_cmd};

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

/// Needs a reachable Docker daemon. The image can be overridden with
/// `LST_TEST_POSTGRES_IMAGE` (e.g. a registry mirror when Docker Hub
/// rate-limits).
#[test]
#[ignore = "needs Docker; run with `cargo test --test e2e -- --ignored docker`"]
fn docker_postgres_and_client_share_gen_db() {
    let info = Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .output()
        .expect("docker CLI not found");
    assert!(
        info.status.success(),
        "Docker daemon not reachable: {}",
        String::from_utf8_lossy(&info.stderr)
    );

    let image =
        std::env::var("LST_TEST_POSTGRES_IMAGE").unwrap_or_else(|_| "postgres:17-alpine".into());
    let repo = Repo::initialised();
    repo.compose("test", &stack(&image));
    repo.lst(&["sync"]).ok();

    let dir = repo.path().join("stacks/test");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let project = format!("lst-e2e-{}-{nanos}", std::process::id());
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

    // The client logs in with the password from its own rendered
    // DATABASE_URL, i.e. the value shared with the db service.
    let query = "psql \"$DATABASE_URL\" -tAc 'select current_user'";
    let good = compose_with(
        &project,
        &dir,
        &rendered,
        &["exec", "-T", "client", "sh", "-c", query],
    );
    assert!(
        good.status.success(),
        "login with the rendered password failed: {}",
        String::from_utf8_lossy(&good.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&good.stdout).trim(), "app");

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
