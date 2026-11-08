//! `lst import`: existing `.env` / `env_file:` values become manual secrets.

use crate::support::{Repo, Run};

/// Values only `.sec/` (encrypted) and `lst render`/`get` may show.
const DB_PW: &str = "0ld-db-$ecret";
const API_KEY: &str = "0ld-api-key";

const COMPOSE: &str = "\
services:
  db:
    image: postgres:17
    environment:
      POSTGRES_PASSWORD: ${DB_PASSWORD}
  app:
    image: example/app
    env_file:
      - app.env
    environment:
      DATABASE_URL: postgres://app:${DB_PASSWORD}@db/app
";

#[track_caller]
fn lst(repo: &Repo, args: &[&str]) -> Run {
    let run = repo.lst(args);
    for v in [DB_PW, API_KEY, "0ld"] {
        assert!(!run.stderr.contains(v), "a value on stderr: {run:#?}");
    }
    run
}

/// An initialised repo with a pre-lst stack `web`: `.env` (gitignored) for
/// interpolation, `app.env` for the app's environment.
fn repo() -> Repo {
    let repo = Repo::initialised();
    repo.write(".gitignore", "/.env\nstacks/*/.env\nstacks/*/*.env\n");
    repo.compose("web", COMPOSE);
    repo.write(
        "stacks/web/.env",
        format!("# web\nDB_PASSWORD='{DB_PW}'\nCOMPOSE_PROJECT_NAME=web\n"),
    );
    repo.write("stacks/web/app.env", format!("API_KEY={API_KEY}\n"));
    repo
}

#[test]
fn import_turns_env_values_into_secrets() {
    let repo = repo();
    let run = lst(&repo, &["import", "web"]);
    run.ok();
    assert!(
        run.stderr
            .contains("lst: import web/db_password (from DB_PASSWORD in stacks/web/.env)")
    );
    assert!(
        run.stderr
            .contains("lst: import web/api_key (from API_KEY in stacks/web/app.env)")
    );
    assert!(run.stderr.contains("move the env_file of service app"));

    assert_eq!(
        repo.read("stacks/web/compose.yaml"),
        "\
services:
  db:
    image: postgres:17
    environment:
      POSTGRES_PASSWORD: <<secret:db_password>>
  app:
    image: example/app
    environment:
      DATABASE_URL: postgres://app:<<secret:db_password>>@db/app
      API_KEY: '<<secret:api_key>>'
"
    );
    // The imported lines are gone; app.env had nothing else and is deleted.
    assert_eq!(
        repo.read("stacks/web/.env"),
        "# web\nCOMPOSE_PROJECT_NAME=web\n"
    );
    assert!(!repo.exists("stacks/web/app.env"));

    // The values are what compose read before (`$` escaped for compose).
    let rendered = lst(&repo, &["render", "web"]).ok().to_owned();
    assert!(rendered.contains("POSTGRES_PASSWORD: 0ld-db-$$ecret\n"));
    assert!(rendered.contains("API_KEY: '0ld-api-key'\n"));
    assert_eq!(
        lst(&repo, &["get", "web/db_password"]).ok(),
        format!("{DB_PW}\n")
    );

    // Commit: the hook is happy, check passes.
    repo.git(&["add", "-A"]);
    repo.commit(&["-m", "import"]).ok();
    lst(&repo, &["check"]).ok();

    // Running it again has nothing to do.
    let again = lst(&repo, &["import", "web"]);
    again.ok();
    assert!(
        again.stderr.contains("nothing to import in stack web"),
        "{again:#?}"
    );
}

#[test]
fn dry_run_writes_nothing() {
    let repo = repo();
    let before = repo.snapshot();
    let run = lst(&repo, &["import", "web", "--dry-run"]);
    run.ok();
    assert!(run.stderr.contains("would import web/db_password"));
    assert!(run.stderr.contains("would delete stacks/web/app.env"));
    assert!(run.stderr.contains("dry run: nothing was written"));
    assert_eq!(repo.snapshot(), before);
}

#[test]
fn exclude_and_manual_blocks() {
    let repo = repo();
    repo.write("stacks/web/app.env", format!("API_KEY={API_KEY}\nTZ=UTC\n"));
    let run = lst(&repo, &["import", "web", "--exclude", "TZ"]);
    run.ok();
    // The env_file can't go (TZ isn't imported): the block to write by hand.
    assert!(
        run.stderr
            .contains("warning: automatic replacement failed for the env_file of service app")
    );
    assert!(run.stderr.contains(
        "    environment:\n      API_KEY: '<<secret:api_key>>'\n      # TZ: not imported"
    ));
    assert!(
        run.stderr
            .contains("not imported: TZ (stacks/web/app.env): excluded")
    );
    let compose = repo.read("stacks/web/compose.yaml");
    assert!(compose.contains("env_file:\n      - app.env\n"));
    // app.env is still used: left whole.
    assert_eq!(
        repo.read("stacks/web/app.env"),
        format!("API_KEY={API_KEY}\nTZ=UTC\n")
    );
    // The value is stored anyway, so the snippet works.
    assert_eq!(
        lst(&repo, &["get", "web/api_key"]).ok(),
        format!("{API_KEY}\n")
    );
}

#[test]
fn tracked_or_unignored_env_files_warn() {
    let repo = repo();
    repo.write(".gitignore", "/.env\n");
    repo.git(&["add", "stacks/web/app.env"]);
    let run = lst(&repo, &["import", "web"]);
    run.ok();
    assert!(
        run.stderr
            .contains("warning: stacks/web/app.env is tracked by git"),
        "{run:#?}"
    );
    assert!(
        run.stderr
            .contains("warning: stacks/web/.env is not gitignored"),
        "{run:#?}"
    );
}

#[test]
fn refusals() {
    let repo = repo();
    // A <<set:…>> waiting in the working tree.
    repo.compose("web", &format!("{COMPOSE}x: <<set:x:v>>\n"));
    lst(&repo, &["import", "web"]).fails_with(&["has a <<set:x:…>>: commit it first"]);

    // A different value already stored under the name.
    let repo = self::repo();
    let mut store = repo.store();
    store
        .set_secret(&repo.seed(), "web", "api_key", "other")
        .unwrap();
    store.save(&repo.path().join(".sec")).unwrap();
    let before = repo.snapshot();
    lst(&repo, &["import", "web"]).fails_with(&[
        "web/api_key is already stored with a different value",
        "--exclude API_KEY",
    ]);
    assert_eq!(repo.snapshot(), before);

    // A gen of the same name.
    let repo = self::repo();
    repo.compose("other", "a: <<gen:x>>\n");
    repo.compose("web", &format!("{COMPOSE}y: <<gen:api_key>>\n"));
    lst(&repo, &["sync"]).ok();
    lst(&repo, &["import", "web"]).fails_with(&["web/api_key is already a generated secret"]);

    // A line lst can't read: named by line, not quoted.
    let repo = self::repo();
    repo.write("stacks/web/app.env", "0ld secret line\n");
    lst(&repo, &["import", "web"])
        .fails_with(&["stacks/web/app.env: line 1: not a KEY=VALUE line"]);

    // Unknown stack; no seed.
    lst(&repo, &["import", "nope"]).fails_with(&["nope"]);
    let repo = self::repo();
    repo.remove(".env");
    lst(&repo, &["import", "web"]).fails_with(&["no .env file"]);
}
