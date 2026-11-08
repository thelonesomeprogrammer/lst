//! `lst import`: existing `.env` / `env_file:` values become manual secrets.

use std::fs;
use std::os::unix::fs::PermissionsExt;

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

// ---------------------------------------------------------------------------
// Seeds, guards and where it runs
// ---------------------------------------------------------------------------

#[test]
fn import_with_lst_seed_and_from_a_subdirectory() {
    // CI: no .env, the seed in LST_SEED.
    let repo = repo();
    let seed = repo.seed_hex();
    repo.remove(".env");
    let run = repo.lst_env(&["import", "web"], &seed);
    for v in [DB_PW, API_KEY] {
        assert!(!run.stderr.contains(v), "{run:#?}");
    }
    run.ok();
    assert!(
        repo.read("stacks/web/compose.yaml")
            .contains("<<secret:db_password>>")
    );

    // From inside the stack directory.
    let repo = self::repo();
    let sub = repo.path().join("stacks/web");
    repo.lst_in(&sub, &["import", "web"]).ok();
    assert!(!repo.exists("stacks/web/app.env"));
}

#[test]
fn import_guards() {
    // Root .env not gitignored: refuse before reading anything.
    let repo = repo();
    repo.write(".gitignore", "stacks/*/.env\nstacks/*/*.env\n");
    let before = repo.snapshot();
    lst(&repo, &["import", "web"]).fails_with(&[".env is not gitignored"]);
    assert_eq!(repo.snapshot(), before);

    // A seed that isn't this repository's.
    let repo = self::repo();
    repo.remove(".env");
    let before = repo.snapshot();
    let other = "ab".repeat(32);
    let run = repo.lst_env(&["import", "web"], &other);
    run.fails_with(&["wrong seed"]);
    assert_eq!(repo.snapshot(), before);
}

#[test]
fn symlinked_and_non_utf8_env_files_are_left_alone() {
    use std::os::unix::fs::symlink;
    let repo = repo();
    // app.env → a file outside the stack; env/ → a symlinked directory.
    repo.remove("stacks/web/app.env");
    repo.write("outside/app.env", format!("API_KEY={API_KEY}\n"));
    symlink(
        "../../outside/app.env",
        repo.path().join("stacks/web/app.env"),
    )
    .unwrap();
    repo.write("outside/dir/b.env", "B=bbb\n");
    symlink("../../outside/dir", repo.path().join("stacks/web/env")).unwrap();
    repo.compose(
        "web",
        &COMPOSE.replace("      - app.env\n", "      - app.env\n      - env/b.env\n"),
    );
    let run = lst(&repo, &["import", "web"]);
    run.ok();
    assert!(
        run.stderr.contains("left the env_file of service app"),
        "{run:#?}"
    );
    assert!(run.stderr.contains("a symlink"), "{run:#?}");
    assert!(repo.path().join("stacks/web/app.env").is_symlink());
    assert_eq!(repo.read("outside/app.env"), format!("API_KEY={API_KEY}\n"));
    assert_eq!(repo.read("outside/dir/b.env"), "B=bbb\n");
    assert!(repo.read("stacks/web/compose.yaml").contains("env_file:"));

    // Not UTF-8: left alone too.
    let repo = self::repo();
    repo.write("stacks/web/app.env", b"API_KEY=\xff\xfe\n");
    let run = lst(&repo, &["import", "web"]);
    run.ok();
    assert!(run.stderr.contains("not UTF-8"), "{run:#?}");
    assert_eq!(
        fs::read(repo.path().join("stacks/web/app.env")).unwrap(),
        b"API_KEY=\xff\xfe\n"
    );
}

// ---------------------------------------------------------------------------
// Files on disk
// ---------------------------------------------------------------------------

#[test]
fn file_modes_are_kept() {
    let repo = repo();
    let mode = |rel: &str| {
        fs::metadata(repo.path().join(rel))
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    };
    let set = |rel: &str, m: u32| {
        fs::set_permissions(repo.path().join(rel), fs::Permissions::from_mode(m)).unwrap();
    };
    set("stacks/web/compose.yaml", 0o640);
    set("stacks/web/.env", 0o600);
    lst(&repo, &["import", "web"]).ok();
    assert_eq!(mode("stacks/web/compose.yaml"), 0o640);
    assert_eq!(mode("stacks/web/.env"), 0o600);
}

#[test]
fn rerun_is_byte_identical_and_finishes_an_interrupted_import() {
    let repo = repo();
    let originals = repo.snapshot();
    lst(&repo, &["import", "web"]).ok();
    let done = repo.snapshot();

    // Again: nothing changes, .sec/ is not re-sealed.
    lst(&repo, &["import", "web"]).ok();
    assert_eq!(repo.snapshot(), done);

    // Interrupted after .sec/ was saved: compose.yaml and the env files are
    // as they were. A second run finishes the job, identically.
    for rel in [
        "stacks/web/compose.yaml",
        "stacks/web/.env",
        "stacks/web/app.env",
    ] {
        repo.write(rel, &originals[std::path::Path::new(rel)]);
    }
    lst(&repo, &["import", "web"]).ok();
    assert_eq!(repo.snapshot(), done);
}

// ---------------------------------------------------------------------------
// With the rest of lst
// ---------------------------------------------------------------------------

#[test]
fn x_deploy_stack_imports_and_plans_a_deploy() {
    let repo = repo();
    repo.compose(
        "web",
        &format!(
            "{COMPOSE}x-deploy:\n  post:\n    - exec: db\n      run: echo ${{DB_PASSWORD}}\n      \
             when: on-change\n"
        ),
    );
    let run = lst(&repo, &["import", "web"]);
    run.ok();
    let compose = repo.read("stacks/web/compose.yaml");
    assert!(compose.contains("POSTGRES_PASSWORD: <<secret:db_password>>"));
    // The command isn't interpolated by compose: left alone, and so is the
    // .env line it still needs at the container's shell.
    assert!(compose.contains("run: echo ${DB_PASSWORD}"));
    assert!(repo.read("stacks/web/.env").contains("DB_PASSWORD="));

    repo.git(&["add", "-A"]);
    repo.commit(&["-m", "import"]).ok();
    let plan = lst(&repo, &["deploy", "web", "--dry-run"]);
    plan.ok();
    assert!(
        plan.stderr.contains("dry run: would deploy web"),
        "{plan:#?}"
    );
}

/// docs/migration.md, "Rotating a password into gen", step by step.
#[test]
fn migration_guide_rotate_into_gen() {
    let repo = repo();
    lst(&repo, &["import", "web"]).ok();
    repo.git(&["add", "-A"]);
    repo.commit(&["-m", "import"]).ok();

    // 1. Change the marker and commit: a new id, the secret is orphaned.
    let compose = repo.read("stacks/web/compose.yaml");
    repo.compose(
        "web",
        &compose.replace("<<secret:db_password>>", "<<gen:db_password>>"),
    );
    repo.git(&["add", "-A"]);
    repo.commit(&["-m", "gen"]).ok();
    // 2. The new value.
    let new = lst(&repo, &["get", "web/db_password"])
        .ok()
        .trim_end()
        .to_owned();
    assert_ne!(new, DB_PW);
    assert_eq!(new.len(), 32);
    // 4. It is what deploys.
    let rendered = lst(&repo, &["render", "web"]).ok().to_owned();
    assert!(rendered.contains(&format!("POSTGRES_PASSWORD: {new}\n")));
    // 5. The old value goes.
    assert_eq!(lst(&repo, &["gc"]).ok(), "web/db_password\n");
    lst(&repo, &["gc", "--remove", "web/db_password"]).ok();
    assert!(
        !repo.store().files()["web"]
            .secrets
            .contains_key("db_password")
    );
    assert_eq!(
        lst(&repo, &["get", "web/db_password"]).ok(),
        format!("{new}\n")
    );
    lst(&repo, &["check"]).ok();
}

/// A stacks directory other than `stacks/`, and a `docker-compose.yml`.
#[test]
fn import_follows_the_layout() {
    let repo = Repo::initialised();
    lst(&repo, &["stacks-dir", "apps"]).ok();
    repo.write(".gitignore", "/.env\napps/*/.env\napps/*/*.env\n");
    repo.write("apps/web/docker-compose.yml", COMPOSE);
    repo.write("apps/web/.env", format!("DB_PASSWORD='{DB_PW}'\n"));
    repo.write("apps/web/app.env", format!("API_KEY={API_KEY}\n"));
    let run = lst(&repo, &["import", "web"]);
    run.ok();
    assert!(
        run.stderr.contains("(from DB_PASSWORD in apps/web/.env)"),
        "{run:#?}"
    );
    assert!(
        run.stderr.contains("at apps/web/docker-compose.yml:5:26"),
        "{run:#?}"
    );
    let compose = repo.read("apps/web/docker-compose.yml");
    assert!(compose.contains("POSTGRES_PASSWORD: <<secret:db_password>>"));
    assert!(compose.contains("API_KEY: '<<secret:api_key>>'"));
    assert!(!repo.exists("apps/web/.env") && !repo.exists("apps/web/app.env"));
    assert!(
        lst(&repo, &["render", "web"])
            .ok()
            .contains("API_KEY: '0ld-api-key'")
    );
    repo.git(&["add", "-A"]);
    repo.commit(&["-m", "import"]).ok();
    lst(&repo, &["check"]).ok();
}
