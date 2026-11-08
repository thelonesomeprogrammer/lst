# Migrating existing stacks to `lst`

Nobody starts with an empty repository. This guide takes stacks that already run, with their passwords in `.env` files, `env_file:` files or written inline, and brings them under `lst` one at a time, without changing a single password on the way. Generated secrets (`<<gen:…>>`) come later, one at a time, and only where you want them.

The short version:

1. Set up `lst` and **test the restore path** before anything important depends on it.
2. Per stack, start with the least important one: `lst import <stack>`, review, commit, `lst deploy <stack>`. The values are unchanged, so the containers don't notice.
3. Later, where it's worth it: **rotate** a password into a `<<gen:…>>` secret. An existing password can't *become* a generated one (see [below](#gen-vs-secret-why-an-existing-password-stays-a-secret)).

## 1. Before you start

```sh
lst init                     # seed → .env, /.env → .gitignore, .sec/meta.toml, pre-commit hook
git add .gitignore .sec && git commit -m "lst init"
```

- **Back up the seed now.** Copy the `LST_SEED=…` line from `.env` into your password manager. Without it, generated secrets can't be recovered and `.sec/` can't be decrypted.
- **Test the restore path early**, while nothing depends on it yet. Clone the repository somewhere else, create `.env` with the seed from your password manager, run `lst hook install` and `lst deploy --all --dry-run`. If that works, a lost machine costs you a clone and one line. Do this again before you migrate the stacks you can't afford to lose (step 2, last stage).
- **Gitignore the stacks' own env files** before you start (`stacks/*/.env`, `stacks/*/*.env`, or whatever names you use). `lst import` removes the lines it imports, but other lines stay, and `git add stacks` must not pick them up. If one of them was ever committed, its values are in your history: see [Cleanup](#4-cleanup).
- Put each stack in its own directory in the stacks directory, `stacks/<name>/` by default (`lst stacks-dir DIR` sets another, `.` for the repository root), with its compose file (`compose.yaml`, `compose.yml`, `docker-compose.yaml` or `docker-compose.yml`) and any config files it needs next to it. `lst deploy` runs `docker compose -p <name> --project-directory stacks/<name>`, so the project name is the directory name. Keep it the same as the running project's name, or compose will create a second set of containers.

## 2. Order: pilot first, core last

Go from "doesn't matter if it breaks" to "everything depends on it":

1. **A throwaway stack** (say Postgres plus a small web app): learn the cycle of import, commit, deploy, rotate where nothing is at stake.
2. **Low-stakes apps:** the ones you could rebuild in an afternoon.
3. **Stacks that share secrets or need deploy steps** (an MQTT broker and its clients through `shared/…` names, a password file hashed in an `x-deploy` `pre` step). These use the rest of `lst`'s features, so do them once the basics are routine.
4. **The rest** of the ordinary stacks.
5. **Core infrastructure last:** reverse proxy, SSO/auth, the password manager that holds your seed. Only after you have run the restore test from step 1 again, for real: wipe a clone, restore the seed from the password manager, deploy, and confirm it works. If the password manager itself is a stack you deploy with `lst`, keep an offline copy of the seed too.

## 3. Per stack: `lst import`

```sh
lst import web --dry-run     # what would happen; writes nothing
lst import web               # do it
git diff                     # review
git add -A stacks/web .sec && git commit -m "web: secrets under lst"
lst check && lst deploy web
```

What `lst import <stack>` does:

- It reads the stack directory's `.env` (compose's interpolation file) and every file an `env_file:` names, and stores their values **encrypted in `.sec/`** as manual secrets. The secret's name is the variable name in lowercase (`DB_PASSWORD` → `web/db_password`).
- In the compose file, `${DB_PASSWORD}` (and `$DB_PASSWORD`, `${DB_PASSWORD:-…}`, `${DB_PASSWORD:?…}`) becomes `<<secret:db_password>>`. `${VAR:+…}` doesn't evaluate to the value and is left alone.
- An `env_file:` becomes an `environment:` block of `KEY: '<<secret:key>>'` entries. If the service already has a block-style `environment:`, the entries are added to it; keys it already sets are left out, because they override the file anyway.
- **Every rewrite is checked.** A rewrite is kept only if compose would read exactly the same values afterwards: lst renders the result in memory (with the real values, as `lst render` would), parses and interpolates it the way compose does, and compares that with the original. A rewrite that fails the check is left as it was and reported:
  - `left ${VAR} as it is`: with the value written in raw, the YAML would read something else: a value with `: ` or ` #` in a plain scalar, `"` inside double quotes, or a value YAML could read as a number, bool or null (`0777`, `1e3`, `yes`, an empty value) standing alone in a plain scalar. Put the scalar in single quotes and run `lst import` again.
  - `automatic replacement failed for the env_file of service …`: lst prints the `environment:` entries to write by hand. The values are already imported, so the markers resolve. Remove the `env_file:` yourself when you add them.
- Then it **removes the imported lines** from the env files. A file with nothing left in it but blank and comment lines is deleted. A line stays as long as something still reads it (a `${VAR}` that couldn't be replaced, an `env_file:` that is still there).
- `--exclude VAR` (repeatable) leaves a variable alone: not imported, not rewritten, its line kept. Use it for plain settings you'd rather keep visible (`TZ`, `PUID`). An `env_file:` that still holds an excluded variable can't be replaced automatically; lst prints the block to finish by hand.
- It never prints a value: only variable names, secret names, files and line numbers. It needs the seed, like `lst sync`.
- Running it again is safe: it finishes what's left and reports "nothing to import" once done.

It refuses (and changes nothing) when:

- a name is already a generated secret, or already stored with a different value (`--exclude` the variable, or sort out the stored one);
- two variables would get the same name (`DB_PW` and `db_pw`), or one variable has different values in two files;
- a `<<set:…>>` waits in `compose.yaml` (commit it first);
- a line in an env file isn't `KEY=VALUE` (it names the line, never its content).

Values lst can't reproduce exactly are skipped with the reason, and their lines stay: an unquoted or double-quoted value with `$` (compose would interpolate it), a double-quoted value with escapes such as `\n`, multi-line values, a line with text after its closing quote, and a bare `KEY` (compose takes its value from its own environment). Import them by hand with `<<set:name:VALUE>>`. lst reads env files the way compose does (single quotes literal except `\'`, `"…"` with `\\`, `\"` and `\$`, `#` comments after a space); this is checked against `docker compose config` in lst's tests.

**Inline secrets** (`POSTGRES_PASSWORD: hunter2` written straight into `compose.yaml`) aren't touched by `lst import`. Wrap them by hand: `POSTGRES_PASSWORD: <<set:db_password:hunter2>>`, and commit. The hook stores the value and rewrites the marker to `<<secret:db_password>>`. Those values were committed in plain text before, so they are in your history: rotate them (step 5) once the stack runs under `lst`.

**Not covered:** variables compose takes from the shell that runs it (they override `.env`), `docker compose --env-file`, `env_file:` paths outside the stack directory or with `$` in them. lst reports these as left alone where it sees them.

## 4. Cleanup

- If an env file was ever committed, its values are in your Git history, whatever lst does now. Once the stack runs under `lst`, give them new values (step 5).
- `git gc --prune=now` is **not** needed after `lst import`: unlike `<<set:…>>` it never puts a value into a Git blob. It is needed after `<<set:…>>`, which the hook reminds you of.
- `lst check` should pass, and `lst deploy <stack> --dry-run` should show the plan you expect.

## 5. gen vs. secret: why an existing password stays a secret

`<<gen:name>>` values are **derived**: `value = KDF(seed, random id)`. You can't choose what comes out, so you can't make `lst` generate the password your database already has. An existing password therefore comes in as a **manual secret** (`<<secret:…>>`, stored encrypted in `.sec/`), and that is fine to keep for good.

Use `<<gen:…>>` for:

- **new** secrets: a new stack, a new service, a new API token between two of your own services;
- existing ones you **rotate into gen** on purpose, because you want a strong value `lst` manages, or because the old one leaked (it was committed, or written inline).

Keep `<<secret:…>>` for values that come from outside (an API token a provider gave you, an SMTP password) and for anything you don't want to change.

### Rotating a password into gen

Example: stack `web`, imported as `<<secret:db_password>>`, used by Postgres and by the app.

1. **Change the marker** in `compose.yaml` everywhere it's used: `<<secret:db_password>>` → `<<gen:db_password>>`. Commit. The hook gives the name an id (and so a value), and marks the old secret entry as an orphan.
2. **Read the new value:** `lst get web/db_password` (or `--copy`).
3. **Set it inside the app first.** A database reads `POSTGRES_PASSWORD` / `MARIADB_ROOT_PASSWORD` / `MONGO_INITDB_ROOT_PASSWORD` **only when it creates its data directory**, so a new value in compose alone changes nothing in the database, while the apps that connect to it start using the new one. Change it where the password really lives:
   - Postgres: `docker compose -p web exec db psql -U postgres -c "ALTER USER app PASSWORD '…'"`
   - MariaDB/MySQL: `ALTER USER 'app'@'%' IDENTIFIED BY '…';`
   - MongoDB: `db.changeUserPassword("app", "…")`
   - an app's admin password: in the app's UI or CLI.
   
   Or let the deploy do it with an `x-deploy` `post` step that runs after `up --wait`, with `when: on-change` (see the README's [Deploy steps](../README.md#deploy-steps-x-deploy)). The apps restart with the new value before the step runs, so expect a short window of failed connections.
4. **Deploy:** `lst deploy web`. The services pick up the new value.
5. **Remove the old value** once nothing needs it: `lst gc` lists it as an orphan; `lst gc --remove web/db_password` deletes the secret entry. (The gen entry of the same name is in use, so it stays.)

A generated secret can be rotated again later with `lst rotate web/db_password`, with the same caveat for databases: set the new value inside the app too.

## Checklist per stack

- [ ] `stacks/<name>/compose.yaml`, project name unchanged
- [ ] env files gitignored
- [ ] `lst import <name> --dry-run`, then `lst import <name>`
- [ ] anything it reported done by hand (quoting, `env_file:` blocks, inline values with `<<set:…>>`)
- [ ] commit; `lst check`; `lst deploy <name>`
- [ ] values that were ever committed: rotated
- [ ] core stacks only: restore test done
