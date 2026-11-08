# lst: Lazy Secret Tool

> Write your compose files. Don't think about secrets.

`lst` lets you keep Docker Compose stacks in Git without ever inventing, copying or syncing a secret by hand. You put a marker where a secret goes; `lst` derives, stores and fills in the real value at deploy time.

```yaml
services:
  db:
    image: postgres:17
    environment:
      POSTGRES_PASSWORD: <<gen:db>>
  app:
    image: example/app
    environment:
      DATABASE_URL: postgres://app:<<gen:db>>@db/app
      CF_TOKEN: <<secret:cloudflare>>
```

> **Status:** in development. See [Roadmap](#roadmap).

## Why

- **You are never the source of randomness.** Generated secrets come from a master seed that `lst` creates itself.
- **You just write config.** Two services that reference `<<gen:db>>` get the same password, with no copy-pasting.
- **State is shared once.** Copy one seed to each machine; nothing ever needs syncing again.
- **No extra files to hand-write.** Everything lives in your compose files. `lst` manages its own files (`.env`, `.sec/`).

## Markers

| Marker | Meaning |
|---|---|
| `<<gen:name>>` | Generated secret, derived from the seed. Optional format: `<<gen:name:hex64>>` |
| `<<secret:name>>` | Manual secret (API token, SMTP password…) that is already stored |
| `<<set:name:VALUE>>` | Enter or replace a manual secret. On commit, `lst` encrypts it and rewrites the marker to `<<secret:name>>` |

- Names are scoped to their stack. Use `shared/name` for secrets used across stacks.
- Markers work anywhere in a value, including inside URLs and DSNs.
- Markers work in any file `lst` renders, not just compose.

**Formats:** `alnumN` (default `alnum32`, URL-safe), `hexN`, `base64-N`, `uuid`. N counts output characters; it must give at least 128 bits (`alnum` and `base64` N ≥ 22, `hex` N ≥ 32) and is at most 256.

**Escaping in `<<set:…>>`:** `\\` → `\`, `\>` → `>`. The value ends at the first unescaped `>>`.

```
<<set:x:a\>>b>>        value: a>>b
<<set:x:C:\\path>>     value: C:\path
```

## How it works

```
master seed (.env, gitignored)
   │
   ├─ BLAKE3 derive_key ──► generated secrets   (KDF(seed, id))
   └─ BLAKE3 derive_key ──► encryption key ───► manual secrets in .sec/
```

- **`.env`** holds the master seed. It's written by `lst init`, is never committed, and `lst` refuses to run if it isn't gitignored.
- **`.sec/`** is committed and written only by `lst`. It contains:
  - for each generated secret: name → random id + format (the id, not the name, is what gets derived, so renaming is safe);
  - manual secrets, encrypted with XChaCha20-Poly1305;
  - a seed fingerprint, so a wrong seed fails loudly instead of deploying wrong passwords.
- **The pre-commit hook** keeps `.sec/` in sync with your compose files and processes `<<set:…>>` markers, so plaintext never reaches a commit.
- **`lst deploy`** checks state, renders every marker, and pipes the result straight into `docker compose`. Nothing plaintext is written to disk unless a target needs a file.

## Deploy steps: `x-deploy`

Per-stack deploy logic lives inside the compose file (Compose ignores `x-` keys; `lst` strips this one before deploying):

```yaml
services:
  mosquitto:
    image: eclipse-mosquitto:2
    volumes:
      - /mnt/appdata/mosquitto/config:/mosquitto/config
x-deploy:
  render:                           # template in the repo → rendered file on the host
    - from: config/mosquitto.conf
      to: /mnt/appdata/mosquitto/config/mosquitto.conf
      mode: "0644"                  # default "0600"
  pre:                              # one-off container from the service's image, before `up`
    - with: mosquitto
      run: rm -f /mosquitto/config/passwd && mosquitto_passwd -b -c /mosquitto/config/passwd z2m <<gen:shared/mqtt-z2m>>
    - with: mosquitto
      run: [chown, "mosquitto:mosquitto", /mosquitto/config/passwd]   # exec form, no shell
  post:                             # inside the running, healthy service, after `up --wait`
    - exec: mongo
      run: mongosh --eval '…createUser("app1", "<<gen:mongo-app1>>")…'
      when: on-change               # default: always
```

When a service's rendered inputs change, `lst` changes a `lst.render-hash` label on it, so Compose recreates the container. No state file is needed.

- **`render:`** `from` is a file in `stacks/<stack>/` (with markers, rendered as raw text); `to` is an absolute host path. `lst deploy` writes it atomically, only when its content changed, with exactly `mode` (whatever the umask); missing parent directories are created (`0755`). A wrong mode on an unchanged file is fixed. Ownership is never changed: a new file belongs to the user running lst, and a rewritten file keeps its owner and group, so a `chown` from a `pre` step survives. A symlink or a directory at `to` is refused. `lst render <stack> --file <from>` prints what would be written. lst writes `to` where it runs, so in CI the deploy step must mount the target directories at the same paths ([`docs/ci.md`](docs/ci.md#x-deploy-render-targets)); bind-mount them into the service with the same absolute host path (a relative `./config` doesn't count for the hash and points elsewhere in CI).
- **`pre: [{with, run, when}]`** runs `docker compose run --rm --no-deps -T <with> …` before `up`: a throwaway container of the service, with its volumes, so the app's own tools (here `mosquitto_passwd`) work without installing anything on the host. It goes through the image's entrypoint (lst never overrides it), so it works with images whose entrypoint script runs the given command (mosquitto, postgres, …) but not with images whose entrypoint is the app binary itself; use a `post` step there.
- **`post: [{exec, run, when}]`** runs `docker compose exec -T <exec> …` in the running container after `up --wait` (the entrypoint doesn't matter here).
- **`run:`** a string runs as `sh -c <string>`; a list runs as it is (exec form, no shell: for images without one, or to keep `$` and quotes away from a shell). Markers are rendered in `run` (the values are briefly visible in `ps` on the host).
- **`when:`** `always` (default) runs the step on every deploy; `on-change` only when the service's `lst.render-hash` differs from the label of its existing container (no container counts as changed). Steps run on every deploy otherwise, so write them idempotently (note `rm -f` above: `mosquitto_passwd -c` refuses an existing file since Mosquitto 2.1).
- **Order per stack:** read the existing hashes of services with `on-change` steps → write the changed `render:` files (`lst: wrote <to>` / `lst: fixed the mode of <to>`) → `pre` steps in order → `docker compose up -d --wait --remove-orphans` → `post` steps in order. A skipped step prints `lst: skipped x-deploy.pre[0] (mosquitto): inputs unchanged`. A failing `pre` step stops before `up` (files already written stay written); a failing `post` step fails the deploy with the stack already up. Either way the stacks after it are not attempted.
- A step's command is part of its service's hash, so changing a command recreates that container once.

## Commands

| Command | Does |
|---|---|
| `lst init` | Create the seed, gitignore `.env`, write `.sec/meta.toml`, install the hook |
| `lst sync` | Update `.sec/` from your compose files (the hook does this for you) |
| `lst render <stack>` | Print the resolved compose file to stdout (`--file FROM`: one rendered `x-deploy` file) |
| `lst rename <stack>/<old> <new>` | Rename a secret keeping its value (`--replace` if the new name exists) |
| `lst deploy <stack>…` / `--changed-since REV` / `--all` | Check, then per stack: render, `x-deploy` files and `pre` steps, `compose up --wait`, `post` steps (`--dry-run`: only print the plan) |
| `lst check` | Verify `.sec/` is current, no `<<set:` committed, all secrets resolvable |
| `lst hook install` / `run` | Install / run the pre-commit logic |
| `lst rotate <stack>/<name>` | Give a generated secret a new value |
| `lst gc [--remove [NAME…]]` | List orphaned secrets, or remove them |
| `lst stacks-dir [DIR]` | Show or set where the stacks live (default `stacks`, `.` for a flat repo) |
| `lst get <stack>/<name>` | Print one secret's value, e.g. to log in (`--copy`: to the clipboard) |
| `lst import <stack>` | Turn a running stack's `.env` / `env_file:` values into manual secrets (`--exclude VAR`, `--dry-run`) |

## Setup

```sh
lst init                     # on the first machine (also installs the pre-commit hook)
# save the seed from .env in your password manager (this is also your backup)
# on each other machine: clone, put the seed in .env, run `lst hook install` (or `lst init`)
```

**Existing stacks:** [`docs/migration.md`](docs/migration.md) walks through bringing running stacks under `lst` (`lst import`, the order to do it in, and how to rotate an existing password into a `<<gen:…>>` one).

## Usage

```sh
lst init                     # in the repo: seed → .env (mode 0600), /.env → .gitignore, .sec/meta.toml, pre-commit hook
git add .gitignore .sec && git commit -m "lst init"
# copy the LST_SEED=… line from .env into your password manager now

# edit compose files, then just commit: the hook updates .sec/ and stores <<set:…>> values
git add stacks && git commit

lst check                    # is everything consistent and resolvable?
lst deploy web               # check, render, docker compose up (or: lst render web | docker compose …)
lst deploy --all --dry-run   # what a deploy of every stack would do, without doing it

lst rotate web/db            # new value for a generated secret; commit .sec/, then deploy web
lst gc                       # list orphaned secrets; lst gc --remove deletes them
```

- **`lst init`** gitignores `.env` (and refuses if `.env` is tracked), creates the seed and writes `.sec/meta.toml`. Other lines in an existing `.env` are kept. It never prints the seed. Running it again only checks that the seed in `.env` matches `.sec/`. If `.sec/` already exists but `.env` has no seed, it refuses rather than create a second seed. As its last step it installs the pre-commit hook (see below), also when the repo is already initialised; an existing pre-commit hook that isn't lst's is left alone, with a warning.
- **The pre-commit hook** (`lst hook run`, which git runs on every commit) checks and updates what you commit:
  - It reads the **staged** files (the index, not the working tree): every staged file under `stacks/<stack>/`, not only the changed ones.
  - New `<<gen:…>>` names get ids, unused names are marked as orphans, and the updated `.sec/` goes into the same commit. When one name disappears and one appears, it prints the `lst rename … --replace` command that keeps the old value.
  - `<<set:name:VALUE>>` is encrypted into `.sec/` and rewritten to `<<secret:name>>` in the commit and in your working tree. Only that exact marker text is replaced; the rest of the file, unstaged edits included, is left alone. It then reminds you that `git add` already wrote the plaintext as a blob into `.git/objects`: no commit references it and it is never pushed, but it stays on disk until `git gc --prune=now` (or git's own pruning) removes it.
  - It **blocks the commit** (nothing is committed or changed) on:
    - a `<<secret:…>>` with no stored value (it names the `<<set:…>>` to write);
    - a malformed marker, or one name set to two different values;
    - a `<<set:` in any staged file outside a stack, or in a non-UTF-8 file;
    - a symlinked stack directory or compose file;
    - unresolved merge conflicts;
    - a wrong or missing seed, or `.env` not being gitignored;
    - `lst` not being on `PATH`.
  - It is silent when there is nothing to report.
  - `git commit -a` works. `git commit <paths>` commits from a temporary index that git never copies back to your real index, so it only works when the hook has nothing to change. Otherwise it blocks and asks you to `git add` the files and run `git commit` without paths.
- **`lst hook install [--force]`** installs the hook where git looks for it (`git rev-parse --git-path hooks`, so `core.hooksPath` is respected). Run it once in every clone (`lst init` does it too). It never replaces a pre-commit hook that isn't lst's unless you pass `--force`.
- **`git commit --no-verify` skips the hook**, and with it the protection: a `<<set:…>>` committed that way is plaintext in your history. Don't. `lst check` and `lst deploy` refuse a committed `<<set:` and tell you to rotate the secret (a new value through `<<set:…>>`; `lst rotate` is for generated secrets).
- **`lst sync`** does by hand what the hook does on commit (you rarely need it). It reads every file under `stacks/<stack>/` in the working tree that git would stage (not only the compose file). Gitignored files, such as bind-mounted data, are skipped; symlinks are skipped rather than followed; non-UTF-8 files are skipped unless they contain `<<set:`. A symlinked `stacks/`, a symlink directly in `stacks/` and a symlinked compose file are errors (git commits a symlink as a link, so the hook couldn't see the stack). It updates `.sec/`: new generated names get a random id, names that are no longer used are marked as orphans (never deleted; `lst gc` removes them), and orphans that come back are reused with the same id (and so the same value). Commit `.sec/` afterwards (any commit does: the hook stages it). `<<set:…>>` is refused: commit the file instead, and the pre-commit hook stores the value. When one name disappears and one appears in the same stack, it prints the `lst rename` command that keeps the old value.
- **`lst rename <from> <to> [--replace]`** renames an entry in `.sec/` without changing its value: a generated secret keeps its id, a manual secret is re-encrypted under the new name. `<from>` is a full name (`web/db`, `shared/mqtt`); `<to>` is a full name too, or a name without `/` in the same stack (or `shared`). Moving between a stack and `shared/` works. If `<to>` already exists (typically because a sync or commit just gave it a fresh id) pass `--replace`. It does not edit your files: change the markers yourself.
- **`lst rotate <name>`** gives a generated secret a new value: a new random id, the same format. `<name>` is a full name (`web/db`, `shared/mqtt`). It only rotates a `<<gen:…>>` name that is in use: a manual secret is refused (write `<<set:name:VALUE>>` to replace it), and so is an orphan (nothing uses it; `lst gc` removes it). A name with no entry in `.sec/` hints at `lst sync`. It needs the seed, like `lst sync` and `lst rename`, and changes nothing else. Commit `.sec/` afterwards, then deploy the stacks it names (the stacks whose files use the name). **An app that only reads a password on first start keeps the old one**: a database's initial password (`POSTGRES_PASSWORD`, `MONGO_INITDB_ROOT_PASSWORD`, …) is only applied when the data directory is created, so after a rotation the database keeps the old password while the services that connect to it get the new one. Change the password inside the app too (in Postgres, `ALTER USER … PASSWORD …`).
- **`lst get <name>`** prints the value of one secret on stdout, for logging in to the app it belongs to (`lst get web/admin`, `lst get shared/mqtt`). `<name>` is a full name. It needs the seed, like `lst render` (which shows the same values), and is read-only. The output is the raw value plus a newline (`-n` leaves the newline off): what a `render:` file gets, so a `$` is not doubled as in `lst render <stack>`. Orphans can be shown too (with a note on stderr), since an app may still use the old value. A name with no entry lists the names that do exist in that stack. `--copy` puts the value (without a newline) in the clipboard instead of printing it, through the first of `wl-copy`, `xclip`, `xsel` and `pbcopy` that works; a clipboard manager may keep it in its history.
- **`lst import <stack> [--exclude VAR]… [--dry-run]`** brings a running stack's existing values under `lst` (see [`docs/migration.md`](docs/migration.md)). It reads the stack directory's `.env` (compose's interpolation file) and every file an `env_file:` names, stores the values encrypted in `.sec/` as manual secrets (name: the variable name in lowercase, `DB_PASSWORD` → `web/db_password`), and rewrites the stack's compose file: `${VAR}` (also `$VAR`, `${VAR:-…}`, `${VAR:?…}`) becomes `<<secret:var>>`, and an `env_file:` becomes an `environment:` block of `<<secret:…>>` entries (or is added to the service's block-style `environment:`). Every rewrite is kept only if compose would read exactly the same values afterwards (checked by rendering, parsing and interpolating in memory); one that isn't is left as it was and reported, an `env_file:` with the entries to write by hand. The imported lines are then removed from the env files, and a file left with nothing but blank and comment lines is deleted. `--exclude VAR` leaves a variable where it is; `--dry-run` writes nothing. It refuses a name that is a generated secret or stored with a different value, two variables that would share a name, and an env-file line that isn't `KEY=VALUE`. Values it can't reproduce exactly (with `$`, escapes or several lines) are skipped with the reason. It never prints a value, needs the seed, and warns about env files that are tracked or not gitignored. Unlike `<<set:…>>` it writes no value into a Git blob. Running it again finishes what's left.
- **`lst gc [--remove [NAME…]]`** deals with orphans (entries no marker uses any more, which `lst sync` and the hook mark but never delete):
  - `lst gc` lists them on stdout, one bare full name per line, sorted (`web/old`, `shared/x`), so the list can be piped into `lst gc --remove`. It is read-only; with no orphans stdout stays empty and stderr says so.
  - `lst gc --remove` deletes every orphan from `.sec/`; `lst gc --remove NAME…` only the named ones. Each name must be an orphan, otherwise nothing is removed. Commit `.sec/` afterwards.
  - It refuses while the orphan flags in `.sec/` aren't current for the working tree (a marker removed, or one that came back, since the last sync): run `lst sync` first. Otherwise it could delete a name that is in use again.
  - It needs the seed, like `lst sync` and `lst rename` (so not in a seedless CI step).
  - A removed value isn't gone: its id or ciphertext stays in git history, so with the seed the old value can still be derived or decrypted from there. A removed generated name whose marker comes back gets a new id, so a **new** value: only remove orphans no app still needs (a database may still hold the old password).
- **`lst stacks-dir [DIR]`** shows the stacks directory (stdout), or sets it. A stack is a directory directly in it with a compose file. The default is `stacks`; `apps` or `deploy/stacks` work, and `.` makes the repository root the stacks directory (a flat repo: `./web/docker-compose.yml`). The setting lives in `.sec/meta.toml` as `stacks_dir` (written only when it isn't the default), so the hook, CI and every machine agree on it; commit it together with the moved directories. It needs no seed. It refuses paths that leave the repository or go through a dot-directory, and refuses a directory where discovery would fail (a stack directory with an invalid name, say). In a flat repo, top-level directories without a compose file (`docs/`, `scripts/`) are just directories, but the usual rules still apply at the top level: a `<<set:` in a file that belongs to no stack blocks the commit, and a symlink directly in the repository root is an error (git stores it as a link, so lst can't tell whether it hides a stack).
- **`lst render <stack>`** prints the resolved compose file to stdout and nothing else; diagnostics go to stderr. It is read-only: a name that isn't in `.sec/` yet fails with a hint to run `lst sync`. Every unresolvable secret is listed in one go.
- **Stacks with `x-deploy`** (a line starting with `x-deploy:` in the compose file) are rendered through YAML instead of as raw text: markers are substituted inside the parsed strings (so values are quoted correctly, whatever they contain), `x-deploy` is removed, merge keys (`<<: *anchor`) are applied, and every service with rendered inputs gets an `lst.render-hash` label. Comments and formatting are not kept. Stacks without it render byte for byte as before. `lst render <stack> --file <from>` prints one rendered `render:` file instead (`from` as written in `x-deploy`); `lst render` never writes the `to:` files.
  - `render: [{from, to, mode}]`: `from` is relative to `stacks/<stack>/` and must be a file `lst sync` reads (not gitignored, not a symlink, UTF-8); `to` is an absolute path without `..`; `mode` is a quoted octal string, default `"0600"`, at most `"0777"`.
  - `pre: [{with, run, when}]` / `post: [{exec, run, when}]`: `with`/`exec` name a service of the stack; `run` is a string (`sh -c`) or a list (exec form, no shell); `when` is `always` (default) or `on-change`. Markers are rendered in `run` only.
  - A service gets the label if it bind-mounts a rendered `to:` file or a parent directory of it (absolute host paths; short `/host:/ctr[:ro]` or long `type: bind` syntax; named volumes, relative paths and paths with `$VAR` don't count), or if a step targets it. The hash is keyed with the seed, so it reveals nothing. Don't set `lst.render-hash` yourself.
  - Unknown keys and every rule above are errors; YAML errors show only line and column (the parser's message could quote a secret). `lst check` reports them too, also without a seed.
  - Write markers literally: a marker that only appears through YAML escapes (`"\x3c<gen:a>>"`) isn't seen by `lst sync`.
- **`lst check`** lists every problem at once and exits 1 if there is any (read-only):
  - `.sec/` is current for the working tree (what `lst sync` would change: new or orphaned names, a stale format);
  - no file committed in `HEAD` contains `<<set:` (it is in the history: rotate the secret), and no `<<set:` waits in the working tree;
  - every `<<secret:…>>` has a value;
  - with the seed (`.env` or `LST_SEED`) also: it is the seed of `.sec/`, and every marker resolves (every stored value decrypts). Without a seed it stops after the structural checks and says so, which is what a pull-request pipeline wants.
- **`lst deploy <stack>…`** deploys stacks through `docker compose`. It needs the seed, runs the full `lst check` first and deploys nothing if that finds a problem, and checks every stack name up front (it must exist and be a valid compose project name, `[a-z0-9][a-z0-9_-]*`: `MyApp` is an error, never lowercased). Then, per stack in sorted order, it renders the stack's compose file (the same bytes `lst render` prints) and pipes it into `docker compose -p <stack> --project-directory stacks/<stack> -f - up -d --wait --remove-orphans` (the stack's directory under the stacks directory), run in the repository root. The first failure stops it, and the message names the stacks already deployed and the ones not attempted. It prints `lst: deployed <stack>` per stack on stderr (compose's output goes to stderr too) and nothing on stdout. The rendered compose file only goes through the pipe, and `LST_SEED` is not passed on to compose. A stack with `x-deploy` also gets its `render:` files written and its `pre`/`post` steps run around `up` (see [Deploy steps](#deploy-steps-x-deploy)); the only files lst writes are those `to:` targets. A stack without `x-deploy` gets exactly the one `docker compose up`.
- **`lst deploy --changed-since REV`** deploys the stacks affected by the commits `REV..HEAD` instead of a list (one or the other, not both):
  - a change under `stacks/<s>/` or in `.sec/<s>.toml` deploys `<s>`;
  - a changed entry in `.sec/shared.toml` deploys the stacks that use that shared name (an entry that only became orphaned deploys nothing);
  - a change in `.sec/meta.toml` deploys every stack;
  - anything else (README, CI config) deploys nothing. A stack that changed but no longer exists is reported, not taken down (run `docker compose -p <s> down` yourself). Nothing affected prints `nothing to deploy` and exits 0.
  - An unknown `REV` is an error that hints at shallow clones: fetch more history, or deploy the stacks explicitly.
- **`lst deploy --all`** deploys every stack (every `stacks/<s>/` with a compose file), in sorted order. It can't be combined with stack names or `--changed-since`. No stacks prints `nothing to deploy`.
- **`lst deploy --dry-run`** (with any of the three forms) goes as far as a deploy can without changing anything: it needs the seed, runs the full check, picks and renders the stacks (so every error a deploy would meet before running docker shows up) and compares each `render:` file with its target. It then prints the plan on stderr, per stack in deploy order: `would write <to>`, `would fix the mode of <to>` (nothing for a file that is up to date), `would run x-deploy.pre[0] (<service>)`, `would run docker compose -p <stack> … up -d --wait --remove-orphans`, the `post` steps, and `dry run: would deploy <stack>`. It never runs docker and never writes a file, and it never shows a secret value or a step's command (both contain secrets). Since it doesn't ask docker for the existing containers' `lst.render-hash`, it can't tell whether an `on-change` step would be skipped; such steps are listed as conditional. It compares `render:` targets on the machine it runs on, so run it where the deploy runs.
- **`LST_SEED`** (for CI): if this environment variable is set, lst takes the seed from it (the same 64 lowercase hex characters) and never writes it anywhere; `.env` doesn't have to exist. If `.env` also holds a seed, they must match. On your own machines keep the seed in `.env`; the variable is for pipelines, where the seed comes from a CI secret. `lst init` refuses to run while it is set. The `.env` gitignore check still applies.
- **CI:** [`docs/ci.md`](docs/ci.md) sets up the example Woodpecker pipeline ([`docs/examples/woodpecker.yml`](docs/examples/woodpecker.yml)): on each push to the default branch it runs `lst check` and `lst deploy --changed-since <previous commit>` with the Docker socket mounted, and a structural `lst check` (no seed) on pull requests.
- Marker errors point at the spot: `stacks/web/compose.yaml:3:17: …`.
- Exit codes: `0` ok, `1` error, `2` usage error.

**Second machine:** clone the repo, create `.env` with the line `LST_SEED=<the 64 hex characters from your password manager>`, and run `lst hook install` (a clone doesn't bring hooks along). `lst init` works too: there it confirms the seed matches `.sec/meta.toml` and installs the hook. A wrong seed fails loudly, because `.sec/meta.toml` holds its fingerprint.

**Quoting manual secrets in YAML** (stacks without `x-deploy`; with it, the serializer quotes values for you): `render` substitutes raw text, with no YAML quoting or escaping (it renders non-YAML files too). Generated formats are always safe as plain YAML scalars. A manual secret (`<<secret:name>>`) that might contain `"`, `#`, `: ` or a newline must sit in a suitably quoted scalar. This is up to you; `lst` doesn't check it. (`$` is handled for you on both paths: Compose interpolates `$VAR` and `${VAR}` in the file it reads, so `lst` writes every `$` of a substituted value as `$$`, which Compose turns back into `$`. `$` you write yourself around a marker is left alone, and `render:` files and `run:` commands get the value unescaped, since Compose doesn't read them.) A block scalar takes any single-line value as-is:

```yaml
environment:
  SMTP_PASSWORD: |-
    <<secret:smtp>>
```

A single-quoted scalar (`TOKEN: '<<secret:cf>>'`) works if the value can't contain `'`. A value with newlines only stays valid YAML if every line after the first is indented like the marker, which raw substitution doesn't do, so keep multi-line secrets out of compose YAML (or in a non-YAML file).

**Repo layout:**

```
stacks/<stack>/compose.yaml  # or compose.yml, docker-compose.yaml, docker-compose.yml
stacks/<stack>/config/…      # optional template files with markers
.sec/                        # managed by lst, committed
.env                         # managed by lst, gitignored
```

`stacks/` is the default stacks directory: `lst stacks-dir apps` (or `.` for a flat repo with `./<stack>/compose.yaml`) puts it elsewhere. A single compose file at the repository root (the whole repo is one stack) and stacks nested deeper than one level are not supported.

A stack's compose file may use any of Docker's four names. If a stack has more than one, lst uses the first in Docker's order (`compose.yaml`, `compose.yml`, `docker-compose.yaml`, `docker-compose.yml`), the same one `docker compose` reads, and warns about the others. Markers in the ignored files are still processed, so a `<<set:…>>` in one never gets committed.

## Security model

`lst` assumes that anyone who can read `.env` on the server can already read every secret with `docker inspect`. It protects **Git**, not a compromised host:

- secrets never enter the repository or its history in plaintext;
- the seed lives only in `.env` (gitignored) and in your password manager.

**If you lose the seed**, generated secrets can't be recovered, so you'd have to reset them in each app. Back it up.

## Roadmap

- [x] M0: core library (marker parser, derivation, formats, encryption, frozen test vectors)
- [x] M1: `init` + `render` (+ `sync`)
- [x] M2: pre-commit hook
- [x] M3: `deploy` + `check` + CI (example pipeline in `docs/examples/woodpecker.yml`; first real Gitea/Woodpecker run still to be confirmed)
- [x] M4: `x-deploy`
- [x] M5: `rotate`, `gc`, `--all`, `--dry-run`
- [x] M6: migration (`lst import`, [`docs/migration.md`](docs/migration.md))

## License

MIT
