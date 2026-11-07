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
x-deploy:
  render:
    - from: config/mosquitto.conf
      to: /mnt/appdata/mosquitto/config/mosquitto.conf
  pre:                              # one-off container from the service's image
    - with: mosquitto
      run: mosquitto_passwd -b -c /mosquitto/config/passwd z2m <<gen:shared/mqtt-z2m>>
  post:                             # inside the running, healthy service
    - exec: mongo
      run: mongosh --eval '…createUser("app1", "<<gen:mongo-app1>>")…'
      when: on-change               # default: always
```

When a service's rendered inputs change, `lst` changes a `lst.render-hash` label on it, so Compose recreates the container. No state file is needed.

## Commands

| Command | Does |
|---|---|
| `lst init` | Create the seed, gitignore `.env`, write `.sec/meta.toml`, install the hook |
| `lst sync` | Update `.sec/` from your compose files (the hook does this for you) |
| `lst render <stack>` | Print the resolved compose file to stdout (`--file FROM`: one rendered `x-deploy` file) |
| `lst rename <stack>/<old> <new>` | Rename a secret keeping its value (`--replace` if the new name exists) |
| `lst deploy <stack>…` / `--changed-since REV` | Check, then render and `compose up --wait` each stack (`x-deploy` steps: M4; `--all`: M5) |
| `lst check` | Verify `.sec/` is current, no `<<set:` committed, all secrets resolvable |
| `lst hook install` / `run` | Install / run the pre-commit logic |
| `lst rotate <stack>/<name>` | Give a generated secret a new value |
| `lst gc` | List or remove orphaned secrets |

## Setup

```sh
lst init                     # on the first machine (also installs the pre-commit hook)
# save the seed from .env in your password manager (this is also your backup)
# on each other machine: clone, put the seed in .env, run `lst hook install` (or `lst init`)
```

## Usage today (M3)

`rotate`, `gc` and `--all` don't exist yet, and `lst deploy` doesn't run `x-deploy` steps or write `render:` files yet (M4 in progress; `lst render` and `lst check` already handle `x-deploy`). What works now:

```sh
lst init                     # in the repo: seed → .env (mode 0600), /.env → .gitignore, .sec/meta.toml, pre-commit hook
git add .gitignore .sec && git commit -m "lst init"
# copy the LST_SEED=… line from .env into your password manager now

# edit compose files, then just commit: the hook updates .sec/ and stores <<set:…>> values
git add stacks && git commit

lst check                    # is everything consistent and resolvable?
lst deploy web               # check, render, docker compose up (or: lst render web | docker compose …)
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
    - a symlinked stack directory or `compose.yaml`;
    - unresolved merge conflicts;
    - a wrong or missing seed, or `.env` not being gitignored;
    - `lst` not being on `PATH`.
  - It is silent when there is nothing to report.
  - `git commit -a` works. `git commit <paths>` commits from a temporary index that git never copies back to your real index, so it only works when the hook has nothing to change. Otherwise it blocks and asks you to `git add` the files and run `git commit` without paths.
- **`lst hook install [--force]`** installs the hook where git looks for it (`git rev-parse --git-path hooks`, so `core.hooksPath` is respected). Run it once in every clone (`lst init` does it too). It never replaces a pre-commit hook that isn't lst's unless you pass `--force`.
- **`git commit --no-verify` skips the hook**, and with it the protection: a `<<set:…>>` committed that way is plaintext in your history. Don't. `lst check` and `lst deploy` refuse a committed `<<set:` and tell you to rotate the secret.
- **`lst sync`** does by hand what the hook does on commit (you rarely need it). It reads every file under `stacks/<stack>/` in the working tree that git would stage (not only `compose.yaml`). Gitignored files, such as bind-mounted data, are skipped; symlinks are skipped rather than followed; non-UTF-8 files are skipped unless they contain `<<set:`. A symlinked `stacks/`, a symlink directly in `stacks/` and a symlinked `compose.yaml` are errors (git commits a symlink as a link, so the hook couldn't see the stack). It updates `.sec/`: new generated names get a random id, names that are no longer used are marked as orphans (never deleted), and orphans that come back are reused with the same id (and so the same value). Commit `.sec/` afterwards (any commit does: the hook stages it). `<<set:…>>` is refused: commit the file instead, and the pre-commit hook stores the value. When one name disappears and one appears in the same stack, it prints the `lst rename` command that keeps the old value.
- **`lst rename <from> <to> [--replace]`** renames an entry in `.sec/` without changing its value: a generated secret keeps its id, a manual secret is re-encrypted under the new name. `<from>` is a full name (`web/db`, `shared/mqtt`); `<to>` is a full name too, or a name without `/` in the same stack (or `shared`). Moving between a stack and `shared/` works. If `<to>` already exists (typically because a sync or commit just gave it a fresh id) pass `--replace`. It does not edit your files: change the markers yourself.
- **`lst render <stack>`** prints the resolved compose file to stdout and nothing else; diagnostics go to stderr. It is read-only: a name that isn't in `.sec/` yet fails with a hint to run `lst sync`. Every unresolvable secret is listed in one go.
- **Stacks with `x-deploy`** (a line starting with `x-deploy:` in `compose.yaml`) are rendered through YAML instead of as raw text: markers are substituted inside the parsed strings (so values are quoted correctly, whatever they contain), `x-deploy` is removed, merge keys (`<<: *anchor`) are applied, and every service with rendered inputs gets an `lst.render-hash` label. Comments and formatting are not kept. Stacks without it render byte for byte as before. `lst render <stack> --file <from>` prints one rendered `render:` file instead (`from` as written in `x-deploy`); `lst render` never writes the `to:` files.
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
- **`lst deploy <stack>…`** deploys stacks through `docker compose`. It needs the seed, runs the full `lst check` first and deploys nothing if that finds a problem, and checks every stack name up front (it must exist and be a valid compose project name, `[a-z0-9][a-z0-9_-]*`: `MyApp` is an error, never lowercased). Then, per stack in sorted order, it renders `compose.yaml` (the same bytes `lst render` prints) and pipes it into `docker compose -p <stack> --project-directory stacks/<stack> -f - up -d --wait --remove-orphans`, run in the repository root. The first failure stops it, and the message names the stacks already deployed and the ones not attempted. It prints `lst: deployed <stack>` per stack on stderr (compose's output goes to stderr too) and nothing on stdout. It writes no file: the rendered text only goes through the pipe, and `LST_SEED` is not passed on to compose.
- **`lst deploy --changed-since REV`** deploys the stacks affected by the commits `REV..HEAD` instead of a list (one or the other, not both):
  - a change under `stacks/<s>/` or in `.sec/<s>.toml` deploys `<s>`;
  - a changed entry in `.sec/shared.toml` deploys the stacks that use that shared name (an entry that only became orphaned deploys nothing);
  - a change in `.sec/meta.toml` deploys every stack;
  - anything else (README, CI config) deploys nothing. A stack that changed but no longer exists is reported, not taken down (run `docker compose -p <s> down` yourself). Nothing affected prints `nothing to deploy` and exits 0.
  - An unknown `REV` is an error that hints at shallow clones: fetch more history, or deploy the stacks explicitly.
- **`LST_SEED`** (for CI): if this environment variable is set, lst takes the seed from it (the same 64 lowercase hex characters) and never writes it anywhere; `.env` doesn't have to exist. If `.env` also holds a seed, they must match. On your own machines keep the seed in `.env`; the variable is for pipelines, where the seed comes from a CI secret. `lst init` refuses to run while it is set. The `.env` gitignore check still applies.
- **CI:** [`docs/ci.md`](docs/ci.md) sets up the example Woodpecker pipeline ([`docs/examples/woodpecker.yml`](docs/examples/woodpecker.yml)): on each push to the default branch it runs `lst check` and `lst deploy --changed-since <previous commit>` with the Docker socket mounted, and a structural `lst check` (no seed) on pull requests.
- Marker errors point at the spot: `stacks/web/compose.yaml:3:17: …`.
- Exit codes: `0` ok, `1` error, `2` usage error.

**Second machine:** clone the repo, create `.env` with the line `LST_SEED=<the 64 hex characters from your password manager>`, and run `lst hook install` (a clone doesn't bring hooks along). `lst init` works too: there it confirms the seed matches `.sec/meta.toml` and installs the hook. A wrong seed fails loudly, because `.sec/meta.toml` holds its fingerprint.

**Quoting manual secrets in YAML** (stacks without `x-deploy`; with it, the serializer quotes values for you): `render` substitutes raw text, with no YAML quoting or escaping (it renders non-YAML files too). Generated formats are always safe as plain YAML scalars. A manual secret (`<<secret:name>>`) that might contain `"`, `#`, `: ` or a newline must sit in a suitably quoted scalar. This is up to you; `lst` doesn't check it. A block scalar takes any single-line value as-is:

```yaml
environment:
  SMTP_PASSWORD: |-
    <<secret:smtp>>
```

A single-quoted scalar (`TOKEN: '<<secret:cf>>'`) works if the value can't contain `'`. A value with newlines only stays valid YAML if every line after the first is indented like the marker, which raw substitution doesn't do, so keep multi-line secrets out of compose YAML (or in a non-YAML file).

**Repo layout:**

```
stacks/<stack>/compose.yaml
stacks/<stack>/config/…      # optional template files with markers
.sec/                        # managed by lst, committed
.env                         # managed by lst, gitignored
```

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
- [ ] M4: `x-deploy`
- [ ] M5: `rotate`, `gc`, `--all`, `--dry-run`

## License

MIT
