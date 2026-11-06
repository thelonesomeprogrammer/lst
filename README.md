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
| `lst render <stack>` | Print the resolved compose file to stdout |
| `lst deploy <stack>` / `--all` | Check → render files → `pre` → `compose up --wait` → `post` |
| `lst check` | Verify `.sec/` is current, no `<<set:` committed, all secrets resolvable |
| `lst hook install` / `run` | Install / run the pre-commit logic |
| `lst rotate <stack>/<name>` | Give a generated secret a new value |
| `lst gc` | List or remove orphaned secrets |

## Setup

```sh
lst init                     # on the first machine
# save the seed from .env in your password manager (this is also your backup)
# on each other machine: clone, put the seed in .env, run `lst hook install`
```

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
- [ ] M1: `init` + `render`
- [ ] M2: pre-commit hook
- [ ] M3: `deploy` + `check` + CI
- [ ] M4: `x-deploy`
- [ ] M5: `rotate`, `gc`, `--all`, `--dry-run`

## License

MIT
