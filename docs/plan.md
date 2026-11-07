# Lazy Secret Tool (`lst`) — implementation plan

_Created 2026-11-06. Companion to `claude/secrets-tool-design.md` (the design is the source of truth; this is how to build it)._

## Principles
- **Usable early:** after M1 you can already render a stack by hand. Every milestone after that removes a manual step.
- **Shell out, don't reimplement:** call `git` and `docker compose` as subprocesses instead of using libgit2 or the Docker API. That means fewer dependencies, and behaviour matches what you'd type yourself.
- **Freeze the crypto first:** derivation test vectors are written in M0 and never change. They're the guarantee that a future refactor can't silently change every password.

## Crate layout
Single binary crate, split into modules (a workspace is overkill for now):

```
lst/
├─ src/
│  ├─ main.rs        CLI (clap)
│  ├─ marker.rs      lexer/parser for <<gen|secret|set:…>> incl. \ escapes, with byte spans
│  ├─ crypto.rs      seed, BLAKE3 derive_key contexts, XChaCha20-Poly1305, fingerprint
│  ├─ format.rs      alnum32 / hexN / base64-N / uuid from the XOF stream (rejection sampling)
│  ├─ store.rs       .sec/ read/write (minimal diffs, only re-encrypt changed values)
│  ├─ render.rs      substitute markers in raw text; strip x-deploy; inject lst.render-hash labels
│  ├─ deploy.rs      x-deploy model (render/pre/post/when), docker compose invocation
│  ├─ git.rs         staged-file reading, index rewriting, gitignore checks
│  └─ stack.rs       stack discovery (stacks/<name>/compose.yaml)
└─ tests/
   ├─ vectors.rs     frozen derivation test vectors
   └─ e2e/           throwaway git repo + fake stacks
```

## Dependencies (initial)
- `clap` (CLI), `blake3`, `chacha20poly1305`, `getrandom` (OS random generator for the seed and ids)
- `toml` + `serde` for `.sec/` files
- A YAML crate for `x-deploy`, `volumes:` and label injection. `serde_yaml` is archived; pick a maintained fork or alternative (e.g. `serde_yaml_ng`, `saphyr`) when starting M4. Markers themselves never need YAML parsing.
- `rpassword` is not needed (manual secrets arrive via `<<set:…>>`).
- Dev: `proptest` for the marker parser, `tempfile` for end-to-end repos.

## `.sec/` on-disk format
- `.sec/meta.toml`: format version + seed fingerprint.
- `.sec/<stack>.toml` (+ `.sec/shared.toml`): one file per stack keeps diffs small and avoids merge conflicts.
  ```toml
  [gen.db]
  id = "7f3a9c…"
  format = "alnum32"
  orphan = false

  [secret.cloudflare]
  nonce = "…"
  ciphertext = "…"
  ```
- Stable key ordering and stable formatting, so the same state always produces byte-identical files.

## CLI surface (end state)
| Command | Does |
|---|---|
| `lst init` | Create seed → `.env`, ensure `.env` is gitignored, write `.sec/meta.toml`, install the hook |
| `lst sync` | Update `.sec/` from the compose files (new ids, orphans); the hook runs the same logic on staged content |
| `lst render <stack>` | Resolved compose to stdout |
| `lst deploy <stack>` / `--all` | Checks → render files → pre → `compose up --wait` → post |
| `lst check` | Is `.sec/` current, no committed `<<set:`, all secrets resolvable? (used by CI and deploy) |
| `lst hook install` / `lst hook run` | Install / run the pre-commit logic |
| `lst rename <stack>/<old> <new>` | Rename keeping the value (`--replace` if the target exists) |
| `lst rotate <stack>/<name>` | New id → new value |
| `lst gc` | List or remove orphans (explicit) |

## Milestones

### M0 — Core library (no I/O)
- Marker parser: the three marker kinds, optional format, `\\` and `\>` escapes, unescaped `>>` terminator, errors with positions.
- Formats + derivation + encryption.
- Tests: proptest round-trips (escape → parse = original), malformed-input cases, **frozen test vectors** for every format.
- _Done when:_ `cargo test` covers the parser and the vectors.

### M1 — `init` + `render` (first usable version)
- `lst init`: seed, `.env`, gitignore check/entry, fingerprint.
- `store.rs`: create `gen` entries for new names (random id), read/write `.sec/`.
- `lst sync`: update `.sec/` from the working-tree compose files (the M2 hook reuses this on staged content). `render` stays read-only.
- `lst render <stack>`: resolve `gen` and `secret`; fail on a missing seed, a fingerprint mismatch or an unset secret.
- _Done when:_ `lst render test | docker compose -p test --project-directory stacks/test -f - up -d` works for a test stack with a Postgres plus an app sharing `<<gen:db>>`.

### M2 — Pre-commit hook
- Read **staged** compose files (`git diff --cached --name-only`, `git show :path`).
- Update `.sec/` for new names; mark vanished names as orphans; print rename hints.
- Process `<<set:name:VALUE>>`: encrypt → store → rewrite to `<<secret:name>>` in **both** the index (`git hash-object -w` + `git update-index --cacheinfo`, which preserves partial staging) and the working tree.
- Block the commit on unset `<<secret:…>>` and on malformed markers.
- `git add .sec/`, then exit 0 silently when nothing changed.
- `lst rename <stack>/<old> <new> [--replace]` (keeps the id / re-seals), printed as a hint for one-out-one-in changes.
- `lst sync` scans every file under `stacks/<stack>/` (same scope as the hook); `lst init` installs the hook.
- _Done when:_ e2e tests cover new gen names, a `set` round-trip, partial staging, and the block cases.

### M3 — `deploy` + `check` + Woodpecker
- `lst check`: `.sec/` matches the compose files; no `<<set:` in the tree (with a "rotate this secret" message); all secrets resolvable.
- `lst deploy <stack>`: check → render → pipe into `docker compose … -f - up -d --wait`.
- Woodpecker pipeline: on push, run `lst deploy` for the changed stacks.
- _Done when:_ a push to Gitea deploys the pilot stack with no manual steps. **Dockge can start being retired here.**

### M4 — `x-deploy`
- Parse `x-deploy` (`render`, `pre`, `post`, `when`), strip it from the output.
- Render extra files to their `to:` paths.
- Compute `lst.render-hash` per service (from rendered inputs) and inject it as a label; find affected services via `volumes:`.
- `pre` via `docker compose run --rm --no-deps <service> <cmd>`; `post` via `docker compose exec <service> <cmd>` after `--wait`.
- `when: on-change`: compare the running container's label with the new hash.
- YAML crate: `serde_yaml_ng`. Details (model, keyed render hash, `run:` forms, file modes, CI mounts) in design.md "x-deploy details".
- _Done when:_ Mosquitto (password file via `pre`) and a shared Mongo/Postgres user setup (via `post`) deploy correctly and only restart when inputs change.

### M5 — Lifecycle polish
- `lst rotate`, `lst gc`, `lst deploy --all`, good error messages, `--dry-run` for deploy.

## Migration order (pilot → core)
1. **Throwaway test stack** (Postgres + whoami/adminer): M1–M3.
2. **Linkding** (playground, low stakes).
3. **Mosquitto + Zigbee2MQTT + AppDaemon** (`shared/` names and a `pre` hasher, M4).
4. Rest of the playground stacks.
5. **Core last:** Traefik, Authelia, Vaultwarden. Only after the restore path is tested: wipe a clone, restore the seed from Vaultwarden, deploy, and confirm it works.

## Out of scope for now
- rsync / multi-host targets (the render-to-file path exists in the design; build it when needed).
- Watching for changes or a daemon mode. `lst` is a run-and-exit CLI.
- Any UI.
