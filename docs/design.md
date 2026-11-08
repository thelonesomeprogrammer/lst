# Lazy Secret Tool (`lst`) — design notes

_Started 2026-11-06. Own tool, written in Rust. Status: M0–M5 implemented. Binary name: `lst`._

## Requirements (tlp)
1. tlp is never the source of randomness.
2. Write compose config without thinking about secrets.
3. State between machines (desktop, server) is shared exactly once.
4. tlp writes no files beyond what he'd normally write (compose files). Tool-written files are fine.

## Core design
- **Markers in compose:**
  - `<<gen:name>>` for generated secrets, with an optional format: `<<gen:name:hex64>>` (default `alnum32`).
  - `<<secret:name>>` for manual/external secrets that are already stored.
  - `<<set:name:VALUE>>` to enter or replace a manual secret inline (see Manual secrets).
  - Names are scoped per stack; `shared/...` names work across stacks (e.g. MQTT credentials).
  - Markers must work inside strings (DSNs, URLs).
  - Markers are parsed on the **raw file text**, not after YAML parsing, so they work the same in compose and non-YAML config files.
- **Master seed:** created by `init` from the OS random generator and stored in `.env`, which the tool writes and which is gitignored.
  - Rationale: anyone who can read `.env` on the server can already `docker inspect` every secret.
  - The seed also derives the encryption key for `.sec/`, so no age or other key management is needed.
- **`.sec/` intermediate (program-written, committed):**
  - name (plaintext) → random `id` + format. Secret = KDF(seed, id).
  - Renaming = change the name in compose and `.sec/`; the id is kept, so the value is unchanged.
  - Rotation = new id for a name.
  - Seed fingerprint (hash), so a wrong or missing seed fails loudly.
  - Manual secrets, encrypted.
  - Does NOT store derived values (they'd be a second source of truth).
- **Sharing state once:** copy the seed to the second machine through a Vaultwarden entry; that entry also serves as the disaster-recovery backup.

## Crypto (decided 2026-11-06)
- **Derivation: BLAKE3 in `derive_key` mode** (Rust `blake3` crate).
  - Generated secret: `derive_key(context = "lst v1 gen", key_material = seed || id)`. Use the XOF output stream for whatever length the format needs.
  - `.sec/` encryption key: `derive_key(context = "lst v1 sec-encryption", seed)`.
  - Seed fingerprint: `derive_key(context = "lst v1 fingerprint", seed)`, truncated to 16 bytes, hex.
  - Context strings are **frozen forever** from the first real use; changing one changes every secret. They are pinned to `lst v1` and don't follow the tool's name if it's renamed later. The `v1` is the escape hatch for a future scheme.
- **Encryption of manual secrets: XChaCha20-Poly1305** (Rust `chacha20poly1305` crate), random 24-byte nonce per value.
  - A random nonce means a new ciphertext on every write, so the tool must only rewrite entries whose value actually changed (keeps Git diffs quiet).
- Why these: BLAKE3 is fast, modern, has native key-derivation and variable-length output, and is pure Rust. HKDF-SHA256 would be the more conservative choice if audit-friendliness ever matters more.

### Frozen encoding details (decided 2026-11-06, raised by Claude Code during M0)
- **Generated-secret id:** 16 random bytes (128 bits) from `getrandom`, created when a name is first seen. Stored in `.sec/` as 32 lowercase hex characters.
- **`seed || id`:** the 32 raw seed bytes followed by the 16 raw id bytes, 48 bytes total. Raw bytes, not the hex string, so the input always has a fixed length.
  - Stack, name and format are deliberately **not** part of the derivation input; renaming and sharing depend on the id alone. (The format still changes the value, because it changes how the stream is encoded.)
- **Associated data (AEAD) for manual secrets:** each ciphertext is bound to its name. AD = `"lst v1 secret\0"` + full name (`stack/name` or `shared/name`), UTF-8. Names can't contain `\0`.
  - This stops a bad merge or hand edit from moving one secret's ciphertext under another name; decryption fails loudly instead.
  - Cost: renaming a manual secret means decrypting and re-encrypting it, which `lst` does automatically (it owns `.sec/` and has the seed).
- **Formats; N counts output characters:**
  - `alnumN` (default `alnum32`): characters from `[A-Za-z0-9]`, by rejection sampling on the XOF stream (to avoid bias).
  - `hexN`: take ⌈N/2⌉ bytes from the start of the stream, lowercase hex, truncate to N characters. `hex64` = 64 characters.
  - `base64-N`: take ⌈3N/4⌉ bytes, URL-safe unpadded base64, truncate to N characters. `base64-32` = 32 characters.
  - `uuid`: v4 layout from the first 16 bytes of the stream.
  - Minimum of at least 128 bits of randomness: hex N ≥ 32, base64 N ≥ 22, alnum N ≥ 22; otherwise an error. Maximum N = 256.
  - Bytes are always consumed from the start of the XOF stream, in order.

### On-disk formats and M1 behaviour (decided 2026-11-06, raised by Claude Code before M1)
- **`.env`:** the seed is one line `LST_SEED=<64 lowercase hex chars>`. Other lines in `.env` are preserved untouched. Uppercase hex, wrong length or a duplicate `LST_SEED` line is an error.
- **`.sec/` encoding:** nonces and ciphertexts are lowercase hex, like ids.
- **`lst sync`:** updates `.sec/` from the compose files (in M1: the working tree). It creates ids for new gen names, marks vanished names as orphans and un-orphans names that come back. The M2 pre-commit hook runs the same logic on staged content.
- **`lst render` is read-only:** it never writes `.sec/`. A gen name with no entry fails with a hint to run `lst sync`.
- **Substitution is raw text.** `render` doesn't quote or escape for YAML (it also renders non-YAML files). Generated formats are always YAML-safe as plain scalars. A marker for a manual secret that may contain `"`, `#`, `: ` or newlines must sit in a suitably quoted YAML scalar; this is documented for users, not enforced.

### Pre-commit hook (decided 2026-11-06, before M2)
- **Finding lst:** the hook script runs `lst hook run` from PATH. If `lst` isn't on PATH the commit is **blocked**, never skipped. `lst init` installs the hook (also when already initialised); other machines run `lst hook install`. A foreign pre-commit hook is never overwritten without `--force`. Installed into `git rev-parse --git-path hooks` (respects `core.hooksPath`).
- **Source of truth is the index:** the hook reads every staged file under `stacks/<stack>/` (not only changed ones) so orphan marking stays correct; `GIT_INDEX_FILE` is honoured (`git commit -a`, partial staging).
- **Scan scope:** every staged file under `stacks/<stack>/` carries markers (set processing, gen sync, orphans). `lst sync` uses the same scope in the working tree; `render` still renders only `compose.yaml` until M4. A `<<set:` anywhere else (outside `stacks/`, or in a non-UTF-8 file) blocks the commit.
- **Leftover plaintext blob:** `git add` of a file with `<<set:…>>` already wrote the plaintext as a blob in `.git/objects`. The hook keeps it out of every commit, but the dangling blob stays locally until `git gc` prunes it. Accepted (local only, never pushed, same trust level as `.env`); documented, and the hook prints a `git gc --prune=now` hint after processing a set.
- **Working-tree rewrite:** only the identical `<<set:name:VALUE>>` text is replaced by `<<secret:name>>`; if the working tree no longer holds that exact marker, it's left alone with a warning (the next commit processes it). Partial staging is preserved.
- **`git commit <paths>`** (temporary index): git builds the commit from a temporary index and never copies the hook's changes back to the real index, so the real index would keep the plaintext and a stale `.sec/`. The hook therefore passes such commits only when it has nothing to change (no `<<set:`, `.sec/` already current) and otherwise blocks with a hint to `git add` and commit without paths. `git commit -a` works normally. (Found during M2.)
- **Symlinks** (same rule for sync and the hook, because git stores a symlink as a link): symlinks *inside* a stack are skipped; a symlinked `stacks/`, a symlink directly in `stacks/` or a symlinked `compose.yaml` is an error. `lst sync` only reads files git would stage (tracked + untracked-not-ignored), so bind-mounted data dirs are never read.
- **Strict index:** a staged `compose.yaml` under an invalid or reserved stack name is an error; a non-UTF-8 path anywhere in the index blocks every commit (fail closed).
- **Renames:** `lst rename <stack>/<old> <new>` moves a gen entry keeping its id (value unchanged) or re-encrypts a manual secret under the new name. An existing target needs `--replace` (the common case: the commit already gave the new name a fresh id). When one name disappears and one appears in the same stack, the hook prints the exact command.

### check, deploy and CI (decided 2026-11-07, before M3)
- **Seed in CI:** if the `LST_SEED` environment variable is set, lst uses it (same 64-lowercase-hex rules) and never writes it to disk. If `.env` also holds a seed, both must match. The `.env` ignore guard still runs whenever `.env` is read. `lst init` refuses to run while `LST_SEED` is set (init manages `.env`).
- **`lst check`** lists every problem at once: `.sec/` is current for the working tree (a dry-run sync changes nothing); no `<<set:` in any blob of the `HEAD` tree (it's in history: rotate the secret); every `<<secret:…>>` has an entry. Without a seed it stops there (structural, e.g. for PR pipelines); with a seed it also checks the fingerprint and that every marker resolves (every ciphertext decrypts).
- **`lst deploy <stack>…`** runs the full check once, then per stack (sorted): render `compose.yaml` and pipe it into `docker compose -p <stack> --project-directory stacks/<stack> -f - up -d --wait --remove-orphans`. Stops at the first failure and says which stacks were deployed. A stack name that isn't a valid compose project name (`[a-z0-9][a-z0-9_-]*`) is an error, not silently lowercased.
- **`lst deploy --changed-since REV`** deploys the stacks affected by `REV..HEAD`: any change under `stacks/<s>/` or in `.sec/<s>.toml`; a change in `.sec/shared.toml` affects only the stacks using a shared name whose entry changed; a change in `.sec/meta.toml` affects every stack. Deleted stacks are reported, not torn down. Can't be combined with explicit stacks.
- **Woodpecker:** the example pipeline (`docs/examples/woodpecker.yml`) builds lst with `cargo install --locked --git … --tag …` (cached) and deploys with the Docker socket mounted (trusted repo), `LST_SEED` from a Woodpecker secret. Publishing a prebuilt image is left for later.

### x-deploy details (decided 2026-11-07, before M4)
- **YAML crate:** `serde_yaml_ng` (maintained serde_yaml fork). Only stacks whose `compose.yaml` has a top-level `x-deploy` key go through YAML; other stacks keep the raw-text rendering of M1–M3 byte for byte.
- **YAML path (stacks with `x-deploy`):** parse the *raw* (unrendered) compose text, so parse errors never contain secret values (report line/column only); substitute markers inside string scalars of the parsed document (the serializer then quotes values correctly, so manual secrets with `"`, `#` or `: ` are safe there); strip `x-deploy`; inject labels; serialize. Comments and formatting are not preserved in the output (compose doesn't need them).
- **Model:** `render: [{from, to, mode?}]` — `from` is relative to the stack dir and must stay inside it (it's already in sync/hook scope); `to` must be absolute (no `..`); `mode` is an octal string, default `"0600"`; ownership is not changed (use a `pre` step to `chown` if a container user needs it). Files are written atomically and only when their content changed. `pre: [{with, run, when?}]`, `post: [{exec, run, when?}]`; `with`/`exec` must name a service of the stack; `when` is `always` (default) or `on-change`. Unknown keys are errors.
- **`run:`** a string runs as `sh -c <string>` in the container; a list runs as exec form (no shell, for images without one). Markers in commands are rendered (visible in `ps` briefly; accepted).
- **Commands:** `pre` = `docker compose … -f - run --rm --no-deps -T <service> …` before `up`; `post` = `docker compose … -f - exec -T <service> …` after `up --wait`. A failing `pre` aborts before `up`; a failing `post` fails the deploy (stack is up).
- **Entrypoint (decided 2026-11-07 by tlp):** lst never overrides the image's ENTRYPOINT. `post` steps use `exec` into the running container (entrypoint irrelevant), which covers most cases; `pre` steps run through the image's entrypoint, so they work with images whose entrypoint script runs the given command (mosquitto, postgres, …) but not with a binary entrypoint. Documented as a limitation; no `--entrypoint` option.
- **`lst.render-hash`:** keyed BLAKE3 with key `derive_key("lst v1 render-hash", seed)` (FROZEN context string; it reveals nothing without the seed) over a canonical encoding of the service's inputs: every rendered `to:` file the service mounts (bind-mount source equal to the file or a parent directory, short or long volume syntax), plus the rendered `run` commands of the `pre`/`post` steps targeting that service. Injected as a label only on services that have such inputs; when it changes, compose recreates the container.
- **`when: on-change`:** compare the label on the service's existing container (read before `up`) with the new hash; no container counts as changed.
- **Deploy order:** check → render compose + files → write changed files → `pre` → `up -d --wait --remove-orphans` → `post`.
- **`lst render <stack>`** prints the final compose (stripped, labelled) and never writes files; `lst render <stack> --file <from>` prints one rendered extra file.
- **CI:** lst writes `to:` files itself, so the deploy step must mount the target directories at the same paths (documented in `docs/ci.md`).
- **`$` in values (decided 2026-11-07 by tlp, found during M4):** compose interpolates `$` (`$VAR`, `${VAR}`) in every value of the file it reads and turns `$$` into a literal `$`. So every value lst substitutes into compose text (both render paths) has each `$` written as `$$`; text the user wrote around a marker is left alone (a hand-written `$$HOME` stays as it is). Values that don't pass through compose stay raw: `render:` files, `run:` commands (passed as arguments) and `lst render --file`. `lst render <stack>` shows the escaped form, exactly what compose reads. The render hash is computed from the raw files and commands, so it is unaffected.
- **Implementation choices (raised by Claude Code during M4, pending review by tlp):**
  - *Which path:* a line starting with `x-deploy:` (or a quoted key) selects the YAML path; other stacks are never YAML-parsed. If such a line exists but there is no top-level key, or the text parses with a top-level `x-deploy` that no line starts with (flow style), that is an error, so steps never silently don't run.
  - *Merge keys* (`<<: *a`) are applied before anything else, so merged `volumes:`/`labels:` count and an injected `labels:` never hides merged ones.
  - *Markers are substituted after YAML decoding*; sync and the hook read raw text, so a marker that only exists through a YAML escape isn't synced (documented: write markers literally). A marker in a service name is an error; `from`, `to`, `mode`, `with`, `exec`, `when` must not contain markers (they're used as written).
  - *Paths:* `.` and empty components are dropped from `from`/`to`; `..` is refused; `from` must be a file `lst sync` reads (not gitignored, not a symlink) and UTF-8. `mode` is 3–4 octal digits, `"0640"` or `640` quoted; an unquoted number is refused (ambiguous).
  - *Mounts:* bind sources that are relative, named, contain `$` or `..`, and top-level `volumes:` driver options are ignored.
  - *Hash inputs:* exactly the design's (mounted files' rendered contents by `to`, then the targeted steps' phase, `when` and rendered command); `mode` is not hashed. The byte layout is documented on `xdeploy::service_hash` and pinned in `tests/vectors.rs`.
  - *Errors:* every unresolved name of a stack (compose, commands, `render:` files) is reported in one list under the stack's `compose.yaml`; a user-set `lst.render-hash` label is an error on any service.
  - *Deploy wiring (part Z):* stacks are still rendered one at a time inside the deploy loop (as in M3), so "up front" checks of a stack (its steps' service names against compose's `[a-zA-Z0-9._-]+`) happen before anything runs *for that stack*, not before earlier stacks deploy. The `docker ps` hash reads go in sorted service order, once per service with an `on-change` step, before any file is written. An `on-change` step is skipped only if the existing label is present and equal to the new hash. Messages: `wrote <to>`, `fixed the mode of <to>` (M5; was `mode fixed <to>`), `skipped x-deploy.<phase>[i] (<service>): inputs unchanged`; a failing `pre` adds "so `docker compose up` did not run for this stack", a failing `post` "the stack is up …", both inside the usual deployed/failed/not-attempted summary.
  - *Found with real Docker (part Z):* Mosquitto 2.1's `mosquitto_passwd -c` refuses an existing file, so the `pre` example above fails from the second deploy on; it needs `rm -f <file> &&` first (README shows that). The 2.1 image's entrypoint also no longer chowns `/mosquitto`, so the root-created `0600` password file needs a `chown mosquitto:mosquitto` step. Compose interpolates `$` in every value of the file it reads, so a manual secret with `$` arrived changed; tlp decided to escape it (see "`$` in values" below).

### M5 lifecycle (decided 2026-11-08)
- **Decided 2026-11-08 by tlp:**
  - *`lst rotate <full name>`* only rotates a generated secret that is in use: a new random id, the same format (so a new value). A manual secret is refused with a hint to write `<<set:name:VALUE>>`; an orphan is refused (nothing uses it; the message points at `lst gc --remove`); a name with no entry hints at `lst sync`. It touches no other entry. Afterwards: commit `.sec/`, deploy the stacks that use the name. Apps that only read a value on first start (a database's initial password) keep the old one; documented, not handled.
  - *`lst gc`* lists the orphans (read-only); `lst gc --remove` deletes all of them from `.sec/`, `lst gc --remove NAME…` only the named ones. All-or-nothing: each name must exist and be an orphan, otherwise nothing is removed. A removed gen name whose marker comes back gets a new id.
  - *`lst deploy --dry-run` never invokes docker*, so it can't read the existing containers' `lst.render-hash`: `on-change` steps are reported as conditional, not as run or skipped.
  - *No teardown in M5:* a stack deleted under `--changed-since` stays reported, not torn down (`docker compose -p <s> down` by hand).
- **Implementation choices (raised by Claude Code during M5, pending review by tlp):**
  - *Stale-orphan guard:* `lst gc` (list and `--remove`) refuses while the orphan flags in `.sec/` aren't current for the working tree (a dry-run sync would orphan or un-orphan a name) and asks for `lst sync`. Otherwise it could delete a name whose marker came back since the last sync, and the next sync would give it a new value.
  - *Same guards as sync/rename:* `gc` and `rotate` need the seed and check its fingerprint (and the `.env` ignore guard), although neither derives anything. So `lst gc` doesn't run in a seedless CI step.
  - *Emptied stack file:* a `.sec/<stack>.toml` that loses its last entry (gc, as after `rename`) is kept, written as just the header.
  - *gc's output:* the list goes to stdout as bare full names, one per line, sorted, so it can be piped into `lst gc --remove`; "no orphans" and the `--remove` report go to stderr.
  - *Dry run:* runs everything a deploy runs before docker (seed, full check, target selection, rendering, step service names, the read-only comparison of each `render:` file with its target) and prints `would …` lines on stderr in deploy order. It is silent for `render:` files that are up to date, and never prints a value or a step's command, only `x-deploy.<phase>[i] (<service>)` and the compose arguments. A failure is reported with its own wording (stopped at stack X; nothing was run or written) instead of the deploy's deployed/failed/not-attempted summary.
  - *`--all`* deploys every existing stack, sorted, and is exclusive with explicit stacks and `--changed-since` (one target form per call).

### `lst get` (requested by tlp 2026-11-08; details pending review)
- **Why:** reading a secret back ("what's the Vaultwarden admin password?") otherwise means `lst render <stack> | grep`. It reveals nothing new: whoever has the seed can already render.
- **Implementation choices (Claude Code, pending review by tlp):**
  - *`lst get <full name>`* (`web/db`, `shared/mq`) prints the value plus a newline on stdout (`-n`: no newline). The raw value, as a `render:` file gets it, not the `$$`-escaped form `lst render <stack>` shows. stderr only ever gets the name.
  - *Same guards as rotate/gc:* the `.env` ignore guard, the seed and its fingerprint. Read-only; reads `.sec/` as it is (no check that it is current), so a marker not synced yet hints at `lst sync`.
  - *Orphans* are shown too (an app may still use the old value), with a note on stderr. A name with both a gen and a secret entry (its marker switched kind) shows the one in use; neither or both in use is refused as ambiguous.
  - *Unknown name:* the error lists the names in that `.sec/` file (names aren't secret).
  - *`--copy`* hands the value (no newline) to the first clipboard tool that works, on its stdin: `wl-copy`, `xclip -selection clipboard`, `xsel --clipboard --input`, `pbcopy`. No clipboard crate and no auto-clear; a clipboard manager may keep a history.

### `lst import` (decided 2026-11-08 by tlp)
- **Why:** migrating a running stack meant hand-writing `<<set:…>>` for every existing password. `lst import <stack>` reads the stack's `.env` (compose's interpolation file) and every `env_file:`, and turns the values into manual secrets.
- **Decided by tlp:**
  - *Seal directly:* import calls `Store::set_secret` itself (a second write path into `.sec/`, beside the hook's `<<set:…>>`), with the same guards as `rename`/`rotate` (`.env` ignore guard, seed, fingerprint). No value ever goes into a compose file or a Git blob.
  - *`env_file:` blocks:* replaced blindly, as text, by an `environment:` block; the result is checked with the parser, and a block that fails is printed (markers only) for the user to replace by hand, with a message that automatic replacement failed.
  - *Which variables:* all of them, minus `--exclude VAR`.
  - *Old lines:* the imported lines are removed from the env files.
- **Implementation choices (raised by Claude Code, pending review by tlp):**
  - *Name:* the variable name in lowercase, in the stack's scope (`DB_PASSWORD` → `web/db_password`). Refused, before anything is written: a name that isn't valid, two variables with one name, one variable with different values in two files, a name that exists as a gen entry, or as a secret with a different value (the same value is a no-op). A `<<set:` in `compose.yaml` is refused too (commit it first).
  - *Interpolation:* `$VAR`, `${VAR}`, `${VAR-…}`, `${VAR:-…}`, `${VAR?…}`, `${VAR:?…}` become `<<secret:var>>`; `${VAR+…}`/`${VAR:+…}` and `$$` are left alone. Only for variables of the stack's `.env` (lst deploys with `--project-directory stacks/<stack>`); shell variables and `--env-file` are out of scope.
  - *The check:* every edit (one `${…}` or one `env_file:` block) is kept only if the stack means the same to compose afterwards. Meaning = the text rendered in memory as lst would (raw path: `render_compose` then YAML; `x-deploy` path: YAML, then markers substituted in string scalars, `x-deploy` strings raw and not interpolated), merge keys applied, values interpolated with compose's rules, every readable `env_file:` merged into `environment` (normalised to a map; `environment` wins). Unknown values (shell variables, skipped values) are opaque tokens keyed by their text, the same on both sides. Edits are tried one at a time in text order, each with the ones already kept. The rendered values exist only in memory; YAML errors show line and column only.
  - *`env_file:` text:* the `env_file:` key line plus its deeper lines (or same-indent `- ` items). Without an `environment:` in the service it becomes `environment:` with `KEY: '<<secret:key>>'` entries (a `|-` block scalar if the value has `'`). With a block-style map or list `environment:`, the entries are appended to it (list: `- 'KEY=<<secret:key>>'`) and the `env_file:` removed; keys it already sets are not imported (they override the file anyway). A flow-style or empty `environment:`, an unknown service, or a file still holding a variable that isn't imported (excluded or skipped) makes the block manual. Entries of `env_file:` other than a path, a list of paths or `{path, required}` (e.g. `format:`), absolute paths, `..`, `$`, symlinks (also a symlinked directory on the way), non-UTF-8 and missing required files leave the block alone and import nothing from it.
  - *What is sealed:* a variable used by a kept edit, or by a printed manual block (so its markers resolve). One whose every `${…}` failed the check is not sealed.
  - *Env-file syntax (`dotenv.rs`):* `KEY=VALUE`, `export `, `'…'` literal, `"…"` with `\\`, `\"`, `\'`; unquoted values end at ` #`. A value compose would interpolate (`$` unquoted or double-quoted), other escapes and multi-line values are skipped with the reason (their lines stay); a line that isn't a definition is an error naming the line.
  - *Line removal:* a sealed variable's lines are removed from a file only if no `env_file:` still names that file and, for `.env`, no `${…}` still references the variable. A file left with only blank and comment lines is deleted. If any `env_file:` path can't be followed (`$`), no env file is edited.
  - *Order of writes:* `.sec/` first, then `compose.yaml`, then the env files, so an interrupted import leaves at most unused entries, and a second run finishes it.
  - *Output:* names, files and positions only, on stderr; `--dry-run` prints the same with "would". Warnings for env files that are tracked (rotate those values) or not gitignored.

## Manual secrets (decided 2026-11-06)
- **Enter or replace inline:** write `<<set:name:VALUE>>` in the compose file.
  - On commit, the pre-commit hook stores VALUE encrypted in `.sec/` and rewrites the marker to `<<secret:name>>` (strips `:VALUE`).
  - The rewrite happens in **both the staged content and the working tree**, so the plaintext never enters a commit and the file you see matches what's committed.
  - Writing `<<set:…>>` again for an existing name replaces the value.
  - This is the one case where the tool edits a user file, and it only removes the value.
- `<<secret:name>>` with no stored value: the hook blocks the commit and deploy fails, both with the hint `write <<set:name:VALUE>> to set it`.
- **Parsing and escaping (decided):**
  - Names can't contain `:`. VALUE is everything after the second `:` (so the value itself may contain `:`).
  - VALUE ends at the first **unescaped** `>>`.
  - Classic backslash escaping: `\` escapes the next character, so `\\` → `\` and `\>` → `>`. The stored value is the unescaped string.
  - Examples: value `a>>b` → `<<set:x:a\>>b>>`. Value ending in `>` → `<<set:x:abc\>>>`. Value `C:\path` → `<<set:x:C:\\path>>`.
  - Only the tool's escaping applies: markers are read from raw text, so YAML quoting rules don't stack on top.
- **Plaintext guardrails** (the risk of this design is a value slipping into Git):
  - The hook must be installed with `required` semantics. If it can't process a `<<set:…>>` (including a malformed escape), it aborts the commit rather than letting it through.
  - Backstop: deploy refuses to run if any `<<set:` appears in the committed tree (e.g. after `--no-verify` or a clone without the hook), and says the secret must be rotated, because it's now in Git history.

## Delivery (decided 2026-11-06)
- The tool is a **render step**, the last step before whatever ships the config (`docker compose up`, rsync, etc.). It replaces every marker with its real value and hands off a plain, resolved compose file.
- Secrets reach containers as ordinary inline values, so they're visible in `docker inspect`. This is accepted, consistent with the `.env` reasoning.
- Two commands:
  - `lst render <stack>`: resolved compose to stdout. Generic, so it can be piped into anything.
  - `lst deploy <stack>`: render, then run the configured target (default `docker compose up -d`).
- Prefer piping over writing files: `docker compose -p <stack> --project-directory stacks/<stack> -f - up -d` reads compose from stdin.
  - With stdin, the project name and project directory must be passed explicitly, so relative paths (bind mounts, build contexts) still resolve.
- If a target needs a file (e.g. rsync to another host), write the rendered file to a gitignored or tmpfs location and treat it as disposable plaintext.

### Files other than compose + hashed secrets (decided 2026-11-06)
- **Rendering markers into other config files is fine.** Rendered files on disk are as secret as `.env`, so the same trust level applies. (Authelia, Traefik and Mosquitto read secrets from bind-mounted config files.)
- **Hashing is not the tool's job.** For configs that need a *hash* of a secret (Mosquitto's password file, Authelia's user database), a deploy step runs the app's own hasher (e.g. `mosquitto_passwd`, `authelia crypto hash generate`) on the rendered secret.
  - The tool stays a dumb substituter: no argon2/bcrypt formats, no deterministic-salt problem.
- Rendered files in appdata get backed up as plaintext along with it, the same exposure as `.env`.

### `x-deploy:` section (decided 2026-11-06)
Per-stack deploy steps live **inside the compose file** as a top-level `x-deploy:` key. Compose ignores `x-` keys, so requirement 4 holds (no extra files). The tool strips the key from rendered output.

```yaml
x-deploy:
  render:                      # extra files with markers → rendered copies
    - from: config/mosquitto.conf
      to: /mnt/<appdata>/mosquitto/config/mosquitto.conf
  pre:                         # before compose up
    - with: mosquitto          # one-off container from that service's image
      run: rm -f /mosquitto/config/passwd && mosquitto_passwd -b -c /mosquitto/config/passwd z2m <<gen:shared/mqtt-z2m>>
    - with: mosquitto          # Mosquitto 2.1: the broker runs as `mosquitto` and must read the file
      run: [chown, "mosquitto:mosquitto", /mosquitto/config/passwd]
  post:                        # after compose up, inside the running service
    - exec: mongo
      run: mongosh … createUser("app1", "<<gen:mongo-app1>>") …
      when: on-change
```
_(Example updated 2026-11-07: since Mosquitto 2.1, `mosquitto_passwd -c` refuses an existing file, hence the `rm -f`, and the image no longer chowns `/mosquitto`, hence the `chown` step. Found with real Docker during M4; the decision itself is unchanged.)_
- **`render`:** template files in the repo (with markers) and where their rendered copies go.
- **`pre` with `with: <service>`:** runs in a throwaway container of that service's image, with the service's volumes. The app's own hasher is used without installing anything on Unraid, and the file exists before the real container starts.
- **`post` with `exec: <service>`:** runs inside the already-running container.
  - Rarely needed. It's for setup against a live server, e.g. one MongoDB (or Postgres) shared by several services, each needing its own user. That beats spinning up a temporary DB instance and tearing it down.
  - `post` waits until the service is healthy (`docker compose up --wait`) before running.
  - Commands like `createUser` fail if the user already exists, so post steps should be written idempotently or use `when: on-change`.
- **`when:` on every `pre`/`post` step:** `always` (the default) runs the step on every deploy; `on-change` runs it only when the service's render hash changed (read from the existing container label versus the new one).
- Markers inside `x-deploy` commands are rendered too. A secret on a command line is briefly visible in `ps`; accepted at the `.env` trust level.
- **Restart on change, without state:** the tool hashes each service's rendered *inputs* (extra files + the secrets they use) and injects the hash as a container label, e.g. `lst.render-hash`. When the hash changes, compose sees a changed container config and recreates the container by itself.
  - This solves "compose doesn't notice bind-mounted file changes" with no state file.
  - The hash is taken from the inputs, not the hasher's salted output, so it's stable across deploys.
  - Which services get the label is inferred from their `volumes:` (whichever service mounts a rendered `to:` path), so nothing extra has to be written.
- Order of a deploy: render compose + files → `pre` steps → `compose up --wait` → `post` steps.

## Lifecycle
- **Pre-commit hook:** runs `lst`. If `.sec/` is current, it exits silently; if missing or stale, `lst` rewrites it and `git add`s it into the same commit. It also processes `<<set:…>>` markers.
  - Must read the *staged* compose content, not the working tree.
- **Deploy (Woodpecker):** verify `.sec/` is current and that no `<<set:` is committed (backstop for `--no-verify` and fresh clones without the hook), then `lst deploy`. Writes no state.
- **Orphans:** names that vanish from compose are marked as orphans, never deleted automatically (the DB still uses the old password). Removed only by an explicit cleanup command (`lst gc --remove`, M5).
- **Rename hint:** if one name disappears and one appears in the same stack, print a hint; don't block the commit.

## Guardrails
- Refuse to run if `.env` isn't gitignored; add the ignore entry on `init`.
- Deploy fails loudly if a referenced secret can't be resolved.
- Marked files aren't valid until rendered, so deploy only goes through the tool.

## Status
- Design complete. Implementation plan: `docs/plan.md`. M0–M6 implemented (2026-11-08). Migration guide: `docs/migration.md`.
