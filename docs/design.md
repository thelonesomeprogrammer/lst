# Lazy Secret Tool (`lst`) — design notes

_Started 2026-11-06. Own tool, written in Rust. Status: design complete, M0 in progress. Binary name: `lst`._

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
      run: mosquitto_passwd -b -c /mosquitto/config/passwd z2m <<gen:shared/mqtt-z2m>>
  post:                        # after compose up, inside the running service
    - exec: mongo
      run: mongosh … createUser("app1", "<<gen:mongo-app1>>") …
      when: on-change
```
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
- **Orphans:** names that vanish from compose are marked as orphans, never deleted automatically (the DB still uses the old password). Removed only by an explicit cleanup command.
- **Rename hint:** if one name disappears and one appears in the same stack, print a hint; don't block the commit.

## Guardrails
- Refuse to run if `.env` isn't gitignored; add the ignore entry on `init`.
- Deploy fails loudly if a referenced secret can't be resolved.
- Marked files aren't valid until rendered, so deploy only goes through the tool.

## Status
- Design complete. Implementation plan: `docs/plan.md`. M0 (core library) in progress in Claude Code.
