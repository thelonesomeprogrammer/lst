# CLAUDE.md: lst (Lazy Secret Tool)

Rust CLI that fills secret markers in Docker Compose files with seed-derived or encrypted values at deploy time. Solo homelab project by tlp. Read `README.md` for the user-facing picture.

**Source of truth:** `docs/design.md` (decisions) and `docs/plan.md` (milestones). If code and design disagree, stop and ask; don't silently pick one.

## Frozen invariants: never change these without explicit approval
- **BLAKE3 `derive_key` context strings:** `"lst v1 gen"`, `"lst v1 sec-encryption"`, `"lst v1 fingerprint"`, `"lst v1 render-hash"` (added for M4, approved 2026-11-07). Changing any of the first three changes every secret ever generated; changing the last restarts every container that carries the label.
- **Derivation input:** `key_material = seed || id` for generated secrets.
- **Format encoders** (`alnumN`, `hexN`, `base64-N`, `uuid`; N counts output characters), including the rejection-sampling alphabet, the N limits and the order bytes are consumed from the XOF stream. See `docs/design.md` → "Frozen encoding details".
- **Encoding details:** ids are 16 random bytes; `seed || id` is the 48 raw bytes; manual-secret AEAD associated data is `"lst v1 secret\0" + full_name`.
- **Test vectors in `tests/vectors.rs`.** If a vector test fails, the code is wrong, not the vector. Never "update" a vector to make a test pass.
- **Marker grammar:** `<<gen:name[:format]>>`, `<<secret:name>>`, `<<set:name:VALUE>>`. Names contain no `:`. In VALUE, `\\` → `\` and `\>` → `>`, and VALUE ends at the first unescaped `>>`.

## Security rules
- Never log, print, `Debug`-format or include in error messages a secret value, the seed or a decrypted ciphertext. Errors name the *secret* (`stack/name`), never the value.
- Hold seeds and secret values in `zeroize`/`secrecy` types. Implement `Debug` manually as redacted.
- All randomness (seed, ids, nonces) comes from `getrandom` / the OS random generator. No `thread_rng`, and no seeding from time.
- A failure while processing `<<set:…>>` must abort the commit. Fail closed: no fallback that lets plaintext through.
- `.env` must be gitignored before `lst` reads or writes it; otherwise refuse with a clear message.

## Architecture
```
src/main.rs     CLI (clap derive), thin; maps errors to exit codes
src/marker.rs   lexer/parser over raw text → Vec<Marker> with byte spans; escaping
src/crypto.rs   seed type, derive_key wrappers, XChaCha20-Poly1305 seal/open, fingerprint
src/format.rs   XOF stream → formatted secret strings
src/store.rs    .sec/ model + TOML (de)serialisation; deterministic output; only re-encrypt changed values
src/render.rs   substitute markers in text; strip x-deploy; inject lst.render-hash labels
src/deploy.rs   x-deploy model; docker compose invocation
src/git.rs      shell out to git: staged files, index rewrite (hash-object + update-index), ignore checks
src/stack.rs    discover stacks/<name>/compose.yaml
src/clipboard.rs  `lst get --copy`: pipe a value into wl-copy/xclip/xsel/pbcopy
```
- `marker`, `crypto` and `format` are **pure**: no filesystem, no subprocesses, no environment variables. Keep them that way; that's what makes them testable.
- Markers are parsed from **raw text**, never from parsed YAML. YAML parsing is only for `x-deploy`, `volumes:` and label injection (M4).
- Shell out to `git` and `docker compose` with `std::process::Command`. No libgit2, no Docker API crates. Pass arguments as a vector, never through a shell string.

## Conventions
- Rust 2024 edition, stable toolchain. `cargo fmt` and `cargo clippy -- -D warnings` must be clean.
- `thiserror` for library error types; `anyhow` only in `main.rs`.
- No `unsafe`. No `unwrap()`/`expect()` outside tests, unless an invariant comment explains why it can't fail.
- Keep dependencies minimal. Ask before adding a crate that isn't in `docs/plan.md`.
- Output must be deterministic: same inputs → byte-identical `.sec/` files and rendered output (sorted keys, stable formatting).
- Small, focused commits, one milestone step at a time.

## Testing
- `cargo test` must pass before any milestone is called done.
- The marker parser gets `proptest` round-trips (escape(v) → parse → v) and explicit malformed-input cases.
- End-to-end tests (M2+) use a `tempfile` git repo with fake stacks. Tests that need Docker are `#[ignore]` and run explicitly.
- Never test against real secrets or the user's real repository.

## Working style
- tlp knows Rust and embedded/systems work well. Skip beginner explanations, but explain *design* tradeoffs briefly before choosing.
- Work milestone by milestone (`docs/plan.md`). Don't start the next milestone without being asked.
- When something in the design is ambiguous or seems wrong, ask instead of guessing. The design was decided carefully.
