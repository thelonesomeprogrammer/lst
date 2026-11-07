# Deploying from Woodpecker CI

`docs/examples/woodpecker.yml` is a pipeline for the **homelab repository** (the one with `stacks/`, `.sec/` and the committed `/.env` rule), not for lst's own repository. On every push to the default branch it checks the repository and deploys the stacks the push changed, through the Docker daemon of the machine the Woodpecker agent runs on.

It has three steps:

| Step | Runs on | Does |
|---|---|---|
| `build` | push, manual | Builds lst with `cargo install --locked --git … --tag …` into a cache directory on the agent host. Skipped when the cached binary already is the wanted version, so it only compiles after you bump `LST_TAG`. The binary is static (musl), so any Alpine image can run it. |
| `deploy` | push, manual | `lst check`, then `lst deploy --changed-since <previous pipeline's commit>`, or `lst deploy <every stack>` when that commit can't be trusted (see below). Has the seed and the Docker socket. |
| `check` | pull request | `lst check` without the seed (structural only: `.sec/` is current, no committed `<<set:…>>`, every `<<secret:…>>` has a value). No seed, no Docker socket. Uses the binary the `build` step cached. |

The pipeline is written for Woodpecker 3 (list syntax for `steps` and `clone`); compare it with the workflow syntax docs of your version.

## Setup

1. **Activate the repository** in Woodpecker (it must be connected to your Gitea).
2. **Trust it for volumes.** The `build` and `deploy` steps mount host paths (the cache directory and `/var/run/docker.sock`), which Woodpecker only allows for trusted repositories. An admin sets this in the repository's settings (Woodpecker 3 splits "trusted" into security, network and volumes; volumes is the one needed).
3. **Add the secret `lst_seed`** in the repository's settings: the value is the 64 hex characters of the seed (from your password manager, or the part after `LST_SEED=` in `.env`), without `LST_SEED=`, quotes or a trailing newline. Make it available to the **push** and **manual** events only, never to pull requests. The pipeline hands it to lst as the `LST_SEED` environment variable; lst never writes it to disk and never passes it on to compose.
4. **Copy the pipeline** to `.woodpecker.yml` in the homelab repository and set `LST_TAG` to the lst release you want. Change `/var/lib/woodpecker/lst-cache` (three places) if you want the cache elsewhere; Docker creates the directory on first use.
5. **Run the agent on the deploy host.** The stacks run on whichever Docker daemon the agent's `/var/run/docker.sock` belongs to. With several agents, pin the pipeline to the right one (agent labels).

### Bind mounts must be absolute host paths

`docker compose` runs *inside* the `deploy` step's container, and the daemon it talks to is the host's. Compose resolves a relative bind mount such as `./data:/data` against the project directory, which here is the CI workspace (`/woodpecker/src/…/stacks/<stack>`), and the host daemon then looks for that path **on the host**, where it doesn't exist (it creates an empty directory instead). Use absolute host paths for bind mounts (`/mnt/appdata/<stack>/data:/data`) or named volumes. Things compose reads itself (`env_file:`, build contexts) work as usual, because the client sends them.

### What the Docker socket means

Mounting `/var/run/docker.sock` gives the step full control of the host's Docker daemon, which is root on the host: it can start a privileged container with `/` mounted. So everything that can run in a pipeline with the trusted settings can take over the host. In particular:

- **Pull requests run the pipeline file from the pull request.** A pull request can change `.woodpecker.yml` to mount the socket in its own step (trusted applies to the repository, not to the file), or mount the cache directory read-write and replace the lst binary that the next push runs with the seed. Keep the repository private and don't accept pull requests from people you don't trust; set Woodpecker to require approval for pull request pipelines, or drop the `pull_request` event from the pipeline.
- **Anyone who can push to the default branch can deploy anything**, and read every secret (the seed is in the step's environment). That is the same trust as a shell on the host, which is the threat model lst already has: whoever can read `.env` on the server can `docker inspect` every secret anyway.
- Rendered secrets show up in `docker inspect`, as with any lst deploy. They don't show up in the pipeline log: lst prints stack names and compose's own progress output, never values.

### Retiring Dockge

The M3 goal (`docs/plan.md`) is that a push to Gitea deploys the pilot stack with no manual steps; from there, Dockge can start being retired, one stack at a time. lst uses the stack's directory name as the compose project name, so if a stack has the same name in Dockge, `lst deploy` takes over its containers (compose recreates the ones whose configuration differs). Once a stack deploys from CI, remove it from Dockge's stacks directory by hand rather than with Dockge's delete action, which also takes the stack down. Until then, don't edit the same stack in both places.

## First run

Commit `.woodpecker.yml` and push. The first pipeline has no previous pipeline, so it builds lst (a few minutes, once per version) and deploys every stack:

```text
lst: check ok
deploying every stack: there is no previous pipeline
lst: deployed <stack>
…
```

A manual run ("Run pipeline" on the default branch) also deploys every stack. That is always safe: compose leaves services whose configuration didn't change alone, so a full deploy only recreates what changed.

From then on, a push deploys only what changed since the previous pipeline's commit (`lst deploy --changed-since`, see the README): a change under `stacks/<s>/` or in `.sec/<s>.toml` deploys `<s>`, a changed entry in `.sec/shared.toml` deploys the stacks that use it, a change in `.sec/meta.toml` deploys everything, and other files (README, the pipeline itself) deploy nothing. Deleted stacks are reported, not taken down.

## How the deploy step picks `--changed-since`

It only diffs against a commit it knows was deployed. It uses `CI_PREV_COMMIT_SHA` when all of these hold, and otherwise deploys every stack and prints why:

- this pipeline is a push (a manual run deploys everything);
- the previous pipeline succeeded (after a failed deploy, its commit's changes may not be live);
- the previous pipeline was a push or manual run on the same branch (not a pull request);
- that commit is in the clone (`git cat-file`).

The default Woodpecker clone fetches a single commit, so the pipeline's `clone` section asks for 50 (`partial: false`, `depth: 50`). A push of more commits than that, or a force push that dropped the previous commit, falls back to deploying every stack. Raise `depth` if that happens often.

## Troubleshooting

| Message | Cause and fix |
|---|---|
| `LST_SEED is empty: add the lst_seed secret …` | The secret doesn't exist, or isn't available for this event (push, manual). |
| `the LST_SEED environment variable is not 64 lowercase hex characters …` | The secret has `LST_SEED=`, quotes, spaces or a trailing newline in it, or uppercase hex. Store just the 64 characters. |
| `wrong seed: its fingerprint does not match .sec/meta.toml` | The secret holds another seed (another repository's, or an old one). |
| `.env is not gitignored; lst refuses to read or write it …` | Commit the `/.env` rule `lst init` added to `.gitignore`; lst checks it even when `.env` doesn't exist. |
| `… <<set:…>> value is in git history; rotate the secret …` | A plaintext value was committed without the hook (`--no-verify`, or a clone without `lst hook install`). Set a new value with `<<set:…>>` (through the hook) and treat the old one as leaked: it stays in the history. |
| `check failed: …` (stale `.sec/`, unset secret) | Someone committed without the hook. Run `lst sync` (or commit through the hook) locally and push. |
| `` `docker compose up` for stack "x" failed (…) (deployed: …; failed: x; not attempted: …) `` | Compose's own output above says why (bad image, a container that never gets healthy with `--wait`). The stacks listed as deployed are live; the others weren't touched. Fix and push: the failed pipeline makes the next one deploy every stack. |
| `detected dubious ownership in repository` | The clone belongs to another user than the step. The example's `git config --global --add safe.directory` line handles that; keep it. |
| `permission denied … docker.sock` / `Cannot connect to the Docker daemon` | The socket isn't mounted: the repository isn't trusted for volumes, or the agent's host has its socket elsewhere. |
| `deploying every stack: its commit … is not in this clone` | Expected after a long push or a force push; raise the clone `depth` if it happens on ordinary pushes. |
| `lst is not in the cache yet` (pull request check) | The cache is filled by the default branch's pipeline: run it once. |
| `build` fails in `cargo install` | No network to GitHub or crates.io from the agent, or the tag doesn't exist. |
| A bind-mounted directory is empty in the container | A relative bind mount; see [Bind mounts must be absolute host paths](#bind-mounts-must-be-absolute-host-paths). |

**Upgrading lst:** bump `LST_TAG` in the `build` step and push; `build` sees the version change and compiles the new one. To force a rebuild, delete `/var/lib/woodpecker/lst-cache/lst` on the agent host.
