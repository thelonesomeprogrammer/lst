//! Shelling out to `git`: repository discovery, ignore/tracking checks and
//! the index plumbing the pre-commit hook uses.
//!
//! Every call is `git -C <dir> …` with an argument vector (never a shell
//! string), so nothing depends on the process's working directory.
//! `LC_ALL=C` is set on every invocation so that the one message we match
//! on ("not a git repository") isn't translated. The rest of the
//! environment is inherited on purpose: inside a git hook (M2) `GIT_DIR` /
//! `GIT_INDEX_FILE` must keep pointing where git says.
//!
//! Paths passed as `rel_path` are relative to the repository root, use `/`
//! separators. `is_tracked` matches them literally (`--literal-pathspecs`,
//! and the exact entry must be listed), so `*` or `?` in a name is never a
//! glob. `check-ignore` takes plain pathnames, not pathspecs (and rejects
//! `--literal-pathspecs`).
//!
//! git's stderr is included in errors: for the commands used here it only
//! ever contains paths, object ids and git's own messages, never file
//! contents. stdout is never included: `read_blob`'s is a staged file, which
//! may hold a plaintext `<<set:…>>` value.
//!
//! The index layer (`staged_entries`, `read_blob`, `write_blob`,
//! `update_index`, `add`) is what the pre-commit hook works through. It
//! never touches the working tree, and because the environment is
//! inherited it operates on whichever index `GIT_INDEX_FILE` names (git
//! points it at a temporary index for `git commit -a` / `git commit <path>`).

use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};

use zeroize::Zeroizing;

const GIT: &str = "git";
/// The seed file, relative to the repository root.
pub const ENV_FILE: &str = ".env";
const GITIGNORE: &str = ".gitignore";
/// The rule `ensure_env_ignored` appends: anchored, so it only ignores the
/// root `.env` and not, say, `stacks/foo/.env`.
const ENV_RULE: &[u8] = b"/.env\n";

#[derive(Debug, thiserror::Error)]
pub enum GitError {
    #[error("could not run git (is it installed and on PATH?)")]
    Spawn(#[source] io::Error),
    #[error("{} is not inside a git repository", path.display())]
    NotARepo { path: PathBuf },
    #[error("`git {command}` failed ({status}): {stderr}")]
    Failed {
        command: String,
        status: String,
        stderr: String,
    },
    #[error("the repository path is not valid UTF-8, which lst does not support")]
    NonUtf8Path,
    #[error(
        ".env is tracked by git, so the seed would be committed; \
         run `git rm --cached .env` and commit that first"
    )]
    EnvTracked,
    #[error(
        ".env is not gitignored; lst refuses to read or write it until it is \
         (run `lst init`, or add `/.env` to .gitignore)"
    )]
    EnvNotIgnored,
    #[error(
        "added `/.env` to {} but git still does not ignore .env; check your ignore rules",
        path.display()
    )]
    StillNotIgnored { path: PathBuf },
    #[error(
        "{} is a symlink; git does not read symlinked .gitignore files, so lst won't write through it",
        path.display()
    )]
    GitignoreSymlink { path: PathBuf },
    #[error("`git {command}` printed output lst could not parse")]
    BadOutput { command: String },
    #[error("could not send data to `git {command}`")]
    Stdin {
        command: String,
        #[source]
        source: io::Error,
    },
    #[error("{path} has unresolved merge conflicts; resolve them before committing")]
    Unmerged { path: String },
    #[error("staged path {lossy:?} is not valid UTF-8, which lst does not support")]
    NonUtf8IndexPath { lossy: String },
    #[error("{}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// What `ensure_env_ignored` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgnoreOutcome {
    AlreadyIgnored,
    /// `/.env` was appended to `<root>/.gitignore`.
    Added,
}

fn io_err(path: &Path) -> impl FnOnce(io::Error) -> GitError + '_ {
    move |source| GitError::Io {
        path: path.to_owned(),
        source,
    }
}

/// Runs `<program> -C <dir> <args…>` and captures its output.
fn run(program: &OsStr, dir: &Path, args: &[&OsStr]) -> Result<Output, GitError> {
    Command::new(program)
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .output()
        .map_err(GitError::Spawn)
}

/// `args` as one string, for error messages.
fn command_line(args: &[&OsStr]) -> String {
    args.iter()
        .map(|a| a.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ")
}

/// A non-zero exit. Takes the status and stderr rather than the whole
/// `Output` so callers holding secret stdout can move it out first; stdout
/// never goes into an error.
fn failed(args: &[&OsStr], status: ExitStatus, stderr: &[u8]) -> GitError {
    GitError::Failed {
        command: command_line(args),
        status: status.to_string(),
        stderr: String::from_utf8_lossy(stderr).trim_end().to_owned(),
    }
}

/// The top-level directory of the work tree containing `cwd`.
pub fn repo_root(cwd: &Path) -> Result<PathBuf, GitError> {
    repo_root_with(OsStr::new(GIT), cwd)
}

fn repo_root_with(program: &OsStr, cwd: &Path) -> Result<PathBuf, GitError> {
    let args = [OsStr::new("rev-parse"), OsStr::new("--show-toplevel")];
    let out = run(program, cwd, &args)?;
    if !out.status.success() {
        if String::from_utf8_lossy(&out.stderr).contains("not a git repository") {
            return Err(GitError::NotARepo {
                path: cwd.to_owned(),
            });
        }
        return Err(failed(&args, out.status, &out.stderr));
    }
    Ok(PathBuf::from(path_line(out.stdout)?))
}

/// A path printed by `git rev-parse` on one line.
fn path_line(mut stdout: Vec<u8>) -> Result<String, GitError> {
    if stdout.last() == Some(&b'\n') {
        stdout.pop();
    }
    String::from_utf8(stdout).map_err(|_| GitError::NonUtf8Path)
}

/// Whether git ignores `rel_path`. A tracked file is never ignored.
pub fn is_ignored(root: &Path, rel_path: &Path) -> Result<bool, GitError> {
    is_ignored_with(OsStr::new(GIT), root, rel_path)
}

fn is_ignored_with(program: &OsStr, root: &Path, rel_path: &Path) -> Result<bool, GitError> {
    let args = [
        OsStr::new("check-ignore"),
        OsStr::new("-q"),
        OsStr::new("--"),
        rel_path.as_os_str(),
    ];
    let out = run(program, root, &args)?;
    match out.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(failed(&args, out.status, &out.stderr)),
    }
}

/// Whether `rel_path` is in the index (exactly that path, not a directory
/// prefix of tracked files).
pub fn is_tracked(root: &Path, rel_path: &Path) -> Result<bool, GitError> {
    is_tracked_with(OsStr::new(GIT), root, rel_path)
}

fn is_tracked_with(program: &OsStr, root: &Path, rel_path: &Path) -> Result<bool, GitError> {
    let args = [
        OsStr::new("--literal-pathspecs"),
        OsStr::new("ls-files"),
        OsStr::new("-z"),
        OsStr::new("--"),
        rel_path.as_os_str(),
    ];
    let out = run(program, root, &args)?;
    if !out.status.success() {
        return Err(failed(&args, out.status, &out.stderr));
    }
    let want = rel_path.as_os_str().as_encoded_bytes();
    Ok(out.stdout.split(|&b| b == 0).any(|entry| entry == want))
}

/// `lst init`'s step: make sure `<root>/.env` is ignored, appending
/// `/.env` to `<root>/.gitignore` if needed.
///
/// Refuses if `.env` is tracked (it would be committed whatever the ignore
/// rules say) or if `.gitignore` is a symlink. If the appended rule doesn't
/// take effect the line is left in place and an error is returned.
pub fn ensure_env_ignored(root: &Path) -> Result<IgnoreOutcome, GitError> {
    ensure_env_ignored_with(OsStr::new(GIT), root)
}

fn ensure_env_ignored_with(program: &OsStr, root: &Path) -> Result<IgnoreOutcome, GitError> {
    let env = Path::new(ENV_FILE);
    if is_tracked_with(program, root, env)? {
        return Err(GitError::EnvTracked);
    }
    if is_ignored_with(program, root, env)? {
        return Ok(IgnoreOutcome::AlreadyIgnored);
    }
    let path = root.join(GITIGNORE);
    if fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(GitError::GitignoreSymlink { path });
    }
    let existing = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(io_err(&path)(e)),
    };
    let mut append = Vec::with_capacity(ENV_RULE.len() + 1);
    if !existing.is_empty() && !existing.ends_with(b"\n") {
        append.push(b'\n');
    }
    append.extend_from_slice(ENV_RULE);
    OpenOptions::new()
        .append(true)
        .create(true)
        .open(&path)
        .and_then(|mut f| f.write_all(&append))
        .map_err(io_err(&path))?;
    if is_ignored_with(program, root, env)? {
        Ok(IgnoreOutcome::Added)
    } else {
        Err(GitError::StillNotIgnored { path })
    }
}

/// The guard every command runs before reading or writing `<root>/.env`:
/// `.env` must be untracked and ignored.
pub fn require_env_ignored(root: &Path) -> Result<(), GitError> {
    require_env_ignored_with(OsStr::new(GIT), root)
}

fn require_env_ignored_with(program: &OsStr, root: &Path) -> Result<(), GitError> {
    let env = Path::new(ENV_FILE);
    if is_tracked_with(program, root, env)? {
        return Err(GitError::EnvTracked);
    }
    if !is_ignored_with(program, root, env)? {
        return Err(GitError::EnvNotIgnored);
    }
    Ok(())
}

/// One stage-0 entry of the index, as `git ls-files -s` lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    /// The octal mode git records: `100644` / `100755` for regular files,
    /// `120000` for symlinks (the blob is the link target), `160000` for
    /// submodules (the oid is a commit, so `read_blob` fails on it).
    pub mode: String,
    /// The object id, lowercase hex (SHA-1 or SHA-256).
    pub oid: String,
    /// Relative to the repository root, `/`-separated.
    pub path: String,
}

impl IndexEntry {
    /// A regular file (executable or not): the only kind whose blob is file
    /// content.
    pub fn is_file(&self) -> bool {
        self.mode == "100644" || self.mode == "100755"
    }
}

/// Whether `s` looks like an object id: 40 (SHA-1) or 64 (SHA-256)
/// lowercase hex digits.
fn is_oid(s: &str) -> bool {
    matches!(s.len(), 40 | 64) && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The fields of one `ls-files -s -z` record,
/// `<mode> SP <oid> SP <stage> TAB <path>`; `None` if it isn't one.
fn parse_stage_record(rec: &[u8]) -> Option<(&str, &str, &str, &[u8])> {
    let tab = rec.iter().position(|&b| b == b'\t')?;
    let (meta, path) = (&rec[..tab], &rec[tab + 1..]);
    let mut fields = std::str::from_utf8(meta).ok()?.split(' ');
    let (Some(mode), Some(oid), Some(stage), None) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return None;
    };
    let valid = !mode.is_empty()
        && mode.bytes().all(|b| b.is_ascii_digit())
        && is_oid(oid)
        && matches!(stage, "0" | "1" | "2" | "3")
        && !path.is_empty();
    valid.then_some((mode, oid, stage, path))
}

/// Parses `ls-files -s -z` output. Paths may contain anything but NUL
/// (`-z` turns off quoting), so the path is everything after the tab.
fn parse_stage_entries(args: &[&OsStr], stdout: &[u8]) -> Result<Vec<IndexEntry>, GitError> {
    let bad = || GitError::BadOutput {
        command: command_line(args),
    };
    let body = match stdout.strip_suffix(b"\0") {
        Some(body) => body,
        None if stdout.is_empty() => return Ok(Vec::new()),
        None => return Err(bad()),
    };
    let mut entries = Vec::new();
    let mut unmerged = Vec::new();
    for rec in body.split(|&b| b == 0) {
        let (mode, oid, stage, path) = parse_stage_record(rec).ok_or_else(bad)?;
        let path = String::from_utf8(path.to_vec()).map_err(|e| GitError::NonUtf8IndexPath {
            lossy: String::from_utf8_lossy(e.as_bytes()).into_owned(),
        })?;
        if stage == "0" {
            entries.push(IndexEntry {
                mode: mode.to_owned(),
                oid: oid.to_owned(),
                path,
            });
        } else {
            unmerged.push(path);
        }
    }
    if let Some(path) = unmerged.into_iter().min() {
        return Err(GitError::Unmerged { path });
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(entries)
}

/// Every index entry at or under `prefix` (a file or directory path,
/// matched literally; `""` means the whole index), sorted by path.
///
/// Symlinks and submodules are listed too, with their modes, so the caller
/// can decide to skip them (see `IndexEntry::is_file`). If any matching
/// path has unmerged stages the result is `Unmerged` (the smallest such
/// path): there is no single staged content to work on. A path that isn't
/// UTF-8 is `NonUtf8IndexPath`.
pub fn staged_entries(root: &Path, prefix: &str) -> Result<Vec<IndexEntry>, GitError> {
    staged_entries_with(OsStr::new(GIT), root, prefix)
}

fn staged_entries_with(
    program: &OsStr,
    root: &Path,
    prefix: &str,
) -> Result<Vec<IndexEntry>, GitError> {
    let mut args = vec![
        OsStr::new("--literal-pathspecs"),
        OsStr::new("ls-files"),
        OsStr::new("-s"),
        OsStr::new("-z"),
    ];
    // An empty string is not a valid pathspec; no pathspec means everything.
    if !prefix.is_empty() {
        args.extend([OsStr::new("--"), OsStr::new(prefix)]);
    }
    let out = run(program, root, &args)?;
    if !out.status.success() {
        return Err(failed(&args, out.status, &out.stderr));
    }
    parse_stage_entries(&args, &out.stdout)
}

/// The content of blob `oid`. It may be a staged file holding a plaintext
/// `<<set:…>>` value, so it comes back as `Zeroizing` and never appears in
/// an error. (Best effort: `std::process` grows its read buffer as output
/// arrives and does not wipe the buffers it outgrows.)
pub fn read_blob(root: &Path, oid: &str) -> Result<Zeroizing<Vec<u8>>, GitError> {
    read_blob_with(OsStr::new(GIT), root, oid)
}

fn read_blob_with(program: &OsStr, root: &Path, oid: &str) -> Result<Zeroizing<Vec<u8>>, GitError> {
    let args = [OsStr::new("cat-file"), OsStr::new("blob"), OsStr::new(oid)];
    let Output {
        status,
        stdout,
        stderr,
    } = run(program, root, &args)?;
    let stdout = Zeroizing::new(stdout);
    if !status.success() {
        return Err(failed(&args, status, &stderr));
    }
    Ok(stdout)
}

/// Writes `bytes` to the object database as a blob and returns its oid
/// (`git hash-object -w --stdin`). `bytes` is streamed from the caller's
/// buffer; no copy is made here.
pub fn write_blob(root: &Path, bytes: &[u8]) -> Result<String, GitError> {
    write_blob_with(OsStr::new(GIT), root, bytes)
}

fn write_blob_with(program: &OsStr, root: &Path, bytes: &[u8]) -> Result<String, GitError> {
    let args = [
        OsStr::new("hash-object"),
        OsStr::new("-w"),
        OsStr::new("--stdin"),
    ];
    let mut child = Command::new(program)
        .arg("-C")
        .arg(root)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(GitError::Spawn)?;
    // Writing all of stdin before reading any output can't deadlock:
    // hash-object reads its input to EOF before printing the oid, and
    // prints nothing else except a short message when it fails (in which
    // case it stops reading and the write ends with EPIPE, not a hang).
    // Dropping the handle closes the pipe so git sees EOF.
    let written = {
        // Invariant: stdin was configured as `Stdio::piped()` above, so
        // `spawn` populated the handle and nothing has taken it yet.
        let mut stdin = child.stdin.take().expect("stdin is piped");
        stdin.write_all(bytes)
    };
    let out = child.wait_with_output().map_err(GitError::Spawn)?;
    if !out.status.success() {
        return Err(failed(&args, out.status, &out.stderr));
    }
    // git exited 0 without taking all of the input: whatever it stored is
    // not `bytes`.
    if let Err(source) = written {
        return Err(GitError::Stdin {
            command: command_line(&args),
            source,
        });
    }
    match std::str::from_utf8(&out.stdout).map(|s| s.trim_end_matches('\n')) {
        Ok(oid) if is_oid(oid) => Ok(oid.to_owned()),
        _ => Err(GitError::BadOutput {
            command: command_line(&args),
        }),
    }
}

/// Points the existing index entry `path` at blob `oid` with `mode`
/// (`git update-index --cacheinfo <mode> <oid> <path>`). The working tree
/// is not touched, so partial staging survives.
///
/// The three-argument form is used rather than `<mode>,<oid>,<path>`: the
/// path is passed as its own argument and is taken verbatim, commas,
/// spaces, newlines, leading `-` and all. `--add` is deliberately not
/// passed: the hook only rewrites files that are already staged, so a
/// path missing from the index is a bug and fails here.
pub fn update_index(root: &Path, mode: &str, oid: &str, path: &str) -> Result<(), GitError> {
    update_index_with(OsStr::new(GIT), root, mode, oid, path)
}

fn update_index_with(
    program: &OsStr,
    root: &Path,
    mode: &str,
    oid: &str,
    path: &str,
) -> Result<(), GitError> {
    let args = [
        OsStr::new("update-index"),
        OsStr::new("--cacheinfo"),
        OsStr::new(mode),
        OsStr::new(oid),
        OsStr::new(path),
    ];
    let out = run(program, root, &args)?;
    if !out.status.success() {
        return Err(failed(&args, out.status, &out.stderr));
    }
    Ok(())
}

/// Stages the working-tree state of `rel_path` (a file or directory,
/// matched literally) into the index: `git add -A -- <path>`.
///
/// `-A` so that files deleted from the working tree under `rel_path` are
/// removed from the index as well (the hook stages `.sec/` this way, and a
/// store file that went away must not linger in the commit). Fails if
/// `rel_path` matches nothing in the working tree or the index, or is
/// ignored.
pub fn add(root: &Path, rel_path: &Path) -> Result<(), GitError> {
    add_with(OsStr::new(GIT), root, rel_path)
}

fn add_with(program: &OsStr, root: &Path, rel_path: &Path) -> Result<(), GitError> {
    let args = [
        OsStr::new("--literal-pathspecs"),
        OsStr::new("add"),
        OsStr::new("-A"),
        OsStr::new("--"),
        rel_path.as_os_str(),
    ];
    let out = run(program, root, &args)?;
    if !out.status.success() {
        return Err(failed(&args, out.status, &out.stderr));
    }
    Ok(())
}

/// The directory git runs hooks from (`git rev-parse --git-path hooks`):
/// `core.hooksPath` if set (a relative value is relative to `root`, where
/// git runs hooks), else the hooks directory of the common git dir, which
/// linked worktrees share. The directory need not exist.
pub fn hooks_dir(root: &Path) -> Result<PathBuf, GitError> {
    hooks_dir_with(OsStr::new(GIT), root)
}

fn hooks_dir_with(program: &OsStr, root: &Path) -> Result<PathBuf, GitError> {
    let args = [
        OsStr::new("rev-parse"),
        OsStr::new("--git-path"),
        OsStr::new("hooks"),
    ];
    let out = run(program, root, &args)?;
    if !out.status.success() {
        return Err(failed(&args, out.status, &out.stderr));
    }
    let path = path_line(out.stdout)?;
    if path.is_empty() {
        return Err(GitError::BadOutput {
            command: command_line(&args),
        });
    }
    // `join` keeps an absolute path as is.
    Ok(root.join(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Runs real git in `dir` for test setup.
    fn sh_git(dir: &Path, args: &[&str]) {
        let st = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(st.success(), "git {args:?}");
    }

    /// A fresh repo, isolated from the user's global excludes file.
    fn repo() -> TempDir {
        let dir = tempfile::tempdir().unwrap();
        sh_git(dir.path(), &["init", "-q"]);
        let excludes = dir.path().join(".git/no-global-excludes");
        sh_git(
            dir.path(),
            &["config", "core.excludesFile", excludes.to_str().unwrap()],
        );
        dir
    }

    fn write(root: &Path, rel: &str, contents: &str) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, contents).unwrap();
    }

    fn gitignore(root: &Path) -> String {
        fs::read_to_string(root.join(GITIGNORE)).unwrap()
    }

    #[test]
    fn repo_root_finds_toplevel() {
        let r = repo();
        let top = r.path().canonicalize().unwrap();
        assert_eq!(repo_root(r.path()).unwrap(), top);
        fs::create_dir_all(r.path().join("stacks/a")).unwrap();
        assert_eq!(repo_root(&r.path().join("stacks/a")).unwrap(), top);
    }

    #[test]
    fn repo_root_not_a_repo() {
        let dir = tempfile::tempdir().unwrap();
        let err = repo_root(dir.path()).unwrap_err();
        assert!(
            matches!(&err, GitError::NotARepo { path } if path == dir.path()),
            "{err:?}"
        );
        assert!(err.to_string().contains("not inside a git repository"));
    }

    #[test]
    fn repo_root_other_failure() {
        let dir = tempfile::tempdir().unwrap();
        let err = repo_root(&dir.path().join("missing")).unwrap_err();
        assert!(
            matches!(&err, GitError::Failed { command, stderr, .. }
                if command == "rev-parse --show-toplevel" && stderr.contains("cannot change to")),
            "{err:?}"
        );
        assert!(
            err.to_string()
                .starts_with("`git rev-parse --show-toplevel` failed (")
        );
    }

    #[cfg(unix)]
    #[test]
    fn repo_root_non_utf8() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join(OsStr::from_bytes(b"repo-\xff"));
        fs::create_dir(&sub).unwrap();
        sh_git(&sub, &["init", "-q"]);
        let err = repo_root(&sub).unwrap_err();
        assert!(matches!(err, GitError::NonUtf8Path), "{err:?}");
        assert!(err.to_string().contains("UTF-8"));
    }

    #[test]
    fn spawn_failure_is_distinct() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no-such-git");
        let err = repo_root_with(missing.as_os_str(), dir.path()).unwrap_err();
        assert!(
            matches!(&err, GitError::Spawn(source) if source.kind() == io::ErrorKind::NotFound),
            "{err:?}"
        );
        assert!(err.to_string().contains("could not run git"));
        let env = Path::new(ENV_FILE);
        for err in [
            is_ignored_with(missing.as_os_str(), dir.path(), env).unwrap_err(),
            is_tracked_with(missing.as_os_str(), dir.path(), env).unwrap_err(),
            ensure_env_ignored_with(missing.as_os_str(), dir.path()).unwrap_err(),
        ] {
            assert!(matches!(err, GitError::Spawn(_)), "{err:?}");
        }
    }

    #[test]
    fn ignored_and_tracked() {
        let r = repo();
        let root = r.path();
        write(root, ".gitignore", "*.log\n/ignored-dir/\n");
        write(root, "a.log", "");
        write(root, "b.txt", "");
        write(root, "c.log", "");
        write(root, "ignored-dir/x", "");
        write(root, "*", "");
        sh_git(root, &["add", "-f", "c.log", "*"]);

        assert!(is_ignored(root, Path::new("a.log")).unwrap());
        assert!(!is_ignored(root, Path::new("b.txt")).unwrap());
        // Tracked files are never reported as ignored.
        assert!(!is_ignored(root, Path::new("c.log")).unwrap());
        assert!(is_ignored(root, Path::new("ignored-dir/x")).unwrap());
        // Paths need not exist.
        assert!(is_ignored(root, Path::new("nope.log")).unwrap());

        assert!(is_tracked(root, Path::new("c.log")).unwrap());
        assert!(!is_tracked(root, Path::new("a.log")).unwrap());
        assert!(!is_tracked(root, Path::new("missing")).unwrap());
        // Literal, not a glob: `*` is tracked, `?.log` matches nothing.
        assert!(is_tracked(root, Path::new("*")).unwrap());
        assert!(!is_tracked(root, Path::new("?.log")).unwrap());
    }

    #[test]
    fn tracked_means_exact_path_not_prefix() {
        let r = repo();
        write(r.path(), ".env/inner", "");
        sh_git(r.path(), &["add", ".env/inner"]);
        assert!(!is_tracked(r.path(), Path::new(".env")).unwrap());
        assert!(is_tracked(r.path(), Path::new(".env/inner")).unwrap());
    }

    #[test]
    fn checks_fail_outside_a_repo() {
        let dir = tempfile::tempdir().unwrap();
        let err = is_ignored(dir.path(), Path::new(".env")).unwrap_err();
        assert!(
            matches!(&err, GitError::Failed { command, .. }
                if command == "check-ignore -q -- .env"),
            "{err:?}"
        );
        let err = is_tracked(dir.path(), Path::new(".env")).unwrap_err();
        assert!(matches!(err, GitError::Failed { .. }), "{err:?}");
        assert!(matches!(
            ensure_env_ignored(dir.path()).unwrap_err(),
            GitError::Failed { .. }
        ));
        assert!(matches!(
            require_env_ignored(dir.path()).unwrap_err(),
            GitError::Failed { .. }
        ));
    }

    #[test]
    fn path_outside_repo_is_an_error() {
        let r = repo();
        let err = is_ignored(r.path(), Path::new("/etc/passwd")).unwrap_err();
        assert!(matches!(err, GitError::Failed { .. }), "{err:?}");
    }

    #[test]
    fn ensure_creates_gitignore() {
        let r = repo();
        assert!(matches!(
            require_env_ignored(r.path()).unwrap_err(),
            GitError::EnvNotIgnored
        ));
        assert_eq!(ensure_env_ignored(r.path()).unwrap(), IgnoreOutcome::Added);
        assert_eq!(gitignore(r.path()), "/.env\n");
        require_env_ignored(r.path()).unwrap();
        // Idempotent.
        assert_eq!(
            ensure_env_ignored(r.path()).unwrap(),
            IgnoreOutcome::AlreadyIgnored
        );
        assert_eq!(gitignore(r.path()), "/.env\n");
    }

    #[test]
    fn ensure_appends_preserving_contents() {
        for (before, after) in [
            ("target\n", "target\n/.env\n"),
            ("target", "target\n/.env\n"),
            ("", "/.env\n"),
            ("a\r\nb\r\n", "a\r\nb\r\n/.env\n"),
            ("a\r\nb", "a\r\nb\n/.env\n"),
        ] {
            let r = repo();
            write(r.path(), ".gitignore", before);
            assert_eq!(ensure_env_ignored(r.path()).unwrap(), IgnoreOutcome::Added);
            assert_eq!(gitignore(r.path()), after, "{before:?}");
            require_env_ignored(r.path()).unwrap();
        }
    }

    #[test]
    fn ensure_respects_existing_rules() {
        for rules in ["/.env\n", ".env", "*.env\n", ".*\n"] {
            let r = repo();
            write(r.path(), ".gitignore", rules);
            assert_eq!(
                ensure_env_ignored(r.path()).unwrap(),
                IgnoreOutcome::AlreadyIgnored,
                "{rules:?}"
            );
            assert_eq!(gitignore(r.path()), rules);
        }
        // Rules in .git/info/exclude count too.
        let r = repo();
        write(r.path(), ".git/info/exclude", ".env\n");
        assert_eq!(
            ensure_env_ignored(r.path()).unwrap(),
            IgnoreOutcome::AlreadyIgnored
        );
        assert!(!r.path().join(GITIGNORE).exists());
    }

    #[test]
    fn ensure_overrides_earlier_negation() {
        // `!.env` earlier in the same file: git's last-match-wins means the
        // appended `/.env` takes effect.
        let r = repo();
        write(r.path(), ".gitignore", "*.env\n!.env\n");
        assert!(!is_ignored(r.path(), Path::new(".env")).unwrap());
        assert_eq!(ensure_env_ignored(r.path()).unwrap(), IgnoreOutcome::Added);
        assert_eq!(gitignore(r.path()), "*.env\n!.env\n/.env\n");
        require_env_ignored(r.path()).unwrap();
    }

    #[test]
    fn ensure_refuses_tracked_env() {
        let r = repo();
        write(r.path(), ".env", "A=1\n");
        sh_git(r.path(), &["add", ".env"]);
        // Even with an ignore rule: tracked files are committed regardless.
        write(r.path(), ".gitignore", "/.env\n");
        let err = ensure_env_ignored(r.path()).unwrap_err();
        assert!(matches!(err, GitError::EnvTracked), "{err:?}");
        assert!(err.to_string().contains("git rm --cached .env"));
        let err = require_env_ignored(r.path()).unwrap_err();
        assert!(matches!(err, GitError::EnvTracked), "{err:?}");
        assert_eq!(gitignore(r.path()), "/.env\n");
        assert!(!err.to_string().contains("A=1"));
    }

    #[cfg(unix)]
    #[test]
    fn ensure_refuses_symlinked_gitignore() {
        let r = repo();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("ignore");
        fs::write(&target, "x\n").unwrap();
        std::os::unix::fs::symlink(&target, r.path().join(GITIGNORE)).unwrap();
        let err = ensure_env_ignored(r.path()).unwrap_err();
        assert!(matches!(err, GitError::GitignoreSymlink { .. }), "{err:?}");
        assert!(err.to_string().contains("symlink"));
        assert_eq!(fs::read_to_string(&target).unwrap(), "x\n");
    }

    #[test]
    fn ensure_reports_unreadable_gitignore() {
        let r = repo();
        fs::create_dir(r.path().join(GITIGNORE)).unwrap();
        let err = ensure_env_ignored(r.path()).unwrap_err();
        assert!(
            matches!(&err, GitError::Io { path, .. } if path == &r.path().join(GITIGNORE)),
            "{err:?}"
        );
        assert!(err.to_string().contains(".gitignore"));
    }

    /// A git stand-in whose `ls-files` lists nothing and whose
    /// `check-ignore` always says "not ignored": the only way to reach the
    /// defensive re-check failure, because with real git a rule appended to
    /// the root `.gitignore` always wins for the root `.env` (last match
    /// wins, and the root file is the most specific one).
    #[cfg(unix)]
    #[test]
    fn ensure_detects_ineffective_append() {
        let fake =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-git-never-ignores");
        let dir = tempfile::tempdir().unwrap();
        let err = ensure_env_ignored_with(fake.as_os_str(), dir.path()).unwrap_err();
        assert!(
            matches!(&err, GitError::StillNotIgnored { path } if path == &dir.path().join(GITIGNORE)),
            "{err:?}"
        );
        assert!(err.to_string().contains("still does not ignore"));
        // The line is left in place for the user to inspect.
        assert_eq!(gitignore(dir.path()), "/.env\n");
    }

    /// `check-ignore` failing after `ls-files` succeeded, before and after
    /// the append: with real git both run against the same repo, so they
    /// can't be made to disagree.
    #[cfg(unix)]
    #[test]
    fn ignore_check_failure_after_tracked_check() {
        let fake = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/fake-git-check-ignore-fails");
        let fake = fake.as_os_str();
        let is_check_ignore_failure = |err: &GitError| {
            matches!(err, GitError::Failed { command, stderr, .. }
                if command == "check-ignore -q -- .env" && stderr.contains("simulated"))
        };
        // No .gitignore: the first check says "not ignored", lst appends,
        // the re-check fails.
        let dir = tempfile::tempdir().unwrap();
        let err = ensure_env_ignored_with(fake, dir.path()).unwrap_err();
        assert!(is_check_ignore_failure(&err), "{err:?}");
        assert_eq!(gitignore(dir.path()), "/.env\n");
        // With a .gitignore the first check fails already.
        let err = ensure_env_ignored_with(fake, dir.path()).unwrap_err();
        assert!(is_check_ignore_failure(&err), "{err:?}");
        assert_eq!(gitignore(dir.path()), "/.env\n");
        let err = require_env_ignored_with(fake, dir.path()).unwrap_err();
        assert!(is_check_ignore_failure(&err), "{err:?}");
    }

    // ---- index layer ------------------------------------------------------

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }

    /// Runs real git in `dir` for test setup and returns its stdout.
    fn git_out(dir: &Path, args: &[&str]) -> Vec<u8> {
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}: {out:?}");
        out.stdout
    }

    fn git_str(dir: &Path, args: &[&str]) -> String {
        String::from_utf8(git_out(dir, args)).unwrap()
    }

    /// Like `repo()`, with a local identity, no signing, and one commit.
    fn committed_repo() -> TempDir {
        let r = repo();
        for (k, v) in [
            ("user.name", "lst test"),
            ("user.email", "test@example.invalid"),
            ("commit.gpgsign", "false"),
        ] {
            sh_git(r.path(), &["config", k, v]);
        }
        sh_git(r.path(), &["commit", "-q", "--allow-empty", "-m", "init"]);
        r
    }

    fn entry(mode: &str, oid: &str, path: &str) -> IndexEntry {
        IndexEntry {
            mode: mode.into(),
            oid: oid.into(),
            path: path.into(),
        }
    }

    /// The index as `(mode, path)` pairs, straight from git.
    fn index_modes(root: &Path) -> Vec<(String, String)> {
        staged_entries(root, "")
            .unwrap()
            .into_iter()
            .map(|e| (e.mode, e.path))
            .collect()
    }

    const OID_A: &str = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391";

    #[test]
    fn oid_shape() {
        assert!(is_oid(OID_A));
        assert!(is_oid(&"0123456789abcdef".repeat(4)));
        assert!(!is_oid(&OID_A[1..]));
        assert!(!is_oid(&OID_A.to_uppercase()));
        assert!(!is_oid(&format!("{}g", &OID_A[1..])));
        assert!(!is_oid(""));
    }

    #[test]
    fn parse_stage_output() {
        let args = [OsStr::new("ls-files")];
        assert_eq!(parse_stage_entries(&args, b"").unwrap(), vec![]);
        let out =
            format!("100755 {OID_A} 0\tz/run.sh\0100644 {OID_A} 0\ta\tb\nc\0120000 {OID_A} 0\tl\0");
        assert_eq!(
            parse_stage_entries(&args, out.as_bytes()).unwrap(),
            vec![
                entry("100644", OID_A, "a\tb\nc"),
                entry("120000", OID_A, "l"),
                entry("100755", OID_A, "z/run.sh"),
            ]
        );
        for bad in [
            "garbage".to_owned(),
            format!("100644 {OID_A} 0\ta"),
            format!("100644 {OID_A} 0 a\0"),
            format!("100644 {OID_A}\ta\0"),
            format!("100644 {OID_A} 0 x\ta\0"),
            format!(" {OID_A} 0\ta\0"),
            format!("10064x {OID_A} 0\ta\0"),
            "100644 abc 0\ta\0".to_owned(),
            format!("100644 {OID_A} 4\ta\0"),
            format!("100644 {OID_A} 0\t\0"),
            format!("100644 {OID_A} 0\ta\0\0"),
        ] {
            let err = parse_stage_entries(&args, bad.as_bytes()).unwrap_err();
            assert!(
                matches!(&err, GitError::BadOutput { command } if command == "ls-files"),
                "{bad:?}: {err:?}"
            );
            assert_eq!(
                err.to_string(),
                "`git ls-files` printed output lst could not parse"
            );
        }
        let mut meta_not_utf8 = b"10064\xff ".to_vec();
        meta_not_utf8.extend_from_slice(format!("{OID_A} 0\ta\0").as_bytes());
        assert!(matches!(
            parse_stage_entries(&args, &meta_not_utf8).unwrap_err(),
            GitError::BadOutput { .. }
        ));
        let out = format!(
            "100644 {OID_A} 0\tok\0100644 {OID_A} 2\tz\0100644 {OID_A} 1\ty\0100644 {OID_A} 3\ty\0"
        );
        let err = parse_stage_entries(&args, out.as_bytes()).unwrap_err();
        assert!(
            matches!(&err, GitError::Unmerged { path } if path == "y"),
            "{err:?}"
        );
        assert!(err.to_string().contains("y has unresolved merge conflicts"));
    }

    #[test]
    fn is_file_by_mode() {
        assert!(entry("100644", OID_A, "a").is_file());
        assert!(entry("100755", OID_A, "a").is_file());
        assert!(!entry("120000", OID_A, "a").is_file());
        assert!(!entry("160000", OID_A, "a").is_file());
    }

    #[test]
    fn staged_entries_lists_index_not_worktree() {
        let r = repo();
        let root = r.path();
        assert_eq!(staged_entries(root, "").unwrap(), vec![]);
        write(root, "stacks/b/compose.yaml", "b");
        write(root, "stacks/a/compose.yaml", "a");
        write(root, "stacks/a/conf/x.conf", "x");
        write(root, "stacksfoo", "no");
        write(root, "README", "r");
        sh_git(root, &["add", "."]);
        write(root, "stacks/a/untracked", "u");
        write(root, "stacks/a/compose.yaml", "changed but not staged");

        let got = staged_entries(root, "stacks").unwrap();
        let paths: Vec<_> = got.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "stacks/a/compose.yaml",
                "stacks/a/conf/x.conf",
                "stacks/b/compose.yaml"
            ]
        );
        assert!(got.iter().all(|e| e.mode == "100644" && is_oid(&e.oid)));
        assert_eq!(&*read_blob(root, &got[0].oid).unwrap(), b"a");
        assert_eq!(staged_entries(root, "stacks/").unwrap(), got);
        assert_eq!(staged_entries(root, "").unwrap().len(), 5);
        // Literal: a glob character matches nothing.
        assert_eq!(staged_entries(root, "stacks/*").unwrap(), vec![]);
        assert_eq!(staged_entries(root, "missing").unwrap(), vec![]);
    }

    #[test]
    fn awkward_paths_round_trip() {
        let r = repo();
        let root = r.path();
        let names = [
            "stacks/a, b/compose.yaml",
            "stacks/new\nline",
            "stacks/tab\there",
            "stacks/ünïcødé 码",
            "stacks/--",
            "stacks/-x",
            "stacks/\"quoted\" \\back",
        ];
        for n in names {
            write(root, n, "old");
        }
        sh_git(root, &["add", "--", "stacks"]);
        let got = staged_entries(root, "stacks").unwrap();
        let mut want: Vec<_> = names.iter().map(|n| n.to_string()).collect();
        want.sort();
        assert_eq!(got.iter().map(|e| e.path.clone()).collect::<Vec<_>>(), want);
        let oid = write_blob(root, b"new").unwrap();
        for e in &got {
            update_index(root, &e.mode, &oid, &e.path).unwrap();
        }
        for e in staged_entries(root, "stacks").unwrap() {
            assert_eq!(e.oid, oid, "{:?}", e.path);
            assert_eq!(fs::read(root.join(&e.path)).unwrap(), b"old");
        }
    }

    #[cfg(unix)]
    #[test]
    fn staged_entries_non_utf8_path() {
        use std::os::unix::ffi::OsStrExt;
        let r = repo();
        fs::write(r.path().join(OsStr::from_bytes(b"bad-\xff")), "x").unwrap();
        sh_git(r.path(), &["add", "."]);
        let err = staged_entries(r.path(), "").unwrap_err();
        assert!(
            matches!(&err, GitError::NonUtf8IndexPath { lossy } if lossy == "bad-\u{fffd}"),
            "{err:?}"
        );
        assert!(err.to_string().contains("not valid UTF-8"));
        // Scoped to a prefix that excludes it, the rest still works.
        write(r.path(), "stacks/a", "a");
        sh_git(r.path(), &["add", "stacks"]);
        assert_eq!(staged_entries(r.path(), "stacks").unwrap().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_and_gitlink_are_reported() {
        let r = committed_repo();
        let root = r.path();
        let head = git_str(root, &["rev-parse", "HEAD"]);
        let head = head.trim_end();
        write(root, "stacks/a/compose.yaml", "c");
        std::os::unix::fs::symlink("compose.yaml", root.join("stacks/a/link")).unwrap();
        sh_git(root, &["add", "stacks"]);
        sh_git(
            root,
            &[
                "update-index",
                "--add",
                "--cacheinfo",
                "160000",
                head,
                "stacks/a/sub",
            ],
        );
        let got = staged_entries(root, "stacks").unwrap();
        assert_eq!(
            got.iter()
                .map(|e| (e.mode.as_str(), e.path.as_str(), e.is_file()))
                .collect::<Vec<_>>(),
            [
                ("100644", "stacks/a/compose.yaml", true),
                ("120000", "stacks/a/link", false),
                ("160000", "stacks/a/sub", false),
            ]
        );
        assert_eq!(got[2].oid, head);
        // A symlink's blob is its target; a gitlink has no blob to read.
        assert_eq!(&*read_blob(root, &got[1].oid).unwrap(), b"compose.yaml");
        let err = read_blob(root, &got[2].oid).unwrap_err();
        assert!(
            matches!(&err, GitError::Failed { command, .. }
                if *command == format!("cat-file blob {head}")),
            "{err:?}"
        );
    }

    #[test]
    fn unmerged_entries_block() {
        let r = committed_repo();
        let root = r.path();
        write(root, "stacks/a/compose.yaml", "base\n");
        write(root, "stacks/a/other", "fine\n");
        sh_git(root, &["add", "."]);
        sh_git(root, &["commit", "-q", "-m", "base"]);
        sh_git(root, &["checkout", "-q", "-b", "side"]);
        write(root, "stacks/a/compose.yaml", "side\n");
        sh_git(root, &["commit", "-q", "-am", "side"]);
        sh_git(root, &["checkout", "-q", "-"]);
        write(root, "stacks/a/compose.yaml", "main\n");
        sh_git(root, &["commit", "-q", "-am", "main"]);
        let st = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["merge", "-q", "side"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(!st.success(), "the merge must conflict");

        for prefix in ["", "stacks", "stacks/a/compose.yaml"] {
            let err = staged_entries(root, prefix).unwrap_err();
            assert!(
                matches!(&err, GitError::Unmerged { path } if path == "stacks/a/compose.yaml"),
                "{prefix:?}: {err:?}"
            );
        }
        // Outside the conflict the index is readable.
        assert_eq!(staged_entries(root, "stacks/a/other").unwrap().len(), 1);
    }

    #[test]
    fn partial_staging_is_preserved() {
        let r = committed_repo();
        let root = r.path();
        write(root, "f", "line1\n");
        sh_git(root, &["add", "f"]);
        sh_git(root, &["commit", "-q", "-m", "f"]);
        // Staged: a change to line1. Working tree: that plus an unstaged line.
        write(root, "f", "line1 <<set:x:v>>\n");
        sh_git(root, &["add", "f"]);
        write(root, "f", "line1 <<set:x:v>>\nwip\n");

        let [e] = staged_entries(root, "f").unwrap().try_into().unwrap();
        let staged = read_blob(root, &e.oid).unwrap();
        assert_eq!(&*staged, b"line1 <<set:x:v>>\n");
        let oid = write_blob(root, b"line1 <<secret:x>>\n").unwrap();
        update_index(root, &e.mode, &oid, &e.path).unwrap();

        assert_eq!(
            fs::read(root.join("f")).unwrap(),
            b"line1 <<set:x:v>>\nwip\n"
        );
        assert_eq!(git_str(root, &["show", ":f"]), "line1 <<secret:x>>\n");
        let cached = git_str(root, &["diff", "--cached", "--no-color"]);
        assert!(cached.contains("-line1\n+line1 <<secret:x>>\n"), "{cached}");
        assert!(!cached.contains("set:"), "{cached}");
        let unstaged = git_str(root, &["diff", "--no-color"]);
        assert!(
            unstaged.contains("-line1 <<secret:x>>\n+line1 <<set:x:v>>\n+wip\n"),
            "{unstaged}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn exec_bit_survives_rewrite() {
        use std::os::unix::fs::PermissionsExt;
        let r = repo();
        let root = r.path();
        write(root, "stacks/a/run.sh", "#!/bin/sh\n<<set:x:v>>\n");
        fs::set_permissions(
            root.join("stacks/a/run.sh"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        sh_git(root, &["add", "stacks"]);
        let [e] = staged_entries(root, "stacks").unwrap().try_into().unwrap();
        assert_eq!(e.mode, "100755");
        let oid = write_blob(root, b"#!/bin/sh\n<<secret:x>>\n").unwrap();
        update_index(root, &e.mode, &oid, &e.path).unwrap();
        assert_eq!(
            staged_entries(root, "stacks").unwrap(),
            vec![entry("100755", &oid, "stacks/a/run.sh")]
        );
    }

    #[test]
    fn update_index_refuses_unknown_path() {
        let r = repo();
        let oid = write_blob(r.path(), b"x").unwrap();
        let err = update_index(r.path(), "100644", &oid, "not-staged").unwrap_err();
        assert!(
            matches!(&err, GitError::Failed { command, stderr, .. }
                if *command == format!("update-index --cacheinfo 100644 {oid} not-staged")
                    && stderr.contains("--add")),
            "{err:?}"
        );
        assert_eq!(staged_entries(r.path(), "").unwrap(), vec![]);
    }

    #[test]
    fn blob_round_trip_binary_and_large() {
        let r = repo();
        let root = r.path();
        let small: Vec<u8> = (0..=255u8).chain([0, 0, b'\n', 0xff]).collect();
        // Larger than any pipe buffer, so stdin really streams.
        let large: Vec<u8> = (0..3 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        for bytes in [Vec::new(), small, large] {
            let oid = write_blob(root, &bytes).unwrap();
            assert!(is_oid(&oid), "{oid:?}");
            assert_eq!(git_str(root, &["cat-file", "-t", &oid]), "blob\n");
            assert!(*read_blob(root, &oid).unwrap() == bytes);
        }
        // Deterministic: the empty blob's well-known id.
        assert_eq!(write_blob(root, b"").unwrap(), OID_A);
    }

    #[test]
    fn read_blob_errors_never_carry_content() {
        let r = repo();
        let root = r.path();
        let err = read_blob(root, OID_A).unwrap_err();
        assert!(matches!(err, GitError::Failed { .. }), "{err:?}");
        // A tree is not a blob; nothing of what git might print leaks.
        write(root, "d/secret", "hunter2");
        sh_git(root, &["add", "d"]);
        let tree = git_str(root, &["write-tree"]);
        let err = read_blob(root, tree.trim_end()).unwrap_err();
        assert!(matches!(err, GitError::Failed { .. }), "{err:?}");
        assert!(!format!("{err} {err:?}").contains("hunter2"));
    }

    #[test]
    fn alternate_index_file_is_honoured() {
        let r = committed_repo();
        let root = r.path();
        let alt = fixture("git-alt-index");
        let alt = alt.as_os_str();
        write(root, "stacks/a/compose.yaml", "main index\n");
        sh_git(root, &["add", "stacks"]);
        // Seed the alternate index the way `git commit -a` would: from the
        // main one, plus the working-tree change.
        fs::copy(root.join(".git/index"), root.join(".git/alt-index")).unwrap();
        write(root, "stacks/a/compose.yaml", "<<set:x:v>>\n");
        write(root, ".sec/a.toml", "store\n");
        update_index_with(
            alt,
            root,
            "100644",
            &write_blob_with(alt, root, b"<<set:x:v>>\n").unwrap(),
            "stacks/a/compose.yaml",
        )
        .unwrap();
        let main_before = fs::read(root.join(".git/index")).unwrap();

        let [e] = staged_entries_with(alt, root, "stacks")
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            &*read_blob_with(alt, root, &e.oid).unwrap(),
            b"<<set:x:v>>\n"
        );
        let oid = write_blob_with(alt, root, b"<<secret:x>>\n").unwrap();
        update_index_with(alt, root, &e.mode, &oid, &e.path).unwrap();
        add_with(alt, root, Path::new(".sec")).unwrap();

        assert_eq!(
            staged_entries_with(alt, root, "")
                .unwrap()
                .iter()
                .map(|e| e.path.as_str())
                .collect::<Vec<_>>(),
            [".sec/a.toml", "stacks/a/compose.yaml"]
        );
        assert_eq!(
            staged_entries_with(alt, root, "stacks").unwrap()[0].oid,
            oid
        );
        // The main index is untouched.
        assert_eq!(fs::read(root.join(".git/index")).unwrap(), main_before);
        assert_eq!(
            git_str(root, &["show", ":stacks/a/compose.yaml"]),
            "main index\n"
        );
        assert_eq!(index_modes(root).len(), 1);
    }

    #[test]
    fn add_stages_new_changed_and_deleted() {
        let r = committed_repo();
        let root = r.path();
        write(root, ".sec/a.toml", "a1\n");
        write(root, ".sec/b.toml", "b1\n");
        write(root, "outside", "o1\n");
        sh_git(root, &["add", "."]);
        sh_git(root, &["commit", "-q", "-m", "store"]);
        write(root, ".sec/a.toml", "a2\n");
        fs::remove_file(root.join(".sec/b.toml")).unwrap();
        write(root, ".sec/c d.toml", "c1\n");
        write(root, "outside", "o2\n");

        add(root, Path::new(".sec")).unwrap();
        assert_eq!(
            git_str(root, &["diff", "--cached", "--name-status"]),
            "M\t.sec/a.toml\nD\t.sec/b.toml\nA\t.sec/c d.toml\n"
        );
        // Idempotent; and with everything under it deleted it stages that.
        add(root, Path::new(".sec")).unwrap();
        fs::remove_dir_all(root.join(".sec")).unwrap();
        add(root, Path::new(".sec")).unwrap();
        assert_eq!(index_modes(root), [("100644".into(), "outside".into())]);
    }

    #[test]
    fn add_failures() {
        let r = repo();
        let root = r.path();
        let err = add(root, Path::new(".sec")).unwrap_err();
        assert!(
            matches!(&err, GitError::Failed { command, stderr, .. }
                if command == "--literal-pathspecs add -A -- .sec"
                    && stderr.contains("did not match")),
            "{err:?}"
        );
        // Ignored paths are refused, not silently skipped.
        write(root, ".gitignore", ".sec/\n");
        write(root, ".sec/a.toml", "a\n");
        assert!(matches!(
            add(root, Path::new(".sec")).unwrap_err(),
            GitError::Failed { .. }
        ));
        // Literal pathspec: `*` is not a glob.
        assert!(matches!(
            add(root, Path::new("*")).unwrap_err(),
            GitError::Failed { .. }
        ));
    }

    #[test]
    fn hooks_dir_default_and_configured() {
        let r = repo();
        let root = r.path();
        assert_eq!(hooks_dir(root).unwrap(), root.join(".git/hooks"));
        sh_git(root, &["config", "core.hooksPath", "tools/hooks"]);
        assert_eq!(hooks_dir(root).unwrap(), root.join("tools/hooks"));
        let abs = tempfile::tempdir().unwrap();
        let abs_str = abs.path().to_str().unwrap();
        sh_git(root, &["config", "core.hooksPath", abs_str]);
        assert_eq!(hooks_dir(root).unwrap(), abs.path());
    }

    #[test]
    fn hooks_dir_in_linked_worktree() {
        let r = committed_repo();
        let root = r.path();
        let outer = tempfile::tempdir().unwrap();
        let wt = outer.path().join("wt");
        sh_git(
            root,
            &["worktree", "add", "-q", "--detach", wt.to_str().unwrap()],
        );
        let got = hooks_dir(&wt).unwrap();
        assert_eq!(
            got.canonicalize().unwrap(),
            root.join(".git/hooks").canonicalize().unwrap()
        );
        // A relative core.hooksPath is relative to the worktree's top level.
        sh_git(root, &["config", "core.hooksPath", "h"]);
        assert_eq!(hooks_dir(&wt).unwrap(), wt.join("h"));
    }

    #[cfg(unix)]
    #[test]
    fn hooks_dir_non_utf8() {
        use std::os::unix::ffi::OsStrExt;
        let r = repo();
        let st = Command::new("git")
            .arg("-C")
            .arg(r.path())
            .args(["config", "core.hooksPath"])
            .arg(OsStr::from_bytes(b"/tmp/hooks-\xff"))
            .status()
            .unwrap();
        assert!(st.success());
        assert!(matches!(
            hooks_dir(r.path()).unwrap_err(),
            GitError::NonUtf8Path
        ));
    }

    #[test]
    fn index_layer_fails_outside_a_repo() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let expect_failed = |err: GitError, want: &str| {
            assert!(
                matches!(&err, GitError::Failed { command, .. } if command.starts_with(want)),
                "{want}: {err:?}"
            );
        };
        expect_failed(
            staged_entries(root, "stacks").unwrap_err(),
            "--literal-pathspecs ls-files -s -z -- stacks",
        );
        expect_failed(
            staged_entries(root, "").unwrap_err(),
            "--literal-pathspecs ls-files -s -z",
        );
        expect_failed(read_blob(root, OID_A).unwrap_err(), "cat-file blob");
        // Large enough that git exits before reading it all: the exit status
        // wins over the broken pipe.
        expect_failed(
            write_blob(root, &vec![b'x'; 1 << 20]).unwrap_err(),
            "hash-object -w --stdin",
        );
        expect_failed(write_blob(root, b"x").unwrap_err(), "hash-object");
        expect_failed(
            update_index(root, "100644", OID_A, "f").unwrap_err(),
            "update-index --cacheinfo",
        );
        expect_failed(
            add(root, Path::new("f")).unwrap_err(),
            "--literal-pathspecs add -A",
        );
        expect_failed(hooks_dir(root).unwrap_err(), "rev-parse --git-path hooks");
    }

    #[test]
    fn index_layer_spawn_failures() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let missing = dir.path().join("no-such-git");
        let m = missing.as_os_str();
        for err in [
            staged_entries_with(m, root, "").unwrap_err(),
            read_blob_with(m, root, OID_A).unwrap_err(),
            write_blob_with(m, root, b"x").unwrap_err(),
            update_index_with(m, root, "100644", OID_A, "f").unwrap_err(),
            add_with(m, root, Path::new("f")).unwrap_err(),
            hooks_dir_with(m, root).unwrap_err(),
        ] {
            assert!(matches!(err, GitError::Spawn(_)), "{err:?}");
        }
    }

    /// git stand-ins that exit 0 with output lst can't use.
    #[cfg(unix)]
    #[test]
    fn index_layer_rejects_unusable_output() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let garbage = fixture("fake-git-garbage");
        let g = garbage.as_os_str();
        let err = staged_entries_with(g, root, "").unwrap_err();
        assert!(
            matches!(&err, GitError::BadOutput { command }
                if command == "--literal-pathspecs ls-files -s -z"),
            "{err:?}"
        );
        let err = write_blob_with(g, root, b"x").unwrap_err();
        assert!(
            matches!(&err, GitError::BadOutput { command } if command == "hash-object -w --stdin"),
            "{err:?}"
        );
        // `true` prints nothing.
        let t = OsStr::new("true");
        let err = hooks_dir_with(t, root).unwrap_err();
        assert!(
            matches!(&err, GitError::BadOutput { command } if command == "rev-parse --git-path hooks"),
            "{err:?}"
        );
        assert_eq!(staged_entries_with(t, root, "").unwrap(), vec![]);
        // `true` also exits 0 without reading stdin: a blob it never saw
        // must not come back as stored.
        let err = write_blob_with(t, root, &vec![b'x'; 1 << 20]).unwrap_err();
        assert!(
            matches!(&err, GitError::Stdin { command, source }
                if command == "hash-object -w --stdin"
                    && source.kind() == io::ErrorKind::BrokenPipe),
            "{err:?}"
        );
        assert!(err.to_string().contains("could not send data"));
        // The non-UTF-8 repo-path error comes from the same line parser.
        assert!(matches!(
            path_line(b"\xff\n".to_vec()).unwrap_err(),
            GitError::NonUtf8Path
        ));
    }
}
