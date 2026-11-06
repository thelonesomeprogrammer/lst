//! Shelling out to `git`: repository discovery and ignore/tracking checks.
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
//! ever contains paths and git's own messages, never file contents.

use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

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

fn failed(args: &[&OsStr], out: &Output) -> GitError {
    let command = args
        .iter()
        .map(|a| a.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    GitError::Failed {
        command,
        status: out.status.to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).trim_end().to_owned(),
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
        return Err(failed(&args, &out));
    }
    let mut stdout = out.stdout;
    if stdout.last() == Some(&b'\n') {
        stdout.pop();
    }
    let root = String::from_utf8(stdout).map_err(|_| GitError::NonUtf8Path)?;
    Ok(PathBuf::from(root))
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
        _ => Err(failed(&args, &out)),
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
        return Err(failed(&args, &out));
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
    let program = OsStr::new(GIT);
    let env = Path::new(ENV_FILE);
    if is_tracked_with(program, root, env)? {
        return Err(GitError::EnvTracked);
    }
    if !is_ignored_with(program, root, env)? {
        return Err(GitError::EnvNotIgnored);
    }
    Ok(())
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
}
