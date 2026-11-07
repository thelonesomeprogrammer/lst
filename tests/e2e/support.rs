//! Throwaway git repositories and a runner for the real `lst` binary.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use lst::crypto::{self, Seed};
use lst::envfile;
use lst::format::{self, Format};
use lst::store::Store;
use tempfile::TempDir;

/// What one `lst` run produced.
#[derive(Debug)]
pub struct Run {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl Run {
    pub fn from_output(out: Output) -> Run {
        Run {
            code: out.status.code(),
            stdout: String::from_utf8(out.stdout).unwrap(),
            stderr: String::from_utf8(out.stderr).unwrap(),
        }
    }

    /// Asserts exit code 0 and returns stdout.
    #[track_caller]
    pub fn ok(&self) -> &str {
        assert_eq!(self.code, Some(0), "{self:#?}");
        &self.stdout
    }

    /// Asserts exit code 1, empty stdout and that stderr contains every
    /// `needle`; returns stderr.
    #[track_caller]
    pub fn fails_with(&self, needles: &[&str]) -> &str {
        assert_eq!(self.code, Some(1), "{self:#?}");
        assert_eq!(self.stdout, "", "{self:#?}");
        assert!(self.stderr.starts_with("lst: "), "{self:#?}");
        for n in needles {
            assert!(self.stderr.contains(n), "missing {n:?} in {self:#?}");
        }
        &self.stderr
    }
}

/// A fresh repository in a temp dir, isolated from the user's global and
/// system git config (and so from their global excludes file).
pub struct Repo {
    dir: TempDir,
}

/// `git` with the user's global/system config switched off.
fn git_cmd() -> Command {
    let mut c = Command::new("git");
    c.env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1");
    c
}

impl Repo {
    pub fn new() -> Repo {
        let repo = Repo {
            dir: tempfile::tempdir().unwrap(),
        };
        repo.git(&["init", "-q"]);
        repo.git(&["config", "user.name", "lst test"]);
        repo.git(&["config", "user.email", "lst-test@example.invalid"]);
        repo.git(&["config", "core.excludesFile", "/dev/null"]);
        repo
    }

    /// A repository with `lst init` already run.
    pub fn initialised() -> Repo {
        let repo = Repo::new();
        repo.lst(&["init"]).ok();
        repo
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    pub fn git(&self, args: &[&str]) {
        let st = git_cmd()
            .arg("-C")
            .arg(self.path())
            .args(args)
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(st.success(), "git {args:?}");
    }

    pub fn write(&self, rel: &str, contents: impl AsRef<[u8]>) {
        let p = self.path().join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, contents).unwrap();
    }

    pub fn read(&self, rel: &str) -> String {
        fs::read_to_string(self.path().join(rel)).unwrap()
    }

    pub fn remove(&self, rel: &str) {
        fs::remove_file(self.path().join(rel)).unwrap();
    }

    pub fn exists(&self, rel: &str) -> bool {
        self.path().join(rel).exists()
    }

    pub fn compose(&self, stack: &str, contents: &str) {
        self.write(&format!("stacks/{stack}/compose.yaml"), contents);
    }

    /// `lst <args>` run in `cwd`, with stdout captured.
    pub fn lst_in(&self, cwd: &Path, args: &[&str]) -> Run {
        let out = lst_cmd(cwd, args).output().unwrap();
        Run::from_output(out)
    }

    pub fn lst(&self, args: &[&str]) -> Run {
        self.lst_in(self.path(), args)
    }

    /// `lst <args>` with `LST_SEED=<value>` in its environment (only in the
    /// child's: the test process's environment is never changed).
    pub fn lst_env(&self, args: &[&str], value: impl AsRef<OsStr>) -> Run {
        let out = lst_cmd(self.path(), args)
            .env("LST_SEED", value)
            .output()
            .unwrap();
        Run::from_output(out)
    }

    /// A `git clone` of this repository into a new temp dir, as CI checks
    /// it out: committed files only (no `.env`, no hooks), with a local
    /// identity for commits.
    pub fn clone_repo(&self) -> Repo {
        let repo = Repo {
            dir: tempfile::tempdir().unwrap(),
        };
        let st = git_cmd()
            .args(["clone", "-q"])
            .arg(self.path())
            .arg(repo.path())
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(st.success(), "git clone");
        repo.git(&["config", "user.name", "lst test"]);
        repo.git(&["config", "user.email", "lst-test@example.invalid"]);
        repo.git(&["config", "core.excludesFile", "/dev/null"]);
        repo
    }

    /// The seed in `.env`.
    pub fn seed(&self) -> Seed {
        envfile::parse_seed(&self.read(".env")).unwrap().unwrap()
    }

    pub fn seed_hex(&self) -> String {
        self.seed().to_hex().expose().to_owned()
    }

    pub fn store(&self) -> Store {
        Store::load(&self.path().join(".sec")).unwrap()
    }

    /// The value `<<gen:key:format>>` must render to in file `file` of
    /// `.sec/`, derived here from the seed and the stored id.
    pub fn expected_gen(&self, file: &str, key: &str, format: Format) -> String {
        let store = self.store();
        let entry = &store.files()[file].generated[key];
        assert_eq!(entry.format, format);
        let mut stream = crypto::derive_gen(&self.seed(), &entry.id);
        format::generate(format, &mut stream).expose().to_owned()
    }

    /// Every file outside `.git/` with its bytes.
    pub fn snapshot(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
            for entry in fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                let rel = path.strip_prefix(root).unwrap().to_owned();
                if rel == Path::new(".git") {
                    continue;
                }
                if path.is_dir() {
                    walk(root, &path, out);
                } else {
                    out.insert(rel, fs::read(&path).unwrap());
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(self.path(), self.path(), &mut out);
        out
    }
}

impl Repo {
    /// `git <args>` with its output captured and no assertion on the result.
    /// `path` replaces `PATH` if given; otherwise the directory of the `lst`
    /// under test is put in front of it, so git hooks find that binary
    /// (never a globally installed one).
    pub fn git_run(&self, args: &[&str], path: Option<&OsStr>) -> Run {
        let path = match path {
            Some(p) => p.to_owned(),
            None => path_with_lst(),
        };
        let out = git_cmd()
            .arg("-C")
            .arg(self.path())
            .args(args)
            .env("PATH", path)
            .env_remove("LST_SEED")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        Run::from_output(out)
    }

    /// `git <args>` that must succeed; returns its stdout.
    #[track_caller]
    pub fn git_stdout(&self, args: &[&str]) -> String {
        let run = self.git_run(args, None);
        assert_eq!(run.code, Some(0), "git {args:?}: {run:#?}");
        run.stdout
    }

    /// `git commit -q <args>`, with the hook finding the `lst` under test.
    pub fn commit(&self, args: &[&str]) -> Run {
        let mut all = vec!["commit", "-q"];
        all.extend_from_slice(args);
        self.git_run(&all, None)
    }

    /// `git commit -q <args>` with `LST_SEED=<seed_hex>` in git's (and so
    /// the hook's) environment.
    pub fn commit_env(&self, args: &[&str], seed_hex: &str) -> Run {
        let out = git_cmd()
            .arg("-C")
            .arg(self.path())
            .args(["commit", "-q"])
            .args(args)
            .env("PATH", path_with_lst())
            .env("LST_SEED", seed_hex)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        Run::from_output(out)
    }

    /// The number of commits on `HEAD`.
    pub fn commit_count(&self) -> usize {
        self.git_stdout(&["rev-list", "--count", "HEAD"])
            .trim()
            .parse()
            .unwrap()
    }

    /// `git show <rev>:<path>`.
    pub fn show(&self, rev_path: &str) -> String {
        self.git_stdout(&["show", rev_path])
    }
}

/// The directory holding the `lst` binary under test.
pub fn lst_dir() -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_lst"))
        .parent()
        .unwrap()
        .to_owned()
}

/// `PATH` with [`lst_dir`] in front.
pub fn path_with_lst() -> OsString {
    let mut dirs = vec![lst_dir()];
    dirs.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    std::env::join_paths(dirs).unwrap()
}

/// A `PATH` with git and a shell but no `lst`: the directory of the first
/// `git` on `PATH`, plus `/bin` and `/usr/bin`.
pub fn path_without_lst() -> OsString {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let git_dir = std::env::split_paths(&path)
        .find(|d| d.join("git").is_file())
        .unwrap();
    let dirs = [git_dir, PathBuf::from("/bin"), PathBuf::from("/usr/bin")];
    for d in &dirs {
        assert!(!d.join("lst").exists(), "{} has an lst", d.display());
    }
    std::env::join_paths(dirs).unwrap()
}

/// The real binary, with git's user/system config switched off and no
/// `LST_SEED` inherited from the test runner's environment.
pub fn lst_cmd(cwd: &Path, args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_lst"));
    c.current_dir(cwd)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("LST_SEED")
        .stdin(Stdio::null());
    c
}
