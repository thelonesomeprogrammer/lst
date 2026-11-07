//! `lst` (Lazy Secret Tool): fills secret markers in Docker Compose files
//! with seed-derived or encrypted values at deploy time.
//!
//! `marker`, `crypto`, `format`, `envfile`, `render`, `scan`, `hook`,
//! `check` and `deploy::affected_stacks` are pure (no filesystem,
//! subprocesses or environment variables; `crypto` only uses the OS random
//! generator). `git`, `stack`, `store::{load, read_files, save}`,
//! `deploy::run_compose` and `cli` (the commands behind the binary) do the
//! I/O.
#![forbid(unsafe_code)]

pub mod check;
pub mod cli;
pub mod crypto;
pub mod deploy;
pub mod envfile;
pub mod format;
pub mod git;
pub mod hook;
pub mod marker;
pub mod render;
pub mod scan;
pub mod stack;
pub mod store;
