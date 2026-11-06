//! `lst` (Lazy Secret Tool): fills secret markers in Docker Compose files
//! with seed-derived or encrypted values at deploy time.
//!
//! `marker`, `crypto`, `format`, `envfile` and `render` are pure (no filesystem,
//! subprocesses or environment variables; `crypto` only uses the OS random
//! generator). `git`, `stack`, `store::{load, save}` and `cli` (the commands
//! behind the binary) do the I/O.
#![forbid(unsafe_code)]

pub mod cli;
pub mod crypto;
pub mod envfile;
pub mod format;
pub mod git;
pub mod marker;
pub mod render;
pub mod stack;
pub mod store;
