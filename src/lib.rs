//! `lst` (Lazy Secret Tool): fills secret markers in Docker Compose files
//! with seed-derived or encrypted values at deploy time.
//!
//! `marker`, `crypto`, `format` and `envfile` are pure (no filesystem,
//! subprocesses or environment variables; `crypto` only uses the OS random
//! generator). `git` and `stack` do the I/O.
#![forbid(unsafe_code)]

pub mod crypto;
pub mod envfile;
pub mod format;
pub mod git;
pub mod marker;
pub mod stack;
