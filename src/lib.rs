//! `lst` (Lazy Secret Tool): fills secret markers in Docker Compose files
//! with seed-derived or encrypted values at deploy time.
//!
//! `marker`, `crypto` and `format` are pure (no filesystem, subprocesses or
//! environment variables; `crypto` only uses the OS random generator).
#![forbid(unsafe_code)]

pub mod crypto;
pub mod format;
pub mod marker;
