//! `lst get --copy`: hand a value to the desktop's clipboard tool.
//!
//! No clipboard crate: like `git` and `docker`, the tool is run with
//! [`std::process::Command`] and the value goes in on its stdin (never as
//! an argument, which `ps` would show). The tools are tried in order; one
//! that isn't installed or exits non-zero (e.g. `wl-copy` outside Wayland)
//! is skipped.

use std::io::{self, Write};
use std::process::{Command, Stdio};

/// The tools tried, in order, with their arguments.
pub const TOOLS: &[(&str, &[&str])] = &[
    ("wl-copy", &[]),
    ("xclip", &["-selection", "clipboard"]),
    ("xsel", &["--clipboard", "--input"]),
    ("pbcopy", &[]),
];

#[derive(Debug, thiserror::Error)]
pub enum ClipboardError {
    #[error(
        "no clipboard tool worked (tried {}); install one, or run without --copy",
        names()
    )]
    NoTool,
}

fn names() -> String {
    TOOLS
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Copies `value` with the first tool that accepts it; returns its name.
///
/// The tool's stdout and stderr go to `/dev/null`: `xclip` and `wl-copy`
/// stay in the background to serve the selection, and a pipe they inherit
/// would keep lst waiting.
pub fn copy(value: &str) -> Result<&'static str, ClipboardError> {
    for (name, args) in TOOLS {
        if try_tool(name, args, value).is_ok_and(|ok| ok) {
            return Ok(name);
        }
    }
    Err(ClipboardError::NoTool)
}

fn try_tool(name: &str, args: &[&str], value: &str) -> io::Result<bool> {
    let mut child = Command::new(name)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let written = match child.stdin.take() {
        // Dropping stdin closes it, so the tool sees end of input.
        Some(mut stdin) => stdin.write_all(value.as_bytes()),
        None => Ok(()),
    };
    let status = child.wait()?;
    Ok(written.is_ok() && status.success())
}
