//! `lst` binary: parse arguments, run the command, map the result to an
//! exit code: 0 ok, 1 error, 2 usage error (clap's default).
#![forbid(unsafe_code)]

use std::io;
use std::process::ExitCode;

use anyhow::Context;
use clap::Parser;
use lst::cli::{self, Cli};

fn main() -> ExitCode {
    let args = Cli::parse();
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("lst: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Cli) -> anyhow::Result<()> {
    let cwd = std::env::current_dir().context("cannot determine the current directory")?;
    // The library errors already include their causes in their messages, so
    // they are flattened to one message rather than printed as a chain
    // (which would repeat each cause).
    cli::run(
        args,
        &cwd,
        std::env::var_os("LST_SEED"),
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))
}
