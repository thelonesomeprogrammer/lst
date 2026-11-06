//! The CLI is a stub until M1: it must refuse to do anything.

use std::process::Command;

#[test]
fn stub_cli_exits_with_usage_error() {
    let out = Command::new(env!("CARGO_BIN_EXE_lst")).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("no commands yet"));
}
