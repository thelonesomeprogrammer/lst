//! `lst` CLI. Stub until M1 (`init` + `render`).
#![forbid(unsafe_code)]

fn main() {
    eprintln!(
        "lst {}: no commands yet (M0 is the core library only)",
        env!("CARGO_PKG_VERSION")
    );
    std::process::exit(2);
}
