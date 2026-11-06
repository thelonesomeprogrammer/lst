//! Reading and writing the seed line of `.env`. Pure: text in, text out.
//!
//! `.env` is a list of `KEY=VALUE` lines. `lst` owns exactly one of them,
//! `LST_SEED=<64 lowercase hex characters>`; every other line belongs to the
//! user (or to compose) and is never interpreted or changed.
//!
//! # Accepted syntax (deliberately strict)
//! - Lines are separated by `\n`; a trailing `\r` is stripped, so CRLF files
//!   work.
//! - Blank lines, `#` comment lines (`# LST_SEED=…` included) and lines with
//!   other keys are ignored.
//! - The seed line must be exactly `LST_SEED=<64 lowercase hex>`: no
//!   `export ` prefix, no whitespace anywhere, no quotes, no inline comment.
//! - A line that *looks like* a seed line but isn't exact (e.g.
//!   ` LST_SEED=…`, `export LST_SEED=…`, `LST_SEED = …`, `LST_SEED="…"`,
//!   `LST_SEED` without `=`) is an error, never silently skipped: skipping it
//!   would make `lst` report "no seed" and could lead to a second seed being
//!   created next to the real one.
//!
//! Errors carry line numbers (1-based) only, never line contents: `.env` may
//! hold other secrets besides the seed.

use crate::crypto::{SecretString, Seed};

const KEY: &str = "LST_SEED";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EnvError {
    #[error(
        ".env line {line}: the seed line must be exactly LST_SEED=<64 lowercase hex characters> \
         (no `export`, spaces or quotes)"
    )]
    Malformed { line: usize },
    #[error(".env line {line}: the LST_SEED value is not 64 lowercase hex characters")]
    InvalidSeed { line: usize },
    #[error(".env has more than one LST_SEED line (lines {first} and {second})")]
    Duplicate { first: usize, second: usize },
    #[error(".env already contains an LST_SEED line (line {line}); refusing to overwrite the seed")]
    AlreadyPresent { line: usize },
}

/// Lines of `text` with their 1-based number, `\r\n` / `\n` stripped.
fn lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.split('\n').enumerate().map(|(i, l)| {
        let l = l.strip_suffix('\r').unwrap_or(l);
        (i + 1, l)
    })
}

/// Whether `line` is (an attempt at) the seed line: after leading
/// whitespace / BOM and an optional `export` prefix it starts with
/// `LST_SEED` followed by `=`, whitespace or the end of the line.
fn is_seed_line(line: &str) -> bool {
    let l = line.trim_start_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
    let l = match l.strip_prefix("export") {
        Some(rest) if rest.starts_with(char::is_whitespace) => rest.trim_start(),
        _ => l,
    };
    match l.strip_prefix(KEY) {
        Some(rest) => {
            rest.is_empty() || rest.starts_with('=') || rest.starts_with(char::is_whitespace)
        }
        None => false,
    }
}

/// The 1-based number of the first seed line, if any.
fn first_seed_line(text: &str) -> Option<usize> {
    lines(text).find(|(_, l)| is_seed_line(l)).map(|(n, _)| n)
}

/// The seed stored in `.env`, or `None` if there is no `LST_SEED` line.
pub fn parse_seed(text: &str) -> Result<Option<Seed>, EnvError> {
    let mut found: Option<(usize, Seed)> = None;
    for (n, line) in lines(text) {
        if !is_seed_line(line) {
            continue;
        }
        if let Some((first, _)) = found {
            return Err(EnvError::Duplicate { first, second: n });
        }
        let value = line
            .strip_prefix(KEY)
            .and_then(|rest| rest.strip_prefix('='))
            .ok_or(EnvError::Malformed { line: n })?;
        if value.contains(|c: char| c.is_whitespace() || c == '"' || c == '\'') {
            return Err(EnvError::Malformed { line: n });
        }
        let seed = Seed::from_hex(value).map_err(|_| EnvError::InvalidSeed { line: n })?;
        found = Some((n, seed));
    }
    Ok(found.map(|(_, seed)| seed))
}

/// `text` with an `LST_SEED` line for `seed` appended. Every existing line
/// is kept byte-for-byte; a missing final newline is added first. The new
/// line ends in `\r\n` if the file already uses CRLF, else `\n`.
///
/// Fails if any seed line (well-formed or not) already exists: `init` must
/// never overwrite or shadow a seed.
pub fn with_seed(text: &str, seed: &Seed) -> Result<SecretString, EnvError> {
    if let Some(line) = first_seed_line(text) {
        return Err(EnvError::AlreadyPresent { line });
    }
    let eol = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let hex = seed.to_hex();
    let mut out = SecretString::new(String::with_capacity(
        text.len() + 2 * eol.len() + KEY.len() + 1 + hex.expose().len(),
    ));
    // Capacity is reserved up front so the buffer (which holds the seed)
    // never reallocates and leaves an unzeroized copy behind.
    let s = out.as_mut_string();
    s.push_str(text);
    if !text.is_empty() && !text.ends_with('\n') {
        s.push_str(eol);
    }
    s.push_str(KEY);
    s.push('=');
    s.push_str(hex.expose());
    s.push_str(eol);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    fn seed_bytes() -> [u8; 32] {
        std::array::from_fn(|i| i as u8)
    }

    fn parsed(text: &str) -> [u8; 32] {
        *parse_seed(text).unwrap().unwrap().as_bytes()
    }

    #[test]
    fn no_seed_line() {
        for text in [
            "",
            "\n",
            "\r\n\r\n",
            "FOO=bar\n",
            "# LST_SEED=nope\n",
            "  # LST_SEED=nope",
            "LST_SEEDS=abc\n",
            "MY_LST_SEED=abc\n",
            "exportLST_SEED=abc\n",
            "LST_SEED_OLD=abc",
        ] {
            assert!(parse_seed(text).unwrap().is_none(), "{text:?}");
        }
    }

    #[test]
    fn finds_seed_among_other_lines() {
        let text = format!("# comment\n\nA=1\nLST_SEED={HEX}\nB=\"two\"\n");
        assert_eq!(parsed(&text), seed_bytes());
        assert_eq!(parsed(&format!("LST_SEED={HEX}")), seed_bytes());
        let crlf = format!("# c\r\nA=1\r\n\r\nLST_SEED={HEX}\r\nB=2\r\n");
        assert_eq!(parsed(&crlf), seed_bytes());
        assert_eq!(parsed(&format!("LST_SEED={HEX}\r")), seed_bytes());
    }

    #[test]
    fn rejects_inexact_seed_lines() {
        for line in [
            format!(" LST_SEED={HEX}"),
            format!("\tLST_SEED={HEX}"),
            format!("\u{feff}LST_SEED={HEX}"),
            format!("export LST_SEED={HEX}"),
            format!("export\tLST_SEED={HEX}"),
            format!("LST_SEED ={HEX}"),
            format!("LST_SEED= {HEX}"),
            format!("LST_SEED={HEX} "),
            format!("LST_SEED={HEX} # comment"),
            format!("LST_SEED=\"{HEX}\""),
            format!("LST_SEED='{HEX}'"),
            "LST_SEED".to_owned(),
            "LST_SEED abc".to_owned(),
        ] {
            let text = format!("A=1\n{line}\nB=2\n");
            assert_eq!(
                parse_seed(&text).unwrap_err(),
                EnvError::Malformed { line: 2 },
                "{line:?}"
            );
        }
    }

    #[test]
    fn rejects_invalid_values() {
        for value in [
            String::new(),
            HEX.to_uppercase(),
            HEX[..62].to_owned(),
            format!("{HEX}00"),
            format!("{}g", &HEX[..63]),
            format!("{}#", &HEX[..63]),
        ] {
            let text = format!("LST_SEED={value}\n");
            assert_eq!(
                parse_seed(&text).unwrap_err(),
                EnvError::InvalidSeed { line: 1 },
                "{value:?}"
            );
        }
    }

    #[test]
    fn rejects_duplicates() {
        let text = format!("LST_SEED={HEX}\nA=1\nLST_SEED={HEX}\n");
        assert_eq!(
            parse_seed(&text).unwrap_err(),
            EnvError::Duplicate {
                first: 1,
                second: 3
            }
        );
        // A malformed second line still counts as a duplicate.
        let text = format!("LST_SEED={HEX}\r\nexport LST_SEED=x\r\n");
        assert_eq!(
            parse_seed(&text).unwrap_err(),
            EnvError::Duplicate {
                first: 1,
                second: 2
            }
        );
    }

    #[test]
    fn errors_never_contain_contents() {
        let text = format!("PASSWORD=hunter2\nLST_SEED= {HEX}\n");
        let err = parse_seed(&text).unwrap_err();
        let msg = format!("{err} {err:?}");
        assert!(!msg.contains("hunter2") && !msg.contains("0001020304"));
        for err in [
            EnvError::InvalidSeed { line: 1 },
            EnvError::Duplicate {
                first: 1,
                second: 2,
            },
            EnvError::AlreadyPresent { line: 1 },
        ] {
            assert!(err.to_string().contains("LST_SEED"));
        }
    }

    #[test]
    fn with_seed_appends() {
        let seed = Seed::from_bytes(seed_bytes());
        let line = format!("LST_SEED={HEX}\n");
        let cases = [
            (String::new(), line.clone()),
            ("A=1\n".to_owned(), format!("A=1\n{line}")),
            ("A=1".to_owned(), format!("A=1\n{line}")),
            ("\n\n# c\n".to_owned(), format!("\n\n# c\n{line}")),
            (
                "A=1\r\nB=2\r\n".to_owned(),
                format!("A=1\r\nB=2\r\nLST_SEED={HEX}\r\n"),
            ),
            (
                "A=1\r\nB=2".to_owned(),
                format!("A=1\r\nB=2\r\nLST_SEED={HEX}\r\n"),
            ),
            (
                "# LST_SEED=old\n  X = y \n".to_owned(),
                format!("# LST_SEED=old\n  X = y \n{line}"),
            ),
        ];
        for (input, expected) in cases {
            let out = with_seed(&input, &seed).unwrap();
            assert_eq!(out.expose(), expected, "{input:?}");
            assert!(out.expose().starts_with(&input));
            assert_eq!(parsed(out.expose()), seed_bytes());
        }
    }

    #[test]
    fn with_seed_refuses_existing_seed() {
        let seed = Seed::from_bytes(seed_bytes());
        let cases = [
            (format!("LST_SEED={HEX}\n"), 1),
            (format!("A=1\nLST_SEED={HEX}"), 2),
            ("A=1\r\n\r\nexport LST_SEED=garbage\r\n".to_owned(), 3),
            ("LST_SEED=\n".to_owned(), 1),
        ];
        for (input, line) in cases {
            assert_eq!(
                with_seed(&input, &seed).unwrap_err(),
                EnvError::AlreadyPresent { line },
                "{input:?}"
            );
        }
    }
}
