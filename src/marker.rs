//! Lexer/parser for secret markers in raw text.
//!
//! # Grammar (frozen)
//! ```text
//! <<gen:NAME>>            generated secret, default format alnum32
//! <<gen:NAME:FORMAT>>     generated secret with an explicit format
//! <<secret:NAME>>         stored manual secret
//! <<set:NAME:VALUE>>      enter/replace a manual secret
//! ```
//! - A marker *candidate* starts at `<<` followed by `[a-z]+:`. Anything else
//!   is plain text, so YAML merge keys (`<<: *defaults`) and heredocs
//!   (`<<EOF`) are left alone. A candidate with a kind other than `gen`,
//!   `secret` or `set` is an error (it catches typos like `<<secert:x>>`).
//! - NAME: one or more of `[A-Za-z0-9._-]` and `/`, with no leading, trailing
//!   or doubled `/`. In particular a name never contains `:`, `>`, `\0` or
//!   whitespace.
//! - FORMAT: `[a-z0-9-]+`, see [`Format`].
//! - VALUE: non-empty, everything up to the first unescaped `>>`. `\\` → `\`,
//!   `\>` → `>`; any other backslash sequence is an error. May contain `:`,
//!   newlines and any unicode.
//!
//! Errors carry a byte offset into the input and never any part of a value.

use std::fmt;
use std::ops::Range;

use crate::crypto::SecretString;
use crate::format::{Format, FormatError};

/// A marker found in the text.
#[derive(Debug, Clone)]
pub struct Marker {
    /// Byte range of the whole `<<…>>` in the input.
    pub span: Range<usize>,
    pub kind: MarkerKind,
}

#[derive(Debug, Clone)]
pub enum MarkerKind {
    Gen { name: String, format: Format },
    Secret { name: String },
    Set { name: String, value: SecretString },
}

impl MarkerKind {
    pub fn name(&self) -> &str {
        match self {
            MarkerKind::Gen { name, .. }
            | MarkerKind::Secret { name }
            | MarkerKind::Set { name, .. } => name,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("byte {pos}: {kind}")]
pub struct ParseError {
    /// Byte offset into the input.
    pub pos: usize,
    pub kind: ParseErrorKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseErrorKind {
    #[error("unterminated marker (missing `>>`)")]
    Unterminated,
    #[error("unknown marker kind (expected gen, secret or set)")]
    UnknownKind,
    #[error("empty secret name")]
    EmptyName,
    #[error(
        "invalid character in secret name (allowed: A-Z a-z 0-9 . _ - and single `/` separators)"
    )]
    InvalidName,
    #[error("invalid escape in value (only `\\\\` and `\\>` are allowed)")]
    InvalidEscape,
    #[error("invalid format: {0}")]
    InvalidFormat(FormatError),
    #[error("missing value: write <<set:name:VALUE>>")]
    MissingValue,
    #[error("<<secret:…>> takes no value; write <<set:name:VALUE>> to set one")]
    UnexpectedValue,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Gen,
    Secret,
    Set,
}

fn err(pos: usize, kind: ParseErrorKind) -> ParseError {
    ParseError { pos, kind }
}

fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/')
}

fn is_format_byte(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'
}

/// If a marker candidate starts at `i` (`<<` + `[a-z]+` + `:`), returns the
/// kind's byte range.
fn candidate(t: &[u8], i: usize) -> Option<Range<usize>> {
    if !t[i..].starts_with(b"<<") {
        return None;
    }
    let start = i + 2;
    let end = start
        + t[start..]
            .iter()
            .take_while(|b| b.is_ascii_lowercase())
            .count();
    (end > start && t.get(end) == Some(&b':')).then_some(start..end)
}

/// Parses all markers in `text`, in order. Returns the first error.
pub fn parse(text: &str) -> Result<Vec<Marker>, ParseError> {
    let t = text.as_bytes();
    let mut markers = Vec::new();
    let mut i = 0;
    while i + 1 < t.len() {
        let Some(kind_range) = candidate(t, i) else {
            i += 1;
            continue;
        };
        let marker = parse_marker(text, i, kind_range)?;
        i = marker.span.end;
        markers.push(marker);
    }
    Ok(markers)
}

/// Parses the marker whose candidate starts at `start`.
fn parse_marker(text: &str, start: usize, kind_range: Range<usize>) -> Result<Marker, ParseError> {
    let t = text.as_bytes();
    let kind = match &t[kind_range.clone()] {
        b"gen" => Kind::Gen,
        b"secret" => Kind::Secret,
        b"set" => Kind::Set,
        _ => return Err(err(kind_range.start, ParseErrorKind::UnknownKind)),
    };
    let unterminated = err(start, ParseErrorKind::Unterminated);

    // NAME
    let name_start = kind_range.end + 1;
    let name_end = name_start
        + t[name_start..]
            .iter()
            .take_while(|&&b| is_name_byte(b))
            .count();
    let name = &text[name_start..name_end];
    let Some(&next) = t.get(name_end) else {
        return Err(unterminated);
    };
    if name.is_empty() {
        return Err(err(name_start, ParseErrorKind::EmptyName));
    }
    validate_slashes(name, name_start)?;

    let at_close = |p: usize| t[p..].starts_with(b">>");
    // A byte that isn't a name byte, `:` or `>>` ends the name badly. A line
    // break (or a lone `>` at the end of a line/the text) means the marker
    // was never closed; anything else is a bad name character.
    let bad_char = |p: usize| match (t[p], t.get(p + 1)) {
        (b'\n' | b'\r', _) | (b'>', None | Some(b'\n' | b'\r')) => unterminated,
        _ => err(p, ParseErrorKind::InvalidName),
    };

    match kind {
        Kind::Secret => {
            if at_close(name_end) {
                Ok(Marker {
                    span: start..name_end + 2,
                    kind: MarkerKind::Secret {
                        name: name.to_owned(),
                    },
                })
            } else if next == b':' {
                Err(err(name_end, ParseErrorKind::UnexpectedValue))
            } else {
                Err(bad_char(name_end))
            }
        }
        Kind::Gen => {
            if at_close(name_end) {
                return Ok(Marker {
                    span: start..name_end + 2,
                    kind: MarkerKind::Gen {
                        name: name.to_owned(),
                        format: Format::default(),
                    },
                });
            }
            if next != b':' {
                return Err(bad_char(name_end));
            }
            let f_start = name_end + 1;
            let f_end = f_start
                + t[f_start..]
                    .iter()
                    .take_while(|&&b| is_format_byte(b))
                    .count();
            if !at_close(f_end) {
                return match t.get(f_end) {
                    None | Some(b'\n' | b'\r') => Err(unterminated),
                    Some(_) => Err(err(
                        f_start,
                        ParseErrorKind::InvalidFormat(FormatError::Unknown),
                    )),
                };
            }
            let format: Format = text[f_start..f_end]
                .parse()
                .map_err(|e| err(f_start, ParseErrorKind::InvalidFormat(e)))?;
            Ok(Marker {
                span: start..f_end + 2,
                kind: MarkerKind::Gen {
                    name: name.to_owned(),
                    format,
                },
            })
        }
        Kind::Set => {
            if at_close(name_end) {
                return Err(err(name_end, ParseErrorKind::MissingValue));
            }
            if next != b':' {
                return Err(bad_char(name_end));
            }
            let v_start = name_end + 1;
            let v_end = scan_value(t, v_start).ok_or(unterminated)??;
            if v_end == v_start {
                return Err(err(v_start, ParseErrorKind::MissingValue));
            }
            Ok(Marker {
                span: start..v_end + 2,
                kind: MarkerKind::Set {
                    name: name.to_owned(),
                    value: unescape(&text[v_start..v_end]),
                },
            })
        }
    }
}

/// Rejects leading, trailing and doubled `/` in a name.
fn validate_slashes(name: &str, name_start: usize) -> Result<(), ParseError> {
    let b = name.as_bytes();
    if b[0] == b'/' {
        return Err(err(name_start, ParseErrorKind::InvalidName));
    }
    if let Some(p) = b.windows(2).position(|w| w == b"//") {
        return Err(err(name_start + p + 1, ParseErrorKind::InvalidName));
    }
    if b[b.len() - 1] == b'/' {
        return Err(err(name_start + b.len() - 1, ParseErrorKind::InvalidName));
    }
    Ok(())
}

/// Finds the end of an escaped VALUE starting at `from`: the index of the
/// first unescaped `>>`. `None` if the text ends first; `Some(Err)` on an
/// invalid escape.
///
/// Byte-wise scanning is sound for UTF-8: `\` and `>` are ASCII and never
/// occur inside a multi-byte sequence.
fn scan_value(t: &[u8], from: usize) -> Option<Result<usize, ParseError>> {
    let mut p = from;
    while p < t.len() {
        match t[p] {
            b'\\' => match t.get(p + 1)? {
                b'\\' | b'>' => p += 2,
                _ => return Some(Err(err(p, ParseErrorKind::InvalidEscape))),
            },
            b'>' if t.get(p + 1) == Some(&b'>') => return Some(Ok(p)),
            _ => p += 1,
        }
    }
    None
}

/// Unescapes a VALUE already validated by [`scan_value`].
fn unescape(raw: &str) -> SecretString {
    // Unescaped length ≤ raw length: reserve once so the buffer never
    // reallocates (and never leaves an unzeroized copy).
    let mut out = SecretString::new(String::with_capacity(raw.len()));
    let s = out.as_mut_string();
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            // Validated: always followed by `\` or `>`.
            if let Some(e) = chars.next() {
                s.push(e);
            }
        } else {
            s.push(c);
        }
    }
    out
}

/// Escapes a value for use in `<<set:name:VALUE>>`: `\` → `\\` and every
/// `>` → `\>`. Inverse of the parser's unescaping.
pub fn escape(value: &str) -> SecretString {
    let extra = value.bytes().filter(|&b| b == b'\\' || b == b'>').count();
    let mut out = SecretString::new(String::with_capacity(value.len() + extra));
    let s = out.as_mut_string();
    for c in value.chars() {
        if c == '\\' || c == '>' {
            s.push('\\');
        }
        s.push(c);
    }
    out
}

impl fmt::Display for MarkerKind {
    /// Canonical marker text. A `set` marker is shown without its value.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MarkerKind::Gen { name, format } if *format == Format::default() => {
                write!(f, "<<gen:{name}>>")
            }
            MarkerKind::Gen { name, format } => write!(f, "<<gen:{name}:{format}>>"),
            MarkerKind::Secret { name } => write!(f, "<<secret:{name}>>"),
            MarkerKind::Set { name, .. } => write!(f, "<<set:{name}:…>>"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ParseErrorKind::*;
    use proptest::prelude::*;

    fn one(text: &str) -> Marker {
        let mut m = parse(text).unwrap();
        assert_eq!(m.len(), 1, "{text:?}");
        m.remove(0)
    }

    fn set_value(text: &str) -> String {
        match one(text).kind {
            MarkerKind::Set { value, .. } => value.expose().to_owned(),
            other => panic!("expected set, got {other:?}"),
        }
    }

    fn fails(text: &str) -> ParseError {
        parse(text).unwrap_err()
    }

    #[test]
    fn gen_default_and_explicit_format() {
        let m = one("<<gen:db>>");
        assert_eq!(m.span, 0..10);
        assert!(
            matches!(m.kind, MarkerKind::Gen { ref name, format: Format::Alnum(32) } if name == "db")
        );

        let m = one("x=<<gen:shared/mqtt-z2m:hex64>>;");
        assert_eq!(m.span, 2..31);
        assert!(
            matches!(m.kind, MarkerKind::Gen { ref name, format: Format::Hex(64) } if name == "shared/mqtt-z2m")
        );

        for (f, expected) in [
            ("uuid", Format::Uuid),
            ("base64-32", Format::Base64(32)),
            ("alnum22", Format::Alnum(22)),
        ] {
            assert!(
                matches!(one(&format!("<<gen:a:{f}>>")).kind, MarkerKind::Gen { format, .. } if format == expected)
            );
        }
    }

    #[test]
    fn secret_and_set() {
        let m = one("<<secret:cloudflare>>");
        assert_eq!(m.span, 0..21);
        assert!(matches!(m.kind, MarkerKind::Secret { ref name } if name == "cloudflare"));

        let m = one("a <<set:smtp:p:w>> b");
        assert_eq!(m.span, 2..18);
        assert_eq!(m.kind.name(), "smtp");
        assert_eq!(set_value("<<set:smtp:p:w>>"), "p:w");
    }

    #[test]
    fn design_escape_examples() {
        assert_eq!(set_value(r"<<set:x:a\>>b>>"), "a>>b");
        assert_eq!(set_value(r"<<set:x:abc\>>>"), "abc>");
        assert_eq!(set_value(r"<<set:x:C:\\path>>"), r"C:\path");
        assert_eq!(set_value(r"<<set:x:a>b>>"), "a>b");
        assert_eq!(set_value("<<set:x:line1\nline2>>"), "line1\nline2");
        assert_eq!(set_value("<<set:x:ünï🔑>>"), "ünï🔑");
        // The first unescaped `>>` ends the value; the rest is plain text.
        let m = parse("<<set:x:a>>b>>").unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].span, 0..11);
    }

    #[test]
    fn multiple_markers_in_a_dsn() {
        let text = "DATABASE_URL: postgres://app:<<gen:db>>@db/app?x=<<secret:x>><<gen:y:uuid>>";
        let m = parse(text).unwrap();
        assert_eq!(m.len(), 3);
        assert_eq!(&text[m[0].span.clone()], "<<gen:db>>");
        assert_eq!(&text[m[1].span.clone()], "<<secret:x>>");
        assert_eq!(&text[m[2].span.clone()], "<<gen:y:uuid>>");
    }

    #[test]
    fn non_candidates_are_plain_text() {
        let text = "x-common: &c\n  a: 1\nservices:\n  s:\n    <<: *c\n    command: |\n      cat <<EOF\n      a << b <<gen\n      EOF\n    v: <<A:b>> << gen:x>> <<\n";
        assert!(parse(text).unwrap().is_empty());
        assert!(parse("").unwrap().is_empty());
        assert!(parse("<").unwrap().is_empty());
        assert!(parse("<<").unwrap().is_empty());
        // `<<<gen:x>>` contains a marker starting at the second `<`.
        assert_eq!(one("<<<gen:x>>").span, 1..10);
    }

    #[test]
    fn display_is_canonical_and_hides_values() {
        assert_eq!(one("<<gen:db>>").kind.to_string(), "<<gen:db>>");
        assert_eq!(one("<<gen:db:alnum32>>").kind.to_string(), "<<gen:db>>");
        assert_eq!(one("<<gen:db:hex64>>").kind.to_string(), "<<gen:db:hex64>>");
        assert_eq!(one("<<secret:a/b>>").kind.to_string(), "<<secret:a/b>>");
        let shown = one("<<set:a:hunter2>>").kind.to_string();
        assert!(!shown.contains("hunter2"));
        assert!(!format!("{:?}", one("<<set:a:hunter2>>")).contains("hunter2"));
    }

    #[test]
    fn error_positions() {
        let cases: &[(&str, ParseError)] = &[
            // unterminated
            ("ab <<gen:db", err(3, Unterminated)),
            ("ab <<gen:db\n>>", err(3, Unterminated)),
            ("<<gen:db:hex64", err(0, Unterminated)),
            ("<<gen:db:hex64\n", err(0, Unterminated)),
            ("<<secret:x>", err(0, Unterminated)),
            ("<<set:x:abc", err(0, Unterminated)),
            ("<<set:x:abc\\>>", err(0, Unterminated)),
            ("<<set:x:abc\\", err(0, Unterminated)),
            ("<<gen:", err(0, Unterminated)),
            // unknown kind
            ("x <<secert:a>>", err(4, UnknownKind)),
            ("<<env:a>>", err(2, UnknownKind)),
            // empty name
            ("<<gen:>>", err(6, EmptyName)),
            ("<<secret::x>>", err(9, EmptyName)),
            ("<<set::v>>", err(6, EmptyName)),
            ("<<gen: db>>", err(6, EmptyName)),
            // invalid name
            ("<<gen:d b>>", err(7, InvalidName)),
            ("<<gen:db>x>>", err(8, InvalidName)),
            ("<<gen:/db>>", err(6, InvalidName)),
            ("<<gen:db/>>", err(8, InvalidName)),
            ("<<gen:a//b>>", err(8, InvalidName)),
            ("<<secret:é>>", err(9, EmptyName)),
            ("<<secret:aé>>", err(10, InvalidName)),
            ("<<set:a b:v>>", err(7, InvalidName)),
            // invalid escape
            (r"<<set:x:C:\path>>", err(10, InvalidEscape)),
            (r"<<set:x:ok\\\n>>", err(12, InvalidEscape)),
            // invalid format
            (
                "<<gen:x:hex31>>",
                err(
                    8,
                    InvalidFormat(FormatError::OutOfRange { min: 32, max: 256 }),
                ),
            ),
            (
                "<<gen:x:pass>>",
                err(8, InvalidFormat(FormatError::Unknown)),
            ),
            ("<<gen:x:>>", err(8, InvalidFormat(FormatError::Unknown))),
            (
                "<<gen:x:Hex64>>",
                err(8, InvalidFormat(FormatError::Unknown)),
            ),
            (
                "<<gen:x:hex64 >>",
                err(8, InvalidFormat(FormatError::Unknown)),
            ),
            // missing value
            ("<<set:x>>", err(7, MissingValue)),
            ("<<set:x:>>", err(8, MissingValue)),
            // value on a secret marker
            ("<<secret:x:hunter2>>", err(10, UnexpectedValue)),
        ];
        for (text, expected) in cases {
            assert_eq!(fails(text), *expected, "{text:?}");
        }
    }

    #[test]
    fn first_error_wins_and_errors_hide_values() {
        let e = fails(r"<<gen:ok>> <<set:x:sup3rs3cret\q>> <<bad:x>>");
        assert_eq!(e.kind, InvalidEscape);
        assert!(!e.to_string().contains("sup3rs3cret"));
        assert!(!format!("{e:?}").contains("sup3rs3cret"));
    }

    #[test]
    fn escape_examples() {
        assert_eq!(escape("a>>b").expose(), r"a\>\>b");
        assert_eq!(escape("abc>").expose(), r"abc\>");
        assert_eq!(escape(r"C:\path").expose(), r"C:\\path");
        assert_eq!(escape("plain:ü").expose(), "plain:ü");
    }

    /// Strings biased toward the characters that matter to the grammar.
    fn tricky() -> impl Strategy<Value = String> {
        prop::collection::vec(
            prop_oneof![
                Just('>'),
                Just('\\'),
                Just(':'),
                Just('<'),
                Just('a'),
                Just('é'),
                Just('\n'),
                Just('🔑')
            ],
            1..40,
        )
        .prop_map(|v| v.into_iter().collect())
    }

    /// Text without any `<` (so it can't start or join a marker).
    fn filler() -> impl Strategy<Value = String> {
        "[^<]{0,20}"
    }

    proptest! {
        #[test]
        fn escape_parse_round_trip(v in prop_oneof![".+", "\\PC+", tricky()]) {
            let text = format!("<<set:x:{}>>", escape(&v).expose());
            let markers = parse(&text).unwrap();
            prop_assert_eq!(markers.len(), 1);
            prop_assert_eq!(markers[0].span.clone(), 0..text.len());
            match &markers[0].kind {
                MarkerKind::Set { name, value } => {
                    prop_assert_eq!(name.as_str(), "x");
                    prop_assert_eq!(value.expose(), v.as_str());
                }
                other => prop_assert!(false, "expected set, got {:?}", other),
            }
        }

        #[test]
        fn round_trip_embedded_in_text(pre in filler(), post in filler(), v in tricky()) {
            let marker = format!("<<set:shared/n-1:{}>>", escape(&v).expose());
            let text = format!("{pre}{marker}{post}");
            let markers = parse(&text).unwrap();
            prop_assert_eq!(markers.len(), 1);
            prop_assert_eq!(markers[0].span.clone(), pre.len()..pre.len() + marker.len());
            match &markers[0].kind {
                MarkerKind::Set { value, .. } => prop_assert_eq!(value.expose(), v.as_str()),
                other => prop_assert!(false, "expected set, got {:?}", other),
            }
        }

        #[test]
        fn parse_never_panics(text in "\\PC*") {
            if let Ok(markers) = parse(&text) {
                let mut last = 0;
                for m in markers {
                    prop_assert!(m.span.start >= last && m.span.end <= text.len());
                    prop_assert!(text[m.span.clone()].starts_with("<<") && text[m.span.clone()].ends_with(">>"));
                    last = m.span.end;
                }
            }
        }

        #[test]
        fn parse_never_panics_on_marker_soup(
            parts in prop::collection::vec(
                prop_oneof![
                    Just("<<"), Just(">>"), Just(">"), Just("\\"), Just(":"), Just("gen"), Just("set"),
                    Just("secret"), Just("/"), Just("hex64"), Just("x"), Just("é"), Just("\n"),
                ],
                0..30,
            )
        ) {
            let _ = parse(&parts.concat());
        }
    }
}
