//! Reading the `KEY=VALUE` files compose reads: a stack's `.env` (for
//! `${VAR}` interpolation) and the files named by `env_file:`. Pure: text in,
//! definitions out. Used by `lst import` only.
//!
//! The rules follow what `docker compose config` (Compose v5) does with each
//! form, checked against it by the `compose_config` e2e tests:
//! - a UTF-8 BOM at the start is ignored; a trailing `\r` is stripped;
//! - blank lines and lines starting with `#` (after whitespace) are skipped;
//! - `KEY=VALUE` or `KEY: VALUE` (whichever separator comes first),
//!   optionally prefixed with `export `; whitespace around the key and the
//!   separator is ignored. `KEY` is `[A-Za-z0-9_.-]+`;
//! - an unquoted value is trimmed and ends at a `#` that follows a space (a
//!   tab before `#` doesn't start a comment); backslashes are literal;
//! - a `'single quoted'` value is literal except that `\'` is a quote; a
//!   quote closes the value unless an odd number of backslashes precede it;
//! - a `"double quoted"` value turns `\\`, `\"` and `\$` into `\`, `"` and
//!   `$`; a backslash before any other non-alphanumeric character stays
//!   (`\'` is two characters).
//!
//! A definition lst can't reproduce exactly is a [`Skip`], not an error, so
//! the rest of the file can still be imported: compose would interpolate a
//! `$` in an unquoted or double-quoted value; a double-quoted value with a
//! letter or digit escape (`\n`, `\t`, `\0`, …); a value spanning lines;
//! text after the closing quote (compose ignores some of it and rejects
//! some); a `KEY` without a value (compose takes it from its own
//! environment). A line that isn't a definition at all (a key with spaces or
//! quotes in it) is a [`DotenvError`].
//!
//! Errors and skips carry the variable name and a line number (1-based),
//! never the value.

use crate::crypto::SecretString;

/// One `KEY=VALUE` line.
#[derive(Debug)]
pub struct Def {
    pub key: String,
    /// 1-based line number.
    pub line: usize,
    pub value: Value,
}

/// A definition's value, or why lst leaves it alone.
#[derive(Debug)]
pub enum Value {
    Ok(SecretString),
    Skip(Skip),
}

/// Why a definition can't be imported. Shown to the user (no value in it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    /// An unquoted or double-quoted value with `$`: compose interpolates it.
    Dollar,
    /// A double-quoted value with a letter or digit escape (`\n`, …).
    Escape,
    /// A quoted value that doesn't end on its line (multi-line).
    MultiLine,
    /// Text after the closing quote.
    AfterQuote,
    /// `KEY` alone: compose takes the value from its own environment.
    NoValue,
}

impl std::fmt::Display for Skip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Skip::Dollar => "its value contains `$`, which compose would interpolate",
            Skip::Escape => "its value uses an escape sequence such as `\\n`",
            Skip::MultiLine => "its value spans more than one line",
            Skip::AfterQuote => "its line has more text after the closing quote",
            Skip::NoValue => "it has no value here (compose takes it from its own environment)",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DotenvError {
    #[error("line {line}: not a KEY=VALUE line (lst import can't tell what compose makes of it)")]
    NotADefinition { line: usize },
}

/// Parses `text`. Definitions come in file order; a key defined twice
/// appears twice (the last one wins, as in compose).
pub fn parse(text: &str) -> Result<Vec<Def>, DotenvError> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut out = Vec::new();
    let mut lines = text.split('\n').enumerate();
    while let Some((i, raw)) = lines.next() {
        let line = i + 1;
        let l = raw.strip_suffix('\r').unwrap_or(raw).trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let l = match l.strip_prefix("export") {
            Some(rest) if rest.starts_with([' ', '\t']) => rest.trim_start(),
            _ => l,
        };
        let (key, rest) = match l.find(['=', ':']) {
            Some(i) => (&l[..i], Some(&l[i + 1..])),
            None => (l, None),
        };
        let key = key.trim_end();
        if !is_key(key) {
            return Err(DotenvError::NotADefinition { line });
        }
        let value = match rest.map(str::trim_start) {
            None => Value::Skip(Skip::NoValue),
            Some(rest) => match rest.chars().next() {
                Some(q @ ('\'' | '"')) => match quoted(&rest[1..], q) {
                    Some((value, after)) => {
                        let after = after.trim_start();
                        if after.is_empty() || after.starts_with('#') {
                            value
                        } else {
                            Value::Skip(Skip::AfterQuote)
                        }
                    }
                    None => {
                        // The quote continues on later lines: skip to its end
                        // so its continuation lines aren't read as definitions.
                        skip_continuation(&mut lines, q);
                        Value::Skip(Skip::MultiLine)
                    }
                },
                _ => unquoted(rest),
            },
        };
        out.push(Def {
            key: key.to_owned(),
            line,
            value,
        });
    }
    Ok(out)
}

/// `[A-Za-z0-9_.-]+`.
fn is_key(key: &str) -> bool {
    !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// An unquoted value: up to a `#` after a space, trimmed.
fn unquoted(rest: &str) -> Value {
    let end = rest.find(" #").unwrap_or(rest.len());
    let v = rest[..end].trim();
    if v.contains('$') {
        return Value::Skip(Skip::Dollar);
    }
    Value::Ok(SecretString::new(v.to_owned()))
}

/// The byte index in `s` of the first `q` not escaped by an odd number of
/// backslashes.
fn closing(s: &str, q: char) -> Option<usize> {
    let mut backslashes = 0;
    for (i, c) in s.char_indices() {
        if c == q && backslashes % 2 == 0 {
            return Some(i);
        }
        backslashes = if c == '\\' { backslashes + 1 } else { 0 };
    }
    None
}

/// The quoted value after the opening quote `q`, and the text after the
/// closing quote; `None` if it doesn't close on this line.
fn quoted(s: &str, q: char) -> Option<(Value, &str)> {
    let end = closing(s, q)?;
    let (body, after) = (&s[..end], &s[end + 1..]);
    if q == '\'' {
        let v = SecretString::new(body.replace("\\'", "'"));
        return Some((Value::Ok(v), after));
    }
    let mut out = SecretString::new(String::with_capacity(body.len()));
    let o = out.as_mut_string();
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some(e @ ('\\' | '"' | '$')) => o.push(e),
                Some(e) if e.is_ascii_alphanumeric() => {
                    return Some((Value::Skip(Skip::Escape), after));
                }
                Some(e) => {
                    o.push('\\');
                    o.push(e);
                }
                // `closing` never ends the body on an odd backslash.
                None => o.push('\\'),
            },
            '$' => return Some((Value::Skip(Skip::Dollar), after)),
            c => o.push(c),
        }
    }
    Some((Value::Ok(out), after))
}

/// Consumes lines up to and including the one that closes quote `q`.
fn skip_continuation<'a>(lines: &mut impl Iterator<Item = (usize, &'a str)>, q: char) {
    for (_, l) in lines.by_ref() {
        if closing(l, q).is_some() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn defs(text: &str) -> Vec<(String, usize, Result<String, Skip>)> {
        parse(text)
            .unwrap()
            .into_iter()
            .map(|d| {
                let v = match d.value {
                    Value::Ok(s) => Ok(s.expose().to_owned()),
                    Value::Skip(s) => Err(s),
                };
                (d.key, d.line, v)
            })
            .collect()
    }

    fn one(text: &str) -> (String, Result<String, Skip>) {
        let mut d = defs(text);
        assert_eq!(d.len(), 1, "{text:?}");
        let (k, _, v) = d.remove(0);
        (k, v)
    }

    /// Each line as `docker compose config` (Compose v5.6.1) reads it in an
    /// env_file, probed by hand on 2026-11-08: (line, key, value). Where
    /// compose reads a value lst won't reproduce, the expected result is a
    /// skip instead.
    #[test]
    fn matches_compose() {
        let ok = |v: &str| Ok::<String, Skip>(v.to_owned());
        let cases: &[(&str, &str, Result<String, Skip>)] = &[
            // Single quotes: literal, `\'` is a quote.
            (r"K='a\\b'", "K", ok(r"a\\b")),
            (r"K='a\nb'", "K", ok(r"a\nb")),
            (r"K='a\'b'", "K", ok("a'b")),
            (r"K='a\''", "K", ok("a'")),
            (r"K='\\\''", "K", ok(r"\\'")),
            (r"K='a\\'", "K", ok(r"a\\")),
            ("K='a$b'", "K", ok("a$b")),
            ("K='$$'", "K", ok("$$")),
            ("K='a#b' # c", "K", ok("a#b")),
            // Double quotes.
            (r#"K="a\\b""#, "K", ok(r"a\b")),
            (r#"K="a\"b""#, "K", ok("a\"b")),
            (r#"K="a\'b""#, "K", ok(r"a\'b")),
            (r#"K="a\$b""#, "K", ok("a$b")),
            (r#"K="a\/b""#, "K", ok(r"a\/b")),
            (r#"K="a\#b""#, "K", ok(r"a\#b")),
            (r#"K="a\ b""#, "K", ok(r"a\ b")),
            (r#"K="a\\""#, "K", ok(r"a\")),
            (r#"K="a\\\"b""#, "K", ok(r#"a\"b"#)),
            (r##"K="a#b"#c"##, "K", ok("a#b")),
            (r#"K=" #x""#, "K", ok(" #x")),
            (r#"K="  sp  ""#, "K", ok("  sp  ")),
            (r#"K="a b" "#, "K", ok("a b")),
            (r#"K="x" # c"#, "K", ok("x")),
            // Unquoted: trimmed, ` #` comments, backslashes literal.
            ("K=a #b", "K", ok("a")),
            ("K=a  #c", "K", ok("a")),
            ("K=a #c#d", "K", ok("a")),
            ("K=a\t#b", "K", ok("a\t#b")),
            ("K=a#b", "K", ok("a#b")),
            ("K=#x", "K", ok("#x")),
            ("K= #x", "K", ok("#x")),
            ("K=a b # c", "K", ok("a b")),
            (r"K=a\nb", "K", ok(r"a\nb")),
            (r"K=a\'b", "K", ok(r"a\'b")),
            (r"K=a\", "K", ok(r"a\")),
            ("K=x\"", "K", ok("x\"")),
            ("K=it's", "K", ok("it's")),
            ("K=`x`", "K", ok("`x`")),
            ("K= lead", "K", ok("lead")),
            ("K=\ty", "K", ok("y")),
            ("K=x\t", "K", ok("x")),
            ("K=", "K", ok("")),
            ("K==x", "K", ok("=x")),
            ("K==", "K", ok("=")),
            ("K=a:b", "K", ok("a:b")),
            ("K=été", "K", ok("été")),
            // Keys and separators.
            ("K = spaced ", "K", ok("spaced")),
            ("K\t=tab", "K", ok("tab")),
            ("export K=e", "K", ok("e")),
            ("export  K=e2", "K", ok("e2")),
            ("export=1", "export", ok("1")),
            ("KEY:v", "KEY", ok("v")),
            ("KEY : v", "KEY", ok("v")),
            ("K: yamlish", "K", ok("yamlish")),
            ("K:a=b", "K", ok("a=b")),
            ("K.DOT-dash=1", "K.DOT-dash", ok("1")),
            ("1K=x", "1K", ok("x")),
            (" K=lead", "K", ok("lead")),
            ("K=crlf\r", "K", ok("crlf")),
            ("\u{feff}K=bom", "K", ok("bom")),
            // Skips: compose reads something lst doesn't reproduce.
            ("K=$$", "K", Err(Skip::Dollar)),
            ("K=a$b", "K", Err(Skip::Dollar)),
            (r#"K="a$b""#, "K", Err(Skip::Dollar)),
            (r#"K="a\nb""#, "K", Err(Skip::Escape)),
            (r#"K="a\tb""#, "K", Err(Skip::Escape)),
            (r#"K="a\0""#, "K", Err(Skip::Escape)),
            (r#"K="a\xb""#, "K", Err(Skip::Escape)),
            (r#"K="x"y"#, "K", Err(Skip::AfterQuote)),
            ("K='x'y", "K", Err(Skip::AfterQuote)),
            ("K='x' y", "K", Err(Skip::AfterQuote)),
            ("K", "K", Err(Skip::NoValue)),
            ("export K", "K", Err(Skip::NoValue)),
        ];
        for (line, key, want) in cases {
            assert_eq!(one(line), (key.to_string(), want.clone()), "{line:?}");
        }
    }

    #[test]
    fn plain_lines() {
        let d = defs("# c\n\nA=1\r\nexport B = two words  \n  C=\nD=x=y\n");
        let got: Vec<_> = d
            .iter()
            .map(|(k, l, v)| (k.as_str(), *l, v.clone()))
            .collect();
        assert_eq!(
            got,
            [
                ("A", 3, Ok("1".into())),
                ("B", 4, Ok("two words".into())),
                ("C", 5, Ok(String::new())),
                ("D", 6, Ok("x=y".into())),
            ]
        );
    }

    #[test]
    fn multi_line_values_are_skipped_whole() {
        let d = defs("A=\"line1\nB=not a def\nline3\"\nC=ok\n");
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].2, Err(Skip::MultiLine));
        assert_eq!((d[1].0.as_str(), d[1].1), ("C", 4));
        let d = defs("A='open\nB=x\\'still\nend'\nC=1\n");
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].2, Err(Skip::MultiLine));
        assert_eq!(d[1].0, "C");
        // Never closed: the rest of the file belongs to it.
        let d = defs("A='open\nB=1\n");
        assert_eq!(d.len(), 1);
    }

    #[test]
    fn duplicates_are_kept_in_order() {
        let d = defs("A=1\nA=2\n");
        assert_eq!(d.len(), 2);
        assert_eq!((d[0].1, d[1].1), (1, 2));
        assert_eq!(d[1].2, Ok("2".into()));
    }

    #[test]
    fn errors_name_lines_not_values() {
        for (text, line) in [
            ("A=1\nhunter 2\n", 2),
            ("'K'=x", 1),
            ("K K=x", 1),
            ("=x", 1),
            ("pass\"word\n", 1),
        ] {
            let e = parse(text).unwrap_err();
            assert_eq!(e, DotenvError::NotADefinition { line }, "{text:?}");
            for word in ["hunter", "pass", "word"] {
                assert!(!e.to_string().contains(word));
            }
        }
    }

    proptest! {
        /// Any text: no panic, and an error never quotes it.
        #[test]
        fn never_panics_or_leaks(text in "\\PC{0,80}", secret in "[a-z]{12}") {
            let text = format!("{text}\nX{secret}Y Z={secret}\n");
            match parse(&text) {
                Ok(_) => {}
                Err(e) => prop_assert!(!e.to_string().contains(&secret)),
            }
        }

        /// A value written as `K='…'` (no `'` inside) reads back exactly.
        #[test]
        fn single_quoted_round_trip(v in "[^'\n\r]{0,40}") {
            let (k, got) = one(&format!("K='{v}'"));
            prop_assert_eq!(k, "K");
            // A trailing odd backslash escapes the closing quote.
            let odd = v.len() - v.trim_end_matches('\\').len();
            if odd % 2 == 1 {
                prop_assert_eq!(got, Err(Skip::MultiLine));
            } else {
                prop_assert_eq!(got, Ok(v.replace("\\'", "'")));
            }
        }
    }
}
