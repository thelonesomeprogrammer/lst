//! Reading the `KEY=VALUE` files compose reads: a stack's `.env` (for
//! `${VAR}` interpolation) and the files named by `env_file:`. Pure: text in,
//! definitions out. Used by `lst import` only.
//!
//! The syntax is the common subset of compose's dotenv format:
//! - blank lines and lines starting with `#` (after whitespace) are skipped;
//! - `KEY=VALUE`, optionally prefixed with `export `; whitespace around the
//!   key and around `=` is ignored; a trailing `\r` is stripped;
//! - `KEY` is `[A-Za-z_][A-Za-z0-9_.-]*`;
//! - an unquoted value ends at the end of the line or at a `#` that follows
//!   whitespace (a comment); surrounding whitespace is trimmed;
//! - `'single quoted'` is literal; `"double quoted"` knows `\\`, `\"` and
//!   `\'`; after the closing quote only whitespace or a comment may follow.
//!
//! A value lst can't reproduce exactly is a [`Skip`], not an error, so the
//! rest of the file can still be imported: compose would interpolate a `$`
//! in an unquoted or double-quoted value, a double-quoted value may contain
//! other escapes (`\n`, …), and a quote may span lines. A line that is
//! not a definition at all (`KEY` without `=`, a bad key, an unclosed quote)
//! is an [`DotenvError`]: lst would otherwise guess what compose does with
//! it.
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
    /// A double-quoted value with an escape other than `\\`, `\"`, `\'`.
    Escape,
    /// A quoted value that doesn't end on its line (multi-line).
    MultiLine,
}

impl std::fmt::Display for Skip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Skip::Dollar => "its value contains `$`, which compose would interpolate",
            Skip::Escape => "its value uses an escape sequence such as `\\n`",
            Skip::MultiLine => "its value spans more than one line",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DotenvError {
    #[error("line {line}: not a KEY=VALUE line (lst import can't tell what compose makes of it)")]
    NotADefinition { line: usize },
    #[error("line {line}: {key}: unexpected text after the closing quote")]
    AfterQuote { line: usize, key: String },
}

/// Parses `text`. Definitions come in file order; a key defined twice
/// appears twice (the last one wins, as in compose).
pub fn parse(text: &str) -> Result<Vec<Def>, DotenvError> {
    let mut out = Vec::new();
    let mut lines = text.split('\n').enumerate();
    while let Some((i, raw)) = lines.next() {
        let line = i + 1;
        let l = raw.strip_suffix('\r').unwrap_or(raw).trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let l = l.strip_prefix("export ").map_or(l, str::trim_start);
        let Some((key, rest)) = l.split_once('=') else {
            return Err(DotenvError::NotADefinition { line });
        };
        let key = key.trim_end();
        if !is_key(key) {
            return Err(DotenvError::NotADefinition { line });
        }
        let rest = rest.trim_start();
        let value = match rest.chars().next() {
            Some(q @ ('\'' | '"')) => match quoted(&rest[1..], q) {
                Some((value, after)) => {
                    let after = after.trim_start();
                    if !(after.is_empty() || after.starts_with('#')) {
                        return Err(DotenvError::AfterQuote {
                            line,
                            key: key.to_owned(),
                        });
                    }
                    value
                }
                None => {
                    // The quote continues on later lines: skip to its end so
                    // its continuation lines aren't read as definitions.
                    skip_continuation(&mut lines, q);
                    Value::Skip(Skip::MultiLine)
                }
            },
            _ => unquoted(rest),
        };
        out.push(Def {
            key: key.to_owned(),
            line,
            value,
        });
    }
    Ok(out)
}

/// `[A-Za-z_][A-Za-z0-9_.-]*`.
fn is_key(key: &str) -> bool {
    let mut chars = key.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// An unquoted value: up to a `#` after whitespace, trimmed.
fn unquoted(rest: &str) -> Value {
    let mut end = rest.len();
    let mut prev_space = false;
    for (i, c) in rest.char_indices() {
        if c == '#' && prev_space {
            end = i;
            break;
        }
        prev_space = c == ' ' || c == '\t';
    }
    let v = rest[..end].trim_end();
    if v.contains('$') {
        return Value::Skip(Skip::Dollar);
    }
    Value::Ok(SecretString::new(v.to_owned()))
}

/// The quoted value after the opening quote `q`, and the text after the
/// closing quote; `None` if it doesn't close on this line.
fn quoted(s: &str, q: char) -> Option<(Value, &str)> {
    if q == '\'' {
        let end = s.find('\'')?;
        let v = SecretString::new(s[..end].to_owned());
        return Some((Value::Ok(v), &s[end + 1..]));
    }
    let mut out = SecretString::new(String::with_capacity(s.len()));
    let mut skip = None;
    let mut chars = s.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => {
                let value = match skip {
                    Some(s) => Value::Skip(s),
                    None => Value::Ok(out),
                };
                return Some((value, &s[i + 1..]));
            }
            '\\' => match chars.next() {
                Some((_, e @ ('\\' | '"' | '\''))) => out.as_mut_string().push(e),
                Some(_) => skip = skip.or(Some(Skip::Escape)),
                None => return None,
            },
            '$' => {
                skip = skip.or(Some(Skip::Dollar));
            }
            c => out.as_mut_string().push(c),
        }
    }
    None
}

/// Consumes lines up to and including the one that closes quote `q`.
fn skip_continuation<'a>(lines: &mut impl Iterator<Item = (usize, &'a str)>, q: char) {
    for (_, l) in lines.by_ref() {
        let mut escaped = false;
        for c in l.chars() {
            if q == '"' && c == '\\' && !escaped {
                escaped = true;
                continue;
            }
            if c == q && !escaped {
                return;
            }
            escaped = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn one(text: &str) -> Result<String, Skip> {
        let mut d = defs(text);
        assert_eq!(d.len(), 1, "{text:?}");
        d.remove(0).2
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
    fn comments_and_hashes() {
        assert_eq!(one("A=abc # note"), Ok("abc".into()));
        assert_eq!(one("A=abc#not-a-comment"), Ok("abc#not-a-comment".into()));
        assert_eq!(one("A='x # y' # z"), Ok("x # y".into()));
        assert_eq!(one("A=\"x # y\"#z"), Ok("x # y".into()));
    }

    #[test]
    fn quotes() {
        assert_eq!(one("A='it\\s $raw'"), Ok("it\\s $raw".into()));
        assert_eq!(one(r#"A="a\"b\\c\'d""#), Ok(r#"a"b\c'd"#.into()));
        assert_eq!(one("A=''"), Ok(String::new()));
        assert_eq!(one("A=\"pw with 'q'\""), Ok("pw with 'q'".into()));
    }

    #[test]
    fn skips() {
        assert_eq!(one("A=$HOME"), Err(Skip::Dollar));
        assert_eq!(one("A=\"x${B}\""), Err(Skip::Dollar));
        assert_eq!(one("A=\"a\\nb\""), Err(Skip::Escape));
        let d = defs("A=\"line1\nB=not a def\nline3\"\nC=ok\n");
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].2, Err(Skip::MultiLine));
        assert_eq!((d[1].0.as_str(), d[1].1), ("C", 4));
        let d = defs("A='open\nstill\n");
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].2, Err(Skip::MultiLine));
    }

    #[test]
    fn duplicates_are_kept_in_order() {
        let d = defs("A=1\nA=2\n");
        assert_eq!(d.len(), 2);
        assert_eq!(d[1].2, Ok("2".into()));
    }

    #[test]
    fn errors_name_lines_not_values() {
        assert_eq!(
            parse("A=1\nhunter2\n").unwrap_err(),
            DotenvError::NotADefinition { line: 2 }
        );
        assert_eq!(
            parse("1A=x").unwrap_err(),
            DotenvError::NotADefinition { line: 1 }
        );
        let e = parse("PW='hunter2'oops").unwrap_err();
        assert_eq!(
            e,
            DotenvError::AfterQuote {
                line: 1,
                key: "PW".into()
            }
        );
        assert!(!e.to_string().contains("hunter2"));
        assert!(!e.to_string().contains("oops"));
    }
}
