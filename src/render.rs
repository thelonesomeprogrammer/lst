//! Marker substitution in raw text. Pure: text and a resolver in, text out.
//!
//! Substitution is raw text (see `docs/design.md`): values are inserted
//! as-is, without YAML quoting or escaping, and every byte outside a marker
//! is copied verbatim. Text without markers renders byte-identically.
//!
//! Stacks with `x-deploy` take the YAML path in [`crate::xdeploy`] instead
//! (which uses this for its `render:` files and for every string scalar).

use std::collections::BTreeMap;
use std::fmt;

use crate::crypto::SecretString;
use crate::marker::{self, MarkerKind, ParseError};

/// A marker name that could not be resolved, with the resolver's error.
#[derive(Debug)]
pub struct Unresolved<E> {
    /// The name as written in the marker (e.g. `db` or `shared/mqtt`).
    pub name: String,
    pub error: E,
}

#[derive(Debug)]
pub enum RenderError<E> {
    /// The text has a malformed marker. `pos` is a byte offset into it.
    Parse(ParseError),
    /// One entry per failing marker name, sorted by name and deduplicated
    /// (the first failure of each name is kept). Never empty.
    Unresolved(Vec<Unresolved<E>>),
}

impl<E: fmt::Display> fmt::Display for RenderError<E> {
    /// Shows only what the resolver's errors show; the resolver must keep
    /// values out of them (`store::ResolveError` names secrets only).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RenderError::Parse(e) => write!(f, "{e}"),
            RenderError::Unresolved(list) => {
                let plural = if list.len() == 1 { "" } else { "s" };
                write!(f, "could not resolve {} secret{plural}:", list.len())?;
                for u in list {
                    write!(f, "\n  {}", u.error)?;
                }
                Ok(())
            }
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for RenderError<E> {}

/// Replaces every marker in `text` with `resolve(marker)`.
///
/// `resolve` is called once per marker occurrence, in order, even after a
/// failure, so that every failing name is reported at once.
pub fn render<E>(
    text: &str,
    mut resolve: impl FnMut(&MarkerKind) -> Result<SecretString, E>,
) -> Result<SecretString, RenderError<E>> {
    let markers = marker::parse(text).map_err(RenderError::Parse)?;

    let mut values = Vec::with_capacity(markers.len());
    let mut failures: BTreeMap<String, E> = BTreeMap::new();
    for m in &markers {
        match resolve(&m.kind) {
            Ok(v) => values.push(v),
            Err(e) => {
                failures.entry(m.kind.name().to_owned()).or_insert(e);
            }
        }
    }
    if !failures.is_empty() {
        let list = failures
            .into_iter()
            .map(|(name, error)| Unresolved { name, error })
            .collect();
        return Err(RenderError::Unresolved(list));
    }

    // Spans are in bounds and don't overlap, so this can't underflow.
    let marker_bytes: usize = markers.iter().map(|m| m.span.len()).sum();
    let value_bytes: usize = values.iter().map(|v| v.expose().len()).sum();
    let len = text.len() - marker_bytes + value_bytes;
    // Exact capacity up front: the buffer never reallocates, so no partial
    // unzeroized copy of a secret is left behind.
    let mut out = SecretString::new(String::with_capacity(len));
    let s = out.as_mut_string();
    let mut copied = 0;
    for (m, v) in markers.iter().zip(&values) {
        s.push_str(&text[copied..m.span.start]);
        s.push_str(v.expose());
        copied = m.span.end;
    }
    s.push_str(&text[copied..]);
    Ok(out)
}

/// `value` as it must appear in a compose file: every `$` doubled.
///
/// Compose interpolates `$` (`$VAR`, `${VAR}`) in every value of the file it
/// reads and turns `$$` back into a literal `$`. Rendered secrets are data,
/// not templates, so every value substituted into compose text goes through
/// this (decided 2026-11-07); text the user wrote around a marker is left
/// alone. Values that don't pass through compose (`render:` files, `run:`
/// commands, `lst render --file`) stay as they are.
pub fn escape_compose(value: &SecretString) -> SecretString {
    let v = value.expose();
    let extra = v.bytes().filter(|&b| b == b'$').count();
    if extra == 0 {
        return value.clone();
    }
    // Exact capacity: the buffer never reallocates (no unzeroized copies).
    let mut out = SecretString::new(String::with_capacity(v.len() + extra));
    let s = out.as_mut_string();
    for c in v.chars() {
        if c == '$' {
            s.push('$');
        }
        s.push(c);
    }
    out
}

/// [`render`] for text that compose reads: each substituted value goes
/// through [`escape_compose`].
pub fn render_compose<E>(
    text: &str,
    mut resolve: impl FnMut(&MarkerKind) -> Result<SecretString, E>,
) -> Result<SecretString, RenderError<E>> {
    render(text, |m| resolve(m).map(|v| escape_compose(&v)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn escape_compose_doubles_every_dollar() {
        let esc = |v: &str| {
            escape_compose(&SecretString::new(v.into()))
                .expose()
                .to_owned()
        };
        assert_eq!(esc(""), "");
        assert_eq!(esc("plain"), "plain");
        assert_eq!(esc("pa$wo$$rd"), "pa$$wo$$$$rd");
        assert_eq!(esc("$"), "$$");
        assert_eq!(esc("${HOME}é$"), "$${HOME}é$$");
    }

    #[test]
    fn render_compose_escapes_values_only() {
        let resolve = |_: &MarkerKind| Ok::<_, String>(SecretString::new("a$b".into()));
        let out = render_compose("$$USER=<<gen:x>> $HOME", resolve).unwrap();
        assert_eq!(out.expose(), "$$USER=a$$b $HOME");
        // Errors pass through unchanged.
        let err = render_compose("<<gen:bad>>", fixed).unwrap_err();
        assert!(matches!(err, RenderError::Unresolved(ref l) if l[0].name == "bad"));
    }

    proptest! {
        #[test]
        fn escape_compose_round_trips(v in "\\PC*") {
            let e = escape_compose(&SecretString::new(v.clone()));
            prop_assert_eq!(e.expose().replace("$$", "$"), v.clone());
            prop_assert_eq!(e.expose().len(), v.len() + v.matches('$').count());
        }
    }

    /// gen → `G(name)`, secret → `S(name)`; names starting with `bad` fail,
    /// and so does every `set`.
    fn fixed(m: &MarkerKind) -> Result<SecretString, String> {
        if m.name().starts_with("bad") {
            return Err(format!("`{}` failed", m.name()));
        }
        match m {
            MarkerKind::Gen { name, .. } => Ok(SecretString::new(format!("G({name})"))),
            MarkerKind::Secret { name } => Ok(SecretString::new(format!("S({name})"))),
            MarkerKind::Set { name, .. } => Err(format!("`{name}` is a set marker")),
        }
    }

    fn ok(text: &str) -> String {
        render(text, fixed).unwrap().expose().to_owned()
    }

    fn names<E>(list: &[Unresolved<E>]) -> Vec<&str> {
        list.iter().map(|u| u.name.as_str()).collect()
    }

    #[test]
    fn substitutes_markers_and_keeps_everything_else() {
        assert_eq!(ok(""), "");
        assert_eq!(ok("<<gen:db>>"), "G(db)");
        let text = "services:\r\n  db:\r\n    environment:\r\n      PW: <<gen:db>>\r\n  \
                    app:\r\n      URL: \"postgres://ü:<<gen:db:hex64>>@db/<<secret:x>>?\"\r\n";
        let expected = "services:\r\n  db:\r\n    environment:\r\n      PW: G(db)\r\n  \
                        app:\r\n      URL: \"postgres://ü:G(db)@db/S(x)?\"\r\n";
        assert_eq!(ok(text), expected);
        // Adjacent markers, and YAML merge keys / heredocs left alone.
        assert_eq!(
            ok("<<: *d\n<<gen:a>><<secret:shared/b>>x<<EOF"),
            "<<: *d\nG(a)S(shared/b)x<<EOF"
        );
    }

    #[test]
    fn resolver_sees_every_occurrence_in_order() {
        let mut seen = Vec::new();
        let out = render("<<gen:a>> <<secret:b>> <<gen:a:uuid>>", |m| {
            seen.push(m.to_string());
            fixed(m)
        })
        .unwrap();
        assert_eq!(out.expose(), "G(a) S(b) G(a)");
        assert_eq!(seen, ["<<gen:a>>", "<<secret:b>>", "<<gen:a:uuid>>"]);
    }

    #[test]
    fn reports_every_failing_name_sorted_and_deduplicated() {
        let text = "<<gen:bad-z>> <<gen:ok>> <<secret:bad-a>> <<gen:bad-z:hex32>> \
                    <<set:x:v>> <<secret:bad-m>>";
        let err = render(text, fixed).unwrap_err();
        assert!(
            matches!(&err, RenderError::Unresolved(list)
                if names(list) == ["bad-a", "bad-m", "bad-z", "x"]
                    && list[3].error == "`x` is a set marker"),
            "{err:?}"
        );
        assert_eq!(
            err.to_string(),
            "could not resolve 4 secrets:\n  `bad-a` failed\n  `bad-m` failed\n  \
             `bad-z` failed\n  `x` is a set marker"
        );
        // No set value anywhere in the error.
        assert!(!format!("{err} {err:?}").contains(":v"));

        let err = render("a <<gen:bad>> b", fixed).unwrap_err();
        assert_eq!(
            err.to_string(),
            "could not resolve 1 secret:\n  `bad` failed"
        );
    }

    #[test]
    fn parse_errors_pass_through() {
        let err = render("x: <<gen:db", fixed).unwrap_err();
        assert!(
            matches!(&err, RenderError::Parse(e) if e.pos == 3),
            "{err:?}"
        );
        assert_eq!(
            err.to_string(),
            "byte 3: unterminated marker (missing `>>`)"
        );
        let as_error: &dyn std::error::Error = &err;
        assert!(as_error.source().is_none());
    }

    proptest! {
        #[test]
        fn text_without_markers_is_unchanged(
            text in prop_oneof!["\\PC*", "(<<|<|>>|>|[a-z]|:| |\n|\r|é)*"]
        ) {
            prop_assume!(marker::parse(&text).is_ok_and(|m| m.is_empty()));
            let out = render(&text, fixed).unwrap();
            prop_assert_eq!(out.expose().as_bytes(), text.as_bytes());
        }

        #[test]
        fn output_is_text_with_values_spliced_in(
            parts in prop::collection::vec(("[a-z \n:]{0,8}", "[a-z]{1,4}"), 0..6),
            tail in "[a-z \n]{0,8}",
        ) {
            let mut text = String::new();
            let mut expected = String::new();
            for (plain, name) in &parts {
                text.push_str(plain);
                text.push_str(&format!("<<gen:{name}>>"));
                expected.push_str(plain);
                expected.push_str(&format!("G({name})"));
            }
            text.push_str(&tail);
            expected.push_str(&tail);
            prop_assume!(!parts.iter().any(|(_, n)| n.starts_with("bad")));
            let out = render(&text, fixed).unwrap();
            prop_assert_eq!(out.expose(), expected.as_str());
        }
    }
}
