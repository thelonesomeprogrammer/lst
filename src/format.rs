//! Encoding of the generated-secret XOF stream into formatted strings.
//!
//! # Frozen
//! Every encoder below, its alphabet, its N limits and the exact order in
//! which it consumes bytes from the stream are frozen (see
//! `docs/design.md` → "Frozen encoding details" and `tests/vectors.rs`).
//! N always counts output characters. Bytes are always consumed from the
//! start of the stream, in order.

use std::fmt;
use std::str::FromStr;

use zeroize::Zeroizing;

use crate::crypto::{GenStream, SecretString, push_hex};

/// FROZEN: alnum alphabet, in this order: `A–Z`, `a–z`, `0–9`.
const ALNUM: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
/// FROZEN: rejection threshold for alnum, the largest multiple of 62 ≤ 256.
const ALNUM_LIMIT: u8 = 248; // 4 * 62
/// FROZEN: RFC 4648 §5 URL-safe base64 alphabet.
const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// FROZEN: N limits (at least 128 bits of randomness, at most 256 chars).
pub const ALNUM_MIN: u16 = 22;
pub const HEX_MIN: u16 = 32;
pub const BASE64_MIN: u16 = 22;
pub const MAX_LEN: u16 = 256;

/// Output format of a generated secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Format {
    /// `alnumN`: N characters from `[A-Za-z0-9]`.
    Alnum(u16),
    /// `hexN`: N lowercase hex characters.
    Hex(u16),
    /// `base64-N`: N characters of URL-safe unpadded base64.
    Base64(u16),
    /// `uuid`: a v4-layout UUID.
    Uuid,
}

impl Default for Format {
    fn default() -> Self {
        Format::Alnum(32)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FormatError {
    #[error("unknown format (expected alnumN, hexN, base64-N or uuid)")]
    Unknown,
    #[error("format length must be between {min} and {max}")]
    OutOfRange { min: u16, max: u16 },
}

impl FromStr for Format {
    type Err = FormatError;

    /// Accepts exactly the canonical spellings: `alnumN`, `hexN`,
    /// `base64-N`, `uuid`. Case-sensitive; N is decimal without leading
    /// zeros, so every format has exactly one spelling.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "uuid" {
            return Ok(Format::Uuid);
        }
        let (ctor, min, digits): (fn(u16) -> Format, u16, &str) =
            if let Some(d) = s.strip_prefix("base64-") {
                (Format::Base64, BASE64_MIN, d)
            } else if let Some(d) = s.strip_prefix("alnum") {
                (Format::Alnum, ALNUM_MIN, d)
            } else if let Some(d) = s.strip_prefix("hex") {
                (Format::Hex, HEX_MIN, d)
            } else {
                return Err(FormatError::Unknown);
            };
        if digits.is_empty()
            || !digits.bytes().all(|b| b.is_ascii_digit())
            || digits.starts_with('0')
        {
            return Err(FormatError::Unknown);
        }
        let range = FormatError::OutOfRange { min, max: MAX_LEN };
        let n: u16 = digits.parse().map_err(|_| range)?;
        if !(min..=MAX_LEN).contains(&n) {
            return Err(range);
        }
        Ok(ctor(n))
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Format::Alnum(n) => write!(f, "alnum{n}"),
            Format::Hex(n) => write!(f, "hex{n}"),
            Format::Base64(n) => write!(f, "base64-{n}"),
            Format::Uuid => f.write_str("uuid"),
        }
    }
}

impl Format {
    /// Length of the generated string in characters.
    pub fn output_len(self) -> usize {
        match self {
            Format::Alnum(n) | Format::Hex(n) | Format::Base64(n) => usize::from(n),
            Format::Uuid => 36,
        }
    }
}

/// Encodes a generated secret from a fresh stream (see `crypto::derive_gen`).
///
/// A `Format` can only be built with valid N through `FromStr`; a `Format`
/// constructed directly with an out-of-range N is still encoded as asked
/// (the limits are a policy on what markers may request).
pub fn generate(format: Format, stream: &mut GenStream) -> SecretString {
    // Capacity is reserved up front so the string never reallocates and
    // leaves no unzeroized copy behind.
    let mut out = SecretString::new(String::with_capacity(format.output_len() + 4));
    let s = out.as_mut_string();
    match format {
        // FROZEN: read one byte at a time. b < 248 → ALNUM[b % 62];
        // b ≥ 248 → discard. Stop after N characters.
        Format::Alnum(n) => {
            while s.len() < usize::from(n) {
                let b = stream.next_byte();
                if b < ALNUM_LIMIT {
                    s.push(char::from(ALNUM[usize::from(b % 62)]));
                }
            }
        }
        // FROZEN: read ⌈N/2⌉ bytes; lowercase hex, high nibble first;
        // truncate to N characters.
        Format::Hex(n) => {
            let n = usize::from(n);
            let mut bytes = Zeroizing::new(vec![0u8; n.div_ceil(2)]);
            stream.fill(&mut bytes);
            push_hex(s, &bytes);
            s.truncate(n);
        }
        // FROZEN: read ⌈3N/4⌉ bytes; RFC 4648 URL-safe base64, big-endian
        // 6-bit groups, unpadded; truncate to N characters.
        Format::Base64(n) => {
            let n = usize::from(n);
            let mut bytes = Zeroizing::new(vec![0u8; (3 * n).div_ceil(4)]);
            stream.fill(&mut bytes);
            push_base64url(s, &bytes);
            s.truncate(n);
        }
        // FROZEN: read 16 bytes; b[6] = (b[6] & 0x0f) | 0x40 (version 4),
        // b[8] = (b[8] & 0x3f) | 0x80 (RFC 4122 variant); lowercase
        // 8-4-4-4-12.
        Format::Uuid => {
            let mut b = Zeroizing::new([0u8; 16]);
            stream.fill(&mut b[..]);
            b[6] = (b[6] & 0x0f) | 0x40;
            b[8] = (b[8] & 0x3f) | 0x80;
            for (i, range) in [0..4, 4..6, 6..8, 8..10, 10..16].into_iter().enumerate() {
                if i > 0 {
                    s.push('-');
                }
                push_hex(s, &b[range]);
            }
        }
    }
    out
}

/// Unpadded URL-safe base64 (RFC 4648 §5).
fn push_base64url(out: &mut String, bytes: &[u8]) {
    let sym = |v: u32| char::from(BASE64URL[(v & 0x3f) as usize]);
    for chunk in bytes.chunks(3) {
        let mut group = [0u8; 3];
        group[..chunk.len()].copy_from_slice(chunk);
        let v = u32::from(group[0]) << 16 | u32::from(group[1]) << 8 | u32::from(group[2]);
        // 1 byte → 2 chars, 2 bytes → 3 chars, 3 bytes → 4 chars.
        for i in 0..=chunk.len() {
            out.push(sym(v >> (18 - 6 * i)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{GenId, Seed, derive_gen};
    use proptest::prelude::*;

    fn gen_with(seed: u8, id: [u8; 16], format: Format) -> String {
        let mut stream = derive_gen(&Seed::from_bytes([seed; 32]), &GenId(id));
        generate(format, &mut stream).expose().to_owned()
    }

    #[test]
    fn parse_display_round_trip() {
        for s in [
            "alnum22",
            "alnum32",
            "alnum256",
            "hex32",
            "hex33",
            "hex64",
            "hex256",
            "base64-22",
            "base64-32",
            "base64-256",
            "uuid",
        ] {
            let f: Format = s.parse().unwrap();
            assert_eq!(f.to_string(), s);
        }
        assert_eq!(Format::default().to_string(), "alnum32");
    }

    #[test]
    fn parse_errors() {
        use FormatError::*;
        let cases: &[(&str, FormatError)] = &[
            ("", Unknown),
            ("alnum", Unknown),
            ("hex", Unknown),
            ("base64", Unknown),
            ("base64-", Unknown),
            ("base6432", Unknown),
            ("hex064", Unknown),
            ("hex+64", Unknown),
            ("HEX64", Unknown),
            ("Uuid", Unknown),
            ("uuid4", Unknown),
            ("hex 64", Unknown),
            ("password", Unknown),
            ("alnum21", OutOfRange { min: 22, max: 256 }),
            ("alnum257", OutOfRange { min: 22, max: 256 }),
            ("hex31", OutOfRange { min: 32, max: 256 }),
            ("hex99999999999999999999", OutOfRange { min: 32, max: 256 }),
            ("base64-21", OutOfRange { min: 22, max: 256 }),
            ("base64-1000", OutOfRange { min: 22, max: 256 }),
        ];
        for (s, err) in cases {
            assert_eq!(s.parse::<Format>().unwrap_err(), *err, "{s:?}");
        }
    }

    #[test]
    fn base64url_matches_rfc4648_vectors() {
        // RFC 4648 §10 test vectors (unpadded); URL-safe chars via 0xfb/0xff.
        for (input, expected) in [
            (&b""[..], ""),
            (b"f", "Zg"),
            (b"fo", "Zm8"),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg"),
            (b"fooba", "Zm9vYmE"),
            (b"foobar", "Zm9vYmFy"),
            (&[0xfb, 0xff], "-_8"),
        ] {
            let mut s = String::new();
            push_base64url(&mut s, input);
            assert_eq!(s, expected);
        }
    }

    #[test]
    fn alnum_rejection_path_is_exercised() {
        // The stream for this seed/id must contain bytes ≥ 248 within the
        // first 32 accepted characters; otherwise this test proves nothing.
        let mut stream = derive_gen(&Seed::from_bytes([0x42; 32]), &GenId([0; 16]));
        let (mut accepted, mut rejected) = (0, 0);
        while accepted < 256 {
            if stream.next_byte() < ALNUM_LIMIT {
                accepted += 1;
            } else {
                rejected += 1;
            }
        }
        assert!(rejected > 0);
    }

    fn check_shape(format: Format, s: &str) {
        assert_eq!(s.len(), format.output_len());
        match format {
            Format::Alnum(_) => assert!(s.bytes().all(|b| b.is_ascii_alphanumeric())),
            Format::Hex(_) => assert!(s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))),
            Format::Base64(_) => assert!(s.bytes().all(|b| BASE64URL.contains(&b))),
            Format::Uuid => {
                let parts: Vec<&str> = s.split('-').collect();
                assert_eq!(
                    parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
                    [8, 4, 4, 4, 12]
                );
                assert!(
                    s.bytes()
                        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'-'))
                );
                assert_eq!(&s[14..15], "4");
                assert!(matches!(&s[19..20], "8" | "9" | "a" | "b"));
            }
        }
    }

    fn any_format() -> impl Strategy<Value = Format> {
        prop_oneof![
            (ALNUM_MIN..=MAX_LEN).prop_map(Format::Alnum),
            (HEX_MIN..=MAX_LEN).prop_map(Format::Hex),
            (BASE64_MIN..=MAX_LEN).prop_map(Format::Base64),
            Just(Format::Uuid),
        ]
    }

    proptest! {
        #[test]
        fn every_format_has_the_right_shape(
            seed in any::<u8>(), id in any::<[u8; 16]>(), format in any_format()
        ) {
            check_shape(format, &gen_with(seed, id, format));
        }

        #[test]
        fn shorter_hex_and_base64_are_prefixes(id in any::<[u8; 16]>(), a in 32u16..=256, b in 32u16..=256) {
            let (short, long) = (a.min(b), a.max(b));
            prop_assert!(gen_with(7, id, Format::Hex(long)).starts_with(&gen_with(7, id, Format::Hex(short))));
            prop_assert!(gen_with(7, id, Format::Base64(long)).starts_with(&gen_with(7, id, Format::Base64(short))));
            prop_assert!(gen_with(7, id, Format::Alnum(long)).starts_with(&gen_with(7, id, Format::Alnum(short))));
        }

        #[test]
        fn parse_never_panics(s in "\\PC*") {
            let _ = s.parse::<Format>();
        }
    }
}
