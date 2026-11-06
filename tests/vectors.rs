//! FROZEN test vectors. Generated once on 2026-11-06 and cross-checked
//! against an independent Python implementation of `docs/design.md` (the
//! reference `blake3` bindings and libsodium's XChaCha20-Poly1305).
//!
//! If one of these tests fails, the code is wrong, not the vector. Never
//! update a vector to make a test pass: every deployed secret depends on
//! these exact outputs.

use lst::crypto::{GenId, Sealed, Seed, derive_gen, encryption_key, fingerprint, open};
use lst::format::{Format, generate};

const SEED: [u8; 32] = [0x42; 32];
const ID_ZERO: [u8; 16] = [0x00; 16];
const ID_SEQ: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
const ID_FF: [u8; 16] = [0xff; 16];

fn seed() -> Seed {
    Seed::from_bytes(SEED)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn gen_str(id: [u8; 16], format: &str) -> String {
    let format: Format = format.parse().unwrap();
    generate(format, &mut derive_gen(&seed(), &GenId(id)))
        .expose()
        .to_owned()
}

#[test]
fn fingerprint_vector() {
    assert_eq!(fingerprint(&seed()), "4cfccc1865e245504448b72e59ed14e5");
}

#[test]
fn raw_stream_id_zero() {
    let mut buf = [0u8; 32];
    derive_gen(&seed(), &GenId(ID_ZERO)).fill(&mut buf);
    assert_eq!(
        hex(&buf),
        "e61a8a18db25a7d78c62c15d1fae238d325f22dc69d828150f68c3ab5095f448"
    );
    assert_eq!(GenId(ID_ZERO).to_hex(), "00000000000000000000000000000000");
}

#[test]
fn formats_id_zero() {
    let cases: &[(&str, &str)] = &[
        ("alnum32", "saOYhlrdQkHffyjRyhiireoVPqJvSZ6K"),
        ("alnum22", "saOYhlrdQkHffyjRyhiire"),
        (
            "alnum256",
            concat!(
                "saOYhlrdQkHffyjRyhiireoVPqJvSZ6KeDLH01zSGhZk5SCcTNNl7r5CnCdDxtUn",
                "aB13ABo4zDOmUy7UxaKn34zzq7cxgbfqr2leAvwy7heBZwUF33AR1pzeuaJmiO2w",
                "n9AAOTrkoXTHliiriJYGNwi7VaFIZZ0I9YuUVrRaY61YlC7UHo3koi3H6Q5eNjuI",
                "FnlMIUhEd9S9tMNlMzpMFDaKsCyPfDagrntQTOQHVZxoUCWc6k6G6EY3VJye6xjs",
            ),
        ),
        ("hex32", "e61a8a18db25a7d78c62c15d1fae238d"),
        ("hex33", "e61a8a18db25a7d78c62c15d1fae238d3"),
        (
            "hex64",
            "e61a8a18db25a7d78c62c15d1fae238d325f22dc69d828150f68c3ab5095f448",
        ),
        ("base64-22", "5hqKGNslp9eMYsFdH64jjT"),
        ("base64-32", "5hqKGNslp9eMYsFdH64jjTJfItxp2CgV"),
        ("base64-43", "5hqKGNslp9eMYsFdH64jjTJfItxp2CgVD2jDq1CV9Eg"),
        ("uuid", "e61a8a18-db25-47d7-8c62-c15d1fae238d"),
    ];
    for (format, expected) in cases {
        assert_eq!(gen_str(ID_ZERO, format), *expected, "{format}");
    }
}

#[test]
fn raw_stream_id_seq() {
    let mut buf = [0u8; 32];
    derive_gen(&seed(), &GenId(ID_SEQ)).fill(&mut buf);
    assert_eq!(
        hex(&buf),
        "0fcae54a4280fe910288b5f34e5ea6aadf9f15cde6c9139d37b9ad7e6fda4276"
    );
    assert_eq!(GenId(ID_SEQ).to_hex(), "0102030405060708090a0b0c0d0e0f10");
}

#[test]
fn formats_id_seq() {
    let cases: &[(&str, &str)] = &[
        ("alnum32", "PQrMEEVCM55QgquljVTsPTh39xCxgE4v"),
        ("alnum22", "PQrMEEVCM55QgquljVTsPT"),
        (
            "alnum256",
            concat!(
                "PQrMEEVCM55QgquljVTsPTh39xCxgE4vRf4pYAKWPQmJNdGQp4kUBcHlqIF6Uy8P",
                "33rinHdImbpwIFLYkuuNMPYjUeU5tXXoxIJibC5vsjDmo5wYgpFbhiXX9Bi4Ym1b",
                "NN4gmnrfBlMXTW38vdDEZNBHlo6OhIXJNUMggL5HoJJ02aKjtoeB9f3Sq2rO4GmZ",
                "lANwyJlnUMy5fKQJB4n6Z2BLW9YV4D815b0FHYTFrc7UNrqBWUwG4bdoF8iKAa3T",
            ),
        ),
        ("hex32", "0fcae54a4280fe910288b5f34e5ea6aa"),
        ("hex33", "0fcae54a4280fe910288b5f34e5ea6aad"),
        (
            "hex64",
            "0fcae54a4280fe910288b5f34e5ea6aadf9f15cde6c9139d37b9ad7e6fda4276",
        ),
        ("base64-22", "D8rlSkKA_pECiLXzTl6mqt"),
        ("base64-32", "D8rlSkKA_pECiLXzTl6mqt-fFc3myROd"),
        ("base64-43", "D8rlSkKA_pECiLXzTl6mqt-fFc3myROdN7mtfm_aQna"),
        ("uuid", "0fcae54a-4280-4e91-8288-b5f34e5ea6aa"),
    ];
    for (format, expected) in cases {
        assert_eq!(gen_str(ID_SEQ, format), *expected, "{format}");
    }
}

#[test]
fn raw_stream_id_ff() {
    let mut buf = [0u8; 32];
    derive_gen(&seed(), &GenId(ID_FF)).fill(&mut buf);
    assert_eq!(
        hex(&buf),
        "c1510ba6bf06be143e821b6450e2b0d3298dc91d035ab33bf94417b85d38da57"
    );
    assert_eq!(GenId(ID_FF).to_hex(), "ffffffffffffffffffffffffffffffff");
}

#[test]
fn formats_id_ff() {
    let cases: &[(&str, &str)] = &[
        ("alnum32", "HTLqFGEUAGbmSo0ZpRPdDc37GX8f4gZr"),
        ("alnum22", "HTLqFGEUAGbmSo0ZpRPdDc"),
        (
            "alnum256",
            concat!(
                "HTLqFGEUAGbmSo0ZpRPdDc37GX8f4gZrJC7E24s0v7sOgnINxHjWV47ZUKb2nagp",
                "uUSlUmUMTXtfIJPimLmV7z47SN0NubzjGCGQZiA65vsFjtr6bxtHr1iriUWPuTAZ",
                "0XqSiauybafO5oXKNHQYSahf4ptbzZPCZgXusmBj7NYMZSdWdlUqBqM0MAlBY3F6",
                "MtHlIeKAn1X52zOrT3ZieHj9gyfj0uCHLV3vXzWV7WJdki8tVRPI4CoFvfCoyHUb",
            ),
        ),
        ("hex32", "c1510ba6bf06be143e821b6450e2b0d3"),
        ("hex33", "c1510ba6bf06be143e821b6450e2b0d32"),
        (
            "hex64",
            "c1510ba6bf06be143e821b6450e2b0d3298dc91d035ab33bf94417b85d38da57",
        ),
        ("base64-22", "wVELpr8GvhQ-ghtkUOKw0y"),
        ("base64-32", "wVELpr8GvhQ-ghtkUOKw0ymNyR0DWrM7"),
        ("base64-43", "wVELpr8GvhQ-ghtkUOKw0ymNyR0DWrM7-UQXuF042lf"),
        ("uuid", "c1510ba6-bf06-4e14-be82-1b6450e2b0d3"),
    ];
    for (format, expected) in cases {
        assert_eq!(gen_str(ID_FF, format), *expected, "{format}");
    }
}

/// Pins the encryption-key derivation, the associated-data layout and the
/// AEAD without exposing the key: this blob was sealed once (random nonce)
/// and must open forever.
#[test]
fn decryption_vector() {
    let sealed = Sealed {
        nonce: unhex("73344cb15eedcfee533168a82a616c4be08a8b9a169439db")
            .try_into()
            .unwrap(),
        ciphertext: unhex(concat!(
            "36e22cde12192df9e9725307007dba97aaea2a6d39a2e2c51158c7471615662e",
            "34b516d26820b5c4a4d01bc0e496b443"
        )),
    };
    let key = encryption_key(&seed());
    let value = open(&key, "test/smtp", &sealed).unwrap();
    assert_eq!(value.expose(), "correct horse:battery>>staple\\ü");
    assert!(open(&key, "test/smtp2", &sealed).is_err());
    assert!(open(&key, "shared/smtp", &sealed).is_err());
}
