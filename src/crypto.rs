//! Seed handling, BLAKE3 key derivation, fingerprints and XChaCha20-Poly1305
//! sealing of manual secrets.
//!
//! Pure apart from the OS random generator (`getrandom`), which is used for
//! seeds, ids and nonces.
//!
//! # Frozen
//! The derive_key context strings, the derivation input layout
//! (`seed || id`, 48 raw bytes), the fingerprint truncation and the AEAD
//! associated-data layout are frozen. Changing any of them changes or
//! invalidates every secret ever produced. See `docs/design.md`.

use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use zeroize::{Zeroize, Zeroizing};

/// FROZEN: BLAKE3 derive_key context for generated secrets.
const CTX_GEN: &str = "lst v1 gen";
/// FROZEN: BLAKE3 derive_key context for the `.sec/` encryption key.
const CTX_SEC_ENCRYPTION: &str = "lst v1 sec-encryption";
/// FROZEN: BLAKE3 derive_key context for the seed fingerprint.
const CTX_FINGERPRINT: &str = "lst v1 fingerprint";
/// FROZEN (M4): BLAKE3 derive_key context for the `lst.render-hash` key.
/// Changing it changes every render hash, so every labelled container is
/// recreated once.
const CTX_RENDER_HASH: &str = "lst v1 render-hash";
/// FROZEN: prefix of the AEAD associated data; the full secret name follows.
const AD_PREFIX: &[u8] = b"lst v1 secret\0";

pub const SEED_LEN: usize = 32;
pub const ID_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
/// FROZEN: the fingerprint is the first 16 bytes of its derived key.
const FINGERPRINT_LEN: usize = 16;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("the OS random generator failed")]
    Random,
    #[error("encryption failed")]
    Encrypt,
    #[error("secret name must not contain a NUL byte")]
    InvalidName,
    #[error("invalid id: expected 32 lowercase hex characters")]
    InvalidId,
    /// Wrong key, wrong name, or tampered nonce/ciphertext. Deliberately
    /// carries no detail.
    #[error("decryption failed (wrong seed, wrong name, or corrupted ciphertext)")]
    Decrypt,
    #[error("decrypted value is not valid UTF-8")]
    NotUtf8,
    /// Deliberately carries no detail: the input may be (most of) a seed.
    #[error("invalid seed: expected 64 lowercase hex characters")]
    InvalidSeed,
}

fn random_fill(buf: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(buf).map_err(|_| CryptoError::Random)
}

/// Appends `bytes` as lowercase hex, high nibble first.
pub(crate) fn push_hex(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &b in bytes {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
}

/// The 32-byte master seed. Zeroized on drop; `Debug` is redacted.
#[derive(Clone)]
pub struct Seed(Zeroizing<[u8; SEED_LEN]>);

impl Seed {
    /// A fresh seed from the OS random generator.
    pub fn generate() -> Result<Seed, CryptoError> {
        let mut seed = Seed(Zeroizing::new([0; SEED_LEN]));
        random_fill(&mut seed.0[..])?;
        Ok(seed)
    }

    pub fn from_bytes(bytes: [u8; SEED_LEN]) -> Seed {
        Seed(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; SEED_LEN] {
        &self.0
    }

    /// 64 lowercase hex characters (the `.env` representation). Returned as
    /// a [`SecretString`] so the hex copy is zeroized too.
    pub fn to_hex(&self) -> SecretString {
        let mut s = SecretString::new(String::with_capacity(SEED_LEN * 2));
        // Capacity is reserved up front, so push_hex never reallocates and
        // leaves no unzeroized partial copy behind.
        push_hex(s.as_mut_string(), &self.0[..]);
        s
    }

    /// Parses exactly 64 lowercase hex characters. Decodes straight into the
    /// zeroizing seed buffer; the error never contains the input.
    pub fn from_hex(s: &str) -> Result<Seed, CryptoError> {
        fn nibble(c: u8) -> Result<u8, CryptoError> {
            match c {
                b'0'..=b'9' => Ok(c - b'0'),
                b'a'..=b'f' => Ok(c - b'a' + 10),
                _ => Err(CryptoError::InvalidSeed),
            }
        }
        let s = s.as_bytes();
        if s.len() != SEED_LEN * 2 {
            return Err(CryptoError::InvalidSeed);
        }
        let mut seed = Seed(Zeroizing::new([0; SEED_LEN]));
        for (out, pair) in seed.0.iter_mut().zip(s.chunks_exact(2)) {
            *out = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        }
        Ok(seed)
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Seed(<redacted>)")
    }
}

/// Random id of a generated secret. Public (it is committed in `.sec/`);
/// the secret is derived from `seed || id`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GenId(pub [u8; ID_LEN]);

impl GenId {
    /// A fresh id from the OS random generator.
    pub fn generate() -> Result<GenId, CryptoError> {
        let mut id = [0; ID_LEN];
        random_fill(&mut id)?;
        Ok(GenId(id))
    }

    /// 32 lowercase hex characters (the `.sec/` representation).
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(ID_LEN * 2);
        push_hex(&mut s, &self.0);
        s
    }

    /// Parses exactly 32 lowercase hex characters.
    pub fn from_hex(s: &str) -> Result<GenId, CryptoError> {
        fn nibble(c: u8) -> Result<u8, CryptoError> {
            match c {
                b'0'..=b'9' => Ok(c - b'0'),
                b'a'..=b'f' => Ok(c - b'a' + 10),
                _ => Err(CryptoError::InvalidId),
            }
        }
        let s = s.as_bytes();
        if s.len() != ID_LEN * 2 {
            return Err(CryptoError::InvalidId);
        }
        let mut id = [0; ID_LEN];
        for (out, pair) in id.iter_mut().zip(s.chunks_exact(2)) {
            *out = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        }
        Ok(GenId(id))
    }
}

/// A secret value (generated or decrypted). Zeroized on drop; `Debug` is
/// redacted. There is deliberately no `Display` and no `PartialEq`.
#[derive(Clone, Default)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn new(value: String) -> SecretString {
        SecretString(Zeroizing::new(value))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Mutable access for building a value in place without leaving
    /// unzeroized copies behind. Callers must not shrink-then-grow in a way
    /// that reallocates; reserve capacity up front.
    pub(crate) fn as_mut_string(&mut self) -> &mut String {
        &mut self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

/// Key for sealing manual secrets in `.sec/`. Zeroized on drop; no accessor.
pub struct EncryptionKey(Zeroizing<[u8; 32]>);

impl fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EncryptionKey(<redacted>)")
    }
}

/// An encrypted manual secret: random nonce + ciphertext (with the 16-byte
/// Poly1305 tag appended).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// The XOF stream a generated secret is encoded from. Zeroized on drop;
/// `Debug` is redacted.
pub struct GenStream(blake3::OutputReader);

impl GenStream {
    /// Fills `buf` with the next bytes of the stream.
    pub fn fill(&mut self, buf: &mut [u8]) {
        self.0.fill(buf);
    }

    /// The next single byte of the stream.
    pub fn next_byte(&mut self) -> u8 {
        let mut b = [0u8; 1];
        self.0.fill(&mut b);
        b[0]
    }
}

impl Drop for GenStream {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for GenStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GenStream(<redacted>)")
    }
}

/// FROZEN: `derive_key("lst v1 gen", seed || id)` as an XOF stream, where
/// `seed || id` is the 32 raw seed bytes followed by the 16 raw id bytes.
pub fn derive_gen(seed: &Seed, id: &GenId) -> GenStream {
    let mut hasher = blake3::Hasher::new_derive_key(CTX_GEN);
    hasher.update(&seed.0[..]);
    hasher.update(&id.0);
    let reader = hasher.finalize_xof();
    hasher.zeroize();
    GenStream(reader)
}

/// FROZEN: `derive_key("lst v1 sec-encryption", seed)`.
pub fn encryption_key(seed: &Seed) -> EncryptionKey {
    EncryptionKey(Zeroizing::new(blake3::derive_key(
        CTX_SEC_ENCRYPTION,
        &seed.0[..],
    )))
}

/// FROZEN: first 16 bytes of `derive_key("lst v1 fingerprint", seed)`,
/// as 32 lowercase hex characters.
pub fn fingerprint(seed: &Seed) -> String {
    let full = Zeroizing::new(blake3::derive_key(CTX_FINGERPRINT, &seed.0[..]));
    let mut s = String::with_capacity(FINGERPRINT_LEN * 2);
    push_hex(&mut s, &full[..FINGERPRINT_LEN]);
    s
}

/// Key for the `lst.render-hash` labels (`docs/design.md`, "x-deploy
/// details"). Zeroized on drop; `Debug` is redacted; no accessor.
pub struct RenderHashKey(Zeroizing<[u8; 32]>);

impl fmt::Debug for RenderHashKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RenderHashKey(<redacted>)")
    }
}

/// FROZEN: `derive_key("lst v1 render-hash", seed)`.
pub fn render_hash_key(seed: &Seed) -> RenderHashKey {
    RenderHashKey(Zeroizing::new(blake3::derive_key(
        CTX_RENDER_HASH,
        &seed.0[..],
    )))
}

impl RenderHashKey {
    /// A keyed BLAKE3 hasher (`blake3::Hasher::new_keyed`) under this key.
    /// Feeding it a message and calling [`KeyedHasher::finalize_hex`] gives
    /// the same result as `blake3::keyed_hash(key, message)`.
    pub fn hasher(&self) -> KeyedHasher {
        KeyedHasher(blake3::Hasher::new_keyed(&self.0))
    }
}

/// An incremental keyed BLAKE3 hash. Its state depends on the key and on
/// the (secret) input, so it is zeroized on drop; `Debug` is redacted.
pub struct KeyedHasher(blake3::Hasher);

impl KeyedHasher {
    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    /// The 32-byte keyed hash of everything fed in, as 64 lowercase hex
    /// characters. Without the key it reveals nothing about the input.
    pub fn finalize_hex(self) -> String {
        let hash = self.0.finalize();
        let mut s = String::with_capacity(64);
        push_hex(&mut s, hash.as_bytes());
        s
    }
}

impl Drop for KeyedHasher {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for KeyedHasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyedHasher(<redacted>)")
    }
}

/// FROZEN: AD = `"lst v1 secret\0"` + full name (UTF-8).
fn associated_data(full_name: &str) -> Result<Vec<u8>, CryptoError> {
    if full_name.as_bytes().contains(&0) {
        return Err(CryptoError::InvalidName);
    }
    let mut ad = Vec::with_capacity(AD_PREFIX.len() + full_name.len());
    ad.extend_from_slice(AD_PREFIX);
    ad.extend_from_slice(full_name.as_bytes());
    Ok(ad)
}

fn cipher(key: &EncryptionKey) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(&Key::from(*key.0))
}

/// Encrypts `plaintext` under `key`, bound to `full_name` (`stack/name` or
/// `shared/name`), with a fresh random 24-byte nonce.
pub fn seal(key: &EncryptionKey, full_name: &str, plaintext: &str) -> Result<Sealed, CryptoError> {
    let ad = associated_data(full_name)?;
    let mut nonce = [0u8; NONCE_LEN];
    random_fill(&mut nonce)?;
    let ciphertext = cipher(key)
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext.as_bytes(),
                aad: &ad,
            },
        )
        // Only fails past the cipher's message-length limit (~256 GiB).
        .map_err(|_| CryptoError::Encrypt)?;
    Ok(Sealed { nonce, ciphertext })
}

/// Decrypts a sealed secret. Fails if the key, the name, the nonce or the
/// ciphertext don't match what was sealed.
pub fn open(
    key: &EncryptionKey,
    full_name: &str,
    sealed: &Sealed,
) -> Result<SecretString, CryptoError> {
    let ad = associated_data(full_name)?;
    let plain = cipher(key)
        .decrypt(
            &XNonce::from(sealed.nonce),
            Payload {
                msg: &sealed.ciphertext,
                aad: &ad,
            },
        )
        .map_err(|_| CryptoError::Decrypt)?;
    match String::from_utf8(plain) {
        Ok(s) => Ok(SecretString::new(s)),
        Err(e) => {
            let mut bytes = e.into_bytes();
            bytes.zeroize();
            Err(CryptoError::NotUtf8)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(b: u8) -> Seed {
        Seed::from_bytes([b; SEED_LEN])
    }

    #[test]
    fn seal_open_round_trip() {
        let key = encryption_key(&seed(1));
        for value in ["", "x", "p@ss:w>>rd\\", "ünïcødé 🔑", &"a".repeat(10_000)] {
            let sealed = seal(&key, "stack/name", value).unwrap();
            assert_eq!(sealed.ciphertext.len(), value.len() + 16);
            assert_eq!(open(&key, "stack/name", &sealed).unwrap().expose(), value);
        }
    }

    #[test]
    fn nonces_are_fresh() {
        let key = encryption_key(&seed(1));
        let a = seal(&key, "s/n", "same").unwrap();
        let b = seal(&key, "s/n", "same").unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn open_rejects_tampering_and_wrong_inputs() {
        let key = encryption_key(&seed(1));
        let sealed = seal(&key, "stack/smtp", "hunter2").unwrap();

        for i in 0..sealed.ciphertext.len() {
            let mut t = sealed.clone();
            t.ciphertext[i] ^= 0x01;
            assert_eq!(
                open(&key, "stack/smtp", &t).unwrap_err(),
                CryptoError::Decrypt
            );
        }
        for i in 0..NONCE_LEN {
            let mut t = sealed.clone();
            t.nonce[i] ^= 0x80;
            assert_eq!(
                open(&key, "stack/smtp", &t).unwrap_err(),
                CryptoError::Decrypt
            );
        }
        let mut truncated = sealed.clone();
        truncated.ciphertext.pop();
        assert_eq!(
            open(&key, "stack/smtp", &truncated).unwrap_err(),
            CryptoError::Decrypt
        );

        let wrong_key = encryption_key(&seed(2));
        assert_eq!(
            open(&wrong_key, "stack/smtp", &sealed).unwrap_err(),
            CryptoError::Decrypt
        );
        // Bound to the name: moving it under another name fails.
        assert_eq!(
            open(&key, "stack/cloudflare", &sealed).unwrap_err(),
            CryptoError::Decrypt
        );
        assert_eq!(
            open(&key, "shared/smtp", &sealed).unwrap_err(),
            CryptoError::Decrypt
        );
    }

    #[test]
    fn open_rejects_non_utf8_plaintext() {
        // seal() only takes &str, so build a valid ciphertext of invalid
        // UTF-8 directly with the same AD layout.
        let key = encryption_key(&seed(1));
        let nonce = [7u8; NONCE_LEN];
        let ad = associated_data("s/n").unwrap();
        let ciphertext = cipher(&key)
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &[0xff, 0xfe],
                    aad: &ad,
                },
            )
            .unwrap();
        let sealed = Sealed { nonce, ciphertext };
        assert_eq!(
            open(&key, "s/n", &sealed).unwrap_err(),
            CryptoError::NotUtf8
        );
    }

    #[test]
    fn nul_in_name_is_rejected_by_open_too() {
        let key = encryption_key(&seed(1));
        let sealed = seal(&key, "s/n", "v").unwrap();
        assert_eq!(
            open(&key, "s\0n", &sealed).unwrap_err(),
            CryptoError::InvalidName
        );
    }

    #[test]
    fn nul_in_name_is_rejected() {
        let key = encryption_key(&seed(1));
        assert_eq!(
            seal(&key, "a\0b", "v").unwrap_err(),
            CryptoError::InvalidName
        );
    }

    #[test]
    fn debug_is_redacted() {
        let s = seed(0xab);
        let mut hasher = render_hash_key(&s).hasher();
        hasher.update(b"topsecret");
        let out = format!(
            "{:?} {:?} {:?} {:?} {:?} {:?}",
            s,
            encryption_key(&s),
            SecretString::new("topsecret".into()),
            derive_gen(&s, &GenId([0; ID_LEN])),
            render_hash_key(&s),
            hasher,
        );
        assert!(!out.contains("ab") && !out.contains("171") && !out.contains("topsecret"));
        assert!(out.contains("<redacted>"));
    }

    #[test]
    fn gen_id_hex_round_trip() {
        let id = GenId([
            0x00, 0x01, 0x7f, 0x80, 0xff, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
        ]);
        let hex = id.to_hex();
        assert_eq!(hex, "00017f80ff090a0b0c0d0e0f10111213");
        assert_eq!(GenId::from_hex(&hex).unwrap(), id);
        for bad in [
            "",
            "00",
            &hex.to_uppercase(),
            &format!("{hex}0"),
            &hex.replace('0', "g"),
        ] {
            assert_eq!(
                GenId::from_hex(bad).unwrap_err(),
                CryptoError::InvalidId,
                "{bad}"
            );
        }
    }

    #[test]
    fn seed_hex_round_trip() {
        let mut bytes = [0u8; SEED_LEN];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37) ^ 0xa5;
        }
        let s = Seed::from_bytes(bytes);
        let hex = s.to_hex();
        assert_eq!(hex.expose().len(), 64);
        assert_eq!(Seed::from_hex(hex.expose()).unwrap().as_bytes(), &bytes);
        let good = hex.expose().to_owned();
        let bad_inputs = [
            String::new(),
            good[..62].to_owned(),
            format!("{good}0"),
            good.to_uppercase(),
            format!("g{}", &good[1..]),
            format!("{}g", &good[..63]),
            format!(" {}", &good[1..]),
            // 64 bytes, but not 64 ASCII hex characters.
            format!("é{}", &good[2..]),
        ];
        for bad in &bad_inputs {
            let err = Seed::from_hex(bad).unwrap_err();
            assert_eq!(err, CryptoError::InvalidSeed);
            let msg = format!("{err} {err:?}");
            assert!(!msg.contains(&good[..8]));
        }
    }

    #[test]
    fn random_values_differ() {
        assert_ne!(
            Seed::generate().unwrap().as_bytes(),
            Seed::generate().unwrap().as_bytes()
        );
        assert_ne!(GenId::generate().unwrap(), GenId::generate().unwrap());
    }

    #[test]
    fn derivation_depends_on_seed_and_id() {
        let read = |s: &Seed, id: &GenId| {
            let mut b = [0u8; 32];
            derive_gen(s, id).fill(&mut b);
            b
        };
        let id0 = GenId([0; ID_LEN]);
        let id1 = GenId([1; ID_LEN]);
        assert_eq!(read(&seed(1), &id0), read(&seed(1), &id0));
        assert_ne!(read(&seed(1), &id0), read(&seed(2), &id0));
        assert_ne!(read(&seed(1), &id0), read(&seed(1), &id1));
        // derive_gen must equal the documented one-shot derive_key over the
        // 48-byte `seed || id`.
        let mut km = [0u8; 48];
        km[..32].copy_from_slice(seed(1).as_bytes());
        km[32..].copy_from_slice(&id1.0);
        assert_eq!(read(&seed(1), &id1), blake3::derive_key(CTX_GEN, &km));
    }

    #[test]
    fn render_hash_is_keyed_blake3_under_the_derived_key() {
        let hash = |s: &Seed, parts: &[&[u8]]| {
            let mut h = render_hash_key(s).hasher();
            for p in parts {
                h.update(p);
            }
            h.finalize_hex()
        };
        let key = blake3::derive_key(CTX_RENDER_HASH, seed(1).as_bytes());
        let expected = blake3::keyed_hash(&key, b"abcdef").to_hex().to_string();
        assert_eq!(hash(&seed(1), &[b"abcdef"]), expected);
        // Incremental: how the message is split doesn't matter.
        assert_eq!(hash(&seed(1), &[b"ab", b"", b"cdef"]), expected);
        assert_eq!(expected.len(), 64);
        assert_ne!(hash(&seed(2), &[b"abcdef"]), expected);
        assert_ne!(hash(&seed(1), &[b"abcdeg"]), expected);
        // Not the plain (unkeyed) hash, and not another context's key.
        assert_ne!(expected, blake3::hash(b"abcdef").to_hex().to_string());
        let other = blake3::derive_key(CTX_FINGERPRINT, seed(1).as_bytes());
        assert_ne!(
            expected,
            blake3::keyed_hash(&other, b"abcdef").to_hex().to_string()
        );
    }
}
