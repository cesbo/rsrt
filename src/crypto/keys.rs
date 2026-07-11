//! Key material: SEK/KEK containers, PBKDF2 KEK derivation, RFC 3394 wrap.
//!
//! docs/spec/encryption.md §4.

use std::fmt;

use aes_kw::{
    KeyInit,
    KwAes128,
    KwAes192,
    KwAes256,
};
use zeroize::Zeroize;

use super::CryptoError;

/// SRTO_PASSPHRASE minimum length in bytes (docs/spec/encryption.md §2).
pub const PASSPHRASE_MIN: usize = 10;
/// Maximum passphrase length. `srt.h` documents 79 but the libsrt 1.4.4
/// code accepts 80 (`HAICRYPT_SECRET_MAX_SZ`) — accept 80 (§2 trap).
pub const PASSPHRASE_MAX: usize = 80;

/// PBKDF2 iteration count (`haicrypt.h:HAICRYPT_PBKDF2_ITER_CNT`).
pub const PBKDF2_ITERATIONS: u32 = 2048;

/// AES key length (SRTO_PBKEYLEN). SEK and KEK always share this length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyLength {
    Aes128,
    Aes192,
    Aes256,
}

impl KeyLength {
    pub const fn bytes(self) -> usize {
        match self {
            KeyLength::Aes128 => 16,
            KeyLength::Aes192 => 24,
            KeyLength::Aes256 => 32,
        }
    }

    pub const fn from_bytes(n: usize) -> Option<KeyLength> {
        match n {
            16 => Some(KeyLength::Aes128),
            24 => Some(KeyLength::Aes192),
            32 => Some(KeyLength::Aes256),
            _ => None,
        }
    }
}

/// Secret bytes (a SEK or KEK), zeroized on drop and redacted in Debug.
/// Key bytes must never reach logs.
pub struct SecretKey(Box<[u8]>);

impl SecretKey {
    /// Fresh random key from the OS RNG (libsrt uses `RAND_bytes`; §4.1).
    pub fn generate(len: KeyLength) -> SecretKey {
        let mut bytes = vec![0u8; len.bytes()];
        getrandom::fill(&mut bytes).expect("os rng unavailable");
        SecretKey(bytes.into_boxed_slice())
    }

    /// Wraps existing key bytes (length must be 16/24/32).
    pub fn from_bytes(bytes: &[u8]) -> SecretKey {
        debug_assert!(KeyLength::from_bytes(bytes.len()).is_some());
        SecretKey(bytes.to_vec().into_boxed_slice())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn key_len(&self) -> KeyLength {
        KeyLength::from_bytes(self.0.len()).expect("validated at construction")
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey({} bytes)", self.0.len())
    }
}

/// Key-encrypting key derived from the passphrase (§4.2).
#[derive(Debug)]
pub struct Kek(SecretKey);

impl Kek {
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// PBKDF2-HMAC-SHA1 KEK derivation (§4.2).
///
/// TRAP: the PBKDF2 salt is the LAST 8 BYTES of the 16-byte KM salt
/// (`hcrypt_sa.c:hcryptCtx_GenSecret`), not the whole salt. dkLen = the
/// SEK length; iterations = `PBKDF2_ITERATIONS` (2048).
pub fn derive_kek(passphrase: &[u8], km_salt: &[u8; 16], key_len: KeyLength) -> Kek {
    let mut out = vec![0u8; key_len.bytes()];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(passphrase, &km_salt[8 ..], PBKDF2_ITERATIONS, &mut out);
    Kek(SecretKey(out.into_boxed_slice()))
}

/// RFC 3394 AES key wrap of `plaintext` under `kek` with the default IV
/// `A6A6A6A6A6A6A6A6` (§4.3). `plaintext` is one SEK, or even‖odd (even
/// FIRST) during refresh. Output = 8-byte ICV + `plaintext.len()`.
pub fn wrap_key(kek: &Kek, plaintext: &[u8]) -> Vec<u8> {
    // Wrap input is always 1–2 SEKs of 16/24/32 bytes — a nonzero multiple
    // of the 8-byte semiblock — so the wrap itself cannot fail.
    debug_assert!(!plaintext.is_empty() && plaintext.len().is_multiple_of(8));
    let mut out = vec![0u8; plaintext.len() + 8];
    match kek.0.key_len() {
        KeyLength::Aes128 => KwAes128::new_from_slice(kek.as_slice())
            .expect("KEK length dispatched")
            .wrap_key(plaintext, &mut out),
        KeyLength::Aes192 => KwAes192::new_from_slice(kek.as_slice())
            .expect("KEK length dispatched")
            .wrap_key(plaintext, &mut out),
        KeyLength::Aes256 => KwAes256::new_from_slice(kek.as_slice())
            .expect("KEK length dispatched")
            .wrap_key(plaintext, &mut out),
    }
    .expect("output sized to plaintext + 8-byte ICV");
    out
}

/// RFC 3394 unwrap. ICV mismatch means the KEK (passphrase) is wrong →
/// [`CryptoError::WrongSecret`] (→ `SRT_KM_S_BADSECRET`; §4.3). This is
/// the ONLY wrong-passphrase detector in the protocol (§15).
///
/// For a dual-SEK blob the result is even‖odd concatenated (2·KLen bytes,
/// even first, §4.3 trap) — the caller splits it; only the split halves
/// are keys.
pub fn unwrap_key(kek: &Kek, wrapped: &[u8]) -> Result<SecretKey, CryptoError> {
    // Structural gate: 8-byte ICV plus at least one 16-byte key, whole
    // semiblocks only. The KM parser has already pinned the exact length
    // (§3.1 check 3); this keeps the function safe standalone.
    if wrapped.len() < 24 || !wrapped.len().is_multiple_of(8) {
        return Err(CryptoError::BadKmMessage("wrapped key length"));
    }
    let mut out = vec![0u8; wrapped.len() - 8];
    let res = match kek.0.key_len() {
        KeyLength::Aes128 => KwAes128::new_from_slice(kek.as_slice())
            .expect("KEK length dispatched")
            .unwrap_key(wrapped, &mut out),
        KeyLength::Aes192 => KwAes192::new_from_slice(kek.as_slice())
            .expect("KEK length dispatched")
            .unwrap_key(wrapped, &mut out),
        KeyLength::Aes256 => KwAes256::new_from_slice(kek.as_slice())
            .expect("KEK length dispatched")
            .unwrap_key(wrapped, &mut out),
    }
    .map(|_| ());
    match res {
        Ok(()) => Ok(SecretKey(out.into_boxed_slice())),
        Err(err) => {
            // `out` holds partially recovered material — scrub it.
            out.zeroize();
            match err {
                aes_kw::Error::IntegrityCheckFailed => Err(CryptoError::WrongSecret),
                // Unreachable after the length gate above; map defensively.
                _ => Err(CryptoError::BadKmMessage("wrapped key length")),
            }
        }
    }
}

/// Fresh 16-byte KM salt (§4.1). Generated once per connection; key
/// refresh reuses it (KEK and CTR nonce stay stable).
pub fn random_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).expect("os rng unavailable");
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0 .. s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i .. i + 2], 16).unwrap())
            .collect()
    }

    fn kek_from_hex(s: &str) -> Kek {
        Kek(SecretKey::from_bytes(&hex(s)))
    }

    // ---- PBKDF2-HMAC-SHA1 KEK derivation (§4.2) ----

    /// KM salt for the PBKDF2 KATs; only the LAST 8 bytes feed PBKDF2.
    const KM_SALT: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    ];
    const PASSPHRASE: &[u8] = b"correct horse battery";

    /// Ground truth computed independently with CPython:
    ///
    /// ```text
    /// python3 -c "import hashlib; print(hashlib.pbkdf2_hmac('sha1',
    ///     b'correct horse battery', bytes.fromhex('8899aabbccddeeff'),
    ///     2048, 16).hex())"
    /// ```
    ///
    /// (dkLen 16/24/32 for the three vectors; note the salt argument is
    /// KM_SALT[8..] — the last 8 bytes.)
    #[test]
    fn pbkdf2_kat_all_key_lengths() {
        for (len, expect) in [
            (KeyLength::Aes128, "551b5405cec6898daa3a42a4ddd2ee5a"),
            (
                KeyLength::Aes192,
                "551b5405cec6898daa3a42a4ddd2ee5a61cde5e7fd3b2dd2",
            ),
            (
                KeyLength::Aes256,
                "551b5405cec6898daa3a42a4ddd2ee5a61cde5e7fd3b2dd20a6d8849490e8ccf",
            ),
        ] {
            let kek = derive_kek(PASSPHRASE, &KM_SALT, len);
            assert_eq!(kek.as_slice(), hex(expect), "{len:?}");
        }
    }

    /// §4.2 trap: PBKDF2 uses ONLY the last 8 salt bytes — the first 8 must
    /// not influence the KEK (using all 16 yields a guaranteed BADSECRET).
    #[test]
    fn pbkdf2_ignores_first_8_salt_bytes() {
        let mut first_half_differs = KM_SALT;
        first_half_differs[.. 8].copy_from_slice(&[0xA5; 8]);
        let mut last_half_differs = KM_SALT;
        last_half_differs[15] ^= 0x01;

        let base = derive_kek(PASSPHRASE, &KM_SALT, KeyLength::Aes128);
        let same = derive_kek(PASSPHRASE, &first_half_differs, KeyLength::Aes128);
        let diff = derive_kek(PASSPHRASE, &last_half_differs, KeyLength::Aes128);
        assert_eq!(base.as_slice(), same.as_slice());
        assert_ne!(base.as_slice(), diff.as_slice());
    }

    // ---- RFC 3394 key wrap (§4.3) ----
    //
    // KATs straight from RFC 3394 §4; SRT always has KEK length == key data
    // length, so the matching vectors are 4.1 (128/128), 4.4 (192/192) and
    // 4.6 (256/256).

    /// RFC 3394 §4.1: 128 bits of key data with a 128-bit KEK.
    #[test]
    fn rfc3394_kat_128() {
        let kek = kek_from_hex("000102030405060708090a0b0c0d0e0f");
        let data = hex("00112233445566778899aabbccddeeff");
        let wrapped = wrap_key(&kek, &data);
        assert_eq!(
            wrapped,
            hex("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5")
        );
        assert_eq!(unwrap_key(&kek, &wrapped).unwrap().as_slice(), data);
    }

    /// RFC 3394 §4.4: 192 bits of key data with a 192-bit KEK.
    #[test]
    fn rfc3394_kat_192() {
        let kek = kek_from_hex("000102030405060708090a0b0c0d0e0f1011121314151617");
        let data = hex("00112233445566778899aabbccddeeff0001020304050607");
        let wrapped = wrap_key(&kek, &data);
        assert_eq!(
            wrapped,
            hex("031d33264e15d33268f24ec260743edce1c6c7ddee725a936ba814915c6762d2")
        );
        assert_eq!(unwrap_key(&kek, &wrapped).unwrap().as_slice(), data);
    }

    /// RFC 3394 §4.6: 256 bits of key data with a 256-bit KEK.
    #[test]
    fn rfc3394_kat_256() {
        let kek = kek_from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let data = hex("00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f");
        let wrapped = wrap_key(&kek, &data);
        assert_eq!(
            wrapped,
            hex(concat!(
                "28c9f404c4b810f4cbccb35cfb87f826",
                "3f5786e2d80ed326cbc7f0e71a99f43b",
                "fb988b9b7a02dd21"
            ))
        );
        assert_eq!(unwrap_key(&kek, &wrapped).unwrap().as_slice(), data);
    }

    /// Wrap→unwrap identity for single SEKs and refresh-style dual blobs
    /// (even‖odd, §4.3) at every KEK length.
    #[test]
    fn wrap_unwrap_roundtrip() {
        for len in [KeyLength::Aes128, KeyLength::Aes192, KeyLength::Aes256] {
            let kek = derive_kek(PASSPHRASE, &KM_SALT, len);

            let sek = SecretKey::generate(len);
            let wrapped = wrap_key(&kek, sek.as_slice());
            assert_eq!(wrapped.len(), len.bytes() + 8);
            assert_eq!(
                unwrap_key(&kek, &wrapped).unwrap().as_slice(),
                sek.as_slice()
            );

            // Dual-SEK: even first, both keys the same length.
            let odd = SecretKey::generate(len);
            let mut both = sek.as_slice().to_vec();
            both.extend_from_slice(odd.as_slice());
            let wrapped = wrap_key(&kek, &both);
            assert_eq!(wrapped.len(), 2 * len.bytes() + 8);
            assert_eq!(unwrap_key(&kek, &wrapped).unwrap().as_slice(), both);
        }
    }

    /// Any corrupted bit breaks the recovered ICV → WrongSecret (the
    /// protocol's only wrong-passphrase signal, §4.3).
    #[test]
    fn unwrap_corrupted_blob_is_wrong_secret() {
        let kek = derive_kek(PASSPHRASE, &KM_SALT, KeyLength::Aes128);
        let sek = SecretKey::generate(KeyLength::Aes128);
        let wrapped = wrap_key(&kek, sek.as_slice());

        // Corrupt the ICV half and the ciphertext half in turn.
        for byte in [0, wrapped.len() - 1] {
            let mut bad = wrapped.clone();
            bad[byte] ^= 0x01;
            assert_eq!(
                unwrap_key(&kek, &bad).unwrap_err(),
                CryptoError::WrongSecret
            );
        }
    }

    /// Wrong KEK (= wrong passphrase, or the §4.2 full-salt trap) fails the
    /// ICV check the same way.
    #[test]
    fn unwrap_wrong_kek_is_wrong_secret() {
        let kek = derive_kek(PASSPHRASE, &KM_SALT, KeyLength::Aes128);
        let sek = SecretKey::generate(KeyLength::Aes128);
        let wrapped = wrap_key(&kek, sek.as_slice());

        let wrong = derive_kek(b"wrong passphrase", &KM_SALT, KeyLength::Aes128);
        assert_eq!(
            unwrap_key(&wrong, &wrapped).unwrap_err(),
            CryptoError::WrongSecret
        );
    }

    /// Structurally impossible wrap lengths are BadKmMessage, not
    /// WrongSecret — they cannot be produced by any passphrase.
    #[test]
    fn unwrap_bad_length_is_bad_km_message() {
        let kek = derive_kek(PASSPHRASE, &KM_SALT, KeyLength::Aes128);
        for len in [0, 8, 16, 23, 25] {
            assert_eq!(
                unwrap_key(&kek, &vec![0u8; len]).unwrap_err(),
                CryptoError::BadKmMessage("wrapped key length"),
                "len {len}"
            );
        }
    }
}
