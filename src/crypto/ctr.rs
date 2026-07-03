//! HaiCrypt AES-CTR payload cipher — docs/spec/encryption.md §9.2.

use aes::{
    Aes128Enc,
    Aes192Enc,
    Aes256Enc,
};
use ctr::{
    cipher::{
        consts::U16,
        BlockCipher,
        BlockEncrypt,
        BlockSizeUser,
        InnerIvInit,
        KeyInit,
        StreamCipher,
        StreamCipherCoreWrapper,
    },
    flavors,
    CtrCore,
};

use super::keys::{
    KeyLength,
    SecretKey,
};

/// One SEK's AES key schedule, expanded ONCE at key install and reused for
/// every packet. libsrt does the same: `cryspr.c:crysprFallback_MsSetKey`
/// expands the SEK into the per-key `CRYSPR_AESCTX` only at key install /
/// refresh (`hcrypt_ctx_tx.c`, `hcrypt_ctx_rx.c`) and the per-packet path
/// reuses it — re-running the expansion per packet costs ~30-40 ns, ~30%
/// of a 188-byte crypto op. Only the encrypt schedule is kept: CTR mode
/// never runs the block cipher backwards.
///
/// Like [`SecretKey`], the cached round keys scrub themselves on drop (the
/// `aes/zeroize` Cargo feature, pinned by `cached_round_keys_zeroize_on_drop`).
#[derive(Clone)]
pub struct CtrCipher(Expanded);

#[derive(Clone)]
enum Expanded {
    Aes128(Aes128Enc),
    Aes192(Aes192Enc),
    Aes256(Aes256Enc),
}

impl CtrCipher {
    /// Expands the key schedule for `key` (key-install time only).
    pub fn new(key: &SecretKey) -> CtrCipher {
        CtrCipher(match key.key_len() {
            KeyLength::Aes128 => Expanded::Aes128(
                Aes128Enc::new_from_slice(key.as_slice()).expect("key length dispatched"),
            ),
            KeyLength::Aes192 => Expanded::Aes192(
                Aes192Enc::new_from_slice(key.as_slice()).expect("key length dispatched"),
            ),
            KeyLength::Aes256 => Expanded::Aes256(
                Aes256Enc::new_from_slice(key.as_slice()).expect("key length dispatched"),
            ),
        })
    }

    /// XORs the HaiCrypt keystream over `payload` in place (encryption and
    /// decryption are the same operation; ciphertext length == plaintext
    /// length, no padding).
    ///
    /// Counter block (§9.2): 16 zero bytes, then `seq` written big-endian
    /// at offsets 10..14 and a 16-bit block counter starting at 0 at
    /// offsets 14..16, all XORed with the first 14 bytes of `salt` (block
    /// bytes 14-15 are NOT salted; salt bytes 14-15 are unused). `seq` is
    /// the full 32-bit sequence-number header word (MSB 0 for data
    /// packets). A standard big-endian 128-bit counter increment is
    /// equivalent for SRT payloads (< 2^16 blocks per packet).
    pub fn apply_keystream(&self, salt: &[u8; 16], seq: u32, payload: &mut [u8]) {
        let iv = counter_block(salt, seq);
        match &self.0 {
            Expanded::Aes128(aes) => xor_keystream(aes, &iv, payload),
            Expanded::Aes192(aes) => xor_keystream(aes, &iv, payload),
            Expanded::Aes256(aes) => xor_keystream(aes, &iv, payload),
        }
    }
}

/// One-shot convenience over [`CtrCipher`]: re-expands the key schedule on
/// EVERY call. Per-packet paths must hold a [`CtrCipher`] per installed
/// SEK instead, like libsrt's per-key `CRYSPR_AESCTX`.
pub fn apply_keystream(key: &SecretKey, salt: &[u8; 16], seq: u32, payload: &mut [u8]) {
    CtrCipher::new(key).apply_keystream(salt, seq, payload);
}

/// Runs AES-CTR over `payload` with an already-expanded key schedule. The
/// clone hands the CTR core a plain copy of the round keys — no key
/// expansion — and is scrubbed on drop (`aes/zeroize`).
///
/// `Ctr128BE` (the flavor) increments the whole 128-bit block big-endian,
/// like libsrt's default OpenSSL path (`CRYPTO_ctr128_encrypt`); HaiCrypt's
/// in-tree fallback increments only bytes 14..15. The two diverge only
/// when the 16-bit counter overflows, i.e. for payloads ≥ 2^16 blocks
/// (1 MiB) — the SRT maximum is 1456 B = 91 blocks, and the counter
/// starts at 0, so no carry ever reaches byte 13 and any stock AES-CTR
/// is byte-identical (§9.2).
fn xor_keystream<C>(cipher: &C, iv: &[u8; 16], payload: &mut [u8])
where
    C: BlockEncrypt + BlockCipher + BlockSizeUser<BlockSize = U16> + Clone,
{
    StreamCipherCoreWrapper::from_core(CtrCore::<C, flavors::Ctr128BE>::inner_iv_init(
        cipher.clone(),
        iv.into(),
    ))
    .apply_keystream(payload);
}

/// Builds the §9.2 initial counter block (`hcrypt.h:hcrypt_SetCtrIV`):
///
/// | bytes | 0..10        | 10..14                | 14..16      |
/// |-------|--------------|-----------------------|-------------|
/// | value | `salt[0..10]`| `salt[10..14] XOR seq`| `0` (ctr)   |
fn counter_block(salt: &[u8; 16], seq: u32) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[10 .. 14].copy_from_slice(&seq.to_be_bytes());
    // TRAP (§15): XOR the salt over bytes 0..14 ONLY — the 16-bit block
    // counter at 14..16 is never salted, and salt bytes 14..15 are unused.
    for (b, s) in iv[.. 14].iter_mut().zip(&salt[.. 14]) {
        *b ^= s;
    }
    iv
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

    // AES keys from NIST SP 800-38A (arbitrary — any fixed keys work).
    const KEY_128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
    const KEY_192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
    const KEY_256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";

    /// KAT salt with NONZERO bytes 14..15 (0xB1, 0xA0): an implementation
    /// that wrongly salted the block-counter bytes would fail the KATs.
    const SALT: [u8; 16] = [
        0x9F, 0x8E, 0x7D, 0x6C, 0x5B, 0x4A, 0x39, 0x28, //
        0x17, 0x06, 0xF5, 0xE4, 0xD3, 0xC2, 0xB1, 0xA0,
    ];
    const SEQ: u32 = 0x7B2D_8E4F;

    fn key(s: &str) -> SecretKey {
        SecretKey::from_bytes(&hex(s))
    }

    /// 45-byte plaintext `00 01 .. 2C`: two full blocks + a 13-byte tail,
    /// so the KATs pin the counter increment across block boundaries.
    fn plaintext() -> Vec<u8> {
        (0u8 .. 45).collect()
    }

    /// [`kat_aes128`] ciphertext for [`plaintext`] under (KEY_128, SALT,
    /// SEQ) — see that test for the openssl/python ground-truth commands.
    const KAT_128: &str = concat!(
        "92f0f2fa903d99e1ea3b789e273e9be4",
        "436c50d0a3862eddebb1429b07870c37",
        "d35c17947a70e3bf1c4098d4bc"
    );

    /// IV per §9.2: salt[0..10] ‖ salt[10..14]^seq ‖ 0x0000 =
    /// `9f8e7d6c5b4a392817068ec95d8d0000`. Ground truth computed
    /// independently with both:
    ///
    /// ```text
    /// python3 -c "import sys; sys.stdout.buffer.write(bytes(range(45)))" |
    ///   openssl enc -aes-128-ctr -K 2b7e151628aed2a6abf7158809cf4f3c \
    ///     -iv 9f8e7d6c5b4a392817068ec95d8d0000
    /// ```
    ///
    /// and python3 `cryptography` (`Cipher(algorithms.AES(key),
    /// modes.CTR(iv))`), which agree byte-for-byte.
    #[test]
    fn kat_aes128() {
        let mut buf = plaintext();
        apply_keystream(&key(KEY_128), &SALT, SEQ, &mut buf);
        assert_eq!(buf, hex(KAT_128));
    }

    /// Same construction, AES-192 key (python3 `cryptography` ground truth,
    /// same IV as [`kat_aes128`]).
    #[test]
    fn kat_aes192() {
        let mut buf = plaintext();
        apply_keystream(&key(KEY_192), &SALT, SEQ, &mut buf);
        assert_eq!(
            buf,
            hex(concat!(
                "0fd6b07f0f4113bddc869b6d89bba3b6",
                "edbe53b195d1c2f6099a0455be909a14",
                "ceb3f9b33649fef8728380b2a4"
            ))
        );
    }

    /// Same construction, AES-256 key (python3 `cryptography` ground truth,
    /// same IV as [`kat_aes128`]).
    #[test]
    fn kat_aes256() {
        let mut buf = plaintext();
        apply_keystream(&key(KEY_256), &SALT, SEQ, &mut buf);
        assert_eq!(
            buf,
            hex(concat!(
                "29ee876592413de9644d0ea3e1b66254",
                "bd77554df92419cfc2e32bd906cec223",
                "8ca7c15a62de7469c913315d81"
            ))
        );
    }

    /// Encrypt-then-decrypt is the identity at every key length, across
    /// block boundaries (15/16/17) and at the SRT maximum payload (1456 B
    /// = 91 blocks).
    #[test]
    fn roundtrip_identity_block_boundaries() {
        for k in [KEY_128, KEY_192, KEY_256] {
            let k = key(k);
            for len in [1usize, 15, 16, 17, 1456] {
                let clear: Vec<u8> = (0 .. len).map(|i| (i * 7 + 3) as u8).collect();
                let mut buf = clear.clone();
                apply_keystream(&k, &SALT, SEQ, &mut buf);
                assert_ne!(buf, clear, "len {len}: keystream must not be null");
                apply_keystream(&k, &SALT, SEQ, &mut buf);
                assert_eq!(buf, clear, "len {len}");
            }
        }
    }

    /// The keystream depends only on (key, salt, seq): every call restarts
    /// the block counter at 0, so a shorter payload's ciphertext is a
    /// prefix of a longer one's.
    #[test]
    fn keystream_position_independent_of_payload_length() {
        let k = key(KEY_128);
        let mut full = plaintext();
        apply_keystream(&k, &SALT, SEQ, &mut full);
        for len in [1usize, 15, 16, 17, 32, 33] {
            let mut short = plaintext()[.. len].to_vec();
            apply_keystream(&k, &SALT, SEQ, &mut short);
            assert_eq!(short, full[.. len], "len {len}");
        }
    }

    /// TRAP (§9.2/§15): salt bytes 14..15 are UNUSED — the block counter
    /// is not salted. XORing them in would corrupt every block (the
    /// counter would start nonzero); a divergence shows up even in block 0.
    #[test]
    fn salt_counter_bytes_are_unused() {
        let k = key(KEY_128);
        let mut base = plaintext();
        apply_keystream(&k, &SALT, SEQ, &mut base);

        let mut salt = SALT;
        salt[14] = 0x00;
        salt[15] = 0xFF;
        let mut buf = plaintext();
        apply_keystream(&k, &salt, SEQ, &mut buf);
        assert_eq!(buf, base, "salt[14..16] must not affect the keystream");

        // Sanity: the last salted byte (13) does matter.
        let mut salt = SALT;
        salt[13] ^= 0x01;
        let mut buf = plaintext();
        apply_keystream(&k, &salt, SEQ, &mut buf);
        assert_ne!(buf, base, "salt[13] must affect the keystream");
    }

    /// Each sequence number gets its own keystream (seq is XORed into IV
    /// bytes 10..14 big-endian, so even a ±1 change flips the stream).
    #[test]
    fn seq_changes_keystream() {
        let k = key(KEY_128);
        let mut a = plaintext();
        apply_keystream(&k, &SALT, SEQ, &mut a);
        let mut b = plaintext();
        apply_keystream(&k, &SALT, SEQ + 1, &mut b);
        assert_ne!(a, b);
    }

    /// A [`CtrCipher`] is per-SEK state ONLY: reusing one across packets
    /// (varying seq and length, same packet twice — a §9.3 retransmission)
    /// must match a fresh one-shot call per packet byte-for-byte. Guards
    /// the cached-schedule optimization against counter/keystream state
    /// leaking from one packet into the next.
    #[test]
    fn cached_cipher_is_stateless_across_packets() {
        for k in [KEY_128, KEY_192, KEY_256] {
            let k = key(k);
            let cached = CtrCipher::new(&k);
            for (seq, len) in [
                (SEQ, 45usize),
                (SEQ + 1, 1),
                (0, 16),
                (u32::MAX, 1456),
                (SEQ, 45), // same packet again after other traffic
            ] {
                let clear: Vec<u8> = (0 .. len).map(|i| (i * 13 + 7) as u8).collect();
                let mut reused = clear.clone();
                cached.apply_keystream(&SALT, seq, &mut reused);
                let mut fresh = clear;
                apply_keystream(&k, &SALT, seq, &mut fresh);
                assert_eq!(reused, fresh, "seq {seq:#x}, len {len}");
            }
        }
    }

    /// A warmed (already-used) cached cipher still hits the §9.2 KAT bytes
    /// exactly — schedule reuse must not perturb the absolute ground truth,
    /// only the expansion cost.
    #[test]
    fn cached_cipher_reuse_matches_kat() {
        let cached = CtrCipher::new(&key(KEY_128));
        let mut warmup = plaintext();
        cached.apply_keystream(&SALT, SEQ ^ 0xFFFF, &mut warmup);
        let mut buf = plaintext();
        cached.apply_keystream(&SALT, SEQ, &mut buf);
        assert_eq!(buf, hex(KAT_128));
    }

    /// Pins the `aes/zeroize` Cargo feature: the round keys cached inside
    /// [`CtrCipher`] (and their per-packet clones) must scrub themselves on
    /// drop, matching [`SecretKey`]'s guarantee for the raw key bytes.
    /// Dropping the feature makes this fail to compile.
    #[test]
    fn cached_round_keys_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<Aes128Enc>();
        assert_zeroize_on_drop::<Aes192Enc>();
        assert_zeroize_on_drop::<Aes256Enc>();
    }
}
