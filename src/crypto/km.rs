//! KM (Key Material) message codec — docs/spec/encryption.md §3, §5.
//!
//! The same byte string rides in the `KMREQ`/`KMRSP` handshake extensions
//! and in in-stream `UMSG_EXT` control packets; in both carriers it appears
//! on the UDP wire in natural (hcrypt_msg.h) byte order because libsrt's
//! pre-swap cancels the per-word control swap (§5).

use tracing::trace;

use super::{
    keys::KeyLength,
    CryptoError,
};

/// Fixed KM header length (`hcrypt_msg.h:HCRYPT_MSG_KM_OFS_SALT`); the
/// salt field starts right after it (§3).
const KM_HEADER_LEN: usize = 16;

/// Salt field length as always sent by libsrt 1.4.4
/// (`haicrypt.h:HAICRYPT_SALT_SZ`; §4.1).
const KM_SALT_LEN: usize = 16;

/// RFC 3394 integrity block ("wrap sign") length inside the Wrap field
/// (`haicrypt.h:HAICRYPT_WRAPKEY_SIGN_SZ`; §4.3).
const WRAP_ICV_LEN: usize = 8;

/// `HCRYPT_MSG_SIGN`: 'HAI' PnP Mfr ID = 0x2029, big-endian (§3).
const KM_SIGN: [u8; 2] = [0x20, 0x29];

/// `SRT_KM_STATE` (docs/spec/encryption.md §1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KmState {
    Unsecured = 0,
    Securing = 1,
    Secured = 2,
    NoSecret = 3,
    BadSecret = 4,
}

impl KmState {
    pub fn from_u32(v: u32) -> Option<KmState> {
        match v {
            0 => Some(KmState::Unsecured),
            1 => Some(KmState::Securing),
            2 => Some(KmState::Secured),
            3 => Some(KmState::NoSecret),
            4 => Some(KmState::BadSecret),
            _ => None,
        }
    }
}

/// Which SEK slot(s) a KM message carries: the 2-bit KK field in KM byte 3
/// (§3). Discriminants are the wire bits. `Both` is sent during refresh
/// pre-announce and wraps the EVEN key first (§4.3 trap).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KmKeys {
    Even = 0b01,
    Odd = 0b10,
    Both = 0b11,
}

impl KmKeys {
    /// Number of wrapped SEKs the message carries: `n` in the §3 length
    /// formula (2 for `Both`, else 1).
    pub const fn count(self) -> usize {
        match self {
            KmKeys::Even | KmKeys::Odd => 1,
            KmKeys::Both => 2,
        }
    }
}

/// Parsed KM message (a KMREQ payload, or a successful-KMRSP echo).
///
/// Fixed fields on encode (§3): version 1, PT 2, sign 0x2029, KEKI 0,
/// cipher 2 (AES-CTR), auth 0, SE 2 (TSSRT), SLen 16. `wrapped` is the
/// RFC 3394 blob: 8-byte ICV + n·`key_len` bytes (n = 1, or 2 with the
/// even key first when `keys == Both`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KmMessage {
    pub keys: KmKeys,
    pub key_len: KeyLength,
    pub salt: [u8; 16],
    pub wrapped: Vec<u8>,
}

impl KmMessage {
    /// Strict parse in libsrt's RX validation order (§3.1): srtcore's
    /// length/KLen pre-checks, then the carrier pre-parse gates
    /// (version/PT/sign/SE/KK — these run *before* the
    /// `hcryptCtx_Rx_ParseKM` checks, §3.1 step 5), then salt/SEK length,
    /// exact total length and cipher/auth. Rejections map to
    /// `BadKmMessage`/`Unsupported`; the caller turns them into KM states
    /// (§6.2) — the two pre-check failures below are the ones srtcore
    /// itself answers as BADSECRET, every later one is NOSECRET class.
    pub fn parse(buf: &[u8]) -> Result<KmMessage, CryptoError> {
        // srtcore pre-checks (`crypto.cpp:processSrtMsg_KMREQ`; §3.1 step 1).
        if buf.len() <= KM_HEADER_LEN {
            return Err(CryptoError::BadKmMessage("KM message not longer than its header"));
        }
        let sek_len = usize::from(buf[15]) * 4;
        if sek_len == 0 {
            return Err(CryptoError::BadKmMessage("KM key length is zero"));
        }
        // Carrier pre-parse (`hcrypt_xpt_srt.c:hcryptMsg_SRT_ParseMsg`),
        // identical for the handshake-extension and in-stream carriers.
        if buf[0] >> 4 != 0x1 {
            // The whole nibble must be 0b0001: covers the leading S bit too.
            return Err(CryptoError::Unsupported("KM version is not 1"));
        }
        if buf[0] & 0x0F != 0x2 {
            return Err(CryptoError::BadKmMessage("payload type is not KM"));
        }
        if buf[1 .. 3] != KM_SIGN {
            return Err(CryptoError::BadKmMessage("bad HaiCrypt signature"));
        }
        if buf[10] != 2 {
            return Err(CryptoError::Unsupported("stream encapsulation is not TSSRT"));
        }
        // The upper 6 bits of the KK byte are reserved and never examined
        // by libsrt; ignore them like `hcrypt_msg.h:HCRYPT_MSG_F_xSEK`.
        let keys = match buf[3] & 0x03 {
            0b01 => KmKeys::Even,
            0b10 => KmKeys::Odd,
            0b11 => KmKeys::Both,
            _ => return Err(CryptoError::BadKmMessage("KM carries no key (KK = 0)")),
        };
        // `hcrypt_ctx_rx.c:hcryptCtx_Rx_ParseKM` (§3.1 steps 2-4). KEKI and
        // the reserved fields are never checked, and KLen is NOT compared
        // with the local PBKEYLEN (§7 trap).
        let salt_len = usize::from(buf[14]) * 4;
        if salt_len > KM_SALT_LEN {
            return Err(CryptoError::BadKmMessage("salt longer than 16 bytes"));
        }
        if salt_len != KM_SALT_LEN {
            // libsrt's RX gate is only `salt_len <= 16`, but no 1.4.4 TX
            // ever sends less than 16; the fixed-size container here (and
            // the §4.2 KEK derivation) requires the full 16 bytes.
            return Err(CryptoError::Unsupported("salt shorter than 16 bytes"));
        }
        let key_len = KeyLength::from_bytes(sek_len)
            .ok_or(CryptoError::BadKmMessage("SEK length not 16/24/32"))?;
        if buf.len() != KM_HEADER_LEN + salt_len + WRAP_ICV_LEN + keys.count() * sek_len {
            return Err(CryptoError::BadKmMessage("KM length does not match its fields"));
        }
        if buf[8] != 2 {
            return Err(CryptoError::Unsupported("cipher is not AES-CTR"));
        }
        if buf[9] != 0 {
            return Err(CryptoError::Unsupported("auth is not none"));
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&buf[16 .. 32]);
        trace!(?keys, key_len = sek_len, "parsed KM message");
        Ok(KmMessage {
            keys,
            key_len,
            salt,
            wrapped: buf[32 ..].to_vec(),
        })
    }

    /// Encodes the message; byte-exact vs `hcrypt_ctx_tx.c` (§3). Total
    /// length = 16 + 16 + `wrapped.len()` (56..104 bytes).
    pub fn encode(&self) -> Vec<u8> {
        debug_assert_eq!(
            self.wrapped.len(),
            WRAP_ICV_LEN + self.keys.count() * self.key_len.bytes(),
            "wrap blob length inconsistent with KK/KLen"
        );
        let mut out = Vec::with_capacity(KM_HEADER_LEN + KM_SALT_LEN + self.wrapped.len());
        out.push(0x12); // S=0 | Vers=1 | PT=2 (KM)
        out.extend_from_slice(&KM_SIGN); // sign 'HAI', big-endian
        out.push(self.keys as u8); // resv(6b)=0 | KK
        out.extend_from_slice(&[0; 4]); // KEKI: always 0 in passphrase mode
        out.push(2); // Cipher: AES-CTR
        out.push(0); // Auth: none
        out.push(2); // SE: TSSRT
        out.push(0); // Resv1
        out.extend_from_slice(&[0; 2]); // Resv2
        out.push((KM_SALT_LEN / 4) as u8); // SLen/4: salt is always 16 B on TX
        out.push((self.key_len.bytes() / 4) as u8); // KLen/4: 4/6/8
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.wrapped);
        out
    }
}

/// A decoded KMRSP payload: exactly 4 bytes = failure status, anything
/// longer = byte echo of the KMREQ (§5.1, §6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KmResponse<'a> {
    /// Success: byte-identical echo of the KMREQ (validate by comparison
    /// with the outstanding request, not by re-parsing).
    Echo(&'a [u8]),
    /// Failure: peer's receiver KM state.
    Status(KmState),
}

impl KmResponse<'_> {
    /// TRAP (§5.1): the 1-word failure status is LITTLE-endian on the wire
    /// (sender-host order; the KM double-swap cancellation applies).
    pub fn parse(buf: &[u8]) -> Result<KmResponse<'_>, CryptoError> {
        match buf.len() {
            0 ..= 3 => Err(CryptoError::BadKmMessage("KMRSP shorter than one word")),
            4 => {
                let state = u32::from_le_bytes(buf.try_into().expect("length checked"));
                KmState::from_u32(state)
                    .map(KmResponse::Status)
                    .ok_or(CryptoError::BadKmMessage("unknown KM state in KMRSP"))
            }
            _ => Ok(KmResponse::Echo(buf)),
        }
    }

    /// Failure-KMRSP payload (little-endian; §5.1).
    pub fn encode_status(state: KmState) -> [u8; 4] {
        (state as u32).to_le_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; 16] = [
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, //
        0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    ];

    /// Structurally valid message with a recognizable wrap pattern (the
    /// cryptographic wrap content is keys.rs territory, opaque here).
    fn sample(keys: KmKeys, key_len: KeyLength) -> KmMessage {
        let wrapped_len = WRAP_ICV_LEN + keys.count() * key_len.bytes();
        KmMessage {
            keys,
            key_len,
            salt: SALT,
            wrapped: (0 .. wrapped_len as u8).map(|i| 0x30 + i).collect(),
        }
    }

    fn valid() -> Vec<u8> {
        sample(KmKeys::Even, KeyLength::Aes128).encode()
    }

    // -- Encode -------------------------------------------------------------

    /// §3 worked example: initial even-key KMREQ, KLen 16 — all 56 bytes
    /// computed by hand from the §3 field table.
    #[test]
    fn encode_aes128_even_byte_exact() {
        let msg = sample(KmKeys::Even, KeyLength::Aes128);
        #[rustfmt::skip]
        let mut expected = vec![
            0x12,                   // S=0 | Vers=1 | PT=2 (KM)
            0x20, 0x29,             // sign 'HAI', big-endian
            0x01,                   // resv=0 | KK=01 (even)
            0x00, 0x00, 0x00, 0x00, // KEKI 0 (passphrase mode)
            0x02,                   // cipher: AES-CTR
            0x00,                   // auth: none
            0x02,                   // SE: TSSRT
            0x00,                   // resv1
            0x00, 0x00,             // resv2
            0x04,                   // SLen/4 = 4 (16-byte salt)
            0x04,                   // KLen/4 = 4 (AES-128)
        ];
        expected.extend_from_slice(&SALT);
        expected.extend(0x30 .. 0x48); // wrap: 8 B ICV + 16 B key
        let out = msg.encode();
        assert_eq!(out.len(), 56);
        assert_eq!(out, expected);
    }

    #[test]
    fn encode_kk_bits_on_the_wire() {
        // §3: whole KF byte = 0x01 (even), 0x02 (odd), 0x03 (both).
        assert_eq!(sample(KmKeys::Even, KeyLength::Aes128).encode()[3], 0x01);
        assert_eq!(sample(KmKeys::Odd, KeyLength::Aes128).encode()[3], 0x02);
        assert_eq!(sample(KmKeys::Both, KeyLength::Aes128).encode()[3], 0x03);
    }

    #[test]
    fn encode_dual_key_length_math() {
        // Dual-SEK refresh KM, AES-256: 16 + 16 + 8 + 2·32 = 104 bytes —
        // `HCRYPT_MSG_KM_MAX_SZ` = `SRT_CMD_MAXSZ` (§3).
        let msg = sample(KmKeys::Both, KeyLength::Aes256);
        let out = msg.encode();
        assert_eq!(out.len(), 104);
        assert_eq!(out[3], 0x03); // KK = both
        assert_eq!(out[15], 0x08); // KLen/4 = 8
        assert_eq!(&out[32 ..], &msg.wrapped[..]); // ICV + even SEK + odd SEK
    }

    /// §3 total-length table: single-key 56/64/72, dual-key 72/88/104;
    /// always a multiple of 4.
    #[test]
    fn encoded_lengths_match_spec_table() {
        let cases = [
            (KmKeys::Even, KeyLength::Aes128, 56),
            (KmKeys::Even, KeyLength::Aes192, 64),
            (KmKeys::Even, KeyLength::Aes256, 72),
            (KmKeys::Both, KeyLength::Aes128, 72),
            (KmKeys::Both, KeyLength::Aes192, 88),
            (KmKeys::Both, KeyLength::Aes256, 104),
        ];
        for (keys, key_len, expected) in cases {
            let out = sample(keys, key_len).encode();
            assert_eq!(out.len(), expected, "{keys:?} {key_len:?}");
            assert_eq!(out.len() % 4, 0, "{keys:?} {key_len:?}");
        }
    }

    #[test]
    fn parse_encode_roundtrip_all_combos() {
        for keys in [KmKeys::Even, KmKeys::Odd, KmKeys::Both] {
            for key_len in [KeyLength::Aes128, KeyLength::Aes192, KeyLength::Aes256] {
                let msg = sample(keys, key_len);
                let parsed = KmMessage::parse(&msg.encode()).unwrap();
                assert_eq!(parsed, msg, "{keys:?} {key_len:?}");
            }
        }
    }

    // -- Parse validation (§3.1, in libsrt's order) ---------------------------

    #[test]
    fn parse_rejects_short_input() {
        // srtcore pre-check: msg_len > 16 (a bare header is not a KM).
        let buf = valid();
        for len in [0, 1, 4, 15, 16] {
            assert_eq!(
                KmMessage::parse(&buf[.. len]),
                Err(CryptoError::BadKmMessage("KM message not longer than its header")),
                "len {len}"
            );
        }
    }

    #[test]
    fn parse_rejects_zero_key_length() {
        // srtcore pre-check: `Klen != 0` (§3.1 step 1).
        let mut buf = valid();
        buf[15] = 0;
        assert_eq!(
            KmMessage::parse(&buf),
            Err(CryptoError::BadKmMessage("KM key length is zero"))
        );
    }

    #[test]
    fn parse_rejects_bad_version_nibble() {
        // Version 2, and version 1 with the S bit set: the whole top
        // nibble must be 0b0001.
        for byte0 in [0x22, 0x92] {
            let mut buf = valid();
            buf[0] = byte0;
            assert_eq!(
                KmMessage::parse(&buf),
                Err(CryptoError::Unsupported("KM version is not 1")),
                "byte0 {byte0:#04x}"
            );
        }
    }

    #[test]
    fn parse_rejects_non_km_payload_type() {
        let mut buf = valid();
        buf[0] = 0x11; // PT 1 = media stream
        assert_eq!(
            KmMessage::parse(&buf),
            Err(CryptoError::BadKmMessage("payload type is not KM"))
        );
    }

    #[test]
    fn parse_rejects_bad_signature() {
        for (i, v) in [(1, 0x21), (2, 0x28)] {
            let mut buf = valid();
            buf[i] = v;
            assert_eq!(
                KmMessage::parse(&buf),
                Err(CryptoError::BadKmMessage("bad HaiCrypt signature")),
                "byte {i}"
            );
        }
    }

    #[test]
    fn parse_rejects_bad_stream_encapsulation() {
        let mut buf = valid();
        buf[10] = 1; // HCRYPT_SE_TSUDP
        assert_eq!(
            KmMessage::parse(&buf),
            Err(CryptoError::Unsupported("stream encapsulation is not TSSRT"))
        );
    }

    #[test]
    fn parse_rejects_kk_zero() {
        // §3.1 trap: KF byte 0x00 is rejected in the carrier pre-parse and
        // never reaches the `hcryptCtx_Rx_ParseKM` checks.
        let mut buf = valid();
        buf[3] = 0x00;
        assert_eq!(
            KmMessage::parse(&buf),
            Err(CryptoError::BadKmMessage("KM carries no key (KK = 0)"))
        );
    }

    #[test]
    fn parse_rejects_overlong_salt() {
        let mut buf = valid();
        buf[14] = 5; // claims a 20-byte salt
        assert_eq!(
            KmMessage::parse(&buf),
            Err(CryptoError::BadKmMessage("salt longer than 16 bytes"))
        );
    }

    #[test]
    fn parse_rejects_short_salt() {
        let mut buf = valid();
        buf[14] = 3; // legal for libsrt RX, unrepresentable here
        assert_eq!(
            KmMessage::parse(&buf),
            Err(CryptoError::Unsupported("salt shorter than 16 bytes"))
        );
    }

    #[test]
    fn parse_rejects_bad_sek_length() {
        for klen4 in [1, 5, 7, 9] {
            let mut buf = valid();
            buf[15] = klen4;
            assert_eq!(
                KmMessage::parse(&buf),
                Err(CryptoError::BadKmMessage("SEK length not 16/24/32")),
                "KLen/4 = {klen4}"
            );
        }
    }

    #[test]
    fn parse_rejects_total_length_mismatch() {
        let err = Err(CryptoError::BadKmMessage("KM length does not match its fields"));
        // One byte short / long.
        let buf = valid();
        assert_eq!(KmMessage::parse(&buf[.. buf.len() - 1]), err);
        let mut long = valid();
        long.push(0);
        assert_eq!(KmMessage::parse(&long), err);
        // Dual-key KK on a single-key body: n doubles the expected length.
        let mut dual = valid();
        dual[3] = 0x03;
        assert_eq!(KmMessage::parse(&dual), err);
        // KLen claim inconsistent with the body.
        let mut wide = valid();
        wide[15] = 8;
        assert_eq!(KmMessage::parse(&wide), err);
        // A truncated dual-key message must not parse as single-key: the
        // 88-byte AES-192 dual cut to 64 bytes fails on the KK/length math.
        let mut cut = sample(KmKeys::Both, KeyLength::Aes192).encode();
        cut.truncate(64);
        assert_eq!(KmMessage::parse(&cut), err);
    }

    #[test]
    fn parse_rejects_bad_cipher_and_auth() {
        let mut buf = valid();
        buf[8] = 1; // HCRYPT_CIPHER_AES_ECB
        assert_eq!(
            KmMessage::parse(&buf),
            Err(CryptoError::Unsupported("cipher is not AES-CTR"))
        );
        let mut buf = valid();
        buf[9] = 1;
        assert_eq!(
            KmMessage::parse(&buf),
            Err(CryptoError::Unsupported("auth is not none"))
        );
    }

    #[test]
    fn parse_ignores_unchecked_fields() {
        // KEKI, Resv1/Resv2 and the 6 reserved bits of the KK byte are
        // never examined by libsrt's RX (§3.1 step 6) — mirror that.
        let msg = sample(KmKeys::Even, KeyLength::Aes128);
        let mut buf = msg.encode();
        buf[4 .. 8].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // KEKI
        buf[11] = 0xFF; // Resv1
        buf[12 .. 14].copy_from_slice(&[0xFF, 0xFF]); // Resv2
        buf[3] = 0xFD; // reserved bits set, KK still 01
        assert_eq!(KmMessage::parse(&buf).unwrap(), msg);
    }

    #[test]
    fn parse_validation_order_matches_libsrt() {
        // The carrier pre-parse runs before the `hcryptCtx_Rx_ParseKM`
        // checks (§3.1 step 5): with both a bad sign and a bad cipher, the
        // sign gate fires.
        let mut buf = valid();
        buf[1] = 0xAA;
        buf[8] = 9;
        assert_eq!(
            KmMessage::parse(&buf),
            Err(CryptoError::BadKmMessage("bad HaiCrypt signature"))
        );
        // ...and the exact-length check precedes cipher/auth (§3.1 steps
        // 3 vs 4).
        let mut buf = valid();
        buf[8] = 9;
        buf.push(0);
        assert_eq!(
            KmMessage::parse(&buf),
            Err(CryptoError::BadKmMessage("KM length does not match its fields"))
        );
    }

    // -- KMRSP codec ----------------------------------------------------------

    #[test]
    fn kmrsp_status_word_is_little_endian() {
        // §5.1 trap: BADSECRET = `04 00 00 00` on the wire (sender host
        // order, LE on every mainstream build). UNSECURED = 0 is
        // endian-invariant and would hide a byte-order bug — hence the
        // nonzero state here.
        assert_eq!(
            KmResponse::encode_status(KmState::BadSecret),
            [0x04, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            KmResponse::parse(&[0x04, 0x00, 0x00, 0x00]),
            Ok(KmResponse::Status(KmState::BadSecret))
        );
        // The big-endian bytes decode to 0x04000000 — an unknown state.
        assert_eq!(
            KmResponse::parse(&[0x00, 0x00, 0x00, 0x04]),
            Err(CryptoError::BadKmMessage("unknown KM state in KMRSP"))
        );
    }

    #[test]
    fn kmrsp_roundtrips_every_state() {
        for state in [
            KmState::Unsecured,
            KmState::Securing,
            KmState::Secured,
            KmState::NoSecret,
            KmState::BadSecret,
        ] {
            let wire = KmResponse::encode_status(state);
            assert_eq!(KmResponse::parse(&wire), Ok(KmResponse::Status(state)));
        }
    }

    #[test]
    fn kmrsp_full_length_is_echo() {
        // §6.3: anything longer than one word is the byte echo, surfaced
        // verbatim for the initiator's memcmp — never re-parsed here.
        let buf = valid();
        assert_eq!(KmResponse::parse(&buf), Ok(KmResponse::Echo(&buf)));
    }

    #[test]
    fn kmrsp_rejects_short_payload() {
        let buf = valid();
        for len in 0 .. 4 {
            assert_eq!(
                KmResponse::parse(&buf[.. len]),
                Err(CryptoError::BadKmMessage("KMRSP shorter than one word")),
                "len {len}"
            );
        }
    }

    #[test]
    fn kmrsp_rejects_unknown_state() {
        assert_eq!(
            KmResponse::parse(&[0x05, 0x00, 0x00, 0x00]),
            Err(CryptoError::BadKmMessage("unknown KM state in KMRSP"))
        );
    }
}
