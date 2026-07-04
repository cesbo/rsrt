//! HaiCrypt encryption engine (docs/spec/encryption.md).
//!
//! Sans-I/O, like [`crate::core`]: no sockets, no clock of its own. The
//! packet layer stays crypto-agnostic (KK bits and opaque KM blobs); this
//! module owns key material, the KM message codec and the AES-CTR payload
//! cipher. `core` drives it and applies the enforcement policy
//! (encryption.md §8; encryption is always enforced — mismatches reject
//! the connection).
//!
//! Layout (private modules, re-exported below):
//! - `keys`: SEK/KEK material, PBKDF2 derivation, RFC 3394 wrap;
//! - `km`: KM message and KMRSP codec;
//! - `ctr`: per-packet AES-CTR keystream;
//! - `context`: per-connection engine (KMX, refresh, encrypt/decrypt).

mod context;
mod ctr;
mod keys;
mod km;

pub use self::{
    context::{
        Crypto,
        CryptoConfig,
        KmReqOutcome,
        KmRspOutcome,
    },
    keys::{
        KeyLength,
        PASSPHRASE_MAX,
        PASSPHRASE_MIN,
    },
    km::KmState,
};

/// Errors from KM/key-material processing. Never fatal by themselves —
/// core decides what to do per the enforcement matrix (encryption.md §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// KM message failed structural validation (encryption.md §3.1 order).
    BadKmMessage(&'static str),
    /// Key unwrap integrity check failed — wrong passphrase (→ BADSECRET).
    WrongSecret,
    /// Structurally valid but unsupported (cipher/auth/SE/version).
    Unsupported(&'static str),
    /// Data packet references a SEK slot with no installed key
    /// (undecryptable; encryption.md §9.4).
    NoKey,
}
