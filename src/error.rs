//! Public error type.

use std::{
    fmt,
    io,
};

/// Why an established connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    /// Peer sent SHUTDOWN (clean end of stream).
    Shutdown,
    /// Nothing received from the peer for the peer-idle timeout (5 s default).
    PeerIdle,
    /// Closed by the local application.
    Local,
    /// Caller handshake did not complete within the connect timeout.
    ConnectTimeout,
    /// Peer rejected the handshake (SRT_REJ code, see `packet::reject`).
    Rejected(u32),
    /// Unrecoverable sequence discrepancy (transmission.md §7.1): a data
    /// packet arrived beyond the receive-buffer capacity while the buffer
    /// was empty (e.g. after a long network outage), so reception can never
    /// resume. The connection is broken so the application can reconnect.
    SequenceDiscrepancy,
}

impl fmt::Display for CloseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CloseReason::Shutdown => write!(f, "peer shutdown"),
            CloseReason::PeerIdle => write!(f, "peer idle timeout"),
            CloseReason::Local => write!(f, "closed locally"),
            CloseReason::ConnectTimeout => write!(f, "connect timeout"),
            CloseReason::Rejected(code) => write!(f, "rejected by peer (code {code})"),
            CloseReason::SequenceDiscrepancy => {
                write!(f, "sequence discrepancy: reception no longer possible")
            }
        }
    }
}

/// Errors returned by the public API.
#[derive(Debug)]
pub enum SrtError {
    Io(io::Error),
    /// Handshake did not complete in time.
    ConnectTimeout,
    /// Peer rejected the handshake (SRT_REJ code, see `packet::reject`).
    Rejected(u32),
    /// Encryption mismatch, UNSECURE class (`reject::UNSECURE`, wire code
    /// 1011): one side has a passphrase and the other does not. A caller
    /// whose key exchange failed also surfaces this — libsrt aborts
    /// locally with UNSECURE even when the actual cause was a wrong
    /// passphrase (docs/spec/encryption.md §6.1, §8).
    EncryptionUnsupported,
    /// Encryption mismatch, BADSECRET class (`reject::BADSECRET`, wire code
    /// 1010): the peer (a listener) could not unwrap our key material —
    /// the passphrases differ (docs/spec/encryption.md §8).
    WrongPassphrase,
    /// Live-mode payload larger than the maximum (1456 bytes for MSS 1500).
    PayloadTooLarge(usize),
    /// Operation on a connection that is closed.
    Closed(CloseReason),
    /// Address did not resolve to any IPv4 address (the library is
    /// IPv4-only).
    NoIpv4Address,
    /// StreamID longer than 512 bytes.
    StreamIdTooLong,
    /// Passphrase set but shorter than 10 or longer than 80 bytes
    /// (docs/spec/encryption.md §2).
    InvalidPassphrase,
    /// Key-refresh options out of range: requires
    /// `km_preannounce <= (km_refresh_rate - 1) / 2`
    /// (docs/spec/encryption.md §2).
    InvalidKmParameters(&'static str),
}

impl fmt::Display for SrtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SrtError::Io(e) => write!(f, "io error: {e}"),
            SrtError::ConnectTimeout => write!(f, "connect timeout"),
            SrtError::Rejected(code) => write!(f, "connection rejected by peer (code {code})"),
            SrtError::EncryptionUnsupported => {
                write!(
                    f,
                    "encryption mismatch: passphrase missing on one side or key exchange failed"
                )
            }
            SrtError::WrongPassphrase => write!(f, "encryption mismatch: wrong passphrase"),
            SrtError::PayloadTooLarge(len) => {
                write!(f, "payload of {len} bytes exceeds live-mode maximum")
            }
            SrtError::Closed(reason) => write!(f, "connection closed: {reason}"),
            SrtError::NoIpv4Address => write!(f, "no IPv4 address for target"),
            SrtError::StreamIdTooLong => write!(f, "stream id longer than 512 bytes"),
            SrtError::InvalidPassphrase => {
                write!(f, "passphrase must be 10..=80 bytes")
            }
            SrtError::InvalidKmParameters(why) => {
                write!(f, "invalid key-refresh parameters: {why}")
            }
        }
    }
}

impl std::error::Error for SrtError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SrtError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for SrtError {
    fn from(e: io::Error) -> Self {
        SrtError::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two encryption-mismatch errors must be tellable apart from their
    /// message alone: BADSECRET = wrong passphrase, UNSECURE = a passphrase
    /// on one side only (docs/spec/encryption.md §8.1).
    #[test]
    fn encryption_mismatch_display_distinguishes_classes() {
        let unsecure = SrtError::EncryptionUnsupported.to_string();
        let badsecret = SrtError::WrongPassphrase.to_string();
        assert!(unsecure.contains("encryption mismatch"), "{unsecure}");
        assert!(badsecret.contains("wrong passphrase"), "{badsecret}");
        assert_ne!(unsecure, badsecret);
    }

    /// Local crypto-option validation errors keep their own texts (they
    /// mean "fix the options", not "the peer disagreed").
    #[test]
    fn crypto_option_errors_display() {
        assert_eq!(
            SrtError::InvalidPassphrase.to_string(),
            "passphrase must be 10..=80 bytes"
        );
        let e = SrtError::InvalidKmParameters("why").to_string();
        assert!(e.contains("key-refresh"), "{e}");
        assert!(e.contains("why"), "{e}");
    }
}
