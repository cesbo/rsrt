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
    /// Peer requires encryption, which this library does not support.
    EncryptionUnsupported,
    /// Live-mode payload larger than the maximum (1456 bytes for MSS 1500).
    PayloadTooLarge(usize),
    /// Operation on a connection that is closed.
    Closed(CloseReason),
    /// Address did not resolve to any IPv4 address (the library is
    /// IPv4-only, matching the underlying `udp` crate).
    NoIpv4Address,
    /// StreamID longer than 512 bytes.
    StreamIdTooLong,
}

impl fmt::Display for SrtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SrtError::Io(e) => write!(f, "io error: {e}"),
            SrtError::ConnectTimeout => write!(f, "connect timeout"),
            SrtError::Rejected(code) => write!(f, "connection rejected by peer (code {code})"),
            SrtError::EncryptionUnsupported => write!(f, "peer requires encryption (unsupported)"),
            SrtError::PayloadTooLarge(len) => {
                write!(f, "payload of {len} bytes exceeds live-mode maximum")
            }
            SrtError::Closed(reason) => write!(f, "connection closed: {reason}"),
            SrtError::NoIpv4Address => write!(f, "no IPv4 address for target"),
            SrtError::StreamIdTooLong => write!(f, "stream id longer than 512 bytes"),
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
