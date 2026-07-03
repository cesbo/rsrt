//! SRT (Secure Reliable Transport) protocol library.
//!
//! Live transmission mode over UDP with TSBPD, ARQ and too-late packet
//! drop; caller and listener modes; HSv5 handshake; interoperable with
//! libsrt 1.4.4 (`srt-live-transmit`). No rendezvous mode, no
//! file/messaging mode, no encryption (encrypted peers are rejected).
//!
//! Layering (see ARCHITECTURE.md):
//! - [`packet`] — pure wire codec;
//! - [`core`] — sans-I/O connection state machine;
//! - crate root — tokio-based runtime and public API.
//!
//! # Receiving (caller)
//!
//! ```no_run
//! # async fn demo() -> Result<(), srt::SrtError> {
//! let mut sock = srt::SrtSocket::connect("bg.cesbo.com:10101", srt::SrtOptions::default()).await?;
//! while let Some(payload) = sock.recv().await? {
//!     // one live-mode message, e.g. up to 7 MPEG-TS packets
//! }
//! # Ok(()) }
//! ```
//!
//! # Serving (listener)
//!
//! ```no_run
//! # async fn demo() -> Result<(), srt::SrtError> {
//! let mut listener = srt::SrtListener::bind("0.0.0.0:10101", srt::SrtOptions::default()).await?;
//! let (mut sock, peer) = listener.accept().await?;
//! sock.send(b"...").await?;
//! # Ok(()) }
//! ```

#![deny(unsafe_code)]

pub mod core;
pub mod packet;

mod error;
mod listener;
mod net;
mod options;
mod socket;

pub use self::{
    core::Stats,
    error::{
        CloseReason,
        SrtError,
    },
    listener::SrtListener,
    options::SrtOptions,
    socket::SrtSocket,
};
