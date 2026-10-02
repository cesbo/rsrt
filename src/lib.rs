//! SRT (Secure Reliable Transport) protocol library.
//!
//! Live transmission mode over UDP with TSBPD, ARQ and too-late packet
//! drop; caller and listener modes; HSv5 handshake; AES-128/192/256-CTR
//! encryption (HaiCrypt) with passphrase key material and in-stream key
//! refresh; interoperable with libsrt 1.4.4 (`srt-live-transmit`). No
//! rendezvous mode, no file/messaging mode.
//!
//! Layering (internal modules, see ARCHITECTURE.md):
//! - `packet` — pure wire codec;
//! - `crypto` — sans-I/O HaiCrypt engine (keys, KM messages, AES-CTR);
//! - `core` — sans-I/O connection state machine;
//! - crate root — tokio-based runtime and public API.
//!
//! # Receiving (caller)
//!
//! ```no_run
//! # async fn demo() -> Result<(), rsrt::SrtError> {
//! let mut sock = rsrt::SrtSocket::connect("example.com:10101", rsrt::SrtOptions::default()).await?;
//! while let Some(payload) = sock.recv().await? {
//!     // one live-mode message, e.g. up to 7 MPEG-TS packets
//! }
//! # Ok(()) }
//! ```
//!
//! # IPv6
//!
//! `connect_ip` and `bind_ip` support either IP family and use
//! `std::net::SocketAddr` for address accessors. The original APIs retain
//! their IPv4 types. IPv6 listeners are IPv6-only.
//!
//! ```no_run
//! # async fn demo() -> Result<(), rsrt::SrtError> {
//! let mut listener = rsrt::SrtListener::bind_ip("[::]:10101", rsrt::SrtOptions::default()).await?;
//! let (caller, accepted) = tokio::join!(
//!     rsrt::SrtSocket::connect_ip("[::1]:10101", rsrt::SrtOptions::default()),
//!     listener.accept(),
//! );
//! assert!(caller?.peer_addr().is_ipv6());
//! let (sock, peer) = accepted?;
//! # Ok(()) }
//! ```
//!
//! # Serving (listener)
//!
//! ```no_run
//! # async fn demo() -> Result<(), rsrt::SrtError> {
//! let mut listener = rsrt::SrtListener::bind("0.0.0.0:10101", rsrt::SrtOptions::default()).await?;
//! let (mut sock, peer) = listener.accept().await?;
//! sock.send(b"...").await?;
//! # Ok(()) }
//! ```

#![deny(unsafe_code)]

mod core;
mod crypto;
mod error;
mod listener;
mod net;
mod options;
mod packet;
mod socket;

pub use bytes::Bytes;

pub use self::{
    core::Stats,
    crypto::KeyLength,
    error::{
        CloseReason,
        SrtError,
    },
    listener::SrtListener,
    options::{
        Bandwidth,
        SrtOptions,
    },
    socket::SrtSocket,
};
