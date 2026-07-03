//! Shared support toolkit for integration tests.
//!
//! Integration test files opt in with `mod support;` — each test binary gets
//! its own copy (Cargo compiles `tests/*.rs` as separate crates). Nothing in
//! here touches the `srt` library itself, so these helpers stay usable while
//! the library is under construction.
//!
//! Contents:
//! - [`rng`] — seeded SplitMix64 PRNG (deterministic, no external crates);
//! - [`net`] — free-UDP-port allocator for parallel tests;
//! - [`payload`] — reproducible payload generator + re-chunking-tolerant verifier;
//! - [`proxy`] — lossy UDP proxy (drop/duplicate/reorder per direction, counters);
//! - [`slt`] — `srt-live-transmit` process helpers (locate, spawn, pipe I/O).
//!
//! The in-file `#[cfg(test)]` self-tests run through the dedicated
//! `tests/support_selftest.rs` binary (and in any other test binary that
//! declares `mod support;` — they are cheap and side-effect free).

// Each test binary uses only a subset of the toolkit; don't warn about the rest.
#![allow(dead_code)]
#![allow(unused_macros)]
#![allow(unused_imports)]

pub mod net;
pub mod payload;
pub mod proxy;
pub mod rng;
pub mod slt;

pub use net::{
    free_udp_addr,
    free_udp_port,
};
pub use payload::{
    PayloadGen,
    PayloadVerifier,
    MESSAGE_SIZE,
};
pub use proxy::{
    DirectionBehavior,
    LossyProxy,
    ProxyBehavior,
};
pub use rng::SplitMix64;
pub use slt::SltProcess;
