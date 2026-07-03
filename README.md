# srt

SRT (Haivision Secure Reliable Transport) protocol library for Rust: live
transmission mode over UDP with TSBPD (timestamp-based packet delivery),
ARQ (ACK/NAK/retransmission) and too-late packet drop. Caller and listener
modes, HSv5 handshake, interoperable with libsrt 1.4.4
(`srt-live-transmit`).

**Out of scope**: rendezvous mode, file/messaging mode, encryption
(connections requiring crypto are rejected cleanly).

## Quick start

Receiving (caller):

```rust
let mut sock = srt::SrtSocket::connect("bg.cesbo.com:10101", srt::SrtOptions::default()).await?;
while let Some(payload) = sock.recv().await? {
    // one live-mode message, e.g. up to 7 MPEG-TS packets
}
```

Serving (listener):

```rust
let mut listener = srt::SrtListener::bind("0.0.0.0:10101", srt::SrtOptions::default()).await?;
let (mut sock, peer) = listener.accept().await?;
sock.send(b"...").await?;
```

Tunables (latency, StreamID, buffer sizes, timeouts) live in
[`SrtOptions`](src/options.rs); defaults follow libsrt 1.4.4 live mode.

## Examples

`recv` writes stream payloads to a file or stdout; `send` pushes a file (or
stdin) at a steady bitrate. Both accept `srt://host:port` (caller) or
`srt://:port` (listener) URLs with `?latency=<ms>`, `?streamid=<s>` and,
for `send`, `?rate=<mbps>`:

```text
cargo run --example recv -- 'srt://:9000' out.ts
cargo run --example send -- in.ts 'srt://127.0.0.1:9000?rate=8'
```

## Layout

Three layers; lower layers never depend on higher ones:

- `src/packet/` — pure wire codec: (de)serialization of data and control
  packets, handshake CIF + extensions, wrap-aware protocol integer types.
- `src/core/` — sans-I/O connection state machine: handshake FSMs, sender
  ARQ, receiver TSBPD/loss/ACK-NAK, time base. Driven by explicit inputs
  and `now: Instant`; never sleeps or reads the clock.
- crate root — tokio runtime and public API: `src/socket.rs` /
  `src/listener.rs` driver tasks, `src/net.rs` UDP plumbing.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full layer map and
[docs/spec/](docs/spec/) for the condensed protocol reference (verified
against libsrt 1.4.4, including the trap list in `docs/spec/NOTES.md`).

## Tests

```text
cargo test
```

- lib unit tests — packet codec round-trips, core state machines with a
  fake clock, runtime pieces (221 tests);
- `tests/core_sim.rs` — sans-I/O end-to-end simulations of two `Connection`s
  over a lossy virtual wire (7);
- `tests/loopback.rs` — real sockets, this library on both ends (8);
- `tests/lossy.rs` — loopback through a deterministic drop/reorder/duplicate
  UDP proxy, exercising ARQ and TLPKTDROP (38);
- `tests/interop_slt.rs` — against a real `srt-live-transmit` (libsrt
  1.4.4), both directions, both roles, including lossy-proxy ARQ runs (40);
  these tests **skip** (printing `SKIP`) when `srt-live-transmit` is not
  installed;
- `tests/tsbpd_stall.rs` — TSBPD regression cases (2);
- `tests/support_selftest.rs` — self-tests for the test toolkit itself:
  deterministic RNG, payload verifier, UDP proxy, process harness (37).

## Status and limitations

Interops with libsrt 1.4.4 in both directions; verified against production
streams. Known limitations:

- IPv4 only (`connect`/`bind` reject names that resolve only to IPv6).
- No encryption: peers requiring a passphrase are rejected with
  `SrtError::EncryptionUnsupported` / rejection code `UNSECURE`.
- No rendezvous mode, no file/messaging mode, no bonding/groups, no packet
  filter/FEC (handshakes requesting packet filter are rejected).
- Send pacing is input-driven: packets go out as the application submits
  them (plus ARQ retransmissions). There is no LiveCC output smoothing, so
  a bursty sender produces bursty wire traffic.
- No TSBPD drift compensation: receiver delivery timing assumes
  sender/receiver clock drift stays well under the latency budget, which
  holds at µs-per-minute real-world drift rates (see `src/core/time.rs`).
