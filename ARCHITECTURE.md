# srt - SRT (Secure Reliable Transport) protocol library for Rust

**Scope**: caller and listener modes, HSv5 handshake, live transmission mode with
TSBPD (timestamp-based packet delivery), ARQ (ACK/NAK/retransmission), TLPKTDROP,
AES-CTR encryption (HaiCrypt: passphrase key exchange in the handshake, in-stream
key refresh).

**Out of scope**: rendezvous mode, file/messaging mode, AES-GCM, bonding/groups,
packet filter/FEC.

Protocol reference: `docs/spec/*.md` (condensed from the IETF draft and libsrt docs).

## Layer model

The crate is split into four layers. Lower layers never depend on higher ones.

```
┌───────────────────────────────────────────────────────────┐
│ 4. runtime (tokio)          src/socket.rs  src/listener.rs │
│    UDP I/O, driver tasks, timers, channels, public API     │
├───────────────────────────────────────────────────────────┤
│ 3. core (sans-I/O)          src/core/                      │
│    connection state machine, handshake FSM + KMX policy,   │
│    sender, receiver (TSBPD/loss/ACK-NAK), time base        │
├───────────────────────────────────────────────────────────┤
│ 2. crypto (sans-I/O)        src/crypto/                    │
│    HaiCrypt engine: key material, KM message codec,        │
│    AES-CTR payload cipher, key-refresh state machine       │
├───────────────────────────────────────────────────────────┤
│ 1. packet codec (pure)      src/packet/                    │
│    wire (de)serialization of data & control packets,       │
│    handshake CIF + extensions, protocol integer types      │
└───────────────────────────────────────────────────────────┘
```

Support files: `src/error.rs` (`SrtError`), `src/options.rs` (`SrtOptions`),
`src/lib.rs` (re-exports only). Layers 1–3 (`packet`, `crypto`, `core`) are
crate-private; the only public surface is the root re-exports in `src/lib.rs`
(`SrtSocket`, `SrtListener`, `SrtOptions`, `Bandwidth`, `SrtError`,
`CloseReason`, `Stats`, `KeyLength`).

### Layer 1 — packet codec (`src/packet/`)

Pure functions and types; **no I/O, no `Instant`, no allocation-free ambition**
(payloads are `Vec<u8>`). Everything round-trips: `parse(encode(p)) == p`.

- `types.rs` — `SeqNumber` (31-bit, wrapping), `MsgNumber` (26-bit, wrapping),
  `SocketId`, `Timestamp` (u32 µs since socket start). Wrap-aware arithmetic
  (`diff`, `next`, `add`) lives here and is the ONLY place seq math is written.
- `data.rs` — `DataPacket` (all header flags + payload).
- `control.rs` — `ControlPacket` = timestamp + dst socket id + `ControlType`
  enum (Handshake, KeepAlive, Ack, Nak, Shutdown, AckAck, DropRequest,
  PeerError, CongestionWarning, KmReq/KmRsp for in-stream key refresh). CIF
  codecs for ACK (full/light/small), NAK (singles + MSB ranges), DROPREQ.
- `handshake.rs` — `HandshakeCif` and extension list codec (HSREQ/HSRSP flags,
  StreamID with its per-word byte reversal, KM passthrough as opaque bytes).
- `mod.rs` — `Packet` enum, top-level `parse`/`encode`, `PacketError`.

All multi-byte fields are network byte order (big-endian) on the wire — with
one deliberate exception: KM blobs are raw byte strings, passed through
without the per-word swap (docs/spec/encryption.md §5). The packet layer
stays crypto-agnostic: it carries KK bits and opaque KM bytes, nothing more.

### Layer 2 — crypto (`src/crypto/`)

The HaiCrypt encryption engine, between the codec and the connection logic:
`core` composes it, `packet` knows nothing about it. Sans-I/O like `core` —
no sockets, no clock of its own (refresh pacing takes `now: Instant` from
the caller), fully unit-testable with fixed keys and a fake clock. Protocol
reference: `docs/spec/encryption.md`.

- `keys.rs` — SEK/KEK key material (zeroized on drop), PBKDF2-HMAC-SHA1 KEK
  derivation from the passphrase, RFC 3394 AES key wrap/unwrap (the unwrap
  integrity check is the protocol's only wrong-passphrase detector).
- `km.rs` — KM message codec (the §3 byte layout) and the 1-word failure
  KMRSP (little-endian on the wire, encryption.md §5.1).
- `ctr.rs` — per-packet AES-CTR keystream; IV built from the KM salt XOR
  the packet sequence number (encryption.md §9.2).
- `context.rs` — `Crypto`, the per-connection engine: initiator/responder
  KMX, even/odd SEK slots with KK-bit routing, ACK-driven TX key refresh
  (pre-announce → switch → decommission), payload encrypt/decrypt.

**Policy stays in core.** `crypto` reports outcomes (unwrap ok / wrong
secret / malformed, the resulting KM states) but never decides to reject or
keep a connection: the encryption.md §8 enforcement matrix is applied by
`core::handshake` (reject vs continue-unsecured at KMX time) and
`core::Connection` (in-stream refresh handling, undecryptable-packet
accounting). Key material never appears in logs — lengths and states only.

### Layer 3 — core (`src/core/`)

Sans-I/O: driven entirely by explicit inputs — incoming packets, the current
`Instant`, and API calls. Produces outputs via poll methods. Never sleeps,
never reads the clock itself (always takes `now: Instant` as an argument).
This makes every protocol rule unit-testable with a fake clock.

- `time.rs` — `Timebase` (local `Instant` ↔ wire `Timestamp` in µs) and
  `TimestampExtender` (extends peer's wrapping u32 µs timestamps to a
  monotonic u64; MANDATORY for streams longer than ~71.6 minutes).
- `handshake.rs` — `CallerHandshake` FSM (induction → conclusion → established,
  250 ms retransmit, 3 s overall timeout) and `Listener` responder (stateless
  SYN-cookie induction replies; on valid conclusion produces a `Negotiated`).
  Both run KMX per the encryption.md §8 matrix: the caller attaches its KMREQ
  to the conclusion and judges the KMRSP; the listener unwraps and echoes.
  `Negotiated` carries everything the established connection needs: peer socket
  id, initial seqs both directions, effective snd/rcv latency, peer idle
  timeout, stream id, agreed MSS/flow window, and the seeded `crypto::Crypto`
  engine (`None` for unencrypted connections; the struct is intentionally not
  `Clone` — it owns key material).
- `pacing.rs` — `Pacer`: LiveCC pacing behind the `Bandwidth` option — the
  input-rate estimator, ceiling/overhead math and the whole-µs send-interval
  credit schedule (docs/spec/transmission.md §3.3); consumed by `sender.rs`.
- `sender.rs` — `Sender`: send buffer (seq-indexed), seq/msg-number assignment,
  ACK release + ACKACK reply, NAK-driven retransmission (REXMIT flag),
  too-late packet drop (emits DROPREQ), in-flight window limiting, pacing gate.
- `receiver.rs` — `Receiver`: receive buffer, loss list, immediate + periodic
  NAK generation, full ACK every 10 ms / light ACK every 64 packets, ACKACK
  RTT estimation (7/8 smoothing), DROPREQ handling, TSBPD release queue with
  too-late skip, timestamp-wrap handling via `TimestampExtender`.
- `mod.rs` — `Connection`: owns the state (Connecting/Established/Closed),
  composes handshake+sender+receiver (plus the `Negotiated` crypto engine:
  encrypt once at first transmission, decrypt by KK bits, drop-and-count
  undecryptable packets without NAKing, drive ACK-paced key refresh),
  dispatches packets, runs timers (keepalive 1 s, peer idle 5 s), handles
  Shutdown. Interface pattern (quinn-proto style):
  - inputs: `handle_packet(now, pkt)`, `handle_timer(now)`, `send(now, &[u8])`,
    `close(now)`
  - outputs: `poll_transmit() -> Option<Packet>` (drain queue),
    `poll_deliver(now) -> Option<Vec<u8>>` (TSBPD-released payloads),
  - scheduling: `next_deadline(now) -> Option<Instant>` (min over all timers).

### Layer 4 — runtime (`src/socket.rs`, `src/listener.rs`)

tokio integration and the public API. One **driver task** per connection loops:

```
select! {
    udp datagram   -> connection.handle_packet(now, parse(..))
    sleep_until(dl)-> connection.handle_timer(now)
    app cmd (mpsc) -> connection.send(..) / close
}
then: drain poll_transmit -> socket.send_to, drain poll_deliver -> data mpsc
```

- `SrtSocket` — public handle: `connect(addr, opts)`, `async recv() -> Result<Vec<u8>>`
  (one SRT message, e.g. up to 1456 bytes), `async send(&[u8])`, `stats()`,
  `streamid()`, `close()`. Cloning/splitting not required in v0.
- `SrtListener` — public handle: `bind(addr, opts)`, `async accept() ->
  (SrtSocket, SocketAddrV4)`. The listener driver owns the UDP socket (shared
  `Arc<tokio::net::UdpSocket>` for sends), answers inductions statelessly,
  and on accepted conclusions spawns a connection driver, demuxing subsequent
  datagrams to it by (peer addr, dst socket id) via mpsc.
- UDP sockets are built via `socket2` (`src/net.rs::bind_udp`: receive buffer
  sized before `bind`, deliberately no `SO_REUSEADDR` — a duplicate bind on an
  SRT port must fail instead of hijacking traffic), then
  `set_nonblocking(true)` → `tokio::net::UdpSocket::from_std`. IPv4 only.

## Conventions

- No new external dependencies beyond the pure-Rust RustCrypto stack that
  backs `src/crypto/` (`aes`, `ctr`, `aes-kw`, `pbkdf2`, `sha1`, `zeroize`,
  `getrandom`). `tracing` for logs (`trace!` per packet, `debug!` for state
  transitions, `warn!` for protocol anomalies) — never key material,
  passphrases, salts or KM blob contents.
- No `unsafe`.
- Errors: one public `SrtError` in `src/error.rs`.
- Every module carries unit tests in-file (`#[cfg(test)] mod tests`). The
  sans-I/O simulation suites (`sim_tests`, `encrypted_sim_tests`,
  `tsbpd_stall_tests`) live in `src/core/` as `#[cfg(test)]` modules because
  they exercise crate-private internals.
- Integration tests in `tests/` (interop with srt-live-transmit, lossy-proxy
  ARQ test) use only the public API. Examples in `examples/` (`recv.rs`,
  `send.rs`).
- Payload limit in live mode: 1456 bytes (MSS 1500 − 28 IPv4/UDP − 16 SRT).
  `send()` of anything larger returns `SrtError::PayloadTooLarge`.

## Interface stability rule (for implementation agents)

Public signatures in the skeleton are contracts other agents compile against.
You may add items and change struct/enum *internals*, but do not rename/remove
existing public items or change their signatures. If a signature is genuinely
wrong, implement around it and report the problem in your summary instead.
