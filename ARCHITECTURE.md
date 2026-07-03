# srt - SRT (Secure Reliable Transport) protocol library for Rust

**Scope**: caller and listener modes, HSv5 handshake, live transmission mode with
TSBPD (timestamp-based packet delivery), ARQ (ACK/NAK/retransmission), TLPKTDROP.

**Out of scope**: rendezvous mode, file/messaging mode, encryption (connections
requiring crypto are rejected cleanly), bonding/groups, packet filter/FEC.

Protocol reference: `docs/spec/*.md` (condensed from the IETF draft and libsrt docs).

## Layer model

The crate is split into three layers. Lower layers never depend on higher ones.

```
┌───────────────────────────────────────────────────────────┐
│ 3. runtime (tokio)          src/socket.rs  src/listener.rs │
│    UDP I/O, driver tasks, timers, channels, public API     │
├───────────────────────────────────────────────────────────┤
│ 2. core (sans-I/O)          src/core/                      │
│    connection state machine, handshake FSM, sender,        │
│    receiver (TSBPD/loss/ACK-NAK), time base                │
├───────────────────────────────────────────────────────────┤
│ 1. packet codec (pure)      src/packet/                    │
│    wire (de)serialization of data & control packets,       │
│    handshake CIF + extensions, protocol integer types      │
└───────────────────────────────────────────────────────────┘
```

Support files: `src/error.rs` (`SrtError`), `src/options.rs` (`SrtOptions`),
`src/lib.rs` (re-exports only).

### Layer 1 — packet codec (`src/packet/`)

Pure functions and types; **no I/O, no `Instant`, no allocation-free ambition**
(payloads are `Vec<u8>`). Everything round-trips: `parse(encode(p)) == p`.

- `types.rs` — `SeqNumber` (31-bit, wrapping), `MsgNumber` (26-bit, wrapping),
  `SocketId`, `Timestamp` (u32 µs since socket start). Wrap-aware arithmetic
  (`diff`, `next`, `add`) lives here and is the ONLY place seq math is written.
- `data.rs` — `DataPacket` (all header flags + payload).
- `control.rs` — `ControlPacket` = timestamp + dst socket id + `ControlType`
  enum (Handshake, KeepAlive, Ack, Nak, Shutdown, AckAck, DropRequest,
  PeerError, CongestionWarning). CIF codecs for ACK (full/light/small), NAK
  (singles + MSB ranges), DROPREQ.
- `handshake.rs` — `HandshakeCif` and extension list codec (HSREQ/HSRSP flags,
  StreamID with its per-word byte reversal, KM passthrough as opaque bytes).
- `mod.rs` — `Packet` enum, top-level `parse`/`encode`, `PacketError`.

All multi-byte fields are network byte order (big-endian) on the wire.

### Layer 2 — core (`src/core/`)

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
  `Negotiated` carries everything the established connection needs: peer socket
  id, initial seqs both directions, effective snd/rcv latency, peer idle
  timeout, stream id, agreed MSS/flow window.
- `sender.rs` — `Sender`: send buffer (seq-indexed), seq/msg-number assignment,
  ACK release + ACKACK reply, NAK-driven retransmission (REXMIT flag),
  too-late packet drop (emits DROPREQ), in-flight window limiting.
- `receiver.rs` — `Receiver`: receive buffer, loss list, immediate + periodic
  NAK generation, full ACK every 10 ms / light ACK every 64 packets, ACKACK
  RTT estimation (7/8 smoothing), DROPREQ handling, TSBPD release queue with
  too-late skip, timestamp-wrap handling via `TimestampExtender`.
- `mod.rs` — `Connection`: owns the state (Connecting/Established/Closed),
  composes handshake+sender+receiver, dispatches packets, runs timers
  (keepalive 1 s, peer idle 5 s), handles Shutdown. Interface pattern
  (quinn-proto style):
  - inputs: `handle_packet(now, pkt)`, `handle_timer(now)`, `send(now, &[u8])`,
    `close(now)`
  - outputs: `poll_transmit() -> Option<Packet>` (drain queue),
    `poll_deliver(now) -> Option<Vec<u8>>` (TSBPD-released payloads),
  - scheduling: `next_deadline(now) -> Option<Instant>` (min over all timers).

### Layer 3 — runtime (`src/socket.rs`, `src/listener.rs`)

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
- UDP sockets are created with the `udp` crate (cesbo/libudp: buffer sizing
  etc.), then `into_std()` → `set_nonblocking(true)` → `tokio::net::UdpSocket::from_std`.
  IPv4 only (libudp is `SocketAddrV4`-based).

## Conventions

- Zero new external dependencies. `tracing` for logs (`trace!` per packet,
  `debug!` for state transitions, `warn!` for protocol anomalies).
- No `unsafe`.
- Errors: one public `SrtError` in `src/error.rs`.
- Every module carries unit tests in-file (`#[cfg(test)] mod tests`).
- Integration tests in `tests/` (interop with srt-live-transmit, lossy-proxy
  ARQ test). Examples in `examples/` (`recv.rs`, `send.rs`).
- Payload limit in live mode: 1456 bytes (MSS 1500 − 28 IPv4/UDP − 16 SRT).
  `send()` of anything larger returns `SrtError::PayloadTooLarge`.

## Interface stability rule (for implementation agents)

Public signatures in the skeleton are contracts other agents compile against.
You may add items and change struct/enum *internals*, but do not rename/remove
existing public items or change their signatures. If a signature is genuinely
wrong, implement around it and report the problem in your summary instead.
