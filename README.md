# rsrt

SRT (Secure Reliable Transport) protocol library in pure Rust — no C
dependencies, async (tokio). Live transmission mode over UDP with TSBPD
(timestamp-based packet delivery) including clock-drift compensation, ARQ
(ACK/NAK/retransmission), too-late packet drop, LiveCC send-rate pacing, and
HaiCrypt AES-128/192/256-CTR encryption with passphrase key exchange and
in-stream key refresh. Caller and listener modes, HSv5 handshake.

The implementation was written from the protocol specification, IETF draft
[draft-sharabayko-srt-01](https://datatracker.ietf.org/doc/html/draft-sharabayko-srt-01).
Interoperability with libsrt 1.4.4 (`srt-live-transmit`) is covered by the
test suite in both directions.

**Out of scope:**

- rendezvous mode
- file/messaging mode
- AES-GCM,
- bonding/groups
- packet filter/FEC
- IPv6

## Usage

Receiving (caller):

```rust
let mut sock = rsrt::SrtSocket::connect("127.0.0.1:9000", rsrt::SrtOptions::default()).await?;
while let Some(payload) = sock.recv().await? {
    // one live-mode message, e.g. up to 7 MPEG-TS packets
}
```

Sending (listener):

```rust
let mut listener = rsrt::SrtListener::bind("0.0.0.0:9000", rsrt::SrtOptions::default()).await?;
let (sock, peer) = listener.accept().await?;
sock.send(b"...").await?;
```

Tunables (latency, StreamID, passphrase/key length, bandwidth/pacing, buffer
sizes, timeouts) live in [`SrtOptions`](src/options.rs); defaults follow
libsrt 1.4.4 live mode.

Runnable examples: `recv` writes stream payloads to a file or stdout, `send`
pushes a file (or stdin) at a steady bitrate. Both accept
`srt://host:port` (caller) or `srt://:port` (listener) URLs with
`?latency=<ms>`, `?streamid=<s>`, `?passphrase=<pw>` parameters:

```text
cargo run --example recv -- 'srt://:9000' out.ts
cargo run --example send -- in.ts 'srt://127.0.0.1:9000?rate=8'
```

## Internals

Sans-I/O core: the wire codec, HaiCrypt engine, and connection state machine
are pure and clock-driven, with tokio plumbing only at the crate root. See
[ARCHITECTURE.md](ARCHITECTURE.md) for the layer map. `cargo test` runs unit
tests, sans-I/O simulations, real-socket loopback and lossy-proxy suites;
interop tests against `srt-live-transmit` run when it is installed and are
skipped otherwise.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
