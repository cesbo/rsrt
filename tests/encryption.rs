//! Encrypted loopback integration tests: real caller ↔ listener pairs over
//! 127.0.0.1 exercising the handshake KMX, the always-enforced rejection
//! matrix (docs/spec/encryption.md §8 — the non-enforced rows are not
//! implemented, every mismatch rejects at handshake time) and the
//! key-refresh machinery (§10, §11) end to end through the public API.
//! Each test stays well under ~10 s.

use std::{
    net::Ipv4Addr,
    time::Duration,
};

use rsrt::{
    Bytes,
    KeyLength,
    SrtError,
    SrtListener,
    SrtOptions,
    SrtSocket,
};

/// Passphrases (10..=80 bytes, encryption.md §2). Only ever passed as
/// options — never logged or embedded in assertion output.
const PW: &str = "correct horse battery staple";
const WRONG_PW: &str = "definitely another secret";

/// Deterministic message `i`: 4-byte BE index followed by LCG bytes.
fn message(i: u32, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&i.to_be_bytes());
    let mut x = i.wrapping_mul(2_654_435_761).wrapping_add(0x9E37_79B9);
    while out.len() < len {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        out.push((x >> 24) as u8);
    }
    out
}

/// Establishes a caller ↔ accepted pair through a fresh listener (bound to
/// an ephemeral port, so parallel tests never collide).
async fn pair(copts: SrtOptions, lopts: SrtOptions) -> (SrtSocket, SrtSocket, SrtListener) {
    let mut listener = SrtListener::bind("127.0.0.1:0", lopts)
        .await
        .expect("listener bind");
    let addr = listener.local_addr();
    assert_eq!(*addr.ip(), Ipv4Addr::LOCALHOST);
    assert_ne!(addr.port(), 0);
    let (caller, accepted) = tokio::join!(SrtSocket::connect(addr, copts), listener.accept());
    let caller = caller.expect("connect");
    let (accepted, peer) = accepted.expect("accept");
    assert_eq!(*peer.ip(), Ipv4Addr::LOCALHOST);
    (caller, accepted, listener)
}

// ---- §8 row 8: matching passphrases, all key lengths ----

/// Matching passphrase on both sides: data flows byte-perfect in both
/// directions. The listener gets no `pbkeylen` on purpose — it must adopt
/// the caller's KLen from the KMREQ (encryption.md §7), whatever the
/// caller chose.
async fn matching_passphrase_roundtrip(keylen: KeyLength) {
    const COUNT: u32 = 40;
    const LEN: usize = 600;

    let copts = SrtOptions::default().passphrase(PW).pbkeylen(keylen);
    let lopts = SrtOptions::default().passphrase(PW);
    let (mut caller, mut accepted, _listener) = pair(copts, lopts).await;

    // Caller → listener.
    for i in 0 .. COUNT {
        caller.send(&message(i, LEN)).await.expect("caller send");
    }
    for i in 0 .. COUNT {
        let payload = accepted.recv().await.expect("recv").expect("early EOF");
        assert_eq!(payload, message(i, LEN), "caller→listener message {i}");
    }

    // Listener → caller: the caller's one SEK serves both directions after
    // the handshake KMX (encryption.md §1).
    for i in 0 .. COUNT {
        accepted
            .send(&message(1_000_000 + i, LEN))
            .await
            .expect("accepted send");
    }
    for i in 0 .. COUNT {
        let payload = caller.recv().await.expect("recv").expect("early EOF");
        assert_eq!(
            payload,
            message(1_000_000 + i, LEN),
            "listener→caller message {i}"
        );
    }

    // Every packet decrypted; nobody refreshed (default rate is 2^24, §12).
    assert_eq!(caller.stats().undecrypted_pkts, 0);
    assert_eq!(accepted.stats().undecrypted_pkts, 0);
    assert_eq!(caller.stats().km_refreshes, 0);
    caller.close().await.expect("caller close");
    accepted.close().await.expect("accepted close");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matching_passphrase_roundtrip_aes128() {
    tokio::time::timeout(
        Duration::from_secs(9),
        matching_passphrase_roundtrip(KeyLength::Aes128),
    )
    .await
    .expect("test timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matching_passphrase_roundtrip_aes192() {
    tokio::time::timeout(
        Duration::from_secs(9),
        matching_passphrase_roundtrip(KeyLength::Aes192),
    )
    .await
    .expect("test timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matching_passphrase_roundtrip_aes256() {
    tokio::time::timeout(
        Duration::from_secs(9),
        matching_passphrase_roundtrip(KeyLength::Aes256),
    )
    .await
    .expect("test timed out");
}

// ---- §8 rejection matrix: every mismatch rejects (rows 2-7, 9-11) ----

/// §8 row 9 [wire-verified]: the listener answers a KMREQ it cannot
/// unwrap with `SRT_REJ_BADSECRET` (1010) → [`SrtError::WrongPassphrase`].
/// Rows 10/11 (non-enforced: connect, then drop everything undecryptable)
/// collapse into this rejection — the library is always enforced, so a
/// passphrase mismatch never connects, whichever side holds which secret.
/// The rejection is per-connection: the listener keeps serving and a caller
/// with the right passphrase connects immediately afterwards.
#[tokio::test]
async fn wrong_passphrase_rejected_listener_keeps_serving() {
    let run = async {
        let mut listener = SrtListener::bind("127.0.0.1:0", SrtOptions::default().passphrase(PW))
            .await
            .expect("listener bind");
        let addr = listener.local_addr();

        let err = SrtSocket::connect(addr, SrtOptions::default().passphrase(WRONG_PW))
            .await
            .err()
            .expect("wrong passphrase must not connect");
        assert!(matches!(err, SrtError::WrongPassphrase), "{err:?}");

        // Same listener, right passphrase: connect and move data.
        let (caller, accepted) = tokio::join!(
            SrtSocket::connect(addr, SrtOptions::default().passphrase(PW)),
            listener.accept()
        );
        let caller = caller.expect("connect after rejection");
        let (mut accepted, _) = accepted.expect("accept after rejection");
        caller.send(b"still serving").await.expect("send");
        assert_eq!(
            accepted.recv().await.expect("recv"),
            Some(Bytes::from_static(b"still serving"))
        );
        caller.close().await.expect("caller close");
        accepted.close().await.expect("accepted close");
    };
    tokio::time::timeout(Duration::from_secs(9), run)
        .await
        .expect("test timed out");
}

/// §8 row 5: listener with a passphrase, caller without one — the
/// "Agent declares encryption, but Peer does not" post-check rejects with
/// `SRT_REJ_UNSECURE` (1011) → [`SrtError::EncryptionUnsupported`]. Rows
/// 6/7 (non-enforced: connect and even deliver the caller's cleartext)
/// collapse into this rejection — a listener-side-only passphrase never
/// connects.
#[tokio::test]
async fn plain_caller_rejected_by_encrypted_listener() {
    let run = async {
        let listener = SrtListener::bind("127.0.0.1:0", SrtOptions::default().passphrase(PW))
            .await
            .expect("listener bind");
        let err = SrtSocket::connect(listener.local_addr(), SrtOptions::default())
            .await
            .err()
            .expect("passphrase-less caller must not connect");
        assert!(matches!(err, SrtError::EncryptionUnsupported), "{err:?}");
    };
    tokio::time::timeout(Duration::from_secs(9), run)
        .await
        .expect("test timed out");
}

/// §8 row 2 [wire-verified]: the inverse — a listener *without* a
/// passphrase rejects a caller's KMREQ with `SRT_REJ_UNSECURE` (1011) →
/// [`SrtError::EncryptionUnsupported`]. Rows 3/4 (non-enforced: connect,
/// then silently drop the undecryptable stream) collapse into this
/// rejection — a caller-side-only passphrase never connects either.
#[tokio::test]
async fn encrypted_caller_rejected_by_plain_listener() {
    let run = async {
        let listener = SrtListener::bind("127.0.0.1:0", SrtOptions::default())
            .await
            .expect("listener bind");
        let err = SrtSocket::connect(listener.local_addr(), SrtOptions::default().passphrase(PW))
            .await
            .err()
            .expect("encrypted caller must not connect to a plain listener");
        assert!(matches!(err, SrtError::EncryptionUnsupported), "{err:?}");
    };
    tokio::time::timeout(Duration::from_secs(9), run)
        .await
        .expect("test timed out");
}

// ---- §10, §11: key refresh over real sockets ----

/// A tiny refresh window (rr=64, pa=16) under a real-socket stream of 500
/// messages: the ACK-driven refresh machine (§10.2) rotates the TX SEK at
/// least once mid-stream, the dual-SEK KMREQ keeps the receiver keyed
/// through every switch, and all 500 messages arrive in order, byte-perfect.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn km_refresh_mid_stream_delivers_everything() {
    const COUNT: u32 = 500;
    const LEN: usize = 188;

    let mut copts = SrtOptions::default().passphrase(PW);
    copts.km_refresh_rate = Some(64);
    copts.km_preannounce = Some(16);
    // Generous UDP receive buffer on the receiving side, as in the plain
    // loopback stream test; the kernel clamps to rmem_max silently.
    let mut lopts = SrtOptions::default().passphrase(PW);
    lopts.udp_recv_buffer = Some(4 << 20);

    let (caller, mut accepted, _listener) = pair(copts, lopts).await;

    let send_task = tokio::spawn(async move {
        for i in 0 .. COUNT {
            caller.send(&message(i, LEN)).await.expect("send");
            // Light pacing lets ACKs interleave, so the §10.2 machine gets
            // to pre-announce (and the KMREQ to land) before each switch.
            if i % 10 == 9 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        // Let ARQ (and any in-flight KMX) settle before SHUTDOWN.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let refreshes = caller.stats().km_refreshes;
        caller.close().await.expect("close");
        refreshes
    });

    let recv_task = async {
        let mut next = 0u32;
        while let Some(payload) = accepted.recv().await.expect("recv") {
            assert_eq!(
                payload,
                message(next, LEN),
                "message {next} corrupted or out of order"
            );
            next += 1;
        }
        assert_eq!(next, COUNT, "stream ended early");
    };
    tokio::time::timeout(Duration::from_secs(9), recv_task)
        .await
        .expect("receive timed out");

    // 500 packets across rr=64 crossed the switch threshold repeatedly;
    // the sender must have completed at least one TX key switch (§10.1).
    let refreshes = send_task.await.expect("send task");
    assert!(refreshes >= 1, "km_refreshes = {refreshes}, want >= 1");
    // Nothing was lost to a key switch: every packet found its SEK slot
    // keyed on arrival (§10.4 both-keys window).
    assert_eq!(accepted.stats().undecrypted_pkts, 0);
}
