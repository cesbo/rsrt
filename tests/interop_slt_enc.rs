//! Encrypted interop matrix against the reference `srt-live-transmit`
//! (libsrt 1.4.4), pinning the HaiCrypt wire format and KMX semantics of
//! docs/spec/encryption.md against the normative implementation:
//!
//! 1. **Matching-passphrase matrix** — all four directions of
//!    `tests/interop_slt.rs` with a shared passphrase, at PBKEYLEN 16 and 32
//!    (24 once), byte-perfect payload comparison. Caller directions prove
//!    our initiator KMREQ + KMRSP-echo validation (§6.1, §6.3); listener
//!    directions prove our responder unwrap + byte-exact echo and the
//!    RX→TX clone (§6.2), each against real libsrt ciphertext (§9.2).
//! 2. **Wrong passphrase, both roles** (§8 rows 9/10): an slt listener
//!    (libsrt's default enforced encryption) rejects us with wire code
//!    1010 → [`SrtError::WrongPassphrase`]; our listener rejects an slt
//!    caller, whose log must show libsrt's BADSECRET text "Incorrect
//!    passphrase", while our listener keeps serving.
//! 3. **Key refresh, both roles** (§10, §11): our sender at
//!    `km_refresh_rate=128` / `km_preannounce=32` streams ~2000 packets to
//!    an slt receiver byte-perfect across ≥ 2 SEK switches (wire-proves our
//!    dual-SEK KMREQ and switch timing); an slt sender with the same rates
//!    streams to our receiver byte-perfect (wire-proves our in-stream KMREQ
//!    install + echo KMRSP — libsrt re-sends a KMREQ up to 10× unless the
//!    byte-exact echo lands, §11.2).
//! 4. **Mismatches are always rejected** (§8 rows 2-7, 10/11): the library
//!    is always enforced — the §8 non-enforced rows are not implemented,
//!    every encryption mismatch fails at handshake time. Our listener
//!    rejects an slt caller whose KMX cannot succeed with wire code 1011,
//!    decoded in the slt log as libsrt's UNSECURE text "Password required
//!    or unexpected"; and a permissive (`enforcedencryption=false`) slt
//!    listener that answers our KMREQ with a 1-word failure-status KMRSP
//!    (§5.1) instead of rejecting makes our caller abort locally (§6.1).
//!
//! Same conventions as `tests/interop_slt.rs`: byte-stream (not message)
//! equality since slt re-chunks at 1316 bytes, `SKIP` + return when the
//! binary is missing, unique free ports, a hard 30 s outer timeout, and
//! kill-on-drop slt children. Passphrases appear only in options/URIs,
//! never in assertion output.

mod support;

use std::{
    future::Future,
    time::Duration,
};

use rsrt::{
    KeyLength,
    SrtError,
    SrtListener,
    SrtOptions,
    SrtSocket,
};
use support::{
    free_udp_port,
    payload::verify_prefix,
    slt::{
        caller_uri,
        listener_uri,
        require_slt,
        SltProcess,
    },
    PayloadGen,
    PayloadVerifier,
    MESSAGE_SIZE,
};

/// Hard per-test budget.
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

/// ~1.5 MB per matrix direction, in slt-sized (1316-byte) messages.
const MESSAGES: usize = 1200;
const TOTAL: usize = MESSAGES * MESSAGE_SIZE;

/// Refresh tests stream ~2000 packets: at `km_refresh_rate = 128` that
/// crosses the switch threshold ~15 times (§10.1) — far more than the ≥ 2
/// completed switches the tests assert.
const REFRESH_MESSAGES: usize = 2000;
const REFRESH_TOTAL: usize = REFRESH_MESSAGES * MESSAGE_SIZE;

/// TX SEK refresh window under test: dual-SEK KMREQ at 96 packets, key
/// switch at 128, old key retired 32 packets later (§10.1).
const KM_REFRESH_RATE: u32 = 128;
const KM_PREANNOUNCE: u32 = 32;

/// Pace between messages: ~1.3 MB/s — a modest live rate that never
/// overruns latency or flow windows on loopback.
const PACE: Duration = Duration::from_millis(1);

/// slt log level `note` prints connection events (and warnings, e.g. the
/// rejection reason a rejected caller logs); `SltProcess` echoes them with
/// a `[slt <pid>]` prefix — the debugging trail when an assertion fires.
const LOG: &str = "-ll:note";

/// Shared secret for the matching-passphrase tests (10..=80 bytes, §2).
const PASSPHRASE: &str = "interop-enc m4trix secret";
/// A different, equally valid secret for the mismatch tests.
const WRONG_PASSPHRASE: &str = "interop-enc wr0ng secret";

/// Wraps a test body in the hard outer timeout. On expiry the whole future
/// (sockets, listener, slt child) is dropped, which kills the child.
async fn within_timeout<T>(fut: impl Future<Output = T>) -> T {
    match tokio::time::timeout(TEST_TIMEOUT, fut).await {
        Ok(v) => v,
        Err(_) => panic!("test exceeded the {TEST_TIMEOUT:?} hard timeout"),
    }
}

/// Receives from `sock` until `total` bytes of the stream for `seed` have
/// been verified. Panics on divergence, early end of stream, or a 10 s
/// stall. Divergence is what a missed or mis-decrypted packet looks like:
/// AES-CTR has no integrity check, garbage plaintext only shows up here
/// (§9.4).
async fn recv_and_verify(sock: &mut SrtSocket, seed: u64, total: usize) {
    let mut verifier = PayloadVerifier::new(seed);
    while (verifier.verified() as usize) < total {
        match tokio::time::timeout(Duration::from_secs(10), sock.recv()).await {
            Ok(Ok(Some(payload))) => verifier
                .update(&payload)
                .unwrap_or_else(|e| panic!("received stream diverged: {e}")),
            Ok(Ok(None)) => panic!(
                "stream ended early: {} of {total} bytes",
                verifier.verified()
            ),
            Ok(Err(e)) => panic!("recv failed at byte {}: {e}", verifier.verified()),
            Err(_) => panic!(
                "delivery stalled for 10 s at byte {} of {total}",
                verifier.verified()
            ),
        }
    }
}

/// Sends `messages` [`MESSAGE_SIZE`]-byte paced messages of the stream for
/// `seed`.
async fn send_stream(sock: &SrtSocket, seed: u64, messages: usize) {
    let mut generator = PayloadGen::new(seed);
    for i in 0 .. messages {
        sock.send(&generator.next_message())
            .await
            .unwrap_or_else(|e| panic!("send (message {i}): {e}"));
        tokio::time::sleep(PACE).await;
    }
}

/// `pbkeylen=N` URI parameter for slt (apps/socketoptions.hpp key).
fn pbkeylen_param(keylen: KeyLength) -> String {
    format!("pbkeylen={}", keylen.bytes())
}

// ---- 1. Matching-passphrase matrix (§8 row 8) ----

/// Our caller receives from an slt listener transmitting its stdin. We are
/// the KMX initiator (§1): slt must accept our KMREQ, echo it byte-exact,
/// and encrypt with *our* SEK; our RX decrypts real libsrt AES-CTR.
async fn caller_receives(keylen: KeyLength, seed: u64) {
    let binary = require_slt!();
    within_timeout(async {
        let port = free_udp_port().expect("free port");
        let pw_param = format!("passphrase={PASSPHRASE}");
        let kl_param = pbkeylen_param(keylen);
        // stdin -> srt://:port. `-c:1316` keeps stdin reads within the
        // default SRTO_PAYLOADSIZE even if the pipe coalesces writes.
        let mut slt = SltProcess::spawn_send(
            &binary,
            &listener_uri(port, &["latency=120", &pw_param, &kl_param]),
            &[LOG, "-c:1316", "-a:no"],
        )
        .expect("spawn srt-live-transmit");
        tokio::time::sleep(Duration::from_millis(300)).await; // let it bind

        let opts = SrtOptions::default().passphrase(PASSPHRASE).pbkeylen(keylen);
        let mut sock = SrtSocket::connect(("127.0.0.1", port), opts)
            .await
            .expect("connect to slt listener");
        // slt drops source data while its SRT output has no connection
        // (tiny internal buffering); feed stdin only once it has accepted.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let data = PayloadGen::stream_prefix(seed, TOTAL);
        let (fed, ()) = tokio::join!(
            slt.feed_stdin(&data, MESSAGE_SIZE, PACE),
            recv_and_verify(&mut sock, seed, TOTAL),
        );
        fed.expect("feed slt stdin");

        let stats = sock.stats();
        assert_eq!(
            stats.undecrypted_pkts, 0,
            "every packet must decrypt with the shared passphrase: {stats:?}"
        );
        assert_eq!(
            stats.pkts_recv_dropped, 0,
            "unrecovered drops on a loss-free path: {stats:?}"
        );
        assert!(stats.pkts_recv as usize >= MESSAGES, "{stats:?}");
        sock.close().await.expect("close");
        slt.kill().await.ok();
    })
    .await;
}

/// Our caller sends to an slt listener writing to stdout: real libsrt must
/// unwrap our KMREQ (KEK derivation §4.2, RFC 3394 unwrap §4.3) and decrypt
/// our AES-CTR ciphertext byte-for-byte.
async fn caller_sends(keylen: KeyLength, seed: u64) {
    let binary = require_slt!();
    within_timeout(async {
        let port = free_udp_port().expect("free port");
        let pw_param = format!("passphrase={PASSPHRASE}");
        let kl_param = pbkeylen_param(keylen);
        // srt://:port -> stdout.
        let mut slt = SltProcess::spawn_receive(
            &binary,
            &listener_uri(port, &["latency=120", &pw_param, &kl_param]),
            &[LOG, "-a:no"],
        )
        .expect("spawn srt-live-transmit");
        tokio::time::sleep(Duration::from_millis(300)).await; // let it bind

        let opts = SrtOptions::default().passphrase(PASSPHRASE).pbkeylen(keylen);
        let sock = SrtSocket::connect(("127.0.0.1", port), opts)
            .await
            .expect("connect to slt listener");
        tokio::time::sleep(Duration::from_millis(200)).await; // slt sees the accept

        // Collect concurrently (1.5 MB exceeds the 64 KiB pipe buffer, so a
        // non-reading test would wedge slt). slt's stdout is stdio
        // block-buffered at 4 KiB when piped: the stream tail only flushes
        // when slt exits, so after sending (+ ARQ settle) close our socket —
        // slt (with -a:no) sees the disconnect, exits, and flushes.
        let (out, stats) =
            tokio::join!(slt.collect_stdout(TOTAL, Duration::from_secs(25)), async {
                send_stream(&sock, seed, MESSAGES).await;
                tokio::time::sleep(Duration::from_millis(800)).await;
                let stats = sock.stats();
                sock.close().await.expect("close");
                stats
            },);
        let out = out.expect("collect slt stdout");
        assert_eq!(
            out.len(),
            TOTAL,
            "slt wrote {} of {TOTAL} bytes (data lost sender->slt); slt stderr: {:?}",
            out.len(),
            slt.drain_stderr(),
        );
        verify_prefix(seed, &out).unwrap_or_else(|e| panic!("slt output diverged: {e}"));

        assert_eq!(
            stats.pkts_send_dropped, 0,
            "sender dropped packets on a loss-free path: {stats:?}"
        );
        assert!(stats.pkts_sent as usize >= MESSAGES, "{stats:?}");
        slt.kill().await.ok();
    })
    .await;
}

/// An slt caller pushes its stdin into our listener: our responder must run
/// the §6.2 handshake KMX against a real libsrt KMREQ and answer with the
/// byte-exact echo (§6.3 — slt aborts otherwise), then decrypt slt's
/// AES-CTR. No `pbkeylen` on our side on purpose: the responder adopts the
/// KMREQ's KLen (§7).
async fn listener_receives(keylen: KeyLength, seed: u64) {
    let binary = require_slt!();
    within_timeout(async {
        let opts = SrtOptions::default().passphrase(PASSPHRASE);
        let mut listener = SrtListener::bind("127.0.0.1:0", opts)
            .await
            .expect("bind listener");
        let port = listener.local_addr().port();

        let pw_param = format!("passphrase={PASSPHRASE}");
        let kl_param = pbkeylen_param(keylen);
        let mut slt = SltProcess::spawn_send(
            &binary,
            &caller_uri(port, &["latency=120", &pw_param, &kl_param]),
            &[LOG, "-c:1316", "-a:no"],
        )
        .expect("spawn srt-live-transmit");

        let (mut sock, _peer) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("slt caller never connected")
            .expect("accept");
        // Our listener is established on sending the conclusion response;
        // give slt a moment to process it before data flows.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let data = PayloadGen::stream_prefix(seed, TOTAL);
        let (fed, ()) = tokio::join!(
            slt.feed_stdin(&data, MESSAGE_SIZE, PACE),
            recv_and_verify(&mut sock, seed, TOTAL),
        );
        fed.expect("feed slt stdin");

        let stats = sock.stats();
        assert_eq!(
            stats.undecrypted_pkts, 0,
            "every packet must decrypt with the shared passphrase: {stats:?}"
        );
        assert_eq!(
            stats.pkts_recv_dropped, 0,
            "unrecovered drops on a loss-free path: {stats:?}"
        );
        assert!(stats.pkts_recv as usize >= MESSAGES, "{stats:?}");
        sock.close().await.expect("close");
        slt.kill().await.ok();
    })
    .await;
}

/// An slt caller pulls from our listener to stdout: the caller's SEK rides
/// its KMREQ, our responder clones RX→TX (§1, §6.2 step 5) and encrypts
/// with *slt's* SEK — slt must decrypt our TX byte-for-byte.
async fn listener_sends(keylen: KeyLength, seed: u64) {
    let binary = require_slt!();
    within_timeout(async {
        let opts = SrtOptions::default().passphrase(PASSPHRASE);
        let mut listener = SrtListener::bind("127.0.0.1:0", opts)
            .await
            .expect("bind listener");
        let port = listener.local_addr().port();

        let pw_param = format!("passphrase={PASSPHRASE}");
        let kl_param = pbkeylen_param(keylen);
        let mut slt = SltProcess::spawn_receive(
            &binary,
            &caller_uri(port, &["latency=120", &pw_param, &kl_param]),
            &[LOG, "-a:no"],
        )
        .expect("spawn srt-live-transmit");

        let (sock, _peer) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("slt caller never connected")
            .expect("accept");
        // Let slt process the conclusion response before data flows.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Same shape as `caller_sends`: collect concurrently, then close our
        // socket so slt exits and flushes its block-buffered stdout tail.
        let (out, stats) =
            tokio::join!(slt.collect_stdout(TOTAL, Duration::from_secs(25)), async {
                send_stream(&sock, seed, MESSAGES).await;
                tokio::time::sleep(Duration::from_millis(800)).await;
                let stats = sock.stats();
                sock.close().await.expect("close");
                stats
            },);
        let out = out.expect("collect slt stdout");
        assert_eq!(
            out.len(),
            TOTAL,
            "slt wrote {} of {TOTAL} bytes (data lost listener->slt); slt stderr: {:?}",
            out.len(),
            slt.drain_stderr(),
        );
        verify_prefix(seed, &out).unwrap_or_else(|e| panic!("slt output diverged: {e}"));

        assert_eq!(
            stats.pkts_send_dropped, 0,
            "sender dropped packets on a loss-free path: {stats:?}"
        );
        assert!(stats.pkts_sent as usize >= MESSAGES, "{stats:?}");
        slt.kill().await.ok();
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encrypted_caller_receives_from_slt_listener_aes128() {
    caller_receives(KeyLength::Aes128, 0x51A7_E001).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encrypted_caller_receives_from_slt_listener_aes256() {
    caller_receives(KeyLength::Aes256, 0x51A7_E002).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encrypted_caller_sends_to_slt_listener_aes128() {
    caller_sends(KeyLength::Aes128, 0x51A7_E003).await;
}

/// The single AES-192 run of the matrix: PBKEYLEN 24 exercises the odd-one
/// KEK/keywrap width (§4) through the whole TX path against real libsrt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encrypted_caller_sends_to_slt_listener_aes192() {
    caller_sends(KeyLength::Aes192, 0x51A7_E004).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encrypted_caller_sends_to_slt_listener_aes256() {
    caller_sends(KeyLength::Aes256, 0x51A7_E005).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encrypted_listener_receives_from_slt_caller_aes128() {
    listener_receives(KeyLength::Aes128, 0x51A7_E006).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encrypted_listener_receives_from_slt_caller_aes256() {
    listener_receives(KeyLength::Aes256, 0x51A7_E007).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encrypted_listener_sends_to_slt_caller_aes128() {
    listener_sends(KeyLength::Aes128, 0x51A7_E008).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encrypted_listener_sends_to_slt_caller_aes256() {
    listener_sends(KeyLength::Aes256, 0x51A7_E009).await;
}

// ---- 2. Wrong passphrase (§8 rows 9/10, §8.1) ----

/// Our caller against an slt listener (default enforced encryption) with
/// a different passphrase: the listener cannot unwrap our SEK and rejects
/// with wire code 1010 (BADSECRET, §8 row 9 [wire-verified]) — surfaced
/// as [`SrtError::WrongPassphrase`].
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_passphrase_caller_rejected_by_slt_listener() {
    let binary = require_slt!();
    within_timeout(async {
        let port = free_udp_port().expect("free port");
        let pw_param = format!("passphrase={PASSPHRASE}");
        let mut slt = SltProcess::spawn_receive(
            &binary,
            &listener_uri(port, &["latency=120", &pw_param]),
            &[LOG, "-a:no"],
        )
        .expect("spawn srt-live-transmit");
        tokio::time::sleep(Duration::from_millis(300)).await; // let it bind

        let opts = SrtOptions::default().passphrase(WRONG_PASSPHRASE);
        let err = SrtSocket::connect(("127.0.0.1", port), opts)
            .await
            .err()
            .expect("connect with a mismatched passphrase must fail");
        assert!(
            matches!(err, SrtError::WrongPassphrase),
            "expected the BADSECRET (1010) rejection to surface as \
             WrongPassphrase, got: {err}"
        );
        slt.kill().await.ok();
    })
    .await;
}

/// An slt caller with the wrong passphrase against our listener:
/// we must reject with wire code 1010 — visible as libsrt's BADSECRET
/// reason text "Incorrect passphrase" in slt's log (`srt_rejectreason_msg`)
/// — and the listener must keep serving: the bad caller is never accepted,
/// and a correct-passphrase caller connects and transfers right after.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_passphrase_slt_caller_rejected_listener_keeps_serving() {
    let binary = require_slt!();
    const SEED: u64 = 0x51A7_E00B;
    const HEALTH_MESSAGES: usize = 300;
    const HEALTH_TOTAL: usize = HEALTH_MESSAGES * MESSAGE_SIZE;
    within_timeout(async {
        let opts = SrtOptions::default().passphrase(PASSPHRASE);
        let mut listener = SrtListener::bind("127.0.0.1:0", opts)
            .await
            .expect("bind listener");
        let port = listener.local_addr().port();

        let wrong_param = format!("passphrase={WRONG_PASSPHRASE}");
        let mut bad = SltProcess::spawn_send(
            &binary,
            &caller_uri(port, &["latency=120", &wrong_param]),
            &[LOG, "-c:1316", "-a:no"],
        )
        .expect("spawn srt-live-transmit (wrong passphrase)");

        // Our rejection replaces the conclusion response (§6.2); the slt
        // caller logs the decoded reason at warn level.
        let hit = bad
            .wait_for_stderr(Duration::from_secs(10), |l| {
                l.contains("Incorrect passphrase")
            })
            .await;
        assert!(
            hit.is_some(),
            "slt caller never logged the BADSECRET reason 'Incorrect passphrase'"
        );

        // The rejected caller must never reach the accept queue while it
        // keeps retrying (its connect timeout is ~3 s).
        let pending = tokio::time::timeout(Duration::from_secs(2), listener.accept()).await;
        assert!(
            pending.is_err(),
            "listener accepted a caller whose key exchange failed"
        );
        bad.kill().await.ok();

        // Listener health: a matching caller connects and transfers.
        let pw_param = format!("passphrase={PASSPHRASE}");
        let mut good = SltProcess::spawn_send(
            &binary,
            &caller_uri(port, &["latency=120", &pw_param]),
            &[LOG, "-c:1316", "-a:no"],
        )
        .expect("spawn srt-live-transmit (correct passphrase)");
        let (mut sock, _peer) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("correct-passphrase slt caller never connected")
            .expect("accept");
        tokio::time::sleep(Duration::from_millis(200)).await;

        let data = PayloadGen::stream_prefix(SEED, HEALTH_TOTAL);
        let (fed, ()) = tokio::join!(
            good.feed_stdin(&data, MESSAGE_SIZE, PACE),
            recv_and_verify(&mut sock, SEED, HEALTH_TOTAL),
        );
        fed.expect("feed slt stdin");

        let stats = sock.stats();
        assert_eq!(stats.undecrypted_pkts, 0, "{stats:?}");
        sock.close().await.expect("close");
        good.kill().await.ok();
    })
    .await;
}

// ---- 3. Key refresh across the wire (§10, §11) ----

/// Our sender refreshes its TX SEK every 128 packets while streaming ~2000
/// packets to an slt receiver: byte-perfect slt output across ≥ 2 completed
/// switches wire-proves the dual-SEK KMREQ (even-first wrap order, §4.3),
/// the in-stream `UMSG_EXT` carrier (§11.1) and the KK-bit flip at the
/// switch (§10.1) against real libsrt — its receiver only survives a switch
/// if the refreshed key was installed from our KM message.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn km_refresh_our_sender_switches_seks_under_slt_receiver() {
    let binary = require_slt!();
    const SEED: u64 = 0x51A7_E00C;
    within_timeout(async {
        let port = free_udp_port().expect("free port");
        let pw_param = format!("passphrase={PASSPHRASE}");
        let mut slt = SltProcess::spawn_receive(
            &binary,
            &listener_uri(port, &["latency=120", &pw_param]),
            &[LOG, "-a:no"],
        )
        .expect("spawn srt-live-transmit");
        tokio::time::sleep(Duration::from_millis(300)).await; // let it bind

        let mut opts = SrtOptions::default().passphrase(PASSPHRASE);
        opts.km_refresh_rate = Some(KM_REFRESH_RATE);
        opts.km_preannounce = Some(KM_PREANNOUNCE);
        let sock = SrtSocket::connect(("127.0.0.1", port), opts)
            .await
            .expect("connect to slt listener");
        tokio::time::sleep(Duration::from_millis(200)).await; // slt sees the accept

        // Same collect-then-close shape as the matrix send directions.
        let (out, stats) = tokio::join!(
            slt.collect_stdout(REFRESH_TOTAL, Duration::from_secs(25)),
            async {
                send_stream(&sock, SEED, REFRESH_MESSAGES).await;
                tokio::time::sleep(Duration::from_millis(800)).await;
                let stats = sock.stats();
                sock.close().await.expect("close");
                stats
            },
        );
        let out = out.expect("collect slt stdout");
        assert_eq!(
            out.len(),
            REFRESH_TOTAL,
            "slt wrote {} of {REFRESH_TOTAL} bytes (packets lost across a key \
             switch?); slt stderr: {:?}",
            out.len(),
            slt.drain_stderr(),
        );
        verify_prefix(SEED, &out).unwrap_or_else(|e| panic!("slt output diverged: {e}"));

        // ~2000 packets over rr=128 must have completed several switches;
        // ≥ 2 proves the machine cycles (not a one-shot fluke).
        assert!(
            stats.km_refreshes >= 2,
            "expected >= 2 completed TX SEK switches over {REFRESH_MESSAGES} \
             packets at rr={KM_REFRESH_RATE}: {stats:?}"
        );
        assert_eq!(
            stats.pkts_send_dropped, 0,
            "sender dropped packets on a loss-free path: {stats:?}"
        );
        slt.kill().await.ok();
    })
    .await;
}

/// An slt sender refreshing every 128 packets streams ~2000 packets into
/// our listener: byte-perfect reception with zero undecryptable packets
/// wire-proves our in-stream KMREQ handling — dual-SEK install into the
/// alt context (§10.4) and the byte-exact echo KMRSP (libsrt re-sends the
/// KMREQ up to 10× at 1.5×SRTT unless the echo satisfies it, §11.2).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn km_refresh_slt_sender_our_receiver_installs_dual_sek() {
    let binary = require_slt!();
    const SEED: u64 = 0x51A7_E00D;
    within_timeout(async {
        let opts = SrtOptions::default().passphrase(PASSPHRASE);
        let mut listener = SrtListener::bind("127.0.0.1:0", opts)
            .await
            .expect("bind listener");
        let port = listener.local_addr().port();

        let pw_param = format!("passphrase={PASSPHRASE}");
        let rr_param = format!("kmrefreshrate={KM_REFRESH_RATE}");
        let pa_param = format!("kmpreannounce={KM_PREANNOUNCE}");
        let mut slt = SltProcess::spawn_send(
            &binary,
            &caller_uri(port, &["latency=120", &pw_param, &rr_param, &pa_param]),
            &[LOG, "-c:1316", "-a:no"],
        )
        .expect("spawn srt-live-transmit");

        let (mut sock, _peer) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("slt caller never connected")
            .expect("accept");
        tokio::time::sleep(Duration::from_millis(200)).await;

        let data = PayloadGen::stream_prefix(SEED, REFRESH_TOTAL);
        let (fed, ()) = tokio::join!(
            slt.feed_stdin(&data, MESSAGE_SIZE, PACE),
            recv_and_verify(&mut sock, SEED, REFRESH_TOTAL),
        );
        fed.expect("feed slt stdin");

        let stats = sock.stats();
        // slt switches to the refreshed SEK at rr regardless of our state
        // (§11.2); a single missed dual-SEK install would strand a whole
        // 128-packet window undecryptable.
        assert_eq!(
            stats.undecrypted_pkts, 0,
            "every packet across slt's key switches must decrypt: {stats:?}"
        );
        assert_eq!(
            stats.pkts_recv_dropped, 0,
            "unrecovered drops on a loss-free path: {stats:?}"
        );
        assert!(stats.pkts_recv as usize >= REFRESH_MESSAGES, "{stats:?}");
        sock.close().await.expect("close");
        slt.kill().await.ok();
    })
    .await;
}

// ---- 4. Mismatches are always rejected (§8 rows 2-7, 10/11) ----
//
// The wrong-passphrase seats of the always-enforced matrix (rows 9/10) are
// section 2 above; this section covers the one-sided and permissive-peer
// seats. (An slt caller with the wrong passphrase against our listener is
// `wrong_passphrase_slt_caller_rejected_listener_keeps_serving` — the slt
// side's `enforcedencryption` setting cannot change our rejection.)

/// §8 row 5 from the wire: an slt caller running NO crypto at all (no
/// KMREQ in its conclusion) against our passphrase listener is rejected
/// with wire code 1011 — visible as libsrt's UNSECURE reason text
/// "Password required or unexpected" in slt's log — and never accepted:
/// the passphrase-protected stream is never offered to a peer that did
/// not prove knowledge of the secret (rows 6/7's non-enforced connect is
/// not implemented). The listener keeps serving: a correct-passphrase
/// caller connects and transfers right after.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_slt_caller_rejected_listener_keeps_serving() {
    let binary = require_slt!();
    const SEED: u64 = 0x51A7_E00E;
    const HEALTH_MESSAGES: usize = 300;
    const HEALTH_TOTAL: usize = HEALTH_MESSAGES * MESSAGE_SIZE;
    within_timeout(async {
        let opts = SrtOptions::default().passphrase(PASSPHRASE);
        let mut listener = SrtListener::bind("127.0.0.1:0", opts)
            .await
            .expect("bind listener");
        let port = listener.local_addr().port();

        let mut bad = SltProcess::spawn_send(
            &binary,
            &caller_uri(port, &["latency=120"]),
            &[LOG, "-c:1316", "-a:no"],
        )
        .expect("spawn srt-live-transmit (no passphrase)");

        // Our rejection replaces the conclusion response (§6.2); the slt
        // caller logs the decoded reason at warn level.
        let hit = bad
            .wait_for_stderr(Duration::from_secs(10), |l| {
                l.contains("Password required or unexpected")
            })
            .await;
        assert!(
            hit.is_some(),
            "slt caller never logged the UNSECURE reason 'Password required or unexpected'"
        );

        // The rejected caller must never reach the accept queue while it
        // keeps retrying (its connect timeout is ~3 s).
        let pending = tokio::time::timeout(Duration::from_secs(2), listener.accept()).await;
        assert!(
            pending.is_err(),
            "listener accepted a caller that never sent a KMREQ"
        );
        bad.kill().await.ok();

        // Listener health: a matching caller connects and transfers.
        let pw_param = format!("passphrase={PASSPHRASE}");
        let mut good = SltProcess::spawn_send(
            &binary,
            &caller_uri(port, &["latency=120", &pw_param]),
            &[LOG, "-c:1316", "-a:no"],
        )
        .expect("spawn srt-live-transmit (correct passphrase)");
        let (mut sock, _peer) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("correct-passphrase slt caller never connected")
            .expect("accept");
        tokio::time::sleep(Duration::from_millis(200)).await;

        let data = PayloadGen::stream_prefix(SEED, HEALTH_TOTAL);
        let (fed, ()) = tokio::join!(
            good.feed_stdin(&data, MESSAGE_SIZE, PACE),
            recv_and_verify(&mut sock, SEED, HEALTH_TOTAL),
        );
        fed.expect("feed slt stdin");

        let stats = sock.stats();
        assert_eq!(stats.undecrypted_pkts, 0, "{stats:?}");
        sock.close().await.expect("close");
        good.kill().await.ok();
    })
    .await;
}

/// §8 row 2 from the wire: an encrypted slt caller against our listener
/// *without* a passphrase. We cannot serve its KMREQ and must reject with
/// wire code 1011 — decoded by the slt caller as "Password required or
/// unexpected" — instead of the row-3/4 non-enforced connect-then-drop,
/// and the caller must never reach the accept queue.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encrypted_slt_caller_rejected_by_plain_listener() {
    let binary = require_slt!();
    within_timeout(async {
        let mut listener = SrtListener::bind("127.0.0.1:0", SrtOptions::default())
            .await
            .expect("bind listener");
        let port = listener.local_addr().port();

        let pw_param = format!("passphrase={PASSPHRASE}");
        let mut slt = SltProcess::spawn_send(
            &binary,
            &caller_uri(port, &["latency=120", &pw_param]),
            &[LOG, "-c:1316", "-a:no"],
        )
        .expect("spawn srt-live-transmit");

        let hit = slt
            .wait_for_stderr(Duration::from_secs(10), |l| {
                l.contains("Password required or unexpected")
            })
            .await;
        assert!(
            hit.is_some(),
            "slt caller never logged the UNSECURE reason 'Password required or unexpected'"
        );
        let pending = tokio::time::timeout(Duration::from_secs(2), listener.accept()).await;
        assert!(
            pending.is_err(),
            "listener accepted a caller whose KMREQ it has no passphrase for"
        );
        slt.kill().await.ok();
    })
    .await;
}

/// §8 rows 10/11 from the caller seat: a permissive
/// (`enforcedencryption=false`) slt listener whose unwrap of our KMREQ
/// fails does not reject — it accepts and answers the 1-word BADSECRET
/// KMRSP (`04 00 00 00` on the wire, §5.1). Our caller aborts locally on
/// the failure status (§6.1, libsrt's `processSrtMsg_KMRSP` −1 class);
/// the local abort code is UNSECURE even for a bad secret, so connect
/// fails with [`SrtError::EncryptionUnsupported`].
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn badsecret_kmrsp_from_permissive_slt_listener_aborts_our_caller() {
    let binary = require_slt!();
    within_timeout(async {
        let port = free_udp_port().expect("free port");
        let pw_param = format!("passphrase={PASSPHRASE}");
        let mut slt = SltProcess::spawn_receive(
            &binary,
            &listener_uri(port, &["latency=120", &pw_param, "enforcedencryption=false"]),
            &[LOG, "-a:no"],
        )
        .expect("spawn srt-live-transmit");
        tokio::time::sleep(Duration::from_millis(300)).await; // let it bind

        let opts = SrtOptions::default().passphrase(WRONG_PASSPHRASE);
        let err = SrtSocket::connect(("127.0.0.1", port), opts)
            .await
            .err()
            .expect("a failure-status KMRSP must abort the connect");
        assert!(
            matches!(err, SrtError::EncryptionUnsupported),
            "expected the local UNSECURE abort on a 1-word BADSECRET KMRSP, got: {err}"
        );
        slt.kill().await.ok();
    })
    .await;
}

/// §8 rows 3/4 from the caller seat: a permissive slt listener with *no*
/// passphrase answers our KMREQ with the 1-word NOSECRET KMRSP (`05 00 00
/// 00` on the wire, §5.1) instead of rejecting. Same local abort as
/// above: our caller never connects with a passphrase the peer cannot
/// use — connect fails with [`SrtError::EncryptionUnsupported`].
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nosecret_kmrsp_from_permissive_slt_listener_aborts_our_caller() {
    let binary = require_slt!();
    within_timeout(async {
        let port = free_udp_port().expect("free port");
        let mut slt = SltProcess::spawn_receive(
            &binary,
            &listener_uri(port, &["latency=120", "enforcedencryption=false"]),
            &[LOG, "-a:no"],
        )
        .expect("spawn srt-live-transmit");
        tokio::time::sleep(Duration::from_millis(300)).await; // let it bind

        let opts = SrtOptions::default().passphrase(PASSPHRASE);
        let err = SrtSocket::connect(("127.0.0.1", port), opts)
            .await
            .err()
            .expect("a failure-status KMRSP must abort the connect");
        assert!(
            matches!(err, SrtError::EncryptionUnsupported),
            "expected the local UNSECURE abort on a 1-word NOSECRET KMRSP, got: {err}"
        );
        slt.kill().await.ok();
    })
    .await;
}
