//! Interop matrix against the reference `srt-live-transmit` (libsrt 1.4.4).
//!
//! Four directions, each moving ~1.5 MB of a deterministic byte stream at a
//! modest paced rate (~1.3 MB/s) and asserting byte-stream equality —
//! re-chunking is allowed (slt re-chunks its input at the configured chunk
//! size and pipes merge writes), so equality is checked on the byte stream,
//! not on message boundaries:
//!
//! 1. our caller   <- slt listener   (slt transmits its stdin)
//! 2. our listener <- slt caller     (slt pushes; its streamid must be visible)
//! 3. our caller   -> slt listener   (slt writes what it receives to stdout)
//! 4. our listener -> slt caller     (slt pulls to stdout)
//!
//! Directions 2 and 3 are additionally run with a shared passphrase, pinning
//! the HaiCrypt wire format (docs/spec/encryption.md) against the reference
//! implementation in both the encrypt and decrypt directions.
//!
//! Every test skips cleanly (eprintln "SKIP" + return) when the binary is
//! missing, uses unique free ports, enforces a hard 30 s outer timeout, and
//! never leaks the child: `SltProcess` is kill-on-drop and the success paths
//! kill explicitly.

mod support;

use std::{
    future::Future,
    time::Duration,
};

use rsrt::{
    Bandwidth,
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

/// ~1.5 MB per direction, in slt-sized (1316-byte) messages.
const MESSAGES: usize = 1200;
const TOTAL: usize = MESSAGES * MESSAGE_SIZE;

/// Pace between messages: ~1.3 MB/s — a modest live rate that never
/// overruns latency or flow windows on loopback.
const PACE: Duration = Duration::from_millis(1);

/// slt log level `note` prints connection events; `SltProcess` echoes them
/// with a `[slt <pid>]` prefix — the debugging trail when an assertion fires.
const LOG: &str = "-ll:note";

/// Wraps a test body in the hard outer timeout. On expiry the whole future
/// (sockets, listener, slt child) is dropped, which kills the child.
async fn within_timeout<T>(fut: impl Future<Output = T>) -> T {
    match tokio::time::timeout(TEST_TIMEOUT, fut).await {
        Ok(v) => v,
        Err(_) => panic!("test exceeded the {TEST_TIMEOUT:?} hard timeout"),
    }
}

/// Receives from `sock` until the whole expected stream for `seed` has been
/// verified. Panics on divergence, early end of stream, or a 10 s stall.
async fn recv_and_verify(sock: &mut SrtSocket, seed: u64) {
    let mut verifier = PayloadVerifier::new(seed);
    while (verifier.verified() as usize) < TOTAL {
        match tokio::time::timeout(Duration::from_secs(10), sock.recv()).await {
            Ok(Ok(Some(payload))) => verifier
                .update(&payload)
                .unwrap_or_else(|e| panic!("received stream diverged: {e}")),
            Ok(Ok(None)) => panic!(
                "stream ended early: {} of {TOTAL} bytes",
                verifier.verified()
            ),
            Ok(Err(e)) => panic!("recv failed at byte {}: {e}", verifier.verified()),
            Err(_) => panic!(
                "delivery stalled for 10 s at byte {} of {TOTAL}",
                verifier.verified()
            ),
        }
    }
}

/// Sends the whole stream for `seed` as paced [`MESSAGE_SIZE`] messages.
async fn send_stream(sock: &SrtSocket, seed: u64) {
    let mut generator = PayloadGen::new(seed);
    for i in 0 .. MESSAGES {
        sock.send(&generator.next_message())
            .await
            .unwrap_or_else(|e| panic!("send (message {i}): {e}"));
        tokio::time::sleep(PACE).await;
    }
}

/// Direction 1: srt-live-transmit listens and transmits its stdin; our
/// caller connects and must receive the exact byte stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn caller_receives_from_slt_listener() {
    let binary = require_slt!();
    const SEED: u64 = 0x51A7_0001;
    within_timeout(async {
        let port = free_udp_port().expect("free port");
        // stdin -> srt://:port. `-c:1316` keeps stdin reads within the
        // default SRTO_PAYLOADSIZE even if the pipe coalesces writes.
        let mut slt = SltProcess::spawn_send(
            &binary,
            &listener_uri(port, &["latency=120"]),
            &[LOG, "-c:1316", "-a:no"],
        )
        .expect("spawn srt-live-transmit");
        tokio::time::sleep(Duration::from_millis(300)).await; // let it bind

        let mut sock = SrtSocket::connect(("127.0.0.1", port), SrtOptions::default())
            .await
            .expect("connect to slt listener");
        // slt drops source data while its SRT output has no connection
        // (tiny internal buffering); feed stdin only once it has accepted.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let data = PayloadGen::stream_prefix(SEED, TOTAL);
        let (fed, ()) = tokio::join!(
            slt.feed_stdin(&data, MESSAGE_SIZE, PACE),
            recv_and_verify(&mut sock, SEED),
        );
        fed.expect("feed slt stdin");

        let stats = sock.stats();
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

/// Direction 2: srt-live-transmit calls into our listener and pushes its
/// stdin; the accepted socket must yield the exact byte stream, and the
/// streamid slt sent must be visible.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listener_receives_from_slt_caller() {
    let binary = require_slt!();
    const SEED: u64 = 0x51A7_0002;
    const STREAMID: &str = "interop-listener-recv";
    within_timeout(async {
        let mut listener = SrtListener::bind("127.0.0.1:0", SrtOptions::default())
            .await
            .expect("bind listener");
        let port = listener.local_addr().port();

        let sid_param = format!("streamid={STREAMID}");
        let mut slt = SltProcess::spawn_send(
            &binary,
            &caller_uri(port, &["latency=120", &sid_param]),
            &[LOG, "-c:1316", "-a:no"],
        )
        .expect("spawn srt-live-transmit");

        let (mut sock, _peer) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("slt caller never connected")
            .expect("accept");
        assert_eq!(
            sock.streamid().as_deref(),
            Some(STREAMID),
            "streamid sent by slt must be visible on the accepted socket"
        );
        // Our listener is established on sending the conclusion response;
        // give slt a moment to process it before data flows.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let data = PayloadGen::stream_prefix(SEED, TOTAL);
        let (fed, ()) = tokio::join!(
            slt.feed_stdin(&data, MESSAGE_SIZE, PACE),
            recv_and_verify(&mut sock, SEED),
        );
        fed.expect("feed slt stdin");

        let stats = sock.stats();
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

/// Direction 3: our caller connects to an srt-live-transmit listener that
/// writes everything it receives to stdout; stdout must equal our stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn caller_sends_to_slt_listener() {
    let binary = require_slt!();
    const SEED: u64 = 0x51A7_0003;
    within_timeout(async {
        let port = free_udp_port().expect("free port");
        // srt://:port -> stdout.
        let mut slt = SltProcess::spawn_receive(
            &binary,
            &listener_uri(port, &["latency=120"]),
            &[LOG, "-a:no"],
        )
        .expect("spawn srt-live-transmit");
        tokio::time::sleep(Duration::from_millis(300)).await; // let it bind

        let sock = SrtSocket::connect(("127.0.0.1", port), SrtOptions::default())
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
                send_stream(&sock, SEED).await;
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
        verify_prefix(SEED, &out).unwrap_or_else(|e| panic!("slt output diverged: {e}"));

        assert_eq!(
            stats.pkts_send_dropped, 0,
            "sender dropped packets on a loss-free path: {stats:?}"
        );
        assert!(stats.pkts_sent as usize >= MESSAGES, "{stats:?}");
        slt.kill().await.ok();
    })
    .await;
}

/// Direction 4: srt-live-transmit calls into our listener and writes what it
/// pulls to stdout; stdout must equal the stream our accepted socket sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listener_sends_to_slt_caller() {
    let binary = require_slt!();
    const SEED: u64 = 0x51A7_0004;
    within_timeout(async {
        let mut listener = SrtListener::bind("127.0.0.1:0", SrtOptions::default())
            .await
            .expect("bind listener");
        let port = listener.local_addr().port();

        let mut slt = SltProcess::spawn_receive(
            &binary,
            &caller_uri(port, &["latency=120"]),
            &[LOG, "-a:no"],
        )
        .expect("spawn srt-live-transmit");

        let (sock, _peer) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("slt caller never connected")
            .expect("accept");
        // Let slt process the conclusion response before data flows.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Same shape as direction 3: collect concurrently, then close our
        // socket so slt exits and flushes its block-buffered stdout tail.
        let (out, stats) =
            tokio::join!(slt.collect_stdout(TOTAL, Duration::from_secs(25)), async {
                send_stream(&sock, SEED).await;
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
        verify_prefix(SEED, &out).unwrap_or_else(|e| panic!("slt output diverged: {e}"));

        assert_eq!(
            stats.pkts_send_dropped, 0,
            "sender dropped packets on a loss-free path: {stats:?}"
        );
        assert!(stats.pkts_sent as usize >= MESSAGES, "{stats:?}");
        slt.kill().await.ok();
    })
    .await;
}

/// Pacing interop, `Bandwidth::Estimated` — the SRTO_OHEADBW configuration
/// (docs/spec/transmission.md §3.3.2): our paced caller sends the full
/// stream to a real libsrt 1.4.4 receiver. Byte equality proves the paced
/// stream (probe pairs included) keeps the reference TSBPD/ACK machinery
/// happy, and the settled gauges pin the estimator: the ceiling must be
/// exactly withOverhead(measured input rate), with the measured rate in a
/// generous band around the ~1.3 MB/s send pace (per suite policy wall
/// clock is a hang detector, never a tight rate assertion — the band only
/// proves a real §3.3.3 window closed).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn paced_caller_delivers_everything_to_slt() {
    let binary = require_slt!();
    const SEED: u64 = 0x51A7_0007;
    within_timeout(async {
        let port = free_udp_port().expect("free port");
        // srt://:port -> stdout.
        let mut slt = SltProcess::spawn_receive(
            &binary,
            &listener_uri(port, &["latency=120"]),
            &[LOG, "-a:no"],
        )
        .expect("spawn srt-live-transmit");
        tokio::time::sleep(Duration::from_millis(300)).await; // let it bind

        let opts = SrtOptions::default().bandwidth(Bandwidth::Estimated {
            min_bytes_per_sec: 0,
            overhead_pct: 25,
        });
        let sock = SrtSocket::connect(("127.0.0.1", port), opts)
            .await
            .expect("connect to slt listener");
        tokio::time::sleep(Duration::from_millis(200)).await; // slt sees the accept

        // Same shape as direction 3: collect concurrently, then close our
        // socket so slt exits and flushes its block-buffered stdout tail.
        let (out, stats) =
            tokio::join!(slt.collect_stdout(TOTAL, Duration::from_secs(25)), async {
                send_stream(&sock, SEED).await;
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
        verify_prefix(SEED, &out).unwrap_or_else(|e| panic!("slt output diverged: {e}"));

        assert_eq!(
            stats.pkts_send_dropped, 0,
            "the ceiling has 25% headroom over the input; nothing may drop: {stats:?}"
        );
        // The nominal feed is 1316 B/ms = 1_360_000 B/s with headers; the
        // wide lower bound only tolerates scheduler starvation slowing the
        // pace, and both bounds together prove the estimate is neither 0
        // (never measured) nor BW_INFINITE (stuck in fast-start grace).
        assert!(
            (200_000 ..= 2_000_000).contains(&stats.snd_input_rate),
            "measured input rate outside the loose ~1.36 MB/s band: {stats:?}"
        );
        assert_eq!(
            stats.snd_max_bw,
            stats.snd_input_rate * 125 / 100,
            "SRTO_OHEADBW parity: ceiling = measured·(100+25)/100: {stats:?}"
        );
        assert!(stats.snd_period_us > 0, "pacing must be engaged: {stats:?}");
        slt.kill().await.ok();
    })
    .await;
}

/// Pacing interop, `Bandwidth::Max` far below the offered rate: 600
/// messages (816_000 wire bytes) through a 680_000 B/s ceiling have a firm
/// ~1.13 s wire-time floor (500 paced slots/s plus one free probe slot per
/// 16 packets, transmission.md §3.3.4), while the unpaced handover takes
/// ~0.6 s — finishing under 1 s proves pacing never engaged. Per suite
/// policy the wall-clock bound is a generous lower bound only; the
/// functional assert is eventual byte equality through slt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn low_maxbw_engages_pacing() {
    let binary = require_slt!();
    const SEED: u64 = 0x51A7_0008;
    // ~790 KB: sized so the paced run finishes well inside the budget.
    const N: usize = 600;
    const BYTES: usize = N * MESSAGE_SIZE;
    within_timeout(async {
        let port = free_udp_port().expect("free port");
        // 1 s latency on both sides: the backlog behind the ceiling peaks
        // at ~0.6 s of send lag, which must stay inside both the TSBPD
        // budget and the sender TLPKTDROP threshold — the ceiling
        // throttles, the too-late valves must never fire.
        let mut slt = SltProcess::spawn_receive(
            &binary,
            &listener_uri(port, &["latency=1000"]),
            &[LOG, "-a:no"],
        )
        .expect("spawn srt-live-transmit");
        tokio::time::sleep(Duration::from_millis(300)).await; // let it bind

        let opts = SrtOptions::default()
            .latency(Duration::from_millis(1_000))
            .bandwidth(Bandwidth::Max { bytes_per_sec: 680_000 });
        let sock = SrtSocket::connect(("127.0.0.1", port), opts)
            .await
            .expect("connect to slt listener");
        tokio::time::sleep(Duration::from_millis(200)).await; // slt sees the accept

        // Same shape as direction 3: collect concurrently, then close our
        // socket so slt exits and flushes its block-buffered stdout tail.
        let (out, stats) =
            tokio::join!(slt.collect_stdout(BYTES, Duration::from_secs(25)), async {
                let started = std::time::Instant::now();
                let mut generator = PayloadGen::new(SEED);
                for i in 0 .. N {
                    sock.send(&generator.next_message())
                        .await
                        .unwrap_or_else(|e| panic!("send (message {i}): {e}"));
                    tokio::time::sleep(PACE).await;
                }
                // The handover above is ~2× the ceiling; the wire cannot
                // keep up, so wait until the paced sender emitted it all.
                while (sock.stats().pkts_sent as usize) < N {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                let elapsed = started.elapsed();
                assert!(
                    elapsed >= Duration::from_secs(1),
                    "600×1360 wire bytes cannot pass a 680_000 B/s ceiling \
                     in {elapsed:?} — pacing did not engage"
                );
                // Outlive the 1 s TSBPD latency before closing: slt
                // discards its still-queued tail on disconnect.
                tokio::time::sleep(Duration::from_millis(1_500)).await;
                let stats = sock.stats();
                sock.close().await.expect("close");
                stats
            },);
        let out = out.expect("collect slt stdout");
        assert_eq!(
            out.len(),
            BYTES,
            "slt wrote {} of {BYTES} bytes (data lost sender->slt); slt stderr: {:?}",
            out.len(),
            slt.drain_stderr(),
        );
        verify_prefix(SEED, &out).unwrap_or_else(|e| panic!("slt output diverged: {e}"));

        assert_eq!(
            stats.pkts_send_dropped, 0,
            "the ceiling must throttle without tripping TLPKTDROP: {stats:?}"
        );
        assert_eq!(stats.snd_max_bw, 680_000, "{stats:?}");
        assert_eq!(
            stats.snd_period_us, 2_000,
            "period = trunc(1e6·(1316+44)/680_000): {stats:?}"
        );
        assert_eq!(
            stats.snd_input_rate, 0,
            "Max mode never runs the estimator: {stats:?}"
        );
        slt.kill().await.ok();
    })
    .await;
}

/// Shared secret for the encrypted directions below.
const PASSPHRASE: &str = "interop 5uP3r-secret";

/// Encrypted direction 2: slt calls into our listener with a passphrase and
/// pushes its stdin; our listener must run the §6 handshake KMX against a
/// real libsrt 1.4.4 KMREQ (KEK derivation, AES keywrap unwrap, KMRSP echo)
/// and then decrypt real HaiCrypt AES-CTR ciphertext byte-for-byte
/// (docs/spec/encryption.md §9.2) — the RX half of the wire format that a
/// same-stack loopback cannot pin down (symmetric bugs cancel out).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encrypted_listener_receives_from_slt_caller() {
    let binary = require_slt!();
    const SEED: u64 = 0x51A7_0005;
    within_timeout(async {
        let opts = SrtOptions::default().passphrase(PASSPHRASE);
        let mut listener = SrtListener::bind("127.0.0.1:0", opts)
            .await
            .expect("bind listener");
        let port = listener.local_addr().port();

        let pw_param = format!("passphrase={PASSPHRASE}");
        let mut slt = SltProcess::spawn_send(
            &binary,
            &caller_uri(port, &["latency=120", &pw_param, "pbkeylen=16"]),
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

        let data = PayloadGen::stream_prefix(SEED, TOTAL);
        let (fed, ()) = tokio::join!(
            slt.feed_stdin(&data, MESSAGE_SIZE, PACE),
            recv_and_verify(&mut sock, SEED),
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

/// Encrypted direction 3: our caller connects to an slt listener with the
/// same passphrase and sends; slt's stdout must equal our stream, proving
/// real libsrt accepts our KMREQ (docs/spec/encryption.md §5/§6) and
/// decrypts our AES-CTR ciphertext — the TX half of the wire format.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encrypted_caller_sends_to_slt_listener() {
    let binary = require_slt!();
    const SEED: u64 = 0x51A7_0006;
    within_timeout(async {
        let port = free_udp_port().expect("free port");
        let pw_param = format!("passphrase={PASSPHRASE}");
        // srt://:port -> stdout.
        let mut slt = SltProcess::spawn_receive(
            &binary,
            &listener_uri(port, &["latency=120", &pw_param]),
            &[LOG, "-a:no"],
        )
        .expect("spawn srt-live-transmit");
        tokio::time::sleep(Duration::from_millis(300)).await; // let it bind

        let opts = SrtOptions::default().passphrase(PASSPHRASE);
        let sock = SrtSocket::connect(("127.0.0.1", port), opts)
            .await
            .expect("connect to slt listener");
        tokio::time::sleep(Duration::from_millis(200)).await; // slt sees the accept

        // Same shape as direction 3: collect concurrently, then close our
        // socket so slt exits and flushes its block-buffered stdout tail.
        let (out, stats) =
            tokio::join!(slt.collect_stdout(TOTAL, Duration::from_secs(25)), async {
                send_stream(&sock, SEED).await;
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
        verify_prefix(SEED, &out).unwrap_or_else(|e| panic!("slt output diverged: {e}"));

        assert_eq!(
            stats.pkts_send_dropped, 0,
            "sender dropped packets on a loss-free path: {stats:?}"
        );
        assert!(stats.pkts_sent as usize >= MESSAGES, "{stats:?}");
        slt.kill().await.ok();
    })
    .await;
}
