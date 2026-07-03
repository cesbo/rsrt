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
//! Every test skips cleanly (eprintln "SKIP" + return) when the binary is
//! missing, uses unique free ports, enforces a hard 30 s outer timeout, and
//! never leaks the child: `SltProcess` is kill-on-drop and the success paths
//! kill explicitly.

mod support;

use std::{
    future::Future,
    time::Duration,
};

use srt::{
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
