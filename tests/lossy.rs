//! Full-stack ARQ proof: our caller ↔ lossy UDP proxy ↔ our listener.
//!
//! The proxy (tests/support/proxy.rs) injects deterministic, seeded loss in
//! BOTH directions — data packets forward, ACK/NAK control backward — so
//! these tests exercise retransmission end to end:
//!
//! - moderate loss (3% drops + reordering): every byte must arrive intact, the sender must show
//!   retransmissions, the receiver zero skipped packets;
//! - heavy burst loss (~15%, bursts of 4): drops are tolerated (TLPKTDROP is correct live-mode
//!   behavior) but the stream must keep flowing, deliver a strict majority in order and intact, and
//!   never stall or panic.

mod support;

use std::{
    future::Future,
    net::SocketAddr,
    time::Duration,
};

use rsrt::{
    SrtListener,
    SrtOptions,
    SrtSocket,
    Stats,
};
use support::{
    DirectionBehavior,
    LossyProxy,
    PayloadGen,
    PayloadVerifier,
    ProxyBehavior,
    MESSAGE_SIZE,
};

/// Hard per-test budget.
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

/// ~1 MB in 1316-byte messages.
const MESSAGES: usize = 800;
const TOTAL: usize = MESSAGES * MESSAGE_SIZE;

/// Pace between messages: ~1.3 MB/s.
const PACE: Duration = Duration::from_millis(1);

async fn within_timeout<T>(fut: impl Future<Output = T>) -> T {
    match tokio::time::timeout(TEST_TIMEOUT, fut).await {
        Ok(v) => v,
        Err(_) => panic!("test exceeded the {TEST_TIMEOUT:?} hard timeout"),
    }
}

/// Establishes caller → proxy → listener with the given wire behavior.
/// The handshake itself runs through the lossy path (the FSM's 250 ms
/// retransmits must cope).
async fn lossy_pair(
    behavior: ProxyBehavior,
    proxy_seed: u64,
    opts: SrtOptions,
) -> (SrtSocket, SrtSocket, LossyProxy, SrtListener) {
    let mut listener = SrtListener::bind("127.0.0.1:0", opts.clone())
        .await
        .expect("bind listener");
    let proxy = LossyProxy::spawn(SocketAddr::V4(listener.local_addr()), behavior, proxy_seed)
        .await
        .expect("spawn lossy proxy");
    let (caller, accepted) = tokio::join!(
        SrtSocket::connect(proxy.local_addr(), opts),
        listener.accept(),
    );
    let caller = caller.expect("connect through lossy proxy");
    let (accepted, _peer) = accepted.expect("accept");
    (caller, accepted, proxy, listener)
}

/// Sends the whole stream paced, lets the tail NAK/retransmit rounds finish,
/// snapshots the sender stats, then closes. Returns the stats.
async fn send_all(caller: SrtSocket, seed: u64, settle: Duration) -> Stats {
    let mut generator = PayloadGen::new(seed);
    for i in 0 .. MESSAGES {
        caller
            .send(&generator.next_message())
            .await
            .unwrap_or_else(|e| panic!("send (message {i}): {e}"));
        tokio::time::sleep(PACE).await;
    }
    tokio::time::sleep(settle).await;
    let stats = caller.stats();
    caller.close().await.expect("caller close");
    stats
}

/// 3% drops + 5% reordering, both directions: ARQ must recover everything —
/// full byte equality, retransmissions > 0, zero receiver-side drops.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn arq_recovers_3_percent_loss_with_reorder() {
    const SEED: u64 = 0x1055_0001;
    within_timeout(async {
        let behavior = ProxyBehavior::symmetric(
            DirectionBehavior::passthrough()
                .with_drop(0.03)
                .with_reorder(0.05),
        );
        // 200 ms latency: dozens of NAK rounds fit before TSBPD deadline on
        // a sub-millisecond-RTT path; hold_flush (50 ms) stays well below.
        let opts = SrtOptions::default().latency(Duration::from_millis(200));
        let (caller, mut accepted, proxy, _listener) =
            lossy_pair(behavior, 0xD5EE_D400, opts).await;

        let sender = tokio::spawn(send_all(caller, SEED, Duration::from_millis(800)));

        let mut verifier = PayloadVerifier::new(SEED);
        while (verifier.verified() as usize) < TOTAL {
            match tokio::time::timeout(Duration::from_secs(10), accepted.recv()).await {
                Ok(Ok(Some(payload))) => verifier
                    .update(&payload)
                    .unwrap_or_else(|e| panic!("ARQ failed to recover the stream: {e}")),
                Ok(Ok(None)) => break,
                Ok(Err(e)) => panic!("recv failed at byte {}: {e}", verifier.verified()),
                Err(_) => panic!(
                    "delivery stalled for 10 s at byte {} of {TOTAL}",
                    verifier.verified()
                ),
            }
        }
        assert_eq!(
            verifier.verified() as usize,
            TOTAL,
            "stream ended before all bytes were recovered"
        );

        let send_stats = sender.await.expect("sender task");
        let recv_stats = accepted.stats();
        let wire = proxy.stats();
        eprintln!("3% loss run: sender {send_stats:?}, receiver {recv_stats:?}, wire {wire:?}");
        assert!(
            wire.client_to_upstream.dropped > 0,
            "proxy dropped nothing in the data direction; the test proved nothing: {wire:?}"
        );
        assert!(
            send_stats.pkts_retransmitted > 0,
            "no retransmissions although the proxy dropped {} caller->listener datagrams",
            wire.client_to_upstream.dropped
        );
        assert_eq!(
            recv_stats.pkts_recv_dropped, 0,
            "receiver skipped packets despite recoverable loss: {recv_stats:?}"
        );
        proxy.shutdown().await;
    })
    .await;
}

/// ~15% loss in bursts of 4 datagrams, both directions: drops are allowed,
/// but the connection must keep flowing (no stall, no panic) and deliver a
/// strict majority of the messages, in order and intact.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn heavy_burst_loss_degrades_gracefully() {
    const SEED: u64 = 0x1055_0002;
    within_timeout(async {
        // 4.3% trigger × 4-datagram bursts ≈ 15% effective loss.
        let behavior = ProxyBehavior::symmetric(
            DirectionBehavior::passthrough()
                .with_drop(0.043)
                .with_drop_burst(4),
        );
        // Generous latency (recovery headroom) and connect timeout (the
        // handshake itself fights the 15% loss).
        let opts = SrtOptions::default()
            .latency(Duration::from_millis(500))
            .connect_timeout(Duration::from_secs(10));
        let (caller, mut accepted, proxy, _listener) =
            lossy_pair(behavior, 0xD5EE_DB57, opts).await;

        let expected: Vec<Vec<u8>> = {
            let mut generator = PayloadGen::new(SEED);
            (0 .. MESSAGES).map(|_| generator.next_message()).collect()
        };

        let sender = tokio::spawn(send_all(caller, SEED, Duration::from_millis(1500)));

        // Live-mode delivery under unrecoverable loss skips messages but
        // never corrupts or reorders: each delivered payload must match the
        // next unconsumed expected message (gaps allowed).
        let mut delivered = 0usize;
        let mut next_idx = 0usize;
        loop {
            if next_idx == MESSAGES {
                break; // everything up to the last message accounted for
            }
            // 8 s per-recv budget: even a lost SHUTDOWN surfaces as a
            // peer-idle close (~5 s); silence beyond that is a stall.
            match tokio::time::timeout(Duration::from_secs(8), accepted.recv()).await {
                Ok(Ok(Some(payload))) => {
                    let pos = expected[next_idx ..]
                        .iter()
                        .position(|m| *m == payload)
                        .unwrap_or_else(|| {
                            panic!(
                                "delivered message #{delivered} (len {}) is corrupted, \
                                 duplicated or out of order",
                                payload.len()
                            )
                        });
                    next_idx += pos + 1;
                    delivered += 1;
                }
                Ok(Ok(None)) => break, // clean SHUTDOWN
                Ok(Err(e)) => {
                    // e.g. peer-idle after the SHUTDOWN packet itself was
                    // dropped — an acceptable ending under heavy loss.
                    eprintln!("receiver closed uncleanly (tolerated): {e}");
                    break;
                }
                Err(_) => panic!(
                    "receiver stalled for 8 s (delivered {delivered} of {MESSAGES} messages)"
                ),
            }
        }

        let send_stats = sender.await.expect("sender task");
        let recv_stats = accepted.stats();
        let wire = proxy.stats();
        eprintln!(
            "burst-loss run: delivered {delivered}/{MESSAGES} messages, \
             sender {send_stats:?}, receiver {recv_stats:?}, wire {wire:?}"
        );
        assert!(
            wire.client_to_upstream.dropped > 0 && wire.upstream_to_client.dropped > 0,
            "proxy dropped nothing; the test proved nothing: {wire:?}"
        );
        assert!(
            delivered * 2 > MESSAGES,
            "strict majority not delivered: {delivered} of {MESSAGES}"
        );
        assert!(
            send_stats.pkts_retransmitted > 0,
            "no retransmissions under ~15% loss"
        );
        proxy.shutdown().await;
    })
    .await;
}
