//! Full-stack encrypted ARQ + key-refresh proof: our caller ↔ lossy UDP
//! proxy ↔ our listener, passphrase on both ends — the encrypted
//! counterpart of `tests/lossy.rs`.
//!
//! The proxy (tests/support/proxy.rs) injects deterministic, seeded loss in
//! BOTH directions, so data, ACK/NAK control AND the in-stream KMREQ/KMRSP
//! refresh exchange (docs/spec/encryption.md §11) all fight the same wire.
//! `km_refresh_rate = 96` / `km_preannounce = 47` squeeze many complete
//! refresh cycles (§10.1) into an 800-message stream:
//!
//! - 15% random loss, both directions: every byte must arrive intact — ARQ recovers all data loss
//!   while the 1.5 × SRTT KMREQ retries (§11.2) win every pre-announce window, so not one packet is
//!   lost to an unknown key;
//! - ~25% burst loss (trigger 8%, bursts of 4): drops are tolerated (TLPKTDROP is correct live-mode
//!   behavior, and a refresh KM can genuinely lose its race under this much loss) but the stream
//!   must keep flowing through many key switches — no deadlock, no stall, no corruption, a strict
//!   majority delivered in order.

mod support;

use std::{
    future::Future,
    net::SocketAddr,
    time::Duration,
};

use srt::{
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

/// ~1 MB in 1316-byte messages — one data packet each, so the stream
/// crosses the 96-packet refresh threshold ~8 times.
const MESSAGES: usize = 800;
const TOTAL: usize = MESSAGES * MESSAGE_SIZE;

/// Trailing traffic so a lost tail packet still gets its gap detected
/// (loss is only revealed by a later arrival): the generator stream simply
/// continues past `MESSAGES`; the assertions only cover the first
/// `MESSAGES`. P(all 8 lost) is negligible even for 4-datagram bursts.
const TAIL_MESSAGES: usize = 8;

/// Pace between messages. 8 ms keeps the 47-packet pre-announce window
/// (§10.1) at ~376 ms of wall time. That number is load-bearing:
///
/// - The sender switches SEKs at RR *whether or not* the refresh KMREQ
///   was ever received (§11.2), and from the second refresh on the
///   receiver's slot still holds the two-generations-old key — AES-CTR
///   has no integrity check, so a switch that outruns every KMREQ
///   delivers GARBAGE, not a drop (§9.4, §15; libsrt is identical).
/// - KMREQ (re)sends happen on the ACK path ONLY (§10.2, §11.2), and a
///   pinned loss hole freezes ACKs entirely (duplicate-ACK suppression
///   after ACKACK — libsrt sendCtrlAck is the same). The longest
///   plausible freeze is one initial-NAK-interval repair round: 300 ms
///   (the pre-first-RTT-sample NAK timer, transmission.md §7). A window
///   shorter than that can compress pre-announce → switch into two
///   consecutive ACK ticks, leaving ONE loss-exposed KMREQ attempt —
///   observed as a few-percent corruption flake at 3 ms pace.
///
/// At 376 ms the window survives a full 300 ms freeze with several paced
/// attempts to spare, and otherwise fits the whole 11-send retry budget
/// (~1.5×SRTT apart, §11.2): P(receiver misses a switch) ≈ loss^11.
/// Do not shrink the window (PACE × km_preannounce) below ~350 ms.
const PACE: Duration = Duration::from_millis(8);

/// Passphrase for both ends (10..=80 bytes, encryption.md §2). Only ever
/// passed through options — never logged, never asserted on.
const PASSPHRASE: &str = "correct horse battery staple";

/// Encrypted options with the fast refresh cycle under test. The latency
/// is the ARQ recovery budget: NAK rounds repeat every ≥ 20 ms, so a few
/// hundred ms buys dozens of rounds on a sub-millisecond-RTT path.
fn crypto_opts(latency: Duration) -> SrtOptions {
    SrtOptions {
        passphrase: Some(PASSPHRASE.to_string().into()),
        km_refresh_rate: Some(96),
        // The maximum legal window for RR = 96 ((RR − 1) / 2): see PACE.
        km_preannounce: Some(47),
        latency,
        // The handshake itself fights the loss; the default 3 s can lose
        // the race against an unlucky drop pattern.
        connect_timeout: Duration::from_secs(10),
        ..SrtOptions::default()
    }
}

async fn within_timeout<T>(fut: impl Future<Output = T>) -> T {
    match tokio::time::timeout(TEST_TIMEOUT, fut).await {
        Ok(v) => v,
        Err(_) => panic!("test exceeded the {TEST_TIMEOUT:?} hard timeout"),
    }
}

/// Establishes caller → proxy → listener with the given wire behavior.
/// The handshake — including the CONCLUSION-carried KMX (encryption.md §6)
/// — runs through the lossy path; its 250 ms retransmits must cope.
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

/// Sends the whole stream (plus the gap-revealing tail) paced, lets the
/// trailing NAK/retransmit rounds finish, snapshots the sender stats, then
/// closes. Returns the stats.
async fn send_all(caller: SrtSocket, seed: u64, settle: Duration) -> Stats {
    let mut generator = PayloadGen::new(seed);
    for i in 0 .. MESSAGES + TAIL_MESSAGES {
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

/// 15% random loss in both directions across ~8 key-refresh cycles: ARQ
/// plus the §11.2 KMREQ retries must recover *everything* — full byte
/// equality, several completed refreshes, zero receiver-side drops and
/// zero undecryptable packets.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refresh_under_15_percent_loss_delivers_everything() {
    const SEED: u64 = 0x10E5_0001;
    within_timeout(async {
        let behavior =
            ProxyBehavior::symmetric(DirectionBehavior::passthrough().with_drop(0.15));
        // 600 ms latency: ~30 NAK rounds fit before any TSBPD deadline on
        // a sub-millisecond-RTT path — 15% loss cannot outlast that.
        let opts = crypto_opts(Duration::from_millis(600));
        let (caller, mut accepted, proxy, _listener) =
            lossy_pair(behavior, 0xD5EE_DEC1, opts).await;

        let sender = tokio::spawn(send_all(caller, SEED, Duration::from_millis(2000)));

        let mut verifier = PayloadVerifier::new(SEED);
        while (verifier.verified() as usize) < TOTAL {
            match tokio::time::timeout(Duration::from_secs(10), accepted.recv()).await {
                Ok(Ok(Some(payload))) => verifier.update(&payload).unwrap_or_else(|e| {
                    panic!("stream not recovered byte-perfect (lost to ARQ or to a key switch): {e}")
                }),
                Ok(Ok(None)) => break,
                Ok(Err(e)) => panic!("recv failed at byte {}: {e}", verifier.verified()),
                Err(_) => panic!(
                    "delivery stalled for 10 s at byte {} of {TOTAL}",
                    verifier.verified()
                ),
            }
        }
        let send_stats = sender.await.expect("sender task");
        let recv_stats = accepted.stats();
        let wire = proxy.stats();
        eprintln!("15% loss run: sender {send_stats:?}, receiver {recv_stats:?}, wire {wire:?}");
        assert_eq!(
            verifier.verified() as usize,
            TOTAL,
            "stream ended before all bytes were recovered: \
             sender {send_stats:?}, receiver {recv_stats:?}"
        );
        assert!(
            wire.client_to_upstream.dropped > 0 && wire.upstream_to_client.dropped > 0,
            "proxy dropped nothing; the test proved nothing: {wire:?}"
        );
        assert!(
            send_stats.pkts_retransmitted > 0,
            "no retransmissions under 15% loss"
        );
        // The refresh machinery really cycled under loss (§10.1: a switch
        // every 96 first transmissions; ACK-gating may defer the tail).
        assert!(
            send_stats.km_refreshes >= 6,
            "expected ~8 key switches over {MESSAGES} packets, got {}",
            send_stats.km_refreshes
        );
        // Byte-perfect delivery already implies both, but keep the crypto
        // diagnostics explicit: no packet ever hit a missing key.
        assert_eq!(
            recv_stats.undecrypted_pkts, 0,
            "a refresh KM lost its race with the key switch: {recv_stats:?}"
        );
        assert_eq!(
            recv_stats.pkts_recv_dropped, 0,
            "receiver skipped packets despite recoverable loss: {recv_stats:?}"
        );
        proxy.shutdown().await;
    })
    .await;
}

/// ~25% loss in bursts of 4 datagrams, both directions, with the same fast
/// refresh cycle: drops are allowed, but the connection must keep flowing
/// through the key switches — no deadlock, no stall, no corruption — and
/// deliver a strict majority of the messages, in order and intact.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn burst_loss_25_percent_with_refresh_never_deadlocks() {
    const SEED: u64 = 0x10E5_0002;
    within_timeout(async {
        // 8% trigger × 4-datagram bursts ≈ 4p/(1+3p) ≈ 26% effective loss.
        let behavior = ProxyBehavior::symmetric(
            DirectionBehavior::passthrough()
                .with_drop(0.08)
                .with_drop_burst(4),
        );
        // Generous latency: recovery headroom for whole lost bursts.
        let opts = crypto_opts(Duration::from_millis(800));
        let (caller, mut accepted, proxy, _listener) =
            lossy_pair(behavior, 0xD5EE_DEC2, opts).await;

        let expected: Vec<Vec<u8>> = {
            let mut generator = PayloadGen::new(SEED);
            (0 .. MESSAGES + TAIL_MESSAGES)
                .map(|_| generator.next_message())
                .collect()
        };

        let sender = tokio::spawn(send_all(caller, SEED, Duration::from_millis(2000)));

        // Live-mode delivery under unrecoverable loss skips messages but
        // never corrupts or reorders — and an undecryptable packet is
        // freed, never delivered (encryption.md §9.4), so every payload
        // that does arrive must match the next unconsumed expected
        // message (gaps allowed).
        let mut delivered = 0usize;
        let mut next_idx = 0usize;
        loop {
            if next_idx >= MESSAGES {
                break; // everything up to the last real message accounted for
            }
            // 8 s per-recv budget: even a lost SHUTDOWN surfaces as a
            // peer-idle close (~5 s); silence beyond that is a stall.
            match tokio::time::timeout(Duration::from_secs(8), accepted.recv()).await {
                Ok(Ok(Some(payload))) => {
                    let pos = expected[next_idx ..]
                        .iter()
                        .position(|m| *m == payload)
                        .unwrap_or_else(|| {
                            let anywhere = expected.iter().position(|m| *m == payload);
                            panic!(
                                "delivered message #{delivered} (len {}) is corrupted, \
                                 duplicated or out of order; next_idx={next_idx} \
                                 matches_expected_idx={anywhere:?}",
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
                    "receiver stalled for 8 s (delivered {delivered} of {MESSAGES} messages) — \
                     possible refresh deadlock"
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
        // The stream survived multiple key switches under burst loss: the
        // sender rotated its SEK (§10.1) and kept delivering afterwards.
        assert!(
            send_stats.km_refreshes >= 4,
            "refresh machine stalled under burst loss: {} switches",
            send_stats.km_refreshes
        );
        assert!(
            delivered * 2 > MESSAGES,
            "strict majority not delivered: {delivered} of {MESSAGES}"
        );
        assert!(
            send_stats.pkts_retransmitted > 0,
            "no retransmissions under ~25% burst loss"
        );
        proxy.shutdown().await;
    })
    .await;
}
