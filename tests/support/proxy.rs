//! Lossy UDP proxy for exercising ARQ under deterministic packet loss.
//!
//! Topology: `client <-> proxy(local port) <-> upstream (fixed addr)`.
//!
//! The proxy owns two sockets: a *front* socket on a local port (give its
//! address to the client / caller side) and a *back* socket connected to the
//! fixed upstream address (point the listener side there). The client is
//! learned from the first datagram hitting the front socket — a single-client
//! proxy, which is all SRT tests need.
//!
//! Each direction independently applies, per datagram and in this order:
//! 1. **drop** with probability `drop_probability` (a hit also discards the next `drop_burst − 1`
//!    datagrams unconditionally — burst loss);
//! 2. **reorder-hold** with probability `reorder_probability` (only if no datagram is already
//!    held): the datagram is parked and released right *after* the next forwarded datagram in the
//!    same direction, or after `hold_flush` if the direction goes quiet, whichever comes first;
//! 3. **forward**, plus a **duplicate** copy with probability `duplicate_probability`.
//!
//! All decisions come from per-direction [`SplitMix64`] generators derived
//! from a single seed, so a given `(seed, behavior, input order)` always
//! yields the same loss pattern. Counters are exact: every input datagram is
//! either counted `forwarded` (when actually sent, including released held
//! ones) or `dropped`; `duplicated` counts the extra copies only.

use std::{
    net::SocketAddr,
    sync::{
        atomic::{
            AtomicU64,
            Ordering,
        },
        Arc,
    },
    time::Duration,
};

use tokio::{
    net::UdpSocket,
    sync::oneshot,
    time::Instant,
};

use super::rng::SplitMix64;

/// Per-direction misbehavior knobs. All probabilities in `[0.0, 1.0]`;
/// the default is a clean pass-through.
#[derive(Clone, Copy, Debug, Default)]
pub struct DirectionBehavior {
    pub drop_probability: f64,
    pub duplicate_probability: f64,
    pub reorder_probability: f64,
    /// Total datagrams discarded per drop-roll hit: the rolled datagram plus
    /// `drop_burst − 1` followers (dropped unconditionally, no PRNG draws).
    /// `0` and `1` both mean single-datagram drops.
    pub drop_burst: u32,
}

impl DirectionBehavior {
    /// Forward everything untouched.
    pub fn passthrough() -> Self {
        Self::default()
    }

    pub fn with_drop(mut self, p: f64) -> Self {
        self.drop_probability = p;
        self
    }

    pub fn with_duplicate(mut self, p: f64) -> Self {
        self.duplicate_probability = p;
        self
    }

    pub fn with_reorder(mut self, p: f64) -> Self {
        self.reorder_probability = p;
        self
    }

    /// Every drop-roll hit discards `burst` datagrams in total (burst loss).
    pub fn with_drop_burst(mut self, burst: u32) -> Self {
        self.drop_burst = burst;
        self
    }
}

/// Full proxy configuration.
#[derive(Clone, Copy, Debug)]
pub struct ProxyBehavior {
    pub client_to_upstream: DirectionBehavior,
    pub upstream_to_client: DirectionBehavior,
    /// How long a reorder-held datagram may wait for a successor before it is
    /// released anyway. Keep well below the SRT latency so a flushed hold
    /// still arrives "reordered but on time".
    pub hold_flush: Duration,
}

impl Default for ProxyBehavior {
    fn default() -> Self {
        ProxyBehavior {
            client_to_upstream: DirectionBehavior::passthrough(),
            upstream_to_client: DirectionBehavior::passthrough(),
            hold_flush: Duration::from_millis(50),
        }
    }
}

impl ProxyBehavior {
    /// Same behavior in both directions.
    pub fn symmetric(dir: DirectionBehavior) -> Self {
        ProxyBehavior {
            client_to_upstream: dir,
            upstream_to_client: dir,
            ..Self::default()
        }
    }
}

/// Snapshot of one direction's counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DirectionStats {
    /// Input datagrams actually sent onward (held ones count on release).
    pub forwarded: u64,
    /// Input datagrams discarded by the drop roll.
    pub dropped: u64,
    /// Extra copies sent by the duplicate roll (not included in `forwarded`).
    pub duplicated: u64,
}

/// Snapshot of both directions' counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProxyStats {
    pub client_to_upstream: DirectionStats,
    pub upstream_to_client: DirectionStats,
}

#[derive(Default)]
struct DirectionCounters {
    forwarded: AtomicU64,
    dropped: AtomicU64,
    duplicated: AtomicU64,
}

impl DirectionCounters {
    fn snapshot(&self) -> DirectionStats {
        DirectionStats {
            forwarded: self.forwarded.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            duplicated: self.duplicated.load(Ordering::Relaxed),
        }
    }
}

/// Deterministic per-direction pipeline: pure decision logic, no I/O.
/// Factored out so drop/duplicate/reorder rules are unit-testable.
struct Shaper {
    behavior: DirectionBehavior,
    rng: SplitMix64,
    held: Option<Vec<u8>>,
    /// Remaining datagrams of a drop burst still owed (`drop_burst`).
    burst_left: u32,
    counters: Arc<DirectionCounters>,
}

impl Shaper {
    fn new(behavior: DirectionBehavior, seed: u64, counters: Arc<DirectionCounters>) -> Self {
        Shaper {
            behavior,
            rng: SplitMix64::new(seed),
            held: None,
            burst_left: 0,
            counters,
        }
    }

    /// Feeds one input datagram; returns the datagrams to emit now, in order.
    ///
    /// PRNG draws per input datagram: 0 (burst-continuation drop), 1
    /// (dropped), 2 (held: drop+reorder rolls), or 3 (forwarded:
    /// drop+reorder+duplicate rolls) — fixed order, so the decision stream is
    /// reproducible for a given seed and input sequence.
    fn process(&mut self, datagram: &[u8]) -> Vec<Vec<u8>> {
        if self.burst_left > 0 {
            self.burst_left -= 1;
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
            return Vec::new();
        }
        if self.rng.chance(self.behavior.drop_probability) {
            self.burst_left = self.behavior.drop_burst.saturating_sub(1);
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
            return Vec::new();
        }

        if self.held.is_none() && self.rng.chance(self.behavior.reorder_probability) {
            self.held = Some(datagram.to_vec());
            return Vec::new();
        }

        let mut out = Vec::with_capacity(3);
        out.push(datagram.to_vec());
        self.counters.forwarded.fetch_add(1, Ordering::Relaxed);
        if self.rng.chance(self.behavior.duplicate_probability) {
            out.push(datagram.to_vec());
            self.counters.duplicated.fetch_add(1, Ordering::Relaxed);
        }
        // Release a reorder-held datagram *after* the trigger; no further
        // duplicate roll for it (it already passed its rolls when parked).
        if let Some(prev) = self.held.take() {
            self.counters.forwarded.fetch_add(1, Ordering::Relaxed);
            out.push(prev);
        }
        out
    }

    fn has_held(&self) -> bool {
        self.held.is_some()
    }

    /// Releases the held datagram without waiting for a successor.
    fn flush_held(&mut self) -> Option<Vec<u8>> {
        let prev = self.held.take()?;
        self.counters.forwarded.fetch_add(1, Ordering::Relaxed);
        Some(prev)
    }
}

/// Handle to a running proxy. Dropping it aborts the forwarding task;
/// [`LossyProxy::shutdown`] stops it gracefully and waits for it to finish
/// (releasing the ports deterministically).
pub struct LossyProxy {
    local_addr: SocketAddr,
    counters: Arc<[Arc<DirectionCounters>; 2]>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl LossyProxy {
    /// Binds `127.0.0.1:0` for the client side, connects a second socket to
    /// `upstream`, and spawns the forwarding task on the current runtime.
    ///
    /// `seed` derives both directions' independent PRNG streams; the same
    /// seed reproduces the same behavior for the same traffic order.
    pub async fn spawn(
        upstream: SocketAddr,
        behavior: ProxyBehavior,
        seed: u64,
    ) -> std::io::Result<LossyProxy> {
        let front = UdpSocket::bind("127.0.0.1:0").await?;
        let local_addr = front.local_addr()?;
        let back = UdpSocket::bind("127.0.0.1:0").await?;
        back.connect(upstream).await?;

        let c2u_counters = Arc::new(DirectionCounters::default());
        let u2c_counters = Arc::new(DirectionCounters::default());
        let (c2u_seed, u2c_seed) = direction_seeds(seed);
        let c2u = Shaper::new(behavior.client_to_upstream, c2u_seed, c2u_counters.clone());
        let u2c = Shaper::new(behavior.upstream_to_client, u2c_seed, u2c_counters.clone());

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(run(front, back, c2u, u2c, behavior.hold_flush, shutdown_rx));

        Ok(LossyProxy {
            local_addr,
            counters: Arc::new([c2u_counters, u2c_counters]),
            shutdown_tx: Some(shutdown_tx),
            task: Some(task),
        })
    }

    /// Address the client should send to (`127.0.0.1:port`).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Current counters (safe to poll while traffic flows; counting happens
    /// before the corresponding datagram hits the wire).
    pub fn stats(&self) -> ProxyStats {
        ProxyStats {
            client_to_upstream: self.counters[0].snapshot(),
            upstream_to_client: self.counters[1].snapshot(),
        }
    }

    /// Stops forwarding and waits for the task to exit. Any reorder-held
    /// datagrams are discarded.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for LossyProxy {
    fn drop(&mut self) {
        // Kill-on-drop fallback for tests that forget/skip `shutdown()`.
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Derives the two per-direction PRNG seeds from the user seed
/// (client→upstream first). Public so self-tests can replay decisions with a
/// parallel [`SplitMix64`] and predict the wire outcome exactly.
pub fn direction_seeds(seed: u64) -> (u64, u64) {
    let mut rng = SplitMix64::new(seed);
    (rng.next_u64(), rng.next_u64())
}

/// Sleeps until `deadline`, or forever when there is none (for `select!`).
async fn sleep_opt(deadline: Option<Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending().await,
    }
}

/// Updates a direction's hold-flush deadline after its shaper ran:
/// arm when a datagram just got parked, disarm when the hold was released.
fn update_deadline(deadline: &mut Option<Instant>, shaper: &Shaper, hold_flush: Duration) {
    if shaper.has_held() {
        if deadline.is_none() {
            *deadline = Some(Instant::now() + hold_flush);
        }
    } else {
        *deadline = None;
    }
}

async fn run(
    front: UdpSocket,
    back: UdpSocket,
    mut c2u: Shaper,
    mut u2c: Shaper,
    hold_flush: Duration,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    let mut client_addr: Option<SocketAddr> = None;
    // Max UDP payload; SRT never exceeds its MSS but the proxy is generic.
    let mut front_buf = vec![0u8; 65536];
    let mut back_buf = vec![0u8; 65536];
    let mut c2u_deadline: Option<Instant> = None;
    let mut u2c_deadline: Option<Instant> = None;

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => break,

            res = front.recv_from(&mut front_buf) => {
                let (len, from) = match res {
                    Ok(v) => v,
                    // e.g. ECONNREFUSED bleed-through; keep serving.
                    Err(err) => {
                        eprintln!("[proxy] front recv error (ignored): {err}");
                        continue;
                    }
                };
                // Single-client proxy: latest front-side sender is the client.
                if client_addr != Some(from) {
                    if let Some(old) = client_addr {
                        eprintln!("[proxy] client address changed {old} -> {from}");
                    }
                    client_addr = Some(from);
                }
                for datagram in c2u.process(&front_buf[..len]) {
                    if let Err(err) = back.send(&datagram).await {
                        // Upstream may not be bound yet; the datagram is
                        // already counted as forwarded — tests tolerate this
                        // the same way they tolerate real UDP loss.
                        eprintln!("[proxy] upstream send error (ignored): {err}");
                    }
                }
                update_deadline(&mut c2u_deadline, &c2u, hold_flush);
            }

            res = back.recv(&mut back_buf) => {
                let len = match res {
                    Ok(v) => v,
                    Err(err) => {
                        eprintln!("[proxy] back recv error (ignored): {err}");
                        continue;
                    }
                };
                let Some(client) = client_addr else {
                    // No client yet: nowhere to forward. Drop silently
                    // (uncounted — this is not a shaped drop).
                    continue;
                };
                for datagram in u2c.process(&back_buf[..len]) {
                    if let Err(err) = front.send_to(&datagram, client).await {
                        eprintln!("[proxy] client send error (ignored): {err}");
                    }
                }
                update_deadline(&mut u2c_deadline, &u2c, hold_flush);
            }

            _ = sleep_opt(c2u_deadline) => {
                if let Some(datagram) = c2u.flush_held() {
                    let _ = back.send(&datagram).await;
                }
                c2u_deadline = None;
            }

            _ = sleep_opt(u2c_deadline) => {
                if let (Some(datagram), Some(client)) = (u2c.flush_held(), client_addr) {
                    let _ = front.send_to(&datagram, client).await;
                }
                u2c_deadline = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shaper(behavior: DirectionBehavior, seed: u64) -> (Shaper, Arc<DirectionCounters>) {
        let counters = Arc::new(DirectionCounters::default());
        (Shaper::new(behavior, seed, counters.clone()), counters)
    }

    #[test]
    fn shaper_passthrough_forwards_everything() {
        let (mut sh, counters) = shaper(DirectionBehavior::passthrough(), 1);
        for i in 0 .. 100u8 {
            let out = sh.process(&[i]);
            assert_eq!(out, vec![vec![i]]);
        }
        let stats = counters.snapshot();
        assert_eq!(
            stats,
            DirectionStats {
                forwarded: 100,
                dropped: 0,
                duplicated: 0
            }
        );
    }

    #[test]
    fn shaper_drop_all() {
        let (mut sh, counters) = shaper(DirectionBehavior::passthrough().with_drop(1.0), 1);
        for i in 0 .. 50u8 {
            assert!(sh.process(&[i]).is_empty());
        }
        assert_eq!(counters.snapshot().dropped, 50);
        assert_eq!(counters.snapshot().forwarded, 0);
    }

    #[test]
    fn shaper_duplicate_all() {
        let (mut sh, counters) = shaper(DirectionBehavior::passthrough().with_duplicate(1.0), 1);
        let out = sh.process(&[7]);
        assert_eq!(out, vec![vec![7], vec![7]]);
        let stats = counters.snapshot();
        assert_eq!(stats.forwarded, 1);
        assert_eq!(stats.duplicated, 1);
    }

    #[test]
    fn shaper_reorder_swaps_pairs() {
        // p=1: every packet is held unless a hold is pending, so the output
        // order for A B C D is B A D C.
        let (mut sh, counters) = shaper(DirectionBehavior::passthrough().with_reorder(1.0), 1);
        assert!(sh.process(b"A").is_empty());
        assert!(sh.has_held());
        assert_eq!(sh.process(b"B"), vec![b"B".to_vec(), b"A".to_vec()]);
        assert!(!sh.has_held());
        assert!(sh.process(b"C").is_empty());
        assert_eq!(sh.process(b"D"), vec![b"D".to_vec(), b"C".to_vec()]);
        assert_eq!(counters.snapshot().forwarded, 4);
    }

    #[test]
    fn shaper_flush_releases_held() {
        let (mut sh, counters) = shaper(DirectionBehavior::passthrough().with_reorder(1.0), 1);
        assert!(sh.process(b"A").is_empty());
        assert_eq!(sh.flush_held(), Some(b"A".to_vec()));
        assert_eq!(sh.flush_held(), None);
        assert_eq!(counters.snapshot().forwarded, 1);
    }

    #[test]
    fn shaper_burst_drops_whole_bursts() {
        // Bursts can chain (the datagram after a burst may roll a fresh hit),
        // so every completed run of consecutive drops is a multiple of the
        // burst length; the trailing run may be cut short by end of input.
        let behavior = DirectionBehavior::passthrough()
            .with_drop(0.25)
            .with_drop_burst(4);
        let (mut sh, counters) = shaper(behavior, 7);
        let forwarded: Vec<bool> = (0 .. 400u16)
            .map(|i| !sh.process(&i.to_be_bytes()).is_empty())
            .collect();
        let mut run = 0u32;
        for &fwd in &forwarded {
            if fwd {
                assert_eq!(run % 4, 0, "drop run of length {run} is not whole bursts");
                run = 0;
            } else {
                run += 1;
            }
        }
        let stats = counters.snapshot();
        assert_eq!(stats.dropped + stats.forwarded, 400);
        // Expected loss ≈ 4p/(1+3p) ≈ 57% — far above the 25% trigger rate,
        // proving followers are dropped without their own rolls.
        assert!(
            stats.dropped > 160,
            "bursts should amplify the trigger rate: {stats:?}"
        );
    }

    #[test]
    fn shaper_burst_zero_and_one_mean_single_drops() {
        for burst in [0, 1] {
            let behavior = DirectionBehavior::passthrough()
                .with_drop(1.0)
                .with_drop_burst(burst);
            let (mut sh, counters) = shaper(behavior, 1);
            for i in 0 .. 10u8 {
                assert!(sh.process(&[i]).is_empty());
            }
            assert_eq!(counters.snapshot().dropped, 10);
        }
    }

    #[test]
    fn shaper_drop_pattern_is_seed_deterministic() {
        let behavior = DirectionBehavior::passthrough().with_drop(0.5);
        let pattern = |seed| -> Vec<bool> {
            let (mut sh, _) = shaper(behavior, seed);
            (0 .. 64u8).map(|i| !sh.process(&[i]).is_empty()).collect()
        };
        assert_eq!(pattern(123), pattern(123));
        assert_ne!(pattern(123), pattern(124));
        // Sanity: p=0.5 over 64 packets drops *something* and keeps something.
        let p = pattern(123);
        assert!(p.iter().any(|&kept| kept) && p.iter().any(|&kept| !kept));
    }

    /// End-to-end over localhost: passthrough forwards every datagram in both
    /// directions and the counters agree.
    #[tokio::test]
    async fn proxy_passthrough_bidirectional() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let proxy = LossyProxy::spawn(upstream_addr, ProxyBehavior::default(), 1)
            .await
            .unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(proxy.local_addr()).await.unwrap();

        let mut buf = [0u8; 2048];
        for i in 0 .. 20u8 {
            client.send(&[i; 100]).await.unwrap();
            // Upstream sees it (via the proxy's back socket, not the client).
            let (len, from) =
                tokio::time::timeout(Duration::from_secs(2), upstream.recv_from(&mut buf))
                    .await
                    .expect("timed out waiting for c->u datagram")
                    .unwrap();
            assert_eq!(&buf[.. len], &[i; 100][..]);
            assert_ne!(from, client.local_addr().unwrap());

            // Echo back through the proxy.
            upstream.send_to(&[i ^ 0xFF; 50], from).await.unwrap();
            let len = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
                .await
                .expect("timed out waiting for u->c datagram")
                .unwrap();
            assert_eq!(&buf[.. len], &[i ^ 0xFF; 50][..]);
        }

        let stats = proxy.stats();
        assert_eq!(stats.client_to_upstream.forwarded, 20);
        assert_eq!(stats.upstream_to_client.forwarded, 20);
        assert_eq!(stats.client_to_upstream.dropped, 0);
        assert_eq!(stats.upstream_to_client.dropped, 0);
        proxy.shutdown().await;
    }

    /// With a fixed seed the drop pattern on the wire matches a parallel
    /// replay of the same Shaper decisions exactly.
    #[tokio::test]
    async fn proxy_drops_deterministically() {
        const SEED: u64 = 0xD5EE_D001;
        const N: usize = 60;
        let behavior = ProxyBehavior {
            client_to_upstream: DirectionBehavior::passthrough().with_drop(0.4),
            ..ProxyBehavior::default()
        };

        // Predict which packets survive by replaying the decision stream.
        let (c2u_seed, _) = direction_seeds(SEED);
        let (mut oracle, _) = shaper(behavior.client_to_upstream, c2u_seed);
        let mut expected = Vec::new();
        for i in 0 .. N {
            let payload = vec![i as u8; 32];
            for d in oracle.process(&payload) {
                expected.push(d);
            }
        }
        assert!(
            !expected.is_empty() && expected.len() < N,
            "seed gives a mixed pattern"
        );

        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let proxy = LossyProxy::spawn(upstream.local_addr().unwrap(), behavior, SEED)
            .await
            .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(proxy.local_addr()).await.unwrap();

        for i in 0 .. N {
            client.send(&[i as u8; 32]).await.unwrap();
            // Localhost keeps ordering; small pacing avoids rcvbuf overflow.
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        let mut buf = [0u8; 2048];
        let mut received = Vec::new();
        while received.len() < expected.len() {
            match tokio::time::timeout(Duration::from_millis(500), upstream.recv_from(&mut buf))
                .await
            {
                Ok(Ok((len, _))) => received.push(buf[.. len].to_vec()),
                Ok(Err(err)) => panic!("upstream recv error: {err}"),
                Err(_) => break, // quiescent: no more datagrams coming
            }
        }
        assert_eq!(received, expected);

        let stats = proxy.stats().client_to_upstream;
        assert_eq!(stats.forwarded as usize, expected.len());
        assert_eq!(stats.dropped as usize, N - expected.len());
        proxy.shutdown().await;
    }

    /// Reorder holds a datagram and the flush timer releases it when the
    /// direction goes quiet.
    #[tokio::test]
    async fn proxy_reorder_and_hold_flush() {
        let behavior = ProxyBehavior {
            client_to_upstream: DirectionBehavior::passthrough().with_reorder(1.0),
            hold_flush: Duration::from_millis(50),
            ..ProxyBehavior::default()
        };
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let proxy = LossyProxy::spawn(upstream.local_addr().unwrap(), behavior, 3)
            .await
            .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(proxy.local_addr()).await.unwrap();

        // A gets held, B triggers release: expect B then A.
        client.send(b"A").await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        client.send(b"B").await.unwrap();
        let mut buf = [0u8; 64];
        let mut got = Vec::new();
        for _ in 0 .. 2 {
            let (len, _) =
                tokio::time::timeout(Duration::from_secs(2), upstream.recv_from(&mut buf))
                    .await
                    .expect("timed out")
                    .unwrap();
            got.push(buf[.. len].to_vec());
        }
        assert_eq!(got, vec![b"B".to_vec(), b"A".to_vec()]);

        // C gets held with no successor: the flush timer must deliver it.
        client.send(b"C").await.unwrap();
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), upstream.recv_from(&mut buf))
            .await
            .expect("hold flush never fired")
            .unwrap();
        assert_eq!(&buf[.. len], b"C");
        assert_eq!(proxy.stats().client_to_upstream.forwarded, 3);
        proxy.shutdown().await;
    }

    /// `shutdown` stops the task; the front port stops forwarding.
    #[tokio::test]
    async fn proxy_shutdown_is_clean() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let proxy = LossyProxy::spawn(upstream.local_addr().unwrap(), ProxyBehavior::default(), 1)
            .await
            .unwrap();
        let proxy_addr = proxy.local_addr();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(proxy_addr).await.unwrap();
        client.send(b"x").await.unwrap();
        let mut buf = [0u8; 64];
        tokio::time::timeout(Duration::from_secs(2), upstream.recv_from(&mut buf))
            .await
            .expect("proxy not forwarding")
            .unwrap();

        proxy.shutdown().await;

        // After shutdown nothing is forwarded any more.
        client.send(b"y").await.unwrap();
        let res =
            tokio::time::timeout(Duration::from_millis(200), upstream.recv_from(&mut buf)).await;
        assert!(res.is_err(), "datagram forwarded after shutdown");
    }
}
