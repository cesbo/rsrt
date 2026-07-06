//! Pure in-memory simulation of two `Connection`s (caller + listener-
//! accepted) joined by a lossy/reordering channel.
//!
//! No tokio, no UDP, no sleeping: a fake clock advances in 1 ms steps and
//! every protocol rule runs off the explicit `now` passed into the sans-I/O
//! core. Timers are driven strictly through `next_deadline`, so these tests
//! also verify that the advertised deadlines cover every duty (ACK/NAK
//! ticks, TSBPD release, keepalive, EXP/peer-idle, handshake retransmits).
//!
//! Each endpoint has its own clock ([`SkewClock`]): the wire clock `now`
//! orders link events, while every `handle_*`/`poll_*`/`send` call gets the
//! owning endpoint's instant, skewed by a configurable ppm rate. Since the
//! sans-I/O core derives outgoing wire timestamps from those same instants
//! (via its `Timebase`), a non-zero skew reproduces real sender/receiver
//! quartz drift end to end. At the default 0 ppm every endpoint instant is
//! bit-identical to `now`.
//!
//! Everything is deterministic: the channel PRNG is seeded per test.

use std::{
    net::{
        Ipv4Addr,
        SocketAddrV4,
    },
    time::{
        Duration,
        Instant,
    },
};

use crate::{
    core::{
        ConnState,
        Connection,
        Listener,
        ListenerAction,
        Timebase,
        pacing::{
            BW_INFINITE,
            with_overhead,
        },
    },
    packet::{
        ControlPacket,
        ControlType,
        HandshakeCif,
        HandshakeType,
        Packet,
        SeqNumber,
        SocketId,
    },
    Bandwidth,
    CloseReason,
    SrtOptions,
};

const CALLER_ID: SocketId = SocketId(0x1111_2222);
const ACCEPT_ID: SocketId = SocketId(0x0BAD_CAFE);
const CALLER_ISN: SeqNumber = SeqNumber::new(0x0012_3456);
/// Unused by design: the listener adopts the caller's ISN.
const LISTENER_ISN: SeqNumber = SeqNumber::new(7);
const STEP: Duration = Duration::from_millis(1);

fn caller_addr() -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 50_000)
}

fn listener_addr() -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 9000)
}

/// xorshift64* — deterministic, seedable, no dependencies.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn chance(&mut self, pct: u32) -> bool {
        self.next() % 100 < u64::from(pct)
    }

    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next() % n
        }
    }
}

/// One endpoint's local clock: maps the sim's elapsed time to the
/// endpoint's `Instant`, running fast (`ppm > 0`) or slow (`ppm < 0`)
/// relative to the wire clock — `endpoint_now = origin + elapsed·(1 +
/// ppm/1e6)`, integer-µs math. At 0 ppm the mapping is the identity, so
/// every instant is bit-identical to the shared wire clock.
///
/// Set a non-zero `ppm` only before the first step (re-basing mid-run would
/// jump the endpoint's clock, possibly backwards) and never together with a
/// shared `accept_timebase` (a cross-domain `Timebase` is meaningless under
/// skew).
#[derive(Clone, Copy)]
struct SkewClock {
    origin: Instant,
    ppm: i64,
}

impl SkewClock {
    fn new(origin: Instant) -> SkewClock {
        SkewClock { origin, ppm: 0 }
    }

    fn at(&self, elapsed_us: u64) -> Instant {
        debug_assert!(self.ppm.unsigned_abs() < 1_000_000);
        let skew = elapsed_us as i64 * self.ppm / 1_000_000;
        self.origin + Duration::from_micros((elapsed_us as i64 + skew) as u64)
    }
}

/// One direction of the simulated network path.
struct Link {
    rng: Rng,
    delay: Duration,
    /// Extra per-packet delay in `0..=jitter_us` µs (creates reordering).
    jitter_us: u64,
    /// Percentage of packets dropped at random.
    loss_pct: u32,
    /// Hard outage: everything pushed is discarded.
    down: bool,
    /// Drop the next N CONCLUSION handshake packets (targeted loss).
    drop_conclusions: u32,
    /// In flight: (arrival, insertion order, packet).
    queue: Vec<(Instant, u64, Packet)>,
    counter: u64,
    // Wire observability for assertions (counted only when not lost).
    dropreqs: u64,
    naks: u64,
}

impl Link {
    fn new(seed: u64, delay: Duration) -> Link {
        Link {
            rng: Rng::new(seed),
            delay,
            jitter_us: 0,
            loss_pct: 0,
            down: false,
            drop_conclusions: 0,
            queue: Vec::new(),
            counter: 0,
            dropreqs: 0,
            naks: 0,
        }
    }

    fn push(&mut self, now: Instant, pkt: Packet) {
        if self.down {
            return;
        }
        if self.drop_conclusions > 0 && is_conclusion(&pkt) {
            self.drop_conclusions -= 1;
            return;
        }
        if self.loss_pct > 0 && self.rng.chance(self.loss_pct) {
            return;
        }
        if let Packet::Control(c) = &pkt {
            match c.control_type {
                ControlType::DropRequest { .. } => self.dropreqs += 1,
                ControlType::Nak(_) => self.naks += 1,
                _ => {}
            }
        }
        let jitter = Duration::from_micros(self.rng.below(self.jitter_us + 1));
        self.counter += 1;
        self.queue
            .push((now + self.delay + jitter, self.counter, pkt));
    }

    /// Removes and returns every arrived packet, in arrival order.
    fn pop_due(&mut self, now: Instant) -> Vec<Packet> {
        let mut due: Vec<(Instant, u64, Packet)> = Vec::new();
        let mut i = 0;
        while i < self.queue.len() {
            if self.queue[i].0 <= now {
                due.push(self.queue.swap_remove(i));
            } else {
                i += 1;
            }
        }
        due.sort_by_key(|(at, ord, _)| (*at, *ord));
        due.into_iter().map(|(_, _, p)| p).collect()
    }
}

fn is_conclusion(pkt: &Packet) -> bool {
    matches!(
        pkt,
        Packet::Control(ControlPacket {
            control_type: ControlType::Handshake(HandshakeCif {
                handshake_type: HandshakeType::Conclusion,
                ..
            }),
            ..
        })
    )
}

/// The two endpoints plus the channel between them.
struct Sim {
    /// Wire clock: orders link events and timestamps `*_rx` records.
    now: Instant,
    /// Wire-clock time since the sim started, driving the [`SkewClock`]s.
    elapsed_us: u64,
    caller_clock: SkewClock,
    listener_clock: SkewClock,
    caller: Connection,
    listener: Listener,
    listener_opts: SrtOptions,
    /// Timebase for the accepted connection (wrap tests); `None` = fresh.
    accept_timebase: Option<Timebase>,
    accepted: Option<Connection>,
    /// caller → listener.
    to_listener: Link,
    /// listener → caller.
    to_caller: Link,
    /// Payloads delivered to each application, with delivery instants.
    caller_rx: Vec<(Instant, Vec<u8>)>,
    listener_rx: Vec<(Instant, Vec<u8>)>,
}

impl Sim {
    fn new(now: Instant, caller_opts: SrtOptions, listener_opts: SrtOptions, seed: u64) -> Sim {
        let caller = Connection::connect(now, listener_addr(), CALLER_ID, CALLER_ISN, caller_opts);
        Sim::assemble(now, caller, listener_opts, seed, None)
    }

    /// Both connections share `timebase` (placed near the timestamp wrap).
    fn new_with_timebase(
        now: Instant,
        caller_opts: SrtOptions,
        listener_opts: SrtOptions,
        seed: u64,
        timebase: Timebase,
    ) -> Sim {
        let caller = Connection::connect_with_timebase(
            now,
            listener_addr(),
            CALLER_ID,
            CALLER_ISN,
            caller_opts,
            timebase,
        );
        Sim::assemble(now, caller, listener_opts, seed, Some(timebase))
    }

    fn assemble(
        now: Instant,
        caller: Connection,
        listener_opts: SrtOptions,
        seed: u64,
        accept_timebase: Option<Timebase>,
    ) -> Sim {
        let listener_tb = accept_timebase.unwrap_or_else(|| Timebase::new(now));
        Sim {
            now,
            elapsed_us: 0,
            caller_clock: SkewClock::new(now),
            listener_clock: SkewClock::new(now),
            caller,
            listener: Listener::new(seed ^ 0x5EC2E7, listener_tb, listener_opts.clone()),
            listener_opts,
            accept_timebase,
            accepted: None,
            to_listener: Link::new(seed.wrapping_mul(3), Duration::from_millis(5)),
            to_caller: Link::new(seed.wrapping_mul(5), Duration::from_millis(5)),
            caller_rx: Vec::new(),
            listener_rx: Vec::new(),
        }
    }

    fn accepted_mut(&mut self) -> &mut Connection {
        self.accepted
            .as_mut()
            .expect("listener has accepted a connection")
    }

    /// The caller's local clock at the current sim time.
    fn caller_now(&self) -> Instant {
        self.caller_clock.at(self.elapsed_us)
    }

    /// The listener side's local clock at the current sim time.
    fn listener_now(&self) -> Instant {
        self.listener_clock.at(self.elapsed_us)
    }

    /// Submits one payload on the caller side, at the caller's clock.
    fn send_caller(&mut self, data: Vec<u8>) {
        let now = self.caller_now();
        self.caller.send(now, data).unwrap();
    }

    /// Submits one payload on the accepted (listener) side, at that side's
    /// clock.
    fn send_listener(&mut self, data: Vec<u8>) {
        let now = self.listener_now();
        self.accepted_mut().send(now, data).unwrap();
    }

    /// Advances the fake clock by one step and runs the event loop once.
    /// Link events run on the wire clock; each endpoint's `handle_*`/
    /// `poll_*` calls get that endpoint's own (possibly skewed) instant.
    fn step(&mut self) {
        self.now += STEP;
        self.elapsed_us += STEP.as_micros() as u64;
        let now = self.now;
        let c_now = self.caller_now();
        let l_now = self.listener_now();

        // 1. Deliver arrived packets.
        for pkt in self.to_listener.pop_due(now) {
            match &mut self.accepted {
                Some(conn) => conn.handle_packet(l_now, pkt),
                None => self.listener_handshake(l_now, pkt),
            }
        }
        for pkt in self.to_caller.pop_due(now) {
            self.caller.handle_packet(c_now, pkt);
        }

        // 2. Timers, strictly when the connection says one is due.
        if timer_due(&self.caller, c_now) {
            self.caller.handle_timer(c_now);
        }
        if let Some(conn) = &mut self.accepted {
            if timer_due(conn, l_now) {
                conn.handle_timer(l_now);
            }
        }

        // 3. Drain outputs.
        while let Some(p) = self.caller.poll_transmit(c_now) {
            self.to_listener.push(now, p);
        }
        while let Some(d) = self.caller.poll_deliver(c_now) {
            self.caller_rx.push((now, d));
        }
        if let Some(conn) = &mut self.accepted {
            while let Some(p) = conn.poll_transmit(l_now) {
                self.to_caller.push(now, p);
            }
            while let Some(d) = conn.poll_deliver(l_now) {
                self.listener_rx.push((now, d));
            }
        }
    }

    /// Pre-accept path: handshake packets go to the stateless listener.
    /// `l_now` is the listener side's local clock reading.
    fn listener_handshake(&mut self, l_now: Instant, pkt: Packet) {
        let Packet::Control(ControlPacket {
            control_type: ControlType::Handshake(cif),
            ..
        }) = pkt
        else {
            return; // nothing but handshakes reaches an unaccepted listener
        };
        match self
            .listener
            .handle_handshake(l_now, caller_addr(), &cif, ACCEPT_ID, LISTENER_ISN)
        {
            ListenerAction::Reply(p) => self.to_caller.push(self.now, p),
            ListenerAction::Accept { reply, negotiated } => {
                // The accepted connection queues (and can replay) the reply.
                let conn = match self.accept_timebase {
                    Some(tb) => Connection::accepted_with_timebase(
                        l_now,
                        *negotiated,
                        reply,
                        self.listener_opts.clone(),
                        tb,
                    ),
                    None => Connection::accepted(
                        l_now,
                        *negotiated,
                        reply,
                        self.listener_opts.clone(),
                    ),
                };
                self.accepted = Some(conn);
            }
            ListenerAction::Drop => {}
        }
    }

    fn run_for(&mut self, ms: u64) {
        for _ in 0 .. ms {
            self.step();
        }
    }

    /// Steps until `cond` holds; panics after `cap_ms` steps.
    fn run_until(&mut self, cap_ms: u64, what: &str, cond: impl Fn(&Sim) -> bool) {
        for _ in 0 .. cap_ms {
            if cond(self) {
                return;
            }
            self.step();
        }
        assert!(
            cond(self),
            "condition not reached within {cap_ms} ms: {what}"
        );
    }

    fn both_established(&self) -> bool {
        self.caller.state() == ConnState::Established
            && self
                .accepted
                .as_ref()
                .is_some_and(|c| c.state() == ConnState::Established)
    }
}

fn timer_due(conn: &Connection, now: Instant) -> bool {
    conn.next_deadline(now).is_some_and(|d| d <= now)
}

/// Tagged, numbered payload; the index is recovered by `payload_index`.
fn payload(tag: u8, index: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(64);
    v.push(tag);
    v.extend_from_slice(&index.to_le_bytes());
    v.resize(64, tag ^ 0x5A);
    v
}

fn payload_index(data: &[u8], tag: u8) -> u32 {
    assert_eq!(data[0], tag, "payload from the wrong direction");
    u32::from_le_bytes([data[1], data[2], data[3], data[4]])
}

/// Asserts `rx` is exactly payloads `0..count` of `tag`, in order.
fn assert_contiguous(rx: &[(Instant, Vec<u8>)], tag: u8, count: u32) {
    assert!(
        rx.len() >= count as usize,
        "only {} of {count} payloads delivered (tag {tag:#x})",
        rx.len()
    );
    for (i, (_, data)) in rx.iter().take(count as usize).enumerate() {
        assert_eq!(
            payload_index(data, tag),
            i as u32,
            "payload {i} out of order (tag {tag:#x})"
        );
    }
}

// ---------------------------------------------------------------------------

/// Clean network: handshake, bidirectional data delivered in TSBPD order at
/// the negotiated latency, then a clean shutdown.
#[test]
fn clean_handshake_data_and_shutdown() {
    let t0 = Instant::now();
    let mut sim = Sim::new(t0, SrtOptions::default(), SrtOptions::default(), 1);

    sim.run_until(100, "handshake", Sim::both_established);
    let setup = sim.now.duration_since(t0);
    assert!(
        setup < Duration::from_millis(50),
        "handshake too slow: {setup:?}"
    );
    assert_eq!(sim.caller.remote(), listener_addr());
    assert_eq!(sim.accepted_mut().remote(), caller_addr());

    // 200 payloads in each direction, one every 2 ms.
    let mut caller_sent = Vec::new();
    let mut listener_sent = Vec::new();
    for i in 0 .. 200u32 {
        sim.caller.send(sim.now, payload(0xA, i)).unwrap();
        caller_sent.push(sim.now);
        sim.send_listener(payload(0xB, i));
        listener_sent.push(sim.now);
        sim.run_for(2);
    }
    sim.run_for(300); // 120 ms latency + margin

    assert_eq!(sim.listener_rx.len(), 200);
    assert_eq!(sim.caller_rx.len(), 200);
    assert_contiguous(&sim.listener_rx, 0xA, 200);
    assert_contiguous(&sim.caller_rx, 0xB, 200);

    // TSBPD delivery time: anchor(first packet arrival = send + 5 ms one-way
    // delay) + timestamp delta + 120 ms latency, polled on a 1 ms grid.
    for (i, (at, _)) in sim.listener_rx.iter().enumerate() {
        let lat = at.duration_since(caller_sent[i]);
        assert!(
            lat >= Duration::from_millis(120) && lat <= Duration::from_millis(135),
            "payload {i} delivered at latency {lat:?}"
        );
    }
    for (i, (at, _)) in sim.caller_rx.iter().enumerate() {
        let lat = at.duration_since(listener_sent[i]);
        assert!(
            lat >= Duration::from_millis(120) && lat <= Duration::from_millis(135),
            "payload {i} delivered at latency {lat:?}"
        );
    }

    // Nothing was lost, dropped or retransmitted on a clean link.
    for stats in [sim.caller.stats(), sim.accepted_mut().stats()] {
        assert_eq!(stats.pkts_sent, 200);
        assert_eq!(stats.pkts_recv, 200);
        assert_eq!(stats.pkts_retransmitted, 0);
        assert_eq!(stats.pkts_recv_lost, 0);
        assert_eq!(stats.pkts_recv_dropped, 0);
        assert_eq!(stats.pkts_send_dropped, 0);
        assert!(
            stats.rtt_us < 100_000,
            "RTT must be measured: {}",
            stats.rtt_us
        );
    }
    assert_eq!(sim.to_listener.naks + sim.to_caller.naks, 0);

    // Clean local close: SHUTDOWN reaches the peer.
    sim.caller.close(sim.now);
    sim.run_for(50);
    assert_eq!(sim.caller.state(), ConnState::Closed(CloseReason::Local));
    assert_eq!(
        sim.accepted_mut().state(),
        ConnState::Closed(CloseReason::Shutdown)
    );
}

/// 5% random loss + reordering jitter in both directions: NAK/retransmit
/// recovery delivers everything with zero receiver-side drops.
#[test]
fn five_percent_loss_recovers_everything() {
    let t0 = Instant::now();
    // Latency high enough to absorb NAK retry cycles (including the initial
    // 300 ms periodic-NAK interval before the first RTT-based recompute).
    let opts = SrtOptions::default().latency(Duration::from_millis(400));
    let mut sim = Sim::new(t0, opts.clone(), opts, 0xBEEF);
    sim.to_listener.loss_pct = 5;
    sim.to_caller.loss_pct = 5;
    sim.to_listener.jitter_us = 2_000;
    sim.to_caller.jitter_us = 2_000;

    sim.run_until(2_000, "handshake under loss", Sim::both_established);

    const N: u32 = 400;
    for i in 0 .. N {
        sim.caller.send(sim.now, payload(0xA, i)).unwrap();
        sim.send_listener(payload(0xB, i));
        sim.run_for(2);
    }
    // Trailing traffic so a lost tail packet still gets its gap detected.
    for i in N .. N + 10 {
        sim.caller.send(sim.now, payload(0xA, i)).unwrap();
        sim.send_listener(payload(0xB, i));
        sim.run_for(20);
    }
    sim.run_for(1_500);

    assert_contiguous(&sim.listener_rx, 0xA, N);
    assert_contiguous(&sim.caller_rx, 0xB, N);

    let cs = sim.caller.stats();
    let ls = sim.accepted_mut().stats();
    assert!(cs.pkts_retransmitted > 0, "caller must have retransmitted");
    assert!(
        ls.pkts_retransmitted > 0,
        "listener must have retransmitted"
    );
    assert!(cs.pkts_recv_lost > 0, "losses must have been detected");
    assert!(ls.pkts_recv_lost > 0, "losses must have been detected");
    assert_eq!(cs.pkts_recv_dropped, 0, "recovery must beat every deadline");
    assert_eq!(ls.pkts_recv_dropped, 0, "recovery must beat every deadline");
    assert_eq!(cs.pkts_send_dropped, 0);
    assert_eq!(ls.pkts_send_dropped, 0);
    assert!(sim.to_listener.naks > 0 || sim.to_caller.naks > 0);
    assert!(sim.both_established());
}

/// A total outage longer than the sender's TLPKTDROP threshold: the sender
/// drops too-late packets and announces them with DROPREQ, the receiver
/// skips the unrecoverable hole at its TSBPD deadline, and the stream then
/// continues as if nothing happened.
#[test]
fn burst_loss_beyond_recovery_window() {
    let t0 = Instant::now();
    let mut sim = Sim::new(t0, SrtOptions::default(), SrtOptions::default(), 0xD00D);
    sim.run_until(100, "handshake", Sim::both_established);

    let mut i: u32 = 0;
    let send_every_5ms = |sim: &mut Sim, ms: u64, i: &mut u32| {
        for tick in 0 .. ms {
            if tick.is_multiple_of(5) {
                sim.caller.send(sim.now, payload(0xA, *i)).unwrap();
                *i += 1;
            }
            sim.step();
        }
    };

    // Phase 1: 1 s of clean flow.
    send_every_5ms(&mut sim, 1_000, &mut i);
    let delivered_before_outage = sim.listener_rx.len();
    assert!(delivered_before_outage > 100);

    // Phase 2: hard outage, longer than the 1020 ms TLPKTDROP threshold.
    sim.to_listener.down = true;
    sim.to_caller.down = true;
    send_every_5ms(&mut sim, 1_600, &mut i);

    // Phase 3: link restored; the stream must recover and keep going.
    sim.to_listener.down = false;
    sim.to_caller.down = false;
    let dropreqs_before = sim.to_listener.dropreqs;
    send_every_5ms(&mut sim, 2_000, &mut i);
    let last_sent = i - 1;
    sim.run_for(500);

    assert!(
        sim.both_established(),
        "outage below peer-idle must not break"
    );
    let cs = sim.caller.stats();
    let ls = sim.accepted_mut().stats();
    assert!(cs.pkts_send_dropped > 0, "sender TLPKTDROP must have fired");
    assert!(
        ls.pkts_recv_dropped > 0,
        "receiver must have skipped the hole"
    );
    assert!(
        sim.to_listener.dropreqs > dropreqs_before,
        "DROPREQs must reach the receiver after the outage"
    );

    // Delivery is strictly in order (skips allowed) and reaches the packets
    // sent after the outage, including the very last one.
    let indices: Vec<u32> = sim
        .listener_rx
        .iter()
        .map(|(_, d)| payload_index(d, 0xA))
        .collect();
    assert!(indices.windows(2).all(|w| w[0] < w[1]), "must stay ordered");
    assert_eq!(
        *indices.last().unwrap(),
        last_sent,
        "stream must keep going"
    );
    assert!(
        indices.len() < i as usize,
        "the hole must not be resurrected"
    );
}

/// The listener's CONCLUSION response is lost: the caller keeps
/// retransmitting its CONCLUSION and the accepted connection replays the
/// stored reply. Data sent by the listener meanwhile (racing the caller's
/// establishment) is buffered and delivered.
#[test]
fn lost_conclusion_response_recovered_by_replay() {
    let t0 = Instant::now();
    let mut sim = Sim::new(t0, SrtOptions::default(), SrtOptions::default(), 0xACC);
    sim.to_caller.drop_conclusions = 1; // the accept reply dies on the wire

    // The listener side accepts promptly; the caller keeps waiting.
    sim.run_until(100, "listener accept", |s| s.accepted.is_some());
    let accepted_at = sim.now;
    sim.run_until(1_000, "caller established", |s| {
        s.caller.state() != ConnState::Connecting
    });

    // The caller must have needed the 250 ms CONCLUSION retransmission.
    assert_eq!(sim.caller.state(), ConnState::Established);
    let elapsed = sim.now.duration_since(accepted_at);
    assert!(
        elapsed >= Duration::from_millis(250),
        "established after {elapsed:?}, i.e. without the retransmit?"
    );
    assert!(
        elapsed < Duration::from_millis(600),
        "took too long: {elapsed:?}"
    );

    // Bidirectional data flows after the recovery.
    for j in 0 .. 50u32 {
        sim.caller.send(sim.now, payload(0xA, j)).unwrap();
        sim.send_listener(payload(0xB, j));
        sim.run_for(2);
    }
    sim.run_for(300);
    assert_contiguous(&sim.listener_rx, 0xA, 50);
    assert_contiguous(&sim.caller_rx, 0xB, 50);
    assert_eq!(sim.caller.stats().pkts_recv_dropped, 0);
}

/// Data racing ahead of a lost CONCLUSION response is buffered by the
/// connecting caller and delivered once established.
#[test]
fn early_data_before_conclusion_response_is_delivered() {
    let t0 = Instant::now();
    let mut sim = Sim::new(t0, SrtOptions::default(), SrtOptions::default(), 0xEA51);
    sim.to_caller.drop_conclusions = 1;

    sim.run_until(100, "listener accept", |s| s.accepted.is_some());
    // The listener streams while the caller is still connecting.
    let mut sent: u32 = 0;
    while sim.caller.state() == ConnState::Connecting {
        if sent < 40 {
            sim.send_listener(payload(0xB, sent));
            sent += 1;
        }
        sim.step();
        assert!(
            sim.now.duration_since(t0) < Duration::from_secs(2),
            "caller never established"
        );
    }
    assert_eq!(sim.caller.state(), ConnState::Established);
    sim.run_for(400); // let TSBPD release everything
    assert_contiguous(&sim.caller_rx, 0xB, sent);
    assert_eq!(sim.caller.stats().pkts_recv_dropped, 0);
}

/// The peer falls silent: the connection breaks with PeerIdle after the 5 s
/// timeout (plus EXP escalation), and the closing side's best-effort
/// SHUTDOWN tells the still-reachable peer.
#[test]
fn peer_goes_silent_peer_idle_close() {
    let t0 = Instant::now();
    let mut sim = Sim::new(t0, SrtOptions::default(), SrtOptions::default(), 0x51E7);
    sim.run_until(100, "handshake", Sim::both_established);

    // Steady bidirectional traffic, so the listener is actively talking
    // right up to the moment it goes silent.
    for j in 0 .. 40u32 {
        sim.caller.send(sim.now, payload(0xA, j)).unwrap();
        sim.send_listener(payload(0xB, j));
        sim.run_for(5);
    }

    // The listener's packets stop reaching the caller. The caller keeps
    // transmitting (data + keepalives), so the listener itself stays alive
    // and the break can only come from receive-side idleness.
    sim.to_caller.down = true;
    let silence_start = sim.now;
    let mut j = 100u32;
    let mut steps = 0u64;
    while sim.caller.state() == ConnState::Established {
        if steps.is_multiple_of(10) {
            let _ = sim.caller.send(sim.now, payload(0xA, j));
            j += 1;
        }
        sim.step();
        steps += 1;
        assert!(steps < 8_000, "no PeerIdle close within 8 s");
    }

    assert_eq!(sim.caller.state(), ConnState::Closed(CloseReason::PeerIdle));
    let idle = sim.now.duration_since(silence_start);
    assert!(idle >= Duration::from_secs(5), "broke too early: {idle:?}");
    assert!(
        idle < Duration::from_millis(5_700),
        "broke too late: {idle:?}"
    );

    // The best-effort SHUTDOWN still crosses the working direction.
    sim.run_for(50);
    assert_eq!(
        sim.accepted_mut().state(),
        ConnState::Closed(CloseReason::Shutdown)
    );
}

/// A connected but silent sender: an idle established pair exchanges
/// keepalives automatically, so peer-idle never fires in either direction
/// and only the accepted side's data-idle window can break the connection.
/// The best-effort SHUTDOWN crosses to the still-alive caller.
#[test]
fn data_idle_closes_silent_sender_shutdown_crosses() {
    let t0 = Instant::now();
    let mut sim = Sim::new(
        t0,
        SrtOptions::default(),
        SrtOptions::default().data_idle_timeout(Duration::from_secs(2)),
        0xDA7A,
    );
    sim.run_until(100, "handshake", Sim::both_established);
    let established_at = sim.now;

    // Nobody sends: the accepted side must break at its 2 s window (which
    // opened at accept, a few link round-trips before `established_at`).
    let mut steps = 0u64;
    while sim.accepted_mut().state() == ConnState::Established {
        sim.step();
        steps += 1;
        assert!(steps < 3_000, "no DataIdle close within 3 s");
    }
    assert_eq!(
        sim.accepted_mut().state(),
        ConnState::Closed(CloseReason::DataIdle)
    );
    let idle = sim.now.duration_since(established_at);
    assert!(
        idle >= Duration::from_millis(1_900),
        "broke too early: {idle:?}"
    );
    assert!(
        idle < Duration::from_millis(2_200),
        "broke too late: {idle:?}"
    );

    // The caller, alive on keepalives alone, sees a clean SHUTDOWN.
    sim.run_for(50);
    assert_eq!(
        sim.caller.state(),
        ConnState::Closed(CloseReason::Shutdown)
    );
}

/// Long-run wrap: the shared timebase starts ~71 minutes in the fake past,
/// so wire timestamps cross the 32-bit µs wrap 30 s into the stream. The
/// stream must cross the boundary without stalls, drops or reordering.
#[test]
fn timestamp_wrap_long_run() {
    let base = Instant::now();
    let wrap_period = Duration::from_micros(1u64 << 32); // ~71.6 min
    let t0 = base + (wrap_period - Duration::from_secs(30));
    let timebase = Timebase::new(base);

    let mut sim = Sim::new_with_timebase(
        t0,
        SrtOptions::default(),
        SrtOptions::default(),
        0x14A9,
        timebase,
    );
    sim.run_until(100, "handshake", Sim::both_established);

    // Stream both directions, one payload per 5 ms, for 60 s of fake time —
    // crossing the wrap at the 30 s mark.
    let mut caller_sent = Vec::new();
    let mut listener_sent = Vec::new();
    let mut sent: u32 = 0;
    for tick in 0 .. 60_000u64 {
        if tick.is_multiple_of(5) && tick < 59_000 {
            sim.caller.send(sim.now, payload(0xA, sent)).unwrap();
            caller_sent.push(sim.now);
            sim.send_listener(payload(0xB, sent));
            listener_sent.push(sim.now);
            sent += 1;
        }
        sim.step();
    }

    assert!(sim.both_established());
    assert_eq!(sim.listener_rx.len(), sent as usize);
    assert_eq!(sim.caller_rx.len(), sent as usize);
    assert_contiguous(&sim.listener_rx, 0xA, sent);
    assert_contiguous(&sim.caller_rx, 0xB, sent);

    // No stalls: every payload was released right at its TSBPD deadline
    // (send + 5 ms one-way + 120 ms latency), including across the wrap.
    for (i, (at, _)) in sim.listener_rx.iter().enumerate() {
        let lat = at.duration_since(caller_sent[i]);
        assert!(
            lat >= Duration::from_millis(120) && lat <= Duration::from_millis(140),
            "payload {i}: latency {lat:?} across the wrap"
        );
    }
    for (i, (at, _)) in sim.caller_rx.iter().enumerate() {
        let lat = at.duration_since(listener_sent[i]);
        assert!(
            lat >= Duration::from_millis(120) && lat <= Duration::from_millis(140),
            "payload {i}: latency {lat:?} across the wrap"
        );
    }

    for stats in [sim.caller.stats(), sim.accepted_mut().stats()] {
        assert_eq!(stats.pkts_recv_dropped, 0);
        assert_eq!(stats.pkts_send_dropped, 0);
        assert_eq!(stats.pkts_recv_lost, 0);
        assert_eq!(stats.pkts_recv, u64::from(sent));
    }
}

// ---- TSBPD clock drift (transmission.md §9.4) ----

/// Streams caller → listener for `secs` of wire time (one payload per
/// 10 ms) with the caller's clock skewed by `caller_ppm`, then asserts
/// every payload was delivered in order, nothing was dropped, and each
/// wire-clock delivery latency stayed within `[min_ms, max_ms]`.
///
/// ±500 ppm eats the whole 120 ms latency budget in 240 s, so a 360 s run
/// is decisive in both directions: without the drift tracer the slow-clock
/// run collapses to near-zero latency (every packet released "late") and
/// the fast-clock run inflates past +180 ms.
fn drift_run(caller_ppm: i64, secs: u64, min_ms: u64, max_ms: u64) -> Sim {
    let t0 = Instant::now();
    let mut sim = Sim::new(t0, SrtOptions::default(), SrtOptions::default(), 0xD21F7);
    sim.caller_clock.ppm = caller_ppm;

    sim.run_until(100, "handshake", Sim::both_established);

    let mut sent_at = Vec::new();
    let mut sent: u32 = 0;
    for tick in 0 .. secs * 1_000 {
        if tick.is_multiple_of(10) {
            sim.send_caller(payload(0xA, sent));
            sent_at.push(sim.now);
            sent += 1;
        }
        sim.step();
    }
    sim.run_for(500); // drain the last latency window

    assert!(sim.both_established());
    assert_eq!(sim.listener_rx.len(), sent as usize);
    assert_contiguous(&sim.listener_rx, 0xA, sent);
    let ls = sim.accepted_mut().stats();
    assert_eq!(ls.pkts_recv_dropped, 0);
    assert_eq!(ls.pkts_recv_lost, 0);

    // The tracer corrects in ±5 ms steps once per 1000-ACKACK batch (~10 s
    // at the 10 ms full-ACK cadence), so the residual mistracking stays
    // within one batch of accumulation (~5 ms at 500 ppm) plus the commit
    // lag — the latency window just needs to absorb that, not the full
    // accumulated offset (±180 ms over the run).
    for (i, (at, _)) in sim.listener_rx.iter().enumerate() {
        let lat = at.duration_since(sent_at[i]);
        assert!(
            lat >= Duration::from_millis(min_ms) && lat <= Duration::from_millis(max_ms),
            "payload {i} delivered at latency {lat:?} under {caller_ppm} ppm skew"
        );
    }
    sim
}

/// The sender's clock runs 500 ppm fast: uncompensated, delivery latency
/// would grow 0.5 ms/s to ~+180 ms by the end of the run. The drift tracer
/// must keep it near the nominal 125 ms throughout.
#[test]
fn fast_sender_clock_drift_compensated_long_run() {
    let mut sim = drift_run(500, 360, 110, 150);

    // The listener's net correction ≈ −(accumulated offset): 500 ppm over
    // 360 s = 180 ms, minus at most a couple of batches of tracking lag.
    let drift = sim.accepted_mut().stats().tsbpd_drift_us;
    assert!(
        (-190_000 ..= -160_000).contains(&drift),
        "listener drift correction {drift} µs, expected ≈ −180 ms"
    );
    // The caller received no data, so its tracer never sampled.
    assert_eq!(sim.caller.stats().tsbpd_drift_us, 0);
}

/// The sender's clock runs 500 ppm slow: uncompensated, the 120 ms latency
/// budget is exhausted at 240 s — every later packet is released the moment
/// it arrives (latency collapses to the 5 ms link delay) and ARQ has no
/// recovery window left. The drift tracer must hold the release point.
#[test]
fn slow_sender_clock_drift_compensated_long_run() {
    let mut sim = drift_run(-500, 360, 110, 150);

    let drift = sim.accepted_mut().stats().tsbpd_drift_us;
    assert!(
        (160_000 ..= 190_000).contains(&drift),
        "listener drift correction {drift} µs, expected ≈ +180 ms"
    );
}

/// The real casualty of uncompensated drift is ARQ: once the budget is
/// eaten, every retransmission arrives past its deadline. A slow sender
/// clock plus random loss and reordering over 6 minutes must still recover
/// every single packet at the default 120 ms latency — uncompensated, the
/// budget is gone at 240 s and every loss after that becomes a drop.
#[test]
fn clock_drift_with_loss_keeps_arq_alive() {
    let t0 = Instant::now();
    let mut sim = Sim::new(t0, SrtOptions::default(), SrtOptions::default(), 0xA9C0FFEE);
    sim.caller_clock.ppm = -500;

    sim.run_until(100, "handshake", Sim::both_established);

    let mut sent: u32 = 0;
    for tick in 0 .. 360_000u64 {
        if tick == 5_000 {
            // Clean 5 s warmup first, so NAK pacing runs on a measured RTT
            // (not the 300 ms initial interval) before recovery is needed.
            sim.to_listener.loss_pct = 2;
            sim.to_listener.jitter_us = 2_000;
            sim.to_caller.loss_pct = 2;
            sim.to_caller.jitter_us = 2_000;
        }
        if tick.is_multiple_of(10) {
            sim.send_caller(payload(0xA, sent));
            sent += 1;
        }
        sim.step();
    }
    // Trailing traffic so a lost tail packet still gets its gap detected.
    for _ in 0 .. 10 {
        sim.send_caller(payload(0xA, sent));
        sent += 1;
        sim.run_for(20);
    }
    sim.run_for(1_500);

    assert_contiguous(&sim.listener_rx, 0xA, sent);
    let ls = sim.accepted_mut().stats();
    assert!(ls.pkts_recv_lost > 0, "losses must have been detected");
    assert_eq!(
        ls.pkts_recv_dropped, 0,
        "recovery must beat every deadline despite the clock drift"
    );
    assert!(
        sim.caller.stats().pkts_retransmitted > 0,
        "caller must have retransmitted"
    );
}

// ---- LiveCC pacing (transmission.md §3.3) ----

/// [`payload`] stretched to 1316 bytes (the libsrt live default payload
/// size): with every packet at the avg-payload IIR's min(1316, max_payload)
/// init the pacing period never moves, so the expected rates in the tests
/// below are exact (transmission.md §3.3.1).
fn payload_1316(tag: u8, index: u32) -> Vec<u8> {
    let mut v = payload(tag, index);
    v.resize(1316, tag ^ 0xC3);
    v
}

/// A fixed `Bandwidth::Max` ceiling offered ~2.2× its rate: the wire output
/// must hold the configured 200_000 B/s (payload bytes over 200 ms windows,
/// both bounds) instead of following the input, and the backlog must still
/// deliver everything in order. The latency is sized above the worst-case
/// backlog lag so neither too-late valve (sender TLPKTDROP §8.1, receiver
/// TSBPD drop) interferes with the rate measurement.
#[test]
fn paced_sender_holds_configured_rate() {
    let t0 = Instant::now();
    let latency = Duration::from_millis(3_000);
    let copts = SrtOptions::default()
        .latency(latency)
        .bandwidth(Bandwidth::Max { bytes_per_sec: 200_000 });
    let lopts = SrtOptions::default().latency(latency);
    let mut sim = Sim::new(t0, copts, lopts, 0x9ACE);
    sim.run_until(100, "handshake", Sim::both_established);

    // One 1316-byte payload per 3 ms ≈ 438_667 B/s payload against the
    // 200_000 B/s wire ceiling. Period = trunc(1e6·(1316+44)/200_000) =
    // 6800 µs (§3.3.1): a 200 ms window holds ~29.4 paced slots plus one
    // free probe slot per 16 new packets (`seq & 0xF == 0` schedules the
    // follower at the same instant, §3.3.4) — 31±1 packets.
    let mut i: u32 = 0;
    let mut marks = Vec::new();
    for tick in 0u64 .. 2_000 {
        if tick.is_multiple_of(3) {
            sim.send_caller(payload_1316(0xA, i));
            i += 1;
        }
        if tick >= 600 && tick.is_multiple_of(200) {
            marks.push(sim.caller.stats().bytes_sent);
        }
        sim.step();
    }

    let st = sim.caller.stats();
    assert_eq!(st.snd_max_bw, 200_000, "a fixed ceiling must never move");
    assert_eq!(st.snd_period_us, 6_800, "period must match the §3.3.1 formula");
    assert_eq!(st.snd_input_rate, 0, "Max mode never runs the estimator");
    for (n, w) in marks.windows(2).enumerate() {
        let sent = w[1] - w[0];
        assert!(
            (39_000 ..= 44_000).contains(&sent),
            "window {n} sent {sent} payload B/200 ms: must hold ≈200_000 B/s \
             on the wire (30-33 packets), not the ~438_667 B/s input"
        );
    }

    // The feed stops at 2 s with a ~350-packet backlog; it drains at the
    // ceiling (~2.3 s worst-case send lag, inside the 3 s latency budget),
    // so every payload still arrives in order with zero drops anywhere.
    sim.run_for(3_400);
    assert_contiguous(&sim.listener_rx, 0xA, i);
    assert_eq!(sim.listener_rx.len(), i as usize);
    let cs = sim.caller.stats();
    let ls = sim.accepted_mut().stats();
    assert_eq!(cs.pkts_send_dropped, 0, "backlog must fit the latency budget");
    assert_eq!(ls.pkts_recv_dropped, 0, "paced packets must beat their deadlines");
    assert_eq!(cs.pkts_retransmitted, 0, "clean link needs no rexmits");
}

/// The SRTO_OHEADBW target mode end to end: a CBR feed converges the
/// estimator to the exact input rate and the ceiling follows
/// withOverhead(measured) (§3.3.2-§3.3.3); after a short outage the rexmit
/// backlog drains paced at ≈1.25× the input — across many steps, never as a
/// one-step burst — with zero drops on either side.
#[test]
fn estimated_rate_with_overhead_drains_backlog_paced() {
    let t0 = Instant::now();
    // 400 ms latency is the ARQ budget for the 250 ms outage below: the
    // oldest lost packet is retransmitted ~30 ms after the link returns.
    let latency = Duration::from_millis(400);
    let copts = SrtOptions::default()
        .latency(latency)
        .bandwidth(Bandwidth::Estimated { min_bytes_per_sec: 0, overhead_pct: 25 });
    let lopts = SrtOptions::default().latency(latency);
    let mut sim = Sim::new(t0, copts, lopts, 0xE571);
    sim.run_until(100, "handshake", Sim::both_established);

    // CBR: one 1316-byte payload per 10 ms = 131_600 B/s payload =
    // 136_000 B/s on the wire (+44/pkt, §3.3.3). Every estimator window
    // closes on the same 10 ms grid, so the measured rate is exactly
    // 136_000 wherever the window boundaries fall.
    let mut i: u32 = 0;
    let feed = |sim: &mut Sim, ms: u64, i: &mut u32| {
        for tick in 0 .. ms {
            if tick.is_multiple_of(10) {
                sim.send_caller(payload_1316(0xA, *i));
                *i += 1;
            }
            sim.step();
        }
    };

    // ≥ 1.5 s: the 500 ms fast-start window and at least one 1 s running
    // window close, and full ACKs refresh the ceiling (§3.3.2).
    feed(&mut sim, 1_800, &mut i);
    let st = sim.caller.stats();
    assert_eq!(
        st.snd_input_rate, 136_000,
        "the estimator must measure the CBR feed exactly"
    );
    assert_eq!(
        st.snd_max_bw,
        with_overhead(136_000, 25),
        "ceiling must be withOverhead(measured) = 170_000"
    );
    assert_eq!(st.snd_period_us, 8_000, "period = trunc(1e6·(1316+44)/170_000)");

    // Outage shorter than every drop budget: ~25 in-flight packets die on
    // the wire and the feed keeps going.
    sim.to_listener.down = true;
    sim.to_caller.down = true;
    feed(&mut sim, 250, &mut i);
    sim.to_listener.down = false;
    sim.to_caller.down = false;

    // 100 ms for the gap NAK to land, then measure the drain: the 170_000
    // B/s ceiling caps rexmits + new data at ≈1.25× the input (25-27
    // packets per 200 ms incl. probe slots). The closed range excludes
    // both no-drain (input-only 26_320 B/200 ms) and a one-step flush.
    feed(&mut sim, 100, &mut i);
    let mut marks = vec![sim.caller.stats().bytes_sent];
    for _ in 0 .. 3 {
        feed(&mut sim, 200, &mut i);
        marks.push(sim.caller.stats().bytes_sent);
    }
    for (n, w) in marks.windows(2).enumerate() {
        let sent = w[1] - w[0];
        assert!(
            (30_000 ..= 38_500).contains(&sent),
            "drain window {n} sent {sent} payload B/200 ms: the backlog must \
             drain paced at ≈1.25× the 26_320 B/200 ms input, not in a burst"
        );
    }

    // Let the backlog finish and the last TSBPD windows flush.
    feed(&mut sim, 400, &mut i);
    sim.run_for(600);

    assert_contiguous(&sim.listener_rx, 0xA, i);
    let cs = sim.caller.stats();
    let ls = sim.accepted_mut().stats();
    assert!(cs.pkts_retransmitted > 0, "the outage must have cost rexmits");
    assert!(sim.to_caller.naks > 0, "recovery must be NAK-driven");
    assert_eq!(cs.pkts_send_dropped, 0, "backlog sized inside the drop budget");
    assert_eq!(ls.pkts_recv_dropped, 0, "every rexmit must beat its deadline");
}

/// `Bandwidth::Estimated` before the first 500 ms estimator window closes:
/// the ceiling is BW_INFINITE (libsrt fast-start grace, §3.3.3) whose
/// ~10 µs period vanishes inside a 1 ms step — a burst right after
/// establish must drain like the unpaced default.
#[test]
fn estimated_grace_is_unpaced_before_first_window() {
    let t0 = Instant::now();
    let copts = SrtOptions::default()
        .bandwidth(Bandwidth::Estimated { min_bytes_per_sec: 0, overhead_pct: 25 });
    let mut sim = Sim::new(t0, copts, SrtOptions::default(), 0x62ACE);
    sim.run_until(100, "handshake", Sim::both_established);

    let before = sim.caller.stats().pkts_sent;
    for i in 0 .. 100u32 {
        sim.send_caller(payload(0xA, i));
    }
    // Step 1 emits the first packet and arms the ~10 µs schedule; step 2
    // arrives with ~1 ms of lateness credit, so the rest of the burst goes
    // out back-to-back (the spec-blessed catch-up burst, §3.3.4).
    sim.step();
    sim.step();
    assert_eq!(
        sim.caller.stats().pkts_sent - before,
        100,
        "fast-start grace must be effectively unpaced"
    );

    sim.run_for(300);
    let st = sim.caller.stats();
    assert_eq!(st.snd_input_rate, 0, "no estimator window closed within 500 ms");
    assert_eq!(
        st.snd_max_bw,
        with_overhead(BW_INFINITE, 25),
        "grace ceiling = withOverhead(BW_INFINITE) after the first refresh"
    );
    assert_contiguous(&sim.listener_rx, 0xA, 100);
    assert_eq!(sim.accepted_mut().stats().pkts_recv_dropped, 0);
}

/// Default options in the sim: no pacer exists, a 200-packet burst still
/// drains within a single 1 ms step and the pacing gauges stay 0. Pins
/// divergence D1 (transmission.md §3.3.2) against future default flips:
/// `Unlimited` disables the gate outright instead of pacing at libsrt's
/// BW_INFINITE default.
#[test]
fn default_options_remain_unpaced_in_sim() {
    let t0 = Instant::now();
    let mut sim = Sim::new(t0, SrtOptions::default(), SrtOptions::default(), 0xDEFA);
    sim.run_until(100, "handshake", Sim::both_established);

    let before = sim.caller.stats().pkts_sent;
    for i in 0 .. 200u32 {
        sim.send_caller(payload(0xA, i));
    }
    sim.step();
    assert_eq!(
        sim.caller.stats().pkts_sent - before,
        200,
        "an unpaced burst must hit the wire within one step"
    );
    let st = sim.caller.stats();
    assert_eq!(st.snd_period_us, 0, "pacing disabled reports a 0 period");
    assert_eq!(st.snd_max_bw, 0, "pacing disabled reports a 0 ceiling");
    assert_eq!(st.snd_input_rate, 0, "no estimator without a pacer");

    sim.run_for(300);
    assert_contiguous(&sim.listener_rx, 0xA, 200);
    assert_eq!(sim.accepted_mut().stats().pkts_recv_dropped, 0);
}

/// 5% loss + reorder under a fixed ceiling with ≈1.3× headroom over the
/// input: retransmissions share the paced budget (rexmits are gated by the
/// same period as new data, §3.3.4) and every payload must still beat its
/// TSBPD deadline.
#[test]
fn pacing_with_loss_keeps_arq_alive() {
    let t0 = Instant::now();
    // Latency high enough to absorb NAK retry cycles (including the
    // initial 300 ms periodic-NAK interval before the first RTT-based
    // recompute), as in five_percent_loss_recovers_everything.
    let latency = Duration::from_millis(400);
    let copts = SrtOptions::default()
        .latency(latency)
        .bandwidth(Bandwidth::Max { bytes_per_sec: 180_000 });
    let lopts = SrtOptions::default().latency(latency);
    let mut sim = Sim::new(t0, copts, lopts, 0xA21F);
    sim.to_listener.loss_pct = 5;
    sim.to_caller.loss_pct = 5;
    sim.to_listener.jitter_us = 2_000;
    sim.to_caller.jitter_us = 2_000;

    sim.run_until(2_000, "handshake under loss", Sim::both_established);

    // 100 pkt/s of 1316-byte payloads = 136_000 B/s wire against the
    // 180_000 B/s ceiling (~132 pkt/s): ~1.3× headroom for rexmits.
    const N: u32 = 300;
    for i in 0 .. N {
        sim.send_caller(payload_1316(0xA, i));
        sim.run_for(10);
    }
    // Trailing traffic so a lost tail packet still gets its gap detected.
    for i in N .. N + 10 {
        sim.send_caller(payload_1316(0xA, i));
        sim.run_for(20);
    }
    sim.run_for(1_500);

    assert_contiguous(&sim.listener_rx, 0xA, N);
    let cs = sim.caller.stats();
    let ls = sim.accepted_mut().stats();
    assert_eq!(cs.snd_max_bw, 180_000);
    assert_eq!(
        cs.snd_period_us, 7_555,
        "pacing must be engaged: trunc(1e6·(1316+44)/180_000)"
    );
    assert!(cs.pkts_retransmitted > 0, "caller must have retransmitted");
    assert!(ls.pkts_recv_lost > 0, "losses must have been detected");
    assert!(sim.to_caller.naks > 0, "recovery must be NAK-driven");
    assert_eq!(
        ls.pkts_recv_dropped, 0,
        "recovery must beat every deadline while sharing the paced budget"
    );
    assert_eq!(cs.pkts_send_dropped, 0);
}
