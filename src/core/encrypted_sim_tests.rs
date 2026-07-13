//! Pure in-memory simulation of two encrypted `Connection`s joined by a
//! deterministic channel — the KM-exchange counterpart of
//! `tests/core_sim.rs` (same harness pattern, targeted losses instead of
//! random ones).
//!
//! No tokio, no UDP, no sleeping: a fake clock advances in 1 ms steps and
//! every protocol rule runs off the explicit `now` passed into the sans-I/O
//! core. The channel drops exactly the packets each scenario targets
//! (in-stream KMREQ / KMRSP / chosen data sequences), so every run is fully
//! reproducible and the assertions can be exact.
//!
//! Covered (docs/spec/encryption.md):
//! - lost KMRSPs: the KMREQ is retried at 1.5 × SRTT pacing until an echo
//!   confirms, and the refresh completes (§10.4, §11.2);
//! - lost KMREQs: retries deliver the refresh KM before the key switch
//!   (§11.2);
//! - refresh racing loss recovery: retransmitted old-KK packets decrypt
//!   through the decommission window (§9.3, §10.4);
//! - retry exhaustion: exactly 1 + 10 KMREQ sends, then the sender switches
//!   at RR anyway; the peer drops new-key packets, the connection survives
//!   (§11.2);
//! - undecryptable packets are ACKed and reveal no NAKs — no NAK storm, no
//!   retransmission, the receive cursor advances past suppressed gaps
//!   (§9.4).

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

use bytes::Bytes;

use crate::{
    core::{
        ConnState,
        Connection,
        Listener,
        ListenerAction,
        Timebase,
    },
    packet::{
        ControlPacket,
        ControlType,
        EncryptionFlags,
        Packet,
        SeqNumber,
        SocketId,
    },
    SrtOptions,
};

const CALLER_ID: SocketId = SocketId(0x1111_2222);
const ACCEPT_ID: SocketId = SocketId(0x0BAD_CAFE);
const CALLER_ISN: SeqNumber = SeqNumber::new(0x0012_3456);
/// Unused by design: the listener adopts the caller's ISN.
const LISTENER_ISN: SeqNumber = SeqNumber::new(7);
const STEP: Duration = Duration::from_millis(1);

/// Passphrase for both ends (10..=80 bytes, encryption.md §2). Only ever
/// passed through options — never logged, never asserted on.
const PASSPHRASE: &str = "correct horse battery staple";

fn caller_addr() -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 50_000)
}

fn listener_addr() -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 9000)
}

/// Encrypted options with a tiny refresh cycle: `refresh = (rr, pa)` maps
/// to SRTO_KMREFRESHRATE / SRTO_KMPREANNOUNCE (encryption.md §10.1), so a
/// whole pre-announce → switch → decommission cycle fits in a short run.
fn crypto_opts(refresh: Option<(u32, u32)>) -> SrtOptions {
    SrtOptions {
        passphrase: Some(PASSPHRASE.to_string().into()),
        km_refresh_rate: refresh.map(|(rr, _)| rr),
        km_preannounce: refresh.map(|(_, pa)| pa),
        ..SrtOptions::default()
    }
}

/// One data packet actually put on the wire (post drop rules).
struct DataEvent {
    at: Instant,
    seq: u32,
    kk: EncryptionFlags,
    retransmitted: bool,
}

/// One direction of the simulated network path: fixed 5 ms delay, in-order
/// delivery, targeted drops, and wire observability for assertions.
struct Link {
    delay: Duration,
    /// Drop the next N in-stream KMREQ control packets.
    drop_kmreqs: u32,
    /// Drop the next N in-stream KMRSP control packets.
    drop_kmrsps: u32,
    /// Drop every in-stream KMREQ, forever (retry-exhaustion scenarios).
    drop_all_kmreqs: bool,
    /// Drop every ACKACK: the peer receiver then re-announces its ACK
    /// position at RTT cadence (transmission.md §5.1 rule 4), keeping the
    /// ACK-driven refresh machine ticking across unrepaired holes.
    drop_all_ackacks: bool,
    /// Data sequences to drop; one entry is consumed per matching packet,
    /// so listing a seq twice also kills its first retransmission.
    drop_data_seqs: Vec<u32>,
    /// In flight: (arrival, insertion order, packet).
    queue: Vec<(Instant, u64, Packet)>,
    counter: u64,
    // -- Wire observability --------------------------------------------------
    /// Every KMREQ push, dropped or not: what the sender put on the wire.
    kmreq_sends: Vec<(Instant, Vec<u8>)>,
    /// KMREQs that survived the drop rules (actually delivered).
    kmreqs_through: u64,
    /// Every KMRSP push, dropped or not.
    kmrsps: Vec<Vec<u8>>,
    /// NAK control packets pushed (none are ever dropped here).
    naks: u64,
    /// Data packets that actually went on the wire.
    data_wire: Vec<DataEvent>,
    /// Highest ACK position (next-expected sequence) seen on this link.
    max_ack: Option<SeqNumber>,
}

impl Link {
    fn new() -> Link {
        Link {
            delay: Duration::from_millis(5),
            drop_kmreqs: 0,
            drop_kmrsps: 0,
            drop_all_kmreqs: false,
            drop_all_ackacks: false,
            drop_data_seqs: Vec::new(),
            queue: Vec::new(),
            counter: 0,
            kmreq_sends: Vec::new(),
            kmreqs_through: 0,
            kmrsps: Vec::new(),
            naks: 0,
            data_wire: Vec::new(),
            max_ack: None,
        }
    }

    fn push(&mut self, now: Instant, pkt: Packet) {
        match &pkt {
            Packet::Data(d) => {
                if let Some(i) = self
                    .drop_data_seqs
                    .iter()
                    .position(|s| *s == d.seq.value())
                {
                    self.drop_data_seqs.remove(i);
                    return;
                }
                self.data_wire.push(DataEvent {
                    at: now,
                    seq: d.seq.value(),
                    kk: d.encryption,
                    retransmitted: d.retransmitted,
                });
            }
            Packet::Control(c) => match &c.control_type {
                ControlType::KmReq(blob) => {
                    // Logged before the drop decision: this is what the
                    // sender attempted, which is what §11.2 constrains.
                    self.kmreq_sends.push((now, blob.clone()));
                    if self.drop_all_kmreqs {
                        return;
                    }
                    if self.drop_kmreqs > 0 {
                        self.drop_kmreqs -= 1;
                        return;
                    }
                    self.kmreqs_through += 1;
                }
                ControlType::KmRsp(blob) => {
                    self.kmrsps.push(blob.clone());
                    if self.drop_kmrsps > 0 {
                        self.drop_kmrsps -= 1;
                        return;
                    }
                }
                ControlType::AckAck { .. } if self.drop_all_ackacks => return,
                ControlType::Nak(_) => self.naks += 1,
                ControlType::Ack { cif, .. } => {
                    let better = self
                        .max_ack
                        .is_none_or(|m| cif.last_ack_seq.diff(m) > 0);
                    if better {
                        self.max_ack = Some(cif.last_ack_seq);
                    }
                }
                _ => {}
            },
        }
        self.counter += 1;
        self.queue.push((now + self.delay, self.counter, pkt));
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

    /// Wire KK flags of first-transmission data packets, in push order.
    fn first_send_flags(&self) -> Vec<EncryptionFlags> {
        self.data_wire
            .iter()
            .filter(|e| !e.retransmitted)
            .map(|e| e.kk)
            .collect()
    }
}

/// The two endpoints plus the channel between them.
struct Sim {
    now: Instant,
    caller: Connection,
    listener: Listener,
    listener_opts: SrtOptions,
    accepted: Option<Connection>,
    /// caller → listener.
    to_listener: Link,
    /// listener → caller.
    to_caller: Link,
    /// Payloads delivered to the listener application.
    listener_rx: Vec<(Instant, Bytes)>,
}

impl Sim {
    fn new(now: Instant, caller_opts: SrtOptions, listener_opts: SrtOptions, seed: u64) -> Sim {
        let caller = Connection::connect(now, listener_addr(), CALLER_ID, CALLER_ISN, caller_opts);
        Sim {
            now,
            caller,
            listener: Listener::new(seed ^ 0x5EC2E7, Timebase::new(now), listener_opts.clone()),
            listener_opts,
            accepted: None,
            to_listener: Link::new(),
            to_caller: Link::new(),
            listener_rx: Vec::new(),
        }
    }

    fn accepted_mut(&mut self) -> &mut Connection {
        self.accepted
            .as_mut()
            .expect("listener has accepted a connection")
    }

    /// Advances the fake clock by one step and runs the event loop once.
    fn step(&mut self) {
        self.now += STEP;
        let now = self.now;

        // 1. Deliver arrived packets.
        for pkt in self.to_listener.pop_due(now) {
            match &mut self.accepted {
                Some(conn) => conn.handle_packet(now, pkt),
                None => self.listener_handshake(pkt),
            }
        }
        for pkt in self.to_caller.pop_due(now) {
            self.caller.handle_packet(now, pkt);
        }

        // 2. Timers, strictly when the connection says one is due.
        if timer_due(&self.caller, now) {
            self.caller.handle_timer(now);
        }
        if let Some(conn) = &mut self.accepted {
            if timer_due(conn, now) {
                conn.handle_timer(now);
            }
        }

        // 3. Drain outputs.
        while let Some(p) = self.caller.poll_transmit(now) {
            self.to_listener.push(now, p);
        }
        if let Some(conn) = &mut self.accepted {
            while let Some(p) = conn.poll_transmit(now) {
                self.to_caller.push(now, p);
            }
            while let Some(d) = conn.poll_deliver(now) {
                self.listener_rx.push((now, d));
            }
        }
    }

    /// Pre-accept path: handshake packets go to the stateless listener.
    fn listener_handshake(&mut self, pkt: Packet) {
        let Packet::Control(ControlPacket {
            control_type: ControlType::Handshake(cif),
            ..
        }) = pkt
        else {
            return; // nothing but handshakes reaches an unaccepted listener
        };
        match self
            .listener
            .handle_handshake(self.now, caller_addr(), &cif, ACCEPT_ID, LISTENER_ISN)
        {
            ListenerAction::Reply(p) => self.to_caller.push(self.now, p),
            ListenerAction::Accept { reply, negotiated } => {
                let conn = Connection::accepted(
                    self.now,
                    *negotiated,
                    reply,
                    self.listener_opts.clone(),
                );
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

    /// Establishes the pair; the handshake KMX (CONCLUSION-carried, §6)
    /// rides links that only target in-stream `UMSG_EXT` packets.
    fn establish(&mut self) {
        self.run_until(200, "encrypted handshake", Sim::both_established);
        assert!(
            self.to_listener.kmreq_sends.is_empty(),
            "initial KMX must ride the handshake, not UMSG_EXT (§6.1)"
        );
    }

    /// Streams caller payloads `start .. start + count`, one every
    /// `every_ms` fake ms.
    fn stream_caller(&mut self, start: u32, count: u32, every_ms: u64) {
        for i in start .. start + count {
            self.caller.send(self.now, payload(i)).unwrap();
            self.run_for(every_ms);
        }
    }
}

fn timer_due(conn: &Connection, now: Instant) -> bool {
    conn.next_deadline(now).is_some_and(|d| d <= now)
}

/// Numbered 64-byte payload; the index is recovered by `payload_index`.
fn payload(index: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(64);
    v.push(0xA);
    v.extend_from_slice(&index.to_le_bytes());
    v.resize(64, 0xA ^ 0x5A);
    v
}

fn payload_index(data: &[u8]) -> u32 {
    assert_eq!(data[0], 0xA, "unexpected payload tag");
    u32::from_le_bytes([data[1], data[2], data[3], data[4]])
}

/// Asserts `rx` is exactly payloads `0..count`, in order — i.e. every one
/// of them decrypted back to the original bytes.
fn assert_contiguous(rx: &[(Instant, Bytes)], count: u32) {
    assert_eq!(
        rx.len(),
        count as usize,
        "expected exactly {count} delivered payloads"
    );
    for (i, (_, data)) in rx.iter().enumerate() {
        assert_eq!(payload_index(data), i as u32, "payload {i} out of order");
    }
}

/// Wire seq of the caller's n-th payload (0-based): data starts at the ISN.
fn seq_of(index: u32) -> u32 {
    CALLER_ISN.value() + index
}

/// Asserts consecutive KMREQ sends respect the 1.5 × SRTT pacing (§11.2)
/// and resend identical bytes (§10.3). The sim's fixed 5 ms + 5 ms path
/// pins the measured SRTT at 10 ms, so the pace can never drop below
/// 15 ms — while ACKs tick every 10 ms, so an unpaced implementation that
/// resent on every ACK would fail the floor. The ceiling proves the
/// retries are actually flowing, not stalled.
fn assert_km_retry_pacing(sends: &[(Instant, Vec<u8>)]) {
    for (i, pair) in sends.windows(2).enumerate() {
        let gap = pair[1].0.duration_since(pair[0].0);
        assert!(
            gap >= Duration::from_millis(15),
            "KMREQ retry {i} after only {gap:?} (< 1.5 x SRTT)"
        );
        assert!(
            gap <= Duration::from_millis(350),
            "KMREQ retry {i} stalled for {gap:?}"
        );
        assert_eq!(
            pair[0].1, pair[1].1,
            "KMREQ retry {i} must resend identical bytes"
        );
    }
}

// ---------------------------------------------------------------------------

/// Every KMRSP for the refresh KMREQ is lost three times over: the caller
/// keeps re-sending the same KMREQ at 1.5 × SRTT pacing until an echo
/// finally arrives (§11.2), the responder re-echoes every duplicate
/// (§10.4), and the refresh cycle completes with nothing undecryptable.
#[test]
fn kmrsp_loss_kmreq_retried_until_echo_confirms() {
    let t0 = Instant::now();
    let mut sim = Sim::new(t0, crypto_opts(Some((16, 4))), crypto_opts(None), 0xE21);
    sim.to_caller.drop_kmrsps = 3;
    sim.establish();

    // rr = 16, pa = 4, initial counter 1 (§10.1): pre-announce on the ACK
    // after payload #12 (cnt 13 > 12), switch after #16 (cnt 17 > 16).
    // 26 payloads keep the run inside one refresh cycle (the second
    // pre-announce would need 12 more odd-key packets).
    sim.stream_caller(0, 26, 12);
    sim.run_for(500); // 120 ms latency + retry rounds + margin

    // Initial refresh KMREQ + one paced retry per lost echo; the 4th echo
    // confirms before a 5th send comes due (echo turnaround ≈ RTT, well
    // under the ≥ 15 ms pace). All sends byte-identical, dual-SEK (§3:
    // 72 bytes for AES-128).
    let sends = &sim.to_listener.kmreq_sends;
    assert!(
        (4 ..= 5).contains(&sends.len()),
        "expected the initial KMREQ plus ~3 paced retries, got {}",
        sends.len()
    );
    assert_eq!(sends[0].1.len(), 72, "refresh KM must be dual-SEK (§10.1)");
    assert_km_retry_pacing(sends);

    // §10.4 trap: every duplicate KMREQ is re-answered with the full echo.
    assert_eq!(
        sim.to_caller.kmrsps.len(),
        sends.len(),
        "each delivered KMREQ must be (re-)echoed"
    );
    assert!(
        sim.to_caller.kmrsps.iter().all(|b| *b == sends[0].1),
        "every KMRSP must echo the KMREQ byte-for-byte (§6.3)"
    );

    // The refresh completed: the KK bits flipped on the wire and every
    // payload — old key and new — decrypted and delivered in order.
    let flags = sim.to_listener.first_send_flags();
    assert!(flags.contains(&EncryptionFlags::Even));
    assert!(flags.contains(&EncryptionFlags::Odd), "switch must happen");
    assert_eq!(sim.caller.stats().km_refreshes, 1);
    assert_eq!(sim.accepted_mut().stats().undecrypted_pkts, 0);
    assert_contiguous(&sim.listener_rx, 26);
    assert!(sim.both_established());
    assert_eq!(sim.to_caller.naks, 0, "no loss, no NAK");
}

/// The refresh KMREQ itself is lost three times over: paced retries carry
/// the KM through before the sender's unconditional switch at RR, so the
/// receiver installs both SEKs in time and nothing is lost (§11.2).
#[test]
fn kmreq_loss_retries_deliver_the_refresh_km() {
    let t0 = Instant::now();
    // rr = 32, pa = 12: pre-announce on the ACK after payload #20
    // (cnt 21 > 20), switch after #32 — a 12-packet (~144 ms) window for
    // the ~20 ms-paced retries to win even with 3 KMREQs lost.
    let mut sim = Sim::new(t0, crypto_opts(Some((32, 12))), crypto_opts(None), 0xE22);
    sim.to_listener.drop_kmreqs = 3;
    sim.establish();

    sim.stream_caller(0, 44, 12);
    sim.run_for(500);

    // Initial send + 2 retries lost, the 4th send delivered and echoed.
    let sends = &sim.to_listener.kmreq_sends;
    assert!(
        (4 ..= 5).contains(&sends.len()),
        "expected 3 lost sends plus a delivered one, got {}",
        sends.len()
    );
    assert_km_retry_pacing(sends);
    assert_eq!(
        sim.to_listener.kmreqs_through,
        sends.len() as u64 - 3,
        "exactly 3 KMREQs were eaten by the wire"
    );
    // Only delivered KMREQs are echoed; the first echo confirms.
    assert_eq!(sim.to_caller.kmrsps.len() as u64, sim.to_listener.kmreqs_through);

    // Refresh completed in time: switch on the wire, zero undecryptable.
    let flags = sim.to_listener.first_send_flags();
    assert!(flags.contains(&EncryptionFlags::Odd), "switch must happen");
    assert_eq!(sim.caller.stats().km_refreshes, 1);
    assert_eq!(sim.accepted_mut().stats().undecrypted_pkts, 0);
    assert_contiguous(&sim.listener_rx, 44);
    assert!(sim.both_established());
}

/// A key refresh completes while loss recovery is still in flight: the
/// last even-key packet is lost (and its first retransmission too), so
/// its recovery lands only after the KK bits flipped on the wire — and
/// after the sender already decommissioned the old TX key (§10.1). The
/// stored ciphertext is retransmitted byte-identical with the original
/// even KK bits (§9.3) and the receiver still decrypts it: RX keys are
/// never proactively expired (§10.4 both-keys window).
///
/// The scenario needs ACKs to keep flowing across the unrepaired hole
/// (otherwise the ACK position pins at the hole once ACKACKed, the
/// ACK-driven refresh machine stalls, and the switch would always wait
/// for the recovery). Losing every ACKACK models exactly that: the
/// receiver re-announces its ACK position at RTT cadence
/// (transmission.md §5.1 rule 4), each re-announcement ticks §10.2, and
/// the switch overtakes the still-pending recovery.
#[test]
fn old_key_retransmissions_decrypt_through_decommission_window() {
    let t0 = Instant::now();
    // 400 ms latency: room for the immediate NAK round (retransmission
    // lost) plus the 300 ms periodic re-NAK round before the TSBPD
    // deadline of the lost packet.
    let copts = SrtOptions {
        latency: Duration::from_millis(400),
        ..crypto_opts(Some((16, 4)))
    };
    let lopts = SrtOptions {
        latency: Duration::from_millis(400),
        ..crypto_opts(None)
    };
    let mut sim = Sim::new(t0, copts, lopts, 0xE23);
    sim.establish();

    // Phase 1 (clean): payloads #0..=#12. The RTT estimate converges via
    // live ACKACKs and the pre-announce fires on the ACK after #12
    // (cnt 13 > 12), so the peer holds both SEKs from here on.
    sim.stream_caller(0, 13, 12);

    // Phase 2: the return path stops delivering ACKACKs, and payload #15
    // — the packet whose push crosses `cnt > rr` — dies on the wire twice
    // (first transmission and first retransmission). The re-announced
    // ACKs keep the refresh ticking: the switch fires while #15 is still
    // missing, and its recovery needs the 300 ms periodic re-NAK.
    sim.to_listener.drop_all_ackacks = true;
    sim.to_listener.drop_data_seqs = vec![seq_of(15), seq_of(15)];
    sim.stream_caller(13, 13, 12);
    sim.run_for(1_200); // periodic NAK + latency + margin

    // The recovery really was in flight across the switch: the even-key
    // (R=1) retransmission hit the wire after the first odd-key packet.
    let first_odd = sim
        .to_listener
        .data_wire
        .iter()
        .find(|e| e.kk == EncryptionFlags::Odd)
        .map(|e| e.at)
        .expect("switch must happen while the hole is outstanding");
    let late_rexmit = sim
        .to_listener
        .data_wire
        .iter()
        .find(|e| e.retransmitted && e.at > first_odd)
        .expect("an old-key retransmission must land after the switch");
    assert_eq!(late_rexmit.kk, EncryptionFlags::Even, "original KK bits (§9.3)");
    assert_eq!(late_rexmit.seq, seq_of(15));

    // Two retransmissions of the one packet (immediate NAK round eaten by
    // the wire, periodic re-NAK round delivered)...
    let cs = sim.caller.stats();
    assert_eq!(cs.pkts_retransmitted, 2, "two NAK rounds for one packet");
    assert_eq!(sim.to_caller.naks, 2, "immediate + periodic NAK");
    // ...and every payload decrypted and arrived in order: the receiver's
    // even RX key outlived the sender-side decommission.
    assert_eq!(cs.km_refreshes, 1);
    let ls = sim.accepted_mut().stats();
    assert_eq!(ls.undecrypted_pkts, 0);
    assert_eq!(ls.pkts_recv_dropped, 0, "recovery must beat the deadline");
    assert_contiguous(&sim.listener_rx, 26);
    assert!(sim.both_established());
}

/// Every in-stream KMREQ is eaten by the wire: the caller spends its whole
/// §11.2 budget (initial send + 10 paced retries), then goes silent — and
/// still switches to the new SEK at RR. The peer never learns the odd key:
/// its packets arrive undecryptable, are ACKed and never delivered, and
/// the connection survives on both ends.
#[test]
fn retry_exhaustion_switches_anyway_and_survives() {
    let t0 = Instant::now();
    // rr = 96, pa = 24: pre-announce after payload #72, switch after #96;
    // the ~20 ms-paced retry budget (~220 ms ≈ 18 payloads) exhausts well
    // before the switch, and the second pre-announce (72 odd-key packets
    // after the switch) stays out of reach.
    let mut sim = Sim::new(t0, crypto_opts(Some((96, 24))), crypto_opts(None), 0xE24);
    sim.to_listener.drop_all_kmreqs = true;
    sim.establish();

    sim.stream_caller(0, 150, 12);
    sim.run_for(600);

    // Exactly the §11.2 budget: 1 immediate send + 10 paced retries, all
    // byte-identical, then silence forever.
    let sends = &sim.to_listener.kmreq_sends;
    assert_eq!(
        sends.len(),
        11,
        "KMREQ budget is one send plus SRT_MAX_KMRETRY = 10 retries"
    );
    assert_km_retry_pacing(sends);
    assert!(sim.to_caller.kmrsps.is_empty(), "nothing to echo");

    // The switch happened regardless (§11.2 trap): even first, then odd,
    // never interleaved (no losses → no retransmissions here).
    let flags = sim.to_listener.first_send_flags();
    assert_eq!(flags.len(), 150);
    let odd_start = flags
        .iter()
        .position(|kk| *kk == EncryptionFlags::Odd)
        .expect("sender must switch at RR without confirmation");
    assert!(flags[.. odd_start]
        .iter()
        .all(|kk| *kk == EncryptionFlags::Even));
    assert!(flags[odd_start ..]
        .iter()
        .all(|kk| *kk == EncryptionFlags::Odd));
    // ACK-driven evaluation makes the exact flip index tick-dependent,
    // but it must sit right after the rr = 96 threshold.
    assert!(
        (96 ..= 98).contains(&odd_start),
        "switch at payload #{odd_start}, expected right after RR"
    );
    assert_eq!(sim.caller.stats().km_refreshes, 1);

    // Every odd-key packet arrived undecryptable — ACKed, counted, never
    // delivered — and the connection stayed up on both sides (§9.4).
    let odd_count = (flags.len() - odd_start) as u64;
    let ls = sim.accepted_mut().stats();
    assert_eq!(ls.undecrypted_pkts, odd_count);
    assert_contiguous(&sim.listener_rx, odd_start as u32);
    assert!(sim.both_established(), "exhaustion must not kill the link");
}

/// No NAK storm for undecryptable traffic (§9.4): arrived-but-undecryptable
/// packets are ACKed like any other, and a genuinely lost packet whose gap
/// is revealed by an undecryptable successor is never NAKed — the receive
/// cursor advances past it unconditionally and the sender retransmits
/// nothing.
#[test]
fn undecryptable_arrivals_are_acked_and_reveal_no_naks() {
    let t0 = Instant::now();
    let mut sim = Sim::new(t0, crypto_opts(Some((96, 24))), crypto_opts(None), 0xE25);
    sim.to_listener.drop_all_kmreqs = true;
    // Payload #109 (0-based) is deep in the undecryptable odd-key stretch;
    // its gap is revealed by undecryptable packet #110.
    sim.to_listener.drop_data_seqs = vec![seq_of(109)];
    sim.establish();

    sim.stream_caller(0, 150, 12);
    sim.run_for(600);

    // No NAK ever crossed the wire — neither for the undecryptable
    // arrivals nor for the suppressed gap — and nothing was retransmitted.
    assert_eq!(sim.to_caller.naks, 0, "loss detection must be suppressed");
    assert_eq!(sim.caller.stats().pkts_retransmitted, 0);
    let ls = sim.accepted_mut().stats();
    assert_eq!(ls.pkts_recv_lost, 0, "the gap must never enter the loss list");

    // ...while the ACK position marched past every undecryptable packet
    // AND the suppressed hole, up to the final send position.
    assert_eq!(
        sim.to_caller.max_ack,
        Some(SeqNumber::new(seq_of(149)).next()),
        "undecryptable packets and suppressed gaps must still be ACKed"
    );

    // Bookkeeping matches the wire: all delivered even-key payloads, every
    // odd-key arrival counted undecryptable (the dropped #109 never
    // arrived), connection intact.
    let flags = sim.to_listener.first_send_flags();
    assert_eq!(flags.len(), 149, "one data packet died on the wire");
    let odd_wire = flags
        .iter()
        .filter(|kk| **kk == EncryptionFlags::Odd)
        .count() as u64;
    assert_eq!(ls.undecrypted_pkts, odd_wire);
    assert_contiguous(&sim.listener_rx, (flags.len() as u64 - odd_wire) as u32);
    assert!(sim.both_established());
}
