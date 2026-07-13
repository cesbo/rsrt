//! Live-mode data sender (sans-I/O): send buffer, ARQ, TLPKTDROP.
//!
//! Protocol reference: docs/spec/transmission.md.
//!
//! Responsibilities:
//! - assign sequence numbers, message numbers (PP=Only; O=0 — libsrt's live profile submits with
//!   `inorder = false`) and timestamps to outgoing payloads and keep them buffered for
//!   retransmission;
//! - with crypto, encrypt each payload in place at buffering time and store the returned KK bits:
//!   the buffer holds ciphertext, so the first send and every retransmission emit byte-identical
//!   payload and KK bits (docs/spec/encryption.md §9.3);
//! - on ACK: release acknowledged packets, reply with ACKACK (non-light ACKs only, throttled),
//!   track the peer's advertised receive-buffer window, and adopt the peer receiver's SRTT/RTTVar
//!   pair from the full-ACK CIF (docs/spec/transmission.md §6 step 9);
//! - on NAK: queue retransmissions (R flag set) for packets still buffered; ranges no longer
//!   buffered turn into a DROPREQ; a retransmission whose predecessor is still in flight (within
//!   SRTT - 4*RTTVar) is suppressed (SRTO_RETRANSMITALGO=1, docs/spec/transmission.md §7.5 step 2);
//! - too-late packet drop: packets buffered longer than the drop threshold (based on `snd_latency`)
//!   are dropped and announced with DROPREQ;
//! - respect the in-flight window: min(flow window, peer's advertised available buffer). In live
//!   mode, overflow drops the *oldest* buffered packet (data is perishable) rather than blocking.
//!
//! Internally every buffered packet is tracked by a non-wrapping u64
//! "extended index" (0 = the packet with sequence `initial_seq`); wire
//! sequence numbers are derived at the edges. This keeps all buffer, loss
//! list and window math free of mod-2^31 pitfalls.

use std::{
    collections::{
        BTreeSet,
        VecDeque,
    },
    time::{
        Duration,
        Instant,
    },
};

use tracing::{
    debug,
    trace,
    warn,
};

use super::{
    pacing::Pacer,
    time::Timebase,
};
use crate::{
    crypto::Crypto,
    error::{
        CloseReason,
        SrtError,
    },
    options::Bandwidth,
    packet::{
        AckCif,
        ControlType,
        DataPacket,
        EncryptionFlags,
        LossRange,
        MsgNumber,
        PacketPosition,
        SeqNumber,
        SocketId,
        Timestamp,
    },
};

/// ACKACK throttle: reply to a non-light ACK only if more than this passed
/// since the last ACKACK, or the same ACK number repeats (previous ACKACK
/// lost). Strictly greater-than, per docs/spec/transmission.md §5.1.
const ACKACK_THROTTLE: Duration = Duration::from_millis(10);

/// `SRT_TLPKTDROP_MINTHRESHOLD_MS`: keep at least 1 s of data regardless of
/// how small the negotiated latency is (docs/spec/transmission.md §8.1).
const TLPKTDROP_MIN_THRESHOLD: Duration = Duration::from_millis(1000);

/// `2 * COMM_SYN_INTERVAL`: sender + receiver reaction time added on top of
/// the TLPKTDROP threshold (docs/spec/transmission.md §8.1).
const TLPKTDROP_REACTION: Duration = Duration::from_millis(20);

/// Pre-measurement RTT state (`INITIAL_RTT` / `INITIAL_RTTVAR`), also the
/// gate values for adopting ACK-carried RTT (docs/spec/transmission.md §6
/// step 9). Mirrors the receiver's constants.
const INITIAL_RTT_US: u32 = 100_000;
const INITIAL_RTT_VAR_US: u32 = 50_000;

/// Sender configuration derived from options + [`super::Negotiated`].
#[derive(Clone, Debug)]
pub struct SenderConfig {
    pub initial_seq: SeqNumber,
    /// Max packets in flight: min(local flow_window, peer flow_window).
    pub flow_window: u32,
    /// Effective latency of the direction we send in; the TLPKTDROP
    /// threshold derives from it (docs/spec/transmission.md).
    pub snd_latency: Duration,
    pub max_payload: usize,
    /// Send buffer capacity in packets.
    pub buffer_pkts: usize,
    /// Pacing mode (validated at connect/bind; `Bandwidth::Unlimited` ⇒ no
    /// pacer — docs/spec/transmission.md §3.3).
    pub bandwidth: Bandwidth,
    /// Stamps outgoing data packets.
    pub timebase: Timebase,
}

/// Counters the sender maintains (merged into [`super::Stats`]).
///
/// `pkts_sent`/`bytes_sent` include retransmissions (libsrt `pktSent`
/// semantics); `bytes_sent` counts payload bytes only (no header overhead).
#[derive(Clone, Copy, Debug, Default)]
pub struct SenderStats {
    pub pkts_sent: u64,
    pub bytes_sent: u64,
    pub pkts_retransmitted: u64,
    pub pkts_dropped: u64,
    /// Current inter-packet send interval, µs (libsrt usPktSndPeriod).
    /// 0 = pacing disabled (Bandwidth::Unlimited).
    pub snd_period_us: u64,
    /// Effective pacing ceiling, bytes/s (libsrt mbpsMaxBW analog, kept in
    /// bytes/s to match the option units). In Estimated mode this is
    /// max(min, measured)·(100+overhead)/100 once the estimator has closed
    /// a window; before that the fast-start grace reads the overheaded
    /// BW_INFINITE·(100+overhead)/100 (156_250_000 at the default 25 %)
    /// from the first refresh event (full ACK / NAK / timer tick) on —
    /// plain BW_INFINITE (125_000_000) appears only until that first
    /// refresh. 0 = pacing disabled.
    pub snd_max_bw: u64,
    /// Last measured sender input rate, bytes/s incl. +44/pkt header charge
    /// (crate extension — libsrt 1.4.4 bstats has no such field).
    /// 0 unless Bandwidth::Estimated and at least one window has closed.
    pub snd_input_rate: u64,
}

/// One buffered (scheduled or sent, not yet acknowledged) packet. The
/// sequence number is implicit: buffer front is `base_index`.
struct BufEntry {
    msg: MsgNumber,
    /// Submission time; drives TLPKTDROP.
    origin: Instant,
    /// Wire timestamp taken at submission. Retransmissions MUST reuse it —
    /// restamping breaks the peer's TSBPD (docs/spec/NOTES.md).
    ts: Timestamp,
    /// When this packet was last *re*transmitted (libsrt `RexmitTime`;
    /// `None` until the first retransmission — first transmissions never
    /// stamp it). Drives the §7.5 retransmission throttle.
    last_rexmit: Option<Instant>,
    /// KK bits sampled from the active SEK when the payload was encrypted
    /// at buffering time (`None` without crypto). Emitted identically on
    /// the first send and every retransmission — the buffer holds
    /// ciphertext, never re-encrypted (docs/spec/encryption.md §9.3).
    encryption: EncryptionFlags,
    /// Payload as it goes on the wire: ciphertext when crypto is active.
    payload: Vec<u8>,
}

/// Live-mode sender state machine. All methods are non-blocking; time only
/// enters through the explicit `now` arguments.
pub struct Sender {
    cfg: SenderConfig,
    /// Buffered packets `[base_index ..)`, oldest first.
    buffer: VecDeque<BufEntry>,
    /// Extended index of the buffer front (`SndLastDataAck`): everything
    /// below is released (ACKed) or dropped.
    base_index: u64,
    /// Extended index of the next first-transmission packet
    /// (`incseq(SndCurrSeqNo)`).
    next_send_index: u64,
    /// Extended index of the first not-yet-ACKed sequence (`SndLastAck`);
    /// base of the in-flight window.
    last_ack_index: u64,
    /// Message number for the next submitted payload (starts at 1; wraps
    /// within 26 bits back to 1, never 0).
    next_msg: MsgNumber,
    /// Peer's advertised available receive buffer, in packets
    /// (`FlowWindowSize`). Updated by full ACKs, decremented by light ACKs.
    advertised_window: u32,
    /// Extended indices awaiting retransmission (sender loss list).
    loss_list: BTreeSet<u64>,
    /// DROPREQs owed to the peer.
    control_queue: VecDeque<ControlType>,
    /// Last ACK number answered with an ACKACK (`SndLastAck2`) + when.
    last_ackack_number: u32,
    last_ackack_time: Option<Instant>,
    /// Sender-side RTT/RTTVar estimate: the peer receiver's smoothed pair
    /// adopted from full-ACK CIF words 1-2 (docs/spec/transmission.md §6
    /// step 9). On a send-only socket this is the ONLY RTT source: no
    /// inbound data means the local receiver never emits an ACK, so no
    /// ACKACK ever samples the path.
    rtt_us: u32,
    rtt_var_us: u32,
    /// True once a first non-initial pair was adopted; before that, CIFs
    /// still carrying either initial value are skipped (peer has no real
    /// sample yet).
    rtt_adopted: bool,
    /// Set when the peer sent a NAK failing libsrt's attack validations
    /// (sequence never sent). libsrt breaks the connection here; since
    /// `handle_nak` cannot return an error, the connection layer should
    /// poll this flag after dispatching a NAK.
    protocol_violation: bool,
    /// LiveCC pacing gate (docs/spec/transmission.md §3.3); structurally
    /// absent for `Bandwidth::Unlimited` — the default path stays exactly
    /// as it was before pacing existed.
    pacer: Option<Pacer>,
    stats: SenderStats,
}

impl Sender {
    pub fn new(cfg: SenderConfig) -> Self {
        debug!(
            initial_seq = cfg.initial_seq.value(),
            flow_window = cfg.flow_window,
            snd_latency_ms = cfg.snd_latency.as_millis() as u64,
            buffer_pkts = cfg.buffer_pkts,
            bandwidth = ?cfg.bandwidth,
            "sender created"
        );
        Sender {
            advertised_window: cfg.flow_window,
            pacer: Pacer::new(&cfg.bandwidth, cfg.max_payload),
            cfg,
            buffer: VecDeque::new(),
            base_index: 0,
            next_send_index: 0,
            last_ack_index: 0,
            next_msg: MsgNumber::new(1),
            loss_list: BTreeSet::new(),
            control_queue: VecDeque::new(),
            last_ackack_number: 0,
            last_ackack_time: None,
            rtt_us: INITIAL_RTT_US,
            rtt_var_us: INITIAL_RTT_VAR_US,
            rtt_adopted: false,
            protocol_violation: false,
            stats: SenderStats::default(),
        }
    }

    /// Accepts one application message (≤ `max_payload` bytes) for
    /// transmission. Live mode never blocks: if the buffer or the in-flight
    /// window is full, the oldest packet is dropped to make room.
    ///
    /// With `crypto`, the payload is encrypted in place here and the
    /// returned KK bits are stored with the packet: the buffer holds
    /// ciphertext, and the first send and every retransmission emit
    /// byte-identical payload and KK bits (docs/spec/encryption.md §9.3).
    pub fn push(
        &mut self,
        now: Instant,
        mut payload: Vec<u8>,
        crypto: Option<&mut Crypto>,
    ) -> Result<(), SrtError> {
        if payload.len() > self.cfg.max_payload {
            return Err(SrtError::PayloadTooLarge(payload.len()));
        }

        // Input-rate estimator feed, at the application submit point only
        // (libsrt samples in `addBuffer`; docs/spec/transmission.md §3.3).
        // Sampled before the overflow drops below: in live mode every push
        // is accepted, matching libsrt where every addBuffer counts. The
        // pre-encryption length equals the wire payload length (AES-CTR
        // does not expand); retransmissions never reach this.
        if let Some(p) = &mut self.pacer {
            p.on_input(now, payload.len());
        }

        // Sender TLPKTDROP runs on every submit, before the new packet is
        // added (libsrt `checkNeedDrop`; docs/spec/transmission.md §8.1).
        self.check_tlpktdrop(now);

        // Live-mode overflow policy: drop the oldest packet(s).
        while !self.buffer.is_empty() && self.buffer.len() >= self.cfg.buffer_pkts {
            self.drop_front(1, false, "send buffer full");
        }
        while !self.buffer.is_empty() && self.flight() >= u64::from(self.effective_window()) {
            self.drop_front(1, false, "in-flight window full");
        }

        let index = self.base_index + self.buffer.len() as u64;
        let msg = self.next_msg;
        // Message numbers run 1..=0x03FF_FFFF then wrap back to 1; 0 means
        // "unknown" and is never assigned (docs/spec/NOTES.md).
        let succ = msg.next();
        self.next_msg = if succ.value() == 0 {
            MsgNumber::new(1)
        } else {
            succ
        };

        // Encrypt in place with the final wire seqno in the IV and record
        // the KK bits (docs/spec/encryption.md §9.3). libsrt encrypts at
        // first transmission; doing it at buffering time is equivalent —
        // the sequence assigned here is never restamped — and makes "read
        // active key + stamp KK + encrypt" atomic, as §9.3 demands.
        let encryption = match crypto {
            // §9.4: never encrypt a zero-length payload (HaiCrypt reports
            // it as failure; live mode never produces one).
            Some(crypto) if !payload.is_empty() => crypto.encrypt(self.seq_at(index), &mut payload),
            _ => EncryptionFlags::None,
        };

        let ts = self.cfg.timebase.timestamp(now);
        trace!(
            seq = self.seq_at(index).value(),
            msg = msg.value(),
            len = payload.len(),
            kk = ?encryption,
            "data packet queued"
        );
        self.buffer.push_back(BufEntry {
            msg,
            origin: now,
            ts,
            last_rexmit: None,
            encryption,
            payload,
        });
        Ok(())
    }

    /// Handles an incoming ACK. Returns the ACK number to echo as ACKACK
    /// (`None` for light ACKs, or when the 10 ms ACKACK throttle applies).
    ///
    /// An ACK for a sequence beyond highest-sent + 1 is a protocol
    /// violation: returns an error and the connection must be broken
    /// (docs/spec/transmission.md §6 step 5).
    pub fn handle_ack(
        &mut self,
        now: Instant,
        ack_number: u32,
        cif: &AckCif,
    ) -> Result<Option<u32>, SrtError> {
        let ack_ext = self.ext_of(cif.last_ack_seq);
        // A 4-byte CIF (only the sequence field) is a Light ACK.
        let is_light = cif.rtt_us.is_none();
        trace!(
            ack_number,
            ack_seq = cif.last_ack_seq.value(),
            is_light,
            "ACK received"
        );

        // ACK for data never sent: attack or bug.
        if ack_ext > self.next_send_index as i64 {
            warn!(
                ack_seq = cif.last_ack_seq.value(),
                highest_sent = self.seq_at(self.next_send_index).prev().value(),
                "ACK beyond highest sent sequence: breaking connection"
            );
            self.protocol_violation = true;
            return Err(SrtError::Closed(CloseReason::Local));
        }

        // Release the send buffer below the ACKed sequence — done for light
        // and full ACKs alike (docs/spec/transmission.md §6 step 2).
        if ack_ext > self.base_index as i64 {
            let n = ((ack_ext - self.base_index as i64) as u64).min(self.buffer.len() as u64);
            self.buffer.drain(.. n as usize);
            self.base_index += n;
            // Loss entries below the released region are obsolete.
            self.loss_list = self.loss_list.split_off(&self.base_index);
            debug!(
                released = n,
                ack_seq = cif.last_ack_seq.value(),
                "send buffer released"
            );
        }

        if is_light {
            // Light ACK: consume window credit, no ACKACK
            // (docs/spec/transmission.md §6 step 3).
            if ack_ext >= self.last_ack_index as i64 {
                let off = (ack_ext - self.last_ack_index as i64) as u64;
                self.advertised_window = self
                    .advertised_window
                    .saturating_sub(off.min(u64::from(u32::MAX)) as u32);
                self.last_ack_index = ack_ext as u64;
            }
            return Ok(None);
        }

        // Adopt the peer receiver's smoothed SRTT/RTTVar from the full-ACK
        // CIF (docs/spec/transmission.md §6 step 9). Until the first
        // adoption, a CIF still carrying *either* initial value means the
        // peer receiver has no ACKACK sample yet — skip it (the gate must
        // be the &&-of-both-differ form: after adoption RTTVar legitimately
        // converges to 0 on clean paths, so values equal to an initial one
        // become meaningful and the pair is copied as-is on every full ACK,
        // which §6 step 9 blesses even for bidirectional sockets).
        // Deviation from §6 step 7: duplicate full ACKs
        // (seqoff(SndLastFullAck, ackseq) <= 0) are not filtered here;
        // re-adopting the peer's already-smoothed pair on a repeat is
        // behaviorally harmless, so SndLastFullAck is not tracked.
        if let (Some(rtt), Some(rtt_var)) = (cif.rtt_us, cif.rtt_var_us) {
            if self.rtt_adopted || (rtt != INITIAL_RTT_US && rtt_var != INITIAL_RTT_VAR_US) {
                trace!(rtt, rtt_var, "RTT adopted from ACK");
                self.rtt_us = rtt;
                self.rtt_var_us = rtt_var;
                self.rtt_adopted = true;
            }
        }

        // ACKACK reply decision — before the sanity check, like libsrt
        // (docs/spec/transmission.md §5.1): send unless throttled; a
        // repeated ACK number means the previous ACKACK was lost.
        let throttle_open = self
            .last_ackack_time
            .is_none_or(|t| now.duration_since(t) > ACKACK_THROTTLE);
        let ackack = if throttle_open || ack_number == self.last_ackack_number {
            self.last_ackack_number = ack_number;
            self.last_ackack_time = Some(now);
            Some(ack_number)
        } else {
            None
        };

        if ack_ext >= self.last_ack_index as i64 {
            // Adopt the peer's advertised available buffer as the flow
            // window (docs/spec/transmission.md §6 step 6).
            if let Some(avail) = cif.avail_buf_pkts {
                if avail != self.advertised_window {
                    debug!(avail, "peer advertised window updated");
                }
                self.advertised_window = avail;
            }
            self.last_ack_index = ack_ext as u64;
        }

        // Pacing-rate refresh on full ACKs only (TEV_ACK): light ACKs
        // returned above — libsrt lite ACKs never reach updateCC
        // (core.cpp:8027-8042). Unlike libsrt, non-advancing duplicate
        // full ACKs refresh too — idempotent math, spec-marked
        // simplification (docs/spec/transmission.md §3.3).
        if let Some(p) = &mut self.pacer {
            p.refresh();
        }

        Ok(ackack)
    }

    /// Handles an incoming NAK: queues retransmissions / DROPREQs.
    ///
    /// A NAK naming a sequence never sent is a protocol violation (libsrt
    /// breaks the connection): processing stops and
    /// [`Sender::protocol_violation`] is raised.
    pub fn handle_nak(&mut self, _now: Instant, ranges: &[LossRange]) {
        trace!(ranges = ranges.len(), "NAK received");
        for range in ranges {
            let lo = self.ext_of(range.first);
            let hi = self.ext_of(range.last);
            // The packet codec already rejects ranges with first > last;
            // guard anyway (same reaction as libsrt: treat as attack).
            if lo > hi || hi >= self.next_send_index as i64 {
                warn!(
                    first = range.first.value(),
                    last = range.last.value(),
                    highest_sent = self.seq_at(self.next_send_index).prev().value(),
                    "NAK for a sequence never sent: protocol violation"
                );
                self.protocol_violation = true;
                return;
            }
            let last_ack = self.last_ack_index as i64;
            if lo >= last_ack {
                for i in lo ..= hi {
                    self.loss_list.insert(i as u64);
                }
                trace!(
                    first = range.first.value(),
                    last = range.last.value(),
                    "loss queued"
                );
            } else if hi >= last_ack {
                // Clip the already-acknowledged/dropped head of the range.
                for i in last_ack ..= hi {
                    self.loss_list.insert(i as u64);
                }
                trace!(
                    first = range.first.value(),
                    last = range.last.value(),
                    clipped_to = self.seq_at(last_ack as u64).value(),
                    "stale NAK head clipped"
                );
            } else if range.first != range.last {
                // A whole *range* no longer buffered: tell the receiver to
                // stop NAKing it (docs/spec/transmission.md §7.4). Message
                // number 0 = drop by range only.
                debug!(
                    first = range.first.value(),
                    last = range.last.value(),
                    "NAK for released range: replying DROPREQ"
                );
                self.control_queue.push_back(ControlType::DropRequest {
                    msg_number: MsgNumber::new(0),
                    first: range.first,
                    last: range.last,
                });
            }
            // A stale *single* sequence is ignored silently (§7.4).
        }
        // Pacing-rate refresh (TEV_LOSSREPORT,
        // docs/spec/transmission.md §3.3).
        if let Some(p) = &mut self.pacer {
            p.refresh();
        }
    }

    /// Runs time-based duties (TLPKTDROP scan, pacing-rate refresh).
    pub fn on_timer(&mut self, now: Instant) {
        self.check_tlpktdrop(now);
        // TEV_CHECKTIMER refresh (docs/spec/transmission.md §3.3): with a
        // live peer, full ACKs every 10 ms dominate the cadence exactly as
        // in libsrt; this additionally fires at pace/TLPKTDROP/keepalive
        // deadlines.
        if let Some(p) = &mut self.pacer {
            p.refresh();
        }
    }

    /// Next data packet to put on the wire (retransmissions take priority
    /// over first transmissions). The destination socket id is left 0: the
    /// connection layer stamps it with the peer's id.
    pub fn poll_transmit(&mut self, now: Instant) -> Option<DataPacket> {
        // Pacing gate (docs/spec/transmission.md §3.3; packData
        // core.cpp:8978-8981): a future schedule blocks the whole data
        // path — retransmissions bypass the flow window but NOT pacing.
        // Past-due entry lateness accrues as SendTimeDiff credit, spent by
        // `on_send` to emit back-to-back; accrual happens at most once per
        // scheduled instant because every exit below rewrites the schedule
        // (`on_send`) or clears it (`on_nothing_to_send`).
        if let Some(p) = &mut self.pacer {
            if let Some(t) = p.next_send_time {
                if now < t {
                    // Gated; `next_deadline` advertises `t` to the driver.
                    return None;
                }
                p.credit += now - t;
            }
        }

        // Retransmission throttle window (SRTO_RETRANSMITALGO=1 — the 1.4.4
        // default whenever the peer sends NAK reports, i.e. always in live
        // mode; docs/spec/transmission.md §7.5 step 2): a sequence whose
        // last retransmission is within SRTT - 4*RTTVar is presumed still
        // in flight, so a repeated (periodic) NAK for it is ignored.
        // saturating_sub implements the spec's negative-window note: the
        // unconverged initial pair (100 ms / 50 ms) yields a zero window
        // and the throttle stays naturally inactive.
        let rexmit_window = Duration::from_micros(
            u64::from(self.rtt_us).saturating_sub(4 * u64::from(self.rtt_var_us)),
        );

        // Retransmissions first; they bypass the flow-window check
        // (docs/spec/transmission.md §3.2, §7.5).
        while let Some(index) = self.loss_list.pop_first() {
            if index < self.base_index || index >= self.next_send_index {
                // Released/dropped since the NAK was queued (the loss list
                // is purged on release, so this is defensive only), or
                // never sent yet — the first-transmission path owns it.
                continue;
            }
            let slot = (index - self.base_index) as usize;
            if let Some(last) = self.buffer[slot].last_rexmit {
                if now.duration_since(last) < rexmit_window {
                    // Throttled. The entry was popped and is NOT re-queued:
                    // the peer's next periodic NAK re-adds it (re-inserting
                    // here would spin this loop forever). If everything is
                    // throttled we fall through to new data (§3.2).
                    trace!(seq = self.seq_at(index).value(), "retransmission throttled");
                    continue;
                }
            }
            // Stamp the rexmit time only here, in the retransmission path
            // (libsrt RexmitTime semantics): first transmissions never
            // stamp it, so a *first* retransmission is never throttled.
            self.buffer[slot].last_rexmit = Some(now);
            let pkt = self.packet_at(index, true);
            self.stats.pkts_sent += 1;
            self.stats.bytes_sent += pkt.payload.len() as u64;
            self.stats.pkts_retransmitted += 1;
            trace!(seq = pkt.seq.value(), "retransmitting");
            // Retransmissions consume a paced slot but never probe
            // (docs/spec/transmission.md §3.3).
            if let Some(p) = &mut self.pacer {
                p.on_send(now, pkt.payload.len(), false);
            }
            return Some(pkt);
        }

        // New data, only while the in-flight window allows.
        let end_index = self.base_index + self.buffer.len() as u64;
        if self.next_send_index < end_index && self.flight() < u64::from(self.effective_window()) {
            let index = self.next_send_index;
            self.next_send_index += 1;
            let pkt = self.packet_at(index, false);
            self.stats.pkts_sent += 1;
            self.stats.bytes_sent += pkt.payload.len() as u64;
            trace!(seq = pkt.seq.value(), "sending");
            // Probe-pair exception (PUMASK_SEQNO_PROBE, core.cpp:9221-9230):
            // a NEW packet whose seq & 0xF == 0 schedules the next send at
            // `now` so the pair hits the wire back-to-back for the peer's
            // capacity estimator.
            if let Some(p) = &mut self.pacer {
                let probe = pkt.seq.value() & 0xF == 0;
                p.on_send(now, pkt.payload.len(), probe);
            }
            return Some(pkt);
        }
        // A due tick found nothing sendable (idle or window-blocked): zero
        // schedule AND credit — credit never survives idle
        // (docs/spec/transmission.md §3.3; packData core.cpp:9106-9117).
        if let Some(p) = &mut self.pacer {
            p.on_nothing_to_send();
        }
        None
    }

    /// Next control message the sender owes the peer (DROPREQ; ACKACKs are
    /// surfaced through [`Sender::handle_ack`]'s return value instead).
    pub fn poll_control(&mut self) -> Option<ControlType> {
        self.control_queue.pop_front()
    }

    /// Earliest instant the driver must come back: min of the TLPKTDROP
    /// deadline and the armed pace schedule.
    ///
    /// The TLPKTDROP component is `None` while the buffered timespan is
    /// within the drop threshold: the timespan only grows on `push`, which
    /// re-arms the deadline itself. The pace schedule is ALWAYS advertised
    /// while armed — a gate without a wake-up would park the driver forever;
    /// the guaranteed drain at the tick either emits the due packet or
    /// resets the idle pacer (docs/spec/transmission.md §3.3).
    pub fn next_deadline(&self) -> Option<Instant> {
        let threshold = self.drop_threshold();
        let drop = match (self.buffer.front(), self.buffer.back()) {
            (Some(front), Some(back)) if back.origin.duration_since(front.origin) > threshold => {
                Some(front.origin + threshold)
            }
            _ => None,
        };
        let pace = self.pacer.as_ref().and_then(Pacer::deadline);
        match (drop, pace) {
            (Some(d), Some(p)) => Some(d.min(p)),
            (d, p) => d.or(p),
        }
    }

    pub fn stats(&self) -> SenderStats {
        let mut stats = self.stats;
        // Pacing gauges live in the pacer (no duplicated state); all three
        // read 0 while pacing is disabled (Bandwidth::Unlimited).
        if let Some(p) = &self.pacer {
            stats.snd_period_us = p.period_us();
            stats.snd_max_bw = p.max_bw();
            stats.snd_input_rate = p.input_rate();
        }
        stats
    }

    /// Sender-side RTT estimate `(rtt_us, rtt_var_us)`: the peer receiver's
    /// smoothed pair adopted from full-ACK CIFs (docs/spec/transmission.md
    /// §6 step 9), or the initial 100 ms / 50 ms pair before any adoption.
    /// Mirrors `Receiver::rtt()`; on a send-only socket this is the only
    /// live RTT estimate.
    pub fn rtt(&self) -> (u32, u32) {
        (self.rtt_us, self.rtt_var_us)
    }

    /// True once at least one full ACK's RTT pair passed the initial-value
    /// gate and was adopted (i.e. [`Sender::rtt`] reflects the path, not
    /// the initial constants).
    #[cfg(test)]
    pub fn has_rtt_sample(&self) -> bool {
        self.rtt_adopted
    }

    /// Packets currently buffered (scheduled or in flight, unacknowledged).
    #[cfg(test)]
    pub fn buffered_pkts(&self) -> usize {
        self.buffer.len()
    }

    /// Effective per-message payload limit enforced by [`Sender::push`]
    /// (derived from the negotiated MSS, min of both sides).
    pub fn max_payload(&self) -> usize {
        self.cfg.max_payload
    }

    /// True once the peer committed a protocol violation (NAK/ACK for data
    /// never sent). libsrt breaks the connection on these; `handle_nak`
    /// cannot return an error, so the connection layer should check this
    /// after feeding a NAK.
    pub fn protocol_violation(&self) -> bool {
        self.protocol_violation
    }

    /// Sender-side TLPKTDROP (docs/spec/transmission.md §8.1): when the
    /// buffered timespan exceeds the threshold, drop every leading packet
    /// older than `now - threshold` and announce the range with a DROPREQ
    /// (msgno 0). libsrt 1.4.4 itself sends no DROPREQ here; sending one is
    /// harmless and matches later libsrt versions.
    fn check_tlpktdrop(&mut self, now: Instant) {
        let (front, back) = match (self.buffer.front(), self.buffer.back()) {
            (Some(f), Some(b)) => (f.origin, b.origin),
            _ => return,
        };
        let threshold = self.drop_threshold();
        if back.duration_since(front) <= threshold {
            return;
        }
        let n = self
            .buffer
            .iter()
            .take_while(|e| now.duration_since(e.origin) >= threshold)
            .count();
        if n > 0 {
            self.drop_front(n, true, "too-late packet drop");
        }
    }

    /// `max(snd_latency, 1 s) + 20 ms` (docs/spec/transmission.md §8.1,
    /// with the default `SRTO_SNDDROPDELAY = 0`).
    fn drop_threshold(&self) -> Duration {
        self.cfg.snd_latency.max(TLPKTDROP_MIN_THRESHOLD) + TLPKTDROP_REACTION
    }

    /// Drops `n` packets from the buffer front and "fake-ACKs" them:
    /// advances the release pointer and the flow-window base, purges the
    /// loss list, and never transmits dropped-but-unsent packets
    /// (docs/spec/transmission.md §8.1).
    fn drop_front(&mut self, n: usize, announce: bool, reason: &'static str) {
        debug_assert!(n > 0 && n <= self.buffer.len());
        let first = self.seq_at(self.base_index);
        let last = self.seq_at(self.base_index + n as u64 - 1);
        warn!(
            first = first.value(),
            last = last.value(),
            n,
            reason,
            "dropping buffered packets"
        );
        self.buffer.drain(.. n);
        self.base_index += n as u64;
        if self.next_send_index < self.base_index {
            self.next_send_index = self.base_index;
        }
        if self.last_ack_index < self.base_index {
            self.last_ack_index = self.base_index;
        }
        self.loss_list = self.loss_list.split_off(&self.base_index);
        self.stats.pkts_dropped += n as u64;
        if announce {
            self.control_queue.push_back(ControlType::DropRequest {
                msg_number: MsgNumber::new(0),
                first,
                last,
            });
        }
    }

    /// Packets in flight: sent and not yet acknowledged
    /// (`seqoff(SndLastAck, SndCurrSeqNo) + 1`).
    fn flight(&self) -> u64 {
        self.next_send_index.saturating_sub(self.last_ack_index)
    }

    /// Live-mode in-flight cap: min(negotiated flow window, peer's latest
    /// advertised available buffer) — docs/spec/transmission.md §6.
    fn effective_window(&self) -> u32 {
        self.cfg.flow_window.min(self.advertised_window)
    }

    /// Wire sequence for an extended index.
    fn seq_at(&self, index: u64) -> SeqNumber {
        // (initial + index) mod 2^31; truncation to u32 then the 31-bit
        // mask is exactly mod 2^31 because 2^31 divides 2^32.
        SeqNumber::new((u64::from(self.cfg.initial_seq.value()) + index) as u32)
    }

    /// Extended index for a wire sequence, resolved relative to the buffer
    /// base (valid while the true distance is below 2^30 — guaranteed by
    /// the flow window). May be negative for already-released sequences.
    fn ext_of(&self, seq: SeqNumber) -> i64 {
        self.base_index as i64 + i64::from(seq.diff(self.seq_at(self.base_index)))
    }

    /// Builds the wire packet for a buffered index. Retransmissions reuse
    /// the ORIGINAL sequence, message number, timestamp and KK bits with
    /// R=1 — same ciphertext, never re-encrypted (encryption.md §9.3).
    fn packet_at(&self, index: u64, retransmitted: bool) -> DataPacket {
        let entry = &self.buffer[(index - self.base_index) as usize];
        DataPacket {
            seq: self.seq_at(index),
            position: PacketPosition::Only,
            order: false,
            encryption: entry.encryption,
            retransmitted,
            msg_number: entry.msg,
            timestamp: entry.ts,
            // Stamped with the peer's socket id by the connection layer.
            dst_socket_id: SocketId::default(),
            payload: entry.payload.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        core::pacing::{
            with_overhead,
            BW_INFINITE,
        },
        crypto::{
            CryptoConfig,
            KeyLength,
            KmReqOutcome,
            KmRspOutcome,
        },
    };

    const ISN: u32 = 100;
    const MS: Duration = Duration::from_millis(1);

    fn config(start: Instant) -> SenderConfig {
        SenderConfig {
            initial_seq: SeqNumber::new(ISN),
            flow_window: 8192,
            snd_latency: Duration::from_millis(120), // threshold = 1020 ms
            max_payload: 1456,
            buffer_pkts: 8192,
            bandwidth: Bandwidth::Unlimited,
            timebase: Timebase::new(start),
        }
    }

    fn sender(start: Instant) -> Sender {
        Sender::new(config(start))
    }

    fn full_ack(seq: u32) -> AckCif {
        AckCif {
            last_ack_seq: SeqNumber::new(seq),
            rtt_us: Some(100_000),
            rtt_var_us: Some(50_000),
            avail_buf_pkts: Some(8192),
            recv_rate_pkts: Some(0),
            link_capacity_pkts: Some(0),
            recv_rate_bytes: Some(0),
        }
    }

    fn light_ack(seq: u32) -> AckCif {
        AckCif {
            last_ack_seq: SeqNumber::new(seq),
            ..AckCif::default()
        }
    }

    fn nak(first: u32, last: u32) -> Vec<LossRange> {
        vec![LossRange {
            first: SeqNumber::new(first),
            last: SeqNumber::new(last),
        }]
    }

    /// Push `n` payloads one 1 ms apart starting at `start`, then transmit
    /// them all; returns the transmitted packets.
    fn push_and_send(s: &mut Sender, start: Instant, n: usize) -> Vec<DataPacket> {
        for i in 0 .. n {
            s.push(start + MS * i as u32, vec![i as u8; 3], None)
                .unwrap();
        }
        let mut out = Vec::new();
        while let Some(p) = s.poll_transmit(start + MS * n as u32) {
            out.push(p);
        }
        assert_eq!(out.len(), n);
        out
    }

    // ---- assignment: seq, msgno, flags, timestamps ----

    #[test]
    fn assigns_consecutive_seq_msg_and_live_flags() {
        let t0 = Instant::now();
        let mut s = sender(t0);
        let pkts = push_and_send(&mut s, t0, 3);
        for (i, p) in pkts.iter().enumerate() {
            assert_eq!(p.seq, SeqNumber::new(ISN + i as u32));
            // Message numbers start at 1.
            assert_eq!(p.msg_number, MsgNumber::new(1 + i as u32));
            assert_eq!(p.position, PacketPosition::Only);
            assert!(!p.order, "live profile sends O=0");
            assert_eq!(p.encryption, EncryptionFlags::None);
            assert!(!p.retransmitted);
            // Origin timestamps from the timebase: i ms after start.
            assert_eq!(p.timestamp, Timestamp(1000 * i as u32));
            assert_eq!(p.payload, vec![i as u8; 3]);
        }
        assert!(s.poll_transmit(t0).is_none());
    }

    #[test]
    fn msgno_wraps_back_to_one_skipping_zero() {
        let t0 = Instant::now();
        let mut s = sender(t0);
        s.next_msg = MsgNumber::new(MsgNumber::MASK); // force upcoming wrap
        let pkts = push_and_send(&mut s, t0, 2);
        assert_eq!(pkts[0].msg_number, MsgNumber::new(MsgNumber::MASK));
        assert_eq!(pkts[1].msg_number, MsgNumber::new(1)); // never 0
    }

    #[test]
    fn payload_too_large_rejected() {
        let t0 = Instant::now();
        let mut s = sender(t0);
        match s.push(t0, vec![0; 1457], None) {
            Err(SrtError::PayloadTooLarge(1457)) => {}
            other => panic!("expected PayloadTooLarge, got {other:?}"),
        }
        assert_eq!(s.buffered_pkts(), 0);
        // At the limit is fine.
        s.push(t0, vec![0; 1456], None).unwrap();
        assert_eq!(s.buffered_pkts(), 1);
    }

    // ---- ACK ----

    #[test]
    fn ack_releases_acknowledged_packets() {
        let t0 = Instant::now();
        let mut s = sender(t0);
        push_and_send(&mut s, t0, 3);
        assert_eq!(s.buffered_pkts(), 3);

        // ACK carries last-received + 1: seq 102 releases 100 and 101.
        let r = s.handle_ack(t0 + MS * 10, 1, &full_ack(ISN + 2)).unwrap();
        assert_eq!(r, Some(1));
        assert_eq!(s.buffered_pkts(), 1);

        // Everything acknowledged.
        s.handle_ack(t0 + MS * 30, 2, &full_ack(ISN + 3)).unwrap();
        assert_eq!(s.buffered_pkts(), 0);

        // Duplicate/old ACK is harmless.
        s.handle_ack(t0 + MS * 50, 3, &full_ack(ISN + 1)).unwrap();
        assert_eq!(s.buffered_pkts(), 0);
    }

    #[test]
    fn ack_release_frees_window_for_new_data() {
        let t0 = Instant::now();
        let mut s = Sender::new(SenderConfig {
            flow_window: 2,
            ..config(t0)
        });
        for i in 0 .. 4 {
            s.push(t0 + MS * i, vec![0; 8], None).unwrap();
        }
        // Window of 2: only two go out.
        assert!(s.poll_transmit(t0).is_some());
        assert!(s.poll_transmit(t0).is_some());
        assert!(s.poll_transmit(t0).is_none());
        // ACK for the first releases one window slot.
        s.handle_ack(
            t0 + MS * 5,
            1,
            &AckCif {
                avail_buf_pkts: Some(2),
                ..full_ack(ISN + 1)
            },
        )
        .unwrap();
        let p = s.poll_transmit(t0 + MS * 5).unwrap();
        assert_eq!(p.seq, SeqNumber::new(ISN + 2));
        assert!(s.poll_transmit(t0 + MS * 5).is_none());
    }

    #[test]
    fn ack_beyond_highest_sent_is_protocol_violation() {
        let t0 = Instant::now();
        let mut s = sender(t0);
        push_and_send(&mut s, t0, 1); // highest sent = 100
                                      // ACK 101 (= highest + 1) is the normal full acknowledgment.
        assert!(s.handle_ack(t0 + MS, 1, &full_ack(ISN + 1)).is_ok());
        // ACK 102 acknowledges data never sent: break.
        match s.handle_ack(t0 + MS * 20, 2, &full_ack(ISN + 2)) {
            Err(SrtError::Closed(_)) => {}
            other => panic!("expected protocol-violation error, got {other:?}"),
        }
        assert!(s.protocol_violation());
    }

    #[test]
    fn light_ack_beyond_highest_sent_is_protocol_violation_without_releasing_buffer() {
        let t0 = Instant::now();
        let mut s = sender(t0);
        s.push(t0, vec![1; 8], None).unwrap();
        s.push(t0 + MS, vec![2; 8], None).unwrap();
        assert_eq!(
            s.poll_transmit(t0 + MS * 2).unwrap().seq,
            SeqNumber::new(ISN)
        );
        assert_eq!(s.buffered_pkts(), 2);

        // Only seq 100 was sent, so ACK 102 confirms seq 101 before it was
        // transmitted. A Light ACK must hit the same protocol-violation gate
        // as a full ACK and must not mutate the send buffer first.
        match s.handle_ack(t0 + MS * 3, 0, &light_ack(ISN + 2)) {
            Err(SrtError::Closed(_)) => {}
            other => panic!("expected protocol-violation error, got {other:?}"),
        }
        assert!(s.protocol_violation());
        assert_eq!(s.buffered_pkts(), 2);
    }

    #[test]
    fn ackack_only_for_non_light_acks() {
        let t0 = Instant::now();
        let mut s = sender(t0);
        push_and_send(&mut s, t0, 2);

        // Light ACK: buffer released, no ACKACK.
        let r = s.handle_ack(t0 + MS, 0, &light_ack(ISN + 1)).unwrap();
        assert_eq!(r, None);
        assert_eq!(s.buffered_pkts(), 1);

        // Full ACK: ACKACK with the echoed ACK number.
        let r = s.handle_ack(t0 + MS * 20, 7, &full_ack(ISN + 2)).unwrap();
        assert_eq!(r, Some(7));

        // Small ACK (16-byte CIF: rtt/rttvar/avail only) also gets one.
        let small = AckCif {
            recv_rate_pkts: None,
            link_capacity_pkts: None,
            recv_rate_bytes: None,
            ..full_ack(ISN + 2)
        };
        let r = s.handle_ack(t0 + MS * 40, 8, &small).unwrap();
        assert_eq!(r, Some(8));
    }

    #[test]
    fn ackack_throttled_within_10ms_except_repeats() {
        let t0 = Instant::now();
        let mut s = sender(t0);
        push_and_send(&mut s, t0, 5);

        assert_eq!(s.handle_ack(t0, 1, &full_ack(ISN + 1)).unwrap(), Some(1));
        // 1 ms later, new ACK number: throttled.
        assert_eq!(s.handle_ack(t0 + MS, 2, &full_ack(ISN + 2)).unwrap(), None);
        // Same ACK number as the last ACKACK: previous ACKACK presumed
        // lost — reply despite the throttle.
        assert_eq!(
            s.handle_ack(t0 + MS * 2, 1, &full_ack(ISN + 2)).unwrap(),
            Some(1)
        );
        // Strictly-greater-than 10 ms since the last ACKACK (t0 + 2 ms).
        assert_eq!(
            s.handle_ack(t0 + MS * 12, 3, &full_ack(ISN + 3)).unwrap(),
            None
        );
        assert_eq!(
            s.handle_ack(t0 + MS * 13, 4, &full_ack(ISN + 4)).unwrap(),
            Some(4)
        );
    }

    #[test]
    fn light_ack_consumes_advertised_window() {
        let t0 = Instant::now();
        let mut s = sender(t0);
        for i in 0 .. 5 {
            s.push(t0 + MS * i, vec![0; 8], None).unwrap();
        }
        assert_eq!(
            s.poll_transmit(t0 + MS * 5).unwrap().seq,
            SeqNumber::new(ISN)
        );

        // Full ACK: peer advertises only 2 free units → window = 2.
        s.handle_ack(
            t0 + MS * 6,
            1,
            &AckCif {
                avail_buf_pkts: Some(2),
                ..full_ack(ISN + 1)
            },
        )
        .unwrap();
        assert_eq!(
            s.poll_transmit(t0 + MS * 6).unwrap().seq,
            SeqNumber::new(ISN + 1)
        );
        assert_eq!(
            s.poll_transmit(t0 + MS * 6).unwrap().seq,
            SeqNumber::new(ISN + 2)
        );
        assert!(
            s.poll_transmit(t0 + MS * 6).is_none(),
            "advertised window exhausted"
        );

        // Light ACK one packet further: releases seq 101 but also consumes
        // one unit of window credit (window 2 → 1, flight 1): still full.
        s.handle_ack(t0 + MS * 7, 0, &light_ack(ISN + 2)).unwrap();
        assert!(s.poll_transmit(t0 + MS * 8).is_none());
    }

    #[test]
    fn adopts_rtt_from_full_ack_gated_on_initial_pair() {
        let t0 = Instant::now();
        let mut s = sender(t0);
        push_and_send(&mut s, t0, 6);
        assert_eq!(s.rtt(), (100_000, 50_000), "initial pair before any ACK");
        assert!(!s.has_rtt_sample());

        // CIF still carrying the exact initial pair: the peer receiver has
        // no ACKACK sample yet — not adopted (spec §6 step 9 gate).
        s.handle_ack(t0 + MS, 1, &full_ack(ISN + 1)).unwrap();
        assert!(!s.has_rtt_sample());
        assert_eq!(s.rtt(), (100_000, 50_000));

        // Before the first adoption BOTH values must differ from their
        // initial: one field still at its initial value is skipped too.
        let cif = AckCif {
            rtt_us: Some(200_000),
            ..full_ack(ISN + 2)
        };
        s.handle_ack(t0 + MS * 20, 2, &cif).unwrap();
        assert!(!s.has_rtt_sample());
        let cif = AckCif {
            rtt_var_us: Some(10_000),
            ..full_ack(ISN + 3)
        };
        s.handle_ack(t0 + MS * 40, 3, &cif).unwrap();
        assert!(!s.has_rtt_sample());
        assert_eq!(s.rtt(), (100_000, 50_000));

        // Both differ: adopted verbatim (the pair is already smoothed by
        // the peer receiver — no local smoothing).
        let cif = AckCif {
            rtt_us: Some(200_000),
            rtt_var_us: Some(10_000),
            ..full_ack(ISN + 4)
        };
        s.handle_ack(t0 + MS * 60, 4, &cif).unwrap();
        assert!(s.has_rtt_sample());
        assert_eq!(s.rtt(), (200_000, 10_000));

        // After the first adoption every full ACK is copied as-is, even
        // values equal to an initial one (RTTVar legitimately converges to
        // 0 on a clean path; 50 ms could be a real reading).
        let cif = AckCif {
            rtt_us: Some(150_000),
            rtt_var_us: Some(0),
            ..full_ack(ISN + 5)
        };
        s.handle_ack(t0 + MS * 80, 5, &cif).unwrap();
        assert_eq!(s.rtt(), (150_000, 0));
        s.handle_ack(t0 + MS * 100, 6, &full_ack(ISN + 6)).unwrap();
        assert_eq!(
            s.rtt(),
            (100_000, 50_000),
            "post-adoption pair copied as-is"
        );

        // Light ACKs carry no RTT fields and change nothing.
        s.handle_ack(t0 + MS * 120, 0, &light_ack(ISN + 6)).unwrap();
        assert_eq!(s.rtt(), (100_000, 50_000));
        assert!(s.has_rtt_sample());
    }

    // ---- NAK / retransmission ----

    #[test]
    fn nak_retransmits_with_original_seq_msg_timestamp_and_r_flag() {
        let t0 = Instant::now();
        let mut s = sender(t0);
        let sent = push_and_send(&mut s, t0, 3);

        s.handle_nak(t0 + MS * 100, &nak(ISN + 1, ISN + 1));
        // Much later, the retransmission still carries the original fields.
        let rex = s.poll_transmit(t0 + MS * 500).unwrap();
        assert_eq!(rex.seq, sent[1].seq);
        assert_eq!(rex.msg_number, sent[1].msg_number);
        assert_eq!(
            rex.timestamp, sent[1].timestamp,
            "restamping breaks peer TSBPD"
        );
        assert_eq!(rex.payload, sent[1].payload);
        assert!(rex.retransmitted, "R flag must be set");
        assert!(!sent[1].retransmitted);
        assert!(s.poll_transmit(t0 + MS * 500).is_none());
    }

    #[test]
    fn retransmissions_take_priority_over_new_data() {
        let t0 = Instant::now();
        let mut s = sender(t0);
        for i in 0 .. 3 {
            s.push(t0 + MS * i, vec![i as u8], None).unwrap();
        }
        // Send only the first two; seq 102 still pending.
        assert_eq!(s.poll_transmit(t0).unwrap().seq, SeqNumber::new(ISN));
        assert_eq!(s.poll_transmit(t0).unwrap().seq, SeqNumber::new(ISN + 1));

        s.handle_nak(t0 + MS * 5, &nak(ISN, ISN));
        let first = s.poll_transmit(t0 + MS * 5).unwrap();
        assert_eq!(first.seq, SeqNumber::new(ISN));
        assert!(first.retransmitted);
        let second = s.poll_transmit(t0 + MS * 5).unwrap();
        assert_eq!(second.seq, SeqNumber::new(ISN + 2));
        assert!(!second.retransmitted);
    }

    #[test]
    fn nak_range_covers_multiple_packets() {
        let t0 = Instant::now();
        let mut s = sender(t0);
        push_and_send(&mut s, t0, 4);
        s.handle_nak(t0 + MS * 5, &nak(ISN + 1, ISN + 3));
        let seqs: Vec<u32> = std::iter::from_fn(|| s.poll_transmit(t0 + MS * 6))
            .map(|p| p.seq.value())
            .collect();
        assert_eq!(seqs, vec![ISN + 1, ISN + 2, ISN + 3]);
    }

    #[test]
    fn nak_for_released_range_replies_dropreq() {
        let t0 = Instant::now();
        let mut s = sender(t0);
        push_and_send(&mut s, t0, 3);
        s.handle_ack(t0 + MS * 5, 1, &full_ack(ISN + 3)).unwrap(); // all released

        // Whole stale range → DROPREQ msgno 0 with the same range.
        s.handle_nak(t0 + MS * 6, &nak(ISN, ISN + 1));
        match s.poll_control() {
            Some(ControlType::DropRequest {
                msg_number,
                first,
                last,
            }) => {
                assert_eq!(msg_number, MsgNumber::new(0));
                assert_eq!(first, SeqNumber::new(ISN));
                assert_eq!(last, SeqNumber::new(ISN + 1));
            }
            other => panic!("expected DROPREQ, got {other:?}"),
        }
        assert!(s.poll_control().is_none());
        // Nothing gets retransmitted.
        assert!(s.poll_transmit(t0 + MS * 7).is_none());

        // A stale *single* sequence is ignored silently.
        s.handle_nak(t0 + MS * 8, &nak(ISN + 2, ISN + 2));
        assert!(s.poll_control().is_none());
        assert!(s.poll_transmit(t0 + MS * 9).is_none());
        assert!(!s.protocol_violation());
    }

    #[test]
    fn nak_straddling_release_point_is_clipped() {
        let t0 = Instant::now();
        let mut s = sender(t0);
        push_and_send(&mut s, t0, 4);
        s.handle_ack(t0 + MS * 5, 1, &full_ack(ISN + 2)).unwrap(); // 100..101 released
        s.handle_nak(t0 + MS * 6, &nak(ISN, ISN + 3));
        let seqs: Vec<u32> = std::iter::from_fn(|| s.poll_transmit(t0 + MS * 7))
            .map(|p| p.seq.value())
            .collect();
        assert_eq!(seqs, vec![ISN + 2, ISN + 3], "stale head must be clipped");
    }

    #[test]
    fn nak_beyond_highest_sent_flags_violation() {
        let t0 = Instant::now();
        let mut s = sender(t0);
        push_and_send(&mut s, t0, 2);
        assert!(!s.protocol_violation());
        s.handle_nak(t0 + MS * 5, &nak(ISN, ISN + 5));
        assert!(s.protocol_violation());
        // Nothing was queued from the offending report.
        assert!(s.poll_transmit(t0 + MS * 6).is_none());
    }

    #[test]
    fn ack_purges_pending_retransmissions() {
        let t0 = Instant::now();
        let mut s = sender(t0);
        push_and_send(&mut s, t0, 3);
        s.handle_nak(t0 + MS * 5, &nak(ISN, ISN + 1));
        // ACK arrives before the retransmission went out: loss list purged.
        s.handle_ack(t0 + MS * 6, 1, &full_ack(ISN + 3)).unwrap();
        assert!(s.poll_transmit(t0 + MS * 7).is_none());
    }

    /// Full ACK carrying a converged RTT estimate: SRTT 200 ms, RTTVar
    /// 10 ms → §7.5 throttle window = 200 - 4*10 = 160 ms.
    fn converged_ack(seq: u32) -> AckCif {
        AckCif {
            rtt_us: Some(200_000),
            rtt_var_us: Some(10_000),
            ..full_ack(seq)
        }
    }

    #[test]
    fn rexmit_throttle_suppresses_duplicate_within_rtt_window() {
        let t0 = Instant::now();
        let mut s = sender(t0);
        push_and_send(&mut s, t0, 3);
        s.handle_ack(t0 + MS, 1, &converged_ack(ISN + 1)).unwrap();

        // First NAK at T: a first retransmission is never throttled.
        s.handle_nak(t0 + MS * 10, &nak(ISN + 1, ISN + 1));
        let rex = s.poll_transmit(t0 + MS * 10).unwrap();
        assert_eq!(rex.seq, SeqNumber::new(ISN + 1));
        assert!(rex.retransmitted);

        // Periodic re-NAK 120 ms after the rexmit (NAK interval
        // (SRTT+4*RTTVar)/2 = 120 ms < RTT): the previous retransmission is
        // still in flight (within the 160 ms window) → no duplicate.
        s.handle_nak(t0 + MS * 130, &nak(ISN + 1, ISN + 1));
        assert!(s.poll_transmit(t0 + MS * 130).is_none());
        assert_eq!(s.stats().pkts_retransmitted, 1, "duplicate suppressed");

        // The suppressed entry was consumed, not re-queued: without a fresh
        // NAK nothing goes out even after the window passes.
        assert!(s.poll_transmit(t0 + MS * 200).is_none());

        // Re-NAK past the window (200 ms after the rexmit): sent again.
        s.handle_nak(t0 + MS * 210, &nak(ISN + 1, ISN + 1));
        let rex2 = s.poll_transmit(t0 + MS * 210).unwrap();
        assert_eq!(rex2.seq, SeqNumber::new(ISN + 1));
        assert!(rex2.retransmitted);
        assert_eq!(s.stats().pkts_retransmitted, 2);
    }

    #[test]
    fn rexmit_throttle_falls_through_to_new_data() {
        let t0 = Instant::now();
        let mut s = sender(t0);
        for i in 0 .. 3 {
            s.push(t0 + MS * i, vec![i as u8], None).unwrap();
        }
        // Send the first two; seq 102 still awaits first transmission.
        assert!(s.poll_transmit(t0).is_some());
        assert!(s.poll_transmit(t0).is_some());
        s.handle_ack(t0 + MS * 3, 1, &converged_ack(ISN)).unwrap(); // releases nothing

        s.handle_nak(t0 + MS * 5, &nak(ISN, ISN));
        assert!(s.poll_transmit(t0 + MS * 5).unwrap().retransmitted);

        // Re-NAK within the window: the retransmission is suppressed but
        // the pending first transmission still goes out (§3.2).
        s.handle_nak(t0 + MS * 20, &nak(ISN, ISN));
        let p = s.poll_transmit(t0 + MS * 20).unwrap();
        assert_eq!(p.seq, SeqNumber::new(ISN + 2));
        assert!(!p.retransmitted);
        assert_eq!(s.stats().pkts_retransmitted, 1);
    }

    #[test]
    fn rexmit_throttle_inactive_before_rtt_convergence() {
        let t0 = Instant::now();
        let mut s = sender(t0);
        push_and_send(&mut s, t0, 2);
        // No RTT adopted: the initial 100 ms / 50 ms pair saturates the
        // window to zero (100 - 4*50 < 0) — duplicates are never throttled
        // (spec's negative-window note).
        s.handle_nak(t0 + MS * 5, &nak(ISN, ISN));
        assert!(s.poll_transmit(t0 + MS * 5).unwrap().retransmitted);
        s.handle_nak(t0 + MS * 6, &nak(ISN, ISN));
        assert!(s.poll_transmit(t0 + MS * 6).unwrap().retransmitted);
        assert_eq!(s.stats().pkts_retransmitted, 2);
    }

    // ---- TLPKTDROP ----

    #[test]
    fn tlpktdrop_on_timer_drops_and_announces() {
        let t0 = Instant::now();
        let mut s = sender(t0);
        // Threshold = max(120 ms, 1 s) + 20 ms = 1020 ms.
        s.push(t0, vec![1], None).unwrap();
        s.push(t0 + Duration::from_millis(1030), vec![2], None)
            .unwrap();
        assert_eq!(s.buffered_pkts(), 2);

        // Timespan (1030 ms) exceeds the threshold: deadline armed at
        // oldest origin + threshold.
        assert_eq!(s.next_deadline(), Some(t0 + Duration::from_millis(1020)));

        s.on_timer(t0 + Duration::from_millis(1030));
        assert_eq!(s.buffered_pkts(), 1);
        assert_eq!(s.stats().pkts_dropped, 1);
        match s.poll_control() {
            Some(ControlType::DropRequest {
                msg_number,
                first,
                last,
            }) => {
                assert_eq!(msg_number, MsgNumber::new(0));
                assert_eq!(first, SeqNumber::new(ISN));
                assert_eq!(last, SeqNumber::new(ISN));
            }
            other => panic!("expected DROPREQ, got {other:?}"),
        }
        // The dropped packet is never transmitted; the survivor is.
        let p = s.poll_transmit(t0 + Duration::from_millis(1031)).unwrap();
        assert_eq!(p.seq, SeqNumber::new(ISN + 1));
        assert_eq!(s.next_deadline(), None);
    }

    #[test]
    fn tlpktdrop_on_push_drops_expired_head() {
        let t0 = Instant::now();
        let mut s = sender(t0);
        s.push(t0, vec![1], None).unwrap();
        // Second push: pre-existing timespan is 0 → no drop.
        s.push(t0 + Duration::from_millis(1100), vec![2], None)
            .unwrap();
        assert_eq!(s.buffered_pkts(), 2);
        // Third push: timespan 1100 ms > 1020 ms → the first packet (older
        // than now - threshold) is dropped before appending.
        s.push(t0 + Duration::from_millis(1150), vec![3], None)
            .unwrap();
        assert_eq!(s.buffered_pkts(), 2);
        assert_eq!(s.stats().pkts_dropped, 1);
        match s.poll_control() {
            Some(ControlType::DropRequest { first, last, .. }) => {
                assert_eq!(first, SeqNumber::new(ISN));
                assert_eq!(last, SeqNumber::new(ISN));
            }
            other => panic!("expected DROPREQ, got {other:?}"),
        }
    }

    #[test]
    fn tlpktdrop_fake_acks_dropped_range() {
        let t0 = Instant::now();
        let mut s = sender(t0);
        let sent = push_and_send(&mut s, t0, 1);
        assert_eq!(sent[0].seq, SeqNumber::new(ISN));
        s.push(t0 + Duration::from_millis(1030), vec![2], None)
            .unwrap();
        s.on_timer(t0 + Duration::from_millis(1030)); // drops seq 100
        s.poll_control(); // discard the DROPREQ announcement

        // A later NAK for the dropped (now sub-SndLastAck) sequence never
        // triggers a retransmission: only the still-buffered seq 101 goes
        // out, as a first transmission.
        s.handle_nak(t0 + Duration::from_millis(1040), &nak(ISN, ISN));
        let p = s.poll_transmit(t0 + Duration::from_millis(1041)).unwrap();
        assert_eq!(p.seq, SeqNumber::new(ISN + 1));
        assert!(!p.retransmitted);
        assert!(s.poll_transmit(t0 + Duration::from_millis(1042)).is_none());
    }

    #[test]
    fn no_deadline_while_timespan_within_threshold() {
        let t0 = Instant::now();
        let mut s = sender(t0);
        s.push(t0, vec![1], None).unwrap();
        s.push(t0 + Duration::from_millis(500), vec![2], None)
            .unwrap();
        assert_eq!(s.next_deadline(), None);
        // Even far in the future the timespan gate keeps the packets:
        // nothing new was submitted (libsrt semantics).
        s.on_timer(t0 + Duration::from_secs(3600));
        assert_eq!(s.buffered_pkts(), 2);
        assert_eq!(s.stats().pkts_dropped, 0);
    }

    // ---- overflow ----

    #[test]
    fn buffer_overflow_drops_oldest() {
        let t0 = Instant::now();
        let mut s = Sender::new(SenderConfig {
            buffer_pkts: 2,
            ..config(t0)
        });
        s.push(t0, vec![1], None).unwrap();
        s.push(t0 + MS, vec![2], None).unwrap();
        s.push(t0 + MS * 2, vec![3], None).unwrap(); // evicts seq 100
        assert_eq!(s.buffered_pkts(), 2);
        assert_eq!(s.stats().pkts_dropped, 1);
        // Oldest is gone: first transmission starts at seq 101.
        assert_eq!(
            s.poll_transmit(t0 + MS * 3).unwrap().seq,
            SeqNumber::new(ISN + 1)
        );
        assert_eq!(
            s.poll_transmit(t0 + MS * 3).unwrap().seq,
            SeqNumber::new(ISN + 2)
        );
        // Plain overflow is not announced with DROPREQ.
        assert!(s.poll_control().is_none());
    }

    #[test]
    fn window_full_drops_oldest_in_flight() {
        let t0 = Instant::now();
        let mut s = Sender::new(SenderConfig {
            flow_window: 2,
            ..config(t0)
        });
        s.push(t0, vec![1], None).unwrap();
        s.push(t0 + MS, vec![2], None).unwrap();
        assert!(s.poll_transmit(t0 + MS).is_some());
        assert!(s.poll_transmit(t0 + MS).is_some());
        assert!(s.poll_transmit(t0 + MS).is_none()); // window full

        // Pushing with a full in-flight window evicts the oldest packet.
        s.push(t0 + MS * 2, vec![3], None).unwrap();
        assert_eq!(s.stats().pkts_dropped, 1);
        assert_eq!(s.buffered_pkts(), 2);
        let p = s.poll_transmit(t0 + MS * 3).unwrap();
        assert_eq!(p.seq, SeqNumber::new(ISN + 2));
        // Window is full again (101 and 102 in flight).
        assert!(s.poll_transmit(t0 + MS * 3).is_none());
    }

    // ---- sequence wrap ----

    #[test]
    fn seq_numbers_wrap_across_max() {
        let t0 = Instant::now();
        let mut s = Sender::new(SenderConfig {
            initial_seq: SeqNumber::new(SeqNumber::MASK - 1),
            ..config(t0)
        });
        let pkts = push_and_send(&mut s, t0, 4);
        let seqs: Vec<u32> = pkts.iter().map(|p| p.seq.value()).collect();
        assert_eq!(seqs, vec![SeqNumber::MASK - 1, SeqNumber::MASK, 0, 1]);

        // ACK past the wrap releases everything before seq 1.
        s.handle_ack(t0 + MS * 10, 1, &full_ack(1)).unwrap();
        assert_eq!(s.buffered_pkts(), 1);

        // NAK across the wrap retransmits with the wrapped sequence.
        s.handle_nak(t0 + MS * 11, &nak(1, 1));
        let rex = s.poll_transmit(t0 + MS * 12).unwrap();
        assert_eq!(rex.seq, SeqNumber::new(1));
        assert!(rex.retransmitted);

        // Full acknowledgment past the wrap: highest sent + 1 = seq 2.
        s.handle_ack(t0 + MS * 20, 2, &full_ack(2)).unwrap();
        assert_eq!(s.buffered_pkts(), 0);
    }

    // ---- stats ----

    #[test]
    fn stats_track_sent_retransmitted_dropped() {
        let t0 = Instant::now();
        let mut s = sender(t0);
        for i in 0 .. 3 {
            s.push(t0 + MS * i, vec![0; 10], None).unwrap();
        }
        while s.poll_transmit(t0 + MS * 3).is_some() {}
        let st = s.stats();
        assert_eq!(st.pkts_sent, 3);
        assert_eq!(st.bytes_sent, 30);
        assert_eq!(st.pkts_retransmitted, 0);
        assert_eq!(st.pkts_dropped, 0);

        // One retransmission: counted in both sent and retransmitted.
        s.handle_nak(t0 + MS * 4, &nak(ISN, ISN));
        assert!(s.poll_transmit(t0 + MS * 5).is_some());
        let st = s.stats();
        assert_eq!(st.pkts_sent, 4);
        assert_eq!(st.bytes_sent, 40);
        assert_eq!(st.pkts_retransmitted, 1);

        // TLPKTDROP of the remaining three.
        s.push(t0 + Duration::from_millis(1500), vec![0; 10], None)
            .unwrap();
        s.on_timer(t0 + Duration::from_millis(1500));
        let st = s.stats();
        assert_eq!(st.pkts_dropped, 3);
        assert_eq!(st.pkts_sent, 4, "drops are not sends");
    }

    #[test]
    fn empty_sender_polls_nothing() {
        let t0 = Instant::now();
        let mut s = sender(t0);
        assert!(s.poll_transmit(t0).is_none());
        assert!(s.poll_control().is_none());
        assert_eq!(s.next_deadline(), None);
        s.on_timer(t0 + Duration::from_secs(10)); // no-op
        assert_eq!(s.buffered_pkts(), 0);
    }

    // ---- encryption (docs/spec/encryption.md §9) ----

    /// Completed KMX pair (encryption.md §6) with tiny refresh thresholds
    /// (`rr = 16`, `pa = 4`, as in the crypto::context tests): `tx`
    /// encrypts what the sender buffers, `rx` plays the peer receiver.
    fn crypto_pair() -> (Crypto, Crypto) {
        let cfg = CryptoConfig {
            passphrase: b"sender test secret".to_vec(),
            key_len: KeyLength::Aes128,
            km_refresh_rate: 16,
            km_preannounce: 4,
        };
        let mut tx = Crypto::new_initiator(cfg.clone());
        let kmreq = tx.kmreq().expect("initial KMREQ cached");
        let (rx, kmrsp) = Crypto::new_responder(cfg, &kmreq).expect("KMX must succeed");
        assert_eq!(tx.handle_kmrsp(&kmrsp), KmRspOutcome::Confirmed);
        (tx, rx)
    }

    /// Pushes payloads `range` (24 bytes of `i` each) encrypted under `tx`.
    fn push_encrypted(s: &mut Sender, tx: &mut Crypto, t0: Instant, range: std::ops::Range<u32>) {
        for i in range {
            s.push(t0 + MS * i, vec![i as u8; 24], Some(tx)).unwrap();
        }
    }

    /// Drives `tx` through one §10.1 refresh cycle around `s`: 16 even-key
    /// packets (the counter starts at 1, so 12 pushes reach the
    /// pre-announce threshold and 16 the switch threshold), the dual-SEK
    /// KM installed on `rx`, then `extra` odd-key packets past the switch.
    fn push_through_key_switch(
        s: &mut Sender,
        tx: &mut Crypto,
        rx: &mut Crypto,
        t0: Instant,
        extra: u32,
    ) {
        push_encrypted(s, tx, t0, 0 .. 12);
        // Refresh ticks run on the ACK path (§10.2); the Connection layer
        // owns that wiring, so the tests tick the engine directly.
        let km = tx.on_ack(t0, 100_000).expect("pre-announce KM");
        let KmReqOutcome::Installed(_) = rx.handle_kmreq(&km) else {
            panic!("refresh KM must install");
        };
        push_encrypted(s, tx, t0, 12 .. 16);
        assert!(tx.on_ack(t0, 100_000).is_none(), "switch emits no KM");
        push_encrypted(s, tx, t0, 16 .. 16 + extra);
    }

    #[test]
    fn push_buffers_ciphertext_with_kk_bits() {
        let t0 = Instant::now();
        let mut s = sender(t0);
        let (mut tx, mut rx) = crypto_pair();

        let clear = b"buffered as ciphertext".to_vec();
        s.push(t0, clear.clone(), Some(&mut tx)).unwrap();
        let p = s.poll_transmit(t0).unwrap();
        // Encrypted at buffering time under the first (even, §9.1) SEK;
        // AES-CTR keeps the length (§9.2).
        assert_eq!(p.encryption, EncryptionFlags::Even);
        assert_ne!(p.payload, clear, "payload must be ciphertext");
        assert_eq!(p.payload.len(), clear.len());
        // The final wire seqno went into the IV: the peer's decrypt with
        // the packet's own seq and KK bits restores the plaintext.
        let mut buf = p.payload.clone();
        rx.decrypt(p.seq, p.encryption, &mut buf).unwrap();
        assert_eq!(buf, clear);
    }

    #[test]
    fn zero_length_payload_is_not_encrypted() {
        // §9.4: HaiCrypt reports a zero-length encrypt as failure and live
        // mode never produces one — the cipher is skipped, KK stays 0.
        let t0 = Instant::now();
        let mut s = sender(t0);
        let (mut tx, _rx) = crypto_pair();
        s.push(t0, Vec::new(), Some(&mut tx)).unwrap();
        let p = s.poll_transmit(t0).unwrap();
        assert_eq!(p.encryption, EncryptionFlags::None);
        assert!(p.payload.is_empty());
    }

    #[test]
    fn rexmit_reuses_ciphertext_and_kk_across_key_switch() {
        let t0 = Instant::now();
        let mut s = sender(t0);
        let (mut tx, mut rx) = crypto_pair();
        push_through_key_switch(&mut s, &mut tx, &mut rx, t0, 2);

        let sent: Vec<DataPacket> = std::iter::from_fn(|| s.poll_transmit(t0 + MS * 18)).collect();
        assert_eq!(sent.len(), 18);
        assert!(sent[.. 16]
            .iter()
            .all(|p| p.encryption == EncryptionFlags::Even));
        assert!(sent[16 ..]
            .iter()
            .all(|p| p.encryption == EncryptionFlags::Odd));

        // Retransmit an old-key packet AFTER the switch: byte-identical
        // ciphertext and the ORIGINAL (even) KK bits — never re-encrypted
        // under the now-active odd key (§9.3); only R is added.
        s.handle_nak(t0 + MS * 20, &nak(ISN + 3, ISN + 3));
        let rex = s.poll_transmit(t0 + MS * 20).unwrap();
        assert!(rex.retransmitted, "R flag set");
        assert_eq!(rex.encryption, EncryptionFlags::Even, "old KK bits kept");
        assert_eq!(rex.payload, sent[3].payload, "identical ciphertext");
        assert_eq!(rex.seq, sent[3].seq);

        // A new-key packet retransmits with its odd KK bits the same way.
        s.handle_nak(t0 + MS * 21, &nak(ISN + 17, ISN + 17));
        let rex = s.poll_transmit(t0 + MS * 21).unwrap();
        assert!(rex.retransmitted);
        assert_eq!(rex.encryption, EncryptionFlags::Odd);
        assert_eq!(rex.payload, sent[17].payload);

        // The peer holds both SEKs from the dual KM (§10.4): every packet
        // decrypts with its own (seq, KK) pair.
        for (i, p) in sent.iter().enumerate() {
            let mut buf = p.payload.clone();
            rx.decrypt(p.seq, p.encryption, &mut buf).unwrap();
            assert_eq!(buf, vec![i as u8; 24], "packet {i}");
        }
    }

    #[test]
    fn kk_bits_survive_buffer_wraparound() {
        // Sequence numbers wrap across MAX while older entries are evicted
        // (overflow) and released (ACK): each surviving packet must keep
        // the KK bits and ciphertext recorded when it was buffered.
        let t0 = Instant::now();
        let mut s = Sender::new(SenderConfig {
            initial_seq: SeqNumber::new(SeqNumber::MASK - 16),
            buffer_pkts: 6,
            ..config(t0)
        });
        let (mut tx, mut rx) = crypto_pair();

        // 20 pushes into a 6-packet buffer: the oldest entry is evicted on
        // every push past the sixth, churning the VecDeque slots.
        push_through_key_switch(&mut s, &mut tx, &mut rx, t0, 4);
        assert_eq!(s.buffered_pkts(), 6);
        assert_eq!(s.stats().pkts_dropped, 14);

        // Survivors are pushes 14..=19: seqs MASK−2 .. 2 — the wire
        // sequence (the IV pki, §9.2) wraps mid-buffer.
        let sent: Vec<DataPacket> = std::iter::from_fn(|| s.poll_transmit(t0 + MS * 20)).collect();
        let seqs: Vec<u32> = sent.iter().map(|p| p.seq.value()).collect();
        assert_eq!(
            seqs,
            vec![
                SeqNumber::MASK - 2,
                SeqNumber::MASK - 1,
                SeqNumber::MASK,
                0,
                1,
                2
            ]
        );
        let flags: Vec<EncryptionFlags> = sent.iter().map(|p| p.encryption).collect();
        assert_eq!(
            flags,
            vec![
                EncryptionFlags::Even, // pushes 14, 15: before the switch
                EncryptionFlags::Even,
                EncryptionFlags::Odd, // pushes 16..: after the switch
                EncryptionFlags::Odd,
                EncryptionFlags::Odd,
                EncryptionFlags::Odd,
            ]
        );
        for (i, p) in sent.iter().enumerate() {
            let mut buf = p.payload.clone();
            rx.decrypt(p.seq, p.encryption, &mut buf).unwrap();
            assert_eq!(buf, vec![(14 + i) as u8; 24], "packet {i}");
        }

        // ACK across the wrap releases the even tail; a NAK for a wrapped
        // odd-key sequence still retransmits its original ciphertext + KK.
        s.handle_ack(t0 + MS * 21, 1, &full_ack(0)).unwrap();
        assert_eq!(s.buffered_pkts(), 3);
        s.handle_nak(t0 + MS * 22, &nak(1, 1));
        let rex = s.poll_transmit(t0 + MS * 22).unwrap();
        assert!(rex.retransmitted);
        assert_eq!(rex.seq, SeqNumber::new(1));
        assert_eq!(rex.encryption, EncryptionFlags::Odd);
        assert_eq!(rex.payload, sent[4].payload);
    }

    // ---- pacing (docs/spec/transmission.md §3.3) ----

    fn us(n: u64) -> Duration {
        Duration::from_micros(n)
    }

    /// `config()` sender with a pacing mode. 1316-byte payloads at
    /// 1_360_000 B/s give a period of exactly 1000 µs
    /// (trunc(1e6·(1316+44)/1_360_000)) — the grid most tests run on.
    fn paced(start: Instant, bandwidth: Bandwidth) -> Sender {
        Sender::new(SenderConfig {
            bandwidth,
            ..config(start)
        })
    }

    #[test]
    fn default_options_are_unpaced() {
        // Divergence pin (§3.3): Bandwidth::Unlimited disables the pacer
        // structurally — a burst drains at one instant, no pace deadline
        // is ever advertised and all gauges read 0. Existing suites rely
        // on same-instant multi-packet drains.
        let t0 = Instant::now();
        let mut s = sender(t0);
        for i in 0 .. 5 {
            s.push(t0 + MS * i, vec![0; 100], None).unwrap();
        }
        let out: Vec<DataPacket> = std::iter::from_fn(|| s.poll_transmit(t0 + MS * 5)).collect();
        assert_eq!(out.len(), 5, "same-instant drain must not be gated");
        assert_eq!(s.next_deadline(), None, "no pace deadline component");
        let st = s.stats();
        assert_eq!(st.snd_period_us, 0);
        assert_eq!(st.snd_max_bw, 0);
        assert_eq!(st.snd_input_rate, 0);
    }

    #[test]
    fn paced_sender_spaces_packets_on_a_microsecond_grid() {
        // §3.3: period = trunc(1e6·(AvgPayloadSize+44)/max_bw) whole µs;
        // the first packet after establish goes immediately (zero
        // m_tsNextSendTime), then the gate holds until the exact tick.
        let t0 = Instant::now();
        let mut s = paced(
            t0,
            Bandwidth::Max {
                bytes_per_sec: 1_360_000,
            },
        );
        for _ in 0 .. 3 {
            s.push(t0, vec![0; 1316], None).unwrap();
        }
        assert!(s.poll_transmit(t0).is_some());
        assert!(s.poll_transmit(t0).is_none(), "second packet gated");
        // MANDATORY: the armed schedule is advertised — the tokio driver
        // sleeps on next_deadline; a silent gate parks it forever.
        assert_eq!(s.next_deadline(), Some(t0 + us(1000)));
        assert!(s.poll_transmit(t0 + us(999)).is_none(), "1 µs early");
        assert!(s.poll_transmit(t0 + us(1000)).is_some());
        assert_eq!(s.stats().snd_period_us, 1000);
        assert_eq!(s.stats().snd_max_bw, 1_360_000);
    }

    #[test]
    fn send_time_credit_repays_lateness_back_to_back() {
        // §3.3: entry lateness accrues as SendTimeDiff credit and is spent
        // to send back-to-back — the catch-up burst that absorbs coarse
        // driver wakes (packData core.cpp:8978-8981, 9221-9248).
        let t0 = Instant::now();
        let mut s = paced(
            t0,
            Bandwidth::Max {
                bytes_per_sec: 1_360_000,
            },
        );
        for _ in 0 .. 6 {
            s.push(t0, vec![0; 1316], None).unwrap();
        }
        assert!(s.poll_transmit(t0).is_some()); // schedule armed at +1000
                                                // The driver comes back 3.5 periods late: 3500 µs of credit buys
                                                // 3 whole periods plus the due slot — 4 packets back-to-back.
        let late = t0 + us(4500);
        let burst: Vec<DataPacket> = std::iter::from_fn(|| s.poll_transmit(late)).collect();
        assert_eq!(burst.len(), 4, "3 whole credits + the due slot");
        // The fractional 500 µs remainder is honored exactly: the sixth
        // packet is due at late + (period - credit) = t0 + 5000 µs.
        assert_eq!(s.next_deadline(), Some(t0 + us(5000)));
        assert!(s.poll_transmit(t0 + us(4999)).is_none());
        assert!(s.poll_transmit(t0 + us(5000)).is_some());
    }

    #[test]
    fn idle_resets_credit_and_schedule() {
        // §3.3: a due poll that finds nothing sendable zeroes credit AND
        // schedule (packData core.cpp:9106-9117) — a push arriving much
        // later starts fresh instead of burning stale credit as a burst.
        let t0 = Instant::now();
        let mut s = paced(
            t0,
            Bandwidth::Max {
                bytes_per_sec: 1_360_000,
            },
        );
        s.push(t0, vec![0; 1316], None).unwrap();
        assert!(s.poll_transmit(t0).is_some());
        assert_eq!(s.next_deadline(), Some(t0 + us(1000)));
        // Contract-honoring drive at the advertised tick: the empty poll
        // performs the idle reset and the pace deadline disappears.
        s.on_timer(t0 + us(1000));
        assert!(s.poll_transmit(t0 + us(1000)).is_none());
        assert_eq!(s.next_deadline(), None, "idle reset disarms the gate");
        // 500 periods later: the first packet goes immediately, but the
        // second waits a FULL period — no spurious credit survived idle.
        let t2 = t0 + Duration::from_millis(500);
        s.push(t2, vec![0; 1316], None).unwrap();
        s.push(t2, vec![0; 1316], None).unwrap();
        assert!(s.poll_transmit(t2).is_some());
        assert!(s.poll_transmit(t2).is_none(), "no spurious burst");
        assert_eq!(s.next_deadline(), Some(t2 + us(1000)));
        assert!(s.poll_transmit(t2 + us(1000)).is_some());
    }

    #[test]
    fn window_blocked_poll_resets_credit() {
        // §3.3: the congested case shares the idle reset — a due tick that
        // is flow-window-blocked zeroes credit and schedule too, so the
        // post-ACK resume is immediate-then-paced, never a credit burst.
        let t0 = Instant::now();
        let mut s = Sender::new(SenderConfig {
            flow_window: 2,
            bandwidth: Bandwidth::Max {
                bytes_per_sec: 1_360_000,
            },
            ..config(t0)
        });
        for _ in 0 .. 4 {
            s.push(t0, vec![0; 1316], None).unwrap();
        }
        assert!(s.poll_transmit(t0).is_some());
        assert!(s.poll_transmit(t0 + us(1000)).is_some());
        // Due tick with the window full (flight 2 of 2): reset.
        assert!(s.poll_transmit(t0 + us(2000)).is_none());
        assert_eq!(s.next_deadline(), None, "window-blocked reset");
        // 8 ms later an ACK releases the window: the next send is
        // immediate (schedule disarmed), the one after a full period.
        s.handle_ack(t0 + us(10_000), 1, &full_ack(ISN + 2))
            .unwrap();
        assert!(s.poll_transmit(t0 + us(10_000)).is_some());
        assert!(
            s.poll_transmit(t0 + us(10_000)).is_none(),
            "credit was zeroed"
        );
        assert_eq!(s.next_deadline(), Some(t0 + us(11_000)));
        assert!(s.poll_transmit(t0 + us(11_000)).is_some());
    }

    #[test]
    fn probe_pair_bypasses_pacing_for_new_data_only() {
        // §3.3 probe pairs (PUMASK_SEQNO_PROBE, core.cpp:9221-9230): a NEW
        // packet whose seq & 0xF == 0 schedules the next send at `now` —
        // the follower goes back-to-back; retransmissions never probe.
        let t0 = Instant::now();
        let mut s = Sender::new(SenderConfig {
            initial_seq: SeqNumber::new(112), // 112 & 0xF == 0
            bandwidth: Bandwidth::Max {
                bytes_per_sec: 1_360_000,
            },
            ..config(t0)
        });
        for _ in 0 .. 3 {
            s.push(t0, vec![0; 1316], None).unwrap();
        }
        // seq 112 probes: its follower (113) is emitted at the SAME
        // instant; the packet after the pair is gated normally.
        assert_eq!(s.poll_transmit(t0).unwrap().seq, SeqNumber::new(112));
        assert_eq!(s.poll_transmit(t0).unwrap().seq, SeqNumber::new(113));
        assert!(s.poll_transmit(t0).is_none(), "after the pair: gated");
        assert_eq!(s.next_deadline(), Some(t0 + us(1000)));
        assert_eq!(
            s.poll_transmit(t0 + us(1000)).unwrap().seq,
            SeqNumber::new(114)
        );
        // A RETRANSMISSION of the & 0xF == 0 sequence does not arm a
        // probe: no same-instant follower after the rexmit.
        s.handle_nak(t0 + us(1500), &nak(112, 112));
        assert!(s.poll_transmit(t0 + us(1500)).is_none(), "gated until tick");
        let rex = s.poll_transmit(t0 + us(2000)).unwrap();
        assert_eq!(rex.seq, SeqNumber::new(112));
        assert!(rex.retransmitted);
        assert!(
            s.poll_transmit(t0 + us(2000)).is_none(),
            "rexmit never probes"
        );
        assert_eq!(s.next_deadline(), Some(t0 + us(3000)));
    }

    #[test]
    fn rexmit_and_new_data_share_one_paced_slot() {
        // §3.3: retransmissions bypass the flow window but NOT pacing —
        // one packet per period across classes, rexmit first (§3.2
        // ordering preserved under the gate).
        let t0 = Instant::now();
        let mut s = paced(
            t0,
            Bandwidth::Max {
                bytes_per_sec: 1_360_000,
            },
        );
        for _ in 0 .. 4 {
            s.push(t0, vec![0; 1316], None).unwrap();
        }
        assert!(s.poll_transmit(t0).is_some()); // seq 100 out
                                                // NAK while gated: nothing is emitted, the loss entry is retained.
        s.handle_nak(t0 + us(100), &nak(ISN, ISN));
        assert!(
            s.poll_transmit(t0 + us(100)).is_none(),
            "gate blocks rexmits too"
        );
        // At the tick the retransmission takes the paced slot ...
        let rex = s.poll_transmit(t0 + us(1000)).unwrap();
        assert_eq!(rex.seq, SeqNumber::new(ISN));
        assert!(rex.retransmitted);
        assert!(s.poll_transmit(t0 + us(1000)).is_none());
        // ... and new data resumes only a full period later.
        let p = s.poll_transmit(t0 + us(2000)).unwrap();
        assert_eq!(p.seq, SeqNumber::new(ISN + 1));
        assert!(!p.retransmitted);
    }

    #[test]
    fn avg_payload_iir_moves_period_only_on_rate_events() {
        // §3.3: TEV_SEND feeds the avg_iir<128> payload smoother but never
        // the interval — the period changes only at refresh events (full
        // ACK / NAK / timer); light ACKs never reach updateCC
        // (core.cpp:7371-7379, 8027-8042).
        let t0 = Instant::now();
        let mut s = paced(
            t0,
            Bandwidth::Max {
                bytes_per_sec: 1_360_000,
            },
        );
        s.push(t0, vec![0; 100], None).unwrap();
        s.push(t0, vec![0; 100], None).unwrap();
        // Two 100-byte sends move the IIR (1316 → 1306 → 1296), yet the
        // period stays at its construction value across both.
        assert!(s.poll_transmit(t0).is_some());
        assert_eq!(s.stats().snd_period_us, 1000);
        assert!(s.poll_transmit(t0 + us(1000)).is_some());
        assert_eq!(s.stats().snd_period_us, 1000);
        // Light ACK: no refresh.
        s.handle_ack(t0 + us(1500), 0, &light_ack(ISN + 2)).unwrap();
        assert_eq!(s.stats().snd_period_us, 1000);
        // Full ACK: refresh picks up the IIR drift —
        // trunc(1e6·(1296+44)/1_360_000) = 985.
        s.handle_ack(t0 + us(1600), 1, &full_ack(ISN + 2)).unwrap();
        assert_eq!(s.stats().snd_period_us, 985);
    }

    #[test]
    fn estimated_ceiling_tracks_estimator_with_overhead_and_floor() {
        // §3.3 auto mode: ceiling = withOverhead(max(min, measured)),
        // refreshed on full ACKs; BW_INFINITE grace until the first
        // estimator window closes (buffer.h:207, congctl.cpp:182-219).
        let t0 = Instant::now();
        let mut s = paced(
            t0,
            Bandwidth::Estimated {
                min_bytes_per_sec: 5_000,
                overhead_pct: 25,
            },
        );
        // Construction parity with updateBandwidth(0, 0) at TEV_INIT: the
        // LiveCC ctor ceiling, period trunc(1e6·1360/125e6) = 10 µs.
        let st = s.stats();
        assert_eq!(st.snd_max_bw, BW_INFINITE);
        assert_eq!(st.snd_input_rate, 0);
        assert_eq!(st.snd_period_us, 10);
        // Before the first window closes a refresh overheads the grace
        // value: 125e6·125/100 — still effectively unpaced.
        s.push(t0, vec![0; 1000], None).unwrap(); // stamps the window only
        s.handle_ack(t0 + Duration::from_millis(100), 1, &full_ack(ISN))
            .unwrap();
        let st = s.stats();
        assert_eq!(st.snd_max_bw, 156_250_000);
        assert_eq!(st.snd_input_rate, 0, "no fictitious grace rate in stats");
        // First window closes at 501 ms with 2 counted 1000-byte pushes:
        // rate = (2000 + 2·44)·1e6/501_000 = 4167 — below the 5000 floor.
        s.push(t0 + Duration::from_millis(250), vec![0; 1000], None)
            .unwrap();
        s.push(t0 + Duration::from_millis(501), vec![0; 1000], None)
            .unwrap();
        s.handle_ack(t0 + Duration::from_millis(502), 2, &full_ack(ISN))
            .unwrap();
        let st = s.stats();
        assert_eq!(st.snd_input_rate, 4167);
        assert_eq!(st.snd_max_bw, with_overhead(5_000, 25), "floor wins");
        assert_eq!(st.snd_max_bw, 6_250);
        // Second (1 s) window measures above the floor: 5 pushes of 1000
        // bytes over 1.001 s → (5000 + 5·44)·1e6/1_001_000 = 5214.
        for i in 1 ..= 4u64 {
            s.push(
                t0 + Duration::from_millis(501 + 200 * i),
                vec![0; 1000],
                None,
            )
            .unwrap();
        }
        s.push(t0 + Duration::from_millis(1502), vec![0; 1000], None)
            .unwrap();
        s.handle_ack(t0 + Duration::from_millis(1503), 3, &full_ack(ISN))
            .unwrap();
        let st = s.stats();
        assert_eq!(st.snd_input_rate, 5214);
        assert_eq!(st.snd_max_bw, with_overhead(5214, 25), "estimate wins");
        assert_eq!(st.snd_max_bw, 6517);
        // Period follows: trunc(1e6·(1316+44)/6517) = 208_684 µs (nothing
        // was emitted, so the payload IIR still sits at its init).
        assert_eq!(st.snd_period_us, 208_684);
    }

    #[test]
    fn tlpktdrop_fires_under_pacing_backpressure() {
        // §8.1 + §3.3 composition: pace-blocked packets age in the buffer
        // and sender TLPKTDROP sheds them; next_deadline() is the min of
        // the two components and the gate survives the drop untouched.
        let t0 = Instant::now();
        // 1360 B/s: period = 1e6·(1316+44)/1360 = exactly 1 s.
        let mut s = paced(
            t0,
            Bandwidth::Max {
                bytes_per_sec: 1360,
            },
        );
        s.push(t0, vec![0; 1316], None).unwrap();
        s.push(t0, vec![0; 1316], None).unwrap();
        assert!(s.poll_transmit(t0).is_some());
        assert_eq!(s.next_deadline(), Some(t0 + us(1_000_000)), "pace only");
        // Third push stretches the timespan past the 1020 ms threshold:
        // the drop deadline (t0 + 1020 ms) arms, but the pace tick
        // (t0 + 1000 ms) is earlier and wins the min.
        s.push(t0 + Duration::from_millis(1030), vec![0; 1316], None)
            .unwrap();
        assert_eq!(s.next_deadline(), Some(t0 + Duration::from_millis(1000)));
        // Pace tick: nothing is droppable yet (both t0 packets are 1000 ms
        // old < 1020 ms); the paced slot emits and re-arms at +2 s, so the
        // drop deadline is now the earlier component.
        s.on_timer(t0 + Duration::from_millis(1000));
        assert!(s.poll_transmit(t0 + Duration::from_millis(1000)).is_some());
        assert!(s.poll_transmit(t0 + Duration::from_millis(1000)).is_none());
        assert_eq!(s.next_deadline(), Some(t0 + Duration::from_millis(1020)));
        // Drop tick: both t0 packets (one sent, one pace-blocked) cross
        // the threshold and are shed with a DROPREQ; the gate stays armed.
        s.on_timer(t0 + Duration::from_millis(1020));
        assert_eq!(s.stats().pkts_dropped, 2);
        assert!(matches!(
            s.poll_control(),
            Some(ControlType::DropRequest { .. })
        ));
        assert!(
            s.poll_transmit(t0 + Duration::from_millis(1020)).is_none(),
            "still gated"
        );
        assert_eq!(s.next_deadline(), Some(t0 + Duration::from_secs(2)));
        // The survivor goes out at the tick, as a first transmission.
        let p = s.poll_transmit(t0 + Duration::from_secs(2)).unwrap();
        assert_eq!(p.seq, SeqNumber::new(ISN + 2));
        assert!(!p.retransmitted);
    }

    #[test]
    fn no_busy_wake_invariant() {
        // §3.3 deadline contract: after any drain-to-None at `now`, the
        // advertised deadline is None (idle reset ran) or strictly in the
        // future (gated) — the driver never busy-loops, and the one extra
        // wake at burst end performs the reset itself.
        let t0 = Instant::now();
        let mut s = paced(
            t0,
            Bandwidth::Max {
                bytes_per_sec: 1_360_000,
            },
        );
        assert!(s.poll_transmit(t0).is_none());
        assert_eq!(s.next_deadline(), None, "idle sender advertises nothing");
        s.push(t0, vec![0; 1316], None).unwrap();
        s.push(t0, vec![0; 1316], None).unwrap();
        let mut now = t0;
        loop {
            while s.poll_transmit(now).is_some() {}
            match s.next_deadline() {
                Some(d) => {
                    assert!(d > now, "deadline at or before `now` busy-loops the driver");
                    now = d;
                }
                None => break,
            }
        }
        // The loop ends exactly at the burst-end wake: both packets went
        // out and the empty poll reset the schedule.
        assert_eq!(s.stats().pkts_sent, 2);
        assert_eq!(s.next_deadline(), None);
    }
}
