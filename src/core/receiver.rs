//! Live-mode data receiver (sans-I/O): buffer, loss list, ACK/NAK, TSBPD.
//!
//! Protocol reference: docs/spec/transmission.md.
//!
//! Responsibilities:
//! - buffer arriving data packets by sequence number, detect gaps;
//! - on a gap: record the range in the loss list and queue an immediate NAK; re-send NAKs for
//!   still-missing ranges on the periodic NAK timer (max((RTT + 4·RTTVar)/2, 20 ms));
//! - full ACK every 10 ms (with RTT/buffer/rate estimates), light ACK every 64 data packets between
//!   full ACKs; keep an ACK history so ACKACK can be matched by ACK number;
//! - on ACKACK: RTT sample → smoothed RTT (7/8) and RTT variance (3/4), initial 100 ms / 50 ms;
//! - on DROPREQ: drop the range from the loss list, never NAK it again;
//! - §7.1 guard: a packet landing beyond the capacity of an EMPTY buffer is an unrecoverable
//!   sequence discrepancy — flagged via [`Receiver::sequence_discrepancy`] so the owner breaks the
//!   connection;
//! - TSBPD: release a buffered packet when `anchor_local + (extended_ts - anchor_ts) + rcv_latency`
//!   is reached; missing packets whose deadline passed are skipped (counted dropped). Peer
//!   timestamps go through [`super::time::TimestampExtender`] — mandatory for streams longer than
//!   ~71.6 minutes.

use std::{
    collections::VecDeque,
    time::{
        Duration,
        Instant,
    },
};

use tracing::{
    debug,
    error,
    trace,
    warn,
};

use super::time::TimestampExtender;
use crate::packet::{
    AckCif,
    ControlType,
    DataPacket,
    LossRange,
    MsgNumber,
    SeqNumber,
    Timestamp,
};

/// Full-ACK period (`COMM_SYN_INTERVAL_US`).
const FULL_ACK_INTERVAL: Duration = Duration::from_millis(10);

/// Light-ACK trigger (`SELF_CLOCK_INTERVAL`): after 64·n data packets
/// received within one full-ACK period.
const LIGHT_ACK_PACKETS: u32 = 64;

/// ACK→ACKACK RTT history depth (`ACK_WND_SIZE`).
const ACK_HISTORY: usize = 1024;

/// Pre-measurement RTT state (`INITIAL_RTT` / `INITIAL_RTTVAR`).
const INITIAL_RTT_US: u32 = 100_000;
const INITIAL_RTT_VAR_US: u32 = 50_000;

/// Periodic-NAK floor installed by LiveCC.
const NAK_MIN_INTERVAL: Duration = Duration::from_millis(20);

/// Periodic-NAK interval before the first recomputation (UDT legacy value).
const NAK_INITIAL_INTERVAL: Duration = Duration::from_millis(300);

/// Available-buffer floor advertised in full ACKs (deadlock breaker).
const MIN_AVAIL_BUF: usize = 2;

/// Fallback maximum payload (MSS 1500 − 44 bytes of headers), used to bound
/// the NAK CIF until [`Receiver::set_max_payload`] installs the negotiated
/// value (§7.3): a NAK must fit one packet payload, max_payload / 4 32-bit
/// words. Remaining ranges go in later periodic reports.
const DEFAULT_MAX_PAYLOAD: usize = 1456;

/// Floor for the NAK word budget: one two-word range must always fit, or a
/// pathological negotiated MSS (< 52) would queue empty periodic NAKs
/// forever while the loss list never drains.
const MIN_NAK_WORDS: usize = 2;

/// `CAckNo::incack`: ACK journal numbers are a 31-bit counter.
fn incack(a: u32) -> u32 {
    if a == 0x7FFF_FFFF {
        0
    } else {
        a + 1
    }
}

/// Receiver configuration derived from options + [`super::Negotiated`].
#[derive(Clone, Debug)]
pub struct ReceiverConfig {
    pub initial_seq: SeqNumber,
    /// Effective TSBPD latency of the direction we receive in.
    pub rcv_latency: Duration,
    /// Receive buffer capacity in packets (also advertised in full ACKs).
    pub buffer_pkts: usize,
}

/// Counters the receiver maintains (merged into [`super::Stats`]).
#[derive(Clone, Copy, Debug, Default)]
pub struct ReceiverStats {
    pub pkts_recv: u64,
    pub bytes_recv: u64,
    /// Gaps detected (packets that entered the loss list).
    pub pkts_lost: u64,
    /// Missing packets skipped by TSBPD deadline (never recovered).
    pub pkts_dropped: u64,
    /// Belated packets discarded (already delivered past them).
    pub pkts_belated: u64,
    pub rtt_us: u32,
    pub rtt_var_us: u32,
}

/// TSBPD time base: local arrival instant of the anchor packet — the
/// CONCLUSION handshake when provided via [`Receiver::set_hs_anchor`]
/// (spec §9.2), else the first data packet — paired with its extended
/// (64-bit) peer timestamp.
#[derive(Clone, Copy, Debug)]
struct Anchor {
    instant: Instant,
    ext_us: u64,
}

/// One buffered, not-yet-delivered data packet.
struct Slot {
    payload: Vec<u8>,
    msg_number: MsgNumber,
    /// TSBPD release deadline (anchor + timestamp delta + latency).
    deadline: Instant,
}

/// ACK journal entry: lets an ACKACK be matched back to its send time.
#[derive(Clone, Copy, Debug)]
struct AckRecord {
    number: u32,
    seq: SeqNumber,
    sent: Instant,
}

pub struct Receiver {
    cfg: ReceiverConfig,

    /// Next sequence to deliver to the application = front of `slots`.
    /// Advanced by delivery and by TSBPD skips (libsrt `RcvLastSkipAck`,
    /// merged with the read position — delivery here IS the app read).
    base_seq: SeqNumber,
    /// `slots[seq - base_seq]`; `None` = hole (missing or already cleared).
    slots: VecDeque<Option<Slot>>,
    /// Highest contiguity-tracked received sequence (`RcvCurrSeqNo`).
    rcv_curr_seq: SeqNumber,
    /// Missing ranges, ascending and disjoint. First entry pins the ACK.
    loss: Vec<LossRange>,

    extender: TimestampExtender,
    anchor: Option<Anchor>,

    /// Last position sent in a full ACK (`RcvLastAck`); never regresses.
    rcv_last_ack: SeqNumber,
    /// Last position the peer confirmed via ACKACK (`RcvLastAckAck`).
    rcv_last_ackack: SeqNumber,
    ack_journal: VecDeque<AckRecord>,
    /// Last used ACK journal number; incremented before send (first ACK = 1).
    ack_seq_no: u32,
    next_full_ack: Instant,
    /// When the last full ACK was queued (ACK-repeat cadence, §4.2 rule 4).
    last_ack_time: Instant,
    /// Data packets since the last timer ACK.
    pkt_count: u32,
    /// Light-ACK scaling factor, reset to 1 by every timer ACK.
    light_ack_count: u32,

    nak_interval: Duration,
    next_nak_time: Instant,

    srtt_us: u32,
    rtt_var_us: u32,
    /// True until the first ACKACK RTT sample (which resets, not smooths).
    rtt_first: bool,

    /// Negotiated maximum payload size, bounding the NAK CIF (§7.3).
    max_payload: usize,

    /// Unrecoverable sequence discrepancy (§7.1): a data packet landed at
    /// an offset beyond the buffer capacity while the buffer was empty, so
    /// `base_seq` can never advance again. The connection owner must poll
    /// [`Receiver::sequence_discrepancy`] and break the connection
    /// (mirrors `Sender::protocol_violation`).
    discrepancy: bool,

    control_q: VecDeque<ControlType>,
    stats: ReceiverStats,
}

impl Receiver {
    pub fn new(now: Instant, cfg: ReceiverConfig) -> Self {
        Receiver {
            base_seq: cfg.initial_seq,
            rcv_curr_seq: cfg.initial_seq.prev(),
            rcv_last_ack: cfg.initial_seq,
            rcv_last_ackack: cfg.initial_seq,
            slots: VecDeque::new(),
            loss: Vec::new(),
            extender: TimestampExtender::new(),
            anchor: None,
            ack_journal: VecDeque::new(),
            ack_seq_no: 0,
            next_full_ack: now + FULL_ACK_INTERVAL,
            last_ack_time: now,
            pkt_count: 0,
            light_ack_count: 1,
            nak_interval: NAK_INITIAL_INTERVAL,
            next_nak_time: now + NAK_INITIAL_INTERVAL,
            srtt_us: INITIAL_RTT_US,
            rtt_var_us: INITIAL_RTT_VAR_US,
            rtt_first: true,
            max_payload: DEFAULT_MAX_PAYLOAD,
            discrepancy: false,
            control_q: VecDeque::new(),
            stats: ReceiverStats::default(),
            cfg,
        }
    }

    /// Seeds the TSBPD time base from the CONCLUSION handshake packet that
    /// completed the connection (spec transmission.md §9.2, line 580):
    /// `instant` is the local arrival of that packet and `ts` its header
    /// timestamp. Call before handling any data; the anchor is set exactly
    /// once, so later calls — or a call after data already anchored the
    /// time base — are ignored. Without this seed the receiver falls back
    /// to anchoring on the first arriving data packet, which permanently
    /// bakes that packet's extra one-way delay (first-burst queueing) into
    /// every delivery deadline.
    pub fn set_hs_anchor(&mut self, instant: Instant, ts: Timestamp) {
        if self.anchor.is_some() {
            return;
        }
        let ext_us = self.extender.extend(ts, instant);
        debug!(ext_us, "TSBPD anchored at handshake packet");
        self.anchor = Some(Anchor { instant, ext_us });
    }

    /// Installs the negotiated maximum payload size (min of both sides'
    /// MSS − 44). Periodic NAK CIFs are truncated to `max_payload / 4`
    /// 32-bit words (§7.3) so a loss report never exceeds what the path
    /// carries. Defaults to 1456 (MSS 1500) until called.
    pub fn set_max_payload(&mut self, bytes: usize) {
        self.max_payload = bytes;
    }

    /// True once an unrecoverable sequence discrepancy has been detected
    /// (transmission.md §7.1): a data packet arrived beyond the buffer
    /// capacity while the buffer was empty. Nothing can ever occupy a slot
    /// again, so no delivery, TSBPD skip, ACK advance, or NAK will happen —
    /// the connection owner must break the connection (sending SHUTDOWN),
    /// exactly as libsrt does, so the application can reconnect.
    pub fn sequence_discrepancy(&self) -> bool {
        self.discrepancy
    }

    /// Buffers an arriving data packet, updating the loss list. May queue an
    /// immediate NAK (fetched via `poll_control`).
    pub fn handle_data(&mut self, now: Instant, pkt: DataPacket) {
        self.stats.pkts_recv += 1;
        self.stats.bytes_recv += pkt.payload.len() as u64;
        self.pkt_count += 1;

        // Extend every observed timestamp so the extender tracks the arrival
        // stream across 2^32 µs wraps. TSBPD is anchored on the handshake
        // packet when the owner seeded it (`set_hs_anchor`, spec §9.2);
        // otherwise fall back to the first data packet (which bakes that
        // packet's one-way delay into every deadline).
        let ext_us = self.extender.extend(pkt.timestamp, now);
        let anchor = match self.anchor {
            Some(a) => a,
            None => {
                let a = Anchor {
                    instant: now,
                    ext_us,
                };
                debug!(ext_us, "TSBPD anchored at first data packet");
                self.anchor = Some(a);
                a
            }
        };

        self.store_data(pkt, anchor, ext_us);

        // Light ACK after 64, 128, 192… packets within one full-ACK period
        // (the counter is reset only by the timer ACK, not by light ACKs).
        if self.pkt_count >= LIGHT_ACK_PACKETS * self.light_ack_count {
            self.light_ack_count += 1;
            self.queue_light_ack();
        }
    }

    fn store_data(&mut self, pkt: DataPacket, anchor: Anchor, ext_us: u64) {
        let seq = pkt.seq;
        trace!(
            seq = seq.value(),
            rexmit = pkt.retransmitted,
            len = pkt.payload.len(),
            "data packet"
        );

        let offset = seq.diff(self.base_seq);
        if offset < 0 {
            // Already delivered or skipped past this sequence.
            self.stats.pkts_belated += 1;
            trace!(seq = seq.value(), "belated packet discarded");
            return;
        }
        let offset = offset as usize;
        if offset >= self.cfg.buffer_pkts {
            // §7.1: with TSBPD+TLPKTDROP (always on in live mode), an
            // offset beyond an EMPTY buffer is an unrecoverable sequence
            // discrepancy — `base_seq` only advances through delivery or
            // skips, both of which need an occupied slot, so every future
            // packet lands beyond capacity too and the connection would be
            // a permanent zombie (e.g. after a network outage long enough
            // for the sender's sequence to advance past `buffer_pkts`).
            // libsrt sends SHUTDOWN and breaks the connection here. The
            // all-None check (not `slots.is_empty()`) matters: DROPREQ's
            // msg-number path can leave the deque populated only with
            // holes, which is equally unrecoverable.
            if self.slots.iter().all(|s| s.is_none()) {
                error!(
                    seq = seq.value(),
                    offset,
                    base = self.base_seq.value(),
                    "packet beyond empty receive buffer: unrecoverable sequence discrepancy"
                );
                self.discrepancy = true;
            } else {
                // Buffer genuinely full/behind: drop only (libsrt does the
                // same while the buffer is non-empty).
                warn!(
                    seq = seq.value(),
                    offset, "receive buffer full; packet dropped"
                );
            }
            return;
        }
        if self.slots.len() <= offset {
            // Holes materialize as `None` slots between the old tail and
            // the new packet.
            self.slots.resize_with(offset + 1, || None);
        }
        if self.slots[offset].is_some() {
            trace!(seq = seq.value(), "duplicate packet discarded");
            return;
        }

        // Gap detection: anything between the highest seen and this packet
        // is newly missing → loss list + immediate NAK (SRTO_LOSSMAXTTL = 0).
        let expected = self.rcv_curr_seq.next();
        if seq.diff(expected) > 0 {
            let range = LossRange {
                first: expected,
                last: seq.prev(),
            };
            let lost = range.last.diff(range.first) as u64 + 1;
            self.stats.pkts_lost += lost;
            self.loss.push(range);
            debug!(
                first = range.first.value(),
                last = range.last.value(),
                lost,
                "gap detected; sending NAK"
            );
            self.queue_nak(vec![range]);
        }
        if seq.diff(self.rcv_curr_seq) > 0 {
            self.rcv_curr_seq = seq;
        } else {
            // Filling a hole (retransmission or reordering).
            self.unlose(seq);
        }

        let deadline = self.tsbpd_deadline(anchor, ext_us);
        self.slots[offset] = Some(Slot {
            payload: pkt.payload,
            msg_number: pkt.msg_number,
            deadline,
        });
    }

    /// Matches an ACKACK to a sent ACK and updates the RTT estimate.
    pub fn handle_ackack(&mut self, now: Instant, ack_number: u32) {
        let Some(pos) = self.ack_journal.iter().position(|r| r.number == ack_number) else {
            // Unknown, light (0), or already-consumed number.
            warn!(ack_number, "ACKACK does not match any pending ACK; ignored");
            return;
        };
        let rec = self.ack_journal[pos];
        // The lookup consumes the entry and everything older; out-of-order
        // ACKACKs for older numbers are then unknown and skipped.
        self.ack_journal.drain(..= pos);

        let rtt_us = now
            .saturating_duration_since(rec.sent)
            .as_micros()
            .min(u32::MAX as u128) as u32;
        if rtt_us == 0 {
            warn!(ack_number, "non-positive RTT sample; ignored");
            return;
        }
        if self.rtt_first {
            // First sample resets the estimator instead of smoothing into
            // the 100 ms/50 ms initial values.
            self.rtt_first = false;
            self.srtt_us = rtt_us;
            self.rtt_var_us = rtt_us / 2;
            debug!(rtt_us, "first RTT sample");
        } else {
            // Order matters: RTTVar first, with the old SRTT.
            let err = self.srtt_us.abs_diff(rtt_us);
            self.rtt_var_us = ((3 * self.rtt_var_us as u64 + err as u64) / 4) as u32;
            self.srtt_us = ((7 * self.srtt_us as u64 + rtt_us as u64) / 8) as u32;
            trace!(
                rtt_us,
                srtt_us = self.srtt_us,
                rtt_var_us = self.rtt_var_us,
                "RTT sample"
            );
        }
        if rec.seq.diff(self.rcv_last_ackack) > 0 {
            self.rcv_last_ackack = rec.seq;
        }
    }

    /// Removes a sender-dropped range from the loss list.
    pub fn handle_dropreq(
        &mut self,
        now: Instant,
        msg_number: MsgNumber,
        first: SeqNumber,
        last: SeqNumber,
    ) {
        let _ = now;
        if first.diff(last) > 0 {
            warn!(
                first = first.value(),
                last = last.value(),
                "DROPREQ with inverted range; ignored"
            );
            return;
        }
        debug!(
            msg = msg_number.value(),
            first = first.value(),
            last = last.value(),
            "DROPREQ"
        );
        // No more NAKs for the range; the ACK can advance past it.
        self.remove_loss_range(first, last);

        // Non-zero message number: drop that message from the buffer (live
        // mode: at most one packet). Zero means drop-by-range-only.
        if msg_number.value() != 0 {
            let lo = first.diff(self.base_seq).max(0);
            let hi = last.diff(self.base_seq);
            let mut i = lo;
            while i <= hi && (i as usize) < self.slots.len() {
                if let Some(slot) = &self.slots[i as usize] {
                    if slot.msg_number == msg_number {
                        self.slots[i as usize] = None;
                    }
                }
                i += 1;
            }
        }

        // Skip ahead if the range covers the next expected packet.
        if first.diff(self.rcv_curr_seq.next()) <= 0 && last.diff(self.rcv_curr_seq) > 0 {
            debug!(
                from = self.rcv_curr_seq.value(),
                to = last.value(),
                "DROPREQ skips ahead"
            );
            self.rcv_curr_seq = last;
        }
    }

    /// Runs the ACK / periodic-NAK timers.
    pub fn on_timer(&mut self, now: Instant) {
        if now >= self.next_full_ack {
            self.queue_full_ack(now);
            // The timer ACK resets the light-ACK bookkeeping whether or not
            // an ACK actually went out.
            self.pkt_count = 0;
            self.light_ack_count = 1;
            self.next_full_ack = now + FULL_ACK_INTERVAL;
        }
        if self.loss.is_empty() {
            // Idle: keep rolling the periodic-NAK timer forward (libsrt
            // checkNAKTimer) so a fresh loss re-NAKs one interval later.
            self.next_nak_time = now + self.nak_interval;
        } else if now >= self.next_nak_time {
            let ranges = self.nak_ranges();
            debug!(ranges = ranges.len(), "periodic NAK");
            self.queue_nak(ranges);
            self.next_nak_time = now + self.nak_interval;
        }
    }

    /// Next control message owed to the peer (ACK, NAK).
    pub fn poll_control(&mut self, now: Instant) -> Option<ControlType> {
        let _ = now;
        self.control_q.pop_front()
    }

    /// Next payload whose TSBPD deadline has been reached, in sequence
    /// order. Skips over lost packets once their deadline passes.
    pub fn poll_deliver(&mut self, now: Instant) -> Option<Vec<u8>> {
        let first = self.slots.iter().position(|s| s.is_some())?;
        let deadline = self.slots[first].as_ref().expect("occupied").deadline;
        if deadline > now {
            return None;
        }
        if first > 0 {
            // TLPKTDROP: the first available packet is due but preceded by
            // a hole whose recovery window has closed — skip the hole.
            let lo = self.base_seq;
            let hi = self.base_seq.add(first as i32 - 1);
            warn!(
                first = lo.value(),
                last = hi.value(),
                skipped = first,
                "TSBPD deadline passed; skipping missing packets"
            );
            self.remove_loss_range(lo, hi);
            self.stats.pkts_dropped += first as u64;
            self.slots.drain(.. first);
            self.base_seq = self.base_seq.add(first as i32);
        }
        let slot = self.slots.pop_front().flatten().expect("occupied");
        trace!(
            seq = self.base_seq.value(),
            len = slot.payload.len(),
            "TSBPD release"
        );
        self.base_seq = self.base_seq.next();
        Some(slot.payload)
    }

    /// Earliest instant the receiver needs waking (ACK tick, NAK tick, or
    /// the TSBPD deadline of the next buffered packet).
    pub fn next_deadline(&self, now: Instant) -> Option<Instant> {
        let mut deadline = self.next_full_ack;
        if !self.loss.is_empty() {
            deadline = deadline.min(self.next_nak_time);
        }
        if let Some(t) = self.slots.iter().flatten().next().map(|s| s.deadline) {
            deadline = deadline.min(t);
        }
        Some(deadline.max(now))
    }

    /// Current smoothed RTT estimate `(rtt_us, rtt_var_us)` for ACK CIFs.
    pub fn rtt(&self) -> (u32, u32) {
        (self.srtt_us, self.rtt_var_us)
    }

    pub fn stats(&self) -> ReceiverStats {
        ReceiverStats {
            rtt_us: self.srtt_us,
            rtt_var_us: self.rtt_var_us,
            ..self.stats
        }
    }

    // ---- internals ----

    /// The sequence a new ACK would carry: first missing packet, or last
    /// contiguously received + 1 (§4.2). Monotonic by construction — never
    /// regresses, never exceeds highest-received + 1.
    fn ack_value(&self) -> SeqNumber {
        self.loss
            .first()
            .map(|e| e.first)
            .unwrap_or_else(|| self.rcv_curr_seq.next())
    }

    fn queue_full_ack(&mut self, now: Instant) {
        let ack = self.ack_value();
        // Rule 1: position already confirmed by the peer's ACKACK.
        if ack == self.rcv_last_ackack {
            return;
        }
        let advance = ack.diff(self.rcv_last_ack);
        if advance > 0 {
            self.rcv_last_ack = ack;
        } else if advance == 0 {
            // Rule 4: re-announce an un-ACKACKed position at RTT cadence.
            let repeat_after =
                Duration::from_micros(self.srtt_us as u64 + 4 * self.rtt_var_us as u64);
            if now.saturating_duration_since(self.last_ack_time) < repeat_after {
                return;
            }
        } else {
            // Rule 5: would regress — internal error; libsrt peers break
            // the connection on regressing ACKs, so never send one.
            warn!(
                ack = ack.value(),
                last_ack = self.rcv_last_ack.value(),
                "ACK position regressed; suppressed"
            );
            return;
        }
        // Rule 6: only send while the peer has not confirmed this position.
        if self.rcv_last_ack.diff(self.rcv_last_ackack) <= 0 {
            return;
        }

        self.ack_seq_no = incack(self.ack_seq_no);
        let cif = AckCif {
            last_ack_seq: self.rcv_last_ack,
            rtt_us: Some(self.srtt_us),
            rtt_var_us: Some(self.rtt_var_us),
            avail_buf_pkts: Some(self.avail_buf_pkts()),
            // Spec-sanctioned simplification (§4.4): 0 = "no measurement".
            recv_rate_pkts: Some(0),
            link_capacity_pkts: Some(0),
            recv_rate_bytes: Some(0),
        };
        trace!(
            ack_no = self.ack_seq_no,
            ack = self.rcv_last_ack.value(),
            "full ACK"
        );
        self.control_q.push_back(ControlType::Ack {
            ack_number: self.ack_seq_no,
            cif,
        });
        if self.ack_journal.len() == ACK_HISTORY {
            self.ack_journal.pop_front();
        }
        self.ack_journal.push_back(AckRecord {
            number: self.ack_seq_no,
            seq: self.rcv_last_ack,
            sent: now,
        });
        self.last_ack_time = now;
    }

    fn queue_light_ack(&mut self) {
        let ack = self.ack_value();
        if ack == self.rcv_last_ackack {
            return;
        }
        trace!(ack = ack.value(), "light ACK");
        // 4-byte CIF, ACK number 0, no journal entry, no state updates.
        self.control_q.push_back(ControlType::Ack {
            ack_number: 0,
            cif: AckCif {
                last_ack_seq: ack,
                ..AckCif::default()
            },
        });
    }

    fn queue_nak(&mut self, ranges: Vec<LossRange>) {
        if ranges.is_empty() {
            return;
        }
        // Every loss report refreshes the NAK interval from the current RTT
        // state (libsrt sendCtrl), replacing the initial 300 ms.
        self.nak_interval =
            Duration::from_micros((self.srtt_us as u64 + 4 * self.rtt_var_us as u64) / 2)
                .max(NAK_MIN_INTERVAL);
        self.control_q.push_back(ControlType::Nak(ranges));
    }

    /// Entire current loss list, truncated to one packet's worth of CIF
    /// (`max_payload / 4` 32-bit words, §7.3) so the NAK datagram never
    /// exceeds the negotiated MSS.
    fn nak_ranges(&self) -> Vec<LossRange> {
        let max_words = (self.max_payload / 4).max(MIN_NAK_WORDS);
        let mut words = 0usize;
        let mut out = Vec::new();
        for e in &self.loss {
            let need = if e.first == e.last { 1 } else { 2 };
            if words + need > max_words {
                break;
            }
            words += need;
            out.push(*e);
        }
        out
    }

    /// Free receive-buffer units for the ACK CIF: capacity minus the
    /// ACKed-but-unread span, floored at 2 (§4.3).
    fn avail_buf_pkts(&self) -> u32 {
        let used = self.rcv_last_ack.diff(self.base_seq).max(0) as usize;
        self.cfg.buffer_pkts.saturating_sub(used).max(MIN_AVAIL_BUF) as u32
    }

    fn tsbpd_deadline(&self, anchor: Anchor, ext_us: u64) -> Instant {
        let base = anchor.instant + self.cfg.rcv_latency;
        let delta = ext_us as i64 - anchor.ext_us as i64;
        if delta >= 0 {
            base + Duration::from_micros(delta as u64)
        } else {
            // Reordered packet stamped before the anchor packet.
            base.checked_sub(Duration::from_micros(delta.unsigned_abs()))
                .unwrap_or(anchor.instant)
        }
    }

    /// Removes a single recovered sequence from the loss list.
    fn unlose(&mut self, seq: SeqNumber) {
        for i in 0 .. self.loss.len() {
            let e = self.loss[i];
            if seq.diff(e.first) < 0 {
                // List is ascending: seq precedes every remaining entry.
                return;
            }
            if e.last.diff(seq) < 0 {
                continue;
            }
            if e.first == e.last {
                self.loss.remove(i);
            } else if seq == e.first {
                self.loss[i].first = seq.next();
            } else if seq == e.last {
                self.loss[i].last = seq.prev();
            } else {
                self.loss[i].last = seq.prev();
                self.loss.insert(
                    i + 1,
                    LossRange {
                        first: seq.next(),
                        last: e.last,
                    },
                );
            }
            return;
        }
    }

    /// Removes the intersection with `[lo, hi]` from every loss entry.
    fn remove_loss_range(&mut self, lo: SeqNumber, hi: SeqNumber) {
        let mut out = Vec::with_capacity(self.loss.len());
        for e in self.loss.drain(..) {
            if hi.diff(e.first) < 0 || e.last.diff(lo) < 0 {
                out.push(e);
                continue;
            }
            if e.first.diff(lo) < 0 {
                out.push(LossRange {
                    first: e.first,
                    last: lo.prev(),
                });
            }
            if e.last.diff(hi) > 0 {
                out.push(LossRange {
                    first: hi.next(),
                    last: e.last,
                });
            }
        }
        self.loss = out;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{
        EncryptionFlags,
        PacketPosition,
        SocketId,
        Timestamp,
    };

    const ISN: u32 = 1000;
    const LATENCY: Duration = Duration::from_millis(120);

    fn cfg(isn: u32) -> ReceiverConfig {
        ReceiverConfig {
            initial_seq: SeqNumber::new(isn),
            rcv_latency: LATENCY,
            buffer_pkts: 8192,
        }
    }

    fn rx(t0: Instant) -> Receiver {
        Receiver::new(t0, cfg(ISN))
    }

    fn data(seq: u32, ts_us: u32) -> DataPacket {
        DataPacket {
            seq: SeqNumber::new(seq),
            position: PacketPosition::Only,
            order: true,
            encryption: EncryptionFlags::None,
            retransmitted: false,
            msg_number: MsgNumber::new(1),
            timestamp: Timestamp(ts_us),
            dst_socket_id: SocketId(1),
            payload: vec![seq as u8],
        }
    }

    fn rexmit(seq: u32, ts_us: u32) -> DataPacket {
        DataPacket {
            retransmitted: true,
            ..data(seq, ts_us)
        }
    }

    fn drain(r: &mut Receiver, now: Instant) -> Vec<ControlType> {
        std::iter::from_fn(|| r.poll_control(now)).collect()
    }

    fn naks(ctl: &[ControlType]) -> Vec<Vec<LossRange>> {
        ctl.iter()
            .filter_map(|c| match c {
                ControlType::Nak(l) => Some(l.clone()),
                _ => None,
            })
            .collect()
    }

    fn acks(ctl: &[ControlType]) -> Vec<(u32, AckCif)> {
        ctl.iter()
            .filter_map(|c| match c {
                ControlType::Ack { ack_number, cif } => Some((*ack_number, *cif)),
                _ => None,
            })
            .collect()
    }

    fn range(first: u32, last: u32) -> LossRange {
        LossRange {
            first: SeqNumber::new(first),
            last: SeqNumber::new(last),
        }
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn us(n: u64) -> Duration {
        Duration::from_micros(n)
    }

    // ---- TSBPD ----

    #[test]
    fn in_order_delivery_released_exactly_at_latency() {
        let t0 = Instant::now();
        let mut r = rx(t0);
        r.handle_data(t0, data(ISN, 0));
        assert_eq!(r.poll_deliver(t0), None);
        assert_eq!(r.poll_deliver(t0 + LATENCY - us(1)), None);
        assert_eq!(r.poll_deliver(t0 + LATENCY), Some(vec![ISN as u8]));
        assert_eq!(r.poll_deliver(t0 + LATENCY), None);

        // Second packet stamped 20 ms later on the peer clock: releases
        // exactly 20 ms after the first, independent of its arrival time.
        r.handle_data(t0 + ms(5), data(ISN + 1, 20_000));
        assert_eq!(r.poll_deliver(t0 + LATENCY + ms(20) - us(1)), None);
        assert_eq!(
            r.poll_deliver(t0 + LATENCY + ms(20)),
            Some(vec![(ISN + 1) as u8])
        );
    }

    #[test]
    fn hs_anchor_time_base_from_handshake_not_first_data() {
        let t0 = Instant::now();
        let mut r = rx(t0);
        // The CONCLUSION handshake arrived at t0 stamped 0 on the peer clock
        // (spec §9.2: the time base predates any data).
        r.set_hs_anchor(t0, Timestamp(0));
        // The first data packet is stamped 10 ms after the handshake but
        // arrives 50 ms late (first-burst queueing): its deadline must be
        // handshake-relative, not relative to its own delayed arrival —
        // otherwise the extra 40 ms of one-way delay would be baked into
        // every deadline for the rest of the connection.
        r.handle_data(t0 + ms(50), data(ISN, 10_000));
        assert_eq!(r.poll_deliver(t0 + LATENCY + ms(10) - us(1)), None);
        assert_eq!(r.poll_deliver(t0 + LATENCY + ms(10)), Some(vec![ISN as u8]));
    }

    #[test]
    fn hs_anchor_is_set_exactly_once() {
        let t0 = Instant::now();
        let mut r = rx(t0);
        r.set_hs_anchor(t0, Timestamp(0));
        // A repeated CONCLUSION must not re-anchor (a later local instant
        // would silently loosen every deadline).
        r.set_hs_anchor(t0 + ms(500), Timestamp(400_000));
        r.handle_data(t0 + ms(5), data(ISN, 1_000));
        assert_eq!(r.poll_deliver(t0 + LATENCY + ms(1) - us(1)), None);
        assert_eq!(r.poll_deliver(t0 + LATENCY + ms(1)), Some(vec![ISN as u8]));

        // Once data has already anchored the time base (no seed at
        // establishment), a late seed is ignored too.
        let mut r = rx(t0);
        r.handle_data(t0, data(ISN, 0));
        r.set_hs_anchor(t0 + ms(1), Timestamp(7_000));
        assert_eq!(r.poll_deliver(t0 + LATENCY - us(1)), None);
        assert_eq!(r.poll_deliver(t0 + LATENCY), Some(vec![ISN as u8]));
    }

    #[test]
    fn hs_anchor_seeds_extender_across_timestamp_wrap() {
        let t0 = Instant::now();
        let mut r = rx(t0);
        // Handshake stamped 5 ms before the 2^32 µs wrap; data crosses it.
        let ts0: u32 = ((1u64 << 32) - 5_000) as u32;
        r.set_hs_anchor(t0, Timestamp(ts0));
        r.handle_data(t0 + ms(20), data(ISN, ts0.wrapping_add(20_000)));
        assert_eq!(r.poll_deliver(t0 + LATENCY + ms(20) - us(1)), None);
        assert_eq!(r.poll_deliver(t0 + LATENCY + ms(20)), Some(vec![ISN as u8]));
    }

    #[test]
    fn out_of_order_reassembly_before_deadline() {
        let t0 = Instant::now();
        let mut r = rx(t0);
        r.handle_data(t0, data(ISN, 0));
        r.handle_data(t0 + ms(1), data(ISN + 2, 2_000));
        // The hole is repaired (plain reordering) well before any deadline.
        r.handle_data(t0 + ms(3), data(ISN + 1, 1_000));

        assert_eq!(r.poll_deliver(t0 + LATENCY), Some(vec![ISN as u8]));
        assert_eq!(
            r.poll_deliver(t0 + LATENCY + ms(1)),
            Some(vec![(ISN + 1) as u8])
        );
        assert_eq!(
            r.poll_deliver(t0 + LATENCY + ms(2)),
            Some(vec![(ISN + 2) as u8])
        );
        assert_eq!(r.stats().pkts_dropped, 0);
        // The loss list is clean: the next full ACK covers everything.
        r.on_timer(t0 + ms(10));
        let ctl = drain(&mut r, t0 + ms(10));
        assert_eq!(acks(&ctl)[0].1.last_ack_seq, SeqNumber::new(ISN + 3));
    }

    #[test]
    fn deadline_passed_skips_hole_with_drop_count() {
        let t0 = Instant::now();
        let mut r = rx(t0);
        r.handle_data(t0, data(ISN, 0));
        r.handle_data(t0 + ms(1), data(ISN + 3, 3_000)); // hole: ISN+1, ISN+2
        drain(&mut r, t0 + ms(1)); // discard the immediate NAK

        assert_eq!(r.poll_deliver(t0 + LATENCY), Some(vec![ISN as u8]));
        // ISN+3's deadline is t0 + 123 ms; the hole holds delivery until then.
        assert_eq!(r.poll_deliver(t0 + LATENCY + ms(3) - us(1)), None);
        assert_eq!(
            r.poll_deliver(t0 + LATENCY + ms(3)),
            Some(vec![(ISN + 3) as u8])
        );
        assert_eq!(r.stats().pkts_dropped, 2);
        // The skipped range left the loss list: no periodic NAK, ACK advances.
        r.on_timer(t0 + ms(400));
        let ctl = drain(&mut r, t0 + ms(400));
        assert!(naks(&ctl).is_empty());
        assert_eq!(acks(&ctl)[0].1.last_ack_seq, SeqNumber::new(ISN + 4));
    }

    #[test]
    fn belated_packet_discarded() {
        let t0 = Instant::now();
        let mut r = rx(t0);
        r.handle_data(t0, data(ISN, 0));
        assert_eq!(r.poll_deliver(t0 + LATENCY), Some(vec![ISN as u8]));

        r.handle_data(t0 + LATENCY + ms(1), data(ISN, 0));
        assert_eq!(r.stats().pkts_belated, 1);
        assert_eq!(r.poll_deliver(t0 + LATENCY + ms(10)), None);
    }

    #[test]
    fn duplicate_packet_discarded() {
        let t0 = Instant::now();
        let mut r = rx(t0);
        r.handle_data(t0, data(ISN, 0));
        r.handle_data(t0 + ms(1), data(ISN, 0)); // still buffered → duplicate
        assert_eq!(r.stats().pkts_recv, 2);
        assert_eq!(r.stats().pkts_belated, 0);
        assert_eq!(r.poll_deliver(t0 + LATENCY), Some(vec![ISN as u8]));
        assert_eq!(r.poll_deliver(t0 + LATENCY), None);
    }

    #[test]
    fn buffer_overflow_drops_packet_without_loss_entry() {
        let t0 = Instant::now();
        let mut r = Receiver::new(
            t0,
            ReceiverConfig {
                initial_seq: SeqNumber::new(ISN),
                rcv_latency: LATENCY,
                buffer_pkts: 4,
            },
        );
        r.handle_data(t0, data(ISN, 0));
        r.handle_data(t0, data(ISN + 4, 400)); // offset 4 ≥ capacity 4
        assert_eq!(r.stats().pkts_lost, 0);
        assert!(naks(&drain(&mut r, t0)).is_empty());
        // The buffer still holds ISN: recoverable (drop only), NOT a
        // sequence discrepancy — libsrt breaks only on an empty buffer.
        assert!(!r.sequence_discrepancy());
        r.on_timer(t0 + ms(10));
        // The overflowed packet never advanced the contiguity tracker.
        assert_eq!(
            acks(&drain(&mut r, t0 + ms(10)))[0].1.last_ack_seq,
            SeqNumber::new(ISN + 1)
        );
    }

    #[test]
    fn overflow_with_empty_buffer_flags_sequence_discrepancy() {
        let t0 = Instant::now();
        let mut r = Receiver::new(
            t0,
            ReceiverConfig {
                initial_seq: SeqNumber::new(ISN),
                rcv_latency: LATENCY,
                buffer_pkts: 4,
            },
        );
        // Deliver and fully drain the buffer.
        r.handle_data(t0, data(ISN, 0));
        assert_eq!(r.poll_deliver(t0 + LATENCY), Some(vec![ISN as u8]));
        assert!(!r.sequence_discrepancy());

        // "Outage": the sender's sequence advanced ≥ buffer capacity while
        // the buffer sat empty. Every future packet lands at offset ≥
        // capacity, no slot can ever be occupied, `base_seq` is frozen —
        // §7.1 says break the connection so the application reconnects.
        r.handle_data(t0 + ms(100), data(ISN + 5, 100_000)); // offset 4 ≥ 4
        assert!(r.sequence_discrepancy());
        // No loss entry or NAK is fabricated for the unrecoverable range.
        assert_eq!(r.stats().pkts_lost, 0);
        assert!(naks(&drain(&mut r, t0 + ms(100))).is_empty());
    }

    #[test]
    fn overflow_with_only_hole_slots_flags_sequence_discrepancy() {
        let t0 = Instant::now();
        let mut r = Receiver::new(
            t0,
            ReceiverConfig {
                initial_seq: SeqNumber::new(ISN),
                rcv_latency: LATENCY,
                buffer_pkts: 4,
            },
        );
        // DROPREQ's msg-number path clears the only buffered packet but
        // leaves the slot deque populated with a hole (`Some` count = 0,
        // `len` = 1): equally unrecoverable — the check must look at slot
        // occupancy, not at `slots.is_empty()`.
        let mut pkt = data(ISN, 0);
        pkt.msg_number = MsgNumber::new(7);
        r.handle_data(t0, pkt);
        r.handle_dropreq(
            t0,
            MsgNumber::new(7),
            SeqNumber::new(ISN),
            SeqNumber::new(ISN),
        );
        assert!(!r.sequence_discrepancy());

        r.handle_data(t0 + ms(1), data(ISN + 4, 1_000)); // offset 4 ≥ 4
        assert!(r.sequence_discrepancy());
    }

    // ---- loss / NAK ----

    #[test]
    fn gap_sends_immediate_nak_exactly_once_then_periodic() {
        let t0 = Instant::now();
        let mut r = rx(t0);
        r.handle_data(t0, data(ISN, 0));
        assert!(drain(&mut r, t0).is_empty());

        r.handle_data(t0 + ms(1), data(ISN + 3, 3_000));
        let ctl = drain(&mut r, t0 + ms(1));
        assert_eq!(ctl, vec![ControlType::Nak(vec![range(ISN + 1, ISN + 2)])]);
        assert_eq!(r.stats().pkts_lost, 2);

        // A contiguous follow-up does not re-NAK the existing hole.
        r.handle_data(t0 + ms(2), data(ISN + 4, 4_000));
        assert!(naks(&drain(&mut r, t0 + ms(2))).is_empty());

        // Periodic re-NAK: the initial interval is 300 ms; within it the
        // 10 ms timer never re-sends the loss list.
        let mut got: Vec<(u64, Vec<LossRange>)> = Vec::new();
        for k in 1 ..= 45 {
            let t = t0 + ms(k * 10);
            r.on_timer(t);
            for l in naks(&drain(&mut r, t)) {
                got.push((k * 10, l));
            }
        }
        // One at 300 ms; the interval then becomes (100ms + 4·50ms)/2 =
        // 150 ms → next at 450 ms.
        assert_eq!(
            got,
            vec![
                (300, vec![range(ISN + 1, ISN + 2)]),
                (450, vec![range(ISN + 1, ISN + 2)]),
            ]
        );
    }

    #[test]
    fn recovery_via_retransmission_fills_hole() {
        let t0 = Instant::now();
        let mut r = rx(t0);
        r.handle_data(t0, data(ISN, 0));
        r.handle_data(t0 + ms(1), data(ISN + 2, 2_000));
        assert_eq!(
            naks(&drain(&mut r, t0 + ms(1))),
            vec![vec![range(ISN + 1, ISN + 1)]]
        );

        // Retransmission keeps the ORIGINAL timestamp and fills the hole.
        r.handle_data(t0 + ms(5), rexmit(ISN + 1, 1_000));

        r.on_timer(t0 + ms(10));
        let ctl = drain(&mut r, t0 + ms(10));
        assert!(naks(&ctl).is_empty());
        assert_eq!(acks(&ctl), vec![(1, acks(&ctl)[0].1)]);
        assert_eq!(acks(&ctl)[0].1.last_ack_seq, SeqNumber::new(ISN + 3));

        // Delivery in order, each exactly at its original-timestamp deadline.
        assert_eq!(r.poll_deliver(t0 + LATENCY), Some(vec![ISN as u8]));
        assert_eq!(r.poll_deliver(t0 + LATENCY + ms(1) - us(1)), None);
        assert_eq!(
            r.poll_deliver(t0 + LATENCY + ms(1)),
            Some(vec![(ISN + 1) as u8])
        );
        assert_eq!(
            r.poll_deliver(t0 + LATENCY + ms(2)),
            Some(vec![(ISN + 2) as u8])
        );
        assert_eq!(r.stats().pkts_dropped, 0);

        // Loss list empty → no periodic NAK later.
        r.on_timer(t0 + ms(500));
        assert!(naks(&drain(&mut r, t0 + ms(500))).is_empty());
    }

    #[test]
    fn partial_fill_splits_loss_range() {
        let t0 = Instant::now();
        let mut r = rx(t0);
        r.handle_data(t0, data(ISN, 0));
        r.handle_data(t0, data(ISN + 5, 500)); // loss [ISN+1, ISN+4]
        drain(&mut r, t0);
        // Fill the middle: the periodic NAK must carry the two remaining
        // sub-ranges, never an inverted one.
        r.handle_data(t0 + ms(1), rexmit(ISN + 3, 300));
        let t = t0 + ms(300);
        r.on_timer(t);
        let ctl = drain(&mut r, t);
        assert_eq!(
            naks(&ctl),
            vec![vec![range(ISN + 1, ISN + 2), range(ISN + 4, ISN + 4)]]
        );
        // ACK still pinned at the first missing packet.
        assert_eq!(acks(&ctl)[0].1.last_ack_seq, SeqNumber::new(ISN + 1));
    }

    #[test]
    fn periodic_nak_truncated_to_negotiated_max_payload() {
        let t0 = Instant::now();
        // 200 scattered single-packet holes (1 CIF word each): even
        // offsets received, odd ones missing.
        let feed = |r: &mut Receiver| {
            for i in 0 ..= 200u32 {
                r.handle_data(t0, data(ISN + 2 * i, 100 * i));
            }
            drain(r, t0); // discard immediate NAKs and light ACKs
        };

        // Default MSS 1500 → budget 1456/4 = 364 words: all 200 fit
        // (bit-identical to the old hardcoded truncation).
        let mut r = rx(t0);
        feed(&mut r);
        r.on_timer(t0 + ms(300));
        let all = naks(&drain(&mut r, t0 + ms(300)));
        assert_eq!(all[0].len(), 200);

        // Negotiated MSS 620 → max_payload 576 → 144 words: the periodic
        // NAK must carry only the first 144 ranges so the loss report
        // itself still fits the datagram size the path can carry.
        let mut r = rx(t0);
        r.set_max_payload(576);
        feed(&mut r);
        r.on_timer(t0 + ms(300));
        let truncated = naks(&drain(&mut r, t0 + ms(300)));
        assert_eq!(truncated[0].len(), 144);
        assert_eq!(truncated[0][..], all[0][.. 144]);
    }

    #[test]
    fn nak_word_budget_floored_so_one_range_always_fits() {
        let t0 = Instant::now();
        let mut r = rx(t0);
        // Pathological negotiated MSS (handshake validation only requires
        // ≥ 32): a raw budget of 4/4 = 1 word could never fit a two-word
        // range, so periodic NAKs would be empty forever while the loss
        // list never drains. The floor keeps one range flowing.
        r.set_max_payload(4);
        r.handle_data(t0, data(ISN, 0));
        r.handle_data(t0, data(ISN + 3, 300)); // loss [ISN+1, ISN+2]: 2 words
        drain(&mut r, t0); // immediate NAK
        r.on_timer(t0 + ms(300));
        assert_eq!(
            naks(&drain(&mut r, t0 + ms(300))),
            vec![vec![range(ISN + 1, ISN + 2)]]
        );
    }

    // ---- ACK ----

    #[test]
    fn no_ack_before_any_data() {
        let t0 = Instant::now();
        let mut r = rx(t0);
        r.on_timer(t0 + ms(10));
        r.on_timer(t0 + ms(20));
        assert!(drain(&mut r, t0 + ms(20)).is_empty());
    }

    #[test]
    fn ack_cadence_and_last_contiguous_plus_one_across_gap() {
        let t0 = Instant::now();
        let mut r = rx(t0);
        r.handle_data(t0, data(ISN, 0));
        r.handle_data(t0, data(ISN + 1, 100));
        r.handle_data(t0, data(ISN + 4, 400)); // hole: ISN+2, ISN+3
        drain(&mut r, t0); // immediate NAK

        // First full ACK at the 10 ms tick: journal number 1, ACK value =
        // first missing (last-contiguous + 1), NOT highest received + 1.
        r.on_timer(t0 + ms(10));
        let ctl = drain(&mut r, t0 + ms(10));
        let a = acks(&ctl);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].0, 1);
        assert_eq!(a[0].1.last_ack_seq, SeqNumber::new(ISN + 2));
        assert_eq!(a[0].1.rtt_us, Some(INITIAL_RTT_US));
        assert_eq!(a[0].1.rtt_var_us, Some(INITIAL_RTT_VAR_US));
        assert_eq!(a[0].1.avail_buf_pkts, Some(8192 - 2)); // 2 acked, unread
        assert_eq!(a[0].1.recv_rate_pkts, Some(0));
        assert_eq!(a[0].1.link_capacity_pkts, Some(0));
        assert_eq!(a[0].1.recv_rate_bytes, Some(0));

        // Fill the hole: the next tick acknowledges past everything.
        r.handle_data(t0 + ms(12), rexmit(ISN + 2, 200));
        r.handle_data(t0 + ms(12), rexmit(ISN + 3, 300));
        r.on_timer(t0 + ms(20));
        let a = acks(&drain(&mut r, t0 + ms(20)));
        assert_eq!(a, vec![(2, a[0].1)]);
        assert_eq!(a[0].1.last_ack_seq, SeqNumber::new(ISN + 5));

        // Nothing new: same position is NOT repeated within SRTT + 4·RTTVar
        // (300 ms with the initial estimate)...
        r.on_timer(t0 + ms(30));
        assert!(drain(&mut r, t0 + ms(30)).is_empty());
        // ...but is re-announced (fresh ACK number) once the cadence allows.
        r.on_timer(t0 + ms(330));
        let a = acks(&drain(&mut r, t0 + ms(330)));
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].0, 3);
        assert_eq!(a[0].1.last_ack_seq, SeqNumber::new(ISN + 5));

        // Once the peer ACKACKs the position, it is never announced again.
        r.handle_ackack(t0 + ms(331), 3);
        r.on_timer(t0 + ms(700));
        assert!(drain(&mut r, t0 + ms(700)).is_empty());
    }

    #[test]
    fn light_ack_every_64_packets_between_full_acks() {
        let t0 = Instant::now();
        let mut r = rx(t0);
        for i in 0 .. 64 {
            r.handle_data(t0, data(ISN + i, i * 100));
        }
        let ctl = drain(&mut r, t0);
        assert_eq!(
            ctl,
            vec![ControlType::Ack {
                ack_number: 0,
                cif: AckCif {
                    last_ack_seq: SeqNumber::new(ISN + 64),
                    ..AckCif::default()
                },
            }]
        );

        // 64 more without a timer tick → second light ACK (at 128 total).
        for i in 64 .. 128 {
            r.handle_data(t0 + ms(1), data(ISN + i, i * 100));
        }
        let ctl = drain(&mut r, t0 + ms(1));
        let a = acks(&ctl);
        assert_eq!(a, vec![(0, a[0].1)]);
        assert_eq!(a[0].1.last_ack_seq, SeqNumber::new(ISN + 128));
        assert_eq!(a[0].1.rtt_us, None); // 4-byte CIF: light ACK

        // The timer ACK resets the packet counter: 63 packets → nothing,
        // the 64th → light ACK again.
        r.on_timer(t0 + ms(10));
        drain(&mut r, t0 + ms(10)); // full ACK
        for i in 128 .. 191 {
            r.handle_data(t0 + ms(11), data(ISN + i, i * 100));
        }
        assert!(drain(&mut r, t0 + ms(11)).is_empty());
        r.handle_data(t0 + ms(12), data(ISN + 191, 19_100));
        let a = acks(&drain(&mut r, t0 + ms(12)));
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].0, 0);
        assert_eq!(a[0].1.last_ack_seq, SeqNumber::new(ISN + 192));
    }

    // ---- ACKACK / RTT ----

    #[test]
    fn ackack_rtt_first_sample_then_smoothed() {
        let t0 = Instant::now();
        let mut r = rx(t0);
        assert_eq!(r.rtt(), (INITIAL_RTT_US, INITIAL_RTT_VAR_US));

        r.handle_data(t0, data(ISN, 0));
        r.on_timer(t0 + ms(10)); // full ACK #1 sent at t0+10ms
        assert_eq!(acks(&drain(&mut r, t0 + ms(10)))[0].0, 1);

        // First sample: SRTT = rtt, RTTVar = rtt/2.
        r.handle_ackack(t0 + ms(50), 1); // rtt = 40 ms
        assert_eq!(r.rtt(), (40_000, 20_000));
        assert_eq!(r.stats().rtt_us, 40_000);
        assert_eq!(r.stats().rtt_var_us, 20_000);

        // Second sample: RTTVar = (3·RTTVar + |rtt − SRTT|)/4 with the OLD
        // SRTT, then SRTT = (7·SRTT + rtt)/8.
        r.handle_data(t0 + ms(50), data(ISN + 1, 50_000));
        r.on_timer(t0 + ms(60)); // full ACK #2 sent at t0+60ms
        assert_eq!(acks(&drain(&mut r, t0 + ms(60)))[0].0, 2);
        r.handle_ackack(t0 + ms(140), 2); // rtt = 80 ms
        assert_eq!(
            r.rtt(),
            ((7 * 40_000 + 80_000) / 8, (3 * 20_000 + 40_000) / 4)
        );
        assert_eq!(r.rtt(), (45_000, 25_000));
    }

    #[test]
    fn ackack_unknown_or_consumed_number_ignored() {
        let t0 = Instant::now();
        let mut r = rx(t0);
        r.handle_data(t0, data(ISN, 0));
        r.on_timer(t0 + ms(10));
        drain(&mut r, t0 + ms(10));

        r.handle_ackack(t0 + ms(20), 99); // never sent
        assert_eq!(r.rtt(), (INITIAL_RTT_US, INITIAL_RTT_VAR_US));

        r.handle_ackack(t0 + ms(50), 1);
        assert_eq!(r.rtt(), (40_000, 20_000));
        r.handle_ackack(t0 + ms(90), 1); // duplicate: entry consumed
        assert_eq!(r.rtt(), (40_000, 20_000));
    }

    // ---- DROPREQ ----

    #[test]
    fn dropreq_purges_loss_list_and_stops_naks() {
        let t0 = Instant::now();
        let mut r = rx(t0);
        r.handle_data(t0, data(ISN, 0));
        r.handle_data(t0, data(ISN + 5, 500)); // loss [ISN+1, ISN+4]
        assert_eq!(
            naks(&drain(&mut r, t0)),
            vec![vec![range(ISN + 1, ISN + 4)]]
        );

        r.handle_dropreq(
            t0 + ms(1),
            MsgNumber::new(0),
            SeqNumber::new(ISN + 1),
            SeqNumber::new(ISN + 4),
        );

        // No periodic NAK ever again, and the ACK advances past the hole.
        let mut all_acks = Vec::new();
        for k in 1 ..= 60 {
            let t = t0 + ms(k * 10);
            r.on_timer(t);
            let ctl = drain(&mut r, t);
            assert!(naks(&ctl).is_empty(), "NAK after DROPREQ at {}ms", k * 10);
            all_acks.extend(acks(&ctl));
        }
        assert_eq!(all_acks[0].1.last_ack_seq, SeqNumber::new(ISN + 6));
    }

    #[test]
    fn dropreq_covering_next_expected_skips_ahead() {
        let t0 = Instant::now();
        let mut r = rx(t0);
        r.handle_data(t0, data(ISN, 0));
        r.handle_dropreq(
            t0 + ms(1),
            MsgNumber::new(0),
            SeqNumber::new(ISN + 1),
            SeqNumber::new(ISN + 9),
        );
        r.on_timer(t0 + ms(10));
        assert_eq!(
            acks(&drain(&mut r, t0 + ms(10)))[0].1.last_ack_seq,
            SeqNumber::new(ISN + 10)
        );
    }

    #[test]
    fn dropreq_with_msg_number_clears_buffered_packet() {
        let t0 = Instant::now();
        let mut r = rx(t0);
        r.handle_data(t0, data(ISN, 0));
        let mut pkt = data(ISN + 1, 1_000);
        pkt.msg_number = MsgNumber::new(7);
        r.handle_data(t0, pkt);
        r.handle_data(t0, data(ISN + 2, 2_000));

        r.handle_dropreq(
            t0,
            MsgNumber::new(7),
            SeqNumber::new(ISN + 1),
            SeqNumber::new(ISN + 1),
        );

        assert_eq!(r.poll_deliver(t0 + LATENCY), Some(vec![ISN as u8]));
        // ISN+1 was dropped: at ISN+2's deadline the hole is skipped.
        assert_eq!(
            r.poll_deliver(t0 + LATENCY + ms(2)),
            Some(vec![(ISN + 2) as u8])
        );
        assert_eq!(r.stats().pkts_dropped, 1);
    }

    // ---- wrap handling ----

    #[test]
    fn timestamp_wrap_keeps_delivery_deadlines_correct() {
        let t0 = Instant::now();
        let mut r = rx(t0);
        // Peer clock is 10 ms short of the 2^32 µs wrap at the first packet.
        let ts0: u32 = ((1u64 << 32) - 10_000) as u32;
        r.handle_data(t0, data(ISN, ts0));
        // Subsequent packets stamped every 20 ms cross the wrap.
        let ts1 = ts0.wrapping_add(20_000);
        let ts2 = ts0.wrapping_add(40_000);
        assert_eq!(ts1, 10_000); // wrapped
        assert_eq!(ts2, 30_000);
        r.handle_data(t0 + ms(20), data(ISN + 1, ts1));
        r.handle_data(t0 + ms(40), data(ISN + 2, ts2));

        assert_eq!(r.poll_deliver(t0 + LATENCY - us(1)), None);
        assert_eq!(r.poll_deliver(t0 + LATENCY), Some(vec![ISN as u8]));
        assert_eq!(r.poll_deliver(t0 + LATENCY + ms(20) - us(1)), None);
        assert_eq!(
            r.poll_deliver(t0 + LATENCY + ms(20)),
            Some(vec![(ISN + 1) as u8])
        );
        assert_eq!(r.poll_deliver(t0 + LATENCY + ms(40) - us(1)), None);
        assert_eq!(
            r.poll_deliver(t0 + LATENCY + ms(40)),
            Some(vec![(ISN + 2) as u8])
        );
        assert_eq!(r.stats().pkts_dropped, 0);
        assert_eq!(r.stats().pkts_belated, 0);
    }

    #[test]
    fn seq_wrap_crossing_max_delivers_in_order_and_acks() {
        let t0 = Instant::now();
        let isn = 0x7FFF_FFFE;
        let mut r = Receiver::new(t0, cfg(isn));
        let seqs = [0x7FFF_FFFEu32, 0x7FFF_FFFF, 0, 1];
        for (i, s) in seqs.iter().enumerate() {
            r.handle_data(t0, data(*s, i as u32 * 1_000));
        }
        assert!(naks(&drain(&mut r, t0)).is_empty());
        assert_eq!(r.stats().pkts_lost, 0);

        r.on_timer(t0 + ms(10));
        assert_eq!(
            acks(&drain(&mut r, t0 + ms(10)))[0].1.last_ack_seq,
            SeqNumber::new(2)
        );

        for (i, s) in seqs.iter().enumerate() {
            assert_eq!(
                r.poll_deliver(t0 + LATENCY + ms(i as u64)),
                Some(vec![*s as u8]),
                "packet {i}"
            );
        }
    }

    #[test]
    fn gap_across_seq_wrap_naks_wrapped_range() {
        let t0 = Instant::now();
        let mut r = Receiver::new(t0, cfg(0x7FFF_FFFE));
        r.handle_data(t0, data(0x7FFF_FFFE, 0));
        r.handle_data(t0, data(1, 3_000)); // missing: 0x7FFF_FFFF and 0
        assert_eq!(naks(&drain(&mut r, t0)), vec![vec![range(0x7FFF_FFFF, 0)]]);
        assert_eq!(r.stats().pkts_lost, 2);

        // Recover across the wrap and check the ACK follows.
        r.handle_data(t0 + ms(1), rexmit(0x7FFF_FFFF, 1_000));
        r.handle_data(t0 + ms(1), rexmit(0, 2_000));
        r.on_timer(t0 + ms(10));
        assert_eq!(
            acks(&drain(&mut r, t0 + ms(10)))[0].1.last_ack_seq,
            SeqNumber::new(2)
        );
    }

    // ---- scheduling ----

    #[test]
    fn next_deadline_is_min_of_ack_nak_and_tsbpd() {
        let t0 = Instant::now();
        let mut r = rx(t0);
        // Only the ACK tick exists initially.
        assert_eq!(r.next_deadline(t0), Some(t0 + ms(10)));
        // Overdue timers clamp to `now`.
        assert_eq!(r.next_deadline(t0 + ms(50)), Some(t0 + ms(50)));

        // A buffered packet's TSBPD deadline participates once it is the
        // earliest event.
        r.handle_data(t0, data(ISN, 0));
        r.on_timer(t0 + ms(115)); // next ACK tick: t0+125ms
        assert_eq!(r.next_deadline(t0 + ms(115)), Some(t0 + LATENCY));

        // A pending loss adds the NAK tick (initial 300 ms, rolled forward
        // to 115+300 by the idle on_timer above).
        r.handle_data(t0 + ms(116), data(ISN + 2, 2_000));
        drain(&mut r, t0 + ms(116));
        r.poll_deliver(t0 + LATENCY); // deliver ISN; ISN+2 deadline t0+122ms
        assert_eq!(r.next_deadline(t0 + ms(121)), Some(t0 + ms(122)));
        r.poll_deliver(t0 + ms(122)); // skips ISN+1, delivers ISN+2
        assert_eq!(r.stats().pkts_dropped, 1);
        // Loss list emptied by the skip → back to the ACK tick.
        assert_eq!(r.next_deadline(t0 + ms(122)), Some(t0 + ms(125)));
    }
}
